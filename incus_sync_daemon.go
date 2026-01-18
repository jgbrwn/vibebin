package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	CaddyConfDir = "/etc/caddy/conf.d"
	SSHPiperRoot = "/var/lib/sshpiper"
	DBPath       = "/var/lib/shelley/containers.db"
	ShelleyPort  = 9999
	UploadPort   = 8099
)

type lifecycleEvent struct {
	Metadata struct {
		Action string `json:"action"`
		Name   string `json:"name"`
	} `json:"metadata"`
	Type string `json:"type"`
}

type containerInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	State  struct {
		Network map[string]struct {
			Addresses []struct {
				Address string `json:"address"`
				Family  string `json:"family"`
			} `json:"addresses"`
		} `json:"network"`
	} `json:"state"`
	Config map[string]string `json:"config"`
}

func main() {
	fmt.Println("incus-sync-daemon starting...")

	// Wait for incus to be ready
	for i := 0; i < 30; i++ {
		out, err := exec.Command("incus", "version").CombinedOutput()
		if err == nil && !strings.Contains(string(out), "unreachable") {
			break
		}
		fmt.Println("Waiting for incus daemon...")
		time.Sleep(2 * time.Second)
	}

	// Open database
	db, err := sql.Open("sqlite", DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Restore previous container states and sync configs
	fmt.Println("Restoring container states...")
	restoreContainerStates(db)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start monitoring in background
	go monitorIncusEvents(db)

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("Shutting down...")
}

// restoreContainerStates syncs Caddy/SSHPiper configs for running containers
// Note: Incus handles container auto-start via last-state behavior when boot.autostart is unset
func restoreContainerStates(db *sql.DB) {
	// Wait a bit for Incus to restore container states
	time.Sleep(5 * time.Second)

	// Get all containers from incus
	out, err := exec.Command("incus", "list", "--format=json").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list containers: %v\n", err)
		return
	}

	var containers []containerInfo
	if err := json.Unmarshal(out, &containers); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse container list: %v\n", err)
		return
	}

	for _, c := range containers {
		// Check if this container is in our database
		var domain string
		var appPort int
		err := db.QueryRow("SELECT domain, app_port FROM containers WHERE name = ?", c.Name).Scan(&domain, &appPort)
		if err != nil {
			// Container not managed by us, skip
			continue
		}

		currentStatus := strings.ToLower(c.Status)
		fmt.Printf("Container %s: status=%s\n", c.Name, currentStatus)

		// Sync configs for running containers (Incus handles starting them automatically)
		if currentStatus == "running" {
			syncContainerConfig(c.Name, domain, appPort)
		}
	}

	fmt.Println("Config sync complete")
}

func monitorIncusEvents(db *sql.DB) {
	for {
		fmt.Println("Starting incus monitor...")
		cmd := exec.Command("incus", "monitor", "--type=lifecycle", "--format=json")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create pipe: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start monitor: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			var event lifecycleEvent
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				continue
			}

			if event.Type == "lifecycle" {
				handleLifecycleEvent(db, event)
			}
		}

		cmd.Wait()
		fmt.Println("Monitor disconnected, reconnecting...")
		time.Sleep(2 * time.Second)
	}
}

func handleLifecycleEvent(db *sql.DB, event lifecycleEvent) {
	name := event.Metadata.Name
	action := event.Metadata.Action

	fmt.Printf("Event: %s - %s\n", action, name)

	switch action {
	case "instance-started":
		// Wait for container to get IP
		time.Sleep(3 * time.Second)
		
		// Get container info from database
		var domain string
		var appPort int
		err := db.QueryRow("SELECT domain, app_port FROM containers WHERE name = ?", name).Scan(&domain, &appPort)
		if err != nil {
			return // Not our container
		}
		
		syncContainerConfig(name, domain, appPort)
		
	case "instance-deleted":
		// Clean up configs via Caddy API
		removeCaddyRoutes(name)
		os.RemoveAll(filepath.Join(SSHPiperRoot, name))
	}
}

func syncContainerConfig(name, domain string, appPort int) {
	_, ip := getContainerStatus(name)
	if ip == "" {
		return
	}

	fmt.Printf("Syncing %s -> %s\n", name, ip)

	// Update Caddy config via API
	updateCaddyRoutes(name, domain, ip, appPort)

	// Update SSHPiper config - preserve existing username from upstream file
	pDir := filepath.Join(SSHPiperRoot, name)
	os.MkdirAll(pDir, 0700)
	
	// Read existing upstream to get username
	upstreamPath := filepath.Join(pDir, "sshpiper_upstream")
	username := "ubuntu" // default
	if existing, err := os.ReadFile(upstreamPath); err == nil {
		parts := strings.SplitN(string(existing), "@", 2)
		if len(parts) > 0 && parts[0] != "" {
			username = strings.TrimSpace(parts[0])
		}
	}
	os.WriteFile(upstreamPath, []byte(username+"@"+ip+":22\n"), 0600)
}

func updateCaddyRoutes(name, domain, ip string, appPort int) {
	client := &http.Client{Timeout: 10 * time.Second}
	caddyAPI := "http://localhost:2019"

	// Delete existing routes
	deleteCaddyRoute(client, caddyAPI, name+"-app")
	deleteCaddyRoute(client, caddyAPI, name+"-shelley")
	deleteCaddyRoute(client, caddyAPI, name+"-upload")

	// Add app route
	appRoute := map[string]interface{}{
		"@id":   name + "-app",
		"match": []map[string]interface{}{{"host": []string{domain}}},
		"handle": []map[string]interface{}{{
			"handler":   "reverse_proxy",
			"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, appPort)}},
		}},
	}
	addCaddyRoute(client, caddyAPI, appRoute)

	// Add shelley route
	shelleyRoute := map[string]interface{}{
		"@id":   name + "-shelley",
		"match": []map[string]interface{}{{"host": []string{"shelley." + domain}}},
		"handle": []map[string]interface{}{{
			"handler":   "reverse_proxy",
			"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, ShelleyPort)}},
		}},
	}
	addCaddyRoute(client, caddyAPI, shelleyRoute)

	// Add upload route with path rewrite
	uploadRoute := map[string]interface{}{
		"@id": name + "-upload",
		"match": []map[string]interface{}{{
			"host": []string{"shelley." + domain},
			"path": []string{"/upload", "/upload/*"},
		}},
		"handle": []map[string]interface{}{
			{
				"handler":      "rewrite",
				"strip_prefix": "/upload",
			},
			{
				"handler":   "reverse_proxy",
				"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, UploadPort)}},
			},
		},
	}
	addCaddyRoute(client, caddyAPI, uploadRoute)
}

func addCaddyRoute(client *http.Client, caddyAPI string, route map[string]interface{}) {
	body, _ := json.Marshal(route)
	req, _ := http.NewRequest("POST", caddyAPI+"/config/apps/http/servers/srv0/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Caddy API error: %v\n", err)
		return
	}
	resp.Body.Close()
}

func deleteCaddyRoute(client *http.Client, caddyAPI, routeID string) {
	req, _ := http.NewRequest("DELETE", caddyAPI+"/id/"+routeID, nil)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func removeCaddyRoutes(name string) {
	client := &http.Client{Timeout: 10 * time.Second}
	caddyAPI := "http://localhost:2019"
	deleteCaddyRoute(client, caddyAPI, name+"-app")
	deleteCaddyRoute(client, caddyAPI, name+"-shelley")
	deleteCaddyRoute(client, caddyAPI, name+"-upload")
}

func getContainerStatus(name string) (status, ip string) {
	out, err := exec.Command("incus", "list", name, "--format=json").Output()
	if err != nil {
		return "unknown", ""
	}

	var list []containerInfo
	if err := json.Unmarshal(out, &list); err != nil || len(list) == 0 {
		return "not found", ""
	}

	status = strings.ToLower(list[0].Status)
	// Get IP - prefer eth0, skip localhost and docker bridge networks
	for netName, net := range list[0].State.Network {
		for _, addr := range net.Addresses {
			if addr.Family == "inet" &&
				!strings.HasPrefix(addr.Address, "127.") &&
				!strings.HasPrefix(addr.Address, "172.17.") &&
				!strings.HasPrefix(addr.Address, "172.18.") {
				// Prefer eth0 over other interfaces
				if netName == "eth0" {
					ip = addr.Address
					break
				} else if ip == "" {
					ip = addr.Address
				}
			}
		}
		if ip != "" && netName == "eth0" {
			break
		}
	}
	return status, ip
}
