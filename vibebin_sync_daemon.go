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
	CaddyConfDir       = "/etc/caddy/conf.d"
	SSHPiperRoot       = "/var/lib/sshpiper"
	DBPath             = "/var/lib/vibebin/containers.db"
	CodeUIPort         = 9999 // opencode/nanocode web UI port
	AdminPort          = 8099 // AI tools admin app port
	CaddyAPI           = "http://localhost:2019"
	CaddyAccessLogPath = "/var/log/caddy/access.log"
	RouteCheckInterval = 15 * time.Second
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
	fmt.Println("vibebin-sync-daemon starting...")

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

	// Ensure Caddy listeners and logging are configured
	ensureCaddyListeners()
	ensureCaddyLogging()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start monitoring in background
	go monitorIncusEvents(db)

	// Start periodic route checker in background
	go monitorCaddyRoutes(db)

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
		var authUser, authHash sql.NullString
		err := db.QueryRow("SELECT domain, app_port, auth_user, auth_hash FROM containers WHERE name = ?", c.Name).Scan(&domain, &appPort, &authUser, &authHash)
		if err != nil {
			// Container not managed by us, skip
			continue
		}

		currentStatus := strings.ToLower(c.Status)
		fmt.Printf("Container %s: status=%s\n", c.Name, currentStatus)

		// Sync configs for running containers (Incus handles starting them automatically)
		if currentStatus == "running" {
			syncContainerConfig(c.Name, domain, appPort, authUser.String, authHash.String)
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
		var authUser, authHash sql.NullString
		err := db.QueryRow("SELECT domain, app_port, auth_user, auth_hash FROM containers WHERE name = ?", name).Scan(&domain, &appPort, &authUser, &authHash)
		if err != nil {
			return // Not our container
		}
		
		syncContainerConfig(name, domain, appPort, authUser.String, authHash.String)
		
	case "instance-deleted":
		// Clean up configs via Caddy API
		removeCaddyRoutes(name)
		os.RemoveAll(filepath.Join(SSHPiperRoot, name))
	}
}

func syncContainerConfig(name, domain string, appPort int, authUser, authHash string) {
	_, ip := getContainerStatus(name)
	if ip == "" {
		return
	}

	fmt.Printf("Syncing %s -> %s\n", name, ip)

	// Update Caddy config via API
	updateCaddyRoutes(name, domain, ip, appPort, authUser, authHash)

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

func updateCaddyRoutes(name, domain, ip string, appPort int, authUser, authHash string) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Delete existing routes
	deleteCaddyRoute(client, CaddyAPI, name+"-app")
	deleteCaddyRoute(client, CaddyAPI, name+"-code")
	deleteCaddyRoute(client, CaddyAPI, name+"-admin")

	// Add app route
	appRoute := map[string]interface{}{
		"@id":   name + "-app",
		"match": []map[string]interface{}{{"host": []string{domain}}},
		"handle": []map[string]interface{}{{
			"handler":   "reverse_proxy",
			"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, appPort)}},
		}},
	}
	addCaddyRoute(client, CaddyAPI, appRoute)

	// Build code UI route handlers (for opencode/nanocode web UI)
	var codeHandlers []map[string]interface{}
	if authUser != "" && authHash != "" {
		codeHandlers = append(codeHandlers, map[string]interface{}{
			"handler": "authentication",
			"providers": map[string]interface{}{
				"http_basic": map[string]interface{}{
					"accounts": []map[string]string{{
						"username": authUser,
						"password": authHash,
					}},
					"realm": "Code",
				},
			},
		})
	}
	codeHandlers = append(codeHandlers, map[string]interface{}{
		"handler":   "reverse_proxy",
		"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, CodeUIPort)}},
	})

	// Add code UI route
	codeRoute := map[string]interface{}{
		"@id":   name + "-code",
		"match": []map[string]interface{}{{"host": []string{"code." + domain}}},
		"handle": codeHandlers,
	}
	addCaddyRoute(client, CaddyAPI, codeRoute)

	// Build admin app route handlers (same auth as code UI)
	var adminHandlers []map[string]interface{}
	if authUser != "" && authHash != "" {
		adminAuthHandler := map[string]interface{}{
			"handler": "authentication",
			"providers": map[string]interface{}{
				"http_basic": map[string]interface{}{
					"accounts": []map[string]string{{
						"username": authUser,
						"password": authHash,
					}},
					"realm": "Admin",
				},
			},
		}
		adminHandlers = append(adminHandlers, adminAuthHandler)
	}
	adminHandlers = append(adminHandlers, map[string]interface{}{
		"handler":   "reverse_proxy",
		"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, AdminPort)}},
	})

	// Add admin route
	adminRoute := map[string]interface{}{
		"@id":   name + "-admin",
		"match": []map[string]interface{}{{"host": []string{"admin.code." + domain}}},
		"handle": adminHandlers,
	}
	addCaddyRoute(client, CaddyAPI, adminRoute)
}

func addCaddyRoute(client *http.Client, caddyAPI string, route map[string]interface{}) {
	body, _ := json.Marshal(route)
	req, _ := http.NewRequest("POST", CaddyAPI+"/config/apps/http/servers/srv0/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Caddy API error: %v\n", err)
		return
	}
	resp.Body.Close()
}

func deleteCaddyRoute(client *http.Client, caddyAPI, routeID string) {
	req, _ := http.NewRequest("DELETE", CaddyAPI+"/id/"+routeID, nil)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func removeCaddyRoutes(name string) {
	client := &http.Client{Timeout: 10 * time.Second}
	deleteCaddyRoute(client, CaddyAPI, name+"-app")
	deleteCaddyRoute(client, CaddyAPI, name+"-code")
	deleteCaddyRoute(client, CaddyAPI, name+"-admin")
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

// ensureCaddyListeners ensures Caddy is listening on both HTTP (80) and HTTPS (443)
// After a Caddy restart from Caddyfile, it may only listen on :80
func ensureCaddyListeners() {
	client := &http.Client{Timeout: 10 * time.Second}

	// Check current listen addresses
	resp, err := client.Get(CaddyAPI + "/config/apps/http/servers/srv0/listen")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var listen []string
	if err := json.NewDecoder(resp.Body).Decode(&listen); err != nil {
		return
	}

	// Check if :443 is already in the listen list
	has443 := false
	for _, addr := range listen {
		if strings.Contains(addr, ":443") {
			has443 = true
			break
		}
	}

	if has443 {
		return // Already listening on HTTPS
	}

	fmt.Println("Configuring Caddy to listen on :80 and :443...")

	// Set listen addresses to include both HTTP and HTTPS
	listenAddrs := []string{":80", ":443"}
	body, _ := json.Marshal(listenAddrs)
	req, _ := http.NewRequest("PATCH", CaddyAPI+"/config/apps/http/servers/srv0/listen", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to configure Caddy listeners: %v\n", err)
		return
	}
	resp2.Body.Close()
	fmt.Println("Caddy listeners configured")
}

// ensureCaddyLogging configures server-level access logging via Caddy API
// This applies to all routes on srv0, including dynamically added ones
func ensureCaddyLogging() {
	client := &http.Client{Timeout: 10 * time.Second}

	// Ensure log directory exists
	os.MkdirAll(filepath.Dir(CaddyAccessLogPath), 0755)

	// Check if logging is already configured
	resp, err := client.Get(CaddyAPI + "/config/logging/logs/access")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			// Already configured, check if srv0 logs are set
			resp2, err := client.Get(CaddyAPI + "/config/apps/http/servers/srv0/logs")
			if err == nil {
				resp2.Body.Close()
				if resp2.StatusCode == 200 {
					return // Already fully configured
				}
			}
		}
	}

	fmt.Println("Configuring Caddy access logging...")

	// Create the access log sink
	logConfig := map[string]interface{}{
		"writer": map[string]interface{}{
			"output":   "file",
			"filename": CaddyAccessLogPath,
		},
		"encoder": map[string]interface{}{
			"format": "json",
		},
	}
	body, _ := json.Marshal(logConfig)
	req, _ := http.NewRequest("PUT", CaddyAPI+"/config/logging/logs/access", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to configure Caddy log sink: %v\n", err)
		return
	}
	resp.Body.Close()

	// Configure srv0 to use the access log
	srv0Logs := map[string]interface{}{
		"default_logger_name": "access",
	}
	body, _ = json.Marshal(srv0Logs)
	req, _ = http.NewRequest("PUT", CaddyAPI+"/config/apps/http/servers/srv0/logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to configure srv0 logging: %v\n", err)
		return
	}
	resp.Body.Close()

	fmt.Println("Caddy access logging configured")
}

// monitorCaddyRoutes periodically checks if Caddy routes are present and repairs if missing
func monitorCaddyRoutes(db *sql.DB) {
	ticker := time.NewTicker(RouteCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		checkAndRepairRoutes(db)
	}
}

// checkAndRepairRoutes verifies all expected routes exist in Caddy and repairs if missing
func checkAndRepairRoutes(db *sql.DB) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Get current routes from Caddy
	resp, err := client.Get(CaddyAPI + "/config/apps/http/servers/srv0/routes")
	if err != nil {
		// Caddy might not be running, skip this check
		return
	}
	defer resp.Body.Close()

	var routes []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return
	}

	// Build set of existing route IDs and track indices of routes without @id (Caddyfile defaults)
	existingRoutes := make(map[string]bool)
	var defaultRouteIndices []int
	for i, route := range routes {
		if id, ok := route["@id"].(string); ok {
			existingRoutes[id] = true
		} else {
			// Route without @id is a Caddyfile default route
			defaultRouteIndices = append(defaultRouteIndices, i)
		}
	}

	// Get all running containers from database and incus
	rows, err := db.Query("SELECT name, domain, app_port, auth_user, auth_hash FROM containers")
	if err != nil {
		return
	}
	defer rows.Close()

	repaired := false
	for rows.Next() {
		var name, domain string
		var appPort int
		var authUser, authHash sql.NullString
		if err := rows.Scan(&name, &domain, &appPort, &authUser, &authHash); err != nil {
			continue
		}

		// Check if container is running
		status, ip := getContainerStatus(name)
		if status != "running" || ip == "" {
			continue
		}

		// Check if all three routes exist for this container
		appRouteID := name + "-app"
		codeRouteID := name + "-code"
		adminRouteID := name + "-admin"

		if !existingRoutes[appRouteID] || !existingRoutes[codeRouteID] || !existingRoutes[adminRouteID] {
			fmt.Printf("Missing routes detected for %s, repairing...\n", name)
			syncContainerConfig(name, domain, appPort, authUser.String, authHash.String)
			repaired = true
		}
	}

	// Remove Caddyfile default routes (routes without @id) if we have vibebin routes
	// Delete in reverse order to avoid index shifting issues
	if len(defaultRouteIndices) > 0 && len(existingRoutes) > 0 {
		fmt.Printf("Removing %d Caddyfile default route(s)...\n", len(defaultRouteIndices))
		for i := len(defaultRouteIndices) - 1; i >= 0; i-- {
			idx := defaultRouteIndices[i]
			req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/config/apps/http/servers/srv0/routes/%d", CaddyAPI, idx), nil)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
		repaired = true
	}

	// If we repaired routes, also ensure listeners and logging are configured
	if repaired {
		ensureCaddyListeners()
		ensureCaddyLogging()
	}
}
