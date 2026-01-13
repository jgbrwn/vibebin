package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	_ "modernc.org/sqlite"
)

// Configuration
const (
	CaddyConfDir   = "/etc/caddy/conf.d"
	SSHPiperRoot   = "/var/lib/sshpiper"
	ExeuntuImage   = "ghcr:boldsoftware/exeuntu:latest"
	DBPath         = "/var/lib/shelley/containers.db"
	DefaultAppPort = 8000
	ShelleyPort    = 9999
)

// State machine for TUI
type viewState int

const (
	stateLoading viewState = iota
	stateInstalling
	stateList
	stateCreateDomain
	stateCreateDNSProvider
	stateCreateDNSToken
	stateCreateCFProxy  // New: Cloudflare proxy option
	stateCreateAppPort
	stateCreateSSHKey
	stateContainerDetail
	stateEditAppPort
	stateLogs
	stateUntracked      // New: Show untracked containers
	stateImportContainer // New: Import untracked container
)

// DNS Provider types
type dnsProvider int

const (
	dnsNone dnsProvider = iota
	dnsCloudflare
	dnsDesec
)

// Container entry from database
type containerEntry struct {
	ID        int
	Name      string
	Domain    string
	AppPort   int
	Status    string
	IP        string
	CPU       string
	Memory    string
	CreatedAt time.Time
}

// Messages for async operations
type (
	bootstrapDoneMsg   struct{ db *sql.DB; err error }
	installNeededMsg   []string
	installDoneMsg     struct{ err error }
	containersMsg      []containerEntry
	logMsg             string
	errorMsg           string
	successMsg         string
	tickMsg            time.Time
)

// TUI Model
type model struct {
	state       viewState
	db          *sql.DB
	containers  []containerEntry
	cursor      int
	textInput   textinput.Model
	status      string
	logContent  string
	currentSvc  string
	missing     []string

	// Create flow state
	newDomain      string
	newDNSProvider dnsProvider
	newDNSToken    string
	newCFProxy     bool // Cloudflare proxy enabled
	newAppPort     int
	newSSHKey      string

	// Untracked containers
	untrackedContainers []string

	// Edit state
	editingContainer *containerEntry
}

func initialModel() model {
	ti := textinput.New()
	ti.Width = 60
	return model{
		state:     stateLoading,
		textInput: ti,
	}
}

func (m model) Init() tea.Cmd {
	return checkPrerequisitesCmd()
}

func tickCmd() tea.Cmd {
	return tea.Every(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Check what needs to be installed
func checkPrerequisitesCmd() tea.Cmd {
	return func() tea.Msg {
		var missing []string

		// Check incus (need 6.3+ from zabbly)
		out, err := exec.Command("incus", "version").CombinedOutput()
		if err != nil || strings.Contains(string(out), "unreachable") {
			missing = append(missing, "incus")
		} else {
			// Check version - need 6.3+
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "Client version:") {
					ver := strings.TrimSpace(strings.TrimPrefix(line, "Client version:"))
					if ver < "6.3" {
						missing = append(missing, "incus")
					}
					break
				}
			}
		}

		// Check caddy
		if _, err := exec.LookPath("caddy"); err != nil {
			missing = append(missing, "caddy")
		}

		// Check sshpiperd
		if _, err := exec.LookPath("sshpiperd"); err != nil {
			if _, err := os.Stat("/usr/local/bin/sshpiperd"); os.IsNotExist(err) {
				missing = append(missing, "sshpiperd")
			}
		}

		if len(missing) > 0 {
			return installNeededMsg(missing)
		}

		return bootstrapCmd()()
	}
}

// Install missing dependencies
func installDependenciesCmd(missing []string) tea.Cmd {
	return func() tea.Msg {
		for _, dep := range missing {
			switch dep {
			case "incus":
				if err := installIncus(); err != nil {
					return installDoneMsg{err: fmt.Errorf("incus install failed: %w", err)}
				}
			case "caddy":
				if err := installCaddy(); err != nil {
					return installDoneMsg{err: fmt.Errorf("caddy install failed: %w", err)}
				}
			case "sshpiperd":
				if err := installSSHPiper(); err != nil {
					return installDoneMsg{err: fmt.Errorf("sshpiperd install failed: %w", err)}
				}
			}
		}
		return installDoneMsg{}
	}
}

func installIncus() error {
	// Add Zabbly GPG key
	if err := os.MkdirAll("/etc/apt/keyrings", 0755); err != nil {
		return err
	}

	resp, err := http.Get("https://pkgs.zabbly.com/key.asc")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	keyData, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := os.WriteFile("/etc/apt/keyrings/zabbly.asc", keyData, 0644); err != nil {
		return err
	}

	// Get OS codename
	osRelease, _ := os.ReadFile("/etc/os-release")
	codename := "noble" // default
	for _, line := range strings.Split(string(osRelease), "\n") {
		if strings.HasPrefix(line, "VERSION_CODENAME=") {
			codename = strings.TrimPrefix(line, "VERSION_CODENAME=")
			break
		}
	}

	// Get architecture
	arch := "amd64"
	out, _ := exec.Command("dpkg", "--print-architecture").Output()
	if len(out) > 0 {
		arch = strings.TrimSpace(string(out))
	}

	// Add Zabbly stable repository
	repoContent := fmt.Sprintf(`Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: %s
Components: main
Architectures: %s
Signed-By: /etc/apt/keyrings/zabbly.asc
`, codename, arch)

	if err := os.WriteFile("/etc/apt/sources.list.d/zabbly-incus-stable.sources", []byte(repoContent), 0644); err != nil {
		return err
	}

	// Update and install
	if err := exec.Command("apt-get", "update").Run(); err != nil {
		return err
	}
	if err := exec.Command("apt-get", "install", "-y", "incus").Run(); err != nil {
		return err
	}

	// Initialize incus
	exec.Command("systemctl", "enable", "--now", "incus").Run()
	time.Sleep(2 * time.Second)
	exec.Command("incus", "admin", "init", "--minimal").Run()

	// Add current user to incus-admin group
	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user != "" && user != "root" {
		exec.Command("usermod", "-aG", "incus-admin", user).Run()
	}

	return nil
}

func installCaddy() error {
	// Install caddy via apt
	exec.Command("apt-get", "update").Run()
	if err := exec.Command("apt-get", "install", "-y", "caddy").Run(); err != nil {
		return err
	}
	exec.Command("systemctl", "enable", "--now", "caddy").Run()
	return nil
}

func installSSHPiper() error {
	// Download sshpiperd from GitHub releases
	arch := "amd64"
	out, _ := exec.Command("uname", "-m").Output()
	if strings.Contains(string(out), "aarch64") || strings.Contains(string(out), "arm64") {
		arch = "arm64"
	}

	url := fmt.Sprintf("https://github.com/tg123/sshpiper/releases/latest/download/sshpiperd_linux_%s.tar.gz", arch)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tmpFile := "/tmp/sshpiperd.tar.gz"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	io.Copy(f, resp.Body)
	f.Close()

	// Extract to /usr/local/bin
	os.MkdirAll("/usr/local/bin", 0755)
	if err := exec.Command("tar", "-xzf", tmpFile, "-C", "/usr/local/bin").Run(); err != nil {
		return err
	}
	os.Chmod("/usr/local/bin/sshpiperd", 0755)

	return nil
}

// Bootstrap: setup services, init DB
func bootstrapCmd() tea.Cmd {
	return func() tea.Msg {
		// Check incus daemon is running
		out, err := exec.Command("incus", "version").CombinedOutput()
		if err != nil || strings.Contains(string(out), "unreachable") {
			// Try to start it
			exec.Command("systemctl", "start", "incus").Run()
			time.Sleep(2 * time.Second)
			out, err = exec.Command("incus", "version").CombinedOutput()
			if err != nil || strings.Contains(string(out), "unreachable") {
				return bootstrapDoneMsg{err: fmt.Errorf("incus daemon not running")}
			}
		}

		// Add ghcr.io OCI registry if not present
		out, _ = exec.Command("incus", "remote", "list", "--format=csv").Output()
		if !strings.Contains(string(out), "ghcr") {
			exec.Command("incus", "remote", "add", "ghcr", "https://ghcr.io", "--protocol=oci").Run()
		}

		// Ensure directories exist
		for _, dir := range []string{CaddyConfDir, SSHPiperRoot, filepath.Dir(DBPath), "/etc/sshpiper"} {
			os.MkdirAll(dir, 0755)
		}

		// Setup Caddy import
		setupCaddy()

		// Setup SSHPiper service
		setupSSHPiperService()

		// Setup sync daemon
		setupSyncDaemon()

		// Open database
		db, err := sql.Open("sqlite", DBPath)
		if err != nil {
			return bootstrapDoneMsg{err: err}
		}

		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS containers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			domain TEXT UNIQUE NOT NULL,
			app_port INTEGER DEFAULT 8000,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
		if err != nil {
			return bootstrapDoneMsg{err: err}
		}

		// Sync configs for all running containers (handles IP changes after reboot)
		syncRunningContainers(db)

		return bootstrapDoneMsg{db: db}
	}
}

// syncRunningContainers updates Caddy and SSHPiper configs for all running containers
// This handles the case where container IPs changed after a reboot
func syncRunningContainers(db *sql.DB) {
	rows, err := db.Query("SELECT name, domain, app_port FROM containers")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name, domain string
		var appPort int
		if err := rows.Scan(&name, &domain, &appPort); err != nil {
			continue
		}

		status, ip, _, _ := getContainerStatus(name)
		if status == "running" && ip != "" {
			updateCaddyConfig(name, domain, ip, appPort)
			configureSSHPiper(name, ip)
		}
	}
}

func setupCaddy() {
	// Ensure Caddy is running (API-based config management)
	exec.Command("systemctl", "enable", "--now", "caddy").Run()
}

func setupSSHPiperService() {
	// Generate server key if not exists
	keyPath := "/etc/sshpiper/server_key"
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "").Run()
	}

	// Write systemd service
	service := `[Unit]
Description=SSHPiper SSH Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sshpiperd -i /etc/sshpiper/server_key workingdir --root /var/lib/sshpiper --no-check-perm
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
	os.WriteFile("/etc/systemd/system/sshpiperd.service", []byte(service), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "--now", "sshpiperd").Run()
}

func setupSyncDaemon() {
	// Check if sync daemon binary exists
	if _, err := os.Stat("/usr/local/bin/incus-sync-daemon"); os.IsNotExist(err) {
		// Try to copy from current directory
		execPath, _ := os.Executable()
		syncPath := filepath.Join(filepath.Dir(execPath), "incus_sync_daemon")
		if _, err := os.Stat(syncPath); err == nil {
			input, _ := os.ReadFile(syncPath)
			os.WriteFile("/usr/local/bin/incus-sync-daemon", input, 0755)
		}
	}

	// Write systemd service
	service := `[Unit]
Description=Incus Container Sync Daemon
After=network.target incus.service
Wants=incus.service

[Service]
Type=simple
ExecStart=/usr/local/bin/incus-sync-daemon
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`
	os.WriteFile("/etc/systemd/system/incus-sync.service", []byte(service), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "--now", "incus-sync").Run()
}

// Container management functions
func (m *model) refreshContainers() tea.Cmd {
	return func() tea.Msg {
		if m.db == nil {
			return containersMsg{}
		}

		rows, err := m.db.Query("SELECT id, name, domain, app_port, created_at FROM containers ORDER BY created_at DESC")
		if err != nil {
			return containersMsg{}
		}
		defer rows.Close()

		var containers []containerEntry
		for rows.Next() {
			var c containerEntry
			var createdAt string
			if err := rows.Scan(&c.ID, &c.Name, &c.Domain, &c.AppPort, &createdAt); err != nil {
				continue
			}
			c.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
			c.Status, c.IP, c.CPU, c.Memory = getContainerStatus(c.Name)
			containers = append(containers, c)
		}
		return containersMsg(containers)
	}
}

func getContainerStatus(name string) (status, ip, cpu, memory string) {
	out, err := exec.Command("incus", "list", name, "--format=json").Output()
	if err != nil {
		return "unknown", "", "N/A", "N/A"
	}

	var list []struct {
		Status string `json:"status"`
		State  struct {
			CPU struct {
				Usage int64 `json:"usage"`
			} `json:"cpu"`
			Memory struct {
				Usage int64 `json:"usage"`
				Total int64 `json:"total"`
			} `json:"memory"`
			Network map[string]struct {
				Addresses []struct {
					Address string `json:"address"`
					Family  string `json:"family"`
				} `json:"addresses"`
			} `json:"network"`
		} `json:"state"`
	}

	if err := json.Unmarshal(out, &list); err != nil || len(list) == 0 {
		return "not found", "", "N/A", "N/A"
	}

	status = strings.ToLower(list[0].Status)
	
	// Get IP
	for _, net := range list[0].State.Network {
		for _, addr := range net.Addresses {
			if addr.Family == "inet" && !strings.HasPrefix(addr.Address, "127.") {
				ip = addr.Address
				break
			}
		}
	}

	// Format CPU (nanoseconds to seconds)
	if list[0].State.CPU.Usage > 0 {
		cpuSec := float64(list[0].State.CPU.Usage) / 1e9
		cpu = fmt.Sprintf("%.1fs", cpuSec)
	} else {
		cpu = "0s"
	}

	// Format Memory (bytes to MB)
	if list[0].State.Memory.Usage > 0 {
		memMB := float64(list[0].State.Memory.Usage) / (1024 * 1024)
		memory = fmt.Sprintf("%.0fMB", memMB)
	} else {
		memory = "0MB"
	}

	return status, ip, cpu, memory
}

func isDomainInUse(db *sql.DB, domain string) bool {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM containers WHERE domain = ?", domain).Scan(&count)
	return count > 0
}

// getIncusContainers returns all container names from Incus API
func getIncusContainers() []string {
	out, err := exec.Command("incus", "query", "/1.0/instances").Output()
	if err != nil {
		return nil
	}
	
	var paths []string
	if err := json.Unmarshal(out, &paths); err != nil {
		return nil
	}
	
	// Extract names from paths like "/1.0/instances/name"
	var names []string
	for _, p := range paths {
		parts := strings.Split(p, "/")
		if len(parts) > 0 {
			names = append(names, parts[len(parts)-1])
		}
	}
	return names
}

// getTrackedContainerNames returns container names from our database
func getTrackedContainerNames(db *sql.DB) []string {
	if db == nil {
		return nil
	}
	rows, err := db.Query("SELECT name FROM containers")
	if err != nil {
		return nil
	}
	defer rows.Close()
	
	var names []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			names = append(names, name)
		}
	}
	return names
}

// getUntrackedContainers returns container names that exist in Incus but not in our DB
func getUntrackedContainers(db *sql.DB) []string {
	incusContainers := getIncusContainers()
	trackedContainers := getTrackedContainerNames(db)
	
	// Create a set of tracked names
	trackedSet := make(map[string]bool)
	for _, name := range trackedContainers {
		trackedSet[name] = true
	}
	
	// Find untracked
	var untracked []string
	for _, name := range incusContainers {
		if !trackedSet[name] {
			untracked = append(untracked, name)
		}
	}
	return untracked
}

func createContainer(db *sql.DB, domain string, appPort int, sshKey string, dnsProvider dnsProvider, dnsToken string, cfProxy bool) error {
	// Validate domain format
	if !isValidDomain(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	// Generate container name from domain
	name := strings.ReplaceAll(domain, ".", "-")
	re := regexp.MustCompile(`[^a-zA-Z0-9-]`)
	name = re.ReplaceAllString(name, "")
	
	// Ensure name doesn't start with a digit (incus requirement)
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "c-" + name
	}
	
	if len(name) > 50 {
		name = name[:50]
	}
	
	// Ensure name doesn't end with hyphen
	name = strings.TrimSuffix(name, "-")

	// Check if container name already exists in incus
	if containerExistsInIncus(name) {
		return fmt.Errorf("container name '%s' already exists", name)
	}

	// STEP 1: Create DNS records FIRST (if provider specified)
	// DNS points to HOST's public IP, gives time for propagation while container starts
	if dnsProvider != dnsNone && dnsToken != "" {
		hostIP := getHostPublicIP()
		if hostIP != "" {
			if err := createDNSRecord(domain, hostIP, dnsProvider, dnsToken, cfProxy); err != nil {
				fmt.Fprintf(os.Stderr, "DNS creation warning: %v\n", err)
			}
			// Also create shelley subdomain (never proxied - needs direct access)
			createDNSRecord("shelley."+domain, hostIP, dnsProvider, dnsToken, false)
		} else {
			fmt.Fprintf(os.Stderr, "DNS warning: could not determine host public IP\n")
		}
	}

	// STEP 2: Launch container from exeuntu OCI image with systemd init
	// boot.autostart ensures container starts on host reboot
	cmd := exec.Command("incus", "launch", ExeuntuImage, name,
		"-c", "security.nesting=true",
		"-c", "boot.autostart=true",
		"-c", "oci.entrypoint=/sbin/init")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create container: %s - %w", string(out), err)
	}

	// Wait for container to start
	time.Sleep(5 * time.Second)

	// STEP 3: Add SSH key to container using file push (safer than shell echo)
	if sshKey != "" {
		exec.Command("incus", "exec", name, "--", "mkdir", "-p", "/home/exedev/.ssh").Run()
		
		// Write key to temp file and push it
		tmpFile, err := os.CreateTemp("", "sshkey")
		if err == nil {
			tmpFile.WriteString(strings.TrimSpace(sshKey) + "\n")
			tmpFile.Close()
			exec.Command("incus", "file", "push", tmpFile.Name(), name+"/home/exedev/.ssh/authorized_keys").Run()
			os.Remove(tmpFile.Name())
		}
		
		exec.Command("incus", "exec", name, "--", "chown", "-R", "exedev:exedev", "/home/exedev/.ssh").Run()
		exec.Command("incus", "exec", name, "--", "chmod", "700", "/home/exedev/.ssh").Run()
		exec.Command("incus", "exec", name, "--", "chmod", "600", "/home/exedev/.ssh/authorized_keys").Run()
	}

	// STEP 4: Get container IP
	_, ip, _, _ := getContainerStatus(name)

	// STEP 5: Save to database AFTER successful container creation
	_, err := db.Exec("INSERT INTO containers (name, domain, app_port) VALUES (?, ?, ?)", name, domain, appPort)
	if err != nil {
		// Rollback: delete the container if DB insert fails
		exec.Command("incus", "delete", name, "--force").Run()
		return fmt.Errorf("failed to save to database: %w", err)
	}

	// STEP 6: Configure Caddy (DNS has had time to propagate during container startup)
	if ip != "" {
		updateCaddyConfig(name, domain, ip, appPort)
	}

	// STEP 7: Configure SSHPiper
	if ip != "" {
		configureSSHPiper(name, ip)
	}

	return nil
}

// isValidDomain checks if domain format is valid
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	// Basic domain validation: alphanumeric, hyphens, dots
	validDomain := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)
	return validDomain.MatchString(domain)
}

// containerExistsInIncus checks if a container with given name exists
func containerExistsInIncus(name string) bool {
	err := exec.Command("incus", "info", name).Run()
	return err == nil
}

// getHostPublicIP returns the host's public IP address
func getHostPublicIP() string {
	// Try multiple services in case one is down
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	
	client := &http.Client{Timeout: 5 * time.Second}
	
	for _, svc := range services {
		resp, err := client.Get(svc)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		
		ip := strings.TrimSpace(string(body))
		// Basic validation - should look like an IP
		if len(ip) > 0 && len(ip) < 50 && !strings.Contains(ip, " ") {
			return ip
		}
	}
	
	return ""
}

// importContainer adds an existing Incus container to our management DB
func importContainer(db *sql.DB, name, domain string, appPort int) error {
	// Verify container exists in Incus
	_, ip, _, _ := getContainerStatus(name)
	if ip == "" {
		// Container might be stopped, try to start it
		exec.Command("incus", "start", name).Run()
		time.Sleep(3 * time.Second)
		_, ip, _, _ = getContainerStatus(name)
	}
	
	// Add to database
	_, err := db.Exec(`INSERT INTO containers (name, domain, app_port, created_at) VALUES (?, ?, ?, datetime('now'))`,
		name, domain, appPort)
	if err != nil {
		return fmt.Errorf("failed to insert: %w", err)
	}
	
	// Configure Caddy and SSHPiper
	if ip != "" {
		updateCaddyConfig(name, domain, ip, appPort)
		configureSSHPiper(name, ip)
	}
	
	// Set boot.autostart if not already set
	exec.Command("incus", "config", "set", name, "boot.autostart=true").Run()
	
	return nil
}

func deleteContainer(db *sql.DB, name string) error {
	exec.Command("incus", "stop", name, "--force").Run()
	if out, err := exec.Command("incus", "delete", name).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete: %s", string(out))
	}

	// Remove Caddy routes via API
	removeCaddyConfig(name)
	
	// Remove SSHPiper config
	os.RemoveAll(filepath.Join(SSHPiperRoot, name))

	_, err := db.Exec("DELETE FROM containers WHERE name = ?", name)
	return err
}

func startContainer(db *sql.DB, name string) error {
	out, err := exec.Command("incus", "start", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", string(out))
	}
	
	// Wait for container to get IP and update Caddy config
	time.Sleep(3 * time.Second)
	_, ip, _, _ := getContainerStatus(name)
	if ip != "" && db != nil {
		var domain string
		var appPort int
		if err := db.QueryRow("SELECT domain, app_port FROM containers WHERE name = ?", name).Scan(&domain, &appPort); err == nil {
			updateCaddyConfig(name, domain, ip, appPort)
			configureSSHPiper(name, ip)
		}
	}
	return nil
}

func stopContainer(name string) error {
	err := exec.Command("incus", "stop", name).Run()
	if err != nil {
		exec.Command("incus", "stop", name, "--force").Run()
	}
	return nil
}

func restartContainer(db *sql.DB, name string) error {
	out, err := exec.Command("incus", "restart", name).CombinedOutput()
	if err != nil {
		out, err = exec.Command("incus", "restart", name, "--force").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", string(out))
		}
	}
	
	// Wait for container to get IP and update Caddy config
	time.Sleep(3 * time.Second)
	_, ip, _, _ := getContainerStatus(name)
	if ip != "" && db != nil {
		var domain string
		var appPort int
		if err := db.QueryRow("SELECT domain, app_port FROM containers WHERE name = ?", name).Scan(&domain, &appPort); err == nil {
			updateCaddyConfig(name, domain, ip, appPort)
			configureSSHPiper(name, ip)
		}
	}
	return nil
}

// DNS functions
func createDNSRecord(domain, ip string, provider dnsProvider, token string, cfProxy bool) error {
	switch provider {
	case dnsCloudflare:
		return createCloudflareDNS(domain, ip, token, cfProxy)
	case dnsDesec:
		return createDesecDNS(domain, ip, token)
	}
	return nil
}

func createCloudflareDNS(domain, ip, token string, proxied bool) error {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid domain")
	}

	zoneName := strings.Join(parts[len(parts)-2:], ".")
	client := &http.Client{Timeout: 10 * time.Second}

	// Get zone ID
	req, _ := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones?name="+zoneName, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var zoneResp struct {
		Result []struct{ ID string `json:"id"` } `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&zoneResp)
	if len(zoneResp.Result) == 0 {
		return fmt.Errorf("zone not found")
	}
	zoneID := zoneResp.Result[0].ID

	// Check if record already exists
	req, _ = http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records?type=A&name="+domain, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var existingResp struct {
		Result []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		} `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&existingResp)

	record := map[string]interface{}{
		"type": "A", "name": domain, "content": ip, "ttl": 300, "proxied": proxied,
	}
	body, _ := json.Marshal(record)

	if len(existingResp.Result) > 0 {
		// Record exists - update it (PUT) if IP is different
		if existingResp.Result[0].Content == ip {
			// Already correct, nothing to do
			return nil
		}
		recordID := existingResp.Result[0].ID
		req, _ = http.NewRequest("PUT", "https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records/"+recordID, bytes.NewReader(body))
	} else {
		// Record doesn't exist - create it (POST)
		req, _ = http.NewRequest("POST", "https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records", bytes.NewReader(body))
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cloudflare error: %s", string(body))
	}
	return nil
}

func createDesecDNS(domain, ip, token string) error {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid domain")
	}

	var zoneName, subname string
	if len(parts) == 2 {
		zoneName = domain
		subname = ""
	} else {
		zoneName = strings.Join(parts[len(parts)-2:], ".")
		subname = strings.Join(parts[:len(parts)-2], ".")
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// deSEC uses PUT for create-or-update (idempotent)
	// PUT to /rrsets/{subname}/{type}/ will create or update
	record := map[string]interface{}{
		"subname": subname, "type": "A", "records": []string{ip}, "ttl": 300,
	}
	body, _ := json.Marshal(record)

	// Build URL for specific RRset
	url := fmt.Sprintf("https://desec.io/api/v1/domains/%s/rrsets/%s/A/", zoneName, subname)
	
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 200 = updated, 201 = created, both are success
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("desec error: %s", string(body))
	}
	return nil
}

func updateCaddyConfig(name, domain, ip string, appPort int) error {
	if ip == "" {
		return fmt.Errorf("no IP address")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	caddyAPI := "http://localhost:2019"

	// Delete existing routes for this container (if any)
	deleteCaddyRoute(client, caddyAPI, name+"-app")
	deleteCaddyRoute(client, caddyAPI, name+"-shelley")

	// Add app route
	appRoute := map[string]interface{}{
		"@id":   name + "-app",
		"match": []map[string]interface{}{{"host": []string{domain}}},
		"handle": []map[string]interface{}{{
			"handler":   "reverse_proxy",
			"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, appPort)}},
		}},
	}
	if err := addCaddyRoute(client, caddyAPI, appRoute); err != nil {
		return fmt.Errorf("failed to add app route: %w", err)
	}

	// Add shelley route
	shelleyRoute := map[string]interface{}{
		"@id":   name + "-shelley",
		"match": []map[string]interface{}{{"host": []string{"shelley." + domain}}},
		"handle": []map[string]interface{}{{
			"handler":   "reverse_proxy",
			"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, ShelleyPort)}},
		}},
	}
	if err := addCaddyRoute(client, caddyAPI, shelleyRoute); err != nil {
		return fmt.Errorf("failed to add shelley route: %w", err)
	}

	return nil
}

func addCaddyRoute(client *http.Client, caddyAPI string, route map[string]interface{}) error {
	body, _ := json.Marshal(route)
	req, _ := http.NewRequest("POST", caddyAPI+"/config/apps/http/servers/srv0/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy API error: %s", string(errBody))
	}
	return nil
}

func deleteCaddyRoute(client *http.Client, caddyAPI, routeID string) {
	req, _ := http.NewRequest("DELETE", caddyAPI+"/id/"+routeID, nil)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func removeCaddyConfig(name string) {
	client := &http.Client{Timeout: 10 * time.Second}
	caddyAPI := "http://localhost:2019"
	deleteCaddyRoute(client, caddyAPI, name+"-app")
	deleteCaddyRoute(client, caddyAPI, name+"-shelley")
}

func updateContainerAppPort(db *sql.DB, name string, newPort int) error {
	var domain string
	if err := db.QueryRow("SELECT domain FROM containers WHERE name = ?", name).Scan(&domain); err != nil {
		return err
	}

	_, ip, _, _ := getContainerStatus(name)
	if ip == "" {
		return fmt.Errorf("container has no IP")
	}

	if err := updateCaddyConfig(name, domain, ip, newPort); err != nil {
		return err
	}

	_, err := db.Exec("UPDATE containers SET app_port = ? WHERE name = ?", newPort, name)
	return err
}

func configureSSHPiper(name, ip string) {
	pDir := filepath.Join(SSHPiperRoot, name)
	os.MkdirAll(pDir, 0700)
	// Map to exedev user on container (where SSH key is installed)
	os.WriteFile(filepath.Join(pDir, "sshpiper_upstream"), []byte("exedev@"+ip+":22\n"), 0600)
}

// Log streaming
func streamLogsCmd(service string) tea.Cmd {
	return func() tea.Msg {
		out, _ := exec.Command("journalctl", "-u", service, "-n", "50", "--no-pager").Output()
		return logMsg(string(out))
	}
}

// TUI Update method
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case installNeededMsg:
		m.missing = msg
		m.state = stateInstalling
		m.status = fmt.Sprintf("Installing: %v", msg)
		return m, installDependenciesCmd(msg)

	case installDoneMsg:
		if msg.err != nil {
			m.status = "Install error: " + msg.err.Error()
			m.state = stateList
			return m, nil
		}
		m.status = "Installation complete"
		return m, checkPrerequisitesCmd()

	case bootstrapDoneMsg:
		if msg.err != nil {
			m.status = "Error: " + msg.err.Error()
			m.state = stateList
			return m, nil
		}
		m.db = msg.db
		m.state = stateList
		return m, tea.Batch(m.refreshContainers(), tickCmd())

	case containersMsg:
		m.containers = msg
		return m, nil

	case logMsg:
		m.logContent = string(msg)
		return m, nil

	case tickMsg:
		if m.state == stateList || m.state == stateContainerDetail {
			return m, tea.Batch(m.refreshContainers(), tickCmd())
		}
		if m.state == stateLogs {
			return m, tea.Batch(streamLogsCmd(m.currentSvc), tickCmd())
		}
		return m, tickCmd()

	case errorMsg:
		m.status = "Error: " + string(msg)
		return m, nil

	case successMsg:
		m.status = string(msg)
		return m, m.refreshContainers()

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if key == "ctrl+c" {
		return m, tea.Quit
	}
	if key == "esc" {
		if m.state != stateList {
			m.state = stateList
			m.textInput.Reset()
			m.editingContainer = nil
			return m, m.refreshContainers()
		}
	}

	switch m.state {
	case stateList:
		return m.handleListKeys(key)
	case stateContainerDetail:
		return m.handleDetailKeys(key)
	case stateCreateDomain, stateCreateDNSToken, stateCreateAppPort, stateCreateSSHKey, stateEditAppPort, stateImportContainer:
		return m.handleInputKeys(key)
	case stateCreateDNSProvider:
		return m.handleDNSProviderKeys(key)
	case stateCreateCFProxy:
		return m.handleCFProxyKeys(key)
	case stateUntracked:
		return m.handleUntrackedKeys(key)
	case stateLogs:
		// Any key returns to list
		if key == "q" || key == "esc" {
			m.state = stateList
			return m, m.refreshContainers()
		}
	}
	return m, nil
}

func (m model) handleListKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.containers)-1 {
			m.cursor++
		}
	case "n":
		m.state = stateCreateDomain
		m.textInput.Placeholder = "example.com or sub.example.com"
		m.textInput.Focus()
		m.newDomain = ""
		m.newDNSProvider = dnsNone
		m.newDNSToken = ""
		m.newAppPort = DefaultAppPort
		m.newSSHKey = ""
	case "enter":
		if len(m.containers) > 0 {
			m.editingContainer = &m.containers[m.cursor]
			m.state = stateContainerDetail
		}
	case "x", "d":
		if len(m.containers) > 0 {
			c := m.containers[m.cursor]
			if err := deleteContainer(m.db, c.Name); err != nil {
				m.status = "Delete failed: " + err.Error()
			} else {
				m.status = "Deleted " + c.Name
				if m.cursor > 0 {
					m.cursor--
				}
			}
			return m, m.refreshContainers()
		}
	case "i":
		m.state = stateLogs
		m.currentSvc = "incus"
		return m, streamLogsCmd("incus")
	case "l":
		// Show log submenu or cycle through services
		m.state = stateLogs
		m.currentSvc = "incus-sync"
		return m, streamLogsCmd("incus-sync")
	case "u":
		// Show untracked containers
		m.untrackedContainers = getUntrackedContainers(m.db)
		if len(m.untrackedContainers) == 0 {
			m.status = "No untracked containers found"
		} else {
			m.state = stateUntracked
			m.cursor = 0
		}
	}
	return m, nil
}

func (m model) handleDetailKeys(key string) (tea.Model, tea.Cmd) {
	if m.editingContainer == nil {
		m.state = stateList
		return m, nil
	}
	c := m.editingContainer

	switch key {
	case "s":
		if c.Status == "running" {
			stopContainer(c.Name)
			m.status = "Stopping " + c.Name
		} else {
			startContainer(m.db, c.Name)
			m.status = "Starting " + c.Name
		}
		return m, m.refreshContainers()
	case "r":
		restartContainer(m.db, c.Name)
		m.status = "Restarting " + c.Name
		return m, m.refreshContainers()
	case "p":
		m.state = stateEditAppPort
		m.textInput.Placeholder = "8000"
		m.textInput.SetValue(fmt.Sprintf("%d", c.AppPort))
		m.textInput.Focus()
	case "q", "esc":
		m.state = stateList
		m.editingContainer = nil
		return m, m.refreshContainers()
	}
	return m, nil
}

func (m model) handleInputKeys(key string) (tea.Model, tea.Cmd) {
	if key != "enter" {
		return m, nil
	}

	val := strings.TrimSpace(m.textInput.Value())

	switch m.state {
	case stateCreateDomain:
		if val == "" {
			m.status = "Domain cannot be empty"
			return m, nil
		}
		if isDomainInUse(m.db, val) {
			m.status = "Domain already in use"
			return m, nil
		}
		m.newDomain = val
		m.state = stateCreateDNSProvider
		m.textInput.Reset()

	case stateCreateDNSToken:
		m.newDNSToken = val
		m.state = stateCreateAppPort
		m.textInput.Placeholder = "8000"
		m.textInput.SetValue("8000")

	case stateCreateAppPort:
		port := DefaultAppPort
		if val != "" {
			fmt.Sscanf(val, "%d", &port)
		}
		m.newAppPort = port
		m.state = stateCreateSSHKey
		m.textInput.Placeholder = "ssh-ed25519 AAAA..."
		m.textInput.Reset()

	case stateCreateSSHKey:
		if val == "" {
			m.status = "SSH key required"
			return m, nil
		}
		m.newSSHKey = val
		m.status = "Creating container..."
		err := createContainer(m.db, m.newDomain, m.newAppPort, m.newSSHKey, m.newDNSProvider, m.newDNSToken, m.newCFProxy)
		if err != nil {
			m.status = "Create failed: " + err.Error()
		} else {
			m.status = "Created container for " + m.newDomain
		}
		m.state = stateList
		m.textInput.Reset()
		return m, m.refreshContainers()

	case stateEditAppPort:
		port := DefaultAppPort
		fmt.Sscanf(val, "%d", &port)
		if m.editingContainer != nil {
			err := updateContainerAppPort(m.db, m.editingContainer.Name, port)
			if err != nil {
				m.status = "Update failed: " + err.Error()
			} else {
				m.status = "Updated port to " + val
			}
		}
		m.state = stateContainerDetail
		m.textInput.Reset()
		return m, m.refreshContainers()
	
	case stateImportContainer:
		if val == "" {
			m.status = "Domain cannot be empty"
			return m, nil
		}
		if m.cursor < len(m.untrackedContainers) {
			containerName := m.untrackedContainers[m.cursor]
			err := importContainer(m.db, containerName, val, DefaultAppPort)
			if err != nil {
				m.status = "Import failed: " + err.Error()
			} else {
				m.status = fmt.Sprintf("Imported %s as %s", containerName, val)
			}
		}
		m.state = stateList
		m.textInput.Reset()
		return m, m.refreshContainers()
	}
	return m, nil
}

func (m model) handleDNSProviderKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "1":
		m.newDNSProvider = dnsNone
		m.state = stateCreateAppPort
		m.textInput.Placeholder = "8000"
		m.textInput.SetValue("8000")
		m.textInput.Focus()
	case "2":
		m.newDNSProvider = dnsCloudflare
		m.newCFProxy = false // Default to no proxy (DNS-only)
		m.state = stateCreateCFProxy
	case "3":
		m.newDNSProvider = dnsDesec
		m.state = stateCreateDNSToken
		m.textInput.Placeholder = "deSEC API Token"
		m.textInput.Focus()
	}
	return m, nil
}

func (m model) handleCFProxyKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "1", "n", "N":
		m.newCFProxy = false
		m.state = stateCreateDNSToken
		m.textInput.Placeholder = "Cloudflare API Token"
		m.textInput.Focus()
	case "2", "y", "Y":
		m.newCFProxy = true
		m.state = stateCreateDNSToken
		m.textInput.Placeholder = "Cloudflare API Token"
		m.textInput.Focus()
	}
	return m, nil
}

func (m model) handleUntrackedKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.state = stateList
		return m, m.refreshContainers()
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.untrackedContainers)-1 {
			m.cursor++
		}
	case "enter", "i":
		// Import the selected container
		if m.cursor < len(m.untrackedContainers) {
			m.state = stateImportContainer
			m.textInput.Placeholder = "domain.com"
			m.textInput.Focus()
		}
	}
	return m, nil
}

// TUI View method
func (m model) View() string {
	switch m.state {
	case stateLoading:
		return "🔄 Checking prerequisites..."

	case stateInstalling:
		return fmt.Sprintf("📥 Installing dependencies...\n\nMissing: %v\n\nPlease wait...", m.missing)

	case stateCreateDomain:
		return "📦 CREATE NEW CONTAINER\n\nEnter domain (e.g., app.example.com):\n\n" + m.textInput.View() + "\n\n[Enter] Continue  [Esc] Cancel"

	case stateCreateDNSProvider:
		return fmt.Sprintf("📦 CREATE: %s\n\nAuto-create DNS record?\n\n[1] No - I'll configure DNS manually\n[2] Cloudflare\n[3] deSEC\n\n[Esc] Cancel", m.newDomain)

	case stateCreateCFProxy:
		return fmt.Sprintf("📦 CREATE: %s\n\nEnable Cloudflare proxy (orange cloud)?\n\n[1] No  - DNS only (recommended for SSH/non-HTTP)\n[2] Yes - Proxy through Cloudflare (HTTP/HTTPS only)\n\n[Esc] Cancel", m.newDomain)

	case stateCreateDNSToken:
		provider := "Cloudflare"
		if m.newDNSProvider == dnsDesec {
			provider = "deSEC"
		}
		return fmt.Sprintf("📦 CREATE: %s\n\nEnter %s API Token:\n\n%s\n\n[Enter] Continue  [Esc] Cancel", m.newDomain, provider, m.textInput.View())

	case stateCreateAppPort:
		return fmt.Sprintf("📦 CREATE: %s\n\nApp port (default 8000):\n\n%s\n\n[Enter] Continue  [Esc] Cancel", m.newDomain, m.textInput.View())

	case stateCreateSSHKey:
		return fmt.Sprintf("📦 CREATE: %s\n\nSSH Public Key:\n\n%s\n\n[Enter] Create  [Esc] Cancel", m.newDomain, m.textInput.View())

	case stateEditAppPort:
		return fmt.Sprintf("✏️  EDIT APP PORT\n\nNew port:\n\n%s\n\n[Enter] Save  [Esc] Cancel", m.textInput.View())

	case stateUntracked:
		return m.viewUntracked()

	case stateImportContainer:
		if m.cursor < len(m.untrackedContainers) {
			return fmt.Sprintf("📥 IMPORT CONTAINER: %s\n\nEnter domain to associate:\n\n%s\n\n[Enter] Import  [Esc] Cancel",
				m.untrackedContainers[m.cursor], m.textInput.View())
		}
		return "No container selected"

	case stateLogs:
		return fmt.Sprintf("📜 LOGS: %s  [Esc] Back\n%s\n\n%s", m.currentSvc, strings.Repeat("─", 60), m.logContent)

	case stateContainerDetail:
		return m.viewContainerDetail()

	default:
		return m.viewList()
	}
}

func (m model) viewList() string {
	s := "🐧 INCUS CONTAINER MANAGER\n"
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += "[n] New  [Enter] Details  [d] Delete  [u] Untracked  [i] Incus Logs  [l] Sync Logs  [q] Quit\n\n"

	if len(m.containers) == 0 {
		s += "  No containers. Press [n] to create one.\n"
	} else {
		s += fmt.Sprintf("  %-22s %-14s %-8s %-6s %-6s %-5s %s\n", "DOMAIN", "IP", "STATUS", "CPU", "MEM", "PORT", "CREATED")
		s += "  " + strings.Repeat("─", 85) + "\n"
		for i, c := range m.containers {
			cursor := "  "
			if i == m.cursor {
				cursor = "▶ "
			}
			created := c.CreatedAt.Format("2006-01-02")
			s += fmt.Sprintf("%s%-22s %-14s %-8s %-6s %-6s %-5d %s\n", cursor, truncate(c.Domain, 21), c.IP, c.Status, c.CPU, c.Memory, c.AppPort, created)
		}
	}

	if m.status != "" {
		s += "\n📋 " + m.status
	}
	return s
}

func (m model) viewUntracked() string {
	s := "🔍 UNTRACKED CONTAINERS\n"
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += "These containers exist in Incus but are not managed by incus_manager.\n"
	s += "[Enter/i] Import  [Esc] Back\n\n"

	if len(m.untrackedContainers) == 0 {
		s += "  No untracked containers found.\n"
	} else {
		for i, name := range m.untrackedContainers {
			status, ip, _, _ := getContainerStatus(name)
			cursor := "  "
			if i == m.cursor {
				cursor = "▶ "
			}
			s += fmt.Sprintf("%s%-30s  %-10s  %s\n", cursor, name, status, ip)
		}
	}

	if m.status != "" {
		s += "\n" + m.status
	}
	return s
}

func (m model) viewContainerDetail() string {
	if m.editingContainer == nil {
		return "No container selected"
	}
	c := m.editingContainer
	c.Status, c.IP, c.CPU, c.Memory = getContainerStatus(c.Name)

	s := fmt.Sprintf("🔍 CONTAINER: %s\n", c.Name)
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += fmt.Sprintf("  Domain:     %s\n", c.Domain)
	s += fmt.Sprintf("  Status:     %s\n", c.Status)
	s += fmt.Sprintf("  IP:         %s\n", c.IP)
	s += fmt.Sprintf("  CPU:        %s\n", c.CPU)
	s += fmt.Sprintf("  Memory:     %s\n", c.Memory)
	s += fmt.Sprintf("  App Port:   %d\n", c.AppPort)
	s += fmt.Sprintf("  Created:    %s\n", c.CreatedAt.Format("2006-01-02 15:04:05"))
	s += "\n"
	s += fmt.Sprintf("  🌐 App URL:     https://%s\n", c.Domain)
	s += fmt.Sprintf("  🤖 Shelley URL: https://shelley.%s\n", c.Domain)
	s += fmt.Sprintf("  🔑 SSH:         ssh -l %s <host> (via sshpiper on port 22)\n", c.Name)
	s += "\n"
	s += "───────────────────────────────────────────────────────────────────────────────\n"
	s += "[s] Start/Stop  [r] Restart  [p] Change Port  [Esc] Back\n"

	if m.status != "" {
		s += "\n📋 " + m.status
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-2] + ".."
}

func main() {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
