package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	_ "modernc.org/sqlite"
)

// Configuration
const (
	CaddyConfDir   = "/etc/caddy/conf.d"
	SSHPiperRoot   = "/var/lib/sshpiper"
	DBPath         = "/var/lib/vibebin/containers.db"
	PIDFile        = "/var/run/vibebin.pid"
	DefaultAppPort = 8000
	CodeUIPort     = 9999 // opencode/nanocode web UI port
	AdminPort      = 8099 // AI tools admin app port
)

// Container image options
type containerImage int

const (
	imageUbuntu containerImage = iota
	imageDebian
)

func (i containerImage) String() string {
	switch i {
	case imageUbuntu:
		return "images:ubuntu/noble" // Ubuntu 24.04 LTS
	case imageDebian:
		return "images:debian/13" // Debian 13 (Trixie)
	}
	return "images:ubuntu/noble"
}

func (i containerImage) User() string {
	switch i {
	case imageUbuntu:
		return "ubuntu"
	case imageDebian:
		return "debian"
	}
	return "ubuntu"
}

func (i containerImage) DisplayName() string {
	switch i {
	case imageUbuntu:
		return "Ubuntu 24.04 LTS (Noble)"
	case imageDebian:
		return "Debian 13 (Trixie)"
	}
	return "Ubuntu 24.04 LTS (Noble)"
}

// State machine for TUI
type viewState int

const (
	stateLoading viewState = iota
	stateInstalling
	stateList
	stateCreateDomain
	stateCreateImage        // Select container image (Ubuntu/Debian)
	stateCreateDNSProvider
	stateCreateDNSToken
	stateCreateCFProxy
	stateCreateAppPort
	stateCreateSSHKey
	stateCreateAuthUser
	stateCreateAuthPass
	stateContainerDetail
	stateEditAppPort
	stateEditAuthUser
	stateEditAuthPass
	stateUpdateTools  // Update opencode/nanocode
	stateLogs
	stateUntracked
	stateImportContainer
	stateImportImage           // Select image for imported container
	stateImportAuthUser
	stateImportAuthPass
	stateSnapshots          // View/manage snapshots
	stateSnapshotCreate     // Create new snapshot (name input)
	stateSnapshotRestore    // Confirm restore from snapshot
	stateSnapshotDelete     // Confirm delete snapshot
	stateDNSTokens          // View/manage DNS API tokens
	stateDNSTokenEdit       // Edit/add DNS token
	stateCreating           // Container creation in progress
	stateConfirmDelete      // Confirm container deletion
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

// Snapshot entry from Incus
type snapshotEntry struct {
	Name      string
	CreatedAt time.Time
	Stateful  bool
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
	createDoneMsg       struct{ err error; name string; output string }    // Container creation completed
	clearStatusMsg      struct{}                                           // Clear status message
	toolsUpdateMsg      struct{ output string; success bool }              // opencode/nanocode update result
)

// TUI Model
type model struct {
	state         viewState
	db            *sql.DB
	containers    []containerEntry
	cursor        int
	textInput     textinput.Model
	status        string
	logContent    string
	currentSvc    string
	missing       []string
	updateOutput  string  // Output from opencode/nanocode update command
	updateSuccess bool    // Whether tools update succeeded

	// Create flow state
	newDomain        string
	newImage         containerImage // Selected container image
	newDNSProvider   dnsProvider
	newDNSToken      string
	newCFProxy       bool // Cloudflare proxy enabled
	newAppPort       int
	newSSHKey        string
	newAuthUser      string
	newAuthPass      string

	// Untracked containers
	untrackedContainers []string

	// Edit state
	editingContainer *containerEntry

	// Snapshot management
	snapshots       []snapshotEntry
	snapshotCursor  int
	newSnapshotName string

	// DNS token editing
	editingDNSProvider dnsProvider

	// Container creation progress
	createOutput string
}

func initialModel() model {
	ti := textinput.New()
	ti.Width = 60
	return model{
		state:     stateLoading,
		textInput: ti,
	}
}

// isInputState returns true if the current state requires text input
func (m model) isInputState() bool {
	switch m.state {
	case stateCreateDomain, stateCreateDNSToken, stateCreateAppPort, stateCreateSSHKey,
		stateCreateAuthUser, stateCreateAuthPass,
		stateEditAppPort, stateEditAuthUser, stateEditAuthPass,
		stateImportContainer, stateImportAuthUser, stateImportAuthPass,
		stateSnapshotCreate, stateDNSTokenEdit:
		return true
	}
	return false
}

func (m model) Init() tea.Cmd {
	return checkPrerequisitesCmd()
}

// isVersionAtLeast checks if version string (e.g., "6.20") is >= major.minor
func isVersionAtLeast(ver string, major, minor int) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 1 {
		return false
	}
	var verMajor, verMinor int
	fmt.Sscanf(parts[0], "%d", &verMajor)
	if len(parts) > 1 {
		fmt.Sscanf(parts[1], "%d", &verMinor)
	}
	if verMajor > major {
		return true
	}
	if verMajor == major && verMinor >= minor {
		return true
	}
	return false
}

func clearStatusAfterDelay() tea.Cmd {
	return tea.Tick(4*time.Second, func(t time.Time) tea.Msg {
		return clearStatusMsg{}
	})
}

func tickCmd() tea.Cmd {
	return tea.Every(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Check what needs to be installed
func checkPrerequisitesCmd() tea.Cmd {
	return func() tea.Msg {
		var missing []string

		// Check incus (need 6.3+ from zabbly for OCI support)
		out, err := exec.Command("incus", "version").CombinedOutput()
		if err != nil || strings.Contains(string(out), "unreachable") || strings.Contains(string(out), "Error") {
			missing = append(missing, "incus")
		} else {
			// Check version - need 6.3+ for OCI image support
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "Client version:") {
					ver := strings.TrimSpace(strings.TrimPrefix(line, "Client version:"))
					if !isVersionAtLeast(ver, 6, 3) {
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
	arch := "x86_64"
	out, _ := exec.Command("uname", "-m").Output()
	if strings.Contains(string(out), "aarch64") || strings.Contains(string(out), "arm64") {
		arch = "arm64"
	}

	url := fmt.Sprintf("https://github.com/tg123/sshpiper/releases/latest/download/sshpiperd_with_plugins_linux_%s.tar.gz", arch)
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

	// Extract to temp directory first
	tmpDir := "/tmp/sshpiper-extract"
	os.RemoveAll(tmpDir)
	os.MkdirAll(tmpDir, 0755)
	if err := exec.Command("tar", "-xzf", tmpFile, "-C", tmpDir).Run(); err != nil {
		return err
	}

	// Copy main binary
	os.MkdirAll("/usr/local/bin", 0755)
	exec.Command("cp", tmpDir+"/sshpiperd", "/usr/local/bin/sshpiperd").Run()
	os.Chmod("/usr/local/bin/sshpiperd", 0755)

	// Copy plugins to /usr/local/bin so they're in PATH
	plugins, _ := filepath.Glob(tmpDir + "/plugins/*")
	for _, p := range plugins {
		dest := "/usr/local/bin/" + filepath.Base(p)
		exec.Command("cp", p, dest).Run()
		os.Chmod(dest, 0755)
	}

	// Cleanup
	os.RemoveAll(tmpDir)
	os.Remove(tmpFile)

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
			auth_user TEXT DEFAULT '',
			auth_hash TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
		if err != nil {
			return bootstrapDoneMsg{err: err}
		}
		// Migration for existing DBs
		db.Exec(`ALTER TABLE containers ADD COLUMN auth_user TEXT DEFAULT ''`)
		db.Exec(`ALTER TABLE containers ADD COLUMN auth_hash TEXT DEFAULT ''`)

		// DNS tokens table
		db.Exec(`CREATE TABLE IF NOT EXISTS dns_tokens (
			provider TEXT PRIMARY KEY,
			token TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)

		// Sync configs for all running containers (handles IP changes after reboot)
		syncRunningContainers(db)

		return bootstrapDoneMsg{db: db}
	}
}

// syncRunningContainers updates Caddy and SSHPiper configs for all running containers
// This handles the case where container IPs changed after a reboot
func syncRunningContainers(db *sql.DB) {
	rows, err := db.Query("SELECT name, domain, app_port, auth_user, auth_hash FROM containers")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name, domain string
		var appPort int
		var authUser, authHash sql.NullString
		if err := rows.Scan(&name, &domain, &appPort, &authUser, &authHash); err != nil {
			continue
		}

		status, ip, _, _ := getContainerStatus(name)
		if status == "running" && ip != "" {
			updateCaddyConfig(name, domain, ip, appPort, authUser.String, authHash.String)
			updateSSHPiperUpstream(name, ip)
		}
	}
}

func setupCaddy() {
	// Ensure Caddy is running (API-based config management)
	exec.Command("systemctl", "enable", "--now", "caddy").Run()
	
	// Configure Caddy server with both HTTP and HTTPS listeners for automatic TLS
	configureCaddyHTTPS()
}

func configureCaddyHTTPS() {
	client := &http.Client{Timeout: 10 * time.Second}
	caddyAPI := "http://localhost:2019"

	// Check if server already has proper listen addresses
	resp, err := client.Get(caddyAPI + "/config/apps/http/servers/srv0")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var serverConfig map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&serverConfig); err != nil {
		return
	}

	// Check if listen addresses include HTTPS (443)
	listen, ok := serverConfig["listen"].([]interface{})
	hasHTTPS := false
	if ok {
		for _, addr := range listen {
			if addrStr, ok := addr.(string); ok && (strings.Contains(addrStr, ":443") || strings.Contains(addrStr, "https")) {
				hasHTTPS = true
				break
			}
		}
	}

	// If already configured with HTTPS, no changes needed
	if hasHTTPS {
		return
	}

	// Set up proper listen addresses for both HTTP and HTTPS
	// This enables automatic HTTPS certificate provisioning
	listenAddrs := []string{":80", ":443"}
	body, _ := json.Marshal(listenAddrs)
	req, _ := http.NewRequest("PATCH", caddyAPI+"/config/apps/http/servers/srv0/listen", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req)
	if err != nil {
		return
	}
	resp2.Body.Close()
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
ExecStart=/usr/local/bin/sshpiperd -p 2222 -i /etc/sshpiper/server_key workingdir --root /var/lib/sshpiper --no-check-perm
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
	// Check if sync daemon binary exists at the expected location
	binaryPath := "/usr/local/bin/vibebin_sync_daemon"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		// Try alternate name
		binaryPath = "/usr/local/bin/vibebin-sync-daemon"
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			// Try to copy from current directory
			execPath, _ := os.Executable()
			syncPath := filepath.Join(filepath.Dir(execPath), "vibebin_sync_daemon")
			if _, err := os.Stat(syncPath); err == nil {
				input, _ := os.ReadFile(syncPath)
				os.WriteFile("/usr/local/bin/vibebin_sync_daemon", input, 0755)
				binaryPath = "/usr/local/bin/vibebin_sync_daemon"
			}
		}
	}

	// Only write/update service file if it doesn't exist yet
	serviceFile := "/etc/systemd/system/vibebin-sync.service"
	if _, err := os.Stat(serviceFile); os.IsNotExist(err) {
		service := `[Unit]
Description=Incus Container Sync Daemon
After=network.target incus.service
Wants=incus.service

[Service]
Type=simple
ExecStart=/usr/local/bin/vibebin_sync_daemon
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`
		os.WriteFile(serviceFile, []byte(service), 0644)
		exec.Command("systemctl", "daemon-reload").Run()
	}

	// Always ensure the service is enabled and started
	exec.Command("systemctl", "enable", "vibebin-sync").Run()
	exec.Command("systemctl", "start", "vibebin-sync").Run()
}

// Container management functions
func (m *model) refreshContainers() tea.Cmd {
	return func() tea.Msg {
		if m.db == nil {
			return containersMsg{}
		}

		rows, err := m.db.Query("SELECT id, name, domain, app_port, COALESCE(created_at, datetime('now')) FROM containers ORDER BY created_at DESC")
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
			// Try multiple date formats
			if t, err := time.Parse("2006-01-02 15:04:05", createdAt); err == nil {
				c.CreatedAt = t
			} else if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
				c.CreatedAt = t
			} else {
				c.CreatedAt = time.Now() // Fallback to now if parsing fails
			}
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
	
	// Get IP - prefer eth0, skip localhost and docker bridge networks
	for netName, net := range list[0].State.Network {
		for _, addr := range net.Addresses {
			if addr.Family == "inet" && 
				!strings.HasPrefix(addr.Address, "127.") &&
				!strings.HasPrefix(addr.Address, "172.17.") && // Docker bridge
				!strings.HasPrefix(addr.Address, "172.18.") { // Docker networks
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
			break // Found eth0 IP, stop looking
		}
	}

	// Format CPU time (nanoseconds to human readable)
	// This is cumulative CPU time used, not current CPU percentage
	if list[0].State.CPU.Usage > 0 {
		cpuSec := float64(list[0].State.CPU.Usage) / 1e9
		if cpuSec >= 3600 {
			cpu = fmt.Sprintf("%.1fh", cpuSec/3600)
		} else if cpuSec >= 60 {
			cpu = fmt.Sprintf("%.1fm", cpuSec/60)
		} else {
			cpu = fmt.Sprintf("%.0fs", cpuSec)
		}
	} else {
		cpu = "0s"
	}

	// Format Memory (bytes to MB/GB)
	// Note: This is total memory usage including buffers/cache
	if list[0].State.Memory.Usage > 0 {
		memMB := float64(list[0].State.Memory.Usage) / (1024 * 1024)
		if memMB >= 1024 {
			memory = fmt.Sprintf("%.1fGB", memMB/1024)
		} else {
			memory = fmt.Sprintf("%.0fMB", memMB)
		}
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

// getContainerOS detects the OS of a container (returns "debian", "ubuntu", or "unknown")
func getContainerOS(containerName string) string {
	// Try to read /etc/os-release from the container
	out, err := exec.Command("incus", "exec", containerName, "--", "cat", "/etc/os-release").Output()
	if err != nil {
		return "unknown"
	}
	osRelease := strings.ToLower(string(out))
	if strings.Contains(osRelease, "id=debian") {
		return "debian"
	}
	if strings.Contains(osRelease, "id=ubuntu") {
		return "ubuntu"
	}
	return "unknown"
}

// createContainerWithProgress creates a container and sends progress updates via channel
func createContainerWithProgress(db *sql.DB, domain string, image containerImage, appPort int, sshKey string, dnsProvider dnsProvider, dnsToken string, cfProxy bool, authUser, authPass string, progress chan<- string) error {
	sendProgress := func(msg string) {
		if progress != nil {
			select {
			case progress <- msg:
			default:
			}
		}
	}

	// Validate domain format
	sendProgress("Validating domain format...")
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
	if dnsProvider != dnsNone && dnsToken != "" {
		sendProgress("Creating DNS records...")
		hostIP := getHostPublicIP()
		if hostIP != "" {
			sendProgress(fmt.Sprintf("Host IP: %s", hostIP))
			
			// Create main domain record
			sendProgress(fmt.Sprintf("Creating A record for %s...", domain))
			if err := createDNSRecord(domain, hostIP, dnsProvider, dnsToken, cfProxy); err != nil {
				sendProgress(fmt.Sprintf("❌ DNS error for %s: %v", domain, err))
			} else {
				sendProgress(fmt.Sprintf("✅ Created: %s -> %s", domain, hostIP))
			}
			
			// Create code subdomain (never proxied - needs direct access for websockets)
			codeDomain := "code." + domain
			sendProgress(fmt.Sprintf("Creating A record for %s...", codeDomain))
			if err := createDNSRecord(codeDomain, hostIP, dnsProvider, dnsToken, false); err != nil {
				sendProgress(fmt.Sprintf("❌ DNS error for %s: %v", codeDomain, err))
			} else {
				sendProgress(fmt.Sprintf("✅ Created: %s -> %s", codeDomain, hostIP))
			}
			
			// Create admin.code subdomain for admin app
			adminDomain := "admin.code." + domain
			sendProgress(fmt.Sprintf("Creating A record for %s...", adminDomain))
			if err := createDNSRecord(adminDomain, hostIP, dnsProvider, dnsToken, false); err != nil {
				sendProgress(fmt.Sprintf("❌ DNS error for %s: %v", adminDomain, err))
			} else {
				sendProgress(fmt.Sprintf("✅ Created: %s -> %s", adminDomain, hostIP))
			}
			
			// Wait for DNS propagation and verify
			sendProgress("Waiting for DNS propagation (5s)...")
			time.Sleep(5 * time.Second)
			
			// Verify DNS records
			sendProgress("Verifying DNS records...")
			mainOK := checkDNSResolvesToHost(domain)
			codeOK := checkDNSResolvesToHost(codeDomain)
			adminOK := checkDNSResolvesToHost(adminDomain)
			if mainOK {
				sendProgress(fmt.Sprintf("✅ DNS verified: %s", domain))
			} else {
				sendProgress(fmt.Sprintf("⚠️ DNS not yet propagated: %s", domain))
			}
			if codeOK {
				sendProgress(fmt.Sprintf("✅ DNS verified: %s", codeDomain))
			} else {
				sendProgress(fmt.Sprintf("⚠️ DNS not yet propagated: %s", codeDomain))
			}
			if adminOK {
				sendProgress(fmt.Sprintf("✅ DNS verified: %s", adminDomain))
			} else {
				sendProgress(fmt.Sprintf("⚠️ DNS not yet propagated: %s", adminDomain))
			}
		} else {
			sendProgress("❌ Could not determine host public IP")
		}
	}

	// STEP 2: Clean up any stale container with same name
	sendProgress("Cleaning up any stale containers...")
	exec.Command("incus", "delete", name, "--force").Run()

	// STEP 3: Launch container from native Incus image
	sendProgress(fmt.Sprintf("Launching container from %s...", image.String()))
	sendProgress("This may take a minute if the image needs to be downloaded...")
	// Note: boot.autostart is intentionally NOT set - when unset, Incus uses "last-state"
	// behavior which restores the container to its previous running/stopped state on daemon restart
	cmd := exec.Command("incus", "launch", image.String(), name,
		"-c", "security.nesting=true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		sendProgress(fmt.Sprintf("Error: %s", string(out)))
		return fmt.Errorf("failed to create container: %s", string(out))
	}
	sendProgress(string(out))

	// Wait for container to start and get basic networking
	sendProgress("Waiting for container to initialize...")
	time.Sleep(5 * time.Second)

	// STEP 4: Configure the container user and install dependencies
	sendProgress("Configuring container user and installing dependencies...")
	containerUser := image.User()
	err = configureContainerEnvironment(name, containerUser, domain, sshKey, sendProgress)
	if err != nil {
		sendProgress(fmt.Sprintf("Warning: Some configuration steps failed: %v", err))
	}

	// STEP 5: Get container IP (SSH key setup is handled by configureSSHPiper later)
	sendProgress("Getting container IP address...")
	_, ip, _, _ := getContainerStatus(name)
	if ip != "" {
		sendProgress(fmt.Sprintf("Container IP: %s", ip))
	} else {
		sendProgress("Warning: Could not get container IP yet")
	}

	// STEP 6: Hash password for basic auth
	sendProgress("Configuring authentication...")
	authHash := ""
	if authUser != "" && authPass != "" {
		hashOut, hashErr := exec.Command("caddy", "hash-password", "--plaintext", authPass).Output()
		if hashErr == nil {
			authHash = strings.TrimSpace(string(hashOut))
		}
	}

	// STEP 8: Save to database
	sendProgress("Saving to database...")
	_, err = db.Exec("INSERT INTO containers (name, domain, app_port, auth_user, auth_hash, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
		name, domain, appPort, authUser, authHash)
	if err != nil {
		sendProgress("Database error, rolling back...")
		exec.Command("incus", "delete", name, "--force").Run()
		return fmt.Errorf("failed to save to database: %w", err)
	}

	// STEP 9: Configure Caddy reverse proxy
	sendProgress("Configuring Caddy reverse proxy...")
	if ip != "" {
		updateCaddyConfig(name, domain, ip, appPort, authUser, authHash)
	}

	// STEP 10: Configure SSHPiper with key mapping
	sendProgress("Configuring SSH routing...")
	if ip != "" {
		configureSSHPiper(name, ip, containerUser, sshKey)
	}

	sendProgress("Container creation complete!")
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

// getHostPublicIP returns the host's public IPv4 address
func getHostPublicIP() string {
	// Try multiple services in case one is down
	// Using IPv4-specific endpoints to avoid issues with cloud providers
	// that may have internal IPs assigned to the main interface
	services := []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://checkip.amazonaws.com",
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

// checkDNSResolvesToHost checks if a domain resolves to the host's public IP
// Returns true if DNS is already correctly configured
func checkDNSResolvesToHost(domain string) bool {
	hostIP := getHostPublicIP()
	if hostIP == "" {
		return false
	}

	// Lookup the domain
	ips, err := net.LookupIP(domain)
	if err != nil {
		return false
	}

	// Check if any resolved IP matches the host IP
	for _, ip := range ips {
		if ip.String() == hostIP {
			return true
		}
	}

	return false
}

// checkAllDNSForDomain checks if the domain resolves correctly to the host IP
// checkAllDNSForDomain checks the main domain, code subdomain, and admin.code subdomain
func checkAllDNSForDomain(domain string) bool {
	mainOK := checkDNSResolvesToHost(domain)
	codeOK := checkDNSResolvesToHost("code." + domain)
	adminOK := checkDNSResolvesToHost("admin.code." + domain)
	return mainOK && codeOK && adminOK
}

// importContainer adds an existing Incus container to our management DB
func importContainer(db *sql.DB, name, domain string, image containerImage, appPort int, authUser, authPass, sshKey string) error {
	// Verify container exists in Incus
	_, ip, _, _ := getContainerStatus(name)
	if ip == "" {
		// Container might be stopped, try to start it
		exec.Command("incus", "start", name).Run()
		time.Sleep(3 * time.Second)
		_, ip, _, _ = getContainerStatus(name)
	}

	// Hash password for basic auth (used by Caddy)
	authHash := ""
	if authUser != "" && authPass != "" {
		hashOut, hashErr := exec.Command("caddy", "hash-password", "--plaintext", authPass).Output()
		if hashErr == nil {
			authHash = strings.TrimSpace(string(hashOut))
		}
	}

	// Add to database
	_, err := db.Exec(`INSERT INTO containers (name, domain, app_port, auth_user, auth_hash, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		name, domain, appPort, authUser, authHash)
	if err != nil {
		return fmt.Errorf("failed to insert: %w", err)
	}

	// Configure Caddy and SSHPiper
	containerUser := image.User()
	if ip != "" {
		updateCaddyConfig(name, domain, ip, appPort, authUser, authHash)
		configureSSHPiper(name, ip, containerUser, sshKey)
	}

	// Configure the container environment (user, Docker, Go, Node, opencode, nanocode)
	silentProgress := func(msg string) {} // Silent for imports
	configureContainerEnvironment(name, containerUser, domain, sshKey, silentProgress)

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

// Snapshot management functions
func listSnapshots(containerName string) []snapshotEntry {
	out, err := exec.Command("incus", "snapshot", "list", containerName, "--format", "json").Output()
	if err != nil {
		return nil
	}

	var snapshots []struct {
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
		Stateful  bool   `json:"stateful"`
	}
	if err := json.Unmarshal(out, &snapshots); err != nil {
		return nil
	}

	result := make([]snapshotEntry, 0, len(snapshots))
	for _, s := range snapshots {
		created, _ := time.Parse(time.RFC3339, s.CreatedAt)
		result = append(result, snapshotEntry{
			Name:      s.Name,
			CreatedAt: created,
			Stateful:  s.Stateful,
		})
	}
	return result
}

func createSnapshot(containerName, snapshotName string) error {
	out, err := exec.Command("incus", "snapshot", "create", containerName, snapshotName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", string(out))
	}
	return nil
}

func restoreSnapshot(containerName, snapshotName string) error {
	// Stop container first for clean restore
	exec.Command("incus", "stop", containerName, "--force").Run()
	
	out, err := exec.Command("incus", "snapshot", "restore", containerName, snapshotName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", string(out))
	}
	
	// Start container back up
	exec.Command("incus", "start", containerName).Run()
	return nil
}

func deleteSnapshot(containerName, snapshotName string) error {
	out, err := exec.Command("incus", "snapshot", "delete", containerName, snapshotName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", string(out))
	}
	return nil
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
		var authUser, authHash sql.NullString
		if err := db.QueryRow("SELECT domain, app_port, auth_user, auth_hash FROM containers WHERE name = ?", name).Scan(&domain, &appPort, &authUser, &authHash); err == nil {
			updateCaddyConfig(name, domain, ip, appPort, authUser.String, authHash.String)
			updateSSHPiperUpstream(name, ip)
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
		var authUser, authHash sql.NullString
		if err := db.QueryRow("SELECT domain, app_port, auth_user, auth_hash FROM containers WHERE name = ?", name).Scan(&domain, &appPort, &authUser, &authHash); err == nil {
			updateCaddyConfig(name, domain, ip, appPort, authUser.String, authHash.String)
			updateSSHPiperUpstream(name, ip)
		}
	}
	return nil
}

// DNS token management
func getDNSToken(db *sql.DB, provider dnsProvider) string {
	var providerName string
	switch provider {
	case dnsCloudflare:
		providerName = "cloudflare"
	case dnsDesec:
		providerName = "desec"
	default:
		return ""
	}
	var token string
	db.QueryRow("SELECT token FROM dns_tokens WHERE provider = ?", providerName).Scan(&token)
	return token
}

func saveDNSToken(db *sql.DB, provider dnsProvider, token string) error {
	var providerName string
	switch provider {
	case dnsCloudflare:
		providerName = "cloudflare"
	case dnsDesec:
		providerName = "desec"
	default:
		return fmt.Errorf("unknown provider")
	}
	_, err := db.Exec(`INSERT OR REPLACE INTO dns_tokens (provider, token, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`,
		providerName, token)
	return err
}

func deleteDNSToken(db *sql.DB, provider dnsProvider) error {
	var providerName string
	switch provider {
	case dnsCloudflare:
		providerName = "cloudflare"
	case dnsDesec:
		providerName = "desec"
	default:
		return fmt.Errorf("unknown provider")
	}
	_, err := db.Exec("DELETE FROM dns_tokens WHERE provider = ?", providerName)
	return err
}

func providerName(p dnsProvider) string {
	switch p {
	case dnsCloudflare:
		return "Cloudflare"
	case dnsDesec:
		return "deSEC"
	default:
		return "None"
	}
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

func updateCaddyConfig(name, domain, ip string, appPort int, authUser, authHash string) error {
	if ip == "" {
		return fmt.Errorf("no IP address")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	caddyAPI := "http://localhost:2019"

	// Remove default catch-all route if present (route at index 0 with no host matcher)
	// This route from the default Caddyfile catches all requests before our host-specific routes
	removeDefaultCatchAllRoute(client, caddyAPI)

	// Delete existing routes for this container (if any)
	deleteCaddyRoute(client, caddyAPI, name+"-app")
	deleteCaddyRoute(client, caddyAPI, name+"-code")
	deleteCaddyRoute(client, caddyAPI, name+"-admin")

	// Add app route (public access to the container's app)
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

	// Build code UI route handlers (for opencode/nanocode web UI)
	var codeHandlers []map[string]interface{}

	// Add basic auth handler if credentials are set
	if authUser != "" && authHash != "" {
		authHandler := map[string]interface{}{
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
		}
		codeHandlers = append(codeHandlers, authHandler)
	}

	// Add reverse proxy handler for opencode/nanocode web UI
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
	if err := addCaddyRoute(client, caddyAPI, codeRoute); err != nil {
		return fmt.Errorf("failed to add code route: %w", err)
	}

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
	if err := addCaddyRoute(client, caddyAPI, adminRoute); err != nil {
		return fmt.Errorf("failed to add admin route: %w", err)
	}

	return nil
}

// removeDefaultCatchAllRoute removes the default file_server route that has no host matcher
// This route catches all requests and prevents our host-specific routes from working
func removeDefaultCatchAllRoute(client *http.Client, caddyAPI string) {
	// Get current routes
	resp, err := client.Get(caddyAPI + "/config/apps/http/servers/srv0/routes")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var routes []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return
	}

	// Find and remove routes with no host matcher (catch-all routes)
	// We iterate backwards to safely remove by index
	for i := len(routes) - 1; i >= 0; i-- {
		route := routes[i]
		// Check if route has no "match" field or empty match (catches all)
		if _, hasMatch := route["match"]; !hasMatch {
			// This is a catch-all route, remove it by index
			req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/config/apps/http/servers/srv0/routes/%d", caddyAPI, i), nil)
			delResp, err := client.Do(req)
			if err == nil {
				delResp.Body.Close()
			}
		}
	}
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
	deleteCaddyRoute(client, caddyAPI, name+"-code")
	deleteCaddyRoute(client, caddyAPI, name+"-admin")
}

func updateContainerAppPort(db *sql.DB, name string, newPort int) error {
	var domain string
	var authUser, authHash sql.NullString
	if err := db.QueryRow("SELECT domain, auth_user, auth_hash FROM containers WHERE name = ?", name).Scan(&domain, &authUser, &authHash); err != nil {
		return err
	}

	_, ip, _, _ := getContainerStatus(name)
	if ip == "" {
		return fmt.Errorf("container has no IP")
	}

	if err := updateCaddyConfig(name, domain, ip, newPort, authUser.String, authHash.String); err != nil {
		return err
	}

	_, err := db.Exec("UPDATE containers SET app_port = ? WHERE name = ?", newPort, name)
	return err
}

func updateContainerAuth(db *sql.DB, name, newUser, newPass string) error {
	var domain string
	var appPort int
	if err := db.QueryRow("SELECT domain, app_port FROM containers WHERE name = ?", name).Scan(&domain, &appPort); err != nil {
		return err
	}

	_, ip, _, _ := getContainerStatus(name)
	if ip == "" {
		return fmt.Errorf("container has no IP")
	}

	// Hash the new password
	authHash := ""
	if newUser != "" && newPass != "" {
		hashOut, hashErr := exec.Command("caddy", "hash-password", "--plaintext", newPass).Output()
		if hashErr != nil {
			return fmt.Errorf("failed to hash password: %w", hashErr)
		}
		authHash = strings.TrimSpace(string(hashOut))
	}

	// Update Caddy config with new auth
	if err := updateCaddyConfig(name, domain, ip, appPort, newUser, authHash); err != nil {
		return err
	}

	// Update database
	_, err := db.Exec("UPDATE containers SET auth_user = ?, auth_hash = ? WHERE name = ?", newUser, authHash, name)
	return err
}

// updateSSHPiperUpstream updates just the upstream IP (for IP changes after reboot)
// Note: This reads the existing upstream file to preserve the username
func updateSSHPiperUpstream(name, ip string) {
	pDir := filepath.Join(SSHPiperRoot, name)
	os.MkdirAll(pDir, 0700)
	
	// Try to read existing upstream to get the username
	upstreamPath := filepath.Join(pDir, "sshpiper_upstream")
	username := "ubuntu" // default
	if existing, err := os.ReadFile(upstreamPath); err == nil {
		// Parse existing: "user@ip:port"
		parts := strings.SplitN(string(existing), "@", 2)
		if len(parts) > 0 && parts[0] != "" {
			username = strings.TrimSpace(parts[0])
		}
	}
	os.WriteFile(upstreamPath, []byte(username+"@"+ip+":22\n"), 0600)
}

// configureSSHPiper sets up full SSHPiper config including key mapping for public key auth
func configureSSHPiper(name, ip, containerUser, userPublicKey string) {
	pDir := filepath.Join(SSHPiperRoot, name)
	os.MkdirAll(pDir, 0700)
	
	// Map to container user (ubuntu or debian)
	os.WriteFile(filepath.Join(pDir, "sshpiper_upstream"), []byte(containerUser+"@"+ip+":22\n"), 0600)
	
	// For public key auth, SSHPiper needs:
	// 1. authorized_keys - client's public key (to verify incoming connection)
	// 2. id_rsa - mapping private key (to authenticate with upstream/container)
	// The container needs the public key corresponding to id_rsa
	
	idRsaPath := filepath.Join(pDir, "id_rsa")
	idRsaPubPath := filepath.Join(pDir, "id_rsa.pub")
	
	// Generate mapping keypair if it doesn't exist
	if _, err := os.Stat(idRsaPath); os.IsNotExist(err) {
		exec.Command("ssh-keygen", "-t", "rsa", "-b", "4096", "-f", idRsaPath, "-N", "", "-C", "sshpiper-"+name).Run()
		os.Chmod(idRsaPath, 0600)
	}
	
	// Put user's public key in authorized_keys (for SSHPiper to verify client)
	if userPublicKey != "" {
		os.WriteFile(filepath.Join(pDir, "authorized_keys"), []byte(strings.TrimSpace(userPublicKey)+"\n"), 0600)
	}
	
	// Append the mapping public key to the container's authorized_keys
	// (don't overwrite - the user's key may already be there from configureContainerEnvironment)
	userHome := "/home/" + containerUser
	if pubKey, err := os.ReadFile(idRsaPubPath); err == nil {
		// Create .ssh directory on container if it doesn't exist
		exec.Command("incus", "exec", name, "--", "mkdir", "-p", userHome+"/.ssh").Run()
		
		// Write mapping public key to a temp file and append to authorized_keys
		tmpPubKey, err := os.CreateTemp("", "sshpiper_pubkey")
		if err == nil {
			tmpPubKey.Write(pubKey)
			tmpPubKey.Close()
			// Push to container
			exec.Command("incus", "file", "push", tmpPubKey.Name(), name+"/tmp/sshpiper_mapping_key.pub").Run()
			os.Remove(tmpPubKey.Name())
			// Append to authorized_keys if not already present
			appendCmd := fmt.Sprintf("cat /tmp/sshpiper_mapping_key.pub >> %s/.ssh/authorized_keys && rm /tmp/sshpiper_mapping_key.pub", userHome)
			exec.Command("incus", "exec", name, "--", "sh", "-c", appendCmd).Run()
		}
		
		// Set correct permissions
		exec.Command("incus", "exec", name, "--", "chown", "-R", containerUser+":"+containerUser, userHome+"/.ssh").Run()
		exec.Command("incus", "exec", name, "--", "chmod", "700", userHome+"/.ssh").Run()
		exec.Command("incus", "exec", name, "--", "chmod", "600", userHome+"/.ssh/authorized_keys").Run()
	}
}

// configureContainerEnvironment sets up the container with all required software and configuration
// This includes: user setup, Docker, Go, Node.js, uv, bun, deno, opencode, and nanocode
func configureContainerEnvironment(containerName, containerUser, domain, sshKey string, sendProgress func(string)) error {
	// Helper to run commands in container as root with error handling
	rootExec := func(args ...string) error {
		cmd := exec.Command("incus", append([]string{"exec", containerName, "--"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %s", err, string(out))
		}
		return nil
	}

	// Helper to run commands in container as the container user
	userExec := func(shellCmd string) error {
		cmd := exec.Command("incus", "exec", containerName, "--", "su", "-", containerUser, "-c", shellCmd)
		return cmd.Run()
	}

	userHome := fmt.Sprintf("/home/%s", containerUser)

	// STEP 1: Ensure the container user exists with passwordless sudo
	sendProgress(fmt.Sprintf("Ensuring user '%s' exists with sudo access...", containerUser))
	sendProgress("Installing base packages (this may take a few minutes)...")
	basePackagesScript := `
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
	sudo curl wget git make screen openssh-server unzip jq \
	dnsutils software-properties-common sosreport gnupg dirmngr \
	ripgrep sqlite3 neovim lsof python3-pip python-is-python3 python3-dns \
	tree net-tools file build-essential pipx psmisc bsdmainutils socat rsync \
	binutils dctrl-tools debootstrap lintian quilt devscripts diffstat dpkg-dev \
	lftp ncftp dput python3-debian python3-debianbts python3-distro-info python3-ubuntutools \
	mc byobu tmux man-db manpages manpages-dev htop atop btop iotop ncdu \
	libglib2.0-0 libnss3 libxcomposite1 libxdamage1 libxi6 libxrandr2 libgbm1 libgtk-3-0 \
	fonts-noto-color-emoji fonts-symbola fontconfig imagemagick ffmpeg \
	kitty-terminfo

# Install Debian-specific packages
if grep -q "ID=debian" /etc/os-release; then
	apt-get install -y wtmpdb libpam-wtmpdb lastlog2
	echo "Debian-specific packages installed"
fi

echo "Base packages installed"
`
	if err := runScriptInContainer(containerName, basePackagesScript, "install-base-packages.sh"); err != nil {
		sendProgress(fmt.Sprintf("Warning: Failed to install base packages: %v", err))
	} else {
		sendProgress("✅ Base packages installed")
	}

	// Install GitHub CLI (gh)
	sendProgress("Installing GitHub CLI...")
	ghScript := `
set -e
export DEBIAN_FRONTEND=noninteractive
mkdir -p -m 755 /etc/apt/keyrings
wget -nv -O /tmp/githubcli-archive-keyring.gpg https://cli.github.com/packages/githubcli-archive-keyring.gpg
cat /tmp/githubcli-archive-keyring.gpg | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null
chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
mkdir -p -m 755 /etc/apt/sources.list.d
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
apt-get update
apt-get install -y gh
rm -f /tmp/githubcli-archive-keyring.gpg
echo "GitHub CLI installed"
`
	if err := runScriptInContainer(containerName, ghScript, "install-gh.sh"); err != nil {
		sendProgress(fmt.Sprintf("Warning: GitHub CLI installation failed: %v", err))
	} else {
		sendProgress("✅ GitHub CLI installed")
	}

	// Post-install configuration
	sendProgress("Running post-install configuration...")
	postInstallScript := `
set -e
# Allow non-root users to use ping without sudo
setcap cap_net_raw=+ep /usr/bin/ping || true
# Refresh font cache
fc-cache -f -v > /dev/null 2>&1 || true
# Clean up apt cache
apt-get clean
echo "Post-install configuration complete"
`
	if err := runScriptInContainer(containerName, postInstallScript, "post-install.sh"); err != nil {
		sendProgress(fmt.Sprintf("Warning: Post-install configuration failed: %v", err))
	} else {
		sendProgress("✅ Post-install configuration complete")
	}

	// Install ghostty terminfo (no deb package available)
	sendProgress("Installing ghostty terminfo...")
	ghosttyTerminfo := `#	Reconstructed via infocmp from file: /Applications/Ghostty.app/Contents/Resources/terminfo/78/xterm-ghostty
xterm-ghostty|ghostty|Ghostty,
	am, bce, ccc, hs, km, mc5i, mir, msgr, npc, xenl, AX, Su, Tc, XT, fullkbd,
	colors#256, cols#80, it#8, lines#24, pairs#32767,
	acsc=++\,\,--..00` + "`" + `aaffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz{{||}}~~,
	bel=^G, blink=\E[5m, bold=\E[1m, cbt=\E[Z, civis=\E[?25l,
	clear=\E[H\E[2J, cnorm=\E[?12l\E[?25h, cr=^M,
	csr=\E[%i%p1%d;%p2%dr, cub=\E[%p1%dD, cub1=^H,
	cud=\E[%p1%dB, cud1=^J, cuf=\E[%p1%dC, cuf1=\E[C,
	cup=\E[%i%p1%d;%p2%dH, cuu=\E[%p1%dA, cuu1=\E[A,
	cvvis=\E[?12;25h, dch=\E[%p1%dP, dch1=\E[P, dim=\E[2m,
	dl=\E[%p1%dM, dl1=\E[M, dsl=\E]2;\007, ech=\E[%p1%dX,
	ed=\E[J, el=\E[K, el1=\E[1K, flash=\E[?5h$<100/>\E[?5l,
	fsl=^G, home=\E[H, hpa=\E[%i%p1%dG, ht=^I, hts=\EH,
	ich=\E[%p1%d@, ich1=\E[@, il=\E[%p1%dL, il1=\E[L, ind=^J,
	indn=\E[%p1%dS,
	initc=\E]4;%p1%d;rgb\:%p2%{255}%*%{1000}%/%2.2X/%p3%{255}%*%{1000}%/%2.2X/%p4%{255}%*%{1000}%/%2.2X\E\\,
	invis=\E[8m, kDC=\E[3;2~, kEND=\E[1;2F, kHOM=\E[1;2H,
	kIC=\E[2;2~, kLFT=\E[1;2D, kNXT=\E[6;2~, kPRV=\E[5;2~,
	kRIT=\E[1;2C, kbs=\177, kcbt=\E[Z, kcub1=\EOD, kcud1=\EOB,
	kcuf1=\EOC, kcuu1=\EOA, kdch1=\E[3~, kend=\EOF, kent=\EOM,
	kf1=\EOP, kf10=\E[21~, kf11=\E[23~, kf12=\E[24~,
	kf13=\E[1;2P, kf14=\E[1;2Q, kf15=\E[1;2R, kf16=\E[1;2S,
	kf17=\E[15;2~, kf18=\E[17;2~, kf19=\E[18;2~, kf2=\EOQ,
	kf20=\E[19;2~, kf21=\E[20;2~, kf22=\E[21;2~,
	kf23=\E[23;2~, kf24=\E[24;2~, kf25=\E[1;5P, kf26=\E[1;5Q,
	kf27=\E[1;5R, kf28=\E[1;5S, kf29=\E[15;5~, kf3=\EOR,
	kf30=\E[17;5~, kf31=\E[18;5~, kf32=\E[19;5~,
	kf33=\E[20;5~, kf34=\E[21;5~, kf35=\E[23;5~,
	kf36=\E[24;5~, kf37=\E[1;6P, kf38=\E[1;6Q, kf39=\E[1;6R,
	kf4=\EOS, kf40=\E[1;6S, kf41=\E[15;6~, kf42=\E[17;6~,
	kf43=\E[18;6~, kf44=\E[19;6~, kf45=\E[20;6~,
	kf46=\E[21;6~, kf47=\E[23;6~, kf48=\E[24;6~,
	kf49=\E[1;3P, kf5=\E[15~, kf50=\E[1;3Q, kf51=\E[1;3R,
	kf52=\E[1;3S, kf53=\E[15;3~, kf54=\E[17;3~,
	kf55=\E[18;3~, kf56=\E[19;3~, kf57=\E[20;3~,
	kf58=\E[21;3~, kf59=\E[23;3~, kf6=\E[17~, kf60=\E[24;3~,
	kf61=\E[1;4P, kf62=\E[1;4Q, kf63=\E[1;4R, kf7=\E[18~,
	kf8=\E[19~, kf9=\E[20~, khome=\EOH, kich1=\E[2~,
	kind=\E[1;2B, kmous=\E[<, knp=\E[6~, kpp=\E[5~,
	kri=\E[1;2A, oc=\E]104\007, op=\E[39;49m, rc=\E8,
	rep=%p1%c\E[%p2%{1}%-%db, rev=\E[7m, ri=\EM,
	rin=\E[%p1%dT, ritm=\E[23m, rmacs=\E(B, rmam=\E[?7l,
	rmcup=\E[?1049l, rmir=\E[4l, rmkx=\E[?1l\E>, rmso=\E[27m,
	rmul=\E[24m, rs1=\E]\E\\\Ec, sc=\E7,
	setab=\E[%?%p1%{8}%<%t4%p1%d%e%p1%{16}%<%t10%p1%{8}%-%d%e48;5;%p1%d%;m,
	setaf=\E[%?%p1%{8}%<%t3%p1%d%e%p1%{16}%<%t9%p1%{8}%-%d%e38;5;%p1%d%;m,
	sgr=%?%p9%t\E(0%e\E(B%;\E[0%?%p6%t;1%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;%?%p7%t;8%;m,
	sgr0=\E(B\E[m, sitm=\E[3m, smacs=\E(0, smam=\E[?7h,
	smcup=\E[?1049h, smir=\E[4h, smkx=\E[?1h\E=, smso=\E[7m,
	smul=\E[4m, tbc=\E[3g, tsl=\E]2;, u6=\E[%i%d;%dR, u7=\E[6n,
	u8=\E[?%[;0123456789]c, u9=\E[c, vpa=\E[%i%p1%dd,
	BD=\E[?2004l, BE=\E[?2004h, Clmg=\E[s,
	Cmg=\E[%i%p1%d;%p2%ds, Dsmg=\E[?69l, E3=\E[3J,
	Enmg=\E[?69h, Ms=\E]52;%p1%s;%p2%s\007, PE=\E[201~,
	PS=\E[200~, RV=\E[>c, Se=\E[2 q,
	Setulc=\E[58\:2\:\:%p1%{65536}%/%d\:%p1%{256}%/%{255}%&%d\:%p1%{255}%&%d%;m,
	Smulx=\E[4\:%p1%dm, Ss=\E[%p1%d q,
	Sync=\E[?2026%?%p1%{1}%-%tl%eh%;,
	XM=\E[?1006;1000%?%p1%{1}%=%th%el%;, XR=\E[>0q,
	fd=\E[?1004l, fe=\E[?1004h, kDC3=\E[3;3~, kDC4=\E[3;4~,
	kDC5=\E[3;5~, kDC6=\E[3;6~, kDC7=\E[3;7~, kDN=\E[1;2B,
	kDN3=\E[1;3B, kDN4=\E[1;4B, kDN5=\E[1;5B, kDN6=\E[1;6B,
	kDN7=\E[1;7B, kEND3=\E[1;3F, kEND4=\E[1;4F,
	kEND5=\E[1;5F, kEND6=\E[1;6F, kEND7=\E[1;7F,
	kHOM3=\E[1;3H, kHOM4=\E[1;4H, kHOM5=\E[1;5H,
	kHOM6=\E[1;6H, kHOM7=\E[1;7H, kIC3=\E[2;3~, kIC4=\E[2;4~,
	kIC5=\E[2;5~, kIC6=\E[2;6~, kIC7=\E[2;7~, kLFT3=\E[1;3D,
	kLFT4=\E[1;4D, kLFT5=\E[1;5D, kLFT6=\E[1;6D,
	kLFT7=\E[1;7D, kNXT3=\E[6;3~, kNXT4=\E[6;4~,
	kNXT5=\E[6;5~, kNXT6=\E[6;6~, kNXT7=\E[6;7~,
	kPRV3=\E[5;3~, kPRV4=\E[5;4~, kPRV5=\E[5;5~,
	kPRV6=\E[5;6~, kPRV7=\E[5;7~, kRIT3=\E[1;3C,
	kRIT4=\E[1;4C, kRIT5=\E[1;5C, kRIT6=\E[1;6C,
	kRIT7=\E[1;7C, kUP=\E[1;2A, kUP3=\E[1;3A, kUP4=\E[1;4A,
	kUP5=\E[1;5A, kUP6=\E[1;6A, kUP7=\E[1;7A, kxIN=\E[I,
	kxOUT=\E[O, rmxx=\E[29m, rv=\E\\[[0-9]+;[0-9]+;[0-9]+c,
	setrgbb=\E[48\:2\:%p1%d\:%p2%d\:%p3%dm,
	setrgbf=\E[38\:2\:%p1%d\:%p2%d\:%p3%dm, smxx=\E[9m,
	xm=\E[<%i%p3%d;%p1%d;%p2%d;%?%p4%tM%em%;,
	xr=\EP>\\|[ -~]+a\E\\,
`
	// Write terminfo file and compile it
	tmpTerminfo, err := os.CreateTemp("", "xterm-ghostty.terminfo")
	if err == nil {
		tmpTerminfo.WriteString(ghosttyTerminfo)
		tmpTerminfo.Close()
		exec.Command("incus", "file", "push", tmpTerminfo.Name(), containerName+"/tmp/xterm-ghostty.terminfo").Run()
		os.Remove(tmpTerminfo.Name())
		// Compile the terminfo
		if err := rootExec("tic", "-x", "/tmp/xterm-ghostty.terminfo"); err != nil {
			sendProgress(fmt.Sprintf("Warning: ghostty terminfo compilation failed: %v", err))
		} else {
			rootExec("rm", "/tmp/xterm-ghostty.terminfo")
			sendProgress("✅ ghostty terminfo installed")
		}
	}
	
	// Create user if doesn't exist, add to sudo group
	rootExec("id", containerUser) // Check if exists
	rootExec("usermod", "-aG", "sudo", containerUser)
	
	// Configure passwordless sudo for the user
	sudoersLine := fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL", containerUser)
	sudoersFile := fmt.Sprintf("/etc/sudoers.d/%s", containerUser)
	tmpSudoers, err := os.CreateTemp("", "sudoers")
	if err == nil {
		tmpSudoers.WriteString(sudoersLine + "\n")
		tmpSudoers.Close()
		exec.Command("incus", "file", "push", tmpSudoers.Name(), containerName+sudoersFile).Run()
		rootExec("chmod", "440", sudoersFile)
		os.Remove(tmpSudoers.Name())
	}

	// STEP 2: Configure SSH server security
	sendProgress("Configuring SSH access...")
	rootExec("sed", "-i", "s/^#*PermitRootLogin.*/PermitRootLogin no/", "/etc/ssh/sshd_config")
	rootExec("sed", "-i", "s/^#*PasswordAuthentication.*/PasswordAuthentication no/", "/etc/ssh/sshd_config")
	rootExec("systemctl", "enable", "--now", "ssh")

	// Set up SSH key for the user
	sshDir := userHome + "/.ssh"
	rootExec("mkdir", "-p", sshDir)
	if sshKey != "" {
		tmpKey, err := os.CreateTemp("", "authorized_keys")
		if err == nil {
			tmpKey.WriteString(strings.TrimSpace(sshKey) + "\n")
			tmpKey.Close()
			exec.Command("incus", "file", "push", tmpKey.Name(), containerName+sshDir+"/authorized_keys").Run()
			os.Remove(tmpKey.Name())
		}
	}
	rootExec("chown", "-R", containerUser+":"+containerUser, sshDir)
	rootExec("chmod", "700", sshDir)
	rootExec("chmod", "600", sshDir+"/authorized_keys")

	// STEP 3: Install Docker
	sendProgress("Installing Docker...")
	dockerScript := `
set -e
curl -fsSL https://get.docker.com | sh
echo "Docker installed successfully"
`
	if err := runScriptInContainer(containerName, dockerScript, "install-docker.sh"); err != nil {
		sendProgress(fmt.Sprintf("Warning: Docker installation failed: %v", err))
	} else {
		rootExec("usermod", "-aG", "docker", containerUser)
		sendProgress("✅ Docker installed")
	}

	// STEP 4: Install Go (latest version)
	sendProgress("Installing Go (latest version)...")
	goInstallScript := `
set -e
ARCH=$(uname -m)
case $ARCH in
    x86_64) GOARCH="amd64" ;;
    aarch64|arm64) GOARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

GO_VERSION=$(curl -sL 'https://go.dev/VERSION?m=text' | head -1)
if [ -z "$GO_VERSION" ]; then
    GO_VERSION="go1.23.5"
fi

cd /tmp
curl -sLO "https://go.dev/dl/${GO_VERSION}.linux-${GOARCH}.tar.gz"
rm -rf /usr/local/go
tar -C /usr/local -xzf "${GO_VERSION}.linux-${GOARCH}.tar.gz"
rm -f "${GO_VERSION}.linux-${GOARCH}.tar.gz"
echo "Go ${GO_VERSION} installed successfully"
`
	if err := runScriptInContainer(containerName, goInstallScript, "install-go.sh"); err != nil {
		sendProgress(fmt.Sprintf("Warning: Go installation failed: %v", err))
	} else {
		sendProgress("✅ Go installed")
	}
	userExec("grep -q 'go/bin' ~/.bashrc || echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc")

	// STEP 5: Install Node.js (latest LTS)
	sendProgress("Installing Node.js (latest LTS)...")
	nodeInstallScript := `
set -e
export DEBIAN_FRONTEND=noninteractive
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt-get install -y nodejs
echo "Node.js $(node --version) installed successfully"
`
	if err := runScriptInContainer(containerName, nodeInstallScript, "install-node.sh"); err != nil {
		sendProgress(fmt.Sprintf("Warning: Node.js installation failed: %v", err))
	} else {
		sendProgress("✅ Node.js installed")
	}

	// STEP 6: Install uv (Python package manager)
	sendProgress("Installing uv (Python package manager)...")
	if err := userExec("curl -LsSf https://astral.sh/uv/install.sh | sh"); err != nil {
		sendProgress(fmt.Sprintf("Warning: uv installation failed: %v", err))
	} else {
		sendProgress("✅ uv installed")
	}
	// Add to PATH
	userExec("grep -q '.local/bin' ~/.bashrc || echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc")

	// STEP 7: Install Bun
	sendProgress("Installing Bun...")
	if err := userExec("curl -fsSL https://bun.sh/install | bash"); err != nil {
		sendProgress(fmt.Sprintf("Warning: Bun installation failed: %v", err))
	} else {
		sendProgress("✅ Bun installed")
	}
	// Add to PATH
	userExec("grep -q '.bun/bin' ~/.bashrc || echo 'export PATH=$PATH:$HOME/.bun/bin' >> ~/.bashrc")

	// STEP 8: Install Deno
	sendProgress("Installing Deno...")
	if err := userExec("curl -fsSL https://deno.land/install.sh | sh"); err != nil {
		sendProgress(fmt.Sprintf("Warning: Deno installation failed: %v", err))
	} else {
		sendProgress("✅ Deno installed")
	}
	// Add to PATH
	userExec("grep -q '.deno/bin' ~/.bashrc || echo 'export PATH=$PATH:$HOME/.deno/bin' >> ~/.bashrc")

	// STEP 9: Install opencode
	sendProgress("Installing opencode...")
	if err := userExec("curl -fsSL https://opencode.ai/install | bash"); err != nil {
		sendProgress(fmt.Sprintf("Warning: opencode installation failed: %v", err))
	} else {
		sendProgress("✅ opencode installed")
	}
	// Add opencode to PATH
	userExec("grep -q '.opencode/bin' ~/.bashrc || echo 'export PATH=$PATH:$HOME/.opencode/bin' >> ~/.bashrc")

	// STEP 10: Install nanocode (requires bun to be in PATH)
	sendProgress("Installing nanocode...")
	if err := userExec("export PATH=$PATH:$HOME/.bun/bin && bun i -g nanocode@latest"); err != nil {
		sendProgress(fmt.Sprintf("Warning: nanocode installation failed: %v", err))
	} else {
		sendProgress("✅ nanocode installed")
	}

	// STEP 10b: Build and Install Shelley Web Agent from source (with domain patch)
	sendProgress("Building Shelley Web Agent from source...")
	sendProgress("  (This may take 2-3 minutes)")
	
	// Shelley build script with patches for custom domain support
	shelleyBuildScript := fmt.Sprintf(`#!/bin/bash
set -e

DOMAIN="%s"
BUILD_DIR="/tmp/shelley-build-$$"

echo "Cloning Shelley repository..."
rm -rf "$BUILD_DIR"
git clone --depth 1 https://github.com/boldsoftware/shelley.git "$BUILD_DIR" 2>&1 | tail -2
cd "$BUILD_DIR"

echo "Applying domain patches..."

# Patch server/system_prompt.go - replace the hostname logic
sed -i 's|// Get hostname for exe.dev|// Get hostname - check SHELLEY_DOMAIN env var first\n\tif envDomain := os.Getenv("SHELLEY_DOMAIN"); envDomain != "" {\n\t\tdata.Hostname = envDomain\n\t} else // Get hostname for exe.dev|' server/system_prompt.go

# Patch server/handlers.go - replace the hostname logic  
sed -i 's|// Get hostname (add .exe.xyz suffix if no dots, matching system_prompt.go)|// Get hostname - check SHELLEY_DOMAIN env var first\n\tif envDomain := os.Getenv("SHELLEY_DOMAIN"); envDomain != "" {\n\t\thostname = envDomain\n\t} else // Get hostname (add .exe.xyz suffix if no dots, matching system_prompt.go)|' server/handlers.go

echo "Building UI..."
cd ui
npm install --silent 2>&1 | tail -3
npm run build 2>&1 | tail -3
cd ..

echo "Building Shelley binary..."
/usr/local/go/bin/go build -o /usr/local/bin/shelley ./cmd/shelley 2>&1
chmod 755 /usr/local/bin/shelley

echo "Cleaning up..."
rm -rf "$BUILD_DIR"

echo "Verifying installation..."
/usr/local/bin/shelley version | grep version | head -1

echo "Shelley build complete!"
`, domain)

	tmpBuildScript, _ := os.CreateTemp("", "shelley-build-*.sh")
	tmpBuildScript.WriteString(shelleyBuildScript)
	tmpBuildScript.Close()
	exec.Command("incus", "file", "push", tmpBuildScript.Name(), containerName+"/tmp/build-shelley.sh").Run()
	os.Remove(tmpBuildScript.Name())
	rootExec("chmod", "+x", "/tmp/build-shelley.sh")
	
	// Run the build script
	buildCmd := exec.Command("incus", "exec", containerName, "--", "bash", "/tmp/build-shelley.sh")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		sendProgress(fmt.Sprintf("Warning: Shelley build failed: %v", err))
		sendProgress(string(out))
	} else {
		// Extract version from output
		outStr := string(out)
		if strings.Contains(outStr, "version") {
			sendProgress("✅ Shelley built and installed")
		} else {
			sendProgress("✅ Shelley installed")
		}
	}
	rootExec("rm", "-f", "/tmp/build-shelley.sh")

	// Create start-shelley.sh wrapper script
	startShelleyScript := `#!/bin/bash

# Load environment variables from .shelley_env file
if [ -f ~/.shelley_env ]; then
    set -a
    source ~/.shelley_env
    set +a
else
    echo "Warning: ~/.shelley_env file not found. Shelley may not have access to LLM providers."
    echo "Create ~/.shelley_env with your API keys (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.)"
fi

# Start Shelley (global flags go before the command)
exec /usr/local/bin/shelley serve -port 9999
`
	tmpStartShelley, _ := os.CreateTemp("", "start-shelley-*.sh")
	tmpStartShelley.WriteString(startShelleyScript)
	tmpStartShelley.Close()
	exec.Command("incus", "file", "push", tmpStartShelley.Name(), containerName+"/usr/local/bin/start-shelley.sh").Run()
	os.Remove(tmpStartShelley.Name())
	rootExec("chmod", "755", "/usr/local/bin/start-shelley.sh")
	// Verify start-shelley.sh is executable by user
	checkCmd := exec.Command("incus", "exec", containerName, "--", "ls", "-la", "/usr/local/bin/start-shelley.sh")
	if lsOut, _ := checkCmd.Output(); strings.Contains(string(lsOut), "rwxr-xr-x") {
		sendProgress("✅ start-shelley.sh wrapper created (755)")
	} else {
		sendProgress(fmt.Sprintf("Warning: start-shelley.sh permissions may be incorrect: %s", strings.TrimSpace(string(lsOut))))
	}

	// Create .shelley_env template file for the user
	shelleyEnvTemplate := fmt.Sprintf(`# Shelley Web Agent Configuration
# Replace the placeholder values with your actual API keys.
# Shelley will use these when started via start-shelley.sh
# See: https://github.com/boldsoftware/shelley

# Domain for this container (used by Shelley for App URL display)
SHELLEY_DOMAIN=%s

# Anthropic (Claude)
ANTHROPIC_API_KEY=your-key-here

# OpenAI (GPT-4, etc.)
OPENAI_API_KEY=your-key-here

# Google (Gemini)
GEMINI_API_KEY=your-key-here

# Fireworks AI
FIREWORKS_API_KEY=your-key-here

# Note: You can also configure custom models within Shelley's web UI,
# but doing so switches to "custom model mode" and these env var models
# will no longer be shown.
`, domain)
	tmpShelleyEnv, _ := os.CreateTemp("", "shelley-env-*")
	tmpShelleyEnv.WriteString(shelleyEnvTemplate)
	tmpShelleyEnv.Close()
	exec.Command("incus", "file", "push", tmpShelleyEnv.Name(), containerName+fmt.Sprintf("/home/%s/.shelley_env", containerUser)).Run()
	os.Remove(tmpShelleyEnv.Name())
	// Fix ownership and permissions of .shelley_env
	rootExec("chown", fmt.Sprintf("%s:%s", containerUser, containerUser), fmt.Sprintf("/home/%s/.shelley_env", containerUser))
	rootExec("chmod", "600", fmt.Sprintf("/home/%s/.shelley_env", containerUser))
	// Verify .shelley_env ownership
	ownerCheckCmd := exec.Command("incus", "exec", containerName, "--", "stat", "-c", "%U", fmt.Sprintf("/home/%s/.shelley_env", containerUser))
	if ownerOut, _ := ownerCheckCmd.Output(); strings.TrimSpace(string(ownerOut)) == containerUser {
		sendProgress("✅ .shelley_env template created")
	} else {
		sendProgress("Warning: .shelley_env created but ownership may be incorrect")
	}

	// STEP 10c: Create project directories for AI coding tools
	sendProgress("Creating project directory...")
	userExec("mkdir -p ~/projects")
	sendProgress("✅ Project directory created")

	// STEP 10d: Setup AI Tools Admin webapp
	sendProgress("Setting up AI Tools Admin webapp...")
	
	// Create admin.code directory structure
	userExec("mkdir -p ~/admin.code/templates ~/admin.code/static ~/admin.code/logs")
	
	// Write domain config
	exec.Command("incus", "exec", containerName, "--", "bash", "-c", 
		fmt.Sprintf("echo '%s' > /home/%s/admin.code/.domain", domain, containerUser)).Run()

	// The admin app source files will be written and compiled
	// Write main.go
	adminMainGo := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	WebUIPort   = 9999
	AdminPort   = 8099
	LogFile     = "ai-tools.log"
	MaxLogLines = 500
	ProjectsDir = "projects"
)

type Tool struct {
	Name        string ` + "`json:\"name\"`" + `
	DisplayName string ` + "`json:\"displayName\"`" + `
	Active      bool   ` + "`json:\"active\"`" + `
}

type AppState struct {
	mu            sync.RWMutex
	activeTool    string
	activeProcess *exec.Cmd
	activePID     int
	homeDir       string
	domain        string
}

var state = &AppState{}

func main() {
	currentUser, _ := user.Current()
	state.homeDir = currentUser.HomeDir
	state.domain = os.Getenv("CONTAINER_DOMAIN")
	if state.domain == "" {
		data, _ := os.ReadFile(filepath.Join(state.homeDir, "admin.code", ".domain"))
		state.domain = strings.TrimSpace(string(data))
	}
	os.MkdirAll(filepath.Join(state.homeDir, ProjectsDir), 0755)
	os.MkdirAll(filepath.Join(state.homeDir, "admin.code", "logs"), 0755)
	state.detectActiveTool()
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/toggle", handleToggle)
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/update", handleUpdate)
	http.HandleFunc("/api/dns-check", handleDNSCheck)
	fmt.Printf("Admin app on port %d, domain: %s\n", AdminPort, state.domain)
	http.ListenAndServe(fmt.Sprintf(":%d", AdminPort), nil)
}

func (s *AppState) detectActiveTool() {
	s.mu.Lock()
	defer s.mu.Unlock()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", WebUIPort), time.Second)
	if err != nil { s.activeTool = ""; return }
	conn.Close()
	// Check which process is actually listening on the port using lsof
	out, _ := exec.Command("bash", "-c", "lsof -i :9999 -t 2>/dev/null | head -1 | xargs -r ps -p -o comm= 2>/dev/null").Output()
	procName := strings.TrimSpace(string(out))
	if strings.Contains(procName, "shelley") { s.activeTool = "shelley"; return }
	if strings.Contains(procName, "opencode") { s.activeTool = "opencode"; return }
	if strings.Contains(procName, "nanocode") || strings.Contains(procName, "bun") { s.activeTool = "nanocode"; return }
	// Fallback: check running processes
	out, _ = exec.Command("bash", "-c", "pgrep -af 'opencode serve|nanocode serve|shelley serve' 2>/dev/null | head -1").Output()
	if strings.Contains(string(out), "shelley") { s.activeTool = "shelley" }
	if strings.Contains(string(out), "opencode") { s.activeTool = "opencode" }
	if strings.Contains(string(out), "nanocode") { s.activeTool = "nanocode" }
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.New("index").Parse(indexHTML)
	tmpl.Execute(w, map[string]string{
		"Domain": state.domain, "AppURL": "https://" + state.domain,
		"CodeURL": "https://code." + state.domain, "AdminURL": "https://admin.code." + state.domain,
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	at := state.activeTool
	state.mu.RUnlock()
	go state.detectActiveTool()
	tools := []Tool{
		{Name: "opencode", DisplayName: "OpenCode", Active: at == "opencode"},
		{Name: "nanocode", DisplayName: "NanoCode", Active: at == "nanocode"},
		{Name: "shelley", DisplayName: "Shelley", Active: at == "shelley"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"tools": tools, "activeTool": at})
}

func handleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Error(w, "Method not allowed", 405); return }
	var req struct { Tool string ` + "`json:\"tool\"`" + `; Action string ` + "`json:\"action\"`" + ` }
	json.NewDecoder(r.Body).Decode(&req)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.activeTool != "" { stopTool(state.activeTool); state.activeTool = ""; state.activeProcess = nil; state.activePID = 0 }
	if req.Action == "start" && req.Tool != "" {
		if err := startTool(req.Tool); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		state.activeTool = req.Tool
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "activeTool": state.activeTool})
}

func startTool(tool string) error {
	logPath := filepath.Join(state.homeDir, "admin.code", "logs", LogFile)
	logFile, _ := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	fmt.Fprintf(logFile, "\n=== Starting %s at %s ===\n", tool, time.Now().Format("2006-01-02 15:04:05"))
	var cmd *exec.Cmd
	proj := filepath.Join(state.homeDir, ProjectsDir)
	switch tool {
	case "opencode": cmd = exec.Command("bash", "-c", fmt.Sprintf("cd %s && %s/.opencode/bin/opencode serve --port %d --hostname 0.0.0.0", proj, state.homeDir, WebUIPort))
	case "nanocode": cmd = exec.Command("bash", "-c", fmt.Sprintf("cd %s && %s/.bun/bin/nanocode serve --port %d --hostname 0.0.0.0", proj, state.homeDir, WebUIPort))
	case "shelley":
		cmd = exec.Command("bash", "-c", fmt.Sprintf("cd %s && /usr/local/bin/start-shelley.sh", proj))
		fmt.Fprintf(logFile, "Note: Shelley requires API keys in ~/.shelley_env\n")
	default: logFile.Close(); return fmt.Errorf("unknown tool: %s", tool)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, _ := cmd.StdoutPipe(); stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil { logFile.Close(); return err }
	state.activeProcess = cmd; state.activePID = cmd.Process.Pid
	go func() { defer logFile.Close(); multi := io.MultiReader(stdout, stderr); sc := bufio.NewScanner(multi); for sc.Scan() { fmt.Fprintf(logFile, "%s\n", sc.Text()) } }()
	go func() { cmd.Wait(); state.mu.Lock(); if state.activeProcess == cmd { state.activeTool = ""; state.activeProcess = nil; state.activePID = 0 }; state.mu.Unlock() }()
	return nil
}

func stopTool(tool string) {
	logPath := filepath.Join(state.homeDir, "admin.code", "logs", LogFile)
	logFile, _ := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	defer logFile.Close()
	fmt.Fprintf(logFile, "\n=== Stopping %s at %s ===\n", tool, time.Now().Format("2006-01-02 15:04:05"))
	if state.activeProcess != nil && state.activePID > 0 { syscall.Kill(-state.activePID, syscall.SIGTERM); time.Sleep(500*time.Millisecond); syscall.Kill(-state.activePID, syscall.SIGKILL) }
	switch tool {
	case "shelley": exec.Command("pkill", "-f", "shelley serve").Run()
	default: exec.Command("pkill", "-f", tool+" serve").Run()
	}
	fmt.Fprintf(logFile, "=== %s stopped ===\n", tool)
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	logPath := filepath.Join(state.homeDir, "admin.code", "logs", LogFile)
	file, err := os.Open(logPath)
	lines := []string{}
	if err == nil { defer file.Close(); sc := bufio.NewScanner(file); for sc.Scan() { lines = append(lines, sc.Text()); if len(lines) > MaxLogLines { lines = lines[1:] } } }
	if len(lines) == 0 { lines = []string{"No logs yet. Start a tool to see output here."} }
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"lines": lines})
}

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Error(w, "Method not allowed", 405); return }
	w.Header().Set("Content-Type", "text/event-stream"); w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)
	send := func(m string) { fmt.Fprintf(w, "data: %s\n\n", m); flusher.Flush() }
	send("🔄 Stopping running processes...")
	state.mu.Lock()
	if state.activeTool != "" { stopTool(state.activeTool); state.activeTool = ""; state.activeProcess = nil; state.activePID = 0 }
	state.mu.Unlock()
	exec.Command("pkill", "-f", "opencode serve").Run(); exec.Command("pkill", "-f", "nanocode serve").Run()
	exec.Command("pkill", "-f", "shelley serve").Run()
	time.Sleep(time.Second)
	send("✅ Processes stopped\n")
	// Get current versions
	currentOpencode, _ := exec.Command("bash", "-c", "$HOME/.opencode/bin/opencode --version 2>/dev/null || echo 'not installed'").Output()
	currentNanocode, _ := exec.Command("bash", "-c", "$HOME/.bun/bin/nanocode --version 2>/dev/null || echo 'not installed'").Output()
	currentShelley, _ := exec.Command("bash", "-c", "/usr/local/bin/shelley version 2>/dev/null | grep '\"version\"' | cut -d'\"' -f4 || echo 'not installed'").Output()
	send(fmt.Sprintf("Current: opencode %s, nanocode %s, shelley %s\n", strings.TrimSpace(string(currentOpencode)), strings.TrimSpace(string(currentNanocode)), strings.TrimSpace(string(currentShelley))))
	send("\n📦 [1/3] Updating opencode...")
	send("Running: curl -fsSL https://opencode.ai/install | bash")
	out, _ := exec.Command("bash", "-c", "curl -fsSL https://opencode.ai/install 2>/dev/null | bash 2>&1 | tail -5").CombinedOutput()
	if len(strings.TrimSpace(string(out))) > 0 { send(string(out)) }
	send("✅ opencode updated\n")
	send("\n📦 [2/3] Updating nanocode...")
	send("Running: bun i -g nanocode@latest")
	out, _ = exec.Command("bash", "-c", "export PATH=$PATH:$HOME/.bun/bin && bun i -g nanocode@latest 2>&1 | grep -v '^$'").CombinedOutput()
	if len(strings.TrimSpace(string(out))) > 0 { send(string(out)) }
	send("✅ nanocode updated\n")
	// Get latest Shelley version from GitHub
	latestShelley, _ := exec.Command("bash", "-c", "curl -sI https://github.com/boldsoftware/shelley/releases/latest 2>/dev/null | grep -i '^location:' | sed 's|.*/v||' | tr -d '\\r\\n' || echo ''").Output()
	latestShelleyStr := strings.TrimSpace(string(latestShelley))
	currentShelleyStr := strings.TrimSpace(string(currentShelley))
	send(fmt.Sprintf("\n📦 [3/3] Updating Shelley (current: %s, latest: %s)...", currentShelleyStr, latestShelleyStr))
	
	// Get SHELLEY_DOMAIN from .shelley_env
	domainBytes, _ := exec.Command("bash", "-c", "grep '^SHELLEY_DOMAIN=' ~/.shelley_env 2>/dev/null | cut -d'=' -f2 || echo ''").Output()
	shelleyDomain := strings.TrimSpace(string(domainBytes))
	if shelleyDomain == "" {
		shelleyDomain = "localhost"
	}
	
	// Shelley build script (rebuilds from source with domain patch)
	shelleyBuildScript := "#!/bin/bash\nset -e\nDOMAIN=\"" + shelleyDomain + "\"\nBUILD_DIR=\"/tmp/shelley-build-$$\"\n" +
		"echo \"Cloning Shelley...\"\n" +
		"rm -rf \"$BUILD_DIR\"\n" +
		"git clone --depth 1 https://github.com/boldsoftware/shelley.git \"$BUILD_DIR\" 2>&1 | tail -1\n" +
		"cd \"$BUILD_DIR\"\n" +
		"echo \"Patching for custom domain...\"\n" +
		"sed -i 's|// Get hostname for exe.dev|// Get hostname - check SHELLEY_DOMAIN env var first\\n\\tif envDomain := os.Getenv(\"SHELLEY_DOMAIN\"); envDomain != \"\" {\\n\\t\\tdata.Hostname = envDomain\\n\\t} else // Get hostname for exe.dev|' server/system_prompt.go\n" +
		"sed -i 's|// Get hostname (add .exe.xyz suffix if no dots, matching system_prompt.go)|// Get hostname - check SHELLEY_DOMAIN env var first\\n\\tif envDomain := os.Getenv(\"SHELLEY_DOMAIN\"); envDomain != \"\" {\\n\\t\\thostname = envDomain\\n\\t} else // Get hostname (add .exe.xyz suffix if no dots, matching system_prompt.go)|' server/handlers.go\n" +
		"echo \"Building UI...\"\n" +
		"cd ui && npm install --silent 2>&1 | tail -1 && npm run build 2>&1 | tail -1 && cd ..\n" +
		"echo \"Building binary...\"\n" +
		"sudo /usr/local/go/bin/go build -o /usr/local/bin/shelley ./cmd/shelley 2>&1\n" +
		"sudo chmod 755 /usr/local/bin/shelley\n" +
		"rm -rf \"$BUILD_DIR\"\n" +
		"/usr/local/bin/shelley version | grep version\n" +
		"echo \"Done!\"\n"
	
	if latestShelleyStr != "" && currentShelleyStr != latestShelleyStr && currentShelleyStr != "not installed" {
		send("Rebuilding from source (this may take 1-2 minutes)...")
		out, err := exec.Command("bash", "-c", shelleyBuildScript).CombinedOutput()
		outLines := strings.Split(string(out), "\n")
		for _, line := range outLines {
			if strings.TrimSpace(line) != "" { send(line) }
		}
		if err != nil {
			send(fmt.Sprintf("Error: %v", err))
		} else {
			verify, _ := exec.Command("bash", "-c", "/usr/local/bin/shelley version 2>/dev/null | grep '\"version\"' | cut -d'\"' -f4").Output()
			if v := strings.TrimSpace(string(verify)); v != "" {
				send(fmt.Sprintf("✅ Shelley updated to %s\n", v))
			} else {
				send("✅ Shelley updated\n")
			}
		}
	} else if currentShelleyStr == latestShelleyStr {
		send("Already at latest version\n")
	} else {
		send("Building from source (this may take 1-2 minutes)...")
		out, err := exec.Command("bash", "-c", shelleyBuildScript).CombinedOutput()
		outLines := strings.Split(string(out), "\n")
		for _, line := range outLines {
			if strings.TrimSpace(line) != "" { send(line) }
		}
		if err != nil {
			send(fmt.Sprintf("Error: %v", err))
		} else {
			verify, _ := exec.Command("bash", "-c", "/usr/local/bin/shelley version 2>/dev/null | grep '\"version\"' | cut -d'\"' -f4").Output()
			if v := strings.TrimSpace(string(verify)); v != "" {
				send(fmt.Sprintf("✅ Shelley installed (version %s)\n", v))
			} else {
				send("✅ Shelley installed\n")
			}
		}
	}
	send("\n🎉 All updates complete!"); send("DONE")
}

func handleDNSCheck(w http.ResponseWriter, r *http.Request) {
	results := map[string]bool{}
	for _, d := range []string{state.domain, "code." + state.domain, "admin.code." + state.domain} { _, err := net.LookupHost(d); results[d] = err == nil }
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

var indexHTML = ` + "`" + `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Tools Admin</title>
<style>:root{--bg:#0f0f0f;--bg2:#1a1a1a;--bg3:#252525;--txt:#fff;--txt2:#a0a0a0;--acc:#6366f1;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444;--bdr:#333}*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--txt);min-height:100vh}.c{max-width:800px;margin:0 auto;padding:2rem}h1{font-size:1.75rem;margin-bottom:.5rem;background:linear-gradient(135deg,var(--acc),#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.links{display:flex;justify-content:center;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap}.lbtn{display:inline-flex;align-items:center;gap:.5rem;padding:.5rem 1rem;background:var(--bg2);border:1px solid var(--bdr);border-radius:8px;color:var(--txt);text-decoration:none;font-size:.875rem}.lbtn:hover{background:var(--bg3);border-color:var(--acc)}.dns-ok{color:var(--ok)}.dns-fail{color:var(--err)}.mt{display:flex;justify-content:center;margin-bottom:2rem}.tc{display:flex;background:var(--bg2);border-radius:12px;padding:4px;border:1px solid var(--bdr)}.tb{padding:.75rem 2rem;border:none;background:transparent;color:var(--txt2);font-size:.9rem;font-weight:500;cursor:pointer;border-radius:8px}.tb.active{background:var(--acc);color:#fff}.sec{display:none}.sec.active{display:block}.card{background:var(--bg2);border:1px solid var(--bdr);border-radius:12px;padding:1.25rem;margin-bottom:1rem;display:flex;align-items:center;justify-content:space-between}.card:hover{border-color:var(--acc)}.card.active{border-color:var(--ok);background:rgba(34,197,94,.1)}.ti{display:flex;align-items:center;gap:1rem}.icon{width:40px;height:40px;background:var(--bg3);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.25rem}.tn{font-weight:600;font-size:1.1rem}.ts{font-size:.8rem;color:var(--txt2)}.ts.run{color:var(--ok)}.sw{position:relative;width:52px;height:28px}.sw input{opacity:0;width:0;height:0}.sl{position:absolute;cursor:pointer;inset:0;background:var(--bg3);border-radius:28px;transition:.3s;border:1px solid var(--bdr)}.sl:before{position:absolute;content:"";height:20px;width:20px;left:3px;bottom:3px;background:var(--txt2);border-radius:50%;transition:.3s}input:checked+.sl{background:var(--ok);border-color:var(--ok)}input:checked+.sl:before{transform:translateX(24px);background:#fff}input:disabled+.sl{opacity:.5;cursor:not-allowed}.ls{margin-top:2rem}.lh{display:flex;justify-content:space-between;margin-bottom:.75rem}.lt{font-size:.9rem;color:var(--txt2);font-weight:500}.lv{background:var(--bg2);border:1px solid var(--bdr);border-radius:12px;padding:1rem;height:300px;overflow-y:auto;font-family:monospace;font-size:.8rem}.ll{color:var(--txt2);white-space:pre-wrap;word-break:break-all}.ll.hi{color:var(--acc)}.ll.ok{color:var(--ok)}.ll.er{color:var(--err)}.us{text-align:center}.uw{background:rgba(245,158,11,.1);border:1px solid var(--warn);border-radius:12px;padding:1.5rem;margin-bottom:2rem;text-align:left}.uw h3{color:var(--warn);margin-bottom:.75rem;font-size:1rem}.uw ul{color:var(--txt2);margin-left:1.5rem;font-size:.9rem}.uw li{margin-bottom:.5rem}.ub{background:var(--acc);color:#fff;border:none;padding:1rem 2rem;font-size:1rem;font-weight:600;border-radius:10px;cursor:pointer}.ub:hover{background:#818cf8}.ub:disabled{opacity:.5;cursor:not-allowed}.up{margin-top:2rem;display:none}.up.active{display:block}.sp{display:inline-block;width:16px;height:16px;border:2px solid var(--bdr);border-top-color:var(--acc);border-radius:50%;animation:spin 1s linear infinite;margin-right:.5rem}@keyframes spin{to{transform:rotate(360deg)}}footer{text-align:center;margin-top:3rem;padding-top:2rem;border-top:1px solid var(--bdr);color:var(--txt2);font-size:.8rem}footer a{color:var(--acc);text-decoration:none}</style></head>
<body><div class="c"><header style="text-align:center;margin-bottom:2rem"><h1>🤖 AI Tools Admin</h1>
<div class="links"><a href="{{.AppURL}}" target="_blank" class="lbtn">🌐 App URL <span class="dns-ok" id="dns-app"></span></a><a href="{{.CodeURL}}" target="_blank" class="lbtn">💻 GO CODE! <span id="dns-code"></span></a><span class="lbtn" style="cursor:default">⚙️ Admin <span id="dns-admin"></span></span></div></header>
<div class="mt"><div class="tc"><button class="tb active" data-v="manage">MANAGE</button><button class="tb" data-v="update">UPDATE</button></div></div>
<section id="manage-section" class="sec active"><div id="tools"><div class="card" data-t="opencode"><div class="ti"><div class="icon">🔷</div><div><div class="tn">OpenCode</div><div class="ts" id="st-opencode">Stopped</div></div></div><label class="sw"><input type="checkbox" id="tg-opencode" onchange="tog('opencode',this.checked)"><span class="sl"></span></label></div>
<div class="card" data-t="nanocode"><div class="ti"><div class="icon">🟣</div><div><div class="tn">NanoCode</div><div class="ts" id="st-nanocode">Stopped</div></div></div><label class="sw"><input type="checkbox" id="tg-nanocode" onchange="tog('nanocode',this.checked)"><span class="sl"></span></label></div>
<div class="card" data-t="shelley"><div class="ti"><div class="icon">🐚</div><div><div class="tn">Shelley</div><div class="ts" id="st-shelley">Stopped</div></div></div><label class="sw"><input type="checkbox" id="tg-shelley" onchange="tog('shelley',this.checked)"><span class="sl"></span></label></div></div>
<div class="ls"><div class="lh"><span class="lt">📋 Tool Output Log</span></div><div class="lv" id="log"><div class="ll">No logs yet.</div></div></div></section>
<section id="update-section" class="sec"><div class="uw"><h3>⚠️ Before updating</h3><ul><li>Toggle off all tools in MANAGE</li><li>No AI tools running in CLI</li><li>Update stops running processes</li><li>Updates OpenCode, NanoCode, Shelley</li></ul></div><button class="ub" id="ubtn" onclick="upd()">🚀 Update All Tools</button><div class="up" id="uprog"><div class="lv" id="ulog"></div></div></section>
<footer>Powered by <a href="https://github.com/jgbrwn/vibebin">vibebin</a></footer></div>
<script>let updating=false;document.querySelectorAll('.tb').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tb').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelectorAll('.sec').forEach(s=>s.classList.remove('active'));document.getElementById(b.dataset.v+'-section').classList.add('active')});
async function fst(){try{const r=await fetch('/api/status'),d=await r.json();d.tools.forEach(t=>{const c=document.querySelector('[data-t="'+t.name+'"]'),g=document.getElementById('tg-'+t.name),s=document.getElementById('st-'+t.name);if(t.active){c.classList.add('active');g.checked=true;s.textContent='Running';s.classList.add('run')}else{c.classList.remove('active');g.checked=false;s.textContent='Stopped';s.classList.remove('run')}})}catch(e){}}
async function tog(t,en){document.querySelectorAll('.sw input').forEach(i=>i.disabled=true);const s=document.getElementById('st-'+t);s.innerHTML=en?'<span class="sp"></span>Starting...':'Stopping...';try{const r=await fetch('/api/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:t,action:en?'start':'stop'})});const d=await r.json();if(!d.success)alert('Error: '+d.error)}catch(e){alert('Failed: '+e)}document.querySelectorAll('.sw input').forEach(i=>i.disabled=false);fst()}
async function flg(){try{const r=await fetch('/api/logs'),d=await r.json(),v=document.getElementById('log');v.innerHTML=d.lines.map(l=>{let c='ll';if(l.includes('===')||l.includes('Starting')||l.includes('Stopping'))c+=' hi';else if(l.includes('✅'))c+=' ok';else if(l.includes('error')||l.includes('Error'))c+=' er';return'<div class="'+c+'">'+esc(l)+'</div>'}).join('');v.scrollTop=v.scrollHeight}catch(e){}}
async function dns(){try{const r=await fetch('/api/dns-check'),d=await r.json();Object.entries(d).forEach(([k,v])=>{let id=k.startsWith('admin.code.')?'dns-admin':k.startsWith('code.')?'dns-code':'dns-app';const e=document.getElementById(id);e.innerHTML=v?'✓':'✗';e.className=v?'dns-ok':'dns-fail';e.title=k+(v?' OK':' fail')})}catch(e){}}
async function upd(){if(updating)return;updating=true;const b=document.getElementById('ubtn'),p=document.getElementById('uprog'),l=document.getElementById('ulog');b.disabled=true;b.innerHTML='<span class="sp"></span>Updating...';p.classList.add('active');l.innerHTML='';try{const r=await fetch('/api/update',{method:'POST'}),rd=r.body.getReader(),dc=new TextDecoder();while(true){const{value,done}=await rd.read();if(done)break;dc.decode(value).split('\n').filter(x=>x.startsWith('data: ')).forEach(x=>{const m=x.replace('data: ','');if(m==='DONE'){updating=false;b.disabled=false;b.textContent='🚀 Update All Tools';return}let c='ll';if(m.includes('📦')||m.includes('🐳'))c+=' hi';else if(m.includes('✅'))c+=' ok';else if(m.includes('⚠️'))c+=' er';l.innerHTML+='<div class="'+c+'">'+esc(m)+'</div>';l.scrollTop=l.scrollHeight})}}catch(e){l.innerHTML+='<div class="ll er">Error: '+e+'</div>';updating=false;b.disabled=false;b.textContent='🚀 Update All Tools'}}
function esc(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML}fst();flg();dns();setInterval(()=>{if(!updating){fst();flg()}},3000)</script></body></html>` + "`" + `
`

	// Write the source file to container
	adminMainPath := fmt.Sprintf("/home/%s/admin.code/main.go", containerUser)
	tmpFile, _ := os.CreateTemp("", "admin-main-*.go")
	tmpFile.WriteString(adminMainGo)
	tmpFile.Close()
	exec.Command("incus", "file", "push", tmpFile.Name(), containerName+adminMainPath).Run()
	os.Remove(tmpFile.Name())

	// Write go.mod
	goMod := "module admin-app\n\ngo 1.21\n"
	goModPath := fmt.Sprintf("/home/%s/admin.code/go.mod", containerUser)
	tmpFile2, _ := os.CreateTemp("", "admin-gomod")
	tmpFile2.WriteString(goMod)
	tmpFile2.Close()
	exec.Command("incus", "file", "push", tmpFile2.Name(), containerName+goModPath).Run()
	os.Remove(tmpFile2.Name())

	// Build the admin app inside container
	sendProgress("Building admin app...")
	adminBuildCmd := fmt.Sprintf("cd /home/%s/admin.code && /usr/local/go/bin/go build -o admin-app .", containerUser)
	if err := rootExec("bash", "-c", adminBuildCmd); err != nil {
		sendProgress(fmt.Sprintf("Warning: Admin app build failed: %v", err))
	} else {
		// Fix ownership
		rootExec("chown", "-R", containerUser+":"+containerUser, fmt.Sprintf("/home/%s/admin.code", containerUser))
		sendProgress("✅ Admin app built")
	}

	// Create systemd service for admin app
	adminService := fmt.Sprintf(`[Unit]
Description=AI Tools Admin Web App
After=network.target docker.service

[Service]
Type=simple
User=%s
Group=%s
WorkingDirectory=/home/%s/admin.code
Environment=HOME=/home/%s
Environment=CONTAINER_DOMAIN=%s
ExecStart=/home/%s/admin.code/admin-app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, containerUser, containerUser, containerUser, containerUser, domain, containerUser)

	tmpService, _ := os.CreateTemp("", "admin-app-*.service")
	tmpService.WriteString(adminService)
	tmpService.Close()
	exec.Command("incus", "file", "push", tmpService.Name(), containerName+"/etc/systemd/system/admin-app.service").Run()
	os.Remove(tmpService.Name())

	// Enable and start the admin app service
	rootExec("systemctl", "daemon-reload")
	rootExec("systemctl", "enable", "admin-app")
	rootExec("systemctl", "start", "admin-app")
	sendProgress("✅ Admin app service started")

	// STEP 11: Configure custom MOTD
	sendProgress("Configuring welcome message (MOTD)...")
	motdScript := fmt.Sprintf(`#!/bin/bash
# incus-manager custom MOTD

# User home directory for tool paths
USER_HOME="/home/%s"

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  Container: %s"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Domain:   https://%s"
echo "  Code UI:  https://code.%s"
echo "  Admin:    https://admin.code.%s"
echo ""
echo "  ─────────────────────────────────────────────────────────────────────────────"
echo "  Installed Tools:"
echo "    • Docker    $(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo 'not found')"
echo "    • Go        $(/usr/local/go/bin/go version 2>/dev/null | awk '{print $3}' | sed 's/go//' || echo 'not found')"
echo "    • Node.js   $(node --version 2>/dev/null || echo 'not found')"
echo "    • Bun       $(${USER_HOME}/.bun/bin/bun --version 2>/dev/null || echo 'not found')"
echo "    • Deno      $(${USER_HOME}/.deno/bin/deno --version 2>/dev/null | head -1 | awk '{print $2}' || echo 'not found')"
echo "    • uv        $(${USER_HOME}/.local/bin/uv --version 2>/dev/null | awk '{print $2}' || echo 'not found')"
echo "    • opencode  $(${USER_HOME}/.opencode/bin/opencode --version 2>/dev/null || echo 'not found')"
echo "    • nanocode  $(${USER_HOME}/.bun/bin/nanocode --version 2>/dev/null || echo 'not found')"
echo "    • shelley   $(/usr/local/bin/shelley version 2>/dev/null | grep version | head -1 | awk -F'"' '{print $4}' || echo 'not found')"
echo ""
echo "  ─────────────────────────────────────────────────────────────────────────────"
echo "  AI Coding Agents:"
echo "    ★ MANAGE ALL TOOLS VIA: https://admin.code.%s"
echo "    Note: Only one web UI can run on port 9999 at a time."
echo ""
echo "    Project directory: ~/projects"
echo ""
echo "    opencode (cd ~/projects first):"
echo "      CLI:    opencode"
echo "      Web UI: opencode serve --port 9999 --hostname 0.0.0.0"
echo ""
echo "    nanocode (cd ~/projects first):"
echo "      CLI:    nanocode"
echo "      Web UI: nanocode serve --port 9999 --hostname 0.0.0.0"
echo "      NOTE:   Web UI requires LLM config first - run 'nanocode' CLI to configure"
echo ""
echo "    shelley (Web UI only - no CLI mode):"
echo "      start-shelley.sh 2>&1 | tee -a ~/.shelley.log"
echo "      NOTE: Add API keys to ~/.shelley_env before starting"
echo "            Custom models can be configured in Shelley's UI,"
echo "            but this disables env var models."
echo ""
echo "    Then access web UI via: https://code.%s"
echo ""
echo "  ─────────────────────────────────────────────────────────────────────────────"
echo "  Documentation: https://github.com/jgbrwn/vibebin"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""
`, containerUser, containerName, domain, domain, domain, domain, domain)
	tmpMotd, _ := os.CreateTemp("", "99-incus-manager")
	tmpMotd.WriteString(motdScript)
	tmpMotd.Close()
	exec.Command("incus", "file", "push", tmpMotd.Name(), containerName+"/etc/update-motd.d/99-incus-manager").Run()
	os.Remove(tmpMotd.Name())
	rootExec("chmod", "+x", "/etc/update-motd.d/99-incus-manager")

	sendProgress("Container environment configuration complete!")
	return nil
}

// runScriptInContainer is a helper to run a script in the container as root
func runScriptInContainer(containerName, script, scriptName string) error {
	tmpScript, err := os.CreateTemp("", scriptName)
	if err != nil {
		return err
	}
	tmpScript.WriteString(script)
	tmpScript.Close()
	defer os.Remove(tmpScript.Name())

	if err := exec.Command("incus", "file", "push", tmpScript.Name(), containerName+"/tmp/"+scriptName).Run(); err != nil {
		return err
	}
	if err := exec.Command("incus", "exec", containerName, "--", "chmod", "+x", "/tmp/"+scriptName).Run(); err != nil {
		return err
	}
	cmd := exec.Command("incus", "exec", containerName, "--", "/tmp/"+scriptName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

// createContainerAsync creates a container asynchronously and returns progress/done messages
func createContainerAsync(db *sql.DB, domain string, image containerImage, appPort int, sshKey string, dnsProvider dnsProvider, dnsToken string, cfProxy bool, authUser, authPass string) tea.Cmd {
	return func() tea.Msg {
		// Create a channel to collect progress messages
		progressChan := make(chan string, 100)
		doneChan := make(chan error, 1)

		// Run creation in background
		go func() {
			err := createContainerWithProgress(db, domain, image, appPort, sshKey, dnsProvider, dnsToken, cfProxy, authUser, authPass, progressChan)
			close(progressChan)
			doneChan <- err
		}()

		// Collect all progress messages
		var output strings.Builder
		for msg := range progressChan {
			output.WriteString(msg)
			output.WriteString("\n")
		}

		err := <-doneChan

		// Generate container name for the done message
		name := strings.ReplaceAll(domain, ".", "-")
		re := regexp.MustCompile(`[^a-zA-Z0-9-]`)
		name = re.ReplaceAllString(name, "")
		if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
			name = "c-" + name
		}
		if len(name) > 50 {
			name = name[:50]
		}
		name = strings.TrimSuffix(name, "-")

		return createDoneMsg{err: err, name: name, output: output.String()}
	}
}

// Log streaming
func streamLogsCmd(service string) tea.Cmd {
	return func() tea.Msg {
		out, _ := exec.Command("journalctl", "-u", service, "-n", "50", "--no-pager").Output()
		return logMsg(string(out))
	}
}

// updateToolsCmd updates opencode and nanocode on a container
func updateToolsCmd(containerName, containerUser string) tea.Cmd {
	return func() tea.Msg {
		result := ""

		// Helper to run commands as user
		userExec := func(cmd string) (string, error) {
			c := exec.Command("incus", "exec", containerName, "--", "su", "-", containerUser, "-c", cmd)
			out, err := c.CombinedOutput()
			return string(out), err
		}

		// Helper to run commands as root in container
		rootExec := func(cmd string) (string, error) {
			c := exec.Command("incus", "exec", containerName, "--", "bash", "-c", cmd)
			out, err := c.CombinedOutput()
			return string(out), err
		}

		// Step 1: Check for running processes
		result += "Checking for running processes...\n"
		runningProcs, _ := rootExec("pgrep -af 'opencode|nanocode|shelley' 2>/dev/null | grep -v pgrep || true")
		if strings.TrimSpace(runningProcs) != "" {
			result += "Found running processes:\n" + runningProcs + "\n"
			result += "Stopping AI coding tool processes...\n"
			rootExec("pkill -f 'opencode serve' 2>/dev/null || true")
			rootExec("pkill -f 'nanocode serve' 2>/dev/null || true")
			rootExec("pkill -f 'shelley serve' 2>/dev/null || true")
			result += "✅ Processes stopped\n"
		} else {
			result += "No running processes found\n"
		}

		// Step 2: Check current versions
		result += "\nChecking current versions...\n"
		
		currentOpencode := strings.TrimSpace(func() string {
			v, _ := userExec("~/.opencode/bin/opencode --version 2>/dev/null || echo 'not installed'")
			return v
		}())
		currentNanocode := strings.TrimSpace(func() string {
			v, _ := userExec("~/.bun/bin/nanocode --version 2>/dev/null || echo 'not installed'")
			return v
		}())
		currentShelley := strings.TrimSpace(func() string {
			v, _ := rootExec("/usr/local/bin/shelley version 2>/dev/null | grep '\"version\"' | cut -d'\"' -f4 || echo 'not installed'")
			return v
		}())
		
		result += fmt.Sprintf("  Current opencode:  %s\n", currentOpencode)
		result += fmt.Sprintf("  Current nanocode:  %s\n", currentNanocode)
		result += fmt.Sprintf("  Current shelley:   %s\n", currentShelley)

		// Step 3: Check latest available versions
		result += "\nChecking latest available versions...\n"
		
		// Get latest opencode version from GitHub API (use jq for reliable parsing)
		latestOpencodeOut, err := exec.Command("bash", "-c", "curl -s https://api.github.com/repos/anomalyco/opencode/releases/latest | jq -r '.tag_name // empty' | sed 's/^v//'").Output()
		latestOpencode := strings.TrimSpace(string(latestOpencodeOut))
		if err != nil || latestOpencode == "" {
			// Fallback to manual parsing if jq fails
			rawOut, _ := exec.Command("curl", "-s", "https://api.github.com/repos/anomalyco/opencode/releases/latest").Output()
			if idx := strings.Index(string(rawOut), `"tag_name": "`); idx >= 0 {
				start := idx + len(`"tag_name": "`)
				end := strings.Index(string(rawOut)[start:], `"`)
				if end > 0 {
					latestOpencode = strings.TrimPrefix(string(rawOut)[start:start+end], "v")
				}
			}
		}
		
		// Get latest nanocode version from GitHub API
		latestNanocodeOut, err := exec.Command("bash", "-c", "curl -s https://api.github.com/repos/nanogpt-community/nanocode/releases/latest | jq -r '.tag_name // empty' | sed 's/^v//'").Output()
		latestNanocode := strings.TrimSpace(string(latestNanocodeOut))
		if err != nil || latestNanocode == "" {
			// Fallback to manual parsing if jq fails
			rawOut, _ := exec.Command("curl", "-s", "https://api.github.com/repos/nanogpt-community/nanocode/releases/latest").Output()
			if idx := strings.Index(string(rawOut), `"tag_name": "`); idx >= 0 {
				start := idx + len(`"tag_name": "`)
				end := strings.Index(string(rawOut)[start:], `"`)
				if end > 0 {
					latestNanocode = strings.TrimPrefix(string(rawOut)[start:start+end], "v")
				}
			}
		}

		// Get latest Shelley version from GitHub releases
		latestShelleyOut, _ := exec.Command("bash", "-c", "curl -sI https://github.com/boldsoftware/shelley/releases/latest 2>/dev/null | grep -i '^location:' | sed 's|.*/v||' | tr -d '\\r\\n'").Output()
		latestShelley := strings.TrimSpace(string(latestShelleyOut))
		
		result += fmt.Sprintf("  Latest opencode:  %s\n", latestOpencode)
		result += fmt.Sprintf("  Latest nanocode:  %s\n", latestNanocode)
		result += fmt.Sprintf("  Latest shelley:   %s\n", latestShelley)

		opencodeNeedsUpdate := latestOpencode != "" && currentOpencode != latestOpencode && currentOpencode != "not installed"
		nanocodeNeedsUpdate := latestNanocode != "" && currentNanocode != latestNanocode && currentNanocode != "not installed"
		shelleyNeedsUpdate := latestShelley != "" && currentShelley != latestShelley && currentShelley != "not installed"
		
		var opencodeErr, nanocodeErr, shelleyErr error

		// Step 4: Update opencode if needed
		if opencodeNeedsUpdate {
			result += fmt.Sprintf("\nUpdating opencode (%s -> %s)...\n", currentOpencode, latestOpencode)
			opencodeOut, err := userExec("curl -fsSL https://opencode.ai/install | bash && ~/.opencode/bin/opencode --version")
			result += opencodeOut
			opencodeErr = err
			if err != nil {
				result += fmt.Sprintf("Warning: opencode update had issues: %v\n", err)
			} else {
				result += "✅ opencode updated\n"
			}
		} else if currentOpencode == "not installed" {
			result += "\nInstalling opencode...\n"
			opencodeOut, err := userExec("curl -fsSL https://opencode.ai/install | bash && ~/.opencode/bin/opencode --version")
			result += opencodeOut
			opencodeErr = err
			if err != nil {
				result += fmt.Sprintf("Warning: opencode install had issues: %v\n", err)
			} else {
				result += "✅ opencode installed\n"
			}
		} else {
			result += fmt.Sprintf("\n✅ opencode is already up to date (%s)\n", currentOpencode)
		}

		// Step 5: Update nanocode if needed
		if nanocodeNeedsUpdate {
			result += fmt.Sprintf("\nUpdating nanocode (%s -> %s)...\n", currentNanocode, latestNanocode)
			nanocodeOut, err := userExec("export PATH=$PATH:$HOME/.bun/bin && bun i -g nanocode@latest && ~/.bun/bin/nanocode --version")
			result += nanocodeOut
			nanocodeErr = err
			if err != nil {
				result += fmt.Sprintf("Warning: nanocode update had issues: %v\n", err)
			} else {
				result += "✅ nanocode updated\n"
			}
		} else if currentNanocode == "not installed" {
			result += "\nInstalling nanocode...\n"
			nanocodeOut, err := userExec("export PATH=$PATH:$HOME/.bun/bin && bun i -g nanocode@latest && ~/.bun/bin/nanocode --version")
			result += nanocodeOut
			nanocodeErr = err
			if err != nil {
				result += fmt.Sprintf("Warning: nanocode install had issues: %v\n", err)
			} else {
				result += "✅ nanocode installed\n"
			}
		} else {
			result += fmt.Sprintf("\n✅ nanocode is already up to date (%s)\n", currentNanocode)
		}

		// Step 6: Update shelley if needed (build from source with domain patch)
		// Get domain from .shelley_env
		domainOut, _ := userExec("grep '^SHELLEY_DOMAIN=' ~/.shelley_env 2>/dev/null | cut -d'=' -f2 || echo ''")
		shelleyDomain := strings.TrimSpace(domainOut)
		if shelleyDomain == "" {
			shelleyDomain = "localhost"
		}
		
		// Shelley build script
		shelleyBuildScript := fmt.Sprintf(`
set -e
DOMAIN="%s"
BUILD_DIR="/tmp/shelley-build-$$"
echo "Cloning Shelley repository..."
rm -rf "$BUILD_DIR"
git clone --depth 1 https://github.com/boldsoftware/shelley.git "$BUILD_DIR" 2>&1 | tail -1
cd "$BUILD_DIR"
echo "Applying domain patches..."
sed -i 's|// Get hostname for exe.dev|// Get hostname - check SHELLEY_DOMAIN env var first\n\tif envDomain := os.Getenv("SHELLEY_DOMAIN"); envDomain != "" {\n\t\tdata.Hostname = envDomain\n\t} else // Get hostname for exe.dev|' server/system_prompt.go
sed -i 's|// Get hostname (add .exe.xyz suffix if no dots, matching system_prompt.go)|// Get hostname - check SHELLEY_DOMAIN env var first\n\tif envDomain := os.Getenv("SHELLEY_DOMAIN"); envDomain != "" {\n\t\thostname = envDomain\n\t} else // Get hostname (add .exe.xyz suffix if no dots, matching system_prompt.go)|' server/handlers.go
echo "Building UI..."
cd ui && npm install --silent 2>&1 | tail -2 && npm run build 2>&1 | tail -2 && cd ..
echo "Building Shelley binary..."
/usr/local/go/bin/go build -o /usr/local/bin/shelley ./cmd/shelley 2>&1
chmod 755 /usr/local/bin/shelley
rm -rf "$BUILD_DIR"
echo "Verifying..."
/usr/local/bin/shelley version | grep version | head -1
`, shelleyDomain)
		
		if shelleyNeedsUpdate {
			result += fmt.Sprintf("\nUpdating shelley (%s -> %s)...\n", currentShelley, latestShelley)
			result += "Building from source (this may take 1-2 minutes)...\n"
			shelleyOut, err := rootExec(shelleyBuildScript)
			result += shelleyOut
			if err != nil {
				result += fmt.Sprintf("Warning: shelley update had issues: %v\n", err)
				shelleyErr = err
			} else {
				verifyOut, _ := rootExec("/usr/local/bin/shelley version 2>/dev/null | grep '\"version\"' | cut -d'\"' -f4")
				if v := strings.TrimSpace(verifyOut); v != "" {
					result += fmt.Sprintf("✅ shelley updated to %s\n", v)
				} else {
					result += "✅ shelley updated\n"
				}
			}
		} else if currentShelley == "not installed" {
			result += "\nInstalling shelley...\n"
			result += "Building from source (this may take 1-2 minutes)...\n"
			shelleyOut, err := rootExec(shelleyBuildScript)
			result += shelleyOut
			if err != nil {
				result += fmt.Sprintf("Warning: shelley install had issues: %v\n", err)
				shelleyErr = err
			} else {
				verifyOut, _ := rootExec("/usr/local/bin/shelley version 2>/dev/null | grep '\"version\"' | cut -d'\"' -f4")
				if v := strings.TrimSpace(verifyOut); v != "" {
					result += fmt.Sprintf("✅ shelley installed (version %s)\n", v)
				} else {
					result += "✅ shelley installed\n"
				}
			}
		} else {
			result += fmt.Sprintf("\n✅ shelley is already up to date (%s)\n", currentShelley)
		}

		if opencodeErr != nil || nanocodeErr != nil || shelleyErr != nil {
			result += "\n⚠️ Update completed with some warnings"
			return toolsUpdateMsg{output: result, success: false}
		}

		if !opencodeNeedsUpdate && !nanocodeNeedsUpdate && !shelleyNeedsUpdate && 
		   currentOpencode != "not installed" && currentNanocode != "not installed" && currentShelley != "not installed" {
			result += "\n✅ All tools are already up to date!"
		} else {
			result += "\n✅ Update check complete!"
		}
		return toolsUpdateMsg{output: result, success: true}
	}
}

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

	case toolsUpdateMsg:
		m.updateOutput = msg.output
		m.updateSuccess = msg.success
		if msg.success {
			m.status = "AI coding tools updated successfully"
		} else {
			m.status = "AI coding tools update had issues"
		}
		return m, clearStatusAfterDelay()

	case createDoneMsg:
		m.createOutput = msg.output
		if msg.err != nil {
			m.status = "Create failed: " + msg.err.Error()
			m.createOutput += "\n❌ " + msg.err.Error()
		} else {
			m.status = "Created container: " + msg.name
			m.createOutput += "\n✅ Container created successfully!"
		}
		// Stay on creating screen so user can see the output
		return m, clearStatusAfterDelay()

	case clearStatusMsg:
		m.status = ""
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
		return m, clearStatusAfterDelay()

	case successMsg:
		m.status = string(msg)
		return m, tea.Batch(m.refreshContainers(), clearStatusAfterDelay())

	case tea.KeyMsg:
		// For text input states, update the text input first, then handle special keys
		if m.isInputState() {
			var cmd tea.Cmd
			m.textInput, cmd = m.textInput.Update(msg)
			// Then handle enter/esc
			newModel, newCmd := m.handleKey(msg)
			if newCmd != nil {
				return newModel, tea.Batch(cmd, newCmd)
			}
			return newModel, cmd
		}
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

	switch m.state {
	case stateList:
		return m.handleListKeys(key)
	case stateContainerDetail:
		return m.handleDetailKeys(key)
	case stateCreateDomain, stateCreateDNSToken, stateCreateAppPort, stateCreateSSHKey, stateCreateAuthUser, stateCreateAuthPass, stateEditAppPort, stateEditAuthUser, stateEditAuthPass, stateImportContainer, stateImportAuthUser, stateImportAuthPass:
		return m.handleInputKeys(key)
	case stateCreateDNSProvider:
		return m.handleDNSProviderKeys(key)
	case stateCreateCFProxy:
		return m.handleCFProxyKeys(key)
	case stateCreateImage:
		return m.handleImageSelectKeys(key)
	case stateImportImage:
		return m.handleImportImageSelectKeys(key)
	case stateUntracked:
		return m.handleUntrackedKeys(key)
	case stateSnapshots:
		return m.handleSnapshotKeys(key)
	case stateSnapshotCreate:
		return m.handleSnapshotCreateKeys(key)
	case stateSnapshotRestore, stateSnapshotDelete:
		return m.handleSnapshotConfirmKeys(key)
	case stateDNSTokens:
		return m.handleDNSTokensKeys(key)
	case stateDNSTokenEdit:
		return m.handleDNSTokenEditKeys(key)
	case stateCreating:
		// Allow dismissing only when creation is complete (has checkmark or X)
		if strings.Contains(m.createOutput, "✅") || strings.Contains(m.createOutput, "❌") {
			if key == "enter" || key == "esc" || key == "q" {
				m.state = stateList
				m.createOutput = ""
				return m, m.refreshContainers()
			}
		}
		return m, nil
	case stateConfirmDelete:
		if len(m.containers) > 0 {
			c := m.containers[m.cursor]
			switch key {
			case "y", "Y":
				if err := deleteContainer(m.db, c.Name); err != nil {
					m.status = "❌ Delete failed: " + err.Error()
				} else {
					m.status = "✅ Deleted " + c.Name
					if m.cursor > 0 {
						m.cursor--
					}
				}
				m.state = stateList
				return m, tea.Batch(m.refreshContainers(), clearStatusAfterDelay())
			case "n", "N", "esc", "q":
				m.state = stateList
			}
		}
		return m, nil
	case stateLogs:
		// Any key returns to list
		if key == "q" || key == "esc" {
			m.state = stateList
			return m, m.refreshContainers()
		}
	case stateUpdateTools:
		// Esc returns to container detail
		if key == "q" || key == "esc" {
			m.state = stateContainerDetail
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
			m.state = stateConfirmDelete
		}
	case "i":
		m.state = stateLogs
		m.currentSvc = "incus"
		return m, streamLogsCmd("incus")
	case "l":
		// Show log submenu or cycle through services
		m.state = stateLogs
		m.currentSvc = "vibebin-sync"
		return m, streamLogsCmd("vibebin-sync")
	case "u":
		// Show untracked containers
		m.untrackedContainers = getUntrackedContainers(m.db)
		if len(m.untrackedContainers) == 0 {
			m.status = "No untracked containers found"
			return m, clearStatusAfterDelay()
		} else {
			m.state = stateUntracked
			m.cursor = 0
		}
	case "D":
		// DNS token management
		m.state = stateDNSTokens
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
			if err := stopContainer(c.Name); err != nil {
				m.status = "❌ Stop failed: " + err.Error()
			} else {
				m.status = "✅ Stopped " + c.Name
			}
		} else {
			if err := startContainer(m.db, c.Name); err != nil {
				m.status = "❌ Start failed: " + err.Error()
			} else {
				m.status = "✅ Started " + c.Name
			}
		}
		return m, tea.Batch(m.refreshContainers(), clearStatusAfterDelay())
	case "r":
		if err := restartContainer(m.db, c.Name); err != nil {
			m.status = "❌ Restart failed: " + err.Error()
		} else {
			m.status = "✅ Restarted " + c.Name
		}
		return m, tea.Batch(m.refreshContainers(), clearStatusAfterDelay())
	case "p":
		m.state = stateEditAppPort
		m.textInput.Placeholder = "8000"
		m.textInput.SetValue(fmt.Sprintf("%d", c.AppPort))
		m.textInput.Focus()
	case "a":
		// Edit basic auth credentials
		m.state = stateEditAuthUser
		m.textInput.Placeholder = "username"
		// Get current username from DB
		var currentUser sql.NullString
		m.db.QueryRow("SELECT auth_user FROM containers WHERE name = ?", c.Name).Scan(&currentUser)
		if currentUser.String != "" {
			m.textInput.SetValue(currentUser.String)
		} else {
			m.textInput.SetValue("admin")
		}
		m.textInput.Focus()
	case "S":
		// Snapshot management
		m.snapshots = listSnapshots(c.Name)
		m.snapshotCursor = 0
		m.state = stateSnapshots
		return m, nil
	case "u":
		// Update opencode/nanocode on container
		if c.Status != "running" {
			m.status = "Container must be running to update tools"
			return m, clearStatusAfterDelay()
		}
		m.status = "Updating AI coding tools on " + c.Name + "..."
		m.state = stateUpdateTools
		m.updateOutput = "Updating AI coding tools...\n"
		m.updateSuccess = false
		// Determine container user from image (we'll need to get this from DB or assume ubuntu for now)
		containerUser := "ubuntu" // Default assumption
		return m, updateToolsCmd(c.Name, containerUser)
	case "q", "esc":
		m.state = stateList
		m.editingContainer = nil
		return m, m.refreshContainers()
	}
	return m, nil
}

func (m model) handleInputKeys(key string) (tea.Model, tea.Cmd) {
	// Handle Esc to cancel and return to list
	if key == "esc" {
		m.state = stateList
		m.textInput.Reset()
		m.textInput.EchoMode = textinput.EchoNormal
		m.newDomain = ""
		m.newDNSProvider = dnsNone
		m.newDNSToken = ""
		m.newAppPort = 0
		m.newSSHKey = ""
		m.newAuthUser = ""
		m.newAuthPass = ""
		m.status = "Container creation cancelled"
		return m, clearStatusAfterDelay()
	}

	if key != "enter" {
		return m, nil
	}

	val := strings.TrimSpace(m.textInput.Value())

	switch m.state {
	case stateCreateDomain:
		if val == "" {
			m.status = "Domain cannot be empty"
			return m, clearStatusAfterDelay()
		}
		if isDomainInUse(m.db, val) {
			m.status = "Domain already in use"
			return m, clearStatusAfterDelay()
		}
		m.newDomain = val
		
		// Go to image selection
		m.state = stateCreateImage
		m.newImage = imageDebian // Default to Debian
		m.textInput.Reset()

	case stateCreateDNSToken:
		m.newDNSToken = val
		// Save token for future use
		if val != "" {
			saveDNSToken(m.db, m.newDNSProvider, val)
			m.status = fmt.Sprintf("%s token saved", providerName(m.newDNSProvider))
		}
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
			return m, clearStatusAfterDelay()
		}
		m.newSSHKey = val
		m.state = stateCreateAuthUser
		m.textInput.Placeholder = "admin"
		m.textInput.SetValue("admin")

	case stateCreateAuthUser:
		if val == "" {
			m.status = "Username required for basic authentication"
			return m, clearStatusAfterDelay()
		}
		m.newAuthUser = val
		m.state = stateCreateAuthPass
		m.textInput.Placeholder = "password (min 8 chars)"
		m.textInput.Reset()
		m.textInput.EchoMode = textinput.EchoPassword
		m.textInput.EchoCharacter = '*'

	case stateCreateAuthPass:
		if len(val) < 8 {
			m.status = "Password must be at least 8 characters"
			return m, clearStatusAfterDelay()
		}
		m.newAuthPass = val
		m.textInput.EchoMode = textinput.EchoNormal
		// Start container creation directly
		m.createOutput = "Starting container creation and bootstrap...\n"
		m.state = stateCreating
		m.textInput.Reset()
		// Start async creation
		return m, createContainerAsync(m.db, m.newDomain, m.newImage, m.newAppPort, m.newSSHKey, m.newDNSProvider, m.newDNSToken, m.newCFProxy, m.newAuthUser, m.newAuthPass)

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
		return m, tea.Batch(m.refreshContainers(), clearStatusAfterDelay())

	case stateEditAuthUser:
		if val == "" {
			m.status = "Username cannot be empty"
			return m, clearStatusAfterDelay()
		}
		m.newAuthUser = val
		m.state = stateEditAuthPass
		m.textInput.Placeholder = "new password (min 8 chars)"
		m.textInput.Reset()
		m.textInput.EchoMode = textinput.EchoPassword
		m.textInput.EchoCharacter = '*'

	case stateEditAuthPass:
		if len(val) < 8 {
			m.status = "Password must be at least 8 characters"
			return m, clearStatusAfterDelay()
		}
		m.textInput.EchoMode = textinput.EchoNormal
		if m.editingContainer != nil {
			err := updateContainerAuth(m.db, m.editingContainer.Name, m.newAuthUser, val)
			if err != nil {
				m.status = "Update failed: " + err.Error()
			} else {
				m.status = "Updated basic auth credentials"
			}
		}
		m.state = stateContainerDetail
		m.textInput.Reset()
		return m, tea.Batch(m.refreshContainers(), clearStatusAfterDelay())

	case stateImportContainer:
		if val == "" {
			m.status = "Domain cannot be empty"
			return m, clearStatusAfterDelay()
		}
		m.newDomain = val
		
		// Check DNS status and show info
		if checkAllDNSForDomain(val) {
			m.status = "✓ DNS already configured correctly"
		} else {
			m.status = "⚠ DNS not configured - set up DNS records manually after import"
		}
		
		// Skip image selection - OS was auto-detected when container was selected
		// Go directly to auth user input
		m.state = stateImportAuthUser
		m.textInput.Placeholder = "admin"
		m.textInput.SetValue("admin")
		m.textInput.Focus()

	case stateImportAuthUser:
		if val == "" {
			m.status = "Username required"
			return m, clearStatusAfterDelay()
		}
		m.newAuthUser = val
		m.state = stateImportAuthPass
		m.textInput.Placeholder = "password (min 8 chars)"
		m.textInput.Reset()
		m.textInput.EchoMode = textinput.EchoPassword
		m.textInput.EchoCharacter = '*'

	case stateImportAuthPass:
		if len(val) < 8 {
			m.status = "Password must be at least 8 characters"
			return m, clearStatusAfterDelay()
		}
		m.newAuthPass = val
		m.textInput.EchoMode = textinput.EchoNormal
		// Import container directly (no more LLM provider selection)
		if m.cursor < len(m.untrackedContainers) {
			containerName := m.untrackedContainers[m.cursor]
			err := importContainer(m.db, containerName, m.newDomain, m.newImage, DefaultAppPort, m.newAuthUser, m.newAuthPass, m.newSSHKey)
			if err != nil {
				m.status = "Import failed: " + err.Error()
			} else {
				m.status = fmt.Sprintf("Imported %s as %s", containerName, m.newDomain)
			}
		}
		m.state = stateList
		m.textInput.Reset()
		return m, tea.Batch(m.refreshContainers(), clearStatusAfterDelay())
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
		// Check for saved token
		if savedToken := getDNSToken(m.db, dnsDesec); savedToken != "" {
			m.newDNSToken = savedToken
			m.status = "Using saved deSEC token"
			m.state = stateCreateAppPort
			m.textInput.Placeholder = "8000"
			m.textInput.SetValue("8000")
			m.textInput.Focus()
		} else {
			m.state = stateCreateDNSToken
			m.textInput.Placeholder = "deSEC API Token"
			m.textInput.Focus()
		}
	}
	return m, nil
}

func (m model) handleCFProxyKeys(key string) (tea.Model, tea.Cmd) {
	setProxy := func(proxy bool) {
		m.newCFProxy = proxy
		// Check for saved token
		if savedToken := getDNSToken(m.db, dnsCloudflare); savedToken != "" {
			m.newDNSToken = savedToken
			m.status = "Using saved Cloudflare token"
			m.state = stateCreateAppPort
			m.textInput.Placeholder = "8000"
			m.textInput.SetValue("8000")
			m.textInput.Focus()
		} else {
			m.state = stateCreateDNSToken
			m.textInput.Placeholder = "Cloudflare API Token"
			m.textInput.Focus()
		}
	}

	switch key {
	case "1", "n", "N":
		setProxy(false)
	case "2", "y", "Y":
		setProxy(true)
	}
	return m, nil
}

func (m model) handleImageSelectKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "1":
		m.newImage = imageDebian
		// Check if DNS already resolves correctly - skip DNS provider selection if so
		if checkAllDNSForDomain(m.newDomain) {
			m.status = "✓ DNS already configured correctly"
			m.newDNSProvider = dnsNone
			m.newDNSToken = ""
			m.state = stateCreateAppPort
			m.textInput.Placeholder = "8000"
			m.textInput.SetValue("8000")
		} else {
			m.state = stateCreateDNSProvider
			m.textInput.Reset()
		}
	case "2":
		m.newImage = imageUbuntu
		if checkAllDNSForDomain(m.newDomain) {
			m.status = "✓ DNS already configured correctly"
			m.newDNSProvider = dnsNone
			m.newDNSToken = ""
			m.state = stateCreateAppPort
			m.textInput.Placeholder = "8000"
			m.textInput.SetValue("8000")
		} else {
			m.state = stateCreateDNSProvider
			m.textInput.Reset()
		}
	case "esc", "q":
		m.state = stateList
	}
	return m, nil
}

func (m model) handleImportImageSelectKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "1":
		m.newImage = imageUbuntu
		m.state = stateImportAuthUser
		m.textInput.Placeholder = "admin"
		m.textInput.SetValue("admin")
		m.textInput.Focus()
	case "2":
		m.newImage = imageDebian
		m.state = stateImportAuthUser
		m.textInput.Placeholder = "admin"
		m.textInput.SetValue("admin")
		m.textInput.Focus()
	case "esc", "q":
		m.state = stateUntracked
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
			containerName := m.untrackedContainers[m.cursor]
			// Check if container OS is supported (Debian or Ubuntu)
			detectedOS := getContainerOS(containerName)
			if detectedOS == "unknown" {
				m.status = "❌ Cannot import: container OS is not Debian or Ubuntu"
				return m, clearStatusAfterDelay()
			}
			// Set the image type based on detected OS
			if detectedOS == "debian" {
				m.newImage = imageDebian
			} else {
				m.newImage = imageUbuntu
			}
			m.state = stateImportContainer
			m.textInput.Placeholder = "domain.com"
			m.textInput.Focus()
		}
	}
	return m, nil
}

func (m model) handleSnapshotKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.state = stateContainerDetail
		return m, nil
	case "up", "k":
		if m.snapshotCursor > 0 {
			m.snapshotCursor--
		}
	case "down", "j":
		if m.snapshotCursor < len(m.snapshots)-1 {
			m.snapshotCursor++
		}
	case "n":
		// Create new snapshot
		m.state = stateSnapshotCreate
		m.textInput.Placeholder = "snapshot-name"
		m.textInput.SetValue(fmt.Sprintf("snap-%s", time.Now().Format("20060102-150405")))
		m.textInput.Focus()
	case "enter", "r":
		// Restore selected snapshot
		if len(m.snapshots) > 0 && m.snapshotCursor < len(m.snapshots) {
			m.state = stateSnapshotRestore
		}
	case "d":
		// Delete selected snapshot
		if len(m.snapshots) > 0 && m.snapshotCursor < len(m.snapshots) {
			m.state = stateSnapshotDelete
		}
	}
	return m, nil
}

func (m model) handleSnapshotCreateKeys(key string) (tea.Model, tea.Cmd) {
	if key == "esc" {
		m.state = stateSnapshots
		m.textInput.Reset()
		return m, nil
	}
	if key != "enter" {
		return m, nil
	}

	name := strings.TrimSpace(m.textInput.Value())
	if name == "" {
		m.status = "Snapshot name cannot be empty"
		return m, clearStatusAfterDelay()
	}

	if m.editingContainer != nil {
		if err := createSnapshot(m.editingContainer.Name, name); err != nil {
			m.status = "Snapshot failed: " + err.Error()
		} else {
			m.status = "Created snapshot: " + name
			m.snapshots = listSnapshots(m.editingContainer.Name)
		}
	}
	m.state = stateSnapshots
	m.textInput.Reset()
	return m, clearStatusAfterDelay()
}

func (m model) handleSnapshotConfirmKeys(key string) (tea.Model, tea.Cmd) {
	if m.editingContainer == nil || len(m.snapshots) == 0 || m.snapshotCursor >= len(m.snapshots) {
		m.state = stateSnapshots
		return m, nil
	}

	snap := m.snapshots[m.snapshotCursor]

	switch key {
	case "y", "Y":
		if m.state == stateSnapshotRestore {
			if err := restoreSnapshot(m.editingContainer.Name, snap.Name); err != nil {
				m.status = "Restore failed: " + err.Error()
			} else {
				m.status = "Restored from snapshot: " + snap.Name
			}
		} else if m.state == stateSnapshotDelete {
			if err := deleteSnapshot(m.editingContainer.Name, snap.Name); err != nil {
				m.status = "Delete failed: " + err.Error()
			} else {
				m.status = "Deleted snapshot: " + snap.Name
				m.snapshots = listSnapshots(m.editingContainer.Name)
				if m.snapshotCursor >= len(m.snapshots) && m.snapshotCursor > 0 {
					m.snapshotCursor--
				}
			}
		}
		m.state = stateSnapshots
		return m, clearStatusAfterDelay()
	case "n", "N", "esc", "q":
		m.state = stateSnapshots
	}
	return m, nil
}

func (m model) handleDNSTokensKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.state = stateList
		return m, m.refreshContainers()
	case "1":
		// Edit Cloudflare token
		m.editingDNSProvider = dnsCloudflare
		m.state = stateDNSTokenEdit
		m.textInput.Placeholder = "Cloudflare API Token"
		if token := getDNSToken(m.db, dnsCloudflare); token != "" {
			m.textInput.SetValue(token)
		} else {
			m.textInput.Reset()
		}
		m.textInput.Focus()
	case "2":
		// Edit deSEC token
		m.editingDNSProvider = dnsDesec
		m.state = stateDNSTokenEdit
		m.textInput.Placeholder = "deSEC API Token"
		if token := getDNSToken(m.db, dnsDesec); token != "" {
			m.textInput.SetValue(token)
		} else {
			m.textInput.Reset()
		}
		m.textInput.Focus()
	case "3":
		// Delete Cloudflare token
		deleteDNSToken(m.db, dnsCloudflare)
		m.status = "Cloudflare token deleted"
		return m, clearStatusAfterDelay()
	case "4":
		// Delete deSEC token
		deleteDNSToken(m.db, dnsDesec)
		m.status = "deSEC token deleted"
		return m, clearStatusAfterDelay()
	}
	return m, nil
}

func (m model) handleDNSTokenEditKeys(key string) (tea.Model, tea.Cmd) {
	if key == "esc" {
		m.state = stateDNSTokens
		m.textInput.Reset()
		return m, nil
	}
	if key != "enter" {
		return m, nil
	}

	token := strings.TrimSpace(m.textInput.Value())
	if token != "" {
		saveDNSToken(m.db, m.editingDNSProvider, token)
		m.status = fmt.Sprintf("%s token saved", providerName(m.editingDNSProvider))
	}
	m.state = stateDNSTokens
	m.textInput.Reset()
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
		// Show current DNS status
		dnsStatus := "⚠ DNS not configured (A records needed)"
		mainOK := checkDNSResolvesToHost(m.newDomain)
		codeOK := checkDNSResolvesToHost("code." + m.newDomain)
		adminOK := checkDNSResolvesToHost("admin.code." + m.newDomain)
		if mainOK && codeOK && adminOK {
			dnsStatus = "✅ DNS already configured correctly"
		} else {
			var missing []string
			if !mainOK {
				missing = append(missing, m.newDomain)
			}
			if !codeOK {
				missing = append(missing, "code."+m.newDomain)
			}
			if !adminOK {
				missing = append(missing, "admin.code."+m.newDomain)
			}
			if len(missing) > 0 {
				dnsStatus = "⚠ Missing DNS: " + strings.Join(missing, ", ")
			}
		}
		return fmt.Sprintf("📦 CREATE: %s\n\n%s\n\nAuto-create DNS records?\n\n[1] No - I'll configure DNS manually\n[2] Cloudflare\n[3] deSEC\n\n[Esc] Cancel", m.newDomain, dnsStatus)

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
		return fmt.Sprintf("📦 CREATE: %s\n\nSSH Public Key:\n\n%s\n\n[Enter] Continue  [Esc] Cancel", m.newDomain, m.textInput.View())

	case stateCreateAuthUser:
		return fmt.Sprintf("🔐 CREATE: %s\n\nUsername (for SSH/sudo):\n\n%s\n\n[Enter] Continue  [Esc] Cancel", m.newDomain, m.textInput.View())

	case stateCreateAuthPass:
		return fmt.Sprintf("🔐 CREATE: %s\n\nPassword (min 8 chars):\n\n%s\n\n[Enter] Continue  [Esc] Cancel", m.newDomain, m.textInput.View())

	case stateCreateImage:
		return m.viewImageSelect("CREATE: "+m.newDomain)

	case stateEditAppPort:
		return fmt.Sprintf("✏️  EDIT APP PORT\n\nNew port:\n\n%s\n\n[Enter] Save  [Esc] Cancel", m.textInput.View())

	case stateEditAuthUser:
		containerName := ""
		if m.editingContainer != nil {
			containerName = m.editingContainer.Name
		}
		return fmt.Sprintf("🔐 EDIT BASIC AUTH: %s\n\nNew username:\n\n%s\n\n[Enter] Continue  [Esc] Cancel", containerName, m.textInput.View())

	case stateEditAuthPass:
		containerName := ""
		if m.editingContainer != nil {
			containerName = m.editingContainer.Name
		}
		return fmt.Sprintf("🔐 EDIT BASIC AUTH: %s\n\nNew password (min 8 chars):\n\n%s\n\n[Enter] Save  [Esc] Cancel", containerName, m.textInput.View())

	case stateUpdateTools:
		containerName := ""
		if m.editingContainer != nil {
			containerName = m.editingContainer.Name
		}
		statusIcon := "🔄"
		if m.updateSuccess {
			statusIcon = "✅"
		} else if strings.Contains(m.updateOutput, "failed") {
			statusIcon = "❌"
		}
		s := fmt.Sprintf("%s UPDATE AI CODING TOOLS: %s\n", statusIcon, containerName)
		s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
		s += m.updateOutput
		s += "\n\n───────────────────────────────────────────────────────────────────────────────\n"
		s += "[Esc] Back to container details\n"
		return s

	case stateUntracked:
		return m.viewUntracked()

	case stateImportContainer:
		if m.cursor < len(m.untrackedContainers) {
			return fmt.Sprintf("📥 IMPORT CONTAINER: %s\n\nEnter domain to associate:\n\n%s\n\n[Enter] Continue  [Esc] Cancel",
				m.untrackedContainers[m.cursor], m.textInput.View())
		}
		return "No container selected"

	case stateImportImage:
		if m.cursor < len(m.untrackedContainers) {
			return m.viewImageSelect("IMPORT: " + m.untrackedContainers[m.cursor])
		}
		return "No container selected"

	case stateImportAuthUser:
		if m.cursor < len(m.untrackedContainers) {
			return fmt.Sprintf("🔐 IMPORT: %s\n\nUsername (for SSH/sudo):\n\n%s\n\n[Enter] Continue  [Esc] Cancel",
				m.untrackedContainers[m.cursor], m.textInput.View())
		}
		return "No container selected"

	case stateImportAuthPass:
		if m.cursor < len(m.untrackedContainers) {
			return fmt.Sprintf("🔐 IMPORT: %s\n\nPassword (min 8 chars):\n\n%s\n\n[Enter] Continue  [Esc] Cancel",
				m.untrackedContainers[m.cursor], m.textInput.View())
		}
		return "No container selected"

	case stateSnapshots:
		return m.viewSnapshots()

	case stateSnapshotCreate:
		if m.editingContainer != nil {
			return fmt.Sprintf("📸 CREATE SNAPSHOT: %s\n\nSnapshot name:\n\n%s\n\n[Enter] Create  [Esc] Cancel",
				m.editingContainer.Name, m.textInput.View())
		}
		return "No container selected"

	case stateSnapshotRestore:
		if m.editingContainer != nil && m.snapshotCursor < len(m.snapshots) {
			snap := m.snapshots[m.snapshotCursor]
			return fmt.Sprintf("⚠️  RESTORE SNAPSHOT\n\nRestore %s to snapshot '%s'?\n\nCreated: %s\n\nThis will stop the container and restore its state.\nCurrent state will be lost!\n\n[Y] Yes, restore  [N] No, cancel",
				m.editingContainer.Name, snap.Name, snap.CreatedAt.Format("2006-01-02 15:04:05"))
		}
		return "No snapshot selected"

	case stateSnapshotDelete:
		if m.editingContainer != nil && m.snapshotCursor < len(m.snapshots) {
			snap := m.snapshots[m.snapshotCursor]
			return fmt.Sprintf("🗑️  DELETE SNAPSHOT\n\nDelete snapshot '%s' from %s?\n\nCreated: %s\n\n[Y] Yes, delete  [N] No, cancel",
				snap.Name, m.editingContainer.Name, snap.CreatedAt.Format("2006-01-02 15:04:05"))
		}
		return "No snapshot selected"

	case stateDNSTokens:
		return m.viewDNSTokens()

	case stateDNSTokenEdit:
		return fmt.Sprintf("🔑 %s API TOKEN\n\nEnter token:\n\n%s\n\n[Enter] Save  [Esc] Cancel",
			providerName(m.editingDNSProvider), m.textInput.View())

	case stateCreating:
		s := "📦 CREATING CONTAINER\n"
		s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
		s += m.createOutput
		if strings.Contains(m.createOutput, "✅") || strings.Contains(m.createOutput, "❌") {
			s += "\n[Enter] Continue"
		} else {
			s += "\nPlease wait..."
		}
		return s

	case stateConfirmDelete:
		if len(m.containers) > 0 && m.cursor < len(m.containers) {
			c := m.containers[m.cursor]
			return fmt.Sprintf("⚠️  DELETE CONTAINER\n\nAre you sure you want to delete '%s'?\n\nDomain: %s\nThis will remove:\n  - The container and all its data\n  - Caddy routes\n  - SSH routing\n\n[Y] Yes, delete  [N] No, cancel", c.Name, c.Domain)
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

func (m model) viewImageSelect(title string) string {
	s := fmt.Sprintf("📦 %s\n", title)
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += "Select container base image:\n\n"
	s += "  [1] Debian (latest)  - recommended\n"
	s += "  [2] Ubuntu (latest)\n"
	s += "\n───────────────────────────────────────────────────────────────────────────────\n"
	s += "[1/2] Select  [Esc] Cancel\n"
	return s
}

func (m model) viewList() string {
	s := "🐧 VIBEBIN MANAGER\n"
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += "[n] New  [Enter] Details  [d] Delete  [u] Untracked  [D] DNS Tokens\n"
	s += "[i] Incus Logs  [l] Sync Logs  [q] Quit\n\n"

	if len(m.containers) == 0 {
		s += "  No containers. Press [n] to create one.\n"
	} else {
		s += fmt.Sprintf("  %-22s %-14s %-8s %-6s %-6s %-5s %s\n", "DOMAIN", "IP", "STATUS", "TIME", "MEM", "PORT", "CREATED")
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
	s += "These containers exist in Incus but are not managed by vibebin.\n"
	s += "Only Debian and Ubuntu containers can be imported.\n"
	s += "[Enter/i] Import  [Esc] Back\n\n"

	if len(m.untrackedContainers) == 0 {
		s += "  No untracked containers found.\n"
	} else {
		s += fmt.Sprintf("  %-30s  %-10s  %-8s  %s\n", "NAME", "STATUS", "OS", "IP")
		s += "  " + strings.Repeat("─", 65) + "\n"
		for i, name := range m.untrackedContainers {
			status, ip, _, _ := getContainerStatus(name)
			detectedOS := getContainerOS(name)
			cursor := "  "
			if i == m.cursor {
				cursor = "▶ "
			}
			s += fmt.Sprintf("%s%-30s  %-10s  %-8s  %s\n", cursor, name, status, detectedOS, ip)
		}
	}

	if m.status != "" {
		s += "\n" + m.status
	}
	return s
}

func (m model) viewDNSTokens() string {
	s := "🔑 DNS API TOKENS\n"
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += "Saved tokens are used automatically when creating containers.\n\n"

	// Check for saved tokens
	cfToken := getDNSToken(m.db, dnsCloudflare)
	desecToken := getDNSToken(m.db, dnsDesec)

	cfStatus := "❌ Not configured"
	if cfToken != "" {
		// Show masked token
		cfStatus = "✅ " + cfToken[:8] + "..." + cfToken[len(cfToken)-4:]
	}

	desecStatus := "❌ Not configured"
	if desecToken != "" {
		desecStatus = "✅ " + desecToken[:8] + "..." + desecToken[len(desecToken)-4:]
	}

	s += fmt.Sprintf("  Cloudflare:  %s\n", cfStatus)
	s += fmt.Sprintf("  deSEC:       %s\n", desecStatus)
	s += "\n"
	s += "───────────────────────────────────────────────────────────────────────────────\n"
	s += "[1] Set/Edit Cloudflare  [2] Set/Edit deSEC\n"
	s += "[3] Delete Cloudflare    [4] Delete deSEC\n"
	s += "[Esc] Back\n"

	if m.status != "" {
		s += "\n📋 " + m.status
	}
	return s
}

func (m model) viewSnapshots() string {
	if m.editingContainer == nil {
		return "No container selected"
	}
	c := m.editingContainer

	s := fmt.Sprintf("📸 SNAPSHOTS: %s\n", c.Name)
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += "[n] New  [Enter/r] Restore  [d] Delete  [Esc] Back\n\n"

	if len(m.snapshots) == 0 {
		s += "  No snapshots found.\n"
		s += "\n  Press [n] to create a snapshot.\n"
	} else {
		s += fmt.Sprintf("  %-30s  %-20s  %s\n", "NAME", "CREATED", "STATEFUL")
		s += fmt.Sprintf("  %s\n", strings.Repeat("─", 60))
		for i, snap := range m.snapshots {
			cursor := "  "
			if i == m.snapshotCursor {
				cursor = "▶ "
			}
			stateful := "no"
			if snap.Stateful {
				stateful = "yes"
			}
			s += fmt.Sprintf("%s%-30s  %-20s  %s\n", cursor, snap.Name,
				snap.CreatedAt.Format("2006-01-02 15:04:05"), stateful)
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
	s += fmt.Sprintf("  Domain:       %s\n", c.Domain)
	s += fmt.Sprintf("  Status:       %s\n", c.Status)
	s += fmt.Sprintf("  IP:           %s\n", c.IP)
	s += fmt.Sprintf("  CPU Time:     %s (cumulative)\n", c.CPU)
	s += fmt.Sprintf("  Memory:       %s (incl. cache)\n", c.Memory)
	s += fmt.Sprintf("  App Port:     %d\n", c.AppPort)
	s += fmt.Sprintf("  Created:      %s\n", c.CreatedAt.Format("2006-01-02 15:04:05"))
	s += "\n"
	s += fmt.Sprintf("  🌐 App URL: https://%s\n", c.Domain)
	s += fmt.Sprintf("  🤖 Code UI: https://code.%s\n", c.Domain)
	s += fmt.Sprintf("  ⚙️  Admin:   https://admin.code.%s\n", c.Domain)
	hostIP := getHostPublicIP()
	if hostIP == "" {
		hostIP = "<host>"
	}
	s += fmt.Sprintf("  🔑 SSH:     ssh -p 2222 %s@%s\n", c.Name, hostIP)
	s += "\n"
	s += "───────────────────────────────────────────────────────────────────────────────\n"
	s += "[s] Start/Stop  [r] Restart  [p] Change Port  [a] Change Auth\n"
	s += "[S] Snapshots   [u] Update AI tools  [Esc] Back\n"

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

// cleanupStaleProcesses kills any orphaned vibebin processes
func cleanupStaleProcesses() {
	// Check PID file first
	if pidData, err := os.ReadFile(PIDFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
			// Check if process exists and is vibebin
			if process, err := os.FindProcess(pid); err == nil {
				// Check if it's actually running (signal 0 tests existence)
				if err := process.Signal(syscall.Signal(0)); err == nil {
					// Process exists, check if it's vibebin
					cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
					if strings.Contains(string(cmdline), "vibebin") {
						fmt.Fprintf(os.Stderr, "Terminating stale vibebin process (PID %d)...\n", pid)
						process.Signal(syscall.SIGTERM)
						time.Sleep(500 * time.Millisecond)
						// Force kill if still running
						if err := process.Signal(syscall.Signal(0)); err == nil {
							process.Signal(syscall.SIGKILL)
						}
					}
				}
			}
		}
	}
	os.Remove(PIDFile)
}

// writePIDFile writes our PID to the PID file
func writePIDFile() error {
	return os.WriteFile(PIDFile, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// removePIDFile removes the PID file on exit
func removePIDFile() {
	os.Remove(PIDFile)
}

func main() {
	// Clean up any stale processes from previous runs
	cleanupStaleProcesses()

	// Write our PID file
	if err := writePIDFile(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write PID file: %v\n", err)
	}
	defer removePIDFile()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	// Clear screen and create the bubbletea program with alternate screen
	fmt.Print("\033[H\033[2J") // Clear screen
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())

	// Handle signals in a goroutine
	go func() {
		<-sigChan
		p.Quit()
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
