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
	DBPath         = "/var/lib/shelley/containers.db"
	PIDFile        = "/var/run/incus_manager.pid"
	DefaultAppPort = 8000
	ShelleyPort    = 9999
	UploadPort     = 8099 // Igor file upload service port
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
	stateCreateProviderSelect  // Select LLM provider for shelley-cli
	stateCreateAPIKey          // Enter API key for selected provider
	stateCreateBaseURL         // Enter optional base URL for provider
	stateContainerDetail
	stateEditAppPort
	stateEditAuthUser
	stateEditAuthPass
	stateUpdateShelley  // Update shelley-cli binary
	stateLogs
	stateUntracked
	stateImportContainer
	stateImportImage           // Select image for imported container
	stateImportAuthUser
	stateImportAuthPass
	stateImportProviderSelect  // Select LLM provider for import
	stateImportAPIKey          // Enter API key for import
	stateImportBaseURL         // Enter optional base URL for import
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

// LLM Model configuration
// LLM Provider configuration for shelley-cli
type llmProvider struct {
	ID            string // Provider identifier
	Name          string // Display name
	APIKeyEnvVar  string // Environment variable for API key
	BaseURLEnvVar string // Environment variable for base URL (optional)
}

var availableProviders = []llmProvider{
	{ID: "anthropic", Name: "Anthropic (Claude)", APIKeyEnvVar: "ANTHROPIC_API_KEY", BaseURLEnvVar: "ANTHROPIC_BASE_URL"},
	{ID: "openai", Name: "OpenAI (GPT)", APIKeyEnvVar: "OPENAI_API_KEY", BaseURLEnvVar: "OPENAI_BASE_URL"},
	{ID: "fireworks", Name: "Fireworks", APIKeyEnvVar: "FIREWORKS_API_KEY", BaseURLEnvVar: "FIREWORKS_BASE_URL"},
}

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
	shelleyUpdateMsg    struct{ output string; success bool }              // shelley-cli update result
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
	updateOutput  string  // Output from shelley-cli update command
	updateSuccess bool    // Whether shelley-cli update succeeded

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
	newProviderIndex int    // Index into availableProviders
	newAPIKey        string // API key for the selected provider
	newBaseURL       string // Optional base URL for the provider

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
		stateCreateAuthUser, stateCreateAuthPass, stateCreateAPIKey, stateCreateBaseURL,
		stateEditAppPort, stateEditAuthUser, stateEditAuthPass,
		stateImportContainer, stateImportAuthUser, stateImportAuthPass, stateImportAPIKey, stateImportBaseURL,
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

// createContainerWithProgress creates a container and sends progress updates via channel
func createContainerWithProgress(db *sql.DB, domain string, image containerImage, appPort int, sshKey string, dnsProvider dnsProvider, dnsToken string, cfProxy bool, authUser, authPass string, providerIndex int, apiKey, baseURL string, progress chan<- string) error {
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
			
			// Create shelley subdomain (never proxied - needs direct access for websockets)
			shelleyDomain := "shelley." + domain
			sendProgress(fmt.Sprintf("Creating A record for %s...", shelleyDomain))
			if err := createDNSRecord(shelleyDomain, hostIP, dnsProvider, dnsToken, false); err != nil {
				sendProgress(fmt.Sprintf("❌ DNS error for %s: %v", shelleyDomain, err))
			} else {
				sendProgress(fmt.Sprintf("✅ Created: %s -> %s", shelleyDomain, hostIP))
			}
			
			// Wait for DNS propagation and verify
			sendProgress("Waiting for DNS propagation (5s)...")
			time.Sleep(5 * time.Second)
			
			// Verify DNS records
			sendProgress("Verifying DNS records...")
			mainOK := checkDNSResolvesToHost(domain)
			shelleyOK := checkDNSResolvesToHost(shelleyDomain)
			if mainOK {
				sendProgress(fmt.Sprintf("✅ DNS verified: %s", domain))
			} else {
				sendProgress(fmt.Sprintf("⚠️ DNS not yet propagated: %s", domain))
			}
			if shelleyOK {
				sendProgress(fmt.Sprintf("✅ DNS verified: %s", shelleyDomain))
			} else {
				sendProgress(fmt.Sprintf("⚠️ DNS not yet propagated: %s", shelleyDomain))
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
	screenSessionID, err := configureContainerEnvironment(name, containerUser, domain, providerIndex, apiKey, baseURL, sshKey, sendProgress)
	if err != nil {
		sendProgress(fmt.Sprintf("Warning: Some configuration steps failed: %v", err))
	}
	_ = screenSessionID // Used in final status message

	// STEP 5: Get container IP (SSH key setup is handled by configureSSHPiper later)
	sendProgress("Getting container IP address...")
	_, ip, _, _ := getContainerStatus(name)
	if ip != "" {
		sendProgress(fmt.Sprintf("Container IP: %s", ip))
	} else {
		sendProgress("Warning: Could not get container IP yet")
	}

	// STEP 7: Hash password for Shelley auth
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
// checkAllDNSForDomain checks both the main domain and shelley subdomain
func checkAllDNSForDomain(domain string) bool {
	mainOK := checkDNSResolvesToHost(domain)
	shelleyOK := checkDNSResolvesToHost("shelley." + domain)
	return mainOK && shelleyOK
}

// importContainer adds an existing Incus container to our management DB
func importContainer(db *sql.DB, name, domain string, image containerImage, appPort int, authUser, authPass string, providerIndex int, apiKey, baseURL, sshKey string) error {
	// Verify container exists in Incus
	_, ip, _, _ := getContainerStatus(name)
	if ip == "" {
		// Container might be stopped, try to start it
		exec.Command("incus", "start", name).Run()
		time.Sleep(3 * time.Second)
		_, ip, _, _ = getContainerStatus(name)
	}

	// Hash password for Shelley auth (used by Caddy basic auth)
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

	// Configure the container environment (user, Docker, Go, Node, shelley-cli)
	silentProgress := func(msg string) {} // Silent for imports
	_, _ = configureContainerEnvironment(name, containerUser, domain, providerIndex, apiKey, baseURL, sshKey, silentProgress)

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
	deleteCaddyRoute(client, caddyAPI, name+"-shelley")
	deleteCaddyRoute(client, caddyAPI, name+"-upload")

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

	// Build shelley-cli web UI route handlers
	var shelleyHandlers []map[string]interface{}

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
					"realm": "Shelley",
				},
			},
		}
		shelleyHandlers = append(shelleyHandlers, authHandler)
	}

	// Add reverse proxy handler for shelley-cli web UI
	shelleyHandlers = append(shelleyHandlers, map[string]interface{}{
		"handler":   "reverse_proxy",
		"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, ShelleyPort)}},
	})

	// Build upload route handlers (Igor file upload service)
	// IMPORTANT: Upload route must be added BEFORE shelley route because it's more specific
	// (has path match). Caddy evaluates routes in order, so more specific routes must come first.
	var uploadHandlers []map[string]interface{}

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
					"realm": "Upload",
				},
			},
		}
		uploadHandlers = append(uploadHandlers, authHandler)
	}

	// Add rewrite handler to strip /upload prefix before proxying
	// Use Caddy's placeholder syntax for path manipulation
	uploadHandlers = append(uploadHandlers, map[string]interface{}{
		"handler": "rewrite",
		"uri":     "{http.request.uri.path.strip_prefix(/upload)}",
	})

	// Add reverse proxy handler for Igor upload service
	uploadHandlers = append(uploadHandlers, map[string]interface{}{
		"handler":   "reverse_proxy",
		"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, UploadPort)}},
	})

	uploadRoute := map[string]interface{}{
		"@id": name + "-upload",
		"match": []map[string]interface{}{{
			"host": []string{"shelley." + domain},
			"path": []string{"/upload", "/upload/*"},
		}},
		"handle": uploadHandlers,
	}
	if err := addCaddyRoute(client, caddyAPI, uploadRoute); err != nil {
		return fmt.Errorf("failed to add upload route: %w", err)
	}

	// Add shelley route AFTER upload route (less specific, catches all other paths)
	shelleyRoute := map[string]interface{}{
		"@id":   name + "-shelley",
		"match": []map[string]interface{}{{"host": []string{"shelley." + domain}}},
		"handle": shelleyHandlers,
	}
	if err := addCaddyRoute(client, caddyAPI, shelleyRoute); err != nil {
		return fmt.Errorf("failed to add shelley route: %w", err)
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
	deleteCaddyRoute(client, caddyAPI, name+"-shelley")
	deleteCaddyRoute(client, caddyAPI, name+"-upload")
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
// This includes: user setup, Docker, Go, Node.js, shelley-cli, and API key configuration
// Returns the screen session ID for shelley serve, or empty string if not started
func configureContainerEnvironment(containerName, containerUser, domain string, providerIndex int, apiKey, baseURL, sshKey string, sendProgress func(string)) (string, error) {
	// Helper to run commands in container as root
	rootExec := func(args ...string) error {
		cmd := exec.Command("incus", append([]string{"exec", containerName, "--"}, args...)...)
		return cmd.Run()
	}

	// Helper to run commands in container as the container user
	// Pass a single shell command string
	userExec := func(shellCmd string) error {
		cmd := exec.Command("incus", "exec", containerName, "--", "su", "-", containerUser, "-c", shellCmd)
		return cmd.Run()
	}

	// STEP 1: Ensure the container user exists with passwordless sudo
	sendProgress(fmt.Sprintf("Ensuring user '%s' exists with sudo access...", containerUser))
	rootExec("apt-get", "update")
	rootExec("apt-get", "install", "-y", "sudo", "curl", "wget", "git", "make", "screen", "openssh-server")
	
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
	// Harden sshd_config: disable root login and password auth
	rootExec("sed", "-i", "s/^#*PermitRootLogin.*/PermitRootLogin no/", "/etc/ssh/sshd_config")
	rootExec("sed", "-i", "s/^#*PasswordAuthentication.*/PasswordAuthentication no/", "/etc/ssh/sshd_config")
	// Enable and start SSH service
	rootExec("systemctl", "enable", "--now", "ssh")

	// Set up SSH key for the user
	userHome := fmt.Sprintf("/home/%s", containerUser)
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
	rootExec("sh", "-c", "curl -fsSL https://get.docker.com | sh")
	rootExec("usermod", "-aG", "docker", containerUser)

	// STEP 4: Install Go (latest version, detect architecture)
	sendProgress("Installing Go (latest version)...")
	// Get latest Go version from go.dev - run as root for reliability
	goInstallScript := `
set -ex
ARCH=$(uname -m)
case $ARCH in
    x86_64) GOARCH="amd64" ;;
    aarch64|arm64) GOARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Get latest Go version
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
	tmpGoScript, _ := os.CreateTemp("", "install-go.sh")
	tmpGoScript.WriteString(goInstallScript)
	tmpGoScript.Close()
	exec.Command("incus", "file", "push", tmpGoScript.Name(), containerName+"/tmp/install-go.sh").Run()
	os.Remove(tmpGoScript.Name())
	rootExec("chmod", "+x", "/tmp/install-go.sh")
	rootExec("/tmp/install-go.sh") // Run as root since it installs to /usr/local

	// Add Go to PATH in bashrc
	goPathLine := "export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin"
	userExec("grep -q 'go/bin' ~/.bashrc || echo '" + goPathLine + "' >> ~/.bashrc")

	// STEP 5: Install Node.js (latest LTS)
	sendProgress("Installing Node.js (latest LTS)...")
	nodeInstallScript := `
set -ex
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt-get install -y nodejs
echo "Node.js $(node --version) installed successfully"
`
	tmpNodeScript, _ := os.CreateTemp("", "install-node.sh")
	tmpNodeScript.WriteString(nodeInstallScript)
	tmpNodeScript.Close()
	exec.Command("incus", "file", "push", tmpNodeScript.Name(), containerName+"/tmp/install-node.sh").Run()
	os.Remove(tmpNodeScript.Name())
	rootExec("chmod", "+x", "/tmp/install-node.sh")
	rootExec("/tmp/install-node.sh") // Run as root for apt operations

	// STEP 6: Install shelley-cli and igor service
	sendProgress("Installing shelley-cli...")
	shelleyInstallScript := fmt.Sprintf(`
set -ex
export PATH=$PATH:/usr/local/go/bin
cd /home/%s
rm -rf shelley-cli
git clone https://github.com/davidcjones79/shelley-cli.git
cd shelley-cli
make
# Copy binary to go/bin so it's in PATH
mkdir -p /home/%s/go/bin
cp bin/shelley /home/%s/go/bin/
chown %s:%s /home/%s/go/bin/shelley

# Create igor.service with correct user (not exedev)
cat > /etc/systemd/system/igor.service << 'IGOREOF'
[Unit]
Description=Igor - Shelley File Transfer Assistant
After=network.target

[Service]
Type=exec
User=%s
Group=%s
WorkingDirectory=/home/%s
ExecStart=/home/%s/go/bin/shelley igor -port 8099
Restart=on-failure
RestartSec=5
Environment=HOME=/home/%s
Environment=USER=%s
Environment=PATH=/usr/local/bin:/usr/bin:/bin:/home/%s/go/bin

StandardOutput=journal
StandardError=journal
SyslogIdentifier=igor

[Install]
WantedBy=multi-user.target
IGOREOF

systemctl daemon-reload
systemctl enable --now igor

echo "shelley-cli and igor service installed successfully"
`, containerUser, containerUser, containerUser, containerUser, containerUser, containerUser, containerUser, containerUser, containerUser, containerUser, containerUser, containerUser, containerUser, containerUser)
	tmpShelleyScript, _ := os.CreateTemp("", "install-shelley.sh")
	tmpShelleyScript.WriteString(shelleyInstallScript)
	tmpShelleyScript.Close()
	exec.Command("incus", "file", "push", tmpShelleyScript.Name(), containerName+"/tmp/install-shelley.sh").Run()
	os.Remove(tmpShelleyScript.Name())
	rootExec("chmod", "+x", "/tmp/install-shelley.sh")
	rootExec("/tmp/install-shelley.sh") // Run as root so we can set ownership

	// STEP 7: Configure API key and base URL in bashrc
	sendProgress("Configuring LLM provider credentials...")
	if providerIndex >= 0 && providerIndex < len(availableProviders) {
		provider := availableProviders[providerIndex]
		
		bashrcPath := userHome + "/.bashrc"
		readCmd := exec.Command("incus", "exec", containerName, "--", "cat", bashrcPath)
		currentBashrc, _ := readCmd.Output()
		bashrcContent := string(currentBashrc)
		
		// Add API key
		if apiKey != "" {
			exportLine := fmt.Sprintf("export %s='%s'", provider.APIKeyEnvVar, apiKey)
			if !strings.Contains(bashrcContent, provider.APIKeyEnvVar+"=") {
				bashrcContent += "\n" + exportLine
			}
		}
		
		// Add base URL if provided
		if baseURL != "" && provider.BaseURLEnvVar != "" {
			exportLine := fmt.Sprintf("export %s='%s'", provider.BaseURLEnvVar, baseURL)
			if !strings.Contains(bashrcContent, provider.BaseURLEnvVar+"=") {
				bashrcContent += "\n" + exportLine
			}
		}
		
		// Write updated bashrc
		tmpBashrc, err := os.CreateTemp("", "bashrc")
		if err == nil {
			tmpBashrc.WriteString(bashrcContent)
			tmpBashrc.Close()
			exec.Command("incus", "file", "push", tmpBashrc.Name(), containerName+bashrcPath).Run()
			rootExec("chown", containerUser+":"+containerUser, bashrcPath)
			os.Remove(tmpBashrc.Name())
		}
	}

	// STEP 8: Configure custom MOTD
	sendProgress("Configuring welcome message (MOTD)...")
	motdScript := fmt.Sprintf(`#!/bin/bash
# shelley-lxc custom MOTD

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  shelley-lxc Container: %s"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Domain:     https://%s"
echo "  Shelley UI: https://shelley.%s"
echo "  Upload:     https://shelley.%s/upload"
echo ""
echo "  ─────────────────────────────────────────────────────────────────────────────"
echo "  Installed Tools:"
echo "    • Docker      $(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo 'not found')"
echo "    • Go          $(/usr/local/go/bin/go version 2>/dev/null | awk '{print $3}' | sed 's/go//' || echo 'not found')"
echo "    • Node.js     $(node --version 2>/dev/null || echo 'not found')"
echo "    • shelley-cli $(/home/%s/go/bin/shelley version 2>/dev/null | grep '"commit"' | sed 's/.*: *"\([^"]*\)".*/\1/' | cut -c1-8 || echo 'installed')"
echo ""
echo "  ─────────────────────────────────────────────────────────────────────────────"
echo "  shelley serve Status:"
SCREEN_SESSION=$(screen -ls 2>/dev/null | grep shelley | awk '{print $1}')
if [ -n "$SCREEN_SESSION" ]; then
    echo "    Running in screen session: $SCREEN_SESSION"
    echo "    Attach with: screen -x $SCREEN_SESSION"
else
    echo "    Not running (start with: screen -dmS shelley shelley serve)"
fi
echo "    Log file: ~/shelley-serve.log"
echo ""
echo "  ─────────────────────────────────────────────────────────────────────────────"
echo "  Documentation: https://github.com/jgbrwn/shelley-lxc"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""
`, containerName, domain, domain, domain, containerUser)

	tmpMotd, _ := os.CreateTemp("", "99-shelley-lxc")
	tmpMotd.WriteString(motdScript)
	tmpMotd.Close()
	exec.Command("incus", "file", "push", tmpMotd.Name(), containerName+"/etc/update-motd.d/99-shelley-lxc").Run()
	os.Remove(tmpMotd.Name())
	rootExec("chmod", "+x", "/etc/update-motd.d/99-shelley-lxc")

	// STEP 9: Start shelley serve in a screen session
	sendProgress("Starting shelley serve in screen session...")
	
	// Wait a moment for systemd and other services to fully settle
	time.Sleep(3 * time.Second)
	
	// Create a launcher script that sources bashrc and runs shelley serve
	launcherScript := `#!/bin/bash
source ~/.bashrc
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
cd ~
shelley serve 2>&1 | tee ~/shelley-serve.log
# Keep shell alive if shelley exits
exec bash
`
	tmpLauncher, _ := os.CreateTemp("", "shelley-launcher.sh")
	tmpLauncher.WriteString(launcherScript)
	tmpLauncher.Close()
	exec.Command("incus", "file", "push", tmpLauncher.Name(), containerName+userHome+"/shelley-launcher.sh").Run()
	os.Remove(tmpLauncher.Name())
	rootExec("chmod", "+x", userHome+"/shelley-launcher.sh")
	rootExec("chown", containerUser+":"+containerUser, userHome+"/shelley-launcher.sh")

	// Start shelley serve in a detached screen session named 'shelley'
	startScreenScript := fmt.Sprintf(`#!/bin/bash
set -x  # Debug output
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
cd ~
echo "Current user: $(whoami)"
echo "Home directory: $HOME"
echo "Checking if launcher script exists..."
ls -la %s/shelley-launcher.sh
echo "Starting screen session..."
screen -dmS shelley bash -c '%s/shelley-launcher.sh; exec bash'
echo "Waiting for screen to start..."
sleep 5
echo "Checking screen sessions..."
screen -ls
screen -ls | grep shelley | awk '{print $1}'
`, userHome, userHome)
	tmpScreenScript, _ := os.CreateTemp("", "start-screen.sh")
	tmpScreenScript.WriteString(startScreenScript)
	tmpScreenScript.Close()
	exec.Command("incus", "file", "push", "--mode=0755", tmpScreenScript.Name(), containerName+"/tmp/start-screen.sh").Run()
	os.Remove(tmpScreenScript.Name())
	
	// Run the script and capture the screen session ID
	screenCmd := exec.Command("incus", "exec", containerName, "--", "su", "-", containerUser, "-c", "/tmp/start-screen.sh")
	screenOutput, screenErr := screenCmd.CombinedOutput()
	screenSessionID := ""
	
	if screenErr != nil {
		sendProgress(fmt.Sprintf("Warning: screen command failed: %v", screenErr))
		sendProgress(fmt.Sprintf("Output: %s", string(screenOutput)))
	} else {
		// Parse output to find session ID (last non-empty line should be session ID)
		lines := strings.Split(strings.TrimSpace(string(screenOutput)), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], ".") && strings.Contains(lines[i], "shelley") {
				screenSessionID = strings.TrimSpace(lines[i])
				break
			}
		}
	}
	
	if screenSessionID != "" {
		sendProgress(fmt.Sprintf("shelley serve running in screen session: %s", screenSessionID))
		sendProgress(fmt.Sprintf("To attach: ssh to container then run: screen -x %s", screenSessionID))
		sendProgress("Log file: ~/shelley-serve.log")
	} else {
		sendProgress("Warning: Could not determine screen session ID")
		sendProgress("You may need to start shelley serve manually after SSH'ing in")
	}

	sendProgress("Container environment configuration complete!")
	return screenSessionID, nil
}

// createContainerAsync creates a container asynchronously and returns progress/done messages
func createContainerAsync(db *sql.DB, domain string, image containerImage, appPort int, sshKey string, dnsProvider dnsProvider, dnsToken string, cfProxy bool, authUser, authPass string, providerIndex int, apiKey, baseURL string) tea.Cmd {
	return func() tea.Msg {
		// Create a channel to collect progress messages
		progressChan := make(chan string, 100)
		doneChan := make(chan error, 1)

		// Run creation in background
		go func() {
			err := createContainerWithProgress(db, domain, image, appPort, sshKey, dnsProvider, dnsToken, cfProxy, authUser, authPass, providerIndex, apiKey, baseURL, progressChan)
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

// updateShelleyCmd updates shelley-cli on a container by rebuilding from source
func updateShelleyCmd(containerName, containerUser string) tea.Cmd {
	return func() tea.Msg {
		userHome := "/home/" + containerUser
		
		// First, kill any running shelley serve processes and stop igor
		killScript := `
pkill -f "shelley serve" 2>/dev/null || true
screen -ls | grep shelley | awk '{print $1}' | xargs -r -I{} screen -S {} -X quit 2>/dev/null || true
sudo systemctl stop igor 2>/dev/null || true
echo "Stopped any running shelley serve processes and igor service"
`
		killCmd := exec.Command("incus", "exec", containerName, "--", "su", "-", containerUser, "-c", killScript)
		killCmd.Run()

		// The update commands to run on the container as root (for systemctl operations)
		updateScript := fmt.Sprintf(`
set -e
export PATH=$PATH:/usr/local/go/bin
cd %s
rm -rf shelley-cli
git clone https://github.com/davidcjones79/shelley-cli.git
cd shelley-cli
make
# Copy updated binary
cp bin/shelley %s/go/bin/
chown %s:%s %s/go/bin/shelley

# Update igor.service with correct user
cat > /etc/systemd/system/igor.service << 'IGOREOF'
[Unit]
Description=Igor - Shelley File Transfer Assistant
After=network.target

[Service]
Type=exec
User=%s
Group=%s
WorkingDirectory=/home/%s
ExecStart=/home/%s/go/bin/shelley igor -port 8099
Restart=on-failure
RestartSec=5
Environment=HOME=/home/%s
Environment=USER=%s
Environment=PATH=/usr/local/bin:/usr/bin:/bin:/home/%s/go/bin

StandardOutput=journal
StandardError=journal
SyslogIdentifier=igor

[Install]
WantedBy=multi-user.target
IGOREOF

systemctl daemon-reload
systemctl enable --now igor

echo "shelley-cli and igor service updated successfully!"
`, userHome, userHome, containerUser, containerUser, userHome, containerUser, containerUser, userHome, containerUser, userHome, containerUser, containerUser, userHome)
		
		// Run update as root
		updateCmd := exec.Command("incus", "exec", containerName, "--", "sh", "-c", updateScript)
		updateOutput, updateErr := updateCmd.CombinedOutput()
		result := string(updateOutput)
		
		if updateErr != nil {
			result += fmt.Sprintf("\n\n❌ Update failed: %v", updateErr)
			return shelleyUpdateMsg{output: result, success: false}
		}

		// Restart shelley serve in screen as user
		restartScript := fmt.Sprintf(`
export PATH=$PATH:/usr/local/go/bin:%s/go/bin
cd %s
screen -dmS shelley bash -c '%s/shelley-launcher.sh; exec bash'
sleep 3
SESSION=$(screen -ls | grep shelley | awk '{print $1}')
echo "shelley serve restarted in screen session: $SESSION"
echo "To attach: screen -x $SESSION"
echo "Log file: ~/shelley-serve.log"
`, userHome, userHome, userHome)
		
		// Run restart as user
		restartCmd := exec.Command("incus", "exec", containerName, "--", "su", "-", containerUser, "-c", restartScript)
		restartOutput, _ := restartCmd.CombinedOutput()
		result += string(restartOutput)
		result += "\n\n✅ shelley-cli updated successfully!"

		return shelleyUpdateMsg{output: result, success: true}
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

	case shelleyUpdateMsg:
		m.updateOutput = msg.output
		m.updateSuccess = msg.success
		if msg.success {
			m.status = "shelley-cli updated successfully"
		} else {
			m.status = "shelley-cli update failed"
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
	case stateCreateDomain, stateCreateDNSToken, stateCreateAppPort, stateCreateSSHKey, stateCreateAuthUser, stateCreateAuthPass, stateCreateAPIKey, stateCreateBaseURL, stateEditAppPort, stateEditAuthUser, stateEditAuthPass, stateImportContainer, stateImportAuthUser, stateImportAuthPass, stateImportAPIKey, stateImportBaseURL:
		return m.handleInputKeys(key)
	case stateCreateDNSProvider:
		return m.handleDNSProviderKeys(key)
	case stateCreateCFProxy:
		return m.handleCFProxyKeys(key)
	case stateCreateProviderSelect:
		return m.handleProviderSelectKeys(key)
	case stateImportProviderSelect:
		return m.handleImportProviderSelectKeys(key)
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
	case stateUpdateShelley:
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
		m.currentSvc = "incus-sync"
		return m, streamLogsCmd("incus-sync")
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
		// Edit Shelley auth credentials
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
		// Update shelley-cli on container
		if c.Status != "running" {
			m.status = "Container must be running to update shelley-cli"
			return m, clearStatusAfterDelay()
		}
		m.status = "Updating shelley-cli on " + c.Name + "..."
		m.state = stateUpdateShelley
		m.updateOutput = "Updating shelley-cli...\n"
		m.updateSuccess = false
		// Determine container user from image (we'll need to get this from DB or assume ubuntu for now)
		containerUser := "ubuntu" // Default assumption
		return m, updateShelleyCmd(c.Name, containerUser)
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
			return m, clearStatusAfterDelay()
		}
		if isDomainInUse(m.db, val) {
			m.status = "Domain already in use"
			return m, clearStatusAfterDelay()
		}
		m.newDomain = val
		
		// Go to image selection
		m.state = stateCreateImage
		m.newImage = imageUbuntu // Default to Ubuntu
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
			m.status = "Username required for Shelley authentication"
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
		// Go to provider selection
		m.state = stateCreateProviderSelect
		m.newProviderIndex = 0 // Default to first provider
		m.textInput.Reset()

	case stateCreateAPIKey:
		if val == "" {
			m.status = "API key is required"
			return m, clearStatusAfterDelay()
		}
		m.newAPIKey = val
		// Go to optional base URL
		m.state = stateCreateBaseURL
		provider := availableProviders[m.newProviderIndex]
		m.textInput.Placeholder = fmt.Sprintf("%s (optional, press Enter to skip)", provider.BaseURLEnvVar)
		m.textInput.Reset()

	case stateCreateBaseURL:
		m.newBaseURL = val // Can be empty
		m.createOutput = "Starting container creation and bootstrap...\n"
		m.state = stateCreating
		m.textInput.Reset()
		// Start async creation
		return m, createContainerAsync(m.db, m.newDomain, m.newImage, m.newAppPort, m.newSSHKey, m.newDNSProvider, m.newDNSToken, m.newCFProxy, m.newAuthUser, m.newAuthPass, m.newProviderIndex, m.newAPIKey, m.newBaseURL)

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
				m.status = "Updated Shelley auth credentials"
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
		
		// Go to image selection for import
		m.state = stateImportImage
		m.newImage = imageUbuntu // Default to Ubuntu
		m.textInput.Reset()

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
		// Go to provider selection for import
		m.state = stateImportProviderSelect
		m.newProviderIndex = 0
		m.textInput.Reset()

	case stateImportAPIKey:
		if val == "" {
			m.status = "API key is required"
			return m, clearStatusAfterDelay()
		}
		m.newAPIKey = val
		// Go to optional base URL
		m.state = stateImportBaseURL
		provider := availableProviders[m.newProviderIndex]
		m.textInput.Placeholder = fmt.Sprintf("%s (optional, press Enter to skip)", provider.BaseURLEnvVar)
		m.textInput.Reset()

	case stateImportBaseURL:
		m.newBaseURL = val // Can be empty
		if m.cursor < len(m.untrackedContainers) {
			containerName := m.untrackedContainers[m.cursor]
			err := importContainer(m.db, containerName, m.newDomain, m.newImage, DefaultAppPort, m.newAuthUser, m.newAuthPass, m.newProviderIndex, m.newAPIKey, m.newBaseURL, m.newSSHKey)
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
		m.newImage = imageUbuntu
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
		m.newImage = imageDebian
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

func (m model) handleProviderSelectKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.newProviderIndex > 0 {
			m.newProviderIndex--
		}
	case "down", "j":
		if m.newProviderIndex < len(availableProviders)-1 {
			m.newProviderIndex++
		}
	case "enter":
		// Proceed to API key input
		provider := availableProviders[m.newProviderIndex]
		m.state = stateCreateAPIKey
		m.textInput.Placeholder = provider.APIKeyEnvVar + " value"
		m.textInput.Focus()
	case "esc", "q":
		m.state = stateList
	}
	return m, nil
}

func (m model) handleImportProviderSelectKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.newProviderIndex > 0 {
			m.newProviderIndex--
		}
	case "down", "j":
		if m.newProviderIndex < len(availableProviders)-1 {
			m.newProviderIndex++
		}
	case "enter":
		// Proceed to API key input
		provider := availableProviders[m.newProviderIndex]
		m.state = stateImportAPIKey
		m.textInput.Placeholder = provider.APIKeyEnvVar + " value"
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
		shelleyOK := checkDNSResolvesToHost("shelley." + m.newDomain)
		if mainOK && shelleyOK {
			dnsStatus = "✅ DNS already configured correctly"
		} else if mainOK {
			dnsStatus = "⚠ Main domain OK, shelley." + m.newDomain + " not configured"
		} else if shelleyOK {
			dnsStatus = "⚠ shelley subdomain OK, main domain not configured"
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

	case stateCreateProviderSelect:
		return m.viewProviderSelect("CREATE: "+m.newDomain)

	case stateCreateAPIKey:
		provider := availableProviders[m.newProviderIndex]
		return fmt.Sprintf("🤖 CREATE: %s\n\nSelected provider: %s\n\nEnter %s:\n\n%s\n\n[Enter] Continue  [Esc] Cancel",
			m.newDomain, provider.Name, provider.APIKeyEnvVar, m.textInput.View())

	case stateCreateBaseURL:
		provider := availableProviders[m.newProviderIndex]
		return fmt.Sprintf("🤖 CREATE: %s\n\nSelected provider: %s\n\nEnter %s (optional, press Enter to skip):\n\n%s\n\n[Enter] Create Container  [Esc] Cancel",
			m.newDomain, provider.Name, provider.BaseURLEnvVar, m.textInput.View())

	case stateEditAppPort:
		return fmt.Sprintf("✏️  EDIT APP PORT\n\nNew port:\n\n%s\n\n[Enter] Save  [Esc] Cancel", m.textInput.View())

	case stateEditAuthUser:
		containerName := ""
		if m.editingContainer != nil {
			containerName = m.editingContainer.Name
		}
		return fmt.Sprintf("🔐 EDIT SHELLEY AUTH: %s\n\nNew username:\n\n%s\n\n[Enter] Continue  [Esc] Cancel", containerName, m.textInput.View())

	case stateEditAuthPass:
		containerName := ""
		if m.editingContainer != nil {
			containerName = m.editingContainer.Name
		}
		return fmt.Sprintf("🔐 EDIT SHELLEY AUTH: %s\n\nNew password (min 8 chars):\n\n%s\n\n[Enter] Save  [Esc] Cancel", containerName, m.textInput.View())

	case stateUpdateShelley:
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
		s := fmt.Sprintf("%s UPDATE SHELLEY-CLI: %s\n", statusIcon, containerName)
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

	case stateImportProviderSelect:
		if m.cursor < len(m.untrackedContainers) {
			return m.viewProviderSelect("IMPORT: " + m.untrackedContainers[m.cursor])
		}
		return "No container selected"

	case stateImportAPIKey:
		if m.cursor < len(m.untrackedContainers) {
			provider := availableProviders[m.newProviderIndex]
			return fmt.Sprintf("🤖 IMPORT: %s\n\nSelected provider: %s\n\nEnter %s:\n\n%s\n\n[Enter] Continue  [Esc] Cancel",
				m.untrackedContainers[m.cursor], provider.Name, provider.APIKeyEnvVar, m.textInput.View())
		}
		return "No container selected"

	case stateImportBaseURL:
		if m.cursor < len(m.untrackedContainers) {
			provider := availableProviders[m.newProviderIndex]
			return fmt.Sprintf("🤖 IMPORT: %s\n\nSelected provider: %s\n\nEnter %s (optional, press Enter to skip):\n\n%s\n\n[Enter] Import Container  [Esc] Cancel",
				m.untrackedContainers[m.cursor], provider.Name, provider.BaseURLEnvVar, m.textInput.View())
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
	s += "  [1] Ubuntu (latest)  - recommended\n"
	s += "  [2] Debian (latest)\n"
	s += "\n───────────────────────────────────────────────────────────────────────────────\n"
	s += "[1/2] Select  [Esc] Cancel\n"
	return s
}

func (m model) viewProviderSelect(title string) string {
	s := fmt.Sprintf("🤖 %s\n", title)
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += "Select LLM provider for shelley-cli:\n\n"

	for i, provider := range availableProviders {
		cursor := "  "
		if i == m.newProviderIndex {
			cursor = "▶ "
		}
		s += fmt.Sprintf("%s[%d] %s\n", cursor, i+1, provider.Name)
	}

	s += "\n───────────────────────────────────────────────────────────────────────────────\n"
	s += "[↑/↓] Navigate  [Enter] Select  [Esc] Cancel\n"
	return s
}

func (m model) viewList() string {
	s := "🐧 INCUS CONTAINER MANAGER\n"
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
	s += fmt.Sprintf("  🌐 App URL:     https://%s\n", c.Domain)
	s += fmt.Sprintf("  🤖 Shelley URL: https://shelley.%s\n", c.Domain)
	hostIP := getHostPublicIP()
	if hostIP == "" {
		hostIP = "<host>"
	}
	s += fmt.Sprintf("  🔑 SSH:         ssh -p 2222 %s@%s\n", c.Name, hostIP)
	s += "\n"
	s += "───────────────────────────────────────────────────────────────────────────────\n"
	s += "[s] Start/Stop  [r] Restart  [p] Change Port  [a] Change Auth\n"
	s += "[S] Snapshots   [u] Update shelley-cli  [Esc] Back\n"

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

// cleanupStaleProcesses kills any orphaned incus_manager processes
func cleanupStaleProcesses() {
	// Check PID file first
	if pidData, err := os.ReadFile(PIDFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
			// Check if process exists and is incus_manager
			if process, err := os.FindProcess(pid); err == nil {
				// Check if it's actually running (signal 0 tests existence)
				if err := process.Signal(syscall.Signal(0)); err == nil {
					// Process exists, check if it's incus_manager
					cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
					if strings.Contains(string(cmdline), "incus_manager") {
						fmt.Fprintf(os.Stderr, "Terminating stale incus_manager process (PID %d)...\n", pid)
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
