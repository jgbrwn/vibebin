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
	ExeuntuImage   = "ghcr:boldsoftware/exeuntu:latest"
	DBPath         = "/var/lib/shelley/containers.db"
	PIDFile        = "/var/run/incus_manager.pid"
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
	stateCreateCFProxy
	stateCreateAppPort
	stateCreateSSHKey
	stateCreateAuthUser
	stateCreateAuthPass
	stateCreateModelSelect  // Select default LLM model
	stateCreateAPIKey       // Enter API key for selected model
	stateContainerDetail
	stateEditAppPort
	stateEditAuthUser
	stateEditAuthPass
	stateUpdateShelley
	stateLogs
	stateUntracked
	stateImportContainer
	stateImportAuthUser
	stateImportAuthPass
	stateImportModelSelect  // Select default LLM model for import
	stateImportAPIKey       // Enter API key for import
	stateSnapshots          // View/manage snapshots
	stateSnapshotCreate     // Create new snapshot (name input)
	stateSnapshotRestore    // Confirm restore from snapshot
	stateSnapshotDelete     // Confirm delete snapshot
	stateDNSTokens          // View/manage DNS API tokens
	stateDNSTokenEdit       // Edit/add DNS token
)

// DNS Provider types
type dnsProvider int

const (
	dnsNone dnsProvider = iota
	dnsCloudflare
	dnsDesec
)

// LLM Model configuration
type llmModel struct {
	ID         string // Model ID for shelley.json
	Name       string // Display name
	Provider   string // Provider name (Anthropic, OpenAI, Google, etc.)
	EnvVarName string // Environment variable name for API key
}

var availableModels = []llmModel{
	{ID: "claude-opus-4.5", Name: "Claude Opus 4.5", Provider: "Anthropic", EnvVarName: "ANTHROPIC_API_KEY"},
	{ID: "claude-sonnet-4.5", Name: "Claude Sonnet 4.5", Provider: "Anthropic", EnvVarName: "ANTHROPIC_API_KEY"},
	{ID: "claude-haiku-4.5", Name: "Claude Haiku 4.5", Provider: "Anthropic", EnvVarName: "ANTHROPIC_API_KEY"},
	{ID: "gpt-5", Name: "GPT-5", Provider: "OpenAI", EnvVarName: "OPENAI_API_KEY"},
	{ID: "gpt-5-nano", Name: "GPT-5 Nano", Provider: "OpenAI", EnvVarName: "OPENAI_API_KEY"},
	{ID: "gpt-5.1-codex", Name: "GPT-5.1 Codex", Provider: "OpenAI", EnvVarName: "OPENAI_API_KEY"},
	{ID: "qwen3-coder-fireworks", Name: "Qwen3 Coder", Provider: "Fireworks", EnvVarName: "FIREWORKS_API_KEY"},
	{ID: "glm-4p6-fireworks", Name: "GLM-4P6", Provider: "Fireworks", EnvVarName: "FIREWORKS_API_KEY"},
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
	shelleyUpdateMsg   struct{ output string; success bool }
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
	updateOutput  string  // Output from shelley update command
	updateSuccess bool    // Whether shelley update succeeded

	// Create flow state
	newDomain      string
	newDNSProvider dnsProvider
	newDNSToken    string
	newCFProxy     bool // Cloudflare proxy enabled
	newAppPort     int
	newSSHKey      string
	newAuthUser    string
	newAuthPass    string
	newModelIndex  int    // Index into availableModels
	newAPIKey      string // API key for the selected model

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

func createContainer(db *sql.DB, domain string, appPort int, sshKey string, dnsProvider dnsProvider, dnsToken string, cfProxy bool, authUser, authPass string, modelIndex int, apiKey string) error {
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

	// STEP 2: Clean up any stale container with same name (handles failed previous creations)
	// This prevents "In use" errors from partial container creations
	exec.Command("incus", "delete", name, "--force").Run()

	// STEP 3: Launch container from exeuntu OCI image with systemd init
	// boot.autostart=last-state ensures container respects its previous state on host reboot
	// (running containers restart, stopped containers stay stopped)
	cmd := exec.Command("incus", "launch", ExeuntuImage, name,
		"-c", "security.nesting=true",
		"-c", "boot.autostart=last-state",
		"-c", "oci.entrypoint=/sbin/init")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create container: %s - %w", string(out), err)
	}

	// Wait for container to start
	time.Sleep(5 * time.Second)

	// STEP 4: Add SSH key to container using file push (safer than shell echo)
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

	// STEP 5: Get container IP
	_, ip, _, _ := getContainerStatus(name)

	// STEP 6: Hash password for Shelley auth
	authHash := ""
	if authUser != "" && authPass != "" {
		hashOut, hashErr := exec.Command("caddy", "hash-password", "--plaintext", authPass).Output()
		if hashErr == nil {
			authHash = strings.TrimSpace(string(hashOut))
		}
	}

	// STEP 7: Save to database AFTER successful container creation
	_, err := db.Exec("INSERT INTO containers (name, domain, app_port, auth_user, auth_hash) VALUES (?, ?, ?, ?, ?)",
		name, domain, appPort, authUser, authHash)
	if err != nil {
		// Rollback: delete the container if DB insert fails
		exec.Command("incus", "delete", name, "--force").Run()
		return fmt.Errorf("failed to save to database: %w", err)
	}

	// STEP 8: Configure Caddy with auth (DNS has had time to propagate during container startup)
	if ip != "" {
		updateCaddyConfig(name, domain, ip, appPort, authUser, authHash)
	}

	// STEP 9: Configure SSHPiper
	if ip != "" {
		configureSSHPiper(name, ip)
	}

	// STEP 10: Configure Shelley (shelley.json and API key)
	if modelIndex >= 0 && modelIndex < len(availableModels) {
		configureShelley(name, modelIndex, apiKey)
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

// checkAllDNSForDomain checks both the main domain and shelley subdomain
// Returns true only if BOTH resolve correctly to the host IP
func checkAllDNSForDomain(domain string) bool {
	mainOK := checkDNSResolvesToHost(domain)
	shelleyOK := checkDNSResolvesToHost("shelley." + domain)
	return mainOK && shelleyOK
}

// importContainer adds an existing Incus container to our management DB
func importContainer(db *sql.DB, name, domain string, appPort int, authUser, authPass string, modelIndex int, apiKey string) error {
	// Verify container exists in Incus
	_, ip, _, _ := getContainerStatus(name)
	if ip == "" {
		// Container might be stopped, try to start it
		exec.Command("incus", "start", name).Run()
		time.Sleep(3 * time.Second)
		_, ip, _, _ = getContainerStatus(name)
	}

	// Hash password for Shelley auth
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
	if ip != "" {
		updateCaddyConfig(name, domain, ip, appPort, authUser, authHash)
		configureSSHPiper(name, ip)
	}

	// Set boot.autostart to last-state if not already set
	exec.Command("incus", "config", "set", name, "boot.autostart=last-state").Run()

	// Configure Shelley (shelley.json and API key)
	if modelIndex >= 0 && modelIndex < len(availableModels) {
		configureShelley(name, modelIndex, apiKey)
	}

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
		var authUser, authHash sql.NullString
		if err := db.QueryRow("SELECT domain, app_port, auth_user, auth_hash FROM containers WHERE name = ?", name).Scan(&domain, &appPort, &authUser, &authHash); err == nil {
			updateCaddyConfig(name, domain, ip, appPort, authUser.String, authHash.String)
			configureSSHPiper(name, ip)
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

	// Delete existing routes for this container (if any)
	deleteCaddyRoute(client, caddyAPI, name+"-app")
	deleteCaddyRoute(client, caddyAPI, name+"-shelley")

	// Add app route (no auth - public)
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

	// Build shelley route handlers
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

	// Add reverse proxy handler
	shelleyHandlers = append(shelleyHandlers, map[string]interface{}{
		"handler":   "reverse_proxy",
		"upstreams": []map[string]string{{"dial": fmt.Sprintf("%s:%d", ip, ShelleyPort)}},
	})

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

func configureSSHPiper(name, ip string) {
	pDir := filepath.Join(SSHPiperRoot, name)
	os.MkdirAll(pDir, 0700)
	// Map to exedev user on container (where SSH key is installed)
	os.WriteFile(filepath.Join(pDir, "sshpiper_upstream"), []byte("exedev@"+ip+":22\n"), 0600)
}

// configureShelley updates shelley.json and sets the API key in bashrc
func configureShelley(containerName string, modelIndex int, apiKey string) {
	if modelIndex < 0 || modelIndex >= len(availableModels) {
		return
	}
	model := availableModels[modelIndex]

	// Create the new shelley.json content
	// Remove: llm_gateway, terminal_url, links (back to exe.dev)
	shelleyConfig := fmt.Sprintf(`{"default_model":"%s","key_generator":"echo irrelevant"}`, model.ID)

	// Write shelley.json to container (as root)
	tmpFile, err := os.CreateTemp("", "shelley-json")
	if err != nil {
		return
	}
	tmpFile.WriteString(shelleyConfig)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Push to container
	exec.Command("incus", "file", "push", tmpFile.Name(), containerName+"/exe.dev/shelley.json").Run()
	// Set ownership to root
	exec.Command("incus", "exec", containerName, "--", "chown", "root:root", "/exe.dev/shelley.json").Run()
	exec.Command("incus", "exec", containerName, "--", "chmod", "644", "/exe.dev/shelley.json").Run()

	// Add API key to exedev's bashrc
	exportLine := fmt.Sprintf("export %s='%s'", model.EnvVarName, apiKey)
	
	// Check if the env var already exists in bashrc and update/add it
	bashrcPath := "/home/exedev/.bashrc"
	
	// Read current bashrc
	readCmd := exec.Command("incus", "exec", containerName, "--", "cat", bashrcPath)
	currentBashrc, _ := readCmd.Output()
	
	// Check if this env var already exists
	lines := strings.Split(string(currentBashrc), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "export "+model.EnvVarName+"=") {
			lines[i] = exportLine
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, exportLine)
	}
	
	// Write updated bashrc
	newBashrc := strings.Join(lines, "\n")
	tmpBashrc, err := os.CreateTemp("", "bashrc")
	if err != nil {
		return
	}
	tmpBashrc.WriteString(newBashrc)
	tmpBashrc.Close()
	defer os.Remove(tmpBashrc.Name())
	
	exec.Command("incus", "file", "push", tmpBashrc.Name(), containerName+bashrcPath).Run()
	exec.Command("incus", "exec", containerName, "--", "chown", "exedev:exedev", bashrcPath).Run()
}

// Log streaming
func streamLogsCmd(service string) tea.Cmd {
	return func() tea.Msg {
		out, _ := exec.Command("journalctl", "-u", service, "-n", "50", "--no-pager").Output()
		return logMsg(string(out))
	}
}

// updateShelleyCmd runs the shelley update command on a container
func updateShelleyCmd(containerName string) tea.Cmd {
	return func() tea.Msg {
		// The update command to run on the container
		updateScript := `curl -Lo /usr/local/bin/shelley "https://github.com/boldsoftware/shelley/releases/latest/download/shelley_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" && chmod +x /usr/local/bin/shelley && sudo systemctl restart shelley`

		// Run as exedev user
		cmd := exec.Command("incus", "exec", containerName, "--user", "1000", "--", "bash", "-c", updateScript)
		output, err := cmd.CombinedOutput()

		result := string(output)
		success := err == nil

		if success {
			result += "\n\n✅ Shelley updated successfully!"
		} else {
			result += fmt.Sprintf("\n\n❌ Update failed: %v", err)
		}

		return shelleyUpdateMsg{output: result, success: success}
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
			m.status = "Shelley updated successfully"
		} else {
			m.status = "Shelley update failed"
		}
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
	case stateCreateDomain, stateCreateDNSToken, stateCreateAppPort, stateCreateSSHKey, stateCreateAuthUser, stateCreateAuthPass, stateCreateAPIKey, stateEditAppPort, stateEditAuthUser, stateEditAuthPass, stateImportContainer, stateImportAuthUser, stateImportAuthPass, stateImportAPIKey:
		return m.handleInputKeys(key)
	case stateCreateDNSProvider:
		return m.handleDNSProviderKeys(key)
	case stateCreateCFProxy:
		return m.handleCFProxyKeys(key)
	case stateCreateModelSelect:
		return m.handleModelSelectKeys(key)
	case stateImportModelSelect:
		return m.handleImportModelSelectKeys(key)
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
	case "u":
		// Update shelley binary on container
		if c.Status != "running" {
			m.status = "Container must be running to update Shelley"
			return m, nil
		}
		m.status = "Updating Shelley on " + c.Name + "..."
		m.state = stateUpdateShelley
		m.updateOutput = "Updating Shelley binary...\n"
		m.updateSuccess = false
		return m, updateShelleyCmd(c.Name)
	case "S":
		// Snapshot management
		m.snapshots = listSnapshots(c.Name)
		m.snapshotCursor = 0
		m.state = stateSnapshots
		return m, nil
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
		
		// Check if DNS already resolves correctly - skip DNS provider selection if so
		if checkAllDNSForDomain(val) {
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
			return m, nil
		}
		m.newSSHKey = val
		m.state = stateCreateAuthUser
		m.textInput.Placeholder = "admin"
		m.textInput.SetValue("admin")

	case stateCreateAuthUser:
		if val == "" {
			m.status = "Username required for Shelley authentication"
			return m, nil
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
			return m, nil
		}
		m.newAuthPass = val
		m.textInput.EchoMode = textinput.EchoNormal
		// Go to model selection
		m.state = stateCreateModelSelect
		m.newModelIndex = 0 // Default to first model
		m.textInput.Reset()

	case stateCreateAPIKey:
		if val == "" {
			m.status = "API key is required"
			return m, nil
		}
		m.newAPIKey = val
		m.status = "Creating container..."
		err := createContainer(m.db, m.newDomain, m.newAppPort, m.newSSHKey, m.newDNSProvider, m.newDNSToken, m.newCFProxy, m.newAuthUser, m.newAuthPass, m.newModelIndex, m.newAPIKey)
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

	case stateEditAuthUser:
		if val == "" {
			m.status = "Username cannot be empty"
			return m, nil
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
			return m, nil
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
		return m, m.refreshContainers()

	case stateImportContainer:
		if val == "" {
			m.status = "Domain cannot be empty"
			return m, nil
		}
		m.newDomain = val
		
		// Check DNS status and show info
		if checkAllDNSForDomain(val) {
			m.status = "✓ DNS already configured correctly"
		} else {
			m.status = "⚠ DNS not configured - set up DNS records manually after import"
		}
		
		m.state = stateImportAuthUser
		m.textInput.Placeholder = "admin"
		m.textInput.SetValue("admin")

	case stateImportAuthUser:
		if val == "" {
			m.status = "Username required for Shelley authentication"
			return m, nil
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
			return m, nil
		}
		m.newAuthPass = val
		m.textInput.EchoMode = textinput.EchoNormal
		// Go to model selection for import
		m.state = stateImportModelSelect
		m.newModelIndex = 0
		m.textInput.Reset()

	case stateImportAPIKey:
		if val == "" {
			m.status = "API key is required"
			return m, nil
		}
		m.newAPIKey = val
		if m.cursor < len(m.untrackedContainers) {
			containerName := m.untrackedContainers[m.cursor]
			err := importContainer(m.db, containerName, m.newDomain, DefaultAppPort, m.newAuthUser, m.newAuthPass, m.newModelIndex, m.newAPIKey)
			if err != nil {
				m.status = "Import failed: " + err.Error()
			} else {
				m.status = fmt.Sprintf("Imported %s as %s", containerName, m.newDomain)
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

func (m model) handleModelSelectKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.newModelIndex > 0 {
			m.newModelIndex--
		}
	case "down", "j":
		if m.newModelIndex < len(availableModels)-1 {
			m.newModelIndex++
		}
	case "enter":
		// Proceed to API key input
		model := availableModels[m.newModelIndex]
		m.state = stateCreateAPIKey
		m.textInput.Placeholder = model.EnvVarName + " value"
		m.textInput.Focus()
	}
	return m, nil
}

func (m model) handleImportModelSelectKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.newModelIndex > 0 {
			m.newModelIndex--
		}
	case "down", "j":
		if m.newModelIndex < len(availableModels)-1 {
			m.newModelIndex++
		}
	case "enter":
		// Proceed to API key input
		model := availableModels[m.newModelIndex]
		m.state = stateImportAPIKey
		m.textInput.Placeholder = model.EnvVarName + " value"
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
		return m, nil
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
	return m, nil
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
	case "4":
		// Delete deSEC token
		deleteDNSToken(m.db, dnsDesec)
		m.status = "deSEC token deleted"
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
		dnsStatus := "⚠ DNS not configured (records needed)"
		mainOK := checkDNSResolvesToHost(m.newDomain)
		shelleyOK := checkDNSResolvesToHost("shelley." + m.newDomain)
		if mainOK && shelleyOK {
			dnsStatus = "✅ DNS already configured correctly"
		} else if mainOK {
			dnsStatus = "⚠ Main domain OK, shelley." + m.newDomain + " not configured"
		} else if shelleyOK {
			dnsStatus = "⚠ shelley subdomain OK, main domain not configured"
		}
		return fmt.Sprintf("📦 CREATE: %s\n\n%s\n\nAuto-create DNS record?\n\n[1] No - I'll configure DNS manually\n[2] Cloudflare\n[3] deSEC\n\n[Esc] Cancel", m.newDomain, dnsStatus)

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
		return fmt.Sprintf("🔐 CREATE: %s\n\nShelley Auth Username:\n\n%s\n\n[Enter] Continue  [Esc] Cancel", m.newDomain, m.textInput.View())

	case stateCreateAuthPass:
		return fmt.Sprintf("🔐 CREATE: %s\n\nShelley Auth Password (min 8 chars):\n\n%s\n\n[Enter] Continue  [Esc] Cancel", m.newDomain, m.textInput.View())

	case stateCreateModelSelect:
		return m.viewModelSelect("CREATE: "+m.newDomain)

	case stateCreateAPIKey:
		model := availableModels[m.newModelIndex]
		return fmt.Sprintf("🤖 CREATE: %s\n\nSelected model: %s (%s)\n\nEnter %s:\n\n%s\n\n[Enter] Create Container  [Esc] Cancel",
			m.newDomain, model.Name, model.Provider, model.EnvVarName, m.textInput.View())

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
		s := fmt.Sprintf("%s UPDATE SHELLEY: %s\n", statusIcon, containerName)
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

	case stateImportAuthUser:
		if m.cursor < len(m.untrackedContainers) {
			return fmt.Sprintf("🔐 IMPORT: %s\n\nShelley Auth Username:\n\n%s\n\n[Enter] Continue  [Esc] Cancel",
				m.untrackedContainers[m.cursor], m.textInput.View())
		}
		return "No container selected"

	case stateImportAuthPass:
		if m.cursor < len(m.untrackedContainers) {
			return fmt.Sprintf("🔐 IMPORT: %s\n\nShelley Auth Password (min 8 chars):\n\n%s\n\n[Enter] Continue  [Esc] Cancel",
				m.untrackedContainers[m.cursor], m.textInput.View())
		}
		return "No container selected"

	case stateImportModelSelect:
		if m.cursor < len(m.untrackedContainers) {
			return m.viewModelSelect("IMPORT: " + m.untrackedContainers[m.cursor])
		}
		return "No container selected"

	case stateImportAPIKey:
		if m.cursor < len(m.untrackedContainers) {
			model := availableModels[m.newModelIndex]
			return fmt.Sprintf("🤖 IMPORT: %s\n\nSelected model: %s (%s)\n\nEnter %s:\n\n%s\n\n[Enter] Import Container  [Esc] Cancel",
				m.untrackedContainers[m.cursor], model.Name, model.Provider, model.EnvVarName, m.textInput.View())
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

	case stateLogs:
		return fmt.Sprintf("📜 LOGS: %s  [Esc] Back\n%s\n\n%s", m.currentSvc, strings.Repeat("─", 60), m.logContent)

	case stateContainerDetail:
		return m.viewContainerDetail()

	default:
		return m.viewList()
	}
}

func (m model) viewModelSelect(title string) string {
	s := fmt.Sprintf("🤖 %s\n", title)
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += "Select default LLM model for Shelley:\n\n"

	for i, model := range availableModels {
		cursor := "  "
		if i == m.newModelIndex {
			cursor = "▶ "
		}
		s += fmt.Sprintf("%s[%d] %-25s (%s)\n", cursor, i+1, model.Name, model.Provider)
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

	// Get auth user from DB
	var authUser sql.NullString
	m.db.QueryRow("SELECT auth_user FROM containers WHERE name = ?", c.Name).Scan(&authUser)
	authDisplay := "(not set)"
	if authUser.String != "" {
		authDisplay = authUser.String
	}

	s := fmt.Sprintf("🔍 CONTAINER: %s\n", c.Name)
	s += "═══════════════════════════════════════════════════════════════════════════════\n\n"
	s += fmt.Sprintf("  Domain:       %s\n", c.Domain)
	s += fmt.Sprintf("  Status:       %s\n", c.Status)
	s += fmt.Sprintf("  IP:           %s\n", c.IP)
	s += fmt.Sprintf("  CPU:          %s\n", c.CPU)
	s += fmt.Sprintf("  Memory:       %s\n", c.Memory)
	s += fmt.Sprintf("  App Port:     %d\n", c.AppPort)
	s += fmt.Sprintf("  Shelley Auth: %s\n", authDisplay)
	s += fmt.Sprintf("  Created:      %s\n", c.CreatedAt.Format("2006-01-02 15:04:05"))
	s += "\n"
	s += fmt.Sprintf("  🌐 App URL:     https://%s\n", c.Domain)
	s += fmt.Sprintf("  🤖 Shelley URL: https://shelley.%s\n", c.Domain)
	s += fmt.Sprintf("  🔑 SSH:         ssh -p 2222 %s@<host> (via sshpiper)\n", c.Name)
	s += "\n"
	s += "───────────────────────────────────────────────────────────────────────────────\n"
	s += "[s] Start/Stop  [r] Restart  [p] Change Port  [a] Change Auth\n"
	s += "[S] Snapshots   [u] Update Shelley  [Esc] Back\n"

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

	// Create the bubbletea program with options for better terminal handling
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
