package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	_ "modernc.org/sqlite"
)

// --- Configuration ---
const (
	BridgeName     = "fire0"
	BridgeIP       = "172.21.0.1"
	CaddyConfDir   = "/etc/caddy/conf.d"
	SSHPiperRoot   = "/var/lib/sshpiper"
	DomainSuffix   = "yourdomain.com"
	ExeuntuImage   = "ghcr.io/boldsoftware/exeuntu:latest"
	DBPath         = "/var/lib/shelley/shelley_prod.db"
	FirecrackerVer = "v1.10.1"
	FlintlockVer   = "v0.11.0"
)

type state int

const (
	stateChecking state = iota
	stateInstalling
	stateMain
	stateSSHInput
	stateLogs
)

type vmEntry struct {
	ID        int
	Name      string
	IP        string
	Subdomain string
	CPU       string
	Mem       string
}

type tickMsg time.Time
type logMsg string
type bootstrapResultMsg struct {
	db      *sql.DB
	missing []string
	err     error
}

type model struct {
	state      state
	db         *sql.DB
	vms        []vmEntry
	cursor     int
	textInput  textinput.Model
	status     string
	missing    []string
	logContent string
	currentSvc string
}

func (m model) Init() tea.Cmd {
	return tea.Batch(bootstrapCmd, m.tick())
}

func (m model) tick() tea.Cmd {
	return tea.Every(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// --- 1. BOOTSTRAP & INSTALL ENGINE ---

func bootstrapCmd() tea.Msg {
	// Check for required binaries
	bins := []string{"flintlockd", "firecracker", "caddy", "sshpiperd", "containerd"}
	var missing []string
	for _, b := range bins {
		if _, err := exec.LookPath(b); err != nil {
			missing = append(missing, b)
		}
	}
	if len(missing) > 0 {
		return bootstrapResultMsg{missing: missing}
	}

	// Persistent Networking
	_ = os.MkdirAll("/etc/systemd/network", 0755)
	_ = os.WriteFile("/etc/systemd/network/20-fire0.netdev",
		[]byte(fmt.Sprintf("[NetDev]\nName=%s\nKind=bridge\n", BridgeName)), 0644)
	_ = os.WriteFile("/etc/systemd/network/21-fire0.network",
		[]byte(fmt.Sprintf("[Match]\nName=%s\n[Network]\nAddress=%s/24\n", BridgeName, BridgeIP)), 0644)
	_ = exec.Command("systemctl", "unmask", "systemd-networkd").Run()
	_ = exec.Command("systemctl", "enable", "--now", "systemd-networkd").Run()
	_ = exec.Command("systemctl", "restart", "systemd-networkd").Run()

	// Persistence Folders
	_ = os.MkdirAll(CaddyConfDir, 0755)
	_ = os.MkdirAll(SSHPiperRoot, 0755)
	_ = os.MkdirAll(filepath.Dir(DBPath), 0755)

	// Update Caddyfile to import conf.d
	caddyMain := "/etc/caddy/Caddyfile"
	dat, _ := os.ReadFile(caddyMain)
	if !strings.Contains(string(dat), "import /etc/caddy/conf.d/*.conf") {
		f, err := os.OpenFile(caddyMain, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			_, _ = f.WriteString("\nimport /etc/caddy/conf.d/*.conf\n")
			_ = f.Close()
		}
	}

	// Service Generation
	writeService("flintlockd", fmt.Sprintf("/usr/local/bin/flintlockd run --parent-iface %s", BridgeName))
	writeService("sshpiperd", fmt.Sprintf("/usr/local/bin/sshpiperd -i /etc/sshpiper/server_key workingdir --root %s --no-check-perm", SSHPiperRoot))

	// Ensure sshpiper server key directory and key exist
	_ = os.MkdirAll("/etc/sshpiper", 0755)
	if _, err := os.Stat("/etc/sshpiper/server_key"); os.IsNotExist(err) {
		_ = exec.Command("ssh-keygen", "-t", "ed25519", "-f", "/etc/sshpiper/server_key", "-N", "").Run()
	}

	// Open/create database
	db, err := sql.Open("sqlite", DBPath)
	if err != nil {
		return bootstrapResultMsg{err: fmt.Errorf("failed to open database: %w", err)}
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS vms (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		ip TEXT,
		subdomain TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return bootstrapResultMsg{err: fmt.Errorf("failed to create table: %w", err)}
	}

	return bootstrapResultMsg{db: db}
}

func writeService(name, cmd string) {
	path := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	unit := fmt.Sprintf(`[Unit]
Description=%s service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, name, cmd)
	_ = os.WriteFile(path, []byte(unit), 0644)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "enable", "--now", name).Run()
}

func (m model) installMissing() tea.Cmd {
	return func() tea.Msg {
		arch := runtime.GOARCH
		if arch == "amd64" {
			arch = "x86_64"
		}

		for _, bin := range m.missing {
			switch bin {
			case "caddy", "containerd":
				_ = exec.Command("apt", "update").Run()
				_ = exec.Command("apt", "install", "-y", bin).Run()

			case "flintlockd":
				url := fmt.Sprintf("https://github.com/weaveworks-liquidmetal/flintlock/releases/download/%s/flintlock_%s_linux_%s.tar.gz",
					FlintlockVer, strings.TrimPrefix(FlintlockVer, "v"), arch)
				if err := downloadAndExtract(url, "/usr/local/bin"); err != nil {
					return bootstrapResultMsg{err: fmt.Errorf("failed to install flintlockd: %w", err)}
				}

			case "firecracker":
				url := fmt.Sprintf("https://github.com/firecracker-microvm/firecracker/releases/download/%s/firecracker-%s-%s.tgz",
					FirecrackerVer, FirecrackerVer, arch)
				if err := downloadAndExtract(url, "/tmp/fc"); err != nil {
					return bootstrapResultMsg{err: fmt.Errorf("failed to download firecracker: %w", err)}
				}
				// Move binaries to /usr/local/bin
				files, _ := filepath.Glob("/tmp/fc/release-*/firecracker-*")
				for _, f := range files {
					base := filepath.Base(f)
					if strings.HasPrefix(base, "firecracker-") && !strings.Contains(base, ".") {
						_ = os.Rename(f, "/usr/local/bin/firecracker")
						_ = os.Chmod("/usr/local/bin/firecracker", 0755)
					}
				}

			case "sshpiperd":
				// sshpiperd needs to be built from source or downloaded from releases
				url := "https://github.com/tg123/sshpiper/releases/latest/download/sshpiperd_linux_amd64.tar.gz"
				if arch == "aarch64" {
					url = "https://github.com/tg123/sshpiper/releases/latest/download/sshpiperd_linux_arm64.tar.gz"
				}
				if err := downloadAndExtract(url, "/usr/local/bin"); err != nil {
					return bootstrapResultMsg{err: fmt.Errorf("failed to install sshpiperd: %w", err)}
				}
			}
		}
		return bootstrapCmd()
	}
}

func downloadAndExtract(url, destDir string) error {
	_ = os.MkdirAll(destDir, 0755)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download: HTTP %d", resp.StatusCode)
	}

	tmpFile := "/tmp/download.tar.gz"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		return err
	}

	cmd := exec.Command("tar", "-xzf", tmpFile, "-C", destDir)
	return cmd.Run()
}

// --- 2. ORCHESTRATION & MONITORING ---

func (m *model) createVM(sshKey string) {
	name := fmt.Sprintf("shelley-%x", time.Now().Unix())
	sub := name + "." + DomainSuffix

	// Create cloud-init user-data
	userData := fmt.Sprintf(`#cloud-config
ssh_authorized_keys:
  - %s
`, strings.TrimSpace(sshKey))
	userDataPath := "/tmp/" + name + "-cloud"
	if err := os.WriteFile(userDataPath, []byte(userData), 0644); err != nil {
		m.status = "Error: failed to write user-data"
		return
	}

	// Note: flintlock uses gRPC API, not a CLI "create" command
	// This is a placeholder - actual implementation would use flintlock's gRPC client
	// For now, we'll use a hypothetical CLI wrapper or direct API call
	cmd := exec.Command("flintctl", "microvm", "create",
		"--name", name,
		"--kernel", "/var/lib/flintlock/kernel/vmlinux",
		"--root-image", ExeuntuImage,
		"--metadata", userDataPath,
		"--output", "json")

	out, err := cmd.Output()
	if err != nil {
		m.status = fmt.Sprintf("Error creating VM: %v", err)
		return
	}

	var res struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		m.status = fmt.Sprintf("Error parsing VM response: %v", err)
		return
	}

	// Configure Caddy reverse proxy
	caddyConf := fmt.Sprintf(`%s {
	reverse_proxy %s:3000
}
`, sub, res.IP)
	if err := os.WriteFile(filepath.Join(CaddyConfDir, name+".conf"), []byte(caddyConf), 0644); err != nil {
		m.status = "Error: failed to write Caddy config"
		return
	}
	_ = exec.Command("systemctl", "reload", "caddy").Run()

	// Configure SSHPiper
	pDir := filepath.Join(SSHPiperRoot, name)
	_ = os.MkdirAll(pDir, 0700)
	upstreamConf := fmt.Sprintf("%s:22\n", res.IP)
	_ = os.WriteFile(filepath.Join(pDir, "sshpiper_upstream"), []byte(upstreamConf), 0600)

	// Save to database
	if m.db != nil {
		_, _ = m.db.Exec("INSERT INTO vms (name, ip, subdomain) VALUES (?, ?, ?)", name, res.IP, sub)
	}

	m.status = "Deployed " + name
}

func (m *model) deleteVM() {
	if len(m.vms) == 0 {
		return
	}
	vm := m.vms[m.cursor]

	// Delete the microVM
	_ = exec.Command("flintctl", "microvm", "delete", vm.Name).Run()

	// Remove Caddy config
	_ = os.Remove(filepath.Join(CaddyConfDir, vm.Name+".conf"))
	_ = exec.Command("systemctl", "reload", "caddy").Run()

	// Remove SSHPiper config
	_ = os.RemoveAll(filepath.Join(SSHPiperRoot, vm.Name))

	// Remove from database
	if m.db != nil {
		_, _ = m.db.Exec("DELETE FROM vms WHERE name = ?", vm.Name)
	}

	m.status = "Deleted " + vm.Name
}

func (m model) streamLogs(service string) tea.Cmd {
	return func() tea.Msg {
		out, _ := exec.Command("journalctl", "-u", service, "-n", "40", "--no-pager").Output()
		return logMsg(out)
	}
}

func (m *model) refreshVMs() {
	if m.db == nil {
		return
	}

	rows, err := m.db.Query("SELECT id, name, ip, subdomain FROM vms")
	if err != nil {
		return
	}
	defer rows.Close()

	m.vms = nil
	for rows.Next() {
		var v vmEntry
		if err := rows.Scan(&v.ID, &v.Name, &v.IP, &v.Subdomain); err != nil {
			continue
		}

		// Get CPU/memory usage via process lookup
		cmd := fmt.Sprintf("ps -eo pcpu,pmem,args | grep '[f]irecracker' | grep '%s'", v.Name)
		out, _ := exec.Command("sh", "-c", cmd).Output()
		fields := strings.Fields(string(out))
		if len(fields) >= 2 {
			v.CPU = fields[0] + "%"
			v.Mem = fields[1] + "%"
		} else {
			v.CPU = "N/A"
			v.Mem = "N/A"
		}
		m.vms = append(m.vms, v)
	}
}

// --- 3. TUI CORE ---

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case bootstrapResultMsg:
		if msg.err != nil {
			m.status = fmt.Sprintf("Error: %v", msg.err)
			m.state = stateMain
			return m, m.tick()
		}
		if len(msg.missing) > 0 {
			m.missing = msg.missing
			m.state = stateInstalling
			return m, m.installMissing()
		}
		if msg.db != nil {
			m.db = msg.db
			m.state = stateMain
			m.refreshVMs()
		}
		return m, m.tick()

	case tickMsg:
		m.refreshVMs()
		if m.state == stateLogs {
			return m, tea.Batch(m.streamLogs(m.currentSvc), m.tick())
		}
		return m, m.tick()

	case logMsg:
		m.logContent = string(msg)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "esc":
			m.state = stateMain
			return m, m.tick()
		case "i":
			if m.state == stateMain {
				m.currentSvc = "flintlockd"
				m.state = stateLogs
				return m, m.streamLogs("flintlockd")
			}
		case "o":
			if m.state == stateMain {
				m.currentSvc = "sshpiperd"
				m.state = stateLogs
				return m, m.streamLogs("sshpiperd")
			}
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down":
			if m.cursor < len(m.vms)-1 {
				m.cursor++
			}
		case "n":
			if m.state == stateMain {
				m.state = stateSSHInput
				m.textInput.Focus()
			}
		case "x":
			if m.state == stateMain {
				m.deleteVM()
			}
		case "enter":
			if m.state == stateSSHInput {
				m.createVM(m.textInput.Value())
				m.state = stateMain
				m.textInput.Reset()
			}
		}
	}

	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m model) View() string {
	switch m.state {
	case stateChecking:
		return "🔍 Initializing infrastructure and checking binaries..."
	case stateInstalling:
		return fmt.Sprintf("📥 Missing binaries detected: %v\nRunning zero-touch installation...", m.missing)
	case stateSSHInput:
		return "🔑 Paste SSH Public Key for Shelley VM:\n\n" + m.textInput.View() + "\n\n(Enter to Launch, Esc to cancel)"
	case stateLogs:
		return fmt.Sprintf("\n--- SERVICE LOGS: %s (Esc to close) ---\n\n%s", m.currentSvc, m.logContent)
	default:
		s := "💠 SHELLEY MANAGER | [n] New VM | [x] Delete | [i] Flint Logs | [o] Piper Logs | [q] Quit\n\n"
		s += fmt.Sprintf(" %-20s | %-15s | %-6s | %-6s | %-30s\n", "NAME", "IP", "CPU", "MEM", "DOMAIN")
		s += strings.Repeat("─", 90) + "\n"
		for i, v := range m.vms {
			cur := " "
			if i == m.cursor {
				cur = ">"
			}
			s += fmt.Sprintf("%s%-20s | %-15s | %-6s | %-6s | %s\n", cur, v.Name, v.IP, v.CPU, v.Mem, v.Subdomain)
		}
		if len(m.vms) == 0 {
			s += "\n  No active Firecracker VMs.\n"
		}
		if m.status != "" {
			s += "\n Status: " + m.status
		}
		return s
	}
}

func main() {
	ti := textinput.New()
	ti.Placeholder = "ssh-ed25519 AAA..."
	ti.Width = 60

	p := tea.NewProgram(model{state: stateChecking, textInput: ti})
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
