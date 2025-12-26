// Package copilot provides GitHub Copilot integration via the external copilot-api process.
// It manages the lifecycle of the copilot-api Node.js process, handles authentication events,
// and provides status monitoring for the Copilot API endpoint.
package copilot

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	log "github.com/sirupsen/logrus"
)

// DefaultPort is the default port for the copilot-api server.
const DefaultPort = 54546

// Status represents the current state of the copilot-api process.
type Status struct {
	Running       bool   `json:"running"`
	Port          int    `json:"port"`
	Endpoint      string `json:"endpoint"`
	Authenticated bool   `json:"authenticated"`
	PID           int    `json:"pid,omitempty"`
}

// AuthEvent represents an authentication event from copilot-api.
type AuthEvent struct {
	Type     string `json:"type"`      // "device_code", "authenticated", "error"
	Code     string `json:"code"`      // Device code for user to enter
	URL      string `json:"url"`       // URL for authentication
	Message  string `json:"message"`   // Human-readable message
	ExpiresIn int   `json:"expires_in"` // Seconds until code expires
}

// AuthEventHandler is a callback for authentication events.
type AuthEventHandler func(event AuthEvent)

// Manager handles the lifecycle of the copilot-api process.
type Manager struct {
	cfg           *config.CopilotConfig
	cmd           *exec.Cmd
	mu            sync.RWMutex
	running       bool
	authenticated bool
	port          int
	authHandler   AuthEventHandler
	stopChan      chan struct{}
	httpClient    *http.Client
}

// NewManager creates a new Copilot manager with the given configuration.
func NewManager(cfg *config.CopilotConfig) *Manager {
	port := cfg.Port
	if port == 0 {
		port = DefaultPort
	}

	return &Manager{
		cfg:  cfg,
		port: port,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// SetAuthHandler sets the callback for authentication events.
func (m *Manager) SetAuthHandler(handler AuthEventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authHandler = handler
}

// Start spawns the copilot-api process.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil // Already running
	}
	m.mu.Unlock()

	// Find npx or bunx
	npxPath, err := findNodeRunner()
	if err != nil {
		return fmt.Errorf("copilot-api requires Node.js: %w", err)
	}

	// Build command arguments
	args := []string{"copilot-api@latest", "start", "--port", strconv.Itoa(m.port)}

	// Add account type flag
	switch strings.ToLower(m.cfg.AccountType) {
	case "business":
		args = append(args, "--business")
	case "enterprise":
		args = append(args, "--enterprise")
	}

	// Add rate limiting
	if m.cfg.RateLimit > 0 {
		args = append(args, "--rate-limit", strconv.Itoa(m.cfg.RateLimit))
		if m.cfg.RateLimitWait {
			args = append(args, "--wait")
		}
	}

	// Add GitHub token if provided
	if m.cfg.GithubToken != "" {
		args = append(args, "--github-token", m.cfg.GithubToken)
	}

	// Create command
	cmd := exec.CommandContext(ctx, npxPath, args...)
	cmd.Env = os.Environ()

	// Capture stdout for auth messages
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Capture stderr for logging
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start copilot-api: %w", err)
	}

	m.mu.Lock()
	m.cmd = cmd
	m.running = true
	m.stopChan = make(chan struct{})
	m.mu.Unlock()

	log.WithFields(log.Fields{
		"port": m.port,
		"pid":  cmd.Process.Pid,
	}).Info("Started copilot-api process")

	// Monitor stdout for auth events
	go m.monitorOutput(stdout, "stdout")
	go m.monitorOutput(stderr, "stderr")

	// Wait for process exit in background
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		m.running = false
		m.authenticated = false
		close(m.stopChan)
		m.mu.Unlock()

		if err != nil {
			log.WithError(err).Warn("copilot-api process exited with error")
		} else {
			log.Info("copilot-api process exited normally")
		}
	}()

	return nil
}

// Stop gracefully stops the copilot-api process.
func (m *Manager) Stop() error {
	m.mu.Lock()
	if !m.running || m.cmd == nil || m.cmd.Process == nil {
		m.mu.Unlock()
		return nil
	}
	cmd := m.cmd
	stopChan := m.stopChan
	m.mu.Unlock()

	log.Info("Stopping copilot-api process...")

	// Send interrupt signal
	if runtime.GOOS == "windows" {
		// Windows doesn't support interrupt, use kill
		if err := cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill copilot-api: %w", err)
		}
	} else {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return fmt.Errorf("failed to interrupt copilot-api: %w", err)
		}
	}

	// Wait for process to exit with timeout
	select {
	case <-stopChan:
		log.Info("copilot-api process stopped")
	case <-time.After(10 * time.Second):
		log.Warn("copilot-api did not stop gracefully, killing...")
		_ = cmd.Process.Kill()
	}

	return nil
}

// GetStatus returns the current status of the copilot-api process.
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := Status{
		Running:       m.running,
		Port:          m.port,
		Endpoint:      fmt.Sprintf("http://127.0.0.1:%d", m.port),
		Authenticated: m.authenticated,
	}

	if m.cmd != nil && m.cmd.Process != nil {
		status.PID = m.cmd.Process.Pid
	}

	return status
}

// HealthCheck verifies the copilot-api endpoint is responding.
func (m *Manager) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	if !m.running {
		m.mu.RUnlock()
		return fmt.Errorf("copilot-api is not running")
	}
	port := m.port
	m.mu.RUnlock()

	url := fmt.Sprintf("http://127.0.0.1:%d/v1/models", port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("copilot-api not responding: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("copilot-api returned status %d", resp.StatusCode)
	}

	m.mu.Lock()
	m.authenticated = true
	m.mu.Unlock()

	return nil
}

// monitorOutput reads output from the process and handles auth events.
func (m *Manager) monitorOutput(r io.Reader, source string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		log.WithField("source", source).Debug(line)

		// Check for device code auth message
		if strings.Contains(line, "device code") || strings.Contains(line, "https://github.com/login/device") {
			m.emitAuthEvent(AuthEvent{
				Type:    "device_code",
				Message: line,
				URL:     "https://github.com/login/device",
			})
		}

		// Check for successful authentication
		if strings.Contains(line, "authenticated") || strings.Contains(line, "logged in") {
			m.mu.Lock()
			m.authenticated = true
			m.mu.Unlock()
			m.emitAuthEvent(AuthEvent{
				Type:    "authenticated",
				Message: "Successfully authenticated with GitHub Copilot",
			})
		}
	}
}

// emitAuthEvent sends an auth event to the handler if set.
func (m *Manager) emitAuthEvent(event AuthEvent) {
	m.mu.RLock()
	handler := m.authHandler
	m.mu.RUnlock()

	if handler != nil {
		handler(event)
	}
}

// findNodeRunner finds npx or bunx executable.
func findNodeRunner() (string, error) {
	// Try npx first (more common)
	var npxName string
	if runtime.GOOS == "windows" {
		npxName = "npx.cmd"
	} else {
		npxName = "npx"
	}

	if path, err := exec.LookPath(npxName); err == nil {
		return path, nil
	}

	// Try bunx as fallback
	var bunxName string
	if runtime.GOOS == "windows" {
		bunxName = "bunx.exe"
	} else {
		bunxName = "bunx"
	}

	if path, err := exec.LookPath(bunxName); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("neither npx nor bunx found in PATH; please install Node.js or Bun")
}
