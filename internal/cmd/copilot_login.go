package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	log "github.com/sirupsen/logrus"
)

// DoCopilotLogin starts the copilot-api process for interactive authentication.
// It runs the device code flow and waits for the user to complete authentication.
func DoCopilotLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	// Find npx or bunx
	npxPath, err := findCopilotRunner()
	if err != nil {
		log.Errorf("Copilot login failed: %v", err)
		fmt.Println("\nPlease install Node.js from https://nodejs.org or Bun from https://bun.sh")
		return
	}

	fmt.Println("Starting GitHub Copilot authentication...")
	fmt.Println("This will use the device code flow to authenticate with GitHub.")
	fmt.Println()

	// Build command arguments for copilot-api
	args := []string{"copilot-api@latest", "auth", "login"}

	// Add account type if configured
	if cfg != nil && cfg.Copilot.AccountType != "" {
		switch strings.ToLower(cfg.Copilot.AccountType) {
		case "business":
			args = append(args, "--business")
		case "enterprise":
			args = append(args, "--enterprise")
		}
	}

	// Create command
	cmd := exec.Command(npxPath, args...)
	cmd.Env = os.Environ()

	// Create pipes for output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("Failed to create stdout pipe: %v", err)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Errorf("Failed to create stderr pipe: %v", err)
		return
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		log.Errorf("Failed to start copilot-api: %v", err)
		return
	}

	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nCancelling authentication...")
		_ = cmd.Process.Kill()
	}()

	// Monitor stdout for auth messages
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)

			// Check for device code - highlight it for user
			if strings.Contains(line, "https://github.com/login/device") ||
				strings.Contains(line, "device code") {
				fmt.Println("\n" + strings.Repeat("=", 60))
				fmt.Println("  Please visit the URL above and enter the code shown")
				fmt.Println(strings.Repeat("=", 60) + "\n")

				// Try to open browser if not disabled
				if !options.NoBrowser {
					go openBrowserSafe("https://github.com/login/device")
				}
			}
		}
	}()

	// Monitor stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) != "" {
				fmt.Fprintln(os.Stderr, line)
			}
		}
	}()

	// Wait for process to complete
	err = cmd.Wait()
	signal.Stop(sigChan)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == -1 {
				// Process was killed (e.g., by Ctrl+C)
				return
			}
		}
		log.Errorf("Copilot authentication failed: %v", err)
		return
	}

	fmt.Println("\nGitHub Copilot authentication successful!")
	fmt.Println("You can now use copilot-* models in your requests.")
}

// findCopilotRunner finds npx or bunx executable.
func findCopilotRunner() (string, error) {
	var npxName string
	if runtime.GOOS == "windows" {
		npxName = "npx.cmd"
	} else {
		npxName = "npx"
	}

	if path, err := exec.LookPath(npxName); err == nil {
		return path, nil
	}

	var bunxName string
	if runtime.GOOS == "windows" {
		bunxName = "bunx.exe"
	} else {
		bunxName = "bunx"
	}

	if path, err := exec.LookPath(bunxName); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("neither npx nor bunx found in PATH")
}

// openBrowserSafe attempts to open a URL in the default browser.
func openBrowserSafe(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
