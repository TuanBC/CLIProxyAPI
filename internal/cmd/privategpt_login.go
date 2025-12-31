package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	log "github.com/sirupsen/logrus"
)

// DoPrivateGPTLogin opens the browser to PrivateGPT and displays instructions
// for refreshing the authentication token.
func DoPrivateGPTLogin(cfg *config.Config, options *LoginOptions) {
	upstreamURL := cfg.PrivateGPT.UpstreamURL
	if upstreamURL == "" {
		upstreamURL = "https://privategpt.fptconsulting.co.jp"
	}

	port := cfg.PrivateGPT.Port
	if port == 0 {
		port = 54547
	}

	// Resolve AuthDir
	authDir, err := util.ResolveAuthDir(cfg.AuthDir)
	if err != nil {
		log.Fatalf("Failed to resolve auth directory: %v", err)
	}
	if err := os.MkdirAll(authDir, 0755); err != nil {
		log.Fatalf("Failed to create auth directory: %v", err)
	}
	tokenFile := filepath.Join(authDir, "privategpt_token")

	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              PrivateGPT Token Refresh                            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Opening browser to: %s\n", upstreamURL)
	fmt.Println()
	
	// Open browser
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", upstreamURL)
	case "darwin":
		cmd = exec.Command("open", upstreamURL)
	default:
		cmd = exec.Command("xdg-open", upstreamURL)
	}
	
	if err := cmd.Start(); err != nil {
		fmt.Printf("Failed to open browser: %v\n", err)
		fmt.Printf("Please manually navigate to: %s\n", upstreamURL)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Println("STEP 1: Log in via SSO (if not already logged in)")
	fmt.Println()
	fmt.Println("STEP 2: Open browser Developer Tools (F12)")
	fmt.Println()
	fmt.Println("STEP 3: Go to Console tab and paste this code:")
	fmt.Println("        (This will copy the token to your clipboard)")
	fmt.Println()
	fmt.Println("────────────────────────────────────────────────────────────────────")
	fmt.Println("copy(JSON.parse(localStorage.getItem(JSON.parse(localStorage.getItem(Object.keys(localStorage).find(k=>k.startsWith('msal.token.keys.')))).accessToken[0])).secret)")
	fmt.Println("────────────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("STEP 4: Passt the token below and press Enter:")
	fmt.Println()
	
	fmt.Print("> ")
	
	// Read token from stdin
	var token string
	// Increase buffer size for long tokens if scanning lines
	// Using a scanner to handle potential spaces or just reading the line
	// Tokens are usually long base64 strings without spaces, but better safe
	var scanner = bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		token = strings.TrimSpace(scanner.Text())
	}

	if token == "" {
		fmt.Println("\nError: No token entered. Exiting.")
		return
	}

	if !strings.HasPrefix(token, "Bearer ") {
		token = "Bearer " + token
	}

	// Save token to file
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		log.Errorf("Failed to save token: %v", err)
		fmt.Printf("\nError: Failed to save token: %v\n", err)
		return
	}
	
	fmt.Println("\n✅ Success! Token saved.")
	fmt.Println("You can now use the API.")
}
