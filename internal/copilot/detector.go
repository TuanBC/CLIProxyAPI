// Package copilot provides GitHub Copilot integration via the external copilot-api process.
package copilot

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Detection contains information about the Node.js/Bun runtime availability.
type Detection struct {
	NodeAvailable     bool     `json:"node_available"`
	NPXPath           string   `json:"npx_path,omitempty"`
	BunXPath          string   `json:"bunx_path,omitempty"`
	NodeVersion       string   `json:"node_version,omitempty"`
	BunVersion        string   `json:"bun_version,omitempty"`
	CopilotAPIInstalled bool   `json:"copilot_api_installed"`
	CheckedPaths      []string `json:"checked_paths,omitempty"`
	ErrorMessage      string   `json:"error_message,omitempty"`
}

// Detect checks for Node.js/Bun runtime and copilot-api availability.
func Detect() Detection {
	d := Detection{
		CheckedPaths: make([]string, 0),
	}

	// Check for npx
	npxPath, nodeVersion := detectNPX()
	if npxPath != "" {
		d.NPXPath = npxPath
		d.NodeVersion = nodeVersion
		d.NodeAvailable = true
		d.CheckedPaths = append(d.CheckedPaths, npxPath)
	}

	// Check for bunx
	bunxPath, bunVersion := detectBunX()
	if bunxPath != "" {
		d.BunXPath = bunxPath
		d.BunVersion = bunVersion
		if !d.NodeAvailable {
			d.NodeAvailable = true
		}
		d.CheckedPaths = append(d.CheckedPaths, bunxPath)
	}

	// If neither found, set error message
	if !d.NodeAvailable {
		d.ErrorMessage = "Neither Node.js (npx) nor Bun (bunx) found in PATH. Please install Node.js from https://nodejs.org or Bun from https://bun.sh"
	}

	// Check if copilot-api is globally installed
	if d.NodeAvailable {
		d.CopilotAPIInstalled = checkCopilotAPIInstalled()
	}

	return d
}

// detectNPX finds npx executable and returns its path and Node.js version.
func detectNPX() (path string, version string) {
	var npxName string
	if runtime.GOOS == "windows" {
		npxName = "npx.cmd"
	} else {
		npxName = "npx"
	}

	path, err := exec.LookPath(npxName)
	if err != nil {
		return "", ""
	}

	// Get Node.js version
	var nodeName string
	if runtime.GOOS == "windows" {
		nodeName = "node.exe"
	} else {
		nodeName = "node"
	}

	cmd := exec.Command(nodeName, "--version")
	output, err := cmd.Output()
	if err == nil {
		version = strings.TrimSpace(string(output))
	}

	return path, version
}

// detectBunX finds bunx executable and returns its path and Bun version.
func detectBunX() (path string, version string) {
	var bunxName string
	if runtime.GOOS == "windows" {
		bunxName = "bunx.exe"
	} else {
		bunxName = "bunx"
	}

	path, err := exec.LookPath(bunxName)
	if err != nil {
		return "", ""
	}

	// Get Bun version
	var bunName string
	if runtime.GOOS == "windows" {
		bunName = "bun.exe"
	} else {
		bunName = "bun"
	}

	cmd := exec.Command(bunName, "--version")
	output, err := cmd.Output()
	if err == nil {
		version = strings.TrimSpace(string(output))
	}

	return path, version
}

// checkCopilotAPIInstalled checks if copilot-api is globally installed.
func checkCopilotAPIInstalled() bool {
	// Try npm list -g copilot-api
	var npmName string
	if runtime.GOOS == "windows" {
		npmName = "npm.cmd"
	} else {
		npmName = "npm"
	}

	cmd := exec.Command(npmName, "list", "-g", "copilot-api", "--depth=0")
	output, err := cmd.Output()
	if err == nil && strings.Contains(string(output), "copilot-api") {
		return true
	}

	return false
}

// GetPreferredRunner returns the preferred runner (npx or bunx) path.
func GetPreferredRunner() (string, error) {
	d := Detect()
	if !d.NodeAvailable {
		return "", fmt.Errorf("%s", d.ErrorMessage)
	}

	// Prefer npx over bunx for wider compatibility
	if d.NPXPath != "" {
		return d.NPXPath, nil
	}
	if d.BunXPath != "" {
		return d.BunXPath, nil
	}

	return "", fmt.Errorf("no suitable runtime found")
}
