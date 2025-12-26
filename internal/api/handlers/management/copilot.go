// Package management provides the management API handlers.
// This file adds Copilot management endpoints for start/stop/status.
package management

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/copilot"
)

// copilotManager is the singleton Copilot process manager
var copilotManager *copilot.Manager

// SetCopilotManager sets the Copilot manager instance for the handler.
func (h *Handler) SetCopilotManager(manager *copilot.Manager) {
	copilotManager = manager
}

// GetCopilotStatus returns the current status of the copilot-api process.
// GET /v0/management/copilot/status
func (h *Handler) GetCopilotStatus(c *gin.Context) {
	if copilotManager == nil {
		c.JSON(http.StatusOK, copilot.Status{
			Running:       false,
			Authenticated: false,
			Endpoint:      "",
		})
		return
	}
	c.JSON(http.StatusOK, copilotManager.GetStatus())
}

// StartCopilot starts the copilot-api process.
// POST /v0/management/copilot/start
func (h *Handler) StartCopilot(c *gin.Context) {
	if copilotManager == nil {
		cfg := h.cfg
		if cfg == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "config not available"})
			return
		}
		copilotManager = copilot.NewManager(&cfg.Copilot)
	}

	// Start with a timeout context
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	if err := copilotManager.Start(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed to start copilot-api",
			"details": err.Error(),
		})
		return
	}

	// Wait a moment for the process to initialize
	time.Sleep(500 * time.Millisecond)

	c.JSON(http.StatusOK, gin.H{
		"status":  "started",
		"details": copilotManager.GetStatus(),
	})
}

// StopCopilot stops the copilot-api process.
// POST /v0/management/copilot/stop
func (h *Handler) StopCopilot(c *gin.Context) {
	if copilotManager == nil {
		c.JSON(http.StatusOK, gin.H{"status": "not running"})
		return
	}

	if err := copilotManager.Stop(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed to stop copilot-api",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

// DetectCopilotAPI checks if Node.js and copilot-api are available.
// GET /v0/management/copilot/detect
func (h *Handler) DetectCopilotAPI(c *gin.Context) {
	detection := copilot.Detect()
	c.JSON(http.StatusOK, detection)
}

// HealthCheckCopilot verifies the copilot-api endpoint is responding.
// GET /v0/management/copilot/health
func (h *Handler) HealthCheckCopilot(c *gin.Context) {
	if copilotManager == nil {
		c.JSON(http.StatusOK, gin.H{
			"healthy": false,
			"reason":  "copilot manager not initialized",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if err := copilotManager.HealthCheck(ctx); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"healthy": false,
			"reason":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"healthy": true,
		"status":  copilotManager.GetStatus(),
	})
}
