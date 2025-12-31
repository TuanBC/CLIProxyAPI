package privategpt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers"
	log "github.com/sirupsen/logrus"
)

type PrivateGPTHandler struct {
	Base          *handlers.BaseAPIHandler
	Config        *config.PrivateGPTConfig
	capturedToken string
	tokenMu       sync.RWMutex
	AuthDir       string
}

func NewPrivateGPTHandler(base *handlers.BaseAPIHandler, cfg *config.PrivateGPTConfig, authDir string) *PrivateGPTHandler {
	h := &PrivateGPTHandler{
		Base:    base,
		Config:  cfg,
		AuthDir: authDir,
	}
	h.loadToken()
	return h
}

func (h *PrivateGPTHandler) loadToken() {
	if h.AuthDir == "" {
		return
	}
	tokenBytes, err := os.ReadFile(filepath.Join(h.AuthDir, "privategpt_token"))
	if err == nil {
		token := strings.TrimSpace(string(tokenBytes))
		if token != "" {
			h.capturedToken = token
			log.Info("Loaded PrivateGPT token from file")
		}
	}
}

func (h *PrivateGPTHandler) saveToken(token string) {
	if h.AuthDir == "" {
		return
	}
	if err := os.MkdirAll(h.AuthDir, 0755); err != nil {
		log.Errorf("Failed to create auth dir: %v", err)
		return
	}
	if err := os.WriteFile(filepath.Join(h.AuthDir, "privategpt_token"), []byte(token), 0600); err != nil {
		log.Errorf("Failed to save PrivateGPT token: %v", err)
	} else {
		log.Info("Saved PrivateGPT token to file")
	}
}

// isPlaceholderKey returns true if the authorization header contains a placeholder/dummy API key
// that should be ignored in favor of the captured PrivateGPT token.
// This enables OpenAI SDK compatibility where clients send "sk-dummy" or similar placeholder keys.
func isPlaceholderKey(authHeader string) bool {
	if authHeader == "" {
		return true
	}
	// Extract the actual key (remove "Bearer " prefix if present)
	key := strings.TrimSpace(authHeader)
	if strings.HasPrefix(strings.ToLower(key), "bearer ") {
		key = strings.TrimSpace(key[7:])
	}
	// Check for common placeholder patterns
	keyLower := strings.ToLower(key)
	placeholders := []string{
		"sk-dummy", "sk-test", "sk-none", "sk-placeholder", "sk-fake",
		"dummy", "test", "placeholder", "fake", "none", "null",
		"your-api-key", "your_api_key", "api-key", "api_key",
	}
	for _, p := range placeholders {
		if keyLower == p || strings.HasPrefix(keyLower, p) {
			return true
		}
	}
	// Check if key starts with "sk-" and is too short to be real (real keys are 40+ chars)
	if strings.HasPrefix(keyLower, "sk-") && len(key) < 20 {
		return true
	}
	return false
}

func (h *PrivateGPTHandler) ProxyHandler(c *gin.Context) {
	if !h.Config.Enable {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	upstream, err := url.Parse(h.Config.UpstreamURL)
	if err != nil {
		log.Errorf("Failed to parse upstream URL: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = upstream.Host
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		
		// Rewrite Origin and Referer to match upstream to pass checks
		if req.Header.Get("Origin") != "" {
			req.Header.Set("Origin", h.Config.UpstreamURL)
		}
		if req.Header.Get("Referer") != "" {
			req.Header.Set("Referer", h.Config.UpstreamURL)
		}

		// Use captured token if Authorization header is missing
		if req.Header.Get("Authorization") == "" {
			h.tokenMu.RLock()
			if h.capturedToken != "" {
				req.Header.Set("Authorization", h.capturedToken)
			}
			h.tokenMu.RUnlock()
		}

		// Capture Authorization header if present
		if auth := req.Header.Get("Authorization"); auth != "" {
			h.tokenMu.Lock()
			if h.capturedToken == "" || h.capturedToken != auth {
				h.capturedToken = auth
				h.saveToken(auth) // Persist it
				// log.Debug("Captured PrivateGPT Auth Token")
			}
			h.tokenMu.Unlock()
		}
	}

	// Custom Transport to bypass local hosts file loop
	// We use Google DNS (8.8.8.8) to resolve the upstream Host.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Extract host and port
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// If the host matches our upstream, resolve it using Google DNS
			if host == upstream.Hostname() {
				resolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{
							Timeout: time.Millisecond * time.Duration(10000),
						}
						// Use Google DNS
						return d.DialContext(ctx, "udp", "8.8.8.8:53")
					},
				}
				ips, err := resolver.LookupHost(ctx, host)
				if err != nil {
					log.Errorf("Failed to resolve %s using Google DNS: %v. Falling back to system DNS.", host, err)
					// Fallback to default dialer (might loop if hosts file is set, but better than instant fail)
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				}
				// Use the first IP
				addr = net.JoinHostPort(ips[0], port)
				log.Debugf("Resolved %s to %s via Google DNS", host, ips[0])
			}

			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: upstream.Hostname(), // Ensure SNI matches the domain
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	proxy.Transport = transport

	if h.Config.SSORedirectRewrite {
		proxy.ModifyResponse = func(resp *http.Response) error {
			// Always remove CSP to avoid issues with proxying
			resp.Header.Del("Content-Security-Policy")

			// Check for 401
			if resp.StatusCode == http.StatusUnauthorized {
				// We can't easily modify the body here in a streaming proxy without efficient buffering,
				// but we can log it. 
				// For the "ProxyHandler", we generally just pass through, but if we want to be helpful:
				log.Warn("Received 401 from PrivateGPT. Token might be expired.")
			}

			// Rewrite Location header for redirects
			if location := resp.Header.Get("Location"); location != "" {
				locURL, err := url.Parse(location)
				if err == nil {
					// Parse upstream URL to compare
					upstreamURL, _ := url.Parse(h.Config.UpstreamURL)
					
					// If the redirect target matches the upstream host
					if locURL.Host == upstreamURL.Host {
						// Make it relative to keep it on the proxy
						locURL.Scheme = ""
						locURL.Host = ""
						resp.Header.Set("Location", locURL.String())
						log.Debugf("Rewrote redirect location from %s to %s", location, locURL.String())
					}
				}
			}
			return nil
		}
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

// GetCapturedToken returns the most recently captured Authorization token
func (h *PrivateGPTHandler) GetCapturedToken(c *gin.Context) {
	h.tokenMu.RLock()
	defer h.tokenMu.RUnlock()

	if h.capturedToken == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "No token captured yet. Please login via browser first."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": h.capturedToken})
}

// SetToken allows manual injection of an authorization token
func (h *PrivateGPTHandler) SetToken(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body. Expected: {\"token\": \"Bearer ...\"}"})
		return
	}
	
	token := strings.TrimSpace(req.Token)
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token cannot be empty"})
		return
	}
	
	// Ensure token has Bearer prefix
	if !strings.HasPrefix(token, "Bearer ") {
		token = "Bearer " + token
	}
	
	h.tokenMu.Lock()
	h.capturedToken = token
	h.saveToken(token)
	h.tokenMu.Unlock()
	
	log.Info("PrivateGPT token set via API")
	c.JSON(http.StatusOK, gin.H{"message": "Token set successfully"})
}

// OpenLogin opens the browser to PrivateGPT login page and shows instructions
func (h *PrivateGPTHandler) OpenLogin(c *gin.Context) {
	loginURL := h.Config.UpstreamURL
	
	// Open browser based on OS
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", loginURL)
	case "darwin":
		cmd = exec.Command("open", loginURL)
	default:
		cmd = exec.Command("xdg-open", loginURL)
	}
	
	err := cmd.Start()
	if err != nil {
		log.Warnf("Failed to open browser: %v", err)
	}
	
	// Return instructions
	c.JSON(http.StatusOK, gin.H{
		"message": "Browser opened to PrivateGPT login page",
		"url": loginURL,
		"next_steps": []string{
			"1. Log in via SSO if not already logged in",
			"2. Open browser console (F12)",
			"3. Paste and run this code:",
		},
		"code": `fetch('https://localhost:54547/privategpt/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:JSON.parse(localStorage.getItem(JSON.parse(localStorage.getItem(Object.keys(localStorage).find(k=>k.startsWith('msal.token.keys.')))).accessToken[0])).secret})}).then(r=>r.json()).then(console.log)`,
		"expected_result": "{message: 'Token set successfully'}",
	})
}

// GetModels returns the list of supported models from the configuration
func (h *PrivateGPTHandler) GetModels(c *gin.Context) {
	models := registry.GetPrivateGPTModels()
	
	// Return full OpenAI compatible objects
	apiModels := make([]map[string]interface{}, len(models))
	for i, m := range models {
		apiModels[i] = map[string]interface{}{
			"id":      m.ID,
			"object":  "model",
			"created": m.Created,
			"owned_by": "privategpt",
		}
	}
	
	c.JSON(http.StatusOK, gin.H{
		"object": "list",
		"data":   apiModels,
	})
}

// OpenAIChatCompletionRequest represents the standard OpenAI request body
type OpenAIChatCompletionRequest struct {
	Model    string          `json:"model"`
	Messages []OpenAIMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Tools    []interface{}   `json:"tools,omitempty"`
}

// PrivateGPTRequest represents the upstream request body
type PrivateGPTRequest struct {
	ParentMessageID *string                `json:"parent_message_id"`
	Question        string                 `json:"question"`
	Metadata        map[string]interface{} `json:"metadata"`
	ModelID         string                 `json:"model_id"`
	Tools           []interface{}          `json:"tools"`
	// Use explicit stream field if supported? 
	// The provided curl example targets `/api/chat/v1/conversations` and sets `accept: text/event-stream`.
}

// OpenAIChatCompletionChunk represents a chunk of the OpenAI Chat Completion API response
type OpenAIChatCompletionChunk struct {
	ID      string                       `json:"id"`
	Object  string                       `json:"object"`
	Created int64                        `json:"created"`
	Model   string                       `json:"model"`
	Choices []OpenAIChatCompletionChoice `json:"choices"`
}

type OpenAIChatCompletionChoice struct {
	Index        int         `json:"index"`
	Delta        OpenAIDelta `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

type OpenAIDelta struct {
	Content string `json:"content,omitempty"`
}

// Non-streaming response structs
type OpenAIChatCompletionResponse struct {
	ID      string                                `json:"id"`
	Object  string                                `json:"object"`
	Created int64                                 `json:"created"`
	Model   string                                `json:"model"`
	Choices []OpenAIChatCompletionChoiceNonStream `json:"choices"`
	Usage   *OpenAIUsage                          `json:"usage,omitempty"`
}

type OpenAIChatCompletionChoiceNonStream struct {
	Index        int           `json:"index"`
	Message      OpenAIMessage `json:"message"`
	FinishReason *string       `json:"finish_reason"`
}

type OpenAIMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// GetContentString extracts text content from the message, handling both string and array formats
func (m *OpenAIMessage) GetContentString() string {
	if len(m.Content) == 0 {
		return ""
	}
	// Try string first
	var str string
	if err := json.Unmarshal(m.Content, &str); err == nil {
		return str
	}
	// Try array format (multimodal)
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(m.Content, &parts); err == nil {
		for _, p := range parts {
			if p.Type == "text" && p.Text != "" {
				return p.Text
			}
		}
	}
	return string(m.Content)
}

type OpenAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatCompletion handles the chat completion request and translates SSE events
func (h *PrivateGPTHandler) ChatCompletion(c *gin.Context) {
	// 1. Read request body
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Errorf("Failed to read request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}
	
	// 2. Parse as OpenAI request
	var openAIReq OpenAIChatCompletionRequest
	if err := json.Unmarshal(bodyBytes, &openAIReq); err != nil {
		log.Warnf("Failed to parse as OpenAI request: %v", err)
	}

	// 3. Transform to PrivateGPT request
	question := ""
	if len(openAIReq.Messages) > 0 {
		for i := len(openAIReq.Messages) - 1; i >= 0; i-- {
			if openAIReq.Messages[i].Role == "user" {
				question = openAIReq.Messages[i].GetContentString()
				break
			}
		}
		if question == "" {
			question = openAIReq.Messages[len(openAIReq.Messages)-1].GetContentString()
		}
	}

	upstreamReq := PrivateGPTRequest{
		ParentMessageID: nil,
		Question:        question,
		Metadata:        map[string]interface{}{"attachments": []interface{}{}},
		ModelID:         openAIReq.Model,
		Tools:           []interface{}{},
	}
	if len(openAIReq.Tools) > 0 {
		upstreamReq.Tools = openAIReq.Tools
	}

	if upstreamReq.ModelID == "" {
		upstreamReq.ModelID = "azure-gpt-4o" 
	}

	pgptBody, err := json.Marshal(upstreamReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode upstream request"})
		return
	}

	// 4. Prepare upstream request
	upstreamURL := h.Config.UpstreamURL + "/api/chat/v1/conversations"
	
	req, err := http.NewRequest("POST", upstreamURL, bytes.NewBuffer(pgptBody))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upstream request"})
		return
	}

	// Copy headers
	for k, v := range c.Request.Header {
		if k == "Content-Type" || k == "Content-Length" || k == "Accept-Encoding" {
			continue
		}
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	
	// Automatic Token Injection - inject captured token if no auth or placeholder key
	if isPlaceholderKey(req.Header.Get("Authorization")) {
		h.tokenMu.RLock()
		if h.capturedToken != "" {
			req.Header.Set("Authorization", h.capturedToken)
		}
		h.tokenMu.RUnlock()
	}

	// Force headers for upstream compatibility
	if h.Config.UpstreamURL != "" {
		req.Header.Set("Origin", h.Config.UpstreamURL)
		req.Header.Set("Referer", h.Config.UpstreamURL)
	}
	u, _ := url.Parse(h.Config.UpstreamURL)
	req.Host = u.Host

	// 5. Always request stream to ensure consistent "v" field parsing
	req.Header.Set("Accept", "text/event-stream")

	// 6. Execute upstream request
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("Upstream request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Handle 401 Unauthorized - token expired
		if resp.StatusCode == http.StatusUnauthorized {
			// Read upstream error body for context
			bodyBytes, _ := io.ReadAll(resp.Body)
			upstreamError := string(bodyBytes)
			
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "token_expired",
				"message": "Your PrivateGPT authentication token is missing or expired.",
				"upstream_error": upstreamError,
				"instructions": []string{
					"Run the following command to login:",
					"  CLIProxyAPI -privategpt-login",
					"",
					"Or manually set the token via API:",
					"  POST /privategpt/token {\"token\": \"...\"}",
				},
			})
			return
		}
		
		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
		return
	}

	completionID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	created := time.Now().Unix()

	if openAIReq.Stream {
		h.handleStreamingResponse(c, resp.Body, completionID, created, openAIReq.Model)
	} else {
		h.handleNonStreamingResponse(c, resp.Body, completionID, created, openAIReq.Model)
	}
}

func (h *PrivateGPTHandler) handleStreamingResponse(c *gin.Context, upstreamBody io.Reader, id string, created int64, model string) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")

	reader := bufio.NewReader(upstreamBody)

	c.Stream(func(w io.Writer) bool {
		line, err := reader.ReadString('\n')
		if err != nil {
			// End of stream - send final chunk with finish_reason
			finishReason := "stop"
			finalChunk := OpenAIChatCompletionChunk{
				ID:      id,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []OpenAIChatCompletionChoice{
					{
						Index:        0,
						Delta:        OpenAIDelta{},
						FinishReason: &finishReason,
					},
				},
			}
			finalBytes, _ := json.Marshal(finalChunk)
			fmt.Fprintf(w, "data: %s\n\n", finalBytes)
			w.Write([]byte("data: [DONE]\n\n"))
			return false
		}

		line = strings.TrimSpace(line)
		if line == "" {
			return true
		}

		// Handle DONE event - send final chunk with finish_reason
		if strings.HasPrefix(line, "event: DONE") {
			finishReason := "stop"
			finalChunk := OpenAIChatCompletionChunk{
				ID:      id,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []OpenAIChatCompletionChoice{
					{
						Index:        0,
						Delta:        OpenAIDelta{},
						FinishReason: &finishReason,
					},
				},
			}
			finalBytes, _ := json.Marshal(finalChunk)
			fmt.Fprintf(w, "data: %s\n\n", finalBytes)
			w.Write([]byte("data: [DONE]\n\n"))
			return false
		}

		// Skip event types that aren't data
		if strings.HasPrefix(line, "event:") && !strings.HasPrefix(line, "event: data") {
			// Skip unknown event types (like error events)
			return true
		}

		jsonStr := ""
		if strings.HasPrefix(line, "event: data") {
			dataLine, err := reader.ReadString('\n')
			if err != nil {
				return false
			}
			dataLine = strings.TrimSpace(dataLine)
			if strings.HasPrefix(dataLine, "data: ") {
				jsonStr = strings.TrimPrefix(dataLine, "data: ")
			}
		} else if strings.HasPrefix(line, "data: ") {
			jsonStr = strings.TrimPrefix(line, "data: ")
		}

		if jsonStr != "" {
			var dataObj map[string]interface{}
			if err := json.Unmarshal([]byte(jsonStr), &dataObj); err == nil {
				if v, ok := dataObj["v"].(string); ok && v != "" {
					chunk := OpenAIChatCompletionChunk{
						ID:      id,
						Object:  "chat.completion.chunk",
						Created: created,
						Model:   model,
						Choices: []OpenAIChatCompletionChoice{
							{
								Index: 0,
								Delta: OpenAIDelta{Content: v},
							},
						},
					}
					chunkBytes, _ := json.Marshal(chunk)
					fmt.Fprintf(w, "data: %s\n\n", chunkBytes)
				}
			}
		}

		return true
	})
}

func (h *PrivateGPTHandler) handleNonStreamingResponse(c *gin.Context, upstreamBody io.Reader, id string, created int64, model string) {
	reader := bufio.NewReader(upstreamBody)
	var fullContent strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "event: DONE") {
			break
		}

		jsonStr := ""
		if strings.HasPrefix(line, "event: data") {
			dataLine, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			dataLine = strings.TrimSpace(dataLine)
			if strings.HasPrefix(dataLine, "data: ") {
				jsonStr = strings.TrimPrefix(dataLine, "data: ")
			}
		} else if strings.HasPrefix(line, "data: ") {
			jsonStr = strings.TrimPrefix(line, "data: ")
		}

		if jsonStr != "" {
			var dataObj map[string]interface{}
			if err := json.Unmarshal([]byte(jsonStr), &dataObj); err == nil {
				if v, ok := dataObj["v"].(string); ok {
					fullContent.WriteString(v)
				}
			}
		}
	}

	response := OpenAIChatCompletionResponse{
		ID:      id,
		Object:  "chat.completion",
		Created: created,
		Model:   model,
		Choices: []OpenAIChatCompletionChoiceNonStream{
			{
				Index: 0,
			Message: OpenAIMessage{
					Role:    "assistant",
					Content: func() json.RawMessage { b, _ := json.Marshal(fullContent.String()); return b }(),
				},
				FinishReason: func() *string { s := "stop"; return &s }(),
			},
		},
		Usage: &OpenAIUsage{
			PromptTokens:     0,
			CompletionTokens: 0,
			TotalTokens:      0,
		},
	}

	c.JSON(http.StatusOK, response)
}

// OpenAI Completions API types
type OpenAICompletionsRequest struct {
	Model       string      `json:"model"`
	Prompt      string      `json:"prompt"`
	MaxTokens   int         `json:"max_tokens,omitempty"`
	Temperature float64     `json:"temperature,omitempty"`
	Stream      bool        `json:"stream"`
	Stop        interface{} `json:"stop,omitempty"`
}

type OpenAICompletionsResponse struct {
	ID      string                        `json:"id"`
	Object  string                        `json:"object"`
	Created int64                         `json:"created"`
	Model   string                        `json:"model"`
	Choices []OpenAICompletionsChoice     `json:"choices"`
	Usage   *OpenAIUsage                  `json:"usage,omitempty"`
}

type OpenAICompletionsChoice struct {
	Index        int     `json:"index"`
	Text         string  `json:"text"`
	FinishReason *string `json:"finish_reason"`
}

// OpenAI Responses API types  
type OpenAIResponsesRequest struct {
	Model        string `json:"model"`
	Input        string `json:"input"`
	Instructions string `json:"instructions,omitempty"`
	Stream       bool   `json:"stream"`
}

// Completions handles the /v1/completions endpoint for PrivateGPT
func (h *PrivateGPTHandler) Completions(c *gin.Context) {
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Errorf("Failed to read request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	var completionsReq OpenAICompletionsRequest
	if err := json.Unmarshal(bodyBytes, &completionsReq); err != nil {
		log.Warnf("Failed to parse completions request: %v", err)
	}

	// Use prompt as the question
	question := completionsReq.Prompt
	if question == "" {
		question = "Complete this:"
	}

	modelID := completionsReq.Model
	if modelID == "" {
		modelID = "azure-gpt-4o"
	}

	upstreamReq := PrivateGPTRequest{
		ParentMessageID: nil,
		Question:        question,
		Metadata:        map[string]interface{}{"attachments": []interface{}{}},
		ModelID:         modelID,
		Tools:           []interface{}{},
	}

	pgptBody, err := json.Marshal(upstreamReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode upstream request"})
		return
	}

	upstreamURL := h.Config.UpstreamURL + "/api/chat/v1/conversations"
	
	req, err := http.NewRequest("POST", upstreamURL, bytes.NewBuffer(pgptBody))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upstream request"})
		return
	}

	for k, v := range c.Request.Header {
		if k == "Content-Type" || k == "Content-Length" || k == "Accept-Encoding" {
			continue
		}
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	
	if isPlaceholderKey(req.Header.Get("Authorization")) {
		h.tokenMu.RLock()
		if h.capturedToken != "" {
			req.Header.Set("Authorization", h.capturedToken)
		}
		h.tokenMu.RUnlock()
	}

	if h.Config.UpstreamURL != "" {
		req.Header.Set("Origin", h.Config.UpstreamURL)
		req.Header.Set("Referer", h.Config.UpstreamURL)
	}
	u, _ := url.Parse(h.Config.UpstreamURL)
	req.Host = u.Host

	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("Upstream request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			respBody, _ := io.ReadAll(resp.Body)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "token_expired",
				"message": "Your PrivateGPT authentication token is missing or expired.",
				"upstream_error": string(respBody),
			})
			return
		}
		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
		return
	}

	completionID := fmt.Sprintf("cmpl-%d", time.Now().UnixNano())
	created := time.Now().Unix()

	if completionsReq.Stream {
		h.handleCompletionsStreamingResponse(c, resp.Body, completionID, created, modelID)
	} else {
		h.handleCompletionsNonStreamingResponse(c, resp.Body, completionID, created, modelID)
	}
}

func (h *PrivateGPTHandler) handleCompletionsStreamingResponse(c *gin.Context, upstreamBody io.Reader, id string, created int64, model string) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")

	reader := bufio.NewReader(upstreamBody)
	finishReason := "stop"

	c.Stream(func(w io.Writer) bool {
		line, err := reader.ReadString('\n')
		if err != nil {
			// End of stream - send final chunk with finish_reason
			finalChunk := map[string]interface{}{
				"id":      id,
				"object":  "text_completion",
				"created": created,
				"model":   model,
				"choices": []map[string]interface{}{
					{
						"index":         0,
						"text":          "",
						"finish_reason": finishReason,
					},
				},
			}
			finalBytes, _ := json.Marshal(finalChunk)
			fmt.Fprintf(w, "data: %s\n\n", finalBytes)
			w.Write([]byte("data: [DONE]\n\n"))
			return false
		}

		line = strings.TrimSpace(line)
		if line == "" {
			return true
		}

		if strings.HasPrefix(line, "event: DONE") {
			// Send final chunk with finish_reason
			finalChunk := map[string]interface{}{
				"id":      id,
				"object":  "text_completion",
				"created": created,
				"model":   model,
				"choices": []map[string]interface{}{
					{
						"index":         0,
						"text":          "",
						"finish_reason": finishReason,
					},
				},
			}
			finalBytes, _ := json.Marshal(finalChunk)
			fmt.Fprintf(w, "data: %s\n\n", finalBytes)
			w.Write([]byte("data: [DONE]\n\n"))
			return false
		}

		// Skip unknown event types
		if strings.HasPrefix(line, "event:") && !strings.HasPrefix(line, "event: data") {
			return true
		}

		jsonStr := ""
		if strings.HasPrefix(line, "event: data") {
			dataLine, err := reader.ReadString('\n')
			if err != nil {
				return false
			}
			dataLine = strings.TrimSpace(dataLine)
			if strings.HasPrefix(dataLine, "data: ") {
				jsonStr = strings.TrimPrefix(dataLine, "data: ")
			}
		} else if strings.HasPrefix(line, "data: ") {
			jsonStr = strings.TrimPrefix(line, "data: ")
		}

		if jsonStr != "" {
			var dataObj map[string]interface{}
			if err := json.Unmarshal([]byte(jsonStr), &dataObj); err == nil {
				if v, ok := dataObj["v"].(string); ok && v != "" {
					chunk := map[string]interface{}{
						"id":      id,
						"object":  "text_completion",
						"created": created,
						"model":   model,
						"choices": []map[string]interface{}{
							{
								"index": 0,
								"text":  v,
							},
						},
					}
					chunkBytes, _ := json.Marshal(chunk)
					fmt.Fprintf(w, "data: %s\n\n", chunkBytes)
				}
			}
		}

		return true
	})
}

func (h *PrivateGPTHandler) handleCompletionsNonStreamingResponse(c *gin.Context, upstreamBody io.Reader, id string, created int64, model string) {
	reader := bufio.NewReader(upstreamBody)
	var fullContent strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "event: DONE") {
			break
		}

		jsonStr := ""
		if strings.HasPrefix(line, "event: data") {
			dataLine, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			dataLine = strings.TrimSpace(dataLine)
			if strings.HasPrefix(dataLine, "data: ") {
				jsonStr = strings.TrimPrefix(dataLine, "data: ")
			}
		} else if strings.HasPrefix(line, "data: ") {
			jsonStr = strings.TrimPrefix(line, "data: ")
		}

		if jsonStr != "" {
			var dataObj map[string]interface{}
			if err := json.Unmarshal([]byte(jsonStr), &dataObj); err == nil {
				if v, ok := dataObj["v"].(string); ok {
					fullContent.WriteString(v)
				}
			}
		}
	}

	finishReason := "stop"
	response := OpenAICompletionsResponse{
		ID:      id,
		Object:  "text_completion",
		Created: created,
		Model:   model,
		Choices: []OpenAICompletionsChoice{
			{
				Index:        0,
				Text:         fullContent.String(),
				FinishReason: &finishReason,
			},
		},
		Usage: &OpenAIUsage{
			PromptTokens:     0,
			CompletionTokens: 0,
			TotalTokens:      0,
		},
	}

	c.JSON(http.StatusOK, response)
}

// Responses handles the /v1/responses endpoint for PrivateGPT
func (h *PrivateGPTHandler) Responses(c *gin.Context) {
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Errorf("Failed to read request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	var responsesReq OpenAIResponsesRequest
	if err := json.Unmarshal(bodyBytes, &responsesReq); err != nil {
		log.Warnf("Failed to parse responses request: %v", err)
	}

	// Combine input and instructions into question
	question := responsesReq.Input
	if responsesReq.Instructions != "" {
		question = responsesReq.Instructions + "\n\n" + responsesReq.Input
	}
	if question == "" {
		question = "Respond to this:"
	}

	modelID := responsesReq.Model
	if modelID == "" {
		modelID = "azure-gpt-4o"
	}

	upstreamReq := PrivateGPTRequest{
		ParentMessageID: nil,
		Question:        question,
		Metadata:        map[string]interface{}{"attachments": []interface{}{}},
		ModelID:         modelID,
		Tools:           []interface{}{},
	}

	pgptBody, err := json.Marshal(upstreamReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode upstream request"})
		return
	}

	upstreamURL := h.Config.UpstreamURL + "/api/chat/v1/conversations"
	
	req, err := http.NewRequest("POST", upstreamURL, bytes.NewBuffer(pgptBody))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upstream request"})
		return
	}

	for k, v := range c.Request.Header {
		if k == "Content-Type" || k == "Content-Length" || k == "Accept-Encoding" {
			continue
		}
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	
	if isPlaceholderKey(req.Header.Get("Authorization")) {
		h.tokenMu.RLock()
		if h.capturedToken != "" {
			req.Header.Set("Authorization", h.capturedToken)
		}
		h.tokenMu.RUnlock()
	}

	if h.Config.UpstreamURL != "" {
		req.Header.Set("Origin", h.Config.UpstreamURL)
		req.Header.Set("Referer", h.Config.UpstreamURL)
	}
	u, _ := url.Parse(h.Config.UpstreamURL)
	req.Host = u.Host

	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("Upstream request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			respBody, _ := io.ReadAll(resp.Body)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "token_expired",
				"message": "Your PrivateGPT authentication token is missing or expired.",
				"upstream_error": string(respBody),
			})
			return
		}
		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
		return
	}

	responseID := fmt.Sprintf("resp-%d", time.Now().UnixNano())
	created := time.Now().Unix()

	if responsesReq.Stream {
		h.handleResponsesStreamingResponse(c, resp.Body, responseID, created, modelID)
	} else {
		h.handleResponsesNonStreamingResponse(c, resp.Body, responseID, created, modelID)
	}
}

func (h *PrivateGPTHandler) handleResponsesStreamingResponse(c *gin.Context, upstreamBody io.Reader, id string, created int64, model string) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")

	reader := bufio.NewReader(upstreamBody)

	c.Stream(func(w io.Writer) bool {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false
		}

		line = strings.TrimSpace(line)
		if line == "" {
			return true
		}

		if strings.HasPrefix(line, "event: DONE") {
			// Send response.completed event
			completedEvent := map[string]interface{}{
				"type": "response.completed",
				"response": map[string]interface{}{
					"id":     id,
					"object": "response",
					"status": "completed",
				},
			}
			completedBytes, _ := json.Marshal(completedEvent)
			fmt.Fprintf(w, "event: response.completed\ndata: %s\n\n", completedBytes)
			return false
		}

		// Skip unknown event types
		if strings.HasPrefix(line, "event:") && !strings.HasPrefix(line, "event: data") {
			return true
		}

		jsonStr := ""
		if strings.HasPrefix(line, "event: data") {
			dataLine, err := reader.ReadString('\n')
			if err != nil {
				return false
			}
			dataLine = strings.TrimSpace(dataLine)
			if strings.HasPrefix(dataLine, "data: ") {
				jsonStr = strings.TrimPrefix(dataLine, "data: ")
			}
		} else if strings.HasPrefix(line, "data: ") {
			jsonStr = strings.TrimPrefix(line, "data: ")
		}

		if jsonStr != "" {
			var dataObj map[string]interface{}
			if err := json.Unmarshal([]byte(jsonStr), &dataObj); err == nil {
				if v, ok := dataObj["v"].(string); ok && v != "" {
					// Send response.output_text.delta event
					deltaEvent := map[string]interface{}{
						"type":  "response.output_text.delta",
						"delta": v,
					}
					deltaBytes, _ := json.Marshal(deltaEvent)
					fmt.Fprintf(w, "event: response.output_text.delta\ndata: %s\n\n", deltaBytes)
				}
			}
		}

		return true
	})
}

func (h *PrivateGPTHandler) handleResponsesNonStreamingResponse(c *gin.Context, upstreamBody io.Reader, id string, created int64, model string) {
	reader := bufio.NewReader(upstreamBody)
	var fullContent strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "event: DONE") {
			break
		}

		jsonStr := ""
		if strings.HasPrefix(line, "event: data") {
			dataLine, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			dataLine = strings.TrimSpace(dataLine)
			if strings.HasPrefix(dataLine, "data: ") {
				jsonStr = strings.TrimPrefix(dataLine, "data: ")
			}
		} else if strings.HasPrefix(line, "data: ") {
			jsonStr = strings.TrimPrefix(line, "data: ")
		}

		if jsonStr != "" {
			var dataObj map[string]interface{}
			if err := json.Unmarshal([]byte(jsonStr), &dataObj); err == nil {
				if v, ok := dataObj["v"].(string); ok {
					fullContent.WriteString(v)
				}
			}
		}
	}

	// Build OpenAI Responses format
	response := gin.H{
		"id":         id,
		"object":     "response",
		"created_at": created,
		"model":      model,
		"status":     "completed",
		"output": []gin.H{
			{
				"type": "message",
				"role": "assistant",
				"content": []gin.H{
					{
						"type": "output_text",
						"text": fullContent.String(),
					},
				},
			},
		},
		"usage": gin.H{
			"input_tokens":  0,
			"output_tokens": 0,
			"total_tokens":  0,
		},
	}

	c.JSON(http.StatusOK, response)
}
