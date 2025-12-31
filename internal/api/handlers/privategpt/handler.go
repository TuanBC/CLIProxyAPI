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

// TokenHelperPage serves an HTML page for token submission that bypasses CSP restrictions.
// Since fetch from the PrivateGPT website to localhost is blocked by CSP,
// this page runs on the proxy origin and can submit tokens without CSP issues.
func (h *PrivateGPTHandler) TokenHelperPage(c *gin.Context) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PrivateGPT Token Helper</title>
    <style>
        :root { --bg-primary: #0a0e14; --bg-secondary: #141a22; --bg-card: #1a232e; --text-primary: #e6edf3; --text-secondary: #8b949e; --accent: #58a6ff; --accent-hover: #79c0ff; --success: #3fb950; --error: #f85149; --border: #30363d; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, var(--bg-primary), var(--bg-secondary)); min-height: 100vh; display: flex; align-items: center; justify-content: center; color: var(--text-primary); padding: 20px; }
        .container { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 40px; max-width: 600px; width: 100%; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
        h1 { font-size: 1.75rem; margin-bottom: 8px; background: linear-gradient(90deg, var(--accent), var(--accent-hover)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: var(--text-secondary); margin-bottom: 32px; font-size: 0.95rem; }
        .step { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
        .step-number { display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; background: var(--accent); color: var(--bg-primary); border-radius: 50%; font-size: 0.8rem; font-weight: 600; margin-right: 10px; }
        .step h3 { display: inline; font-size: 1rem; }
        .step p { margin-top: 8px; color: var(--text-secondary); font-size: 0.9rem; line-height: 1.5; }
        .code-block { background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-top: 12px; font-family: 'SF Mono', Consolas, monospace; font-size: 0.75rem; color: var(--accent); overflow-x: auto; white-space: pre-wrap; word-break: break-all; position: relative; }
        .copy-btn { position: absolute; top: 8px; right: 8px; background: var(--border); color: var(--text-secondary); border: none; border-radius: 4px; padding: 4px 8px; font-size: 0.7rem; cursor: pointer; transition: all 0.2s; }
        .copy-btn:hover { background: var(--accent); color: var(--bg-primary); }
        .token-input { width: 100%; padding: 14px 16px; background: var(--bg-primary); border: 1px solid var(--border); border-radius: 8px; color: var(--text-primary); font-size: 0.95rem; margin: 12px 0; transition: border-color 0.2s; }
        .token-input:focus { outline: none; border-color: var(--accent); }
        .token-input::placeholder { color: var(--text-secondary); }
        .submit-btn { width: 100%; padding: 14px 24px; background: linear-gradient(90deg, var(--accent), var(--accent-hover)); color: var(--bg-primary); border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
        .submit-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(88,166,255,0.4); }
        .submit-btn:disabled { background: var(--border); cursor: not-allowed; transform: none; box-shadow: none; }
        .status { margin-top: 16px; padding: 12px; border-radius: 8px; font-size: 0.9rem; display: none; }
        .status.success { display: block; background: rgba(63,185,80,0.15); border: 1px solid var(--success); color: var(--success); }
        .status.error { display: block; background: rgba(248,81,73,0.15); border: 1px solid var(--error); color: var(--error); }
        .quick-action { margin-top: 24px; padding-top: 24px; border-top: 1px solid var(--border); }
        .quick-action h3 { font-size: 0.95rem; margin-bottom: 12px; color: var(--text-secondary); }
        .quick-btn { padding: 10px 20px; background: transparent; color: var(--accent); border: 1px solid var(--accent); border-radius: 8px; font-size: 0.9rem; cursor: pointer; transition: all 0.2s; margin-right: 8px; }
        .quick-btn:hover { background: var(--accent); color: var(--bg-primary); }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 PrivateGPT Token Helper</h1>
        <p class="subtitle">Bypass CSP restrictions by using this page to submit your token</p>
        
        <div class="step">
            <span class="step-number">1</span><h3>Open PrivateGPT & Login</h3>
            <p>Navigate to the PrivateGPT website and complete SSO login if needed.</p>
            <div style="margin-top: 12px;"><button class="quick-btn" onclick="window.open('` + h.Config.UpstreamURL + `', '_blank')">Open PrivateGPT ↗</button></div>
        </div>
        
        <div class="step">
            <span class="step-number">2</span><h3>Extract Token from Browser Console</h3>
            <p>Open Developer Tools (F12), go to Console tab, and run this code:</p>
            <div class="code-block" id="extractCode"><button class="copy-btn" onclick="copyCode('extractCode')">Copy</button>copy(JSON.parse(localStorage.getItem(JSON.parse(localStorage.getItem(Object.keys(localStorage).find(k=>k.startsWith('msal.token.keys.')))).accessToken[0])).secret)</div>
            <p style="margin-top: 8px; font-size: 0.8rem; color: var(--success);">✓ The token will be copied to your clipboard automatically</p>
        </div>
        
        <div class="step">
            <span class="step-number">3</span><h3>Paste Token Below</h3>
            <p>Paste the copied token into the input field and click Submit.</p>
        </div>
        
        <form id="tokenForm">
            <input type="text" class="token-input" id="tokenInput" placeholder="Paste your token here (eyJ... or Bearer eyJ...)" required>
            <button type="submit" class="submit-btn" id="submitBtn">Submit Token</button>
        </form>
        <div class="status" id="status"></div>
        
        <div class="quick-action">
            <h3>Quick Actions</h3>
            <button class="quick-btn" onclick="checkToken()">Check Current Token</button>
            <button class="quick-btn" onclick="testAPI()">Test API</button>
        </div>
    </div>
    
    <script>
        function copyCode(id) {
            const code = document.getElementById(id).textContent.replace('Copy', '').trim();
            navigator.clipboard.writeText(code).then(() => {
                const btn = document.querySelector('#' + id + ' .copy-btn');
                btn.textContent = 'Copied!';
                setTimeout(() => btn.textContent = 'Copy', 2000);
            });
        }
        function showStatus(msg, isError) {
            const s = document.getElementById('status');
            s.textContent = msg;
            s.className = 'status ' + (isError ? 'error' : 'success');
        }
        document.getElementById('tokenForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = document.getElementById('tokenInput');
            const btn = document.getElementById('submitBtn');
            let token = input.value.trim();
            if (!token) { showStatus('Please enter a token', true); return; }
            if (!token.startsWith('Bearer ')) token = 'Bearer ' + token;
            btn.disabled = true; btn.textContent = 'Submitting...';
            try {
                const r = await fetch('/privategpt/token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
                const d = await r.json();
                if (r.ok) { showStatus('✓ Token saved! You can now use the API.', false); input.value = ''; }
                else showStatus('✗ Error: ' + (d.error || 'Failed'), true);
            } catch (err) { showStatus('✗ Network error: ' + err.message, true); }
            finally { btn.disabled = false; btn.textContent = 'Submit Token'; }
        });
        async function checkToken() {
            try {
                const r = await fetch('/privategpt/token');
                const d = await r.json();
                if (r.ok && d.token) showStatus('✓ Token configured: ' + d.token.substring(0, 30) + '...', false);
                else showStatus('No token configured yet.', true);
            } catch (err) { showStatus('✗ Error: ' + err.message, true); }
        }
        async function testAPI() {
            showStatus('Sending test message...', false);
            try {
                const r = await fetch('/v1/chat/completions', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ model: 'azure-gpt-4o', messages: [{ role: 'user', content: 'Reply with just "OK"' }], stream: false })
                });
                const d = await r.json();
                const s = document.getElementById('status');
                s.className = 'status ' + (r.ok ? 'success' : 'error');
                s.innerHTML = '<pre style="white-space:pre-wrap;word-break:break-all;margin:0;font-size:0.8rem;">' + JSON.stringify(d, null, 2) + '</pre>';
            } catch (err) { showStatus('✗ Test failed: ' + err.message, true); }
        }
    </script>
</body>
</html>`
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
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
	
	// Automatic Token Injection
	if req.Header.Get("Authorization") == "" {
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
			return false
		}

		line = strings.TrimSpace(line)
		if line == "" {
			return true
		}

		if strings.HasPrefix(line, "event: DONE") {
			w.Write([]byte("data: [DONE]\n\n"))
			return false
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
