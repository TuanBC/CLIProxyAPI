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
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers"
	log "github.com/sirupsen/logrus"
)

type PrivateGPTHandler struct {
	Base          *handlers.BaseAPIHandler
	Config        *config.PrivateGPTConfig
	capturedToken string
	tokenMu       sync.RWMutex
}

func NewPrivateGPTHandler(base *handlers.BaseAPIHandler, cfg *config.PrivateGPTConfig) *PrivateGPTHandler {
	return &PrivateGPTHandler{
		Base:   base,
		Config: cfg,
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

		// Capture Authorization header if present
		if auth := req.Header.Get("Authorization"); auth != "" {
			h.tokenMu.Lock()
			if h.capturedToken == "" || h.capturedToken != auth {
				h.capturedToken = auth
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

// GetModels returns the list of supported models from the configuration
func (h *PrivateGPTHandler) GetModels(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"models": h.Config.Models})
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
	Role    string `json:"role"`
	Content string `json:"content"`
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
	
	// Extract basic parameters
	var payload map[string]interface{}
	modelID := "privategpt-model"
	isStream := true // Default to true matching PrivateGPT native
	
	if err := json.Unmarshal(bodyBytes, &payload); err == nil {
		if m, ok := payload["model_id"].(string); ok {
			modelID = m
		}
		
		if s, ok := payload["stream"].(bool); ok {
			isStream = s
		} else {
			isStream = false
		}

		// Inject defaults required by PrivateGPT upstream
		if _, ok := payload["parent_message_id"]; !ok {
			payload["parent_message_id"] = nil
		}
		if _, ok := payload["tools"]; !ok {
			payload["tools"] = []interface{}{}
		}
		if _, ok := payload["metadata"]; !ok {
			payload["metadata"] = map[string]interface{}{"attachments": []interface{}{}}
		}
		
		// Re-marshal body with defaults
		if newBody, err := json.Marshal(payload); err == nil {
			bodyBytes = newBody
		} else {
			log.Warnf("Failed to re-marshal payload with defaults: %v", err)
		}

	} else {
		// Fallback if unmarshal fails (unlikely if valid JSON)
		isStream = false 
	}
	
	// Re-create body for upstream request
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 2. Prepare upstream request
	upstreamURL := h.Config.UpstreamURL + c.Request.RequestURI
	req, err := http.NewRequest(c.Request.Method, upstreamURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upstream request"})
		return
	}

	// Copy headers
	req.Header = c.Request.Header.Clone()
	
	// Force headers for upstream compatibility
	if h.Config.UpstreamURL != "" {
		req.Header.Set("Origin", h.Config.UpstreamURL)
		req.Header.Set("Referer", h.Config.UpstreamURL)
	}
	// Ensure Host header is set (some servers require it to match)
	u, _ := url.Parse(h.Config.UpstreamURL)
	req.Host = u.Host

	// 3. Execute upstream request
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Self-signed certs in DevMode/Internal
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("Upstream request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
		return
	}

	completionID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	created := time.Now().Unix()

	if isStream {
		h.handleStreamingResponse(c, resp.Body, completionID, created, modelID)
	} else {
		h.handleNonStreamingResponse(c, resp.Body, completionID, created, modelID)
	}
}

func (h *PrivateGPTHandler) handleStreamingResponse(c *gin.Context, upstreamBody io.Reader, id string, created int64, model string) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")

	reader := bufio.NewReader(upstreamBody)

	c.Stream(func(w io.Writer) bool {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false
		}

		line = strings.TrimSpace(line)
		if line == "" {
			return true // continue
		}

		if strings.HasPrefix(line, "event: DONE") {
			w.Write([]byte("data: [DONE]\n\n"))
			return false
		}

		if strings.HasPrefix(line, "event: data") {
			dataLine, err := reader.ReadString('\n')
			if err != nil {
				return false
			}
			dataLine = strings.TrimSpace(dataLine)
			if strings.HasPrefix(dataLine, "data: ") {
				jsonStr := strings.TrimPrefix(dataLine, "data: ")
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
			// Log error but try to return what we have?
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "event: DONE") {
			break
		}

		if strings.HasPrefix(line, "event: data") {
			dataLine, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			dataLine = strings.TrimSpace(dataLine)
			if strings.HasPrefix(dataLine, "data: ") {
				jsonStr := strings.TrimPrefix(dataLine, "data: ")
				var dataObj map[string]interface{}
				if err := json.Unmarshal([]byte(jsonStr), &dataObj); err == nil {
					if v, ok := dataObj["v"].(string); ok {
						fullContent.WriteString(v)
					}
				}
			}
		}
	}

	// Construct final response
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
					Content: fullContent.String(),
				},
				FinishReason: func() *string { s := "stop"; return &s }(),
			},
		},
		Usage: &OpenAIUsage{
			// We don't have usage data from PrivateGPT stream, so we leave zero values or estimate
			PromptTokens:     0,
			CompletionTokens: 0,
			TotalTokens:      0,
		},
	}

	c.JSON(http.StatusOK, response)
}
