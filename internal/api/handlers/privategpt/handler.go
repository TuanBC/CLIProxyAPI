package privategpt

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
