package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/tidwall/sjson"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

// CopilotExecutor implements a stateless executor for the copilot-api endpoint.
// It routes copilot-* model requests to the local copilot-api process.
type CopilotExecutor struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewCopilotExecutor creates an executor for the Copilot provider.
func NewCopilotExecutor(cfg *config.Config) *CopilotExecutor {
	return &CopilotExecutor{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// Identifier implements cliproxyauth.ProviderExecutor.
func (e *CopilotExecutor) Identifier() string {
	return "copilot"
}

// PrepareRequest is a no-op for Copilot (local endpoint, no auth needed).
func (e *CopilotExecutor) PrepareRequest(_ *http.Request, _ *cliproxyauth.Auth) error {
	return nil
}

// Execute performs a non-streaming request to the copilot-api endpoint.
func (e *CopilotExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	baseURL := e.getBaseURL()
	model := e.stripCopilotPrefix(req.Model)
	
	// Prepare the payload with the stripped model name
	payload := e.overrideModel(req.Payload, model)
	
	// Build HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return resp, fmt.Errorf("copilot: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	
	// Execute
	httpResp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return resp, fmt.Errorf("copilot: request failed: %w", err)
	}
	defer httpResp.Body.Close()
	
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return resp, fmt.Errorf("copilot: failed to read response: %w", err)
	}
	
	if httpResp.StatusCode >= 400 {
		return resp, &statusErr{code: httpResp.StatusCode, msg: string(body)}
	}
	
	return cliproxyexecutor.Response{
		Payload: body,
	}, nil
}

// ExecuteStream performs a streaming request to the copilot-api endpoint.
func (e *CopilotExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (<-chan cliproxyexecutor.StreamChunk, error) {
	baseURL := e.getBaseURL()
	model := e.stripCopilotPrefix(req.Model)
	
	// Prepare the payload with the stripped model name and ensure stream is true
	payload := e.overrideModel(req.Payload, model)
	payload, _ = sjson.SetBytes(payload, "stream", true)
	
	// Build HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("copilot: failed to create stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	
	// Execute
	httpResp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("copilot: stream request failed: %w", err)
	}
	
	if httpResp.StatusCode >= 400 {
		body, _ := io.ReadAll(httpResp.Body)
		httpResp.Body.Close()
		return nil, &statusErr{code: httpResp.StatusCode, msg: string(body)}
	}
	
	ch := make(chan cliproxyexecutor.StreamChunk, 64)
	
	go func() {
		defer close(ch)
		defer httpResp.Body.Close()
		
		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			line := scanner.Text()
			if line == "" {
				continue
			}
			
			// Strip "data: " prefix if present
			if strings.HasPrefix(line, "data: ") {
				line = line[6:]
			}
			
			if line == "[DONE]" {
				return
			}
			
			ch <- cliproxyexecutor.StreamChunk{Payload: []byte(line)}
		}
		
		if err := scanner.Err(); err != nil {
			log.Warnf("copilot stream scanner error: %v", err)
		}
	}()
	
	return ch, nil
}

// CountTokens is not supported by copilot-api, returns an error.
func (e *CopilotExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, fmt.Errorf("copilot: count_tokens not supported")
}

// Refresh is a no-op for Copilot (authentication is handled externally).
func (e *CopilotExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	return auth, nil
}

// getBaseURL returns the base URL for the copilot-api endpoint.
func (e *CopilotExecutor) getBaseURL() string {
	port := 54546
	if e.cfg != nil && e.cfg.Copilot.Port > 0 {
		port = e.cfg.Copilot.Port
	}
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// stripCopilotPrefix removes the "copilot-" prefix from the model name.
func (e *CopilotExecutor) stripCopilotPrefix(model string) string {
	if strings.HasPrefix(model, "copilot-") {
		return model[8:]
	}
	return model
}

// overrideModel sets the model field in the JSON payload.
func (e *CopilotExecutor) overrideModel(payload []byte, model string) []byte {
	result, err := sjson.SetBytes(payload, "model", model)
	if err != nil {
		return payload
	}
	return result
}
