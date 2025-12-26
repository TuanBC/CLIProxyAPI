// Package chat_completions provides response translation for Copilot provider.
// Since copilot-api returns OpenAI-compatible responses, this is a passthrough translator.
package chat_completions

import (
	"bytes"
	"context"
)

// ConvertCopilotResponseToOpenAI translates streaming responses from copilot-api
// to OpenAI Chat Completions format. Since copilot-api is already OpenAI-compatible,
// this is essentially a passthrough.
//
// Parameters:
//   - ctx: Context for cancellation
//   - modelName: The model name (unused)
//   - originalRequestRawJSON: Original request JSON
//   - requestRawJSON: Transformed request JSON
//   - rawJSON: The raw response from copilot-api
//   - param: State parameter for streaming
//
// Returns:
//   - []string: Slice of response strings
func ConvertCopilotResponseToOpenAI(_ context.Context, _ string, originalRequestRawJSON, requestRawJSON, rawJSON []byte, param *any) []string {
	// Strip "data: " prefix if present (SSE format)
	if bytes.HasPrefix(rawJSON, []byte("data:")) {
		rawJSON = bytes.TrimSpace(rawJSON[5:])
	}

	// Handle [DONE] marker
	if bytes.Equal(rawJSON, []byte("[DONE]")) {
		return []string{}
	}

	// Passthrough - copilot-api returns OpenAI-compatible format
	return []string{string(rawJSON)}
}

// ConvertCopilotResponseToOpenAINonStream converts a non-streaming response from copilot-api.
// Since copilot-api is OpenAI-compatible, this is a direct passthrough.
//
// Parameters:
//   - ctx: Context for cancellation
//   - modelName: The model name
//   - originalRequestRawJSON: Original request JSON
//   - requestRawJSON: Transformed request JSON
//   - rawJSON: The raw response from copilot-api
//   - param: State parameter
//
// Returns:
//   - string: The response string
func ConvertCopilotResponseToOpenAINonStream(ctx context.Context, modelName string, originalRequestRawJSON, requestRawJSON, rawJSON []byte, param *any) string {
	return string(rawJSON)
}
