// Package chat_completions provides request translation for Copilot provider.
// Since copilot-api is OpenAI-compatible, requests are passed through with minimal changes.
package chat_completions

import (
	"bytes"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ConvertOpenAIRequestToCopilot converts an OpenAI Chat Completions request
// to be sent to the copilot-api endpoint. Since copilot-api is OpenAI-compatible,
// this is mostly a passthrough with model name stripping of the "copilot-" prefix.
//
// Parameters:
//   - modelName: The model name (e.g., "copilot-gpt-4o")
//   - inputRawJSON: The raw JSON request data
//   - stream: Whether this is a streaming request
//
// Returns:
//   - []byte: The transformed request data
func ConvertOpenAIRequestToCopilot(modelName string, inputRawJSON []byte, _ bool) []byte {
	// Strip the "copilot-" prefix from the model name for the upstream request
	upstreamModel := modelName
	if len(modelName) > 8 && modelName[:8] == "copilot-" {
		upstreamModel = modelName[8:]
	}

	// Update the model field
	updatedJSON, err := sjson.SetBytes(inputRawJSON, "model", upstreamModel)
	if err != nil {
		return bytes.Clone(inputRawJSON)
	}

	// Some copilot-api specific adjustments
	// If max_tokens is not set, ensure a reasonable default for copilot
	if !gjson.GetBytes(updatedJSON, "max_tokens").Exists() {
		updatedJSON, _ = sjson.SetBytes(updatedJSON, "max_tokens", 4096)
	}

	return updatedJSON
}
