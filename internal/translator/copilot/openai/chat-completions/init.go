// Package chat_completions provides OpenAI chat completions translation for Copilot provider.
// Since copilot-api exposes an OpenAI-compatible endpoint, this is a passthrough translator.
package chat_completions

import (
	. "github.com/router-for-me/CLIProxyAPI/v6/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/translator/translator"
)

func init() {
	translator.Register(
		Copilot,
		OpenAI,
		ConvertOpenAIRequestToCopilot,
		interfaces.TranslateResponse{
			Stream:    ConvertCopilotResponseToOpenAI,
			NonStream: ConvertCopilotResponseToOpenAINonStream,
		},
	)
}
