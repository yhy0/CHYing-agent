<!--
name: 'Data: Claude API reference — Go'
description: Go SDK reference including installation, client initialization, basic requests, streaming, and manual agentic loop
ccVersion: 2.1.51
-->
# Claude API — Go

> **Note:** The Go SDK supports the Claude API. Tool runner and Agent SDK are not yet available for Go — use the manual agentic loop for tool use.

## Installation

\`\`\`bash
go get github.com/anthropics/anthropic-sdk-go
\`\`\`

## Client Initialization

\`\`\`go
import (
    "github.com/anthropics/anthropic-sdk-go"
    "github.com/anthropics/anthropic-sdk-go/option"
)

// Default (uses ANTHROPIC_API_KEY env var)
client := anthropic.NewClient()

// Explicit API key
client := anthropic.NewClient(
    option.WithAPIKey("your-api-key"),
)
\`\`\`

---

## Basic Message Request

\`\`\`go
response, err := client.Messages.New(context.TODO(), anthropic.MessageNewParams{
    Model:     anthropic.ModelClaudeOpus4_6,
    MaxTokens: 1024,
    Messages: []anthropic.MessageParam{
        anthropic.NewUserMessage(anthropic.NewTextBlock("What is the capital of France?")),
    },
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(response.Content[0].Text)
\`\`\`

---

## Streaming

\`\`\`go
stream := client.Messages.NewStreaming(context.TODO(), anthropic.MessageNewParams{
    Model:     anthropic.ModelClaudeOpus4_6,
    MaxTokens: 1024,
    Messages: []anthropic.MessageParam{
        anthropic.NewUserMessage(anthropic.NewTextBlock("Write a haiku")),
    },
})

for stream.Next() {
    event := stream.Current()
    switch eventVariant := event.AsAny().(type) {
    case anthropic.ContentBlockDeltaEvent:
        switch deltaVariant := eventVariant.Delta.AsAny().(type) {
        case anthropic.TextDelta:
            fmt.Print(deltaVariant.Text)
        }
    }
}
if err := stream.Err(); err != nil {
    log.Fatal(err)
}
\`\`\`

---

## Tool Use (Manual Loop)

The Go SDK supports raw tool definitions via JSON schema. See the [shared tool use concepts](../shared/tool-use-concepts.md) for the tool definition format and agentic loop pattern.
