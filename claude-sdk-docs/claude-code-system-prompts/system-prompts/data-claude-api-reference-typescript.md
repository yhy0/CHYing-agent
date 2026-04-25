<!--
name: 'Data: Claude API reference — TypeScript'
description: TypeScript SDK reference including installation, client initialization, basic requests, thinking, and multi-turn conversation
ccVersion: 2.1.51
-->
# Claude API — TypeScript

## Installation

\`\`\`bash
npm install @anthropic-ai/sdk
\`\`\`

## Client Initialization

\`\`\`typescript
import Anthropic from "@anthropic-ai/sdk";

// Default (uses ANTHROPIC_API_KEY env var)
const client = new Anthropic();

// Explicit API key
const client = new Anthropic({ apiKey: "your-api-key" });
\`\`\`

---

## Basic Message Request

\`\`\`typescript
const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  messages: [{ role: "user", content: "What is the capital of France?" }],
});
console.log(response.content[0].text);
\`\`\`

---

## System Prompts

\`\`\`typescript
const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  system:
    "You are a helpful coding assistant. Always provide examples in Python.",
  messages: [{ role: "user", content: "How do I read a JSON file?" }],
});
\`\`\`

---

## Vision (Images)

### URL

\`\`\`typescript
const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  messages: [
    {
      role: "user",
      content: [
        {
          type: "image",
          source: { type: "url", url: "https://example.com/image.png" },
        },
        { type: "text", text: "Describe this image" },
      ],
    },
  ],
});
\`\`\`

### Base64

\`\`\`typescript
import fs from "fs";

const imageData = fs.readFileSync("image.png").toString("base64");

const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  messages: [
    {
      role: "user",
      content: [
        {
          type: "image",
          source: { type: "base64", media_type: "image/png", data: imageData },
        },
        { type: "text", text: "What's in this image?" },
      ],
    },
  ],
});
\`\`\`

---

## Prompt Caching

\`\`\`typescript
const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  system: [
    {
      type: "text",
      text: "You are an expert on this large document...",
      cache_control: { type: "ephemeral" }, // default TTL is 5 minutes
    },
  ],
  messages: [{ role: "user", content: "Summarize the key points" }],
});

// With explicit TTL (time-to-live)
const response2 = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  system: [
    {
      type: "text",
      text: "You are an expert on this large document...",
      cache_control: { type: "ephemeral", ttl: "1h" }, // 1 hour TTL
    },
  ],
  messages: [{ role: "user", content: "Summarize the key points" }],
});
\`\`\`

---

## Extended Thinking

> **Opus 4.6 and Sonnet 4.6:** Use adaptive thinking. \`budget_tokens\` is deprecated on both Opus 4.6 and Sonnet 4.6.
> **Older models:** Use \`thinking: {type: "enabled", budget_tokens: N}\` (must be < \`max_tokens\`, min 1024).

\`\`\`typescript
// Opus 4.6: adaptive thinking (recommended)
const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 16000,
  thinking: { type: "adaptive" },
  output_config: { effort: "high" }, // low | medium | high | max
  messages: [
    { role: "user", content: "Solve this math problem step by step..." },
  ],
});

for (const block of response.content) {
  if (block.type === "thinking") {
    console.log("Thinking:", block.thinking);
  } else if (block.type === "text") {
    console.log("Response:", block.text);
  }
}
\`\`\`

---

## Error Handling

\`\`\`typescript
import Anthropic from "@anthropic-ai/sdk";

try {
  const response = await client.messages.create({...});
} catch (error) {
  if (error instanceof Anthropic.BadRequestError) {
    console.error("Bad request:", error.message);
  } else if (error instanceof Anthropic.AuthenticationError) {
    console.error("Invalid API key");
  } else if (error instanceof Anthropic.RateLimitError) {
    console.error("Rate limited - retry later");
  } else if (error instanceof Anthropic.APIError) {
    console.error(\`API error \${error.status}:\`, error.message);
  }
}
\`\`\`

---

## Multi-Turn Conversations

The API is stateless — send the full conversation history each time.

\`\`\`typescript
const messages = [
  { role: "user", content: "My name is Alice." },
  { role: "assistant", content: "Hello Alice! Nice to meet you." },
  { role: "user", content: "What's my name?" },
];

const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  messages: messages,
});
\`\`\`

**Rules:**

- Messages must alternate between \`user\` and \`assistant\`
- First message must be \`user\`

---

### Compaction (long conversations)

> **Beta, Opus 4.6 only.** When conversations approach the 200K context window, compaction automatically summarizes earlier context server-side. The API returns a \`compaction\` block; you must pass it back on subsequent requests — append \`response.content\`, not just the text.

\`\`\`typescript
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();
const messages: Anthropic.Beta.BetaMessageParam[] = [];

async function chat(userMessage: string): Promise<string> {
  messages.push({ role: "user", content: userMessage });

  const response = await client.beta.messages.create({
    betas: ["compact-2026-01-12"],
    model: "claude-opus-4-6",
    max_tokens: 4096,
    messages,
    context_management: {
      edits: [{ type: "compact_20260112" }],
    },
  });

  // Append full content — compaction blocks must be preserved
  messages.push({ role: "assistant", content: response.content });

  const textBlock = response.content.find((block) => block.type === "text");
  return textBlock?.text ?? "";
}

// Compaction triggers automatically when context grows large
console.log(await chat("Help me build a Python web scraper"));
console.log(await chat("Add support for JavaScript-rendered pages"));
console.log(await chat("Now add rate limiting and error handling"));
\`\`\`

---

## Stop Reasons

The \`stop_reason\` field in the response indicates why the model stopped generating:

| Value          | Meaning                                                        |
| -------------- | -------------------------------------------------------------- |
| \`end_turn\`     | Claude finished its response naturally                         |
| \`max_tokens\`   | Hit the \`max_tokens\` limit — increase it or use streaming      |
| \`stop_sequence\`| Hit a custom stop sequence                                     |
| \`tool_use\`     | Claude wants to call a tool — execute it and continue          |
| \`pause_turn\`   | Model paused and can be resumed (agentic flows)                |
| \`refusal\`      | Claude refused for safety reasons — output may not match schema|

---

## Cost Optimization Strategies

### 1. Use Prompt Caching for Repeated Context

\`\`\`typescript
const systemWithCache = [
  {
    type: "text",
    text: largeDocumentText, // e.g., 50KB of context
    cache_control: { type: "ephemeral" }, // add ttl: "1h" for longer caching
  },
];

// First request: full cost
// Subsequent requests: ~90% cheaper for cached portion
\`\`\`

### 2. Use Token Counting Before Requests

\`\`\`typescript
const countResponse = await client.messages.countTokens({
  model: "claude-opus-4-6",
  messages: messages,
  system: system,
});

const estimatedInputCost = countResponse.input_tokens * 0.000005; // $5/1M tokens
console.log(\`Estimated input cost: $\${estimatedInputCost.toFixed(4)}\`);
\`\`\`
