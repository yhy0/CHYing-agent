<!--
name: 'Data: Tool use reference — TypeScript'
description: TypeScript tool use reference including tool runner, manual agentic loop, code execution, and structured outputs
ccVersion: 2.1.51
-->
# Tool Use — TypeScript

For conceptual overview (tool definitions, tool choice, tips), see [shared/tool-use-concepts.md](../../shared/tool-use-concepts.md).

## Tool Runner (Recommended)

**Beta:** The tool runner is in beta in the TypeScript SDK.

Use \`betaZodTool\` with Zod schemas to define tools with a \`run\` function, then pass them to \`client.beta.messages.toolRunner()\`:

\`\`\`typescript
import Anthropic from "@anthropic-ai/sdk";
import { betaZodTool } from "@anthropic-ai/sdk/helpers/beta/zod";
import { z } from "zod";

const client = new Anthropic();

const getWeather = betaZodTool({
  name: "get_weather",
  description: "Get current weather for a location",
  inputSchema: z.object({
    location: z.string().describe("City and state, e.g., San Francisco, CA"),
    unit: z.enum(["celsius", "fahrenheit"]).optional(),
  }),
  run: async (input) => {
    // Your implementation here
    return \`72°F and sunny in \${input.location}\`;
  },
});

// The tool runner handles the agentic loop and returns the final message
const finalMessage = await client.beta.messages.toolRunner({
  model: "claude-opus-4-6",
  max_tokens: 4096,
  tools: [getWeather],
  messages: [{ role: "user", content: "What's the weather in Paris?" }],
});

console.log(finalMessage.content);
\`\`\`

**Key benefits of the tool runner:**

- No manual loop — the SDK handles calling tools and feeding results back
- Type-safe tool inputs via Zod schemas
- Tool schemas are generated automatically from Zod definitions
- Iteration stops automatically when Claude has no more tool calls

---

## Manual Agentic Loop

Use this when you need fine-grained control:

\`\`\`typescript
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();
const tools = [...]; // Your tool definitions
const messages = [{ role: "user", content: userInput }];

while (true) {
  const response = await client.messages.create({
    model: "claude-opus-4-6",
    max_tokens: 4096,
    tools: tools,
    messages: messages,
  });

  if (response.stop_reason === "end_turn") break;

  const toolUseBlocks = response.content.filter((b) => b.type === "tool_use");

  messages.push({ role: "assistant", content: response.content });

  const toolResults = [];
  for (const tool of toolUseBlocks) {
    const result = await executeTool(tool.name, tool.input);
    toolResults.push({
      type: "tool_result",
      tool_use_id: tool.id,
      content: result,
    });
  }

  messages.push({ role: "user", content: toolResults });
}
\`\`\`

---

## Handling Tool Results

\`\`\`typescript
const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  tools: tools,
  messages: [{ role: "user", content: "What's the weather in Paris?" }],
});

for (const block of response.content) {
  if (block.type === "tool_use") {
    const result = await executeTool(block.name, block.input);

    const followup = await client.messages.create({
      model: "claude-opus-4-6",
      max_tokens: 1024,
      tools: tools,
      messages: [
        { role: "user", content: "What's the weather in Paris?" },
        { role: "assistant", content: response.content },
        {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: block.id, content: result },
          ],
        },
      ],
    });
  }
}
\`\`\`

---

## Tool Choice

\`\`\`typescript
const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  tools: tools,
  tool_choice: { type: "tool", name: "get_weather" },
  messages: [{ role: "user", content: "What's the weather in Paris?" }],
});
\`\`\`

---

## Code Execution

### Basic Usage

\`\`\`typescript
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 4096,
  messages: [
    {
      role: "user",
      content:
        "Calculate the mean and standard deviation of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]",
    },
  ],
  tools: [{ type: "code_execution_20260120", name: "code_execution" }],
});
\`\`\`

### Upload Files for Analysis

\`\`\`typescript
import Anthropic, { toFile } from "@anthropic-ai/sdk";
import { createReadStream } from "fs";

const client = new Anthropic();

// 1. Upload a file
const uploaded = await client.beta.files.upload({
  file: await toFile(createReadStream("sales_data.csv"), undefined, {
    type: "text/csv",
  }),
  betas: ["files-api-2025-04-14"],
});

// 2. Pass to code execution
// Code execution is GA; Files API is still beta (pass via RequestOptions)
const response = await client.messages.create(
  {
    model: "claude-opus-4-6",
    max_tokens: 4096,
    messages: [
      {
        role: "user",
        content: [
          {
            type: "text",
            text: "Analyze this sales data. Show trends and create a visualization.",
          },
          { type: "container_upload", file_id: uploaded.id },
        ],
      },
    ],
    tools: [{ type: "code_execution_20260120", name: "code_execution" }],
  },
  { headers: { "anthropic-beta": "files-api-2025-04-14" } },
);
\`\`\`

### Retrieve Generated Files

\`\`\`typescript
import path from "path";
import fs from "fs";

const OUTPUT_DIR = "./claude_outputs";
await fs.promises.mkdir(OUTPUT_DIR, { recursive: true });

for (const block of response.content) {
  if (block.type === "bash_code_execution_tool_result") {
    const result = block.content;
    if (result.type === "bash_code_execution_result" && result.content) {
      for (const fileRef of result.content) {
        if (fileRef.type === "bash_code_execution_output") {
          const metadata = await client.beta.files.retrieveMetadata(
            fileRef.file_id,
          );
          const response = await client.beta.files.download(fileRef.file_id);
          const fileBytes = Buffer.from(await response.arrayBuffer());
          const safeName = path.basename(metadata.filename);
          if (!safeName || safeName === "." || safeName === "..") {
            console.warn(\`Skipping invalid filename: \${metadata.filename}\`);
            continue;
          }
          const outputPath = path.join(OUTPUT_DIR, safeName);
          await fs.promises.writeFile(outputPath, fileBytes);
          console.log(\`Saved: \${outputPath}\`);
        }
      }
    }
  }
}
\`\`\`

### Container Reuse

\`\`\`typescript
// First request: set up environment
const response1 = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 4096,
  messages: [
    {
      role: "user",
      content: "Install tabulate and create data.json with sample user data",
    },
  ],
  tools: [{ type: "code_execution_20260120", name: "code_execution" }],
});

// Reuse container
const containerId = response1.container.id;

const response2 = await client.messages.create({
  container: containerId,
  model: "claude-opus-4-6",
  max_tokens: 4096,
  messages: [
    {
      role: "user",
      content: "Read data.json and display as a formatted table",
    },
  ],
  tools: [{ type: "code_execution_20260120", name: "code_execution" }],
});
\`\`\`

---

## Memory Tool

### Basic Usage

\`\`\`typescript
const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 2048,
  messages: [
    {
      role: "user",
      content: "Remember that my preferred language is TypeScript.",
    },
  ],
  tools: [{ type: "memory_20250818", name: "memory" }],
});
\`\`\`

### SDK Memory Helper

Use \`betaMemoryTool\` with a \`MemoryToolHandlers\` implementation:

\`\`\`typescript
import {
  betaMemoryTool,
  type MemoryToolHandlers,
} from "@anthropic-ai/sdk/helpers/beta/memory";

const handlers: MemoryToolHandlers = {
  async view(command) { ... },
  async create(command) { ... },
  async str_replace(command) { ... },
  async insert(command) { ... },
  async delete(command) { ... },
  async rename(command) { ... },
};

const memory = betaMemoryTool(handlers);

const runner = client.beta.messages.toolRunner({
  model: "claude-opus-4-6",
  max_tokens: 2048,
  tools: [memory],
  messages: [{ role: "user", content: "Remember my preferences" }],
});

for await (const message of runner) {
  console.log(message);
}
\`\`\`

For full implementation examples, use WebFetch:

- \`https://github.com/anthropics/anthropic-sdk-typescript/blob/main/examples/tools-helpers-memory.ts\`

---

## Structured Outputs

### JSON Outputs (Zod — Recommended)

\`\`\`typescript
import Anthropic from "@anthropic-ai/sdk";
import { z } from "zod";
import { zodOutputFormat } from "@anthropic-ai/sdk/helpers/zod";

const ContactInfoSchema = z.object({
  name: z.string(),
  email: z.string(),
  plan: z.string(),
  interests: z.array(z.string()),
  demo_requested: z.boolean(),
});

const client = new Anthropic();

const response = await client.messages.parse({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  messages: [
    {
      role: "user",
      content:
        "Extract: Jane Doe (jane@co.com) wants Enterprise, interested in API and SDKs, wants a demo.",
    },
  ],
  output_config: {
    format: zodOutputFormat(ContactInfoSchema),
  },
});

console.log(response.parsed_output.name); // "Jane Doe"
\`\`\`

### Strict Tool Use

\`\`\`typescript
const response = await client.messages.create({
  model: "claude-opus-4-6",
  max_tokens: 1024,
  messages: [
    {
      role: "user",
      content: "Book a flight to Tokyo for 2 passengers on March 15",
    },
  ],
  tools: [
    {
      name: "book_flight",
      description: "Book a flight to a destination",
      strict: true,
      input_schema: {
        type: "object",
        properties: {
          destination: { type: "string" },
          date: { type: "string", format: "date" },
          passengers: {
            type: "integer",
            enum: [1, 2, 3, 4, 5, 6, 7, 8],
          },
        },
        required: ["destination", "date", "passengers"],
        additionalProperties: false,
      },
    },
  ],
});
\`\`\`
