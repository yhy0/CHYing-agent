<!--
name: 'Tool Description: ToolSearch extended'
description: Extended usage instructions for ToolSearch including query modes and examples
ccVersion: 2.1.31
-->


**Why this is non-negotiable:**
- Deferred tools are not loaded until discovered via this tool
- Calling a deferred tool without first loading it will fail

**Query modes:**

1. **Keyword search** - Use keywords when you're unsure which tool to use or need to discover multiple tools at once:
   - "list directory" - find tools for listing directories
   - "notebook jupyter" - find notebook editing tools
   - "slack message" - find slack messaging tools
   - Returns up to 5 matching tools ranked by relevance
   - All returned tools are immediately available to call — no further selection step needed

2. **Direct selection** - Use \`select:<tool_name>\` when you know the exact tool name and only need that one tool:
   - "select:mcp__slack__read_channel"
   - "select:NotebookEdit"
   - Returns just that tool if it exists

**IMPORTANT:** Both modes load tools equally. Do NOT follow up a keyword search with \`select:\` calls for tools already returned — they are already loaded.

3. **Required keyword** - Prefix with \`+\` to require a match:
   - "+linear create issue" - only tools from "linear", ranked by "create"/"issue"
   - "+slack send" - only "slack" tools, ranked by "send"
   - Useful when you know the service name but not the exact tool

**CORRECT Usage Patterns:**

<example>
User: I need to work with slack somehow
Assistant: Let me search for slack tools.
[Calls ToolSearch with query: "slack"]
Assistant: Found several options including mcp__slack__read_channel.
[Calls mcp__slack__read_channel directly — it was loaded by the keyword search]
</example>

<example>
User: Edit the Jupyter notebook
Assistant: Let me load the notebook editing tool.
[Calls ToolSearch with query: "select:NotebookEdit"]
[Calls NotebookEdit]
</example>

<example>
User: List files in the src directory
Assistant: I can see mcp__filesystem__list_directory in the available tools. Let me select it.
[Calls ToolSearch with query: "select:mcp__filesystem__list_directory"]
[Calls the tool]
</example>

**INCORRECT Usage Patterns - NEVER DO THESE:**

<bad-example>
User: Read my slack messages
Assistant: [Directly calls mcp__slack__read_channel without loading it first]
WRONG - You must load the tool FIRST using this tool
</bad-example>

<bad-example>
Assistant: [Calls ToolSearch with query: "slack", gets back mcp__slack__read_channel]
Assistant: [Calls ToolSearch with query: "select:mcp__slack__read_channel"]
WRONG - The keyword search already loaded the tool. The select call is redundant.
</bad-example>
