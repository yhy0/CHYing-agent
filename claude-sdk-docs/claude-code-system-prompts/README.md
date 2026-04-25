<div>
<div align="right">
<a href="https://piebald.ai"><img width="200" top="20" align="right" src="https://github.com/Piebald-AI/.github/raw/main/Wordmark.svg"></a>
</div>

<div align="left">

### Check out Piebald
We've released **Piebald**, the ultimate agentic AI developer experience. \
Download it and try it out for free!  **https://piebald.ai/**

<a href="https://piebald.ai/discord"><img src="https://img.shields.io/badge/Join%20our%20Discord-5865F2?style=flat&logo=discord&logoColor=white" alt="Join our Discord"></a>
<a href="https://x.com/PiebaldAI"><img src="https://img.shields.io/badge/Follow%20%40PiebaldAI-000000?style=flat&logo=x&logoColor=white" alt="X"></a>

<sub>[**Scroll down for Claude Code's system prompts.**](#claude-code-system-prompts) :point_down:</sub>

</div>
</div>

<div align="left">
<a href="https://piebald.ai">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://piebald.ai/screenshot-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://piebald.ai/screenshot-light.png">
  <img alt="hero" width="800" src="https://piebald.ai/screenshot-light.png">
</picture>
</a>
</div>

# Claude Code System Prompts

[![Mentioned in Awesome Claude Code](https://awesome.re/mentioned-badge.svg)](https://github.com/hesreallyhim/awesome-claude-code)

> [!important]
> **NEW (January 23, 2026): We've added all of Claude Code's ~40 system reminders to this list&mdash;see [System Reminders](#system-reminders).**

This repository contains an up-to-date list of all Claude Code's various system prompts and their associated token counts as of **[Claude Code v2.1.62](https://www.npmjs.com/package/@anthropic-ai/claude-code/v/2.1.62) (February 26th, 2026).**  It also contains a [**CHANGELOG.md**](./CHANGELOG.md) for the system prompts across 114 versions since v2.0.14.  From the team behind [<img src="https://github.com/Piebald-AI/piebald/raw/main/assets/logo.svg" width="15"> **Piebald.**](https://piebald.ai/)

**This repository is updated within minutes of each Claude Code release.  See the [changelog](./CHANGELOG.md), and follow [@PiebaldAI](https://x.com/PiebaldAI) on X for a summary of the system prompt changes in each release.**

> [!note]
> ⭐ **Star** this repository to get notified about new Claude Code versions.  For each new Claude Code version, we create a release on GitHub, which will notify all users who've starred the repository.

---

Why multiple "system prompts?"

**Claude Code doesn't just have one single string for its system prompt.**

Instead, there are:
- Large portions conditionally added depending on the environment and various configs.
- Descriptions for builtin tools like `Write`, `Bash`, and `TodoWrite`, and some are fairly large.
- Separate system prompts for builtin agents like Explore and Plan.
- Numerous AI-powered utility functions, such as conversation compaction, `CLAUDE.md` generation, session title generation, etc. featuring their own systems prompts.

The result&mdash;110+ strings that are constantly changing and moving within a very large minified JS file.

> [!TIP]
> Want to **modify a particular piece of the system prompt** in your own Claude Code installation?  **Use [tweakcc](https://github.com/Piebald-AI/tweakcc).**  It&mdash;
> - lets you customize the the individual pieces of the system prompt as markdown files, and then
> - patches your npm-based or native (binary) Claude Code installation with them, and also
> - provides diffing and conflict management for when both you and Anthropic have conflicting modifications to the same prompt file.

## Extraction

This repository contains the system prompts extracted using a script from the latest npm version of Claude Code.  As they're extracted directly from Claude Code's compiled source code, they're guaranteed to be exactly what Claude Code uses.  If you use [tweakcc](https://github.com/Piebald-AI/tweakcc) to customize the system prompts, it works in a similar way&mdash;it patches the exact same strings in your local installation as are extracted into this repository.

## Prompts

Note that some prompts contain interpolated bits such as builtin tool name references, lists of available sub agents, and various other context-specific variables, so the actual counts in a particular Claude Code session will differ slightly&mdash;likely not beyond ±20 tokens, however.

### Agent Prompts

Sub-agents and utilities.

#### Sub-agents

- [Agent Prompt: Explore](./system-prompts/agent-prompt-explore.md) (**516** tks) - System prompt for the Explore subagent.
- [Agent Prompt: Plan mode (enhanced)](./system-prompts/agent-prompt-plan-mode-enhanced.md) (**633** tks) - Enhanced prompt for the Plan subagent.
- [Agent Prompt: Task tool (extra notes)](./system-prompts/agent-prompt-task-tool-extra-notes.md) (**127** tks) - Additional notes for Task tool usage (absolute paths, no emojis, no colons before tool calls).
- [Agent Prompt: Task tool](./system-prompts/agent-prompt-task-tool.md) (**294** tks) - System prompt given to the subagent spawned via the Task tool.

### Creation Assistants

- [Agent Prompt: Agent creation architect](./system-prompts/agent-prompt-agent-creation-architect.md) (**1110** tks) - System prompt for creating custom AI agents with detailed specifications.
- [Agent Prompt: CLAUDE.md creation](./system-prompts/agent-prompt-claudemd-creation.md) (**384** tks) - System prompt for analyzing codebases and creating CLAUDE.md documentation files.
- [Agent Prompt: Status line setup](./system-prompts/agent-prompt-status-line-setup.md) (**1502** tks) - System prompt for the statusline-setup agent that configures status line display.

### Slash commands

- [Agent Prompt: /pr-comments slash command](./system-prompts/agent-prompt-pr-comments-slash-command.md) (**396** tks) - System prompt for fetching and displaying GitHub PR comments.
- [Agent Prompt: /review-pr slash command](./system-prompts/agent-prompt-review-pr-slash-command.md) (**211** tks) - System prompt for reviewing GitHub pull requests with code analysis.
- [Agent Prompt: /security-review slash command](./system-prompts/agent-prompt-security-review-slash-command.md) (**2610** tks) - Comprehensive security review prompt for analyzing code changes with focus on exploitable vulnerabilities.

### Utilities

- [Agent Prompt: Agent Hook](./system-prompts/agent-prompt-agent-hook.md) (**133** tks) - Prompt for an 'agent hook'.
- [Agent Prompt: Bash command description writer](./system-prompts/agent-prompt-bash-command-description-writer.md) (**207** tks) - Instructions for generating clear, concise command descriptions in active voice for bash commands.
- [Agent Prompt: Bash command file path extraction](./system-prompts/agent-prompt-bash-command-file-path-extraction.md) (**286** tks) - System prompt for extracting file paths from bash command output.
- [Agent Prompt: Bash command prefix detection](./system-prompts/agent-prompt-bash-command-prefix-detection.md) (**823** tks) - System prompt for detecting command prefixes and command injection.
- [Agent Prompt: Claude guide agent](./system-prompts/agent-prompt-claude-guide-agent.md) (**761** tks) - System prompt for the claude-guide agent that helps users understand and use Claude Code, the Claude Agent SDK and the Claude API effectively..
- [Agent Prompt: Conversation summarization](./system-prompts/agent-prompt-conversation-summarization.md) (**1121** tks) - System prompt for creating detailed conversation summaries.
- [Agent Prompt: Hook condition evaluator](./system-prompts/agent-prompt-hook-condition-evaluator.md) (**78** tks) - System prompt for evaluating hook conditions in Claude Code.
- [Agent Prompt: Memory selection](./system-prompts/agent-prompt-memory-selection.md) (**156** tks) - Instructions for selecting relevant memories for a user query.
- [Agent Prompt: Prompt Suggestion Generator v2](./system-prompts/agent-prompt-prompt-suggestion-generator-v2.md) (**296** tks) - V2 instructions for generating prompt suggestions for Claude Code.
- [Agent Prompt: Quick PR creation](./system-prompts/agent-prompt-quick-pr-creation.md) (**945** tks) - Streamlined prompt for creating a commit and pull request with pre-populated context.
- [Agent Prompt: Quick git commit](./system-prompts/agent-prompt-quick-git-commit.md) (**507** tks) - Streamlined prompt for creating a single git commit with pre-populated context.
- [Agent Prompt: Recent Message Summarization](./system-prompts/agent-prompt-recent-message-summarization.md) (**720** tks) - Agent prompt used for summarizing recent messages..
- [Agent Prompt: Session Search Assistant](./system-prompts/agent-prompt-session-search-assistant.md) (**439** tks) - Agent prompt for the session search assistant that finds relevant sessions based on user queries and metadata.
- [Agent Prompt: Session memory update instructions](./system-prompts/agent-prompt-session-memory-update-instructions.md) (**756** tks) - Instructions for updating session memory files during conversations.
- [Agent Prompt: Session title and branch generation](./system-prompts/agent-prompt-session-title-and-branch-generation.md) (**307** tks) - Agent for generating succinct session titles and git branch names.
- [Agent Prompt: Update Magic Docs](./system-prompts/agent-prompt-update-magic-docs.md) (**718** tks) - Prompt for the magic-docs agent..
- [Agent Prompt: User sentiment analysis](./system-prompts/agent-prompt-user-sentiment-analysis.md) (**205** tks) - System prompt for analyzing user frustration and PR creation requests.
- [Agent Prompt: WebFetch summarizer](./system-prompts/agent-prompt-webfetch-summarizer.md) (**189** tks) - Prompt for agent that summarizes verbose output from WebFetch for the main model.

### Data

The content of various template files embedded in Claude Code.

- [Data: Agent SDK patterns — Python](./system-prompts/data-agent-sdk-patterns-python.md) (**2350** tks) - Python Agent SDK patterns including custom tools, hooks, subagents, MCP integration, and session resumption.
- [Data: Agent SDK patterns — TypeScript](./system-prompts/data-agent-sdk-patterns-typescript.md) (**1069** tks) - TypeScript Agent SDK patterns including basic agents, hooks, subagents, and MCP integration.
- [Data: Agent SDK reference — Python](./system-prompts/data-agent-sdk-reference-python.md) (**2750** tks) - Python Agent SDK reference including installation, quick start, custom tools via MCP, and hooks.
- [Data: Agent SDK reference — TypeScript](./system-prompts/data-agent-sdk-reference-typescript.md) (**2287** tks) - TypeScript Agent SDK reference including installation, quick start, custom tools, and hooks.
- [Data: Claude API reference — C#](./system-prompts/data-claude-api-reference-c.md) (**550** tks) - C# SDK reference including installation, client initialization, basic requests, streaming, and tool use.
- [Data: Claude API reference — Go](./system-prompts/data-claude-api-reference-go.md) (**621** tks) - Go SDK reference including installation, client initialization, basic requests, streaming, and manual agentic loop.
- [Data: Claude API reference — Java](./system-prompts/data-claude-api-reference-java.md) (**1226** tks) - Java SDK reference including installation, client initialization, basic requests, streaming, and beta tool use.
- [Data: Claude API reference — PHP](./system-prompts/data-claude-api-reference-php.md) (**394** tks) - PHP SDK reference including installation, client initialization, and basic message requests.
- [Data: Claude API reference — Python](./system-prompts/data-claude-api-reference-python.md) (**3248** tks) - Python SDK reference including installation, client initialization, basic requests, thinking, and multi-turn conversation.
- [Data: Claude API reference — Ruby](./system-prompts/data-claude-api-reference-ruby.md) (**622** tks) - Ruby SDK reference including installation, client initialization, basic requests, streaming, and beta tool runner.
- [Data: Claude API reference — TypeScript](./system-prompts/data-claude-api-reference-typescript.md) (**2388** tks) - TypeScript SDK reference including installation, client initialization, basic requests, thinking, and multi-turn conversation.
- [Data: Claude model catalog](./system-prompts/data-claude-model-catalog.md) (**1510** tks) - Catalog of current and legacy Claude models with exact model IDs, aliases, context windows, and pricing.
- [Data: Files API reference — Python](./system-prompts/data-files-api-reference-python.md) (**1303** tks) - Python Files API reference including file upload, listing, deletion, and usage in messages.
- [Data: Files API reference — TypeScript](./system-prompts/data-files-api-reference-typescript.md) (**798** tks) - TypeScript Files API reference including file upload, listing, deletion, and usage in messages.
- [Data: GitHub Actions workflow for @claude mentions](./system-prompts/data-github-actions-workflow-for-claude-mentions.md) (**527** tks) - GitHub Actions workflow template for triggering Claude Code via @claude mentions.
- [Data: GitHub App installation PR description](./system-prompts/data-github-app-installation-pr-description.md) (**424** tks) - Template for PR description when installing Claude Code GitHub App integration.
- [Data: HTTP error codes reference](./system-prompts/data-http-error-codes-reference.md) (**1387** tks) - Reference for HTTP error codes returned by the Claude API with common causes and handling strategies.
- [Data: Live documentation sources](./system-prompts/data-live-documentation-sources.md) (**2337** tks) - WebFetch URLs for fetching current Claude API and Agent SDK documentation from official sources.
- [Data: Message Batches API reference — Python](./system-prompts/data-message-batches-api-reference-python.md) (**1505** tks) - Python Batches API reference including batch creation, status polling, and result retrieval at 50% cost.
- [Data: Session memory template](./system-prompts/data-session-memory-template.md) (**292** tks) - Template structure for session memory `summary.md` files.
- [Data: Streaming reference — Python](./system-prompts/data-streaming-reference-python.md) (**1534** tks) - Python streaming reference including sync/async streaming and handling different content types.
- [Data: Streaming reference — TypeScript](./system-prompts/data-streaming-reference-typescript.md) (**1553** tks) - TypeScript streaming reference including basic streaming and handling different content types.
- [Data: Tool use concepts](./system-prompts/data-tool-use-concepts.md) (**3640** tks) - Conceptual foundations of tool use with the Claude API including tool definitions, tool choice, and best practices.
- [Data: Tool use reference — Python](./system-prompts/data-tool-use-reference-python.md) (**4180** tks) - Python tool use reference including tool runner, manual agentic loop, code execution, and structured outputs.
- [Data: Tool use reference — TypeScript](./system-prompts/data-tool-use-reference-typescript.md) (**3228** tks) - TypeScript tool use reference including tool runner, manual agentic loop, code execution, and structured outputs.

### System Prompt

Parts of the main system prompt.

- [System Prompt: Agent Summary Generation](./system-prompts/system-prompt-agent-summary-generation.md) (**178** tks) - System prompt used for "Agent Summary" generation..
- [System Prompt: Agent memory instructions](./system-prompts/system-prompt-agent-memory-instructions.md) (**337** tks) - Instructions for including memory update guidance in agent system prompts.
- [System Prompt: Censoring assistance with malicious activities](./system-prompts/system-prompt-censoring-assistance-with-malicious-activities.md) (**98** tks) - Guidelines for assisting with authorized security testing, defensive security, CTF challenges, and educational contexts while censoring requests for malicious activities.
- [System Prompt: Chrome browser MCP tools](./system-prompts/system-prompt-chrome-browser-mcp-tools.md) (**156** tks) - Instructions for loading Chrome browser MCP tools via MCPSearch before use.
- [System Prompt: Claude in Chrome browser automation](./system-prompts/system-prompt-claude-in-chrome-browser-automation.md) (**759** tks) - Instructions for using Claude in Chrome browser automation tools effectively.
- [System Prompt: Context compaction summary](./system-prompts/system-prompt-context-compaction-summary.md) (**278** tks) - Prompt used for context compaction summary (for the SDK).
- [System Prompt: Doing tasks (ambitious tasks)](./system-prompts/system-prompt-doing-tasks-ambitious-tasks.md) (**47** tks) - Allow users to complete ambitious tasks; defer to user judgement on scope.
- [System Prompt: Doing tasks (avoid over-engineering)](./system-prompts/system-prompt-doing-tasks-avoid-over-engineering.md) (**30** tks) - Only make changes that are directly requested or clearly necessary.
- [System Prompt: Doing tasks (blocked approach)](./system-prompts/system-prompt-doing-tasks-blocked-approach.md) (**90** tks) - Consider alternatives when blocked instead of brute-forcing.
- [System Prompt: Doing tasks (help and feedback)](./system-prompts/system-prompt-doing-tasks-help-and-feedback.md) (**24** tks) - How to inform users about help and feedback channels.
- [System Prompt: Doing tasks (minimize file creation)](./system-prompts/system-prompt-doing-tasks-minimize-file-creation.md) (**47** tks) - Prefer editing existing files over creating new ones.
- [System Prompt: Doing tasks (no compatibility hacks)](./system-prompts/system-prompt-doing-tasks-no-compatibility-hacks.md) (**52** tks) - Delete unused code completely rather than adding compatibility shims.
- [System Prompt: Doing tasks (no premature abstractions)](./system-prompts/system-prompt-doing-tasks-no-premature-abstractions.md) (**60** tks) - Do not create abstractions for one-time operations or hypothetical requirements.
- [System Prompt: Doing tasks (no time estimates)](./system-prompts/system-prompt-doing-tasks-no-time-estimates.md) (**47** tks) - Avoid giving time estimates or predictions.
- [System Prompt: Doing tasks (no unnecessary additions)](./system-prompts/system-prompt-doing-tasks-no-unnecessary-additions.md) (**78** tks) - Do not add features, refactor, or improve beyond what was asked.
- [System Prompt: Doing tasks (no unnecessary error handling)](./system-prompts/system-prompt-doing-tasks-no-unnecessary-error-handling.md) (**64** tks) - Do not add error handling for impossible scenarios; only validate at boundaries.
- [System Prompt: Doing tasks (read before modifying)](./system-prompts/system-prompt-doing-tasks-read-before-modifying.md) (**46** tks) - Read and understand existing code before suggesting modifications.
- [System Prompt: Doing tasks (security)](./system-prompts/system-prompt-doing-tasks-security.md) (**67** tks) - Avoid introducing security vulnerabilities like injection, XSS, etc..
- [System Prompt: Doing tasks (software engineering focus)](./system-prompts/system-prompt-doing-tasks-software-engineering-focus.md) (**104** tks) - Users primarily request software engineering tasks; interpret instructions in that context.
- [System Prompt: Executing actions with care](./system-prompts/system-prompt-executing-actions-with-care.md) (**541** tks) - Instructions for executing actions carefully..
- [System Prompt: Git status](./system-prompts/system-prompt-git-status.md) (**97** tks) - System prompt for displaying the current git status at the start of the conversation.
- [System Prompt: Hooks Configuration](./system-prompts/system-prompt-hooks-configuration.md) (**1461** tks) - System prompt for hooks configuration.  Used for above Claude Code config skill..
- [System Prompt: Insights at a glance summary](./system-prompts/system-prompt-insights-at-a-glance-summary.md) (**569** tks) - Generates a concise 4-part summary (what's working, hindrances, quick wins, ambitious workflows) for the insights report.
- [System Prompt: Insights friction analysis](./system-prompts/system-prompt-insights-friction-analysis.md) (**139** tks) - Analyzes aggregated usage data to identify friction patterns and categorize recurring issues.
- [System Prompt: Insights on the horizon](./system-prompts/system-prompt-insights-on-the-horizon.md) (**148** tks) - Identifies ambitious future workflows and opportunities for autonomous AI-assisted development.
- [System Prompt: Insights session facets extraction](./system-prompts/system-prompt-insights-session-facets-extraction.md) (**310** tks) - Extracts structured facets (goal categories, satisfaction, friction) from a single Claude Code session transcript.
- [System Prompt: Insights suggestions](./system-prompts/system-prompt-insights-suggestions.md) (**748** tks) - Generates actionable suggestions including CLAUDE.md additions, features to try, and usage patterns.
- [System Prompt: Learning mode (insights)](./system-prompts/system-prompt-learning-mode-insights.md) (**142** tks) - Instructions for providing educational insights when learning mode is active.
- [System Prompt: Learning mode](./system-prompts/system-prompt-learning-mode.md) (**1042** tks) - Main system prompt for learning mode with human collaboration instructions.
- [System Prompt: Option previewer](./system-prompts/system-prompt-option-previewer.md) (**129** tks) - System prompt for previewing UI options in a side-by-side layout.
- [System Prompt: Parallel tool call note (part of "Tool usage policy")](./system-prompts/system-prompt-parallel-tool-call-note-part-of-tool-usage-policy.md) (**102** tks) - System prompt for telling Claude to using parallel tool calls.
- [System Prompt: Scratchpad directory](./system-prompts/system-prompt-scratchpad-directory.md) (**170** tks) - Instructions for using a dedicated scratchpad directory for temporary files.
- [System Prompt: Skillify Current Session](./system-prompts/system-prompt-skillify-current-session.md) (**1882** tks) - System prompt for converting the current session in to a skill..
- [System Prompt: Teammate Communication](./system-prompts/system-prompt-teammate-communication.md) (**127** tks) - System prompt for teammate communication in swarm.
- [System Prompt: Tone and style (code references)](./system-prompts/system-prompt-tone-and-style-code-references.md) (**39** tks) - Instruction to include file_path:line_number when referencing code.
- [System Prompt: Tone and style (concise output — detailed)](./system-prompts/system-prompt-tone-and-style-concise-output-detailed.md) (**89** tks) - Instruction for concise, polished output without filler or inner monologue.
- [System Prompt: Tone and style (concise output — short)](./system-prompts/system-prompt-tone-and-style-concise-output-short.md) (**16** tks) - Instruction for short and concise responses.
- [System Prompt: Tool Use Summary Generation](./system-prompts/system-prompt-tool-use-summary-generation.md) (**171** tks) - Prompt for generating summaries of tool usage.
- [System Prompt: Tool execution denied](./system-prompts/system-prompt-tool-execution-denied.md) (**144** tks) - System prompt for when tool execution is denied.
- [System Prompt: Tool permission mode](./system-prompts/system-prompt-tool-permission-mode.md) (**155** tks) - Guidance on tool permission modes and handling denied tool calls.
- [System Prompt: Tool usage (create files)](./system-prompts/system-prompt-tool-usage-create-files.md) (**30** tks) - Prefer Write tool instead of cat heredoc or echo redirection.
- [System Prompt: Tool usage (delegate exploration)](./system-prompts/system-prompt-tool-usage-delegate-exploration.md) (**114** tks) - Use Task tool for broader codebase exploration and deep research.
- [System Prompt: Tool usage (direct search)](./system-prompts/system-prompt-tool-usage-direct-search.md) (**52** tks) - Use Glob/Grep directly for simple, directed searches.
- [System Prompt: Tool usage (edit files)](./system-prompts/system-prompt-tool-usage-edit-files.md) (**26** tks) - Prefer Edit tool instead of sed/awk.
- [System Prompt: Tool usage (read files)](./system-prompts/system-prompt-tool-usage-read-files.md) (**29** tks) - Prefer Read tool instead of cat/head/tail/sed.
- [System Prompt: Tool usage (reserve Bash)](./system-prompts/system-prompt-tool-usage-reserve-bash.md) (**75** tks) - Reserve Bash tool exclusively for system commands and terminal operations.
- [System Prompt: Tool usage (search content)](./system-prompts/system-prompt-tool-usage-search-content.md) (**30** tks) - Prefer Grep tool instead of grep or rg.
- [System Prompt: Tool usage (search files)](./system-prompts/system-prompt-tool-usage-search-files.md) (**26** tks) - Prefer Glob tool instead of find or ls.
- [System Prompt: Tool usage (skill invocation)](./system-prompts/system-prompt-tool-usage-skill-invocation.md) (**102** tks) - Slash commands invoke user-invocable skills via Skill tool.
- [System Prompt: Tool usage (subagent guidance)](./system-prompts/system-prompt-tool-usage-subagent-guidance.md) (**103** tks) - Guidance on when and how to use subagents effectively.
- [System Prompt: Tool usage (task management)](./system-prompts/system-prompt-tool-usage-task-management.md) (**73** tks) - Use TodoWrite to break down and track work progress.

### System Reminders

Text for large system reminders.

- [System Reminder: /btw side question](./system-prompts/system-reminder-btw-side-question.md) (**172** tks) - System reminder for /btw slash command side questions without tools.
- [System Reminder: Agent mention](./system-prompts/system-reminder-agent-mention.md) (**45** tks) - Notification that user wants to invoke an agent.
- [System Reminder: Compact file reference](./system-prompts/system-reminder-compact-file-reference.md) (**57** tks) - Reference to file read before conversation summarization.
- [System Reminder: Exited plan mode](./system-prompts/system-reminder-exited-plan-mode.md) (**73** tks) - Notification when exiting plan mode.
- [System Reminder: File exists but empty](./system-prompts/system-reminder-file-exists-but-empty.md) (**27** tks) - Warning when reading an empty file.
- [System Reminder: File modified by user or linter](./system-prompts/system-reminder-file-modified-by-user-or-linter.md) (**97** tks) - Notification that a file was modified externally.
- [System Reminder: File opened in IDE](./system-prompts/system-reminder-file-opened-in-ide.md) (**37** tks) - Notification that user opened a file in IDE.
- [System Reminder: File shorter than offset](./system-prompts/system-reminder-file-shorter-than-offset.md) (**59** tks) - Warning when file read offset exceeds file length.
- [System Reminder: File truncated](./system-prompts/system-reminder-file-truncated.md) (**74** tks) - Notification that file was truncated due to size.
- [System Reminder: Hook additional context](./system-prompts/system-reminder-hook-additional-context.md) (**35** tks) - Additional context from a hook.
- [System Reminder: Hook blocking error](./system-prompts/system-reminder-hook-blocking-error.md) (**52** tks) - Error from a blocking hook command.
- [System Reminder: Hook stopped continuation prefix](./system-prompts/system-reminder-hook-stopped-continuation-prefix.md) (**12** tks) - Prefix for hook stopped continuation messages.
- [System Reminder: Hook stopped continuation](./system-prompts/system-reminder-hook-stopped-continuation.md) (**30** tks) - Message when a hook stops continuation.
- [System Reminder: Hook success](./system-prompts/system-reminder-hook-success.md) (**29** tks) - Success message from a hook.
- [System Reminder: Invoked skills](./system-prompts/system-reminder-invoked-skills.md) (**33** tks) - List of skills invoked in this session.
- [System Reminder: Lines selected in IDE](./system-prompts/system-reminder-lines-selected-in-ide.md) (**66** tks) - Notification about lines selected by user in IDE.
- [System Reminder: MCP resource no content](./system-prompts/system-reminder-mcp-resource-no-content.md) (**41** tks) - Shown when MCP resource has no content.
- [System Reminder: MCP resource no displayable content](./system-prompts/system-reminder-mcp-resource-no-displayable-content.md) (**43** tks) - Shown when MCP resource has no displayable content.
- [System Reminder: Malware analysis after Read tool call](./system-prompts/system-reminder-malware-analysis-after-read-tool-call.md) (**87** tks) - Instructions for analyzing malware without improving or augmenting it.
- [System Reminder: Memory file contents](./system-prompts/system-reminder-memory-file-contents.md) (**38** tks) - Contents of a memory file by path.
- [System Reminder: Nested memory contents](./system-prompts/system-reminder-nested-memory-contents.md) (**33** tks) - Contents of a nested memory file.
- [System Reminder: New diagnostics detected](./system-prompts/system-reminder-new-diagnostics-detected.md) (**35** tks) - Notification about new diagnostic issues.
- [System Reminder: Output style active](./system-prompts/system-reminder-output-style-active.md) (**32** tks) - Notification that an output style is active.
- [System Reminder: Output token limit exceeded](./system-prompts/system-reminder-output-token-limit-exceeded.md) (**35** tks) - Warning when response exceeds output token limit.
- [System Reminder: Plan file reference](./system-prompts/system-reminder-plan-file-reference.md) (**62** tks) - Reference to an existing plan file.
- [System Reminder: Plan mode is active (5-phase)](./system-prompts/system-reminder-plan-mode-is-active-5-phase.md) (**1511** tks) - Enhanced plan mode system reminder with parallel exploration and multi-agent planning.
- [System Reminder: Plan mode is active (iterative)](./system-prompts/system-reminder-plan-mode-is-active-iterative.md) (**797** tks) - Iterative plan mode system reminder for main agent with user interviewing workflow.
- [System Reminder: Plan mode is active (subagent)](./system-prompts/system-reminder-plan-mode-is-active-subagent.md) (**307** tks) - Simplified plan mode system reminder for sub agents.
- [System Reminder: Plan mode re-entry](./system-prompts/system-reminder-plan-mode-re-entry.md) (**236** tks) - System reminder sent when the user enters Plan mode after having previously exited it either via shift+tab or by approving Claude's plan..
- [System Reminder: Session continuation](./system-prompts/system-reminder-session-continuation.md) (**37** tks) - Notification that session continues from another machine.
- [System Reminder: Task status](./system-prompts/system-reminder-task-status.md) (**18** tks) - Task status with TaskOutput tool reference.
- [System Reminder: Task tools reminder](./system-prompts/system-reminder-task-tools-reminder.md) (**123** tks) - Reminder to use task tracking tools.
- [System Reminder: Team Coordination](./system-prompts/system-reminder-team-coordination.md) (**247** tks) - System reminder for team coordination.
- [System Reminder: Team Shutdown](./system-prompts/system-reminder-team-shutdown.md) (**136** tks) - System reminder for team shutdown.
- [System Reminder: Todo list changed](./system-prompts/system-reminder-todo-list-changed.md) (**61** tks) - Notification that todo list has changed.
- [System Reminder: Todo list empty](./system-prompts/system-reminder-todo-list-empty.md) (**83** tks) - Reminder that todo list is empty.
- [System Reminder: TodoWrite reminder](./system-prompts/system-reminder-todowrite-reminder.md) (**98** tks) - Reminder to use TodoWrite tool for task tracking.
- [System Reminder: Token usage](./system-prompts/system-reminder-token-usage.md) (**39** tks) - Current token usage statistics.
- [System Reminder: USD budget](./system-prompts/system-reminder-usd-budget.md) (**42** tks) - Current USD budget statistics.
- [System Reminder: Verify plan reminder](./system-prompts/system-reminder-verify-plan-reminder.md) (**47** tks) - Reminder to verify completed plan.

### Builtin Tool Descriptions

- [Tool Description: AskUserQuestion](./system-prompts/tool-description-askuserquestion.md) (**287** tks) - Tool description for asking user questions..
- [Tool Description: Computer](./system-prompts/tool-description-computer.md) (**161** tks) - Main description for the Chrome browser computer automation tool.
- [Tool Description: Edit](./system-prompts/tool-description-edit.md) (**246** tks) - Tool for performing exact string replacements in files.
- [Tool Description: EnterPlanMode](./system-prompts/tool-description-enterplanmode.md) (**878** tks) - Tool description for entering plan mode to explore and design implementation approaches.
- [Tool Description: EnterWorktree](./system-prompts/tool-description-enterworktree.md) (**334** tks) - Tool description for the EnterWorktree tool..
- [Tool Description: ExitPlanMode](./system-prompts/tool-description-exitplanmode.md) (**417** tks) - Description for the ExitPlanMode tool, which presents a plan dialog for the user to approve.
- [Tool Description: Glob](./system-prompts/tool-description-glob.md) (**122** tks) - Tool description for file pattern matching and searching by name.
- [Tool Description: Grep](./system-prompts/tool-description-grep.md) (**300** tks) - Tool description for content search using ripgrep.
- [Tool Description: LSP](./system-prompts/tool-description-lsp.md) (**255** tks) - Description for the LSP tool..
- [Tool Description: NotebookEdit](./system-prompts/tool-description-notebookedit.md) (**121** tks) - Tool description for editing Jupyter notebook cells.
- [Tool Description: ReadFile](./system-prompts/tool-description-readfile.md) (**469** tks) - Tool description for reading files.
- [Tool Description: SendMessageTool](./system-prompts/tool-description-sendmessagetool.md) (**1241** tks) - Tool for sending messages to teammates and handling protocol requests/responses in a swarm.
- [Tool Description: Skill](./system-prompts/tool-description-skill.md) (**326** tks) - Tool description for executing skills in the main conversation.
- [Tool Description: Sleep](./system-prompts/tool-description-sleep.md) (**154** tks) - Tool for waiting/sleeping with early wake capability on user input.
- [Tool Description: TaskCreate](./system-prompts/tool-description-taskcreate.md) (**558** tks) - Tool description for TaskCreate tool.
- [Tool Description: Task](./system-prompts/tool-description-task.md) (**1331** tks) - Tool description for launching specialized sub-agents to handle complex tasks.
- [Tool Description: TeamDelete](./system-prompts/tool-description-teamdelete.md) (**154** tks) - Tool description for the TeamDelete tool.
- [Tool Description: TeammateTool](./system-prompts/tool-description-teammatetool.md) (**1642** tks) - Tool for managing teams and coordinating teammates in a swarm.
- [Tool Description: TodoWrite](./system-prompts/tool-description-todowrite.md) (**2167** tks) - Tool description for creating and managing task lists.
- [Tool Description: ToolSearch extended](./system-prompts/tool-description-toolsearch-extended.md) (**690** tks) - Extended usage instructions for ToolSearch including query modes and examples.
- [Tool Description: ToolSearch](./system-prompts/tool-description-toolsearch.md) (**144** tks) - Tool description for loading and searching deferred tools before use.
- [Tool Description: WebFetch](./system-prompts/tool-description-webfetch.md) (**297** tks) - Tool description for web fetch functionality.
- [Tool Description: WebSearch](./system-prompts/tool-description-websearch.md) (**319** tks) - Tool description for web search functionality.
- [Tool Description: Write](./system-prompts/tool-description-write.md) (**129** tks) - Tool for writing files to the local filesystem.

**Additional notes for some Tool Desscriptions**

- [Tool Description: Bash (Git commit and PR creation instructions)](./system-prompts/tool-description-bash-git-commit-and-pr-creation-instructions.md) (**1558** tks) - Instructions for creating git commits and GitHub pull requests.
- [Tool Description: Bash (alternative — communication)](./system-prompts/tool-description-bash-alternative-communication.md) (**18** tks) - Bash tool alternative: output text directly instead of echo/printf.
- [Tool Description: Bash (alternative — content search)](./system-prompts/tool-description-bash-alternative-content-search.md) (**27** tks) - Bash tool alternative: use Grep for content search instead of grep/rg.
- [Tool Description: Bash (alternative — edit files)](./system-prompts/tool-description-bash-alternative-edit-files.md) (**27** tks) - Bash tool alternative: use Edit for file editing instead of sed/awk.
- [Tool Description: Bash (alternative — file search)](./system-prompts/tool-description-bash-alternative-file-search.md) (**26** tks) - Bash tool alternative: use Glob for file search instead of find/ls.
- [Tool Description: Bash (alternative — read files)](./system-prompts/tool-description-bash-alternative-read-files.md) (**27** tks) - Bash tool alternative: use Read for file reading instead of cat/head/tail.
- [Tool Description: Bash (alternative — write files)](./system-prompts/tool-description-bash-alternative-write-files.md) (**29** tks) - Bash tool alternative: use Write for file writing instead of echo/cat.
- [Tool Description: Bash (built-in tools note)](./system-prompts/tool-description-bash-built-in-tools-note.md) (**53** tks) - Note that built-in tools provide better UX than Bash equivalents.
- [Tool Description: Bash (command description)](./system-prompts/tool-description-bash-command-description.md) (**71** tks) - Bash tool instruction: write clear command descriptions.
- [Tool Description: Bash (git — avoid destructive ops)](./system-prompts/tool-description-bash-git-avoid-destructive-ops.md) (**58** tks) - Bash tool git instruction: consider safer alternatives to destructive operations.
- [Tool Description: Bash (git — never skip hooks)](./system-prompts/tool-description-bash-git-never-skip-hooks.md) (**59** tks) - Bash tool git instruction: never skip hooks or bypass signing unless user requests it.
- [Tool Description: Bash (git — prefer new commits)](./system-prompts/tool-description-bash-git-prefer-new-commits.md) (**22** tks) - Bash tool git instruction: prefer new commits over amending.
- [Tool Description: Bash (maintain cwd)](./system-prompts/tool-description-bash-maintain-cwd.md) (**41** tks) - Bash tool instruction: use absolute paths and avoid cd.
- [Tool Description: Bash (no newlines)](./system-prompts/tool-description-bash-no-newlines.md) (**24** tks) - Bash tool instruction: do not use newlines to separate commands.
- [Tool Description: Bash (overview)](./system-prompts/tool-description-bash-overview.md) (**19** tks) - Opening line of the Bash tool description.
- [Tool Description: Bash (parallel commands)](./system-prompts/tool-description-bash-parallel-commands.md) (**72** tks) - Bash tool instruction: run independent commands as parallel tool calls.
- [Tool Description: Bash (prefer dedicated tools)](./system-prompts/tool-description-bash-prefer-dedicated-tools.md) (**82** tks) - Warning to prefer dedicated tools over Bash for find, grep, cat, etc..
- [Tool Description: Bash (quote file paths)](./system-prompts/tool-description-bash-quote-file-paths.md) (**35** tks) - Bash tool instruction: quote file paths containing spaces.
- [Tool Description: Bash (sandbox — adjust settings)](./system-prompts/tool-description-bash-sandbox-adjust-settings.md) (**26** tks) - Work with user to adjust sandbox settings on failure.
- [Tool Description: Bash (sandbox — default to sandbox)](./system-prompts/tool-description-bash-sandbox-default-to-sandbox.md) (**38** tks) - Default to sandbox; only bypass when user asks or evidence of sandbox restriction.
- [Tool Description: Bash (sandbox — evidence list header)](./system-prompts/tool-description-bash-sandbox-evidence-list-header.md) (**15** tks) - Header for list of sandbox-caused failure evidence.
- [Tool Description: Bash (sandbox — evidence: access denied)](./system-prompts/tool-description-bash-sandbox-evidence-access-denied.md) (**15** tks) - Sandbox evidence: access denied to paths outside allowed directories.
- [Tool Description: Bash (sandbox — evidence: network failures)](./system-prompts/tool-description-bash-sandbox-evidence-network-failures.md) (**17** tks) - Sandbox evidence: network connection failures to non-whitelisted hosts.
- [Tool Description: Bash (sandbox — evidence: operation not permitted)](./system-prompts/tool-description-bash-sandbox-evidence-operation-not-permitted.md) (**18** tks) - Sandbox evidence: operation not permitted errors.
- [Tool Description: Bash (sandbox — evidence: unix socket errors)](./system-prompts/tool-description-bash-sandbox-evidence-unix-socket-errors.md) (**11** tks) - Sandbox evidence: unix socket connection errors.
- [Tool Description: Bash (sandbox — explain restriction)](./system-prompts/tool-description-bash-sandbox-explain-restriction.md) (**36** tks) - Explain which sandbox restriction caused the failure.
- [Tool Description: Bash (sandbox — failure evidence condition)](./system-prompts/tool-description-bash-sandbox-failure-evidence-condition.md) (**48** tks) - Condition: command failed with evidence of sandbox restrictions.
- [Tool Description: Bash (sandbox — mandatory mode)](./system-prompts/tool-description-bash-sandbox-mandatory-mode.md) (**34** tks) - Policy: all commands must run in sandbox mode.
- [Tool Description: Bash (sandbox — no exceptions)](./system-prompts/tool-description-bash-sandbox-no-exceptions.md) (**17** tks) - Commands cannot run outside sandbox under any circumstances.
- [Tool Description: Bash (sandbox — no sensitive paths)](./system-prompts/tool-description-bash-sandbox-no-sensitive-paths.md) (**36** tks) - Do not suggest adding sensitive paths to sandbox allowlist.
- [Tool Description: Bash (sandbox — per-command)](./system-prompts/tool-description-bash-sandbox-per-command.md) (**52** tks) - Treat each command individually; default to sandbox for future commands.
- [Tool Description: Bash (sandbox — response header)](./system-prompts/tool-description-bash-sandbox-response-header.md) (**17** tks) - Header for how to respond when seeing sandbox-caused failures.
- [Tool Description: Bash (sandbox — retry without sandbox)](./system-prompts/tool-description-bash-sandbox-retry-without-sandbox.md) (**33** tks) - Immediately retry with dangerouslyDisableSandbox on sandbox failure.
- [Tool Description: Bash (sandbox — tmpdir)](./system-prompts/tool-description-bash-sandbox-tmpdir.md) (**102** tks) - Use $TMPDIR for temporary files in sandbox mode.
- [Tool Description: Bash (sandbox — user permission prompt)](./system-prompts/tool-description-bash-sandbox-user-permission-prompt.md) (**14** tks) - Note that disabling sandbox will prompt user for permission.
- [Tool Description: Bash (semicolon usage)](./system-prompts/tool-description-bash-semicolon-usage.md) (**29** tks) - Bash tool instruction: use semicolons when sequential order matters but failure does not.
- [Tool Description: Bash (sequential commands)](./system-prompts/tool-description-bash-sequential-commands.md) (**42** tks) - Bash tool instruction: chain dependent commands with &&.
- [Tool Description: Bash (sleep — keep short)](./system-prompts/tool-description-bash-sleep-keep-short.md) (**29** tks) - Bash tool instruction: keep sleep duration to 1-5 seconds.
- [Tool Description: Bash (sleep — no polling background tasks)](./system-prompts/tool-description-bash-sleep-no-polling-background-tasks.md) (**37** tks) - Bash tool instruction: do not poll background tasks, wait for notification.
- [Tool Description: Bash (sleep — no retry loops)](./system-prompts/tool-description-bash-sleep-no-retry-loops.md) (**28** tks) - Bash tool instruction: diagnose failures instead of retrying in sleep loops.
- [Tool Description: Bash (sleep — run immediately)](./system-prompts/tool-description-bash-sleep-run-immediately.md) (**21** tks) - Bash tool instruction: do not sleep between commands that can run immediately.
- [Tool Description: Bash (sleep — use check commands)](./system-prompts/tool-description-bash-sleep-use-check-commands.md) (**34** tks) - Bash tool instruction: use check commands rather than sleeping when polling.
- [Tool Description: Bash (sleep — use run_in_background)](./system-prompts/tool-description-bash-sleep-use-run_in_background.md) (**48** tks) - Bash tool instruction: use run_in_background for long-running commands.
- [Tool Description: Bash (timeout)](./system-prompts/tool-description-bash-timeout.md) (**75** tks) - Bash tool instruction: optional timeout configuration.
- [Tool Description: Bash (verify parent directory)](./system-prompts/tool-description-bash-verify-parent-directory.md) (**38** tks) - Bash tool instruction: verify parent directory before creating files.
- [Tool Description: Bash (working directory)](./system-prompts/tool-description-bash-working-directory.md) (**37** tks) - Bash tool note about working directory persistence and shell state.
- [Tool Description: TaskList (teammate workflow)](./system-prompts/tool-description-tasklist-teammate-workflow.md) (**133** tks) - Conditional section appended to TaskList tool description.
