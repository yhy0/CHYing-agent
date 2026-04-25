<!--
name: 'Skill: Build with Claude API (trigger)'
description: Activation criteria for the Build with Claude API skill, describing when to invoke it based on user requests
ccVersion: 2.1.51
-->
Build applications that call the Claude API or Anthropic SDK. Use ONLY when the code actually uses or will use the `anthropic` SDK package or Claude API endpoints.
TRIGGER when:
- Code imports `anthropic` or `@anthropic-ai/sdk` (the Anthropic SDK)
- Code imports `claude_agent_sdk` or `@anthropic-ai/claude-agent-sdk` (the Agent SDK)
- User explicitly asks to use Claude, the Anthropic API, or Anthropic SDK
- User needs an AI/LLM and no other provider's SDK is already in use
DO NOT TRIGGER when (use another skill instead):
- Code imports `openai`, `google.generativeai`, or any non-Anthropic AI SDK
