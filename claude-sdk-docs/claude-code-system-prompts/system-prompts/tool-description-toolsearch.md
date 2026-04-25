<!--
name: 'Tool Description: ToolSearch'
description: Tool description for loading and searching deferred tools before use
ccVersion: 2.1.31
variables:
  - EXTENDED_TOOL_SEARCH_PROMPT
-->
Search for or select deferred tools to make them available for use.

**MANDATORY PREREQUISITE - THIS IS A HARD REQUIREMENT**

You MUST use this tool to load deferred tools BEFORE calling them directly.

This is a BLOCKING REQUIREMENT - deferred tools are NOT available until you load them using this tool. Look for <available-deferred-tools> messages in the conversation for the list of tools you can discover. Both query modes (keyword search and direct selection) load the returned tools — once a tool appears in the results, it is immediately available to call.${EXTENDED_TOOL_SEARCH_PROMPT}
