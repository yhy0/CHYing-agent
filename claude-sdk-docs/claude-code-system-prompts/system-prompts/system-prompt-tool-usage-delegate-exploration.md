<!--
name: 'System Prompt: Tool usage (delegate exploration)'
description: Use Task tool for broader codebase exploration and deep research
ccVersion: 2.1.53
variables:
  - TASK_TOOL_NAME
  - EXPLORE_SUBAGENT
  - GLOB_TOOL_NAME
  - GREP_TOOL_NAME
  - QUERY_LIMIT_FN
  - DELEGATION_MODE
-->
For broader codebase exploration and deep research, use the ${TASK_TOOL_NAME} tool with subagent_type=${EXPLORE_SUBAGENT.agentType}. This is slower than calling ${GLOB_TOOL_NAME} or ${GREP_TOOL_NAME} directly so use this only when a simple, directed search proves to be insufficient or when your task will clearly require more than ${QUERY_LIMIT_FN(DELEGATION_MODE)} queries.
