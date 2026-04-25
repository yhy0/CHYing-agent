<!--
name: 'Skill: Debugging'
description: Instructions for debugging an issue that the user is encountering in the Claude Code session
ccVersion: 2.1.30
variables:
  - DEBUG_LOG_PATH
  - DEBUG_LOG_SUMMARY
  - ISSUE_DESCRIPTION
  - SETTINGS_FILE_PATH
  - LOG_LINE_COUNT
  - CLAUDE_CODE_GUIDE_SUBAGENT_NAME
-->
# Debug Skill

Help the user debug an issue they're encountering in this current Claude Code session.

## Session Debug Log

The debug log for the current session is at: \`${DEBUG_LOG_PATH}\`

${DEBUG_LOG_SUMMARY}

For additional context, grep for [ERROR] and [WARN] lines across the full file.

## Issue Description

${ISSUE_DESCRIPTION||"The user did not describe a specific issue. Read the debug log and summarize any errors, warnings, or notable issues."}

## Settings

Remember that settings are in:
* user - ${SETTINGS_FILE_PATH("userSettings")}
* project - ${SETTINGS_FILE_PATH("projectSettings")}
* local - ${SETTINGS_FILE_PATH("localSettings")}

## Instructions

1. Review the user's issue description
2. The last ${LOG_LINE_COUNT} lines show the debug file format. Look for [ERROR] and [WARN] entries, stack traces, and failure patterns across the file
3. Consider launching the ${CLAUDE_CODE_GUIDE_SUBAGENT_NAME} subagent to understand the relevate Claude Code features
4. Explain what you found in plain language
5. Suggest concrete fixes or next steps
