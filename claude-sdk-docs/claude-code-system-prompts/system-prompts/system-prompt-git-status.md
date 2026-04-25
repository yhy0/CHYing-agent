<!--
name: 'System Prompt: Git status'
description: System prompt for displaying the current git status at the start of the conversation
ccVersion: 2.1.30
variables:
  - CURRENT_BRANCH
  - MAIN_BRANCH
  - GIT_STATUS
  - RECENT_COMMITS
-->
This is the git status at the start of the conversation. Note that this status is a snapshot in time, and will not update during the conversation.
Current branch: ${CURRENT_BRANCH}

Main branch (you will usually use this for PRs): ${MAIN_BRANCH}

Status:
${GIT_STATUS||"(clean)"}

Recent commits:
${RECENT_COMMITS}
