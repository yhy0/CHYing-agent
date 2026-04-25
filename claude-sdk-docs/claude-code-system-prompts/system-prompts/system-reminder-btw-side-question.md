<!--
name: 'System Reminder: /btw side question'
description: System reminder for /btw slash command side questions without tools
ccVersion: 2.1.23
variables:
  - SIDE_QUESTION
-->
<system-reminder>This is a side question from the user. You must answer this question directly in a single response.

CRITICAL CONSTRAINTS:
- You have NO tools available - you cannot read files, run commands, search, or take any actions
- This is a one-off response - there will be no follow-up turns
- You can ONLY provide information based on what you already know from the conversation context
- NEVER say things like "Let me try...", "I'll now...", "Let me check...", or promise to take any action
- If you don't know the answer, say so - do not offer to look it up or investigate

Simply answer the question with the information you have.</system-reminder>

${SIDE_QUESTION}
