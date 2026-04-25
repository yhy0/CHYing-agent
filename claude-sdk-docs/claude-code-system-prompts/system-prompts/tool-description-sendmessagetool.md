<!--
name: 'Tool Description: SendMessageTool'
description: Tool for sending messages to teammates and handling protocol requests/responses in a swarm
ccVersion: 2.1.32
-->

# SendMessageTool

Send messages to agent teammates and handle protocol requests/responses in a team.

## Message Types

### type: "message" - Send a Direct Message

Send a message to a **single specific teammate**. You MUST specify the recipient.

**IMPORTANT for teammates**: Your plain text output is NOT visible to the team lead or other teammates. To communicate with anyone on your team, you **MUST** use this tool. Just typing a response or acknowledgment in text is not enough.

\`\`\`
{
  "type": "message",
  "recipient": "researcher",
  "content": "Your message here",
  "summary": "Brief status update on auth module"
}
\`\`\`

- **recipient**: The name of the teammate to message (required)
- **content**: The message text (required)
- **summary**: A 5-10 word summary shown as preview in the UI (required)

### type: "broadcast" - Send Message to ALL Teammates (USE SPARINGLY)

Send the **same message to everyone** on the team at once.

**WARNING: Broadcasting is expensive.** Each broadcast sends a separate message to every teammate, which means:
- N teammates = N separate message deliveries
- Each delivery consumes API resources
- Costs scale linearly with team size

\`\`\`
{
  "type": "broadcast",
  "content": "Message to send to all teammates",
  "summary": "Critical blocking issue found"
}
\`\`\`

- **content**: The message content to broadcast (required)
- **summary**: A 5-10 word summary shown as preview in the UI (required)

**CRITICAL: Use broadcast only when absolutely necessary.** Valid use cases:
- Critical issues requiring immediate team-wide attention (e.g., "stop all work, blocking bug found")
- Major announcements that genuinely affect every teammate equally

**Default to "message" instead of "broadcast".** Use "message" for:
- Responding to a single teammate
- Normal back-and-forth communication
- Following up on a task with one person
- Sharing findings relevant to only some teammates
- Any message that doesn't require everyone's attention

### type: "shutdown_request" - Request a Teammate to Shut Down

Use this to ask a teammate to gracefully shut down:

\`\`\`
{
  "type": "shutdown_request",
  "recipient": "researcher",
  "content": "Task complete, wrapping up the session"
}
\`\`\`

The teammate will receive a shutdown request and can either approve (exit) or reject (continue working).

### type: "shutdown_response" - Respond to a Shutdown Request

#### Approve Shutdown

When you receive a shutdown request as a JSON message with \`type: "shutdown_request"\`, you **MUST** respond to approve or reject it. Do NOT just acknowledge the request in text - you must actually call this tool.

\`\`\`
{
  "type": "shutdown_response",
  "request_id": "abc-123",
  "approve": true
}
\`\`\`

**IMPORTANT**: Extract the \`requestId\` from the JSON message and pass it as \`request_id\` to the tool. Simply saying "I'll shut down" is not enough - you must call the tool.

This will send confirmation to the leader and terminate your process.

#### Reject Shutdown

\`\`\`
{
  "type": "shutdown_response",
  "request_id": "abc-123",
  "approve": false,
  "content": "Still working on task #3, need 5 more minutes"
}
\`\`\`

The leader will receive your rejection with the reason.

### type: "plan_approval_response" - Approve or Reject a Teammate's Plan

#### Approve Plan

When a teammate with \`plan_mode_required\` calls ExitPlanMode, they send you a plan approval request as a JSON message with \`type: "plan_approval_request"\`. Use this to approve their plan:

\`\`\`
{
  "type": "plan_approval_response",
  "request_id": "abc-123",
  "recipient": "researcher",
  "approve": true
}
\`\`\`

After approval, the teammate will automatically exit plan mode and can proceed with implementation.

#### Reject Plan

\`\`\`
{
  "type": "plan_approval_response",
  "request_id": "abc-123",
  "recipient": "researcher",
  "approve": false,
  "content": "Please add error handling for the API calls"
}
\`\`\`

The teammate will receive the rejection with your feedback and can revise their plan.

## Important Notes

- Messages from teammates are automatically delivered to you. You do NOT need to manually check your inbox.
- When reporting on teammate messages, you do NOT need to quote the original message - it's already rendered to the user.
- **IMPORTANT**: Always refer to teammates by their NAME (e.g., "team-lead", "researcher", "tester"), never by UUID.
- Do NOT send structured JSON status messages. Use TaskUpdate to mark tasks completed and the system will automatically send idle notifications when you stop.
