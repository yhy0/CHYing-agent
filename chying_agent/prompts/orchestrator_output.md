<output_format>
Return structured JSON with these fields:

{
  "solved": boolean,           // Challenge solved? Only true when FLAG confirmed
  "flag": string | null,       // FLAG if found, null otherwise
  "summary": string,           // Brief progress summary
  "evidence": string[],        // Key findings/evidence (concise but informative)
  "next_steps": string[],      // Recommended next actions (include agent type, e.g. "executor: enumerate databases")
  "confidence": number,        // 0.0-1.0 confidence in current approach
  "artifacts": [               // Optional: files created during execution
    {"path": string, "description": string}
  ],
  "blocked_reason": string | null,  // REQUIRED when solved=false. Format: "<category>: <observation>. Tried: <list>. Next suggestion: <direction>"
  "recon_complete": boolean,   // Optional: set true after thorough recon with 2+ attack vectors found
  "attack_vectors": [          // Optional: list attack vectors when recon_complete=true
    {"name": string, "description": string, "priority": "high"|"medium"|"low"}
  ]
}

Guidelines:
- solved=true ONLY when FLAG regex matches and is confirmed
- **MULTI-FLAG CHALLENGES**: When the prompt contains "本题得分点进度: X/Y" with Y > 1, this challenge has multiple scoring flags.
  - Set solved=true after finding EACH flag (the runtime will detect remaining flags and continue the session automatically).
  - NEVER close, restart, or destroy the target instance after finding only one flag in a multi-flag challenge.
  - Keep the instance alive and continue exploiting to find all Y flags.
  - Include each newly found flag in the "flag" field immediately; do not wait until all flags are found.
- confidence: 0.0 = no clue, 0.5 = promising lead, 0.8 = likely path found, 1.0 = confirmed
- blocked_reason: **MANDATORY when solved=false** — describe the dead end, all attempted approaches, and specific next suggestion so retry can avoid them and pick up from here. Format: "<category>: <concrete observation>. Tried: <list of specific methods>. Next suggestion: <unexplored direction>". Example: "auth_bypass_failed: /api/login always returns 403, tried SQLi/JWT forgery/default creds. Next suggestion: inspect JS source for token generation logic"
- recon_complete: set true only when you have enumerated all services and found 2+ distinct attack vectors
</output_format>
