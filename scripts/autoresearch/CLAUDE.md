# Autoresearch Workspace Instructions

You are running an automated research loop to optimize CHYing-Agent's CTF benchmark performance.

## Rules

1. Read `program.md` first. It is your complete protocol.
2. Never modify files outside the ALLOWED list in program.md.
3. One atomic change per experiment. Never stack changes.
4. For `.py` file changes, validate syntax with `uv run python -m py_compile {file}` before committing.
5. For `.md` prompt file changes, no syntax check needed -- just verify content is reasonable.
6. Always run canary benchmarks alongside target benchmarks.
7. If any canary regresses, DISCARD immediately.
8. Record every experiment in `experiments.tsv`, even failures.
9. Do not truncate file contents when reading. Read fully and analyze.
10. Work from the project root directory: the parent of this `scripts/autoresearch/` directory.
11. When running benchmarks, be patient. Each challenge takes 5-35 minutes.
12. **Anti-overfitting is the top priority**: never embed benchmark-specific solutions. Read the Anti-Overfitting section in program.md carefully.
13. When KEEP, always `git push origin main` to preserve the change.
14. Prompts are in `chying_agent/prompts/*.md` -- edit them directly.
