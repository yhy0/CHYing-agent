# Autoresearch Program: CHYing-Agent Benchmark Optimization

## Overview

This is a research protocol for automatically diagnosing and optimizing CHYing-Agent's CTF benchmark performance. You (Claude CLI) will execute this protocol autonomously using Bash, Read, Edit, Write, Grep, and Glob tools.

Current baseline: glm-5 model, 53.8% pass rate on XBOW 104-challenge benchmark.

---

## CRITICAL: Anti-Overfitting Rule

This is the most important constraint in the entire protocol. Violations invalidate the experiment.

**The goal is to improve the agent's GENERAL penetration testing ability, not to embed solutions for specific benchmarks.**

### What is forbidden

Any prompt/code change that contains or encodes information specific to individual benchmark challenges:

- Benchmark IDs (XBEN-xxx-xx)
- Specific flags, flag formats, or flag locations for known challenges
- Specific ports, URLs, paths, filenames, or credentials from benchmark challenges
- Specific payloads that only work for a particular benchmark (e.g., "when port is 8080, try {{config.__class__}}")
- Conditional logic keyed to benchmark-specific traits ("if the app has a /trade endpoint...")
- Any information that would only help if you already knew the answer

### What is allowed

Generic improvements to penetration testing methodology:

- "When encountering template rendering, test for SSTI using common probes: {{7*7}}, ${7*7}, #{7*7}, etc."
- "After finding an IDOR, always check if other HTTP methods (PUT, DELETE, PATCH) expose additional functionality"
- "When SQL injection is suspected, try both error-based and blind techniques before giving up"
- "Prioritize reconnaissance: enumerate all endpoints before focusing on a single attack vector"
- Adjusting reflection thresholds based on observed patterns (e.g., "looping detection triggers too late")
- Tuning guidance loop confidence thresholds based on observed decision quality
- Adjusting tool output limits or sub-agent resource budgets

### Self-check before committing

Before every `git commit`, verify:

1. **Blindfold test**: Would this change still make sense if applied to a completely different set of 104 CTF challenges? If the change only helps because you know which specific challenges are in the benchmark, it is overfitting.
2. **No benchmark fingerprints**: `grep -rn "XBEN\|xben" chying_agent/` must return nothing new. No benchmark IDs anywhere in the change.
3. **No specific solutions**: The change must describe a CATEGORY of technique, not a specific exploit for a known target.
4. **Transferability**: A human pentester reading the change should think "this is good general advice" not "this seems tailored to a specific challenge."

### Diagnosis vs. Optimization boundary

In Phase A (diagnosis), you WILL read challenge-specific details -- that is necessary to understand failure patterns. But in Phase B (optimization), the knowledge must be ABSTRACTED:

```
Phase A (allowed): "XBEN-042 failed because agent didn't try SSTI despite seeing Jinja2 template syntax"
Phase A (allowed): "5 challenges with tag 'ssti' all failed; agent never tested template injection"

Phase B (FORBIDDEN): Add "try {{config.__class__.__init__.__globals__}}" to prompt
Phase B (ALLOWED):  Add "when HTML output reflects user input with template-like syntax, always test SSTI with polyglot probes"
```

The abstraction level must be: **vulnerability class + generic detection heuristic**, never **specific exploit for a known target**.

---

## Prompt Architecture

Prompts are stored as `.md` files in `chying_agent/prompts/`, loaded at runtime by `load_prompt()`.

| File | Used by | Content |
|------|---------|---------|
| `orchestrator_identity.md` | `brain_agent/prompts.py` | Orchestrator role identity |
| `orchestrator_strategy.md` | `brain_agent/prompts.py` | Tool selection strategy |
| `orchestrator_constraints.md` | `brain_agent/prompts.py` | Behavioral rules and constraints |
| `orchestrator_output.md` | `brain_agent/prompts.py` | Output JSON schema |
| `prompt_compiler.md` | `brain_agent/prompt_compiler_meta.py` | PromptCompiler system prompt |
| `executor.md` | `agents/executor_agent.py` | Executor sub-agent prompt |
| `browser.md` | `agents/browser_agent.py` | Browser sub-agent prompt |
| `c2.md` | `agents/c2_agent.py` | C2 sub-agent prompt |
| `reverse.md` | `agents/reverse_agent.py` | Reverse engineering sub-agent prompt |
| `scene.md` | `agents/scene_agent.py` | Scene manager prompt |
| `scraper.md` | `agents/scraper_agent.py` | Scraper prompt |
| `writeup.md` | `agents/writeup_agent.py` | Writeup generator prompt |
| `flag_submitter.md` | `agents/flag_submitter_agent.py` | Flag submission prompt |

Editing `.md` files directly -- no Python syntax to worry about.

---

## Phase A: Diagnosis

Goal: Analyze all failed benchmarks to identify root causes and common failure patterns.

### Step A1: Load benchmark state

```
Read benchmark/glm-5-state.json
```

Parse results. Build two lists:
- **PASSED**: benchmarks with `"success": true`
- **FAILED**: benchmarks with `"success": false`

Print summary: total / passed / failed / timeout / error counts, per-level and per-tag breakdown.

### Step A2: Analyze each failed benchmark

For each failed benchmark ID (e.g. `XBEN-001-24`):

1. Find its archived work directory:
   ```bash
   ls agent-work/ctf/Web/ | grep -i "XBEN-001-24" | head -5
   ```
   The pattern is `{challenge_code}__{benchmark_id}__{timestamp}`.

2. In the archive directory, read these files (if they exist):
   - `progress.md` -- agent's progress log
   - `findings.log` -- key findings recorded via `record_key_finding`
   - `dumps/reflection_history.md` -- reflection reports triggered during the run

3. From the benchmark state entry, note: `status`, `duration_seconds`, `cost_usd`, `error_message`, `found_flag`.

4. Classify the root cause into one or more tags:
   - `wrong_approach` -- agent chose an incorrect attack vector and never pivoted
   - `missing_knowledge` -- agent lacked domain knowledge (specific vuln type, protocol, etc.)
   - `timeout` -- ran out of time; was making progress but too slow
   - `looping` -- got stuck in a loop repeating the same action
   - `tool_limitation` -- tools couldn't perform needed action (e.g., browser interaction, file upload)
   - `prompt_gap` -- system prompt didn't guide agent toward the right strategy
   - `recon_insufficient` -- agent didn't gather enough info before attacking
   - `flag_extraction_failure` -- found the vuln but failed to extract the flag
   - `docker_error` -- infrastructure/container issue, not agent's fault
   - `reflection_too_late` -- reflection triggered but too late to recover
   - `reflection_too_early` -- reflection interrupted productive exploration
   - `guidance_misjudged` -- guidance loop made wrong continuation/pivot decision
   - `subagent_budget_exceeded` -- sub-agent hit tool/time limit before completing task

5. Write a brief analysis (2-3 sentences) explaining the failure.

### Step A3: Find common patterns

Group failures by root cause tag. For each tag with 3+ failures:
- Count occurrences
- List affected benchmark IDs
- Identify the **generic capability gap** that caused the failures
- Propose a **generic improvement** (must pass the Anti-Overfitting self-check)
- Identify which optimization layer to target (see Optimization Layers below)

### Step A4: Generate diagnosis report

Write `scripts/autoresearch/diagnosis_report.md` with this structure:

```markdown
# Diagnosis Report
Generated: {timestamp}
Baseline: {pass_rate}% ({passed}/{total})

## Summary Statistics
- Per-level breakdown
- Per-tag breakdown
- Per-root-cause breakdown

## Root Cause Analysis (sorted by frequency)

### 1. {root_cause_tag} ({count} failures)
Affected: XBEN-xxx, XBEN-yyy, ...
Pattern: {description of GENERIC capability gap}
Proposed fix: {GENERIC improvement -- must pass Anti-Overfitting self-check}
Optimization layer: prompt / reflection_threshold / reflection_behavior / guidance_loop / tool_config / subagent_config
Target file: {file path}
Priority: HIGH/MEDIUM/LOW
Expected impact: {number of failures this could fix}
Overfitting risk: LOW/MEDIUM/HIGH (self-assessment)

### 2. ...

## Canary Set (5 benchmarks for regression detection)
Select 5 PASSED benchmarks covering different tags/levels. These must remain PASS after any change.
- XBEN-xxx (Level X, tag)
- ...

## Recommended Experiment Order
1. {highest priority fix}
2. {second priority fix}
...
```

### Phase A completion check

Before moving to Phase B, verify:
- [ ] `scripts/autoresearch/diagnosis_report.md` exists and is complete
- [ ] At least 3 actionable improvement hypotheses are listed
- [ ] Every hypothesis passes the Anti-Overfitting self-check
- [ ] Canary set of 5 PASSED benchmarks is defined
- [ ] Hypotheses are ordered by expected impact

---

## Optimization Layers

Beyond prompt content, the following parameters are available for tuning.

### Layer 1: Prompt content (.md files in `chying_agent/prompts/`)

Direct edit of `.md` files. No Python syntax concerns.

### Layer 2: Reflection thresholds (`chying_agent/claude_sdk/reflection.py`)

Constructor parameters (search for `__init__` in ReflectionTracker):
- `consecutive_failure_threshold` (default 5) -- consecutive tool errors before trigger
- `no_progress_threshold` (default 50) -- tool calls without positive findings before trigger
- `repetition_threshold` (default 8) -- same tool signature in sliding window before trigger
- `ineffective_threshold` (default 15) -- "Permission denied" etc. ops before trigger
- `max_reflections` (default 5) -- hard cap on total reflections
- `pattern_window_size` (default 12) -- sliding window for repetition detection
- `early_phase_immunity` (default 50) -- tool calls before any reflection triggers

### Layer 3: Reflection behavior (`chying_agent/claude_sdk/reflection.py`)

Beyond thresholds, these behavioral settings can be tuned:
- `_synthesis_interval` (default 25) -- periodic "combine findings" reminder frequency
- `_progress_interval` (default 40) -- periodic "update progress.md" reminder frequency
- `_skill_hint_interval` (default 50) -- periodic skill description injection frequency
- `_post_reflection_reminder_countdown` (default 5) -- post-reflection reminder duration
- `_POSITIVE_FINDING_KINDS` set -- what finding kinds fully reset stagnation counters
- `_PARTIAL_POSITIVE_KINDS` set -- what finding kinds partially reset counters
- Mid-value deduction table (search `deduction` in reflection.py) -- how much each finding type buys
- Soft warning half-reset ratio -- buffer window before HARD_REFLECT
- `_INEFFECTIVE_SIGNALS` list -- what output patterns count as "ineffective"

### Layer 4: Guidance loop (`chying_agent/claude_sdk/base.py`)

Constants near the top of the file:
- `MAX_GUIDANCE_ROUNDS` (default 5) -- total continuation rounds after initial run
- `SUBAGENT_MAX_DURATION_MS` (default 600000 / 10min) -- sub-agent time limit
- `SUBAGENT_MAX_TOOL_USES` (default 50) -- sub-agent tool call limit

Guidance decision thresholds (search `_build_guidance_query` and `_is_repeating_summary` in base.py):
- Confidence < 0.2 triggers pivot mode
- Confidence < 0.5 triggers "review findings" hint
- Similarity > 0.6 triggers repeat detection
- `is_repeating AND round_count >= 3` triggers session termination

### Layer 5: Tool configuration (`chying_agent/claude_sdk/mcp_tools.py`)

- `MAX_OUTPUT_LENGTH` (default 40000) -- tool output truncation threshold
- `docker_exec` default timeout (120s, max 600s)
- `python_poc_exec` default timeout (120s, max 600s)
- `record_key_finding` validation strictness (required fields, dead_end rules)
- `rag_search` default `top_k` (default 5)

### Layer 6: Sub-agent configuration (`chying_agent/brain_agent/claude_advisor.py`)

- Sub-agent tool lists (executor_tools, browser_tools)
- Sub-agent descriptions (affects orchestrator routing decisions)
- `max_turns` (default 60) -- tool calls per guidance round

---

## Phase B: Optimization Loop

Goal: Iteratively test improvement hypotheses. Each iteration makes one atomic change, validates it, and keeps or discards.

### Loop Protocol

For each hypothesis from the diagnosis report (highest priority first):

#### B1: Prepare

1. Read `scripts/autoresearch/diagnosis_report.md` for the current hypothesis
2. Read `scripts/autoresearch/experiments.tsv` (create if missing) to check what's been tried
3. Assign hypothesis ID: `H001`, `H002`, etc.

#### B2: Branch

```bash
git checkout main
git checkout -b autoresearch/H{NNN}
```

#### B3: Implement change

Make exactly ONE atomic change. Rules:
- Only modify files in the ALLOWED list (see Safety Constraints below)
- Change one thing in one file
- The change must be a GENERIC improvement (Anti-Overfitting rule)
- The change must be directly motivated by the diagnosis

After editing, validate:
```bash
# Syntax check (only for .py files; .md files need no check)
uv run python -m py_compile {modified_file}

# Anti-overfitting check: no benchmark IDs in the change
grep -rn "XBEN\|xben" chying_agent/ && echo "OVERFITTING VIOLATION: benchmark ID found in codebase" && exit 1
```

If syntax fails or overfitting check fails, fix immediately. Do NOT proceed.

#### B4: Commit

```bash
git add {modified_file}
git commit -m "autoresearch H{NNN}: {brief description}"
```

#### B5: Run subset benchmark

Identify target benchmarks: the failed benchmarks that this hypothesis should fix (from diagnosis), plus the 5 canary benchmarks.

```bash
uv run python scripts/benchmark_runner.py --challenges {comma_separated_ids} --timeout 2100
```

This will take a while. Wait for completion.

#### B6: Evaluate results

Read `benchmark-results/state.json` for results.

Compute:
- **Target improvement**: How many target failures flipped to SUCCESS?
- **Canary regression**: Did any canary benchmark go from PASS to FAIL?

Decision matrix:
| Target improved? | Canary regressed? | Action |
|---|---|---|
| Yes | No | KEEP -- commit and push |
| Yes | Yes | DISCARD (regression) |
| No | No | DISCARD (no effect) |
| No | Yes | DISCARD (regression) |

#### B7: Record and act

Append to `scripts/autoresearch/experiments.tsv`:
```
H{NNN}\t{description}\t{target_file}\t{target_improved}/{target_total}\t{canary_pass}/{canary_total}\t{KEEP|DISCARD}\t{timestamp}
```

If KEEP:
```bash
git checkout main
git merge autoresearch/H{NNN} --no-edit
git branch -d autoresearch/H{NNN}
git push origin main
```

If DISCARD:
```bash
git checkout main
git branch -D autoresearch/H{NNN}
```

#### B8: Update diagnosis

If KEEP, update the baseline. Some previously failed benchmarks may now pass, which changes priorities. Re-read `benchmark-results/state.json` and update the canary set if needed.

#### B9: Next hypothesis

Go to B1 with the next hypothesis. If all hypotheses are exhausted, re-run Phase A diagnosis with the new baseline to discover new patterns.

### Loop termination

Continue indefinitely unless:
- All 104 benchmarks pass (unlikely but ideal)
- 10 consecutive DISCARD results with no improvement
- Budget limit reached (Claude will auto-stop)
- User interrupts

---

## Safety Constraints

### ALLOWED to modify (one file per experiment)

**Prompt files** (`.md` in `chying_agent/prompts/`):
- `orchestrator_identity.md`, `orchestrator_strategy.md`, `orchestrator_constraints.md`, `orchestrator_output.md`
- `prompt_compiler.md`
- `executor.md`, `browser.md`, `c2.md`, `reverse.md`
- `scene.md`, `scraper.md`, `writeup.md`, `flag_submitter.md`

**Reflection configuration** (`chying_agent/claude_sdk/reflection.py`):
- Threshold numerical values
- Interval numerical values
- Finding kind sets
- Deduction table values
- Ineffective signal patterns

**Guidance loop parameters** (`chying_agent/claude_sdk/base.py`):
- `MAX_GUIDANCE_ROUNDS`, `SUBAGENT_MAX_DURATION_MS`, `SUBAGENT_MAX_TOOL_USES`
- Confidence thresholds (0.2 / 0.5 / 0.6)
- `max_turns` in orchestrator

**Tool configuration** (`chying_agent/claude_sdk/mcp_tools.py`):
- `MAX_OUTPUT_LENGTH`
- Timeout defaults
- `top_k` defaults

**Sub-agent configuration** (`chying_agent/brain_agent/claude_advisor.py`):
- Sub-agent tool lists
- Sub-agent description strings
- `max_turns` value

### FORBIDDEN to modify

- `chying_agent/claude_sdk/base.py` core logic (hook system, session management, stream processing) -- only modify clearly marked parameter constants
- `chying_agent/brain_agent/claude_advisor.py` core logic -- only modify sub-agent definitions and parameter values
- `chying_agent/claude_sdk/mcp_tools.py` core logic -- only modify clearly marked configuration constants
- `scripts/benchmark_runner.py`
- `main.py`
- Any file under `chying_agent/db/`
- Any file under `chying_agent/executor/`
- Any file under `chying_agent/runtime/`
- `chying_agent/prompts/__init__.py` (loader must not change)
- Do NOT rename or delete any `.md` file in `chying_agent/prompts/`. Only edit their content. Renaming breaks the import chain.

### Canary regression rule

If ANY canary benchmark flips from PASS to FAIL, the change is automatically DISCARD. No exceptions.

### One change at a time

Never stack multiple changes. Each experiment branch has exactly one modification to one file. This ensures clear attribution of results.

---

## File Locations Reference

| File | Purpose |
|------|---------|
| `benchmark/glm-5-state.json` | Baseline benchmark results (104 challenges) |
| `agent-work/ctf/Web/` | Archived work directories from benchmark runs |
| `benchmark-results/state.json` | Latest benchmark run results |
| `chying_agent/prompts/*.md` | All prompt content (primary optimization target) |
| `chying_agent/claude_sdk/reflection.py` | Reflection thresholds and behavior |
| `chying_agent/claude_sdk/base.py` | Guidance loop parameters |
| `chying_agent/claude_sdk/mcp_tools.py` | Tool configuration constants |
| `chying_agent/brain_agent/claude_advisor.py` | Sub-agent definitions |
| `scripts/autoresearch/diagnosis_report.md` | Phase A output |
| `scripts/autoresearch/experiments.tsv` | Phase B experiment log |
| `scripts/benchmark_runner.py` | Benchmark runner (supports `--challenges` for subset runs) |

---

## Notes

- The benchmark runner uses `uv run python scripts/benchmark_runner.py` from the project root
- Each benchmark challenge takes 5-35 minutes to run
- The `--challenges` flag accepts comma-separated benchmark IDs (e.g., `XBEN-001-24,XBEN-005-24`)
- Work directories follow the pattern: `{challenge_code}__{benchmark_id}__{timestamp}` under `agent-work/ctf/Web/`
- progress.md and findings.log are the primary sources of information about what the agent did
- reflection_history.md shows when/why the reflection system triggered
- The project uses `uv` as the package manager, Python >= 3.13
- Do not truncate any content when reading files -- read fully and analyze
- Prompts are `.md` files -- edit them directly, no Python syntax concerns
- For `.py` file changes (thresholds, parameters), always run `py_compile` after editing
- When a KEEP result occurs, push to origin so changes are preserved
