# Build plan — adopting ARTEX automation patterns

Drafted 2026-11-22. Companion to `plans/orchestrator.md`; it does not replace it.
Reference implementation studied: ARTEX v0.7.0 (`github.com/BaaRai/ARTEX`, AGPL-3.0,
local checkout `/private/tmp/ARTEX`). Only **patterns** are adopted, no code is copied,
so BugVault's licence is unaffected.

> **Status:** design only. Nothing in this file is implemented, and nothing here is a
> standing permission. Written program rules, `scope.json`, the engine's
> scope/method/rate/budget checks and tool approval prompts govern every live action.
> Items marked **[DECIDED]** were answered by the operator on 2026-11-22 (§0).

---

## 0. Decision record (operator, 2026-11-22)

Binding for this plan. Where it changes an `orchestrator.md` decision, that is noted.

| # | Question | Decision |
|---|---|---|
| D1 | `recon exec` as a second sending path | **Accepted.** An accounted path beside `recon send`; refines orchestrator §10 "sending is always `recon send`" to "sending is always `recon send` or `recon exec`" (§3.1) |
| D2 | Cross-process shared limits and parallel workers | **Accepted.** Build cross-process request reservation; parallel workers follow (§4.4). Resolves the open item at `AGENTS.md:104` for this plan |
| D3 | `hunt-rce` env/metadata ban | **Partly adopted.** Proving *reach* of the env/metadata surface is allowed as impact proof; recording the secret values it returns is not (§5.5). Needs an operator answer on the carve-out |
| D4 | `execproof.py` rejecting live evidence | **Lifted.** Live execution evidence (command output from an in-scope target under the program's rules) is accepted as a proof basis (§5.5) |
| D5 | Proof depth | **Maximum proof per class**, bounded by the program's written rules and the secret-handling rule in §5.5 |
| D6 | Notifications | **Deferred.** Not built now; drafts only (§6) |
| D7 | Self-signup | **Enabled** where `account_policy` permits it, using the test mailbox `bchahal909@gmail.com` with plus-aliases (§7.2) |

---

## 1. Why, and what ARTEX does better

A code read of both systems (2026-11-21) concluded:

| | ARTEX | BugVault today |
|---|---|---|
| Unattended run | Yes: planner loop + N parallel workers until every goal is proven | No: `recon run` stops at budget, every hunt is a human-driven session (`Handover.md:35`) |
| Human touchpoints per engagement | ~2 (unauthenticated) to 5–15 (authenticated) | ~15–30 actions plus tool prompts |
| Class knowledge | Weak: generic LLM + scanners; non-recon skills hidden by default | Strong: 32 skills, ledgers, 9 hand-written chains |
| Evidence discipline | Strong: recording proxy, `verified` needs PoE ≥3 + verbatim quote | Very strong: replay + distinct negative control, hash-bound artifacts |

The goal is ARTEX's **execution model** on top of BugVault's **knowledge and evidence
model**. `orchestrator.md` already designs the driver (script owns the loop, agents
think, state on disk). This plan adds the ARTEX mechanisms that driver is missing.

### Do not adopt from ARTEX

- Approval gate and target gate **off by default** → BugVault keeps scope gates always on.
- **Unchecked, model-assigned severity** (`agent/tools.go:1520`) → see §5.3.
- **Blanket HTTP DELETE deny** (`db/db.go:577-610`) → hurts IDOR/BFLA; keep BugVault's
  method grants instead.
- **Body-only quote verification** (`server/finding_verification.go:101-135`) → header-
  proven bugs (OAuth redirect, CRLF, cache, Set-Cookie) must be verifiable; see §5.2.
- Running agents in **permission bypass mode** → see §3.2.

---

## 2. Mapping to `orchestrator.md`

| This plan | Lands in orchestrator.md | Build-order step (§19) |
|---|---|---|
| §3 Safety prerequisites | §15 prerequisites | before step 6 |
| §4 Intent queue, leases, terminal states, resume | §4 architecture, §17 state | steps 1, 8 |
| §4.4 Parallel workers | §10 execution | step 8 (after single-push executor) |
| §4.5 No-stall rule, wake-ups | §12 analyse and re-plan | step 8 |
| §5 Proof levels, measured impact, depth rules | §11 critic, §9 planning | steps 5, 7 |
| §6 Auto-reporter + notifications | §3 (critical surfacing) | after step 7 |
| §7 Self-signup | §13 account provisioning | step 9 |
| §8 Steering, budgets/wrap-up, trace search | §16 failure handling, §18 ceilings | steps 7–8 |

---

## 3. Phase A — safety prerequisites (no target traffic)

These close gaps that become dangerous once anything runs unattended or in parallel.

### 3.1 `recon exec` — scoped wrapper for external tools — **implemented 2026-11-22**

Built: `recon/toolexec.py`, CLI `recon exec <campaign> --tool T --engagement ID
--estimate N [--plan] -- <tool args>`, the missing nuclei importer in `ingest.py`, and
33 tests in `tests/test_recon_toolexec.py` (offline, plus one owned-loopback run of a
fake tool against `EchoServer`). `AGENTS.md` change #6 landed with it. Runs are recorded
at mode 0600 in `.recon/exec/<run-id>/run.json` with artifact hashes, and appended to
`engagements/<id>/exec-runs.jsonl` under an exclusive `flock`.

Two refinements the build forced, both recorded here rather than left implied:

- **Reconciliation is upward only, and nothing is refunded.** Item 3 below said
  "reconcile with the tool's actual request count after the run". No supported tool
  reports a request count that can be trusted, so there is nothing to reconcile
  downward against; an unused estimate stays charged, which is the direction D2 asks
  for. Where an artifact holds more result records than the estimate, those records
  prove at least that many requests were sent and the difference is charged after the
  run. The wall-clock cap derived from `--estimate ÷ max_rps` is what actually bounds a
  tool with no request-count flag. The per-host `host_pacing` clock is advanced across
  that whole window too, so a later `recon send` waits the scan out — but only
  best-effort: that clock's read-modify-write is not atomic across simultaneous
  processes (`recon/README.md:272`), which is precisely the gap D2's reservation closes
  in B3. The campaign budget counter *is* atomic (one conditional `UPDATE`), so the two
  sending paths already cannot together exceed one campaign's total. **Until B3, run one
  sender at a time per campaign.**
- **A profile declares the methods its tool really sends, not the minimum it could.**
  nuclei, dalfox and sqlmap send POST bodies as a matter of course, so they refuse to
  run without a `policy.allowed_methods` POST grant. ffuf requires mode `loud`, since
  path guessing is what `scope-policy` calls loud. Refusing is the safe outcome.

Original design, as built:

Build `python3 -m recon exec --campaign C --tool nuclei -- <args>`:

1. Allowlist of tool profiles (`nuclei`, `httpx`, `ffuf`, `sqlmap`, `dalfox`, `katana`).
2. Extract every target from argv and input files; each must pass `recon check`
   (scope, blocked hosts, method policy). 
3. Inject the tool's own rate/concurrency flags from `policy` (never higher than the
   campaign `max_rps`), and charge a **pre-reserved** request estimate to the campaign
   budget; reconcile with the tool's actual request count after the run.
4. Write stdout/JSON output to `.recon/` with hash + source label; import through the
   existing offline importers (add the missing nuclei importer, `ingest.py:18-19`).
5. A refusal is not a failure to route around (orchestrator §16).

**[DECIDED D1]** Accepted as a second accounted sending path. It shares the campaign
budget and the per-host rate limiter with `recon send` through the reservation in §4.4,
so the two paths together can never exceed one campaign's limits. This refines
`orchestrator.md` §10 from "sending is always `recon send`" to "sending is always
`recon send` or `recon exec`"; any other client remains unaccounted and stays refused.

### 3.2 Permissions without bypass mode — **implemented 2026-11-22**

Built: `.claude/settings.json`, which the project did not have at all before (only
`.claude/settings.local.json`, holding the Burp MCP opt-in).

- `allow`: `Read`, `Glob`, `Grep`, `Bash(python3 -m recon *)`,
  `Bash(python3 -m unittest *)`, and the 13 Burp read/encoding tools.
- `ask`: the 14 Burp sending, preparation, settings, task-control and Collaborator
  tools, named explicitly so a later broad allow rule cannot swallow them. `AGENTS.md`
  already required operator approval for exactly these; `ask` is that rule encoded,
  where `deny` would have been a policy change this plan did not ask for.
- `deny`: direct invocation of the scanner binaries (`nuclei`, `httpx`, `ffuf`,
  `sqlmap`, `dalfox`, `katana`, `bbot`, `feroxbuster`, `subfinder`), which is what makes
  `recon exec` the only way to run them (change #6), plus `Read(**/.recon/private/**)`
  so a model cannot read the mode-0600 owned-account samples that
  `recon authpolicy derive` exists to handle structurally.
- `permissions.defaultMode` is pinned to `default`, so the project states its own
  expectation rather than inheriting one.

The Burp tool names are not guesses: they were read from the running server's own
`tools/list` (27 tools, all 27 classified, verified by a check for typos and for
uncovered tools). Two limits worth stating plainly: a settings file cannot stop
`--dangerously-skip-permissions` on the command line, and `deny` on a Bash prefix is
not a sandbox — both are why change #3's "never run in permission bypass mode" is also
written into `AGENTS.md` as a rule for the model, not left to the file alone.

### 3.3 Operator queue (ARTEX `ask_operator`) — **implemented 2026-11-22**

Built: `recon/operator.py`, CLI `recon operator ask|answer|withdraw|list|resume-input|status`,
26 offline tests in `tests/test_recon_operator.py`. `AGENTS.md` change #9 landed with it.
Entries live at mode 0600 in `<campaign>/.recon/engagements/<id>/operator-queue.jsonl`,
appended under an exclusive `flock` so the parallel workers of §4.4 cannot interleave.
Verified: two intents block independently; answering one unblocks only that one; a
pending question never expires; an answer comes back nonce-framed; and the queue exposes
no scope, policy or budget writer — asserted by a test, not only documented.

ARTEX pauses **only the asking intent**, with no timeout; the rest of the task continues
(`server/ask_operator.go:27-82`).

- `recon operator ask --intent ID --question "..." [--screenshot path]` appends to
  `engagements/<id>/operator-queue.jsonl` and sets that intent to `paused`.
- `recon operator answer ID "..."` resumes it; the answer becomes the worker's next input.
- Used for: CAPTCHA, email/SMS OTP, 2FA, environment blocks (one copy-pastable command),
  and any approval the rules reserve for a human. Never for scope expansion.
- Same mechanism carries orchestrator §16 "blocked-host" items, so the operator has one
  inbox.

### 3.4 Untrusted-output framing — **implemented 2026-11-22**

Built: `recon/untrusted.py` — `frame(text, source, label=...)` and `frame_many`, over a
closed set of sources (`target-response`, `target-derived`, `worker-trace`,
`worker-fact`, `imported-report`, `corpus`, `operator-answer`). The defence is the
unpredictable per-frame nonce; marker-shaped lines inside the text are neutralised, so a
target cannot close the frame early and append instructions outside it. `AGENTS.md`
change #4 landed with it. **Not yet wired into the readers** — responses, Burp history
and corpus text still reach a model unframed; those call sites land with B1.

ARTEX wraps every tool result in nonce-tagged markers (`agent/untrusted_boundary.go`).
Apply the same to everything a worker reads that came from a target or another worker:
responses, Burp history, facts, traces. Extends `AGENTS.md:141`.

---

## 4. Phase B — the loop: intents, leases, parallel workers

**§4.1-4.3 implemented 2026-11-22.** Built: `recon/intents.py`, CLI `recon intent
add|list|show|claim|renew|finish|fail|pause|resume|sweep|context|resume-input|status`,
and 28 offline tests in `tests/test_recon_intents.py`. `AGENTS.md` changes #1, #2, #3
and #7 landed with it. Verified: one worker per intent and only the token holder can
change it; an expired lease sweeps back to `open` and a second worker picks it up;
three dead workers block the intent instead of looping; an error retries twice with
backoff and then blocks; `finish` refuses to accept `blocked` or `paused` as an
outcome, so an error cannot be laundered into a result; a pending operator question
makes only that intent unclaimable; and the queue exposes no scope, policy, budget or
sending writer — asserted by a test.

Two things the build settled:

- **`claim` sweeps before it looks.** A scheduler therefore needs no separate sweep
  loop, and the `recon intent sweep` command exists for inspection rather than as a
  requirement.
- **The first B1 framing call sites are wired.** `recon intent context` returns the
  intent's own instruction separately from nonce-framed surface values
  (`target-derived`) and other workers' facts (`worker-fact`), and `recon send` now
  frames its `body_preview` as `target-response` — it was printing raw target bytes
  straight into a model's context. Burp history reads and corpus text are still
  unframed; those readers are not recon code paths and are covered by the `AGENTS.md`
  rule until B2/C1 touch them.

### 4.1 Intent records

An **intent** is one class × one surface push (orchestrator decision #15) expressed as a
record, stored in `engagements/<id>/intents.jsonl` (append-only events, folded on read):

```json
{"id": 42, "summary": "Test IDOR on GET /api/v2/orders/{id} with accounts A and V",
 "class": "access-control", "skill": "hunt-idor", "surface_ids": ["ep-118"],
 "parent_ids": ["fact-77"], "state": "open", "lease": null, "session_id": null}
```

`summary` names the full target, the action and the reason (ARTEX `add_intent`).
`skill` comes from `skillmap.py`'s routing; an unmatched class gets `skill: "explore"`
(generic reasoning, §5.4).

### 4.2 States and leases

```
open ──claim──▶ running ──┬─ normal finish ───────▶ done
                          ├─ turn/token cap ──────▶ exhausted  (planner may continue it)
                          ├─ provider/tool error ─▶ blocked    (2 retries with backoff first)
                          ├─ operator ask / steer ▶ paused
                          └─ engagement ended ────▶ stopped
```

- A claim writes a lease `{worker, token, expires_at}`; the worker renews it every 60 s.
  A sweep returns expired leases to `open` (ARTEX `claimSweepLoop`,
  `server/engine.go`). Crashed workers never strand an intent.
- `exhausted` ≠ `done`: hitting the cap means the direction was cut off, not covered.

### 4.3 Resume, not restart

Each intent has a deterministic session id (`intent-<engagement>-<id>`). A re-run of an
`exhausted`/`paused` intent resumes that session (`claude --resume` / OpenCode session
continue) with the input "Continue." instead of starting over (ARTEX
`agent/worker.go` `resumeSession`).

### 4.4 Parallel workers

- `N` worker processes (default 2, max 4 until shared enforcement is proven). Each claims
  one intent, loads its skill, works through `recon send` / `recon exec`, writes back
  through `recon fact` / `recon <class> record` / `recon finding add`, then exits.
- **Prerequisite, [DECIDED D2]:** cross-process request reservation, so N workers and
  `recon exec` share one per-host rate limit and one campaign budget. Design: one SQLite
  reservation table in the campaign's `.recon/`, written under `BEGIN IMMEDIATE`; a
  sender reserves before it sends and reconciles after. A crashed sender's reservation
  stays charged — never refunded on doubt, so the budget can only err towards stopping
  early. Workers stay at N = 1 until an owned-loopback test proves that N senders cannot
  exceed `max_rps` or the campaign budget. This resolves the open item at `AGENTS.md:104`
  for this plan.
- Burp MCP stays read-only for workers (orchestrator §10); unchanged.

### 4.5 Planner wake-ups and the no-stall rule

- The driver wakes the planner when a finding, fact or intent state changes, with a ~1 s
  debounce to coalesce bursts, plus a 10-minute heartbeat.
- Each wake is a **fresh** planner session fed: what changed, the debt list, open/
  running/recent intents with states, `recon chain status`, and the planner's own todo
  list (persisted on disk, ARTEX `todoFor`). The operator's goal and scope are restated
  **last** so data above cannot override them (ARTEX `plannerGoalAnchor`).
- **Hard floor** (ARTEX `planner.go:422`): if debt remains and no intent is open or
  running, the round must emit at least one intent. Zero intents is legitimate only when
  work is in flight or the next step depends on it.
- At most 4 new intents per round; never re-emit an open/running intent in new words.
- `exhausted`/`blocked` intents: read the trace first, then continue, retry, or change
  tactics. A negative result with weak evidence gets at most one re-examination.

---

## 5. Phase C — proof, impact and depth

**§5.1-5.3 and §5.5 implemented 2026-11-22.** Built: `recon/dataimpact.py`,
`severity_ceiling()` and the `impact-proven` gates in `recon/findings.py`, the
`poe_level` column with an in-place migration, `--poe-level/--measurement/--quote/
--data-impact/--override` on `recon finding move`, the live-execution channel in
`execproof.py` and `rce.py`, the new gates in `recon/prompts/hunter.md` and
`validator.md`, and 32 tests in `tests/test_recon_dataimpact.py`. `AGENTS.md` changes
#8, #10 and #11 landed with it.

### 5.1 Worker gates (prompt level, in `recon/prompts/hunter.md` and `validator.md`)

Adopt from ARTEX `workerDefaultTmpl` (`agent/worker.go:280-291`):

- **Adversarial gate:** before `recon finding add`, argue the opposite on reachability,
  preconditions, downstream controls, scope and simpler explanation. Eliminations need
  evidence at the same bar as confirmations.
- **End-to-end PoC:** the attacker's goal achieved, not a vulnerable pattern.
- **Measured impact:** a number with a denominator ("3 of 20 variants returned
  other-tenant rows; 17 rejected") plus what the defence blocked.
- **Proof basis:** `executed-live` | `executed-lab` | `static-unexecuted`.
- **Write back as you go:** a result only in the model's context is lost at the cap.
- Do not merge distinct entry points/parameters/privilege levels into one finding.
- Zero findings is a valid outcome; record precise negatives as facts.

These sit beside, not over, the existing reportability and realism gates.

### 5.2 Proof levels, enforced in code (`recon/findings.py`)

Add `poe_level` 0–4 to findings (ARTEX `server/orchestration.go:457`):
1 error/timing/variation · 2 structural manipulation · 3 data actually extracted or
action actually performed · 4 critical impact demonstrated.

- `confirmed` keeps today's replay + distinct negative control.
- `impact-proven` additionally requires an impact artifact containing a measurement
  (numerator/denominator or explicit "not measurable: reason") and `poe_level ≥ 3`, plus
  at least one verbatim quote found in the bound artifact. **Headers count**, not only
  the body (fixes ARTEX's blind spot).
- Timing-only evidence stays a lead until `duration_exceeds` exists (`plans/rce.md` §12).

### 5.3 Severity tied to proof **and to the measured data**

ARTEX severity is free text and never checked. BugVault applies **two** ceilings and
takes the lower: what the stage and proof level can support at all, and what the data is
actually worth (§5.5).

| Stage / PoE | Maximum severity |
|---|---|
| `lead` | none |
| `confirmed`, any PoE | medium |
| `impact-proven`, PoE 3 | high |
| `impact-proven`, PoE 4 | critical |

| Measured data — highest tier present | Maximum severity |
|---|---|
| `credential` (session token, API key, cloud credential, DSN, signing key) | critical at 1 item |
| `sensitive` (PII, another tenant's records, private content) | critical at ≥ 100, high at ≥ 2, medium at 1 |
| `internal` (internal hostnames/paths, software inventory, account *names*) | medium |
| `none` (build metadata, public config, generated noise) | low |
| **not characterised** | **medium** |

Generalises the SSTI ceiling already in `ssti.py:261-267`. An operator may lower a
severity freely; raising above the ceiling needs `--override` with a reason, which is
recorded on the finding event. `severity_ceiling()` in `findings.py` is the single
implementation, and `PoE 4` is refused unless the measurement itself supports critical —
so the top rating is earned by the data rather than asserted.

### 5.4 Depth over coverage, and the long tail

Planner rules adopted from ARTEX `plannerDefaultTmpl`:

- After a high-value entry point, prioritise intents that drive that route deep over
  shallow-testing more assets.
- Keep 2–3 mechanistically different routes in parallel; concentrate only after one shows
  evidence of closing in.
- Serial chains go step by step: use `recon chain status`; dispatch a step only when its
  prerequisite reached `confirmed`.
- Classes with no skill route get an `explore` intent: generic reasoning with the same
  gates. This is the ARTEX behaviour, used only for the long tail.

### 5.5 Proof depth per class [DECIDED D3–D5]

**Rule: take proof to the deepest level the program's written rules allow.**

What changes from today:

- **Live execution evidence is accepted** (D4). `execproof.py` gains a live import path:
  command output captured from an in-scope target, hash-bound, with the exact request or
  command recorded. A worker may prove command execution with a benign identity or
  marker command (`id`, `hostname`, `uname`, writing a unique marker file to a path it
  then reads back). That is `executed-live`, PoE 3, and it satisfies the end-to-end PoC
  gate in §5.1. Callback-only and timing-only evidence remain leads, unchanged.
- **Reach is a primitive, not the impact** (D3, revised by the operator 2026-11-22;
  this supersedes the "severity follows reach" rule that stood here before). Proving the
  request reached `169.254.169.254` and that the service answered, or that an
  environment read executes, establishes that you have a read primitive. It says nothing
  about whether what comes back is a live cloud credential or a page of build flags, and
  those two are a critical and a low on the identical bug. So the primitive is where the
  work starts: go and see what the value is, whether it is important or random useless
  data, what the data is about, and **what the total count of reachable items from that
  point is**. Then maximise within the program's rules, because the count and the quality
  of the data are what make the same finding informative, low, or high/critical.
- **The measurement is the proof.** `recon/dataimpact.py` requires four answers before
  `impact-proven`: what the data is about (`subjects` plus a class per item), whether it
  is valuable or noise (the class's tier), how many items are reachable (`reachable`,
  with `enumeration: complete` or `bounded-sample` so a count is never passed off as
  exact when it is a floor), and how much was actually characterised (`sampled`, which
  must equal the sum of the class counts — a claim about records nobody looked at is not
  a measurement). Severity then falls out of the table in §5.3.
- **Live execution evidence is accepted** (D4). `execproof.py` accepts
  `channel: "live-target"` alongside `"owned-lab"`: command output captured from an
  in-scope target, hash-bound, with the exact request recorded. A benign identity or
  marker command (`id`, `hostname`, `uname`, writing a unique marker and reading it back)
  establishes execution. The bar did not move with the channel — eight evidence roles,
  three distinct owned markers, identity-encoded captures and strictly ordered times are
  all still required, and `direct-output`/`owner-worker-log` are still the only effect
  channels that establish anything. Callback-only and timing-only evidence remain leads.

**Secret handling, which the revision did not change.** Record the field name plus a
redacted fingerprint — a prefix of at most 4 characters and a salted SHA-256 — never the
value. `dataimpact.validate` refuses a measurement carrying a `value`, `secret`,
`password`, `raw` or `cleartext` key, or a prefix longer than 4 characters, so the
redaction is structural rather than a rule to remember. Do not reuse a recovered
credential, token, key or cookie to go further; lateral movement, credential reads and
token use stay grant-gated.

**Open decision #1 is closed by this revision, not by the carve-out.** The question was
whether a per-program grant should permit copying out env/metadata secret *values*. It
is moot: what the new rule needs is the classification, the count and a fingerprint, and
all three are obtainable by looking at a value without storing it. Storing the raw
secret would add nothing to the severity — the tier and count already set it — while
putting production credentials for systems you do not own into local files and a model's
context, which most program rules forbid outright. So the answer is: characterise
aggressively, count exhaustively, store nothing.

---

## 6. Phase D — critical/high: record immediately, draft automatically, notify

BugVault already records findings without any severity gate. Add ARTEX's automatic
reporter (`server/orchestration.go:880-930`):

1. **Trigger:** a finding entering `confirmed` or `impact-proven` (the event is already
   written by `findings.py`) enqueues a reporter job.
2. **Reporter job:** headless session with `recon/prompts/reporter.md`, read-only tools
   plus the finding's evidence; writes `reports/drafts/<finding-id>.md`. Up to 3 in
   parallel, one per finding (ARTEX uses 5).
3. **Notify: not built [DECIDED D6].** Deferred. The draft plus the checkpoint surfacing
   in item 4 is the whole delivery path for now. If it is added later, the payload is
   finding id, class, severity ceiling, campaign and draft path — never evidence,
   tokens, cookies or target response text.
4. **Surfacing:** keep orchestrator §12 behaviour (never halt; `impact-proven` printed at
   the top of every checkpoint).
5. **Manual, unchanged:** submission to the platform and `finding move … reported`.

---

## 7. Phase E — self-signup

### 7.1 How ARTEX does it (for reference)

- Accounts declared at task creation; an empty password means "the agent must register
  it" (`server/server.go:1730`).
- Registration uses the worker's ordinary tools; there is no signup module.
- `save_task_credential` stores the account immediately (encrypted) and every later
  worker sees it (`agent/tools_creds.go:17-115`).
- CAPTCHA/OTP/2FA go to `ask_operator`. No inbox, temp-mail or TOTP tooling exists.

### 7.2 BugVault design (extends orchestrator §13)

1. **Policy:** `scope.json.account_policy` = `designated` | `forbidden` |
   `self-register`, plus `mailbox` and `max_accounts`. Copied from the program's written
   rules at bootstrap. **[DECIDED D7]** the mailbox is `bchahal909@gmail.com`;it is configured once per campaign rather than
   hardcoded in the engine, and it is treated as operator-owned test infrastructure.
2. **Ledger:** `recon account add|list|show` in the campaign's private `.recon/`. Stores
   role (A/V, user/admin), origin (`designated` | `self-registered`), created_at,
   and a **reference** to the secret. Passwords live in the macOS Keychain
   (`security add-generic-password`); cookies/tokens are never stored, consistent with
   "header values are never stored" (`recon/cli.py:1720`).
3. **Registration:** only through the dedicated browser via Burp, after the
   `browser-workflow.md` connection checks pass. Email = plus-addressed alias of the
   mailbox, `bchahal909+<campaign>-a@gmail.com` and `…-v@gmail.com`, so each campaign's
   accounts are separable and revocable. The verification link is read from the webmail
   tab in the same profile; its full destination is inspected before clicking, and a
   link to an unexpected domain goes to the operator queue instead.
4. **Always two accounts** (A and V), then `recon import-har --account A|V`.
5. **Blocks:** CAPTCHA, SMS OTP, 2FA enrolment, lockout → `recon operator ask`; only the
   signup workflow pauses. Never evade.
6. **Never:** paid services, scope expansion through a
   redirect or mail-provider domain.

---

## 8. Phase F — run control

### 8.1 Budgets with a wrap-up turn

- Per-intent turn/token caps and a per-engagement token cap (complements request
  ceilings, addressing orchestrator §18 "model spend is unbounded in time").
- Near the cap, the worker gets one final turn with sending tools disabled: it may only
  write back facts, ledger rows and findings (ARTEX `Settlement`, Bash hidden).
- A worker is not started when the remaining budget cannot cover the average intent cost.

### 8.2 Steer and kill

- `recon intent steer ID "message"` queues a correction; a pre-tool hook delivers it
  before the worker's next tool call (ARTEX `steerBox`). No lost progress.
- `recon intent kill ID` cancels a direction that is wrong as a whole; state → `stopped`.

### 8.3 Cross-worker trace search

Workers may search other intents' traces/facts for observations that never became
facts (an error string, a hidden parameter) instead of re-sending requests. Read-only,
framed as untrusted data (§3.4), and a worker still does only its own intent.

---

## 9. Build order

1. ~~**A1** `recon operator` queue + untrusted framing (offline). Tests first.~~
   **Done 2026-11-22** — 26 tests, suite 818 total with no new failures.
2. ~~**A2** permission allowlist; **A3** `recon exec` (if accepted) against an owned
   loopback lab only.~~ **Done 2026-11-22** — 33 tests.
3. ~~**B1** intent records, leases, sweep, terminal states, resume — single worker,
   manually started (orchestrator step 6).~~ **Done 2026-11-22** — 28 tests.
   Suite 879 total, no new failures.
4. ~~**C1** worker/validator prompt gates; **C2** `poe_level`, measured-impact check,
   severity ceiling in `findings.py`, with tests.~~ **Done 2026-11-22** — 32 tests,
   plus the measured-data-impact rule that replaced "severity follows reach" (§5.5).
5. **D1** auto-reporter drafts (notifications deferred, D6).
6. **B2** planner wake-ups + no-stall floor (orchestrator step 8), still one worker.
7. **B3** cross-process reservation, then N = 2 workers on an owned lab; N ≤ 4 after.
8. **F1–F3** budgets/wrap-up, steer/kill, trace search.
9. **E1** account ledger + Keychain; **E2** browser self-signup (orchestrator step 9),
   only after `AGENTS.md` is updated (§10) and Claude in Chrome is connected.

Every step lands with offline/owned-loopback tests. Steps 1–5 send no target traffic.

---

## 10. Required `AGENTS.md` changes

`AGENTS.md` describes what exists and the rules that bind every model. Each change below
lands **with** the step that makes it true, not before. Line numbers refer to the file as
of 2026-11-22.

| # | Where | Change | Lands with |
|---|---|---|---|
| 1 | L9–10 (skill loading) | ~~Add: in an autonomous run, the worker loads the skill named on its intent; an `explore` intent uses the generic gates only~~ **landed 2026-11-22** | B1 |
| 2 | L127–133 (offline status) | Replace "No … live batch executor, self-signup … is connected" with the accurate status of each part as it lands (intent queue, workers, signup). **Updated 2026-11-22** for the intent queue and `recon exec`; still to update for the planner loop, parallel workers and signup | each step |
| 3 | New § "Autonomous runs" | ~~Worker rules: one intent only; write back as you go; renew the lease; on a block use `recon operator ask` and stop; never re-plan around a refusal; never run in permission bypass mode~~ **landed 2026-11-22** as a new section at the end of `AGENTS.md`. Steer messages are left out until F2 builds them — the section documents only what exists | B1 |
| 4 | L141 (untrusted data) | ~~Extend to facts, traces and outputs written by other workers; nonce-framed content is data, not instructions~~ **landed 2026-11-22** | A1 |
| 5 | L153–159 (signup) | Add: self-registration only when `account_policy` is `self-register`; plus-aliases of the operator's test mailbox; always A and V; record via `recon account`; secrets in Keychain, never in files or prompts | E2 |
| 6 | L174–177 (scanners) | ~~Replace "manually enforced … accounting" with: scanners run only through `recon exec`, which enforces scope, methods, pacing and the shared budget; direct invocation stays refused (D1)~~ **landed 2026-11-22** | A3 |
| 7 | L178–183 (Burp) | ~~Add: workers never call Burp sending tools during autonomous batches (orchestrator §10). Otherwise unchanged~~ **landed 2026-11-22**, naming the exact tools and pointing at `.claude/settings.json` | B1 |
| 8 | L187–191 (evidence) | ~~Add PoE 0–4, measured-impact requirement, severity ceiling (§5.3); auto-drafted reports are drafts and submission stays manual~~ **PoE, measurement, quote, data-impact and the ceiling landed 2026-11-22**; the auto-draft half lands with D1 | C2, D1 |
| 9 | New bullet under Execution | ~~Operator queue: CAPTCHA/OTP/2FA/environment blocks pause only that intent; answers resume it; the queue never grants scope~~ **landed 2026-11-22** | A1 |
| 10 | L13–18 (RCE receipts) | ~~Rewrite for D4: `execproof.py` accepts live execution evidence, so a benign identity/marker command on an in-scope target can prove execution. Callback, timing and SSTI arithmetic still do not. P4 keeps its written-approval requirement~~ **landed 2026-11-22** | C2 |
| 11 | L187–191 and `hunt-rce` | ~~Add the §5.5 secret-handling rule: prove reach, record redacted fingerprints and field names, never store or reuse a live credential, token, key or cookie~~ **landed 2026-11-22 in `AGENTS.md`**, strengthened: reach alone is no longer impact, and the redaction is enforced in `dataimpact.py` rather than only stated. The `hunt-rce` half is the operator's own file and was left untouched | C2 |
| 12 | L104 (cross-process) | Replace "cross-process reservation … remain separate human decisions" with the reservation as implemented, and state the worker ceiling (D2) | B3 |

---

## 11. Open decisions

Settled on 2026-11-22: §0 D1, D2, D4, D5, D6, D7.

Still open:

1. **Worker ceiling** after the reservation test: N = 2 or 4 (§4.4).

Settled by the operator on 2026-11-22:

- ~~**The D3 carve-out (§5.5).**~~ **Closed, and the rule it belonged to was replaced.**
  Reach is no longer accepted as impact proof: severity now follows what the reachable
  data *is* and how much of it there is. The carve-out is moot, because classification,
  count and a redacted fingerprint are all obtainable without storing a value, and
  storing one would add no severity. See §5.3 and §5.5.
- **Burp sending tools no longer prompt.** All 27 Burp MCP tools are in the
  `.claude/settings.json` allowlist, so a worker is not stopped mid-run for a human.
  The accounting gap is now explicit in `AGENTS.md`: Burp traffic is charged to no
  campaign budget and no pacing clock, so `recon send`/`recon exec` stay preferred for
  anything they can do, and `max_rps` and the request budget bind Burp use anyway.
- **GET, HEAD and POST are always available to `recon exec`.** The scanners worth
  running send POST bodies as a matter of course and a grant check only ever stopped the
  run. PUT, PATCH and DELETE still need an explicit `policy.allowed_methods` grant.

Settled by the A3 build:

3. ~~**`recon exec` tool profiles** beyond the initial six (§3.1).~~ The six are built
   and are the whole allowlist: httpx, katana, ffuf, nuclei, dalfox, sqlmap. Adding a
   seventh is a code change in `recon/toolexec.py` with its own refusal list, its honest
   `sends` methods and its own tests — not a configuration knob — so there is nothing
   left open here. `bbot`, `subfinder`, `dnsx`, `puredns` and `feroxbuster` keep offline
   import adapters without an exec profile: nothing needs to launch them from here.
