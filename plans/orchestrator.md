# Build plan — engagement orchestrator

An autonomous engagement driver for OpenCode, sitting on top of the existing BugVault
recon engine.

Drafted 2026-11-21. Target branch `recon-engine`.
Design settled across four question rounds with the operator; the decision record in
§2 is binding, not advisory. Revised in the 2026-11-20 session: decisions #2/#18/#21,
routing (§10), block handling (§16), ceilings (§18), technology playbooks (§21) and
CVE freshness (§22).

> **Implementation checkpoint (2026-11-21):** The private, offline
> `recon engagement init|status|categorise|debt|block-host|acknowledge-scope` and
> `recon push context|validate` commands exist. `push validate --apply` records a
> review receipt only; it neither grants target traffic nor governs the existing
> manual `recon send` path. The exact operation `method` is required, and `endpoint`
> must be an absolute scoped URL; use `--engagement ID`. The new
> `hunt-security-misconfig` skill and its candidate coverage/chain routes exist.
> **Auth-policy offline integration:** `recon authpolicy` records exact operation ×
> account/workflow × case receipts and transient structural sample analyses;
> `recon fields constraint|surface-expect|surface-review|surfaces` records rule
> provenance and declared field × render × case gaps. Engagement debt includes
> unresolved auth cases and declared render surfaces. None sends traffic or
> validates a vulnerability. See §23.1.
> **Not implemented:** pasted-rules bootstrap, five-push autonomous planner,
> connected executor/browser/signup, model router/DeepSeek dispatch, critic,
> unattended learning, 5,000/hour shared enforcement, technology-playbook
> dispatch, NVD/GHSA sync or 15-day CVE freshness gate. Sections below describe
> target behavior, not an existing permission or working feature. The engine's
> existing finite campaign budget is a hard stop; do not create another campaign
> to bypass it. Written program rules and approvals still govern every live action.

---

## 1. Position — this is a driver, not a new system

The instinct when reading the requirement list is to build an orchestrator with its own
scope model, its own endpoint inventory, its own task queue and its own findings store.
That would be a second engine beside the one that already exists, and the two would
drift within a week.

Almost every phase the operator described is already implemented:

| Requirement | Already built |
|---|---|
| scope and out-of-scope | `recon init --seed`, `recon check <url>` — *"is this URL in scope? (and why not)"* |
| recon phase | `recon run`, `import-har`, `import-burp`, `import-openapi` |
| categorise login / signup / config / api / upload | `score.py` — `AUTH_PATH`, `UPLOAD`, `INTERNAL`, `api_like` → `applicable_classes` |
| continuous re-categorisation | `recon run` re-seeds coverage; `recon report` rewrites `recon.md` / `coverage.md` |
| next best pushes | `recon chain status` — *"cross-class todolist/lineage + realism gate"*, ready steps first |
| never run blindly — **recon jobs** | `recon plan --proposal F [--apply]` — validates 8 discovery handlers only (§9.1) |
| never run blindly — **hunt pushes** | `recon push validate` checks an offline manifest and writes an optional non-executing review receipt; no connected executor consumes it (§9.2) |
| load the right skill per push | `recon brief --role hunter` → *"render pre-authorized agent prompts into agents/"* + `skillmap` routing |
| knowledge base | `recon recall`, `recon lookup`, the vault's 15,443 merged rows, `plans/*.md` |
| learn from the session | **nothing — the real gap** |

`plan --proposal F [--apply]` establishes the right *pattern* — validation as a step
separate from enqueuing — but it does **not** cover hunt pushes. `recon/planning.py`
validates eight discovery handlers and nothing else (§9.1). An earlier draft of this
plan claimed it was the batch gate; that was wrong. The separate offline
`recon push validate` gate now exists, but no five-push planner or sender is
connected to it.

The remaining build is a loop driver, model router, bootstrap parser, critic,
account provisioner, CVE synchronizer, technology-conditioned dispatch and learn
pass, all behind the already-built offline push validator. Not all these pieces
are calls into the existing recon engine.

---

## 2. Decision record

Binding. Where a later answer refined an earlier one, the later answer governs and the
supersession is noted.

| # | Decision | Chosen |
|---|---|---|
| 1 | Engine relationship | **Drives the engine.** Extended role: master planner *and* critic |
| 2 | Model split | **Claude plans, DeepSeek V4.1 Flash generates payloads** — supersedes the earlier local-Qwen assignment (2026-11-20) and matches `docs/model-routing.md` §1; the DeepSeek fallback slot stays unconfigured and fails closed |
| 3 | Execution gate | **Autonomous** — refined by #17 |
| 4 | Learn target | **Writes skills directly** — bounded by #19 |
| 5 | Completeness unit | **All three accountings, reconciled as one debt list** |
| 6 | Accounts | **Orchestrator self-signs up via browser** |
| 7 | Raw input | **Bounty page text** → scope, rules, account policy, payout notes |
| 8 | On failure | **Switch model, keep the push** |
| 9 | Browser stack | **Claude extension in Brave** (v1.0.107, `fcoeoabgfenejglbffodgkkbkcdhcgfn`) |
| 10 | Where it lives | **Hybrid — script owns the loop, agents think** |
| 11 | Critic authority | **Veto + re-brief AND escalate** (combined) |
| 12 | Run length | **Until debt clear or ceiling hit** |
| 13 | Browser pushes unattended | **Machine never sleeps; display off, testing continues** |
| 14 | Ladder order | **Re-brief same model once, then escalate** |
| 15 | Push granularity | **One class × one surface; 5 adaptive** |
| 16 | Per-push knowledge | **`recon recall` + the class plan, every push** |
| 17 | Scope gate | **One confirmation of `scope.json` at engagement start, autonomous thereafter** (supersedes #3's blanket autonomy) |
| 18 | Ceilings | **50 req/s per host + 5,000 requests/hour aggregate (rolling refill); no daily budget, no lifetime total, no wall clock** — refined 2026-11-20 |
| 19 | Learn scope | **Append-only to a `LEARNED` section in `hunt-*` only** (bounds #4) |
| 20 | On finding | **Chain it, always continue, never halt** |
| 21 | Per-host block (429 / WAF challenge / lockout / CAPTCHA) | **Defer that host to the todo list, continue testing other hosts; never evade the block** (2026-11-20) |

### Decisions taken by the author, not asked

| Decision | Reason |
|---|---|
| All sending routes through `recon send`; Burp MCP is read-only during autonomous batches | `AGENTS.md`: Burp MCP is *"not integrated into the recon scope/rate/budget enforcement or response-fact store"*. Autonomy must be uniformly bounded, so the unbounded path is closed |
| Each learn pass is one git commit tagged with the session id, gated on the existing evals | Direct skill writes with no human review need automatic rollback. A lesson that breaks a test never lands; `git revert <session>` is the undo |
| Signup is gated on the extracted account policy | Some programs designate test accounts or forbid registration. The bootstrap already extracts account policy, so the gate is free |
| The driver holds a `caffeinate -i` assertion for the run | Satisfies #13 for the duration of a run without permanently altering the operator's power settings |
| Dedicated Brave profile with its own mail account | The extension acts in the operator's real browser with real sessions |

---

## 3. The one human gate

Exactly one, at engagement start:

```
paste bounty page text
   -> bootstrap parses it
   -> writes scope.json
   -> OPERATOR CONFIRMS            <-- the only gate
   -> autonomous until debt clear or ceiling hit
```

The reason it exists at all: `recon check` can only enforce the boundary the parse
wrote. Every downstream phase trusts `scope.json` completely, so a misparse is the one
error that sends traffic at an unauthorised host, and no amount of downstream
enforcement catches it. Thirty seconds of reading buys the whole engagement.

No new approval is sought per ordinary batch **inside an approved envelope**.
This does not waive program disclosure duties, tool prompts or the engine's
scope/method/rate/budget checks. A 429/challenge defers that host while other
approved hosts may continue; unexpected effects or unresolved cleanup also
park the affected workflow until resolved. A critical finding alone does not
stop other safe work, and is prominently surfaced for prompt disclosure.

---

## 4. Architecture

```
  ┌─────────────────────────────────────────────────────────┐
  │  driver script  (owns the loop, holds all state)        │
  │  - caffeinate assertion for run duration                │
  │  - checkpoint after every phase, to disk                │
  │  - reconciles the debt list                             │
  │  - routes each push to a model                           │
  └───────────┬─────────────────────────────────────────────┘
              │ one OpenCode agent invocation per unit of thinking
              ▼
  ┌─────────────────────────────────────────────────────────┐
  │  agents          planner | categoriser | executor       │
  │                  critic  | analyst     | learner        │
  └───────────┬─────────────────────────────────────────────┘
              │ every state change goes through the engine
              ▼
  ┌─────────────────────────────────────────────────────────┐
  │  recon engine    scope · coverage · findings · chains    │
  │                  ledgers · factcheck · recall · send     │
  └─────────────────────────────────────────────────────────┘
```

**Why the script owns the loop.** Loop state in a conversation does not survive
context compaction. This has been demonstrated repeatedly, and PentAGI learned the
same lesson the hard way — `full_execution_context.tmpl:15` marks it CRITICAL that a
callback IP must be re-emitted into compacted context or it is lost to summarisation.
A run bounded by request ceilings with no wall clock can span days and will be
compacted many times. Therefore: **no loop state lives in any model's context.** The
script reads state from disk, hands an agent exactly the context for one unit of work,
and writes the result back.

**Why agents do the thinking.** Scope parsing, categorisation, batch planning,
critique and analysis are judgement, not control flow. OpenCode's per-agent model
config is the model-switching mechanism, so the script selects an agent and OpenCode
selects the model.

---

## 5. Phase 0 — bootstrap

Input: pasted bounty page text. Model: Claude.

Extracts into `scope.json`:

| Field | Source in the pasted text |
|---|---|
| `in_scope` | asset tables, wildcards, named domains and apps |
| `out_of_scope` | exclusion lists, explicitly excluded subdomains, third-party services |
| `rules` | testing rules, allowed methods, rate requests, prohibited techniques |
| `account_policy` | designated test accounts, self-registration permission, required email pattern |
| `payout_notes` | severity table, known-issue list, duplicate policy |
| `ceilings` | requests/hour and total requests (§11) |

Then:

1. `recon init <campaign> --seed <each in-scope seed>`
2. Render the parse as a diff-style summary: what is in, what is out, what rules were
   found, and **every item the parser was unsure about, listed separately**.
3. **Gate.** Operator confirms.
4. `recon check` is run against a sample of in-scope and out-of-scope URLs as a
   self-test, and the results are shown with the confirmation so the operator sees the
   boundary behaving, not just the text.

A wildcard that the parse could not resolve to a concrete boundary is written as
out-of-scope, not in-scope. Fail closed on the one gated step.

---

## 6. Phase 1 — recon

Driven entirely by existing verbs. No new discovery code.

```
recon run <campaign> --max-jobs N
recon import-burp <campaign> <export>        # if the operator supplied traffic
recon import-har <campaign> <file> --account <acct>
recon import-openapi <campaign> <spec>       # declared fields beat guessed ones
recon lookup <campaign>                      # versions -> public exploits / KEV
recon report <campaign>                      # rewrite recon.md / coverage.md / intel.md
```

`import-openapi` runs before any guessing when a spec exists: declared fields are
ground truth and remove a whole category of invented parameter names.

---

## 7. Phase 2 — categorisation, continuous

The operator's examples — login pages, `.env`-style config, API endpoints, signup
pages, upload pages — are already `score.py`'s job:

```python
INTERNAL  = admin|internal|debug|staff|employee|backoffice|manage|console|...
AUTH_PATH = login|signin|sign-in|signup|register|password|passwd|reset|forgot|...
UPLOAD    = upload|import|avatar|attachment|/files?(/|$)|media|image
api_like  = attribute set on the asset
```

So categorisation is **not a new layer**. It is `applicable_classes` plus a thin
labelling pass that gives each asset human-readable tags for the planner's benefit.

Fixed base taxonomy, extensible per engagement:

| Tag | Basis |
|---|---|
| `auth-entry` | `AUTH_PATH` match |
| `signup` | `AUTH_PATH` ∩ register/signup |
| `config-exposure` | `.env`, `.git`, `config.*`, backup extensions, `/actuator`, `/debug` |
| `api` | `api_like` attribute, or OpenAPI-declared |
| `upload-sink` | `UPLOAD` match, or a declared multipart field |
| `internal-surface` | `INTERNAL` match |
| `tenant-scoped` | id params present with an account context |
| `render-surface` | response reflects an input (feeds SSTI/XSS) |

**Continuity requirement.** The operator was explicit that categorisation continues
throughout and updates whenever a new endpoint appears. Mechanism:

- every phase that can discover an endpoint ends with `recon run` + `recon report`
- the categoriser is invoked on the **delta only**, never the full inventory, so its
  cost stays flat as the inventory grows
- a new tag on an existing asset is a debt-list event (§8), because it may open a class
  that was previously not applicable

---

## 8. Phase 3 — the debt list

Decision #5: all three accountings, reconciled into one list. Each answers a different
question and each is individually foolable.

| Accounting | Unit | Answers | Blind to |
|---|---|---|---|
| Coverage rows | asset × bug_class | breadth — is any class unexamined on any asset? | whether the examination was deep |
| `fields.matrix()` | endpoint × trigger | depth — were `list/search/filter/create/edit/bulk/export/sort` all exercised? | classes not wired to the field ledger |
| Chain ready-steps | chain step | escalation — is any proven edge unexploited? | breadth; early engagements have few steps |

Reconciliation produces one ordered debt list:

```
debt = [
  { kind: "coverage", asset, class, status, age_batches },
  { kind: "matrix",   endpoint, trigger, class },
  { kind: "chain",    step, from_finding, why },
  { kind: "retag",    asset, new_tag, newly_applicable_classes },
]
```

"Nothing dropped, nothing left untested" is defined as: **the debt list is empty.**
That is the run's terminating condition, and it is computed from the engine rather
than asserted by a model.

An item that cannot be satisfied — no browser connected, a class with no skill, a
refused precondition — moves to a `blocked` sublist with its reason. Blocked items do
not count as done, and they are what the run reports at the end. Silent drops are the
failure mode this whole phase exists to prevent.

---

## 9. Phase 4 — batch planning

Model: Claude. Output: a proposal file, never direct execution.

A **push** is one class against one surface:

```
push = {
  id, class, asset_id, endpoint,
  skill,                  # from skillmap.SKILLS_FOR_CLASS
  model,                  # from the routing table, §10
  intent,                 # what we expect to establish
  expected_evidence,      # the predicate that would confirm it
  poe_target,             # 1-4, per the RCE plan's ladder
  context_refs,           # recall hits + plans/<class>.md
  debt_items,             # which debt entries this clears
}
```

Five by default, adaptive:

- shrink when pushes are expensive — race conditions, smuggling, anything needing a
  synchronised or raw-socket send
- grow when pushes are cheap — passive reads, static bundle analysis, ledger syncs
- never exceed what the remaining request ceiling can fund

The whole batch is planned **before anything executes**, including each push's model
and skill. That is the operator's "it must never run blindly" requirement. The
mechanism for it has to be built.

### 9.1 What the existing proposal validator actually covers

`recon/planning.py` is narrower than it first appears:

```python
JOB_KINDS = {"domain": {"crtsh", "wayback"}, "host": {"probe"},
             "service": {"wellknown", "jsharvest", "runtime"},
             "js": {"jsparse"}, "sourcemap": {"mapparse"}}
```

Eight **discovery handlers**. A job is exactly `{kind, asset_id, asset_sha256, reason}`
(`:83`); `kind` must be in `JOB_NEEDS` or review raises *"proposal references an
unknown handler"* (`:87`); the top-level key set must be exactly
`{schema_version, scope_sha256, jobs}` (`:75`), so a push cannot be added to the same
file even as an extra field. There is no class, skill, model, predicate, PoE target or
request count anywhere in the schema, and `:104` returns `executed: False`
unconditionally — `--apply` enqueues recon jobs and nothing else.

**It therefore cannot gate a hunt batch.** It validates recon work, not testing work,
and it never sees a request budget.

### 9.2 `recon push validate` — the new validator

A separate manifest validator, run before any hunt execution. It should not invent
discipline; it should copy `planning.py`'s, which is already good, and add the three
things a push needs that a job does not: a routed skill, a bindable predicate, and a
declared request budget.

Inherited from `planning.py` unchanged:

| Property | Source |
|---|---|
| `scope_sha256` must equal current `scope_revision(ctx)` — any change to config, policy, budgets, credentials or runtime invalidates the manifest | `:27-32`, `:77` |
| per-item `asset_sha256` must match the live asset digest | `:92` |
| closed key sets at both levels; an unknown field is rejected, never ignored | `:75`, `:83` |
| capability re-checked at apply time, not trusted from generation time | `:94` |
| entire file validated before any write | `:101-103` |
| hard size and count caps | `:72`, `:79` |
| `executed: False` — review/apply never executes; the current push apply only writes a receipt | `:104-105` pattern, `push.py` implementation |

Manifest:

```json
{
  "schema_version": 1,
  "scope_sha256": "<scope_revision(ctx)>",
  "budget_sha256": "<digest of consumed vs ceiling state>",
  "pushes": [{
    "class": "ssti",
    "asset_id": 42,
    "asset_sha256": "...",
    "endpoint": "https://app.example.test/api/render",
    "method": "GET",
    "skill": "hunt-ssti",
    "model": "<provider/model>",
    "intent": "...",
    "predicate": {"type": "body_contains_raw", "marker": "..."},
    "poe_target": 2,
    "request_budget": 12,
    "debt_items": ["coverage:42:ssti"],
    "reason": "..."
  }]
}
```

For the implemented offline validator, use an **absolute in-scope URL**;
method is mandatory. The engagement
ID selects private `.recon/engagements/<id>/` state. A blocked host is rejected.
The validator reserves no requests and does not currently enforce an hourly pool.

Added checks:

| # | Check | Rejects |
|---|---|---|
| 1 | `class` ∈ `skillmap.SKILLS_FOR_CLASS` | a class the engine does not route |
| 2 | `skill` ∈ `SKILLS_FOR_CLASS[class]` | a skill that does not route to its own class |
| 3 | `skill` ∈ `catalog.HUNT_SKILLS` **and** present on disk | the three-way landing rule, enforced at plan time |
| 4 | `predicate.type` ∈ `factcheck.FIELDS` | **a push declaring evidence the checker cannot bind** |
| 5 | `poe_target` ∈ 1..4 | an unscaled proof claim |
| 6 | `endpoint` passes `ctx.scope.is_in()` | an out-of-scope target |
| 7 | the push's **exact** `method` ∈ `policy.allowed_methods` and active mode | a method/campaign the policy has not granted; class-specific live grants still need separate enforcement |
| 8 | `request_budget` a positive int, and **Σ over pushes ≤ remaining ceiling** | a batch that cannot be funded |
| 9 | `budget_sha256` matches live consumption | a manifest planned against a stale budget |
| 10 | no duplicate `(class, asset_id, endpoint, method)` | the same operation twice in one batch |
| 11 | push count ≤ hard cap | an unbounded batch |

Check 4 is the one that bites immediately and correctly: `factcheck.FIELDS` holds four
content predicates and no timing one, so a push whose only channel is timing is
**rejected at plan time** rather than executed and then found unprovable. That is the
behaviour §20 anticipates.

Check 8 is the genuinely new capability. `planning.py` never sees a request budget
because discovery jobs are funded by the engine's own accounting at run time. A batch
of five pushes has to be costed *before* it starts, or the ceiling that terminates the
run (§18) can be overshot mid-batch.

```
recon push validate <campaign> --manifest batch-NN.json            # validate only
recon push validate <campaign> --manifest batch-NN.json --apply    # authorise
```

`--apply` currently writes an **offline review receipt** naming the manifest
digest; no existing executor consumes it and `recon send` does not consult it.
The future executor (§10) must revalidate the scope, budget, exact operation,
host block and class-specific grants immediately before every send, and refuse
an unapproved/stale manifest. A failed validation is re-planned, never forced.

### Per-push context assembly (decision #16)

Every push brief carries:

1. `recon recall <campaign> "<class> <surface terms>"` — lexical hits over the vault's
   15,443 rows, giving disclosed precedent for this exact shape
2. `plans/<class>.md` — the deepest material we own. The class plans run 540-1,019
   lines each and are wasted if the executing model never sees them
3. the asset's tags, declared fields, and WAF profile if one exists
4. the PoE target and the exact predicate that would satisfy it

Context is assembled by the script from disk, not accumulated in a conversation.

---

## 10. Phase 5 — execution and model routing

### Routing table

| Work | Model | Why |
|---|---|---|
| scope parse | Claude | one-shot, high consequence, needs careful reading |
| categorisation | Claude | cheap, delta-only |
| batch planning | Claude | long context over the debt list and recall hits |
| **payload bodies** | **DeepSeek V4.1 Flash** | `docs/model-routing.md` §1 (operator decision); emitted via `fields packet` / `fields payload` so authorship is recorded in `payload_events`; the unconfigured DeepSeek fallback fails closed |
| execution driving | Claude | tool orchestration, evidence capture |
| critique | Claude | needs the PoE rubric and the debt list |
| analysis | Claude | long context across the batch's results |
| learn | Claude | writes the skill diff |

This matches `docs/model-routing.md` §1: payload generation is DeepSeek V4.1 Flash
primary with an unconfigured DeepSeek fallback that fails closed. The earlier
local-Qwen assignment (measured at 10.5-12.5 tok/s generation, 80-113 tok/s
prefill — a 16k-token output in ~25 minutes) is retired; local Qwen remains, at
most, the summarizer option in `docs/model-routing.md` §3.

The engine contains **zero payload literals** by design. That rule is unchanged: the
DeepSeek route emits payloads, the engine records them through `packet()` /
`record_payload()` with authorship, and the ledgers reference them.

### Per-push execution

```
load skill  ->  assemble brief  ->  dispatch to the push's model
            ->  capture evidence through recon send
            ->  recon fact check   (bind the predicate)
            ->  recon <class> record   (write the ledger row)
            ->  recon finding add|move (lifecycle, if warranted)
```

Sending is always `recon send`, which sits inside scope, method, rate, egress and
budget enforcement. Burp MCP is **read-only** for the duration of an autonomous batch:
`get_proxy_http_history*`, `get_organizer_items*`, `get_scanner_issues`. Its sending
tools are not called, because they bypass the accounting that makes autonomy safe.

---

## 11. Phase 6 — the critic

This is the mechanism behind "push the models to hunt deep". Without it, depth is a
request rather than a process.

The critic runs after each push and judges the result against the push's own contract.
Rubric, drawn from the PoE ladder settled in `plans/rce.md`:

| Question | Fail action |
|---|---|
| Did the result reach its `poe_target`? | re-brief naming the gap |
| Is the claimed evidence actually bound to a stored response? | reject; no `fact check` binding means no claim |
| Did a `lead` get described as `confirmed` without a replay **and** a distinct negative control? | demote, re-brief |
| Was a sub-surface in the brief left untouched? | re-brief with the untouched item named |
| Did the result open a chain edge that was not planned? | add to debt list as a `chain` item |
| Did the model stop at the first refusal instead of exhausting encodings, methods, parameters and paths? | re-brief |
| Does the result assert impact from a status code or a hypothesis? | reject |

### Ladder (decision #14, combining re-brief and escalation)

```
attempt 1   assigned model, original brief
   veto  ->
attempt 2   SAME model, sharper brief naming exactly what was missing
   veto  ->
attempt 3   ESCALATE to Claude, same sharpened brief
   veto  ->
            push becomes a `blocked` debt item with the critique attached
```

One re-brief before escalation, because a vague brief is the more common cause of a
shallow result than a capability ceiling. The escalation ceiling is Claude: there is no
stronger model in the configured set, so a push Claude cannot satisfy after a sharpened
brief is recorded as blocked and surfaced at the end of the run. It is not retried
forever.

---

## 12. Phase 7 — analyse and re-plan

After the batch:

1. `recon report <campaign>` — rewrite `recon.md`, `coverage.md`, `intel.md`
2. `recon chain status` — new ready steps from anything proven this batch
3. recompute the debt list (§8)
4. **New findings feed the next batch's priority** (decision #20) — a `confirmed`
   finding's chain steps outrank unexplored breadth, because a proven edge is the
   strongest signal available about where to look next
5. plan the next batch

The run never halts for a finding, including an `impact-proven` critical. To keep that
from burying something urgent, every checkpoint writes findings **at the top** of its
output, ordered by lifecycle state, so `impact-proven` is the first thing visible
whenever the operator looks in. Prompt-disclosure obligations remain the operator's.

---

## 13. Account provisioning

Decision #6 with the author's policy gate. Browser: Claude extension v1.0.107 in Brave.
Manual prerequisites — program permission, the dedicated gmail account, the Brave
profile — are the operator's to set up by hand; the orchestrator only verifies their
presence at start and then works unattended (decision #17).

```
read scope.json.account_policy
  |
  +-- designated accounts supplied        -> use them, never register
  +-- self-registration forbidden         -> do not register; flag the debt item blocked
  +-- self-registration permitted         -> proceed
                                             |
         find the `signup` tagged surface  <-+
         register account A
         read the verification link from the webmail tab
         register account B                 # two accounts, not one
         record both in scope.json accounts
         recon import-har --account A / --account B
```

**Two accounts, always.** IDOR, access-control, tenant isolation and mass-assignment
all need a second principal. One account makes those classes unprovable, and they are
a large part of the debt list.

Prerequisites, stated as blockers in §15: a dedicated Brave profile, and a mail account
logged into that profile. Claude-in-Brave reads the verification link straight out of a
webmail tab, which removes any need for a mailbox API.

---

## 14. The learn pass

The one genuinely absent capability, and the one with real blast radius.

**Scope (decision #19):** append-only, to a dedicated `## LEARNED` section, in
`hunt-*` skills only. It never rewrites existing prose. It never touches
`scope-policy`, the mapping skills, or anything outside `.claude/skills/hunt-*/`.

**A lesson requires three things** — the shape ARTEX arrived at in
`docs/rsi-lessons.md`:

```
lesson = {
  cue,              # the observable that should trigger this next time
  action,           # what to do when the cue appears
  evidence,         # >=1 finding id or ledger row id; zero evidence = no lesson
  disposition_key,  # the finding state this lesson is contingent on
}
```

**Retraction.** A lesson is contingent on its evidence. If a finding later moves to
`duplicate`, `informative`, `n-a` or is reversed on retest, the lessons that cited it
lose support and are retired. A lesson at zero support is removed, not kept. Without
this, a false positive becomes permanent doctrine.

**Landing procedure:**

1. write the diff
2. run the eval suite
3. a diff that breaks any eval **does not land** — it is recorded as a rejected lesson
   with the failing test named
4. a passing diff lands as **one git commit** tagged with the session id

So the undo is `git revert <session-commit>`, and `tests/test_recon_skills.py`'s
set-equality assertions (`:105-106`, `:112-113`) guarantee the skill set stays coherent
after any autonomous edit.

**What else the learn pass writes, outside skills:**

- engagement issues encountered and their fixes — the operator asked for this
  explicitly; it goes to `engagements/<id>/issues.md`, not into a skill
- new vault rows for precedent worth recalling later
- proposed new classes, as a note only — creating a skill is out of its scope

---

## 15. Prerequisites — all three are blockers

### 1. The Burp MCP schema bug breaks the payload generator

`opencode.json` currently has:

```json
"burp": { "url": "http://127.0.0.1:9876/mcp", "codemode": false }
```

Three of the server's 27 tools — `output_project_options`, `output_user_options`,
`get_active_editor_contents` — declare `inputSchema: {"type": "object"}` with no
`properties`. That is valid MCP. OpenCode's MCP→OpenAI converter emits
`properties: null`, and Ollama rejects it during chat-template validation with
`JSON schema error at #: properties must be an object`, returning 500 in 8-23 ms before
any inference.

**Consequence for this design:** payload generation no longer runs on Ollama (§10,
DeepSeek), so this bug does not touch the payload route. It still breaks any
Ollama-hosted model in the loop — e.g. the Qwen summarizer — and any agent session
whose catalog loads this project config. Run from the
project directory it fails every call. Verified A/B — from `/tmp` with no project config
it succeeds; from the project directory it retried 11 times and failed.

Fix before the first autonomous run: `"disabled": true` on the burp server for
autonomous sessions, or a normalising shim rewriting `properties: null` → `{}` in front
of Ollama. Testing `codemode: true` is worth one attempt first.

Note the existing permission rules are already correct for §10's read-only posture:
`burp_*` → `ask`, with `burp_get_proxy_*`, `burp_get_organizer_*` and
`burp_get_scanner_issues` → `allow`.

### 2. AC power settings

Current state: `sleep 180`, `powernap 1`, `displaysleep 180`, `disksleep 180`.

With no wall-clock ceiling (decision #18) a run may span days, and decision #13
requires the machine to keep testing with the display off. Required:

```
sudo pmset -c sleep 0 displaysleep 10 disksleep 0 powernap 0 standby 0
```

`sleep 0` is the load-bearing value — system never sleeps. `displaysleep 10` gives the
display-off behaviour that was asked for, and satisfies macOS's rule that display
timeout be lower than system timeout. The driver additionally holds `caffeinate -i`
for the run.

Related: `screenLock delay is 300 seconds`. The display sleeping will lock the screen
five minutes later. The browser keeps running when locked, but the extension path
should be exercised once with the screen locked before an unattended run depends on it.

### 3. Dedicated Brave profile

The Claude extension acts in the operator's real browser with real sessions. An
engagement profile, separate from personal browsing, with its own mail account signed
in for verification. Not the personal profile.

---

## 16. Failure handling

Decision #8: switch model, keep the push.

```
push fails
  |
  +-- model/provider error (timeout, schema, hold limit)
   |     -> bounded, configured fallback for that task only; payload generation
   |        has no configured fallback (docs/model-routing.md)
  |     -> log to engagements/<id>/issues.md
  |     -> continue the batch
  |
  +-- 429 / WAF challenge / lockout / CAPTCHA on one host
  |     -> that host moves to the todo list (debt kind: blocked-host, with a
  |        backoff hint); testing continues on other hosts (decision #21)
  |     -> never evade: no IP rotation, no WAF-bypass ladders, no slow-rate
  |        retries designed to slip under the block
  |
  +-- scope / rate / budget refusal
  |     -> NOT a failure. The engine said no.
  |     -> re-plan the push within limits; never route around the refusal
  |
  +-- skill missing for the class
        -> debt item moves to `blocked`, reason recorded
```

The distinction in the middle branch matters. A provider fault is transient and
switching models is correct. A scope or budget refusal is the system working, and
switching models to get a different answer would defeat the only thing bounding an
autonomous run.

Known fault signatures to log by name, all observed: the `properties: null` schema
error; `chunkTimeout` overrun during long prefill; meridian's
`SESSION_TURN_MAX_HOLD_MS` hold limit; Ollama's prompt cache lost on model unload.

---

## 17. State on disk

Nothing the loop needs lives in a model's context.

```
engagements/<id>/
  scope-parse.md          the bootstrap's reading, as confirmed
  debt.json               the reconciled debt list, rewritten each batch
  batch-NN.proposal.json  what was planned, before validation
  batch-NN.result.json    what happened, with evidence refs
  batch-NN.critique.md    the critic's verdicts and re-brief history
  issues.md               engagement issues and their fixes
  checkpoint.json         phase, batch number, ceiling consumption
  accounts.json           provisioned principals (referenced from scope.json)
```

Campaign state — scope, coverage, findings, ledgers, evidence — stays where it already
lives, in the campaign directory and `.recon/`. The orchestrator adds no parallel store
for any of it.

`checkpoint.json` is written after every phase, so a run resumes at phase granularity
after a crash, a compaction, or a machine restart.

---

## 18. Ceilings and stop conditions

Decision #18 (refined 2026-11-20): **50 req/s per host, 5,000 requests/hour
aggregate (rolling refill), no daily budget, no lifetime total, no wall clock.**

```json
"policy": { "max_rps": 50 },
"ceilings": { "requests_per_hour": 5000 }
```

`max_rps` 50 is the engine's own configurable upper bound (`campaign.py`), **not**
an independently safe default for every target. The hourly pool is a proposed
aggregate safety net, not currently enforced. The engine requires a finite
`max_campaign_requests` (≤1,000,000); exhaustion stops requests for that
campaign. Never roll into a fresh campaign just to evade that budget.
Program-published rate rules parsed at bootstrap always override these defaults.

The proposed loop stops/parks when:

1. the debt list is empty **and** there are no blocked items, or
2. the operator interrupts, a required approval/disclosure/cleanup boundary is hit,
   or a scope/rate/budget check refuses further requests.

The current offline reconciler does **not** claim that an empty coarse coverage,
matrix and chain list proves exhaustive class-case or per-field/surface testing.

No wall-clock bound. Two properties follow, recorded here so they are not a surprise
later:

- **Model spend is unbounded in time.** Re-brief and escalation loops consume tokens
  without consuming requests. A run can be cheap in traffic and expensive in inference.
- **A run can span days.** This is why §15's power settings are a blocker rather than
  a nicety.

---

## 19. Build order

1. **`engagements/` state layout + `checkpoint.json` read/write.** No models, no
   traffic. Everything else depends on resumable state existing.
2. **Debt reconciler** (§8) over the three accountings. Read-only against an existing
   campaign; verifiable against a campaign whose state is already known.
3. **Bootstrap parser + the one gate** (§5). Ends with operator confirmation and the
   `recon check` self-test.
4. **`recon push validate`** (§9.2) — the manifest schema and its eleven checks, with
   tests, before any planner exists to emit manifests. Built first so the planner is
   written against a validator that already rejects what it should.
5. **Batch planner** emitting `batch-NN.manifest.json`, validated and **not** applied.
   Manifests can be reviewed before anything is ever authorised.
6. **Executor** for one push, through `recon send` and `recon fact check`, refusing any
   push not covered by a current authorisation record. Single push, manually invoked.
7. **Critic** (§11) with the PoE rubric and the re-brief/escalate ladder.
8. **Loop**: plan → validate → authorise → execute → critique → analyse → re-plan,
   with the `caffeinate` assertion and checkpointing. First runs bounded by a small
   `requests_total` regardless of §18.
9. **Account provisioning** (§13), after the loop is trustworthy.
10. **Learn pass** (§14), last. It writes to skills, so it lands only once the evals it
    must pass are themselves exercised by the loop.

Before step 6's first **CVE-dependent** push, implement §22's source-qualified
feed sync/freshness gate and §21's offline playbook selection. Test both against
fixtures first. Feed refresh is third-party intel traffic, not a target test;
it requires its own bounded provider access. Steps 1-5 send no target traffic.
Step 5 produces reviewable manifests without executing them, which is the
natural point to check the planner's judgement before granting it autonomy.

---

## 20. Open items deliberately left out

- **Timing predicate.** `factcheck.py` is `response-predicates-v1` with four
  content-only predicates. `plans/rce.md` §12 proposes `duration_exceeds`. Until it
  exists, §9.2 check 4 rejects a timing-only push **at plan time**, which is the right
  failure point — better than executing it and discovering the evidence cannot be
  bound. Not this plan's work.
- **Callback host scope validation.** `collaborator` appears in `brief.py`,
  `catalog.py` and `csrf.py`, never in `scope.py` or `policy.py`. Also specified in
  `plans/rce.md` §12.
- **New class creation by the learn pass.** Out of scope by decision #19; proposals are
  written as notes.

---

## 21. Technology-conditioned playbooks

**Status: planned, not a running dispatcher.** `fingerprint.py` already records
stack tags and static `PACKS`; `vulnintel.py` extracts some versions. Neither
executes the table below as a five-push hunt. Add a source-qualified technology
record per **origin and component**, with the exact response/import/asset reference,
observation time and `observed | imported | static-reference | inferred` basis.
An edge banner is not an origin version; a JS reference is not a deployed server
feature. New evidence changes the next *planned* batch, not the campaign's scope
or permissions. All scanner-shaped work needs an explicit standing scanner plan
with tool/version, exact scoped targets, methods, pacing, shared budget and stop
conditions. An installed scanner or API token supplies no traffic grant.

| Signal | Conditional extra work after scope/method review | Do **not** infer |
|---|---|---|
| **WordPress**: observed WP routes/generator, then independently identified core/plugin/theme versions | Check REST, admin/login, media, plugin and XML-RPC surfaces as below; compare exact component versions to WPScan/vendor advisories | A public username or accepted XML-RPC POST authorizes password attacks; a plugin URL proves its installed version |
| **nginx**: attributed `Server`/config signal | Compare in-scope alias/route and auth path behavior with a matched control; map a **verified** nginx version to advisories | An edge nginx banner identifies the backend, or a version alone proves a path flaw; no request-boundary/smuggling traffic is implied |
| **JavaScript/Node**: bundle/map references, Express/Next.js evidence | Existing `jsharvest`/`jsparse`/`mapparse`, source-qualified hidden routes and npm package advisories; input-specific authz/prototype-pollution review on owned writes if granted | A source map or client dependency proves the server runs the same version or exposes a reachable sink |
| **Go**: source/manifest or strong framework evidence | Compare exact routed paths and normalization at an auth boundary; map actual Go modules or runtime versions when supplied | A generic Go error identifies a module version; HTTP/2 support licenses desync testing |
| **AWS**: in-scope storage/identity refs, owner-supplied cloud artifacts | `recon cloud` offline reference triage; conditional `hunt-takeover` and `hunt-ssrf` handoff under their own grants | S3/Cognito IDs prove ownership, public write, credentials or metadata access; a wildcard web scope covers provider namespaces |
| **Cloudflare WAF/CDN/DDoS**: `cf-ray`/edge response | Distinguish edge from origin, record `recon waf` behavior, review *offline* `hunt-cache` evidence; passive history only for possible origin names | A Cloudflare challenge is a bypass invitation; historical IP or certificate name is in scope; CDN headers establish cache poisoning |
| **Python**: observed Flask/Django/Werkzeug clues or source | Debug/error disclosure review; per-field render candidate to `hunt-ssti`; exact parser/worker sink to `recon rce declare` | A Python banner proves Jinja/pickle execution, or a debug page authorizes console access |

### WordPress decision path (no blanket scan)

1. **Identify deployment and source.** Correlate current observed paths,
   generator/version evidence, plugin slugs, theme and related response IDs.
   Enumerate only scoped paths and bounded public pages. A media thumbnail or
   `/wp-json/wp/v2/media` response is an input/publication lead; inspect owned
   objects and their variants rather than sweeping IDs or collecting other
   users' data. Public usernames from REST or author redirects do not become
   targets for credential guessing.
2. **Optional WPScan.** With the approved external-scanner plan, run only the
   configured safe enumeration checks and account for its requests alongside
   browser/Burp/native sends. Pass its API token through a protected environment
   or secret store; never put it in the campaign, command history, logs or a
   model prompt. WPScan's vulnerability DB is a valuable *advisory source*;
   detection mode and plugin/theme version confidence must be captured, not
   upgraded to certainty because a scanner printed them.
3. **XML-RPC.** If `xmlrpc.php` is in scope, record GET behavior and, **only if
   POST is granted**, one bounded non-authenticated method-discovery request.
   `system.listMethods`/`system.multicall` advertised or a 200 POST means a
   reachable interface, **not** a login bypass. Route `pingback.ping` to the
   grant-gated `hunt-ssrf` only for an approved owned receiver. Any XML-RPC
   credential check is limited to operator-owned accounts and a small declared
   attempt count; stop at 429, CAPTCHA or lockout. No multicall amplification
   or guessing against harvested usernames.
4. **wp-admin.** Map access control, reset/session behavior, and the scoped
   login operation with owned test accounts. Do **not** brute-force wp-admin or
   XML-RPC with discovered user names; exposure and username enumeration are
   separate leads, not a credential-testing grant.
5. **Advisory handoff.** Match exact core/plugin/theme slug **and version** to
   affected range, prerequisite and fixed release; leave `version-unknown`
   unresolved. A WPScan match or `recon lookup` lead is not an exploited CVE.

### Playbook acceptance checks

Test with offline fixtures for WordPress behind Cloudflare, nginx as the edge
only, JS-only Go/Python mentions, imported-but-unconfirmed plugin versions and
multiple scoped origins. Assert that tags retain their sources, no cross-origin
version inheritance occurs, blocked hosts are excluded from new pushes, scanner
requests are never dispatched by a static pack, and no playbook changes scope.

## 22. CVE freshness, matching and exploit-reference review

**Current state:** `recon lookup` uses local SearchSploit if installed, optional
Sploitus, and the CISA KEV JSON with a 24-hour *cache lifetime*. It creates
`known-cve` **leads** from product/version sightings and exploit-title text;
KEV matching is by product alias with **version applicability unchecked**.
It does not ingest NVD, GitHub advisories, WPScan or vendor feeds, verify a
15-day completeness window, or search a Metasploit module index. A 24-hour
cache policy is not a proof that every CVE was retrieved or that a feed is fresh.

### Proposed `recon cve sync|status|match` (not implemented)

1. **Declared sources.** Build a historical NVD CVE baseline with complete
   pagination, then incremental `lastModStartDate`/`lastModEndDate` windows
   (at most 120 days per NVD's API), with overlap/backfill for delayed edits.
   Pull the complete CISA KEV JSON for exploitation priority, not CVE
   completeness. Paginate GitHub global security advisories by `modified`
   for supported package ecosystems; retain GHSA-only entries separately from
   CVEs. Add WPScan/vetted vendor advisories for WordPress core/plugins/themes.
   Respect source terms, authentication and provider rate limits; these are
   **third-party intel requests**, never target scan authorization.
2. **Provenance and checkpoints.** Per source and interval persist the URL/API
   version, `fetched_at` UTC, latest source update, page counts and
   `totalResults`, hashes, cursor/high-water mark, validation result and error.
   Advance a watermark only after **every** page in that interval validates;
   failed/rate-limited pages remain explicit gaps and retry with provider
   backoff. Deduplicate by CVE/GHSA ID while preserving source revisions,
   withdrawn/rejected states and vendor references. An HTTP 304 may keep a
   validated prior snapshot, but cannot repair a missing initial baseline.
3. **Freshness gate.** Aim for a successful daily sync; show a visible warning
   when the oldest required source is **over 10 days** old. At **over 15 days**,
   *or with an incomplete baseline, pagination gap, failed validation or unknown
   watermark*, mark CVE-driven planning `degraded` and park CVE-dependent
   pushes. Continue non-CVE work under the campaign policy. `status` must show
   each source's exact age, interval coverage and reason rather than one green
   boolean. This is a guarantee about **our checked sources**, not a promise
   that every newly assigned or embargoed CVE is already published by them.
4. **Affected-version matching.** Normalize component identity and ecosystem
   (nginx edge vs origin, WordPress plugin slug vs core, npm/PyPI/Go module vs
   a client bundle); preserve version evidence and uncertainty. Use NVD
   configurations/CPE criteria including AND/OR and version bounds, GHSA
   package ranges and vendor/WPScan affected-and-fixed releases. Check route,
   feature, authentication and configuration prerequisites. A product-only KEV
   hit, banner or exploit title is `candidate/unverified`, **never** an exact
   vulnerable-version match. Unknown version remains `unresolved`, not safe.
5. **Research a matched CVE.** Start with the vendor advisory, patch and
   write-up. Then search the **exact CVE ID** independently in Rapid7's
   Metasploit module references, Exploit-DB/SearchSploit and relevant GitHub
   repositories; service-version search is a secondary lead. Record module
   name/commit/date, affected range, prerequisites, reliability and any
   side-effect/DoS warning. SearchSploit is **not** a complete Metasploit
   module map. Treat retrieved code and README instructions as untrusted data;
   do not run PoCs as-is or use an LLM's proposed payload as authority.
6. **Controlled validation, not automatic exploitation.** If an exact scoped
   operation, program permission, method grant, safe proof and shared budget
   all exist, plan one class × surface push for the underlying bug class. The
   future DeepSeek V4.1 Flash route may draft a context-fit probe, but no
   provider adapter or autonomous executor exists yet. Keep observed response
   IDs, before/after, replay, distinct negative control and cleanup. `known-cve`
   remains a finding-only lead; a version match or a public PoC alone never
   promotes severity or finding state.

### CVE pipeline acceptance checks

Use offline feed fixtures for multiple pages, revisions, overlap, 304, 429,
withdrawals, GHSA without CVE, one missing page, contradictory version
ranges, ambiguous WordPress slugs, edge-vs-origin mismatch and an unknown
version. Tests must prove that a missed page or a >15-day feed blocks only
CVE-dependent planning and never silently treats a scanner title as proof.

## 23. Per-field validation, security posture and chain-driven depth

The `hunt-security-misconfig` skill is wired to `security-misconfiguration` coverage
rows on auth paths and explicit `security_review=true` assets; config-like paths
also seed candidate reviews. The **offline** `authpolicy.py` case ledger now
organizes exact entry points under that existing class; it does not create a
second `auth-policy` class or a new report label.

**Chaining exists today as an evidence-gated graph.** `recon chain status` reads
findings and `CHAIN_HINTS`: XSS → ATO/CSRF/access control; IDOR → ATO or role/tenant
access; mass assignment → access control; SSRF → metadata → controlled cloud access;
file upload → XSS; CSRF → ATO; SQLi → ATO; info disclosure → access; and the new
security-misconfiguration → ATO/CSRF/info-disclosure edges. The reconciler only
queues reachable chain frontiers (a proven predecessor or open lead), and a
`confirmed` finding still requires replay and a distinct negative control. A
complete chain's impact still needs the realism gate. There is **no automatic
chain executor, severity uplift or reporting** in this implementation.

**One safe field, workflow or render is not all fields, workflows or renders.** Use
`recon inputs` and `recon fields sync|matrix|canary|trace|packet` separately for
first/last/full name, address, comment, password and other actual parameters, per
method, account and surface. For password policy on owned test accounts: compare
the weak value through the UI to a compliant UI value swapped *in transit* on
that same operation, then test independently on the reset-with-token submission
and change/invite flows; a forgot-password request is not a password-setting
operation. Test newer-token/OTP invalidation with two owned issuances; compare
logout back-button behavior to a **fresh, approved server request** with the old
session. Stock campaign templates exclude `/logout` and `/signout`; explicit
written scope review is needed before testing those paths.
Weak policy, missing rate-limit header and sequential IDs stay leads absent a
demonstrated consequence. NTLM challenges and ASP.NET error/viewstate/config
signals are posture cues; clickjacking requires an owned browser action, not just
missing `frame-ancestors` or `X-Frame-Options`.

For XSS, map the exact field's output context and prove execution or an owned
security effect before chaining; a pop-up is not takeover, and `HttpOnly` cookies
cannot be read by script. Public references (PortSwigger, PayloadsAllTheThings,
GitHub) are untrusted research inputs, not default payload lists or automatically
run PoCs. The proposed DeepSeek V4.1 Flash route is not yet a live adapter; never
silently substitute a local model. Only operator-owned accounts and disposable
resources may be used to demonstrate sensitive chains.

### 23.1 Auth-policy adoption — implemented offline, not an executor

`plans/auth-policy.md` contributed a sharper per-rule/entry-point and
event → credential invalidation matrix. Its proposed *new class* was rejected:
`security-misconfiguration` already seeds auth routes and has ATO/CSRF/
info-disclosure chain hints. `recon authpolicy sync` reads **only already observed
or asset-declared methods**; `declare` records an exact scoped method, entry point,
account, role, tenant, workflow and representation. Signup GET cannot clear signup
POST; each sourced password field × rule kind × rule value gets its own case,
and a rule with no source cannot be labelled `observed`. Forgot-password
*request* is not a reset-with-token submission. `plan|status`
show untested cases and `record|verify` store hash-bound, operator-labelled
stored-response contrasts (baseline/test/control plus readback or invalidation
event/old session/control). An observed receipt is **not** a finding or validated
proof; no operation automatically changes coverage or finding state.

`fields constraint` separates HTML/JS, OpenAPI/schema, operator-stated and
response-rejection **claims**. It does not extract client validators automatically,
or infer a server rule from a 400/200. `fields surface-expect` declares expected
field × surface × case × account/workflow coverage. `surface-review` links a
complete, already captured matching canary response or records justified n-a;
blocked/unreviewed/stale cells keep the full *declared* render claim closed.
An empty surface inventory remains **unknown**, even if the older trigger-only
`matrix` is full. The engagement debt reconciler includes both new dimensions;
`push validate` binds an auth-case debt item to its exact asset/URL/method, but
`--apply` remains an offline receipt and `recon send` does not consult it.

`authpolicy derive` transiently reads at most ten samples from a mode-0600
campaign-local `.recon/private/auth-policy/` input on at least two declared owned
accounts. It records only coarse structure and a source-file checksum, **not**
passwords, raw tokens, IDs, value hashes or a prediction. The source is not
retained/rehashable by the ledger; `verify` checks retained metadata integrity,
policy and any stored response snapshots, not the original token values.
Recognizable formatting or monotonic IDs remain leads until a separately
approved, held-out owned-account prediction and real security effect are proven.

**Still not built:** browser control, a connected per-push executor, independent
semantic proof validation, automated client-constraint extraction, completeness
for surfaces no source ever declared, token use/prediction, shared external-traffic
accounting and unattended model routing. No live policy, rate-limit, session or
logout tests were run in this implementation. Any later live exercise needs
written scope, method, account and budget approval; a cached Back page, status
code, session design choice or accepted input alone is not a reportable bug.

## Sources

- The engine itself — `recon --help`, `recon/score.py`, `recon/findings.py:5-11`,
  `recon/fields.py`, `recon/chain.py`, `recon/factcheck.py:19-22`, `recon/skillmap.py`,
  `AGENTS.md`
- `plans/rce.md` §11-12 — the PoE ladder and evidence roles used by the critic
- ARTEX `docs/rsi-lessons.md` — the lesson shape and retraction-on-reversal rule
- PentAGI `full_execution_context.tmpl:15` — callback state lost to context
  compaction, the reason loop state lives on disk
- Measured this session — local Qwen 10.5-12.5 tok/s generation, 80-113 tok/s prefill;
  the `properties: null` A/B; `pmset` state; Brave extension
  `fcoeoabgfenejglbffodgkkbkcdhcgfn` v1.0.107
- Official CVE/advisory contracts reviewed for §22: [NVD Vulnerability APIs](https://nvd.nist.gov/developers/vulnerabilities),
  [GitHub global security advisories](https://docs.github.com/en/rest/security-advisories/global-advisories),
  [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
  [WPScan vulnerability DB API](https://wpscan.com/api),
  [Rapid7 module search](https://docs.rapid7.com/metasploit/modules).
