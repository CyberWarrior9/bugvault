# Model Routing Policy

> **Status: operator-approved policy. Not an implementation.** No router, gateway,
> provider adapter or audit trail exists in code yet. This document records the
> decisions already made and the contract any future implementation must satisfy,
> so routing is designed once — not improvised per component.

---

## 1. Operator decisions on record

| Decision | Value | Date | Source |
|---|---|---|---|
| Payload generation primary | **DeepSeek V4.1 Flash** | 2026-11-09 | Operator (session decision) |
| Payload generation fallback (option 2) | **DeepSeek — exact variant unspecified** | 2026-11-09 | Operator: "keep deepseek as option 2 fallback from v4.1" |
| Routing enforcement | **Deterministic code, never model-decided** | 2026-11-09 | Design discussion |
| Silent cross-model substitution | **Forbidden for payload tasks** | 2026-11-09 | Design discussion |

The fallback slot stays **unconfigured** until the operator names the exact alternate
model. No substitute is guessed and no default is invented. When named, it should be
recorded here as a new row in this table — with the exact provider route/model ID.

One candidate route observed available in the development environment (NOT wired to
BugVault): `opencode/deepseek-v4.1-flash-free`. Its availability in one environment
is not an integration.

## 2. Role assignments

Roles are **logical responsibilities**, not concurrently-running agents. Assignment
principle: deterministic code does everything that can be done deterministically;
models are used only where reasoning is genuinely required, and each gets the
narrowest task that reasoning needs.

| Responsibility | Assigned to | Rationale |
|---|---|---|
| Scope, budgets, permissions, routing itself | **Deterministic code** | Must never be model-decided; current enforcement in `recon/campaign.py`, `net.py`, `egress.py` |
| Retrieval / context assembly | Code first (`recon/recall.py`); optionally local Qwen for summarization later | Lexical recall is already deterministic and provenance-linked |
| Investigation planning | GLM or an OpenAI model — **chosen by evaluation, not yet benchmarked** | No live adapter exists; `recon/planning.py` provides the offline proposal boundary |
| **Payload generation** | **DeepSeek V4.1 Flash primary → DeepSeek fallback** | Operator decision (§1) |
| Candidate/evidence review | A **separate model family** from the generator + deterministic checks | Validator brief already specifies family separation as a requirement |
| Target requests | **Constrained executor, never an LLM** | Scoped GET/HEAD client exists; payload-testing executor does not |
| Report writing | A reporting model restricted to validated evidence artifacts | Reporter brief exists; no model behind it |

Roles not yet implemented anywhere: summarizer, planning model, payload generator,
independent reviewer, reporting model. Roles implemented in code: scheduler,
retrieval, context export (`fact context`), proposal validation, executor (GET/HEAD).

## 3. Routing table (target state)

| Task type | Primary | Fallback | Fallback trigger |
|---|---|---|---|
| `payload.generate` | DeepSeek V4.1 Flash | DeepSeek (TBD) | §4 rules only |
| `plan.propose` | TBD by evaluation | TBD | §4 rules |
| `review.candidate` | Separate family, TBD | TBD | §4 rules |
| `summarize.context` | Local Qwen (TBD) | none — degrade to raw lexical recall | Task skipped, not rerouted |
| `report.draft` | TBD | none — human writes it | Task skipped |

Deterministic stages (scope check, context assembly, fact verification, execution,
evidence gating) have **no model and therefore no fallback** — they succeed, fail, or
block. A policy/budget failure must **never** trigger model fallback; that would be
working around a control (mirrors `recon/reliability.py` semantics for intel providers).

## 4. Fallback trigger rules (deterministic, code-enforced)

Adapted from plan4 §8 and PentAGI's observed failure modes
(`docs/pentagi-analysis.md`):

1. **Schema validation fails** → one retry with the validation error appended →
   then next model in the chain for that task type.
2. **Timeout / rate limit / transport error** → next in chain; mark degraded;
   record provider-reported error verbatim.
3. **Refusal** → one technical rephrase (same model) → next in chain.
4. **PolicyViolation / BudgetExceeded / OutOfScope at any stage** → **stop**.
   No fallback, no retry, no alternate path. The operator resolves the block.
5. **Empty result** → NOT a failure. Distinct from error (see
   `recon/reliability.py` precedent). No fallback on a clean empty.

Maximum 2 attempts per model per task (matches the intel-provider bound), then the
task is marked `unresolved` — never silently rerouted to a third model.

## 5. Authorship audit contract (must exist before any payload runs)

Every model call goes through **one application-owned gateway** — no component
calls a provider directly. For `payload.generate` the gateway must record:

| Field | Purpose |
|---|---|
| `task_type`, `role` | Which job requested generation |
| `requested_provider`, `requested_model` | What routing selected |
| `provider_reported_model`, `provider_request_id` | What the service says handled it |
| `routing_policy_revision` | Hash of this document's machine-readable form at call time |
| `context_packet_sha256`, `prompt_sha256` | Exact inputs submitted |
| `output_sha256` | Exact bytes returned |
| `parent_artifact`, `transformations[]` | Any later component that edited the payload, with its own identity |

Enforcement consequences:

- The (future) executor accepts **only** payload artifacts linked to an approved
  `payload.generate` audit record naming the primary or the configured fallback.
- A planner writing a payload itself does not qualify. A generic "text model"
  response does not qualify. An unconfigured fallback slot means the task **fails
  closed** when the primary is unavailable.
- If any component post-edits a payload, the artifact records the editor; the
  original DeepSeek authorship is preserved as a parent, not overwritten.

**Assurance limit (must be stated in any UI/report):** gateway logs prove what we
requested and what the provider reported — not the provider's internal backend.
Rolling aliases and undisclosed upstream routing are recorded as uncertainty, never
presented as exact-version proof.

## 6. Context completeness gate (prerequisite for `payload.generate`)

Before the gateway forwards anything to the primary model, code must verify the
evidence packet:

1. Required fields present and evidence-linked — via `recon/factcheck.py`
   `require_supported()`: every included fact re-verified `supported` against its
   stored response, or the export is refused.
2. Scope/config snapshot current (scope revision matches `recon/planning.py`
   `scope_revision()`).
3. Observed vs. inferred vs. synthetic-UI bases explicitly labelled; synthetic
   observations never presented as backend responses.
4. Account/role/tenant/workflow context included and not pooled
   (`recon/report.py` context tables define the format).
5. No credentials or unnecessary personal data; cloud-disclosure approval for the
   campaign is an explicit separate setting that does not exist yet.

If the gate fails → task status `needs_context` → back to recon, **not** to the
model with a thinner prompt.

## 7. Implementation prerequisites (in order)

1. Machine-readable form of §1–§4 (a versioned JSON policy file; its hash is the
   `routing_policy_revision`).
2. The gateway + audit table (§5) with the primary route configured and the
   fallback slot either filled by the operator or left failing closed.
3. Context gate wired to `fact context` + scope revision (§6).
4. Independent reviewer stage (separate family) for candidates.
5. Constrained hunting executor (beyond GET/HEAD) + OS-level egress isolation —
   **before** any payload is ever sent to any target, demo or real.

Until all five exist, "DeepSeek designs our payloads" is a policy, not a capability.

## 8. What exists today vs. this document

| This doc says | Exists in code today |
|---|---|
| Deterministic scope/budget enforcement | ✅ `campaign.py`, `net.py`, `egress.py` |
| Deterministic fallback semantics (bounded retries, fail-closed on policy) | ✅ for intel providers only (`reliability.py`) — not for models |
| Context completeness gate (partial) | ✅ `fact context` re-verification; ❌ full packet schema |
| Model gateway + audit | ❌ none |
| Any provider adapter (DeepSeek or otherwise) | ❌ none |
| Payload executor | ❌ none |

## 9. Claude subscription transport check (2026-11-11)

Native Claude Code is installed and its `auth status` confirms an authenticated
Max subscription. It can be used interactively from the BugVault directory without
an API key; it is not wired into BugVault's gateway or scheduler.

The first attempt, `@life-ai-tools/opencode-claude@0.7.0`, failed the installed
OpenCode 2.2.6 plugin contract (missing `setup`/`effect` on its default definition)
and remains disabled.

The operator subsequently requested
[ianjwhite99/opencode-with-claude](https://github.com/ianjwhite99/opencode-with-claude).
Exact version **1.11.2**, with Meridian **1.79.0**, is now installed and loaded.
Global OpenCode configuration routes the Anthropic provider through the plugin's
loopback-only proxy, using the existing native Max login and a dummy local API-key
placeholder. Ollama, the current/default model, and account profiles were preserved;
credentials were not manually copied or exported.

Verification: plugin ID loaded, listener at `127.0.0.1:3456`, health reports
authenticated Max / passthrough mode. An archived session in an empty directory,
requested as `anthropic/claude-sonnet-5-5`, returned `CLAUDE_CONNECTION_OK` with no
tool calls. This is text-transport verification only, not an end-to-end BugVault
agent test or proof of the provider's internal model backend. Native OpenCode
catalog cost estimates are not subscription billing guarantees.

This integration is **unofficial**. It rewrites some system-prompt fingerprints and
is trusted with the existing login; Anthropic's
[credential policy](https://code.claude.com/docs/en/legal-and-compliance#authentication-and-credential-use)
restricts third-party subscription-token routing. Technical success does not
establish compliance, provider support, or protection against account restrictions.
The native Claude Code CLI remains available separately. No account rotation,
network-wide proxy exposure, or change to target-testing permissions was configured.

This adds a transport to the interactive OpenCode harness, **not** a provider adapter
in `recon/`, the §5 authorship audit, DeepSeek routing, or automatic agent switching.
It does not relax the evidence, scope, disclosure, or reportability gates.
