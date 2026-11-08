# KB Expansion Pipeline — Ingesting External Knowledge

> How new knowledge (an X post, a writeup, a disclosed report) enters the vault:
> extraction, validation, testing, and write-back. Nothing enters the vault
> unvalidated; nothing is marked true without a reproduction.

## The pipeline

```text
X post (paste or URL)
   |
[99-Inbox] raw capture          <- git commit #1 (even the raw paste is versioned)
   |
AGENT 1 - EXTRACTOR (local 30B)
   parse -> structured JSON: {class, stack, payload, steps, version claims, bounty, source}
   taxonomy crosswalk -> canonical class
   DEDUP PROBE -> semantic search vault + reports.csv + 35-Report-Studies
   |
   +- duplicate? -> link to existing note, add variant note, STOP
   +- novel?
TRIAGE GATE (deterministic score, no LLM)
   novelty x applicability x actionability
   low  -> saved as status:unverified stub (30 seconds)
   high -> continue
   |
AGENT 2 - VERIFICATION PLANNER (hosted reasoning model)
   lab plan: environment, steps as executor actions, expected observations,
   pass/fail criteria, version matrix
   |
TEST HARNESS (deterministic - plan4 executor/observer/classifier, zero LLM)
   spin up lab -> run steps with canary markers -> classify outcome
   |
AGENT 3 - SKEPTIC (Claude, only for playbook-mutating writes)
   challenges evidence, version claims, impact inflation
   |
AGENT 4 - LIBRARIAN (local 30B)
   writes notes, links, updates playbooks/MOCs -> git commit #2 (atomic, diffable)
   |
Vault expanded -> next session-start auto-loads it
```

## The status ladder

Only test outcomes move an entry's status:

| Status | Meaning | Set by |
|---|---|---|
| `unverified` | parsed from source, not tested | Extractor |
| `lab-reproduced` | confirmed in our sandbox | Test harness |
| `field-confirmed` | found + 7-Q-gated on a real authorized engagement | Classifier + gate |
| `refuted` | test failed, with reason (fixed in vX, requires config Y) | Test harness |
| `stale` | previously worked, re-test failed (evasion techniques rot) | KB-health job |

A refuted entry with a reason is as valuable as a confirmed one — it stops
re-testing dead techniques during campaigns.

## What gets written (fan-out)

One good post typically touches 2-4 notes, never creates orphans:

1. `40-Payloads/<name>.md` (new) — the payload, context requirements, status, source
2. `30-Bug-Classes/<class>.md` (updated) — new row in the technique table
3. `50-WAF-Bypasses/<waf>.md` (updated, if an evasion claim reproduced)
4. `70-Tools/<stack>.md` (updated, if version claims survived testing)

Every write links up (class), sideways (stack/payload), and down (source).

## Testing — three tiers

| Tier | When | How |
|---|---|---|
| Lab reproduction | Self-hostable / general techniques | Docker spin-up at claimed version -> executor actions -> canary markers -> classifier verdict |
| Field validation | Target-specific claims | Becomes a prioritized hypothesis queued when a matching stack appears in an authorized campaign |
| Re-validation | Evasion techniques (they rot) | Quarterly KB-health re-test; demote to `stale` on failure |

A claimed WordPress XSS bypass takes ~10 minutes to verify against a local
container; the version metadata captured (works on 6.4, dead on 6.5) is what
makes the KB trustworthy during engagements.

## Agent roster

**4 LLM roles + 1 deterministic harness:**

| # | Agent | Model | Load |
|---|---|---|---|
| 1 | Extractor | Local 30B | Every post |
| 2 | Verification planner | Hosted (DeepSeek) | High-triage only |
| 3 | Test harness | None (deterministic executor/observer/classifier) | High-triage only |
| 4 | Skeptic | Claude (escalation) | Playbook-mutating writes only |
| 5 | Librarian | Local 30B (Claude fallback) | Every accepted post |

**Minimal bootstrap: 2 agents** — Extractor+Librarian as one local-model agent,
planner folded in, skeptic = human reviewing the git diff. The four-role split
is the growth path when volume makes human review the bottleneck.
