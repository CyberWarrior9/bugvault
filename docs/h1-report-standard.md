# The HackerOne Report Standard — Data-Grounded

> Derived from 10,094 disclosed reports (HackerOne's official dataset) with a deep
> anatomy pass over 52 top-voted, bounty-paid reports stratified across 14 classes.
> This is the standard the automated report agent (plan4 P7) must meet, and the
> calibration the 7-Question Gate checks against.

## Format — what paid reports contain

| Element | Top-52 bounty reports | Corpus-wide (bounty) |
|---|---|---|
| Impact section | **94%** | 53% |
| Structured repro (numbered / Steps-to-Reproduce) | ~70% | 35% |
| Code blocks | 56% (median 1) | 36% |
| Specific target URL | 69% | — |
| Raw HTTP request/response pairs | 15% direct (56% via code blocks) | 11% |
| PoC explicitly labeled | 37% | 31% |
| Screenshot/image | 23% | 13% |

HackerOne's own submission form enforces two fields:
- `vulnerability_information` — "steps to reproduce + supporting material + references"
- `impact` — "the security impact that an attacker could achieve"

The universal skeleton: **title → summary → steps/evidence → impact**.

## Quality — what separates paid from unpaid

1. **Impact framing is the strongest differentiator.** 94% of top bounty reports have
   an explicit Impact section vs 45% of informative reports. Median impact section:
   **26 words** — but concrete ("attacker can log in as victim").
2. **Demonstrated impact beats prose.** The most-upvoted report in the sample
   (#745324, 1,540 votes) is 250 characters with broken English — but proved
   staff-level access with a leaked session.
3. **Root cause + external reference** appears in the best RCE reports
   (ImageMagick policy.xml explanation + public advisory + /etc/hosts verification).
4. **Complete traffic evidence** is the gold standard for auth bugs: full
   request/response pairs per attack step, victim/attacker account structure,
   all sensitive values redacted.

## Quantity — how much is enough

| Report length | Bounty rate (resolved) |
|---|---|
| <300 chars | 69% (direct-impact demos only) |
| 300–1k | 52% |
| 1k–3k | 56% |
| **3k–10k** | **66% — the evidence sweet spot** |
| >10k | 49% (over-long, often low-severity) |

Median top report: ~2,100 chars / ~300 words, 2–4 numbered steps, 3 markdown
headings, 1 code block.

**The lesson:** length doesn't buy bounties — demonstrated impact + evidence
completeness does, with a floor of enough detail that a triager can replay the
finding without asking the reporter anything.

## Bounty rate by class (prioritization data)

Memory Corruption 84% · XSS-DOM 46% · Privilege Escalation 46% · HTTP Smuggling 44% ·
XSS-Generic 42% · Code Injection 41% · Improper Access Control 41% · Business Logic 38% ·
Open Redirect 38% · Command Injection 38% · XSS-Stored 36% · Improper Auth 35% ·
Crypto 34% · CSRF 33%

## The report template (for the P7 agent)

```markdown
# [Vuln class] in [component] leading to [business impact]   ← 46% name impact in the title

## Summary          (2-3 sentences: what + where + why it matters)
## Steps to Reproduce   (numbered, 2-7 steps, exact URLs/params/payloads)
## Evidence         (request/response pairs or payload + result, redacted)
## Impact           (1-3 sentences, median 26 words, concrete attacker capability)
## References       (optional: prior art, advisories)
```

The 7-Q Gate questions map 1:1 to what paid reports answer:
what can the attacker DO, what does the victim LOSE, can a triager reproduce
in 10 minutes.
