# Deep branches: impact ladder, chain mechanics and depth grants

Depth means following proven edges as far as the program's written rules allow. The
campaign's `ssrf.depth_grants` encodes that allowance once — granted branches
(`dns`, `internal`, `cloud`, `credential`, `protocol`, `execution`, or `["all"]`)
run at full depth with every destination still scope-checked; ungranted branches
report `grant-required`; an owned lab remains the default where no grant exists.
`ssrf plan` ranks `chain_next` from proven edges, so depth is systematic chain
following, not payload spray.

## Impact ladder

| Level | Primitive | Why it pays |
|---|---|---|
| 0 | Callback / DNS interaction | Chain edge only; informational alone |
| 1 | Response readback | Internal banners, API bodies, topology |
| 2 | Internal unauthenticated services | Grafana, Kibana, Jenkins, internal admin panels |
| 3 | Cloud metadata credential read | The critical watershed: private credentials |
| 4 | Credential → control plane | S3 read, DB snapshot, Lambda env vars, ECR pull, IAM chains |
| 5 | Non-HTTP protocol primitives | file-scheme reads; the gopher scheme writes arbitrary bytes to arbitrary TCP |
| 6 | Execution-equivalent | Internal script consoles, Docker/k8s/etcd APIs, Redis write primitives |

Severity follows the highest level actually **demonstrated and reproduced**, not
imagined. Levels 3–4 are where severity jumps to high/critical on most programs.

## Chain edges (what an observed case unlocks)

| Observed case | Unlocks |
|---|---|
| `fetch-control` | every parser/redirect/DNS/renderer/internal/cloud comparison |
| `attribution` | `blind-async` window work |
| `response-read` | `render-media`, `platform-chain`, `internal-auth` |
| `method-header-body` | `aws-imds`, `gcp-metadata`, `azure-metadata`, `cross-protocol` |
| any cloud case (`aws-imds`, `gcp-metadata`, `azure-metadata`, `container-other-cloud`) | `credential-use` |
| `internal-canary` | `internal-auth` |
| `file-protocol` | `credential-use` (configs/source read on the file path) |
| `cross-protocol`, `credential-use` | `execution-chain` |
| `credential-use` | `replay-report` |

What actually gates your maximum level — measure these on the base cases first:

1. **Scheme control** (http-only vs arbitrary) — gates file/gopher/dict work
2. **Method control** (GET vs full) — gates IMDSv2, internal POST APIs
3. **Header control** (none vs arbitrary) — gates GCP/Azure metadata entirely
4. **Body control** — gates POST-based internal protocol attacks
5. **Response readability** (blind vs readback) — blind needs the exfil tricks below
6. **Redirect handling** — validator-vs-fetcher revalidation at every hop
7. **Fetcher network position** — same host, worker subnet, or egress-filtered
8. **Error verbosity** — stack traces leaking internal topology

## Cloud metadata mechanics (`cloud` grant)

Confirm the affected worker's provider and deployment before touching any endpoint
from a cheat sheet; an address in a table is not a live service. Exact paths and
headers per provider (all in the vendor docs linked from `sources.md`):

| Provider | Endpoint and prerequisites | What credential-read gives |
|---|---|---|
| AWS IMDSv1 | `169.254.169.254/latest/meta-data/iam/security-credentials/` then the role path; GET only, no headers — plain SSRF reaches it | Temporary keys; role name reveals permissions |
| AWS IMDSv2 | PUT `/latest/api/token` with the TTL header, then GET carrying the returned token header — needs method **and** header control (gopher sink or header-injectable fetcher) | Same as v1; v1-disabled instances stop here |
| AWS ECS | `169.254.170.2/v2/credentials/<id>`; the ID comes from the task metadata, never guessing | Task role keys |
| GCP | `metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` with `Metadata-Flavor: Google`; also project metadata, attributes, ssh-keys | Service-account access token → project-level rights of that SA |
| Azure VM | `169.254.169.254/metadata/instance?api-version=...` with `Metadata: true` and no `X-Forwarded-For`; identity token from the identity/oauth2/token path | Managed-identity token; Key Vault reads are the classic critical cascade |
| Azure App Service | Different endpoint and header prerequisites from VM IMDS; establish the deployment shape first | App identity token |
| Alibaba / Oracle / others | `100.100.100.100/latest/meta-data/` (Alibaba), `169.254.169.254/opc/v2/instance/` (Oracle) — frequently GET-only | Instance credentials; often forgotten and unguarded |

A 401/404 is a prerequisite answer, not a working chain. `method-header-body`
measured controls decide which provider cases are even viable before you start.

## Credential use ladder (`credential` grant)

`credential-use` activates when any cloud case records `observed`. Reading the
credential **is the finding** — record it, redact the secret itself in shared
context, store the raw capture privately. Then demonstrate unlock:

1. **Identity proof** — one idempotent who-am-I call (AWS STS GetCallerIdentity
   style): proves the key is live and names the principal, without side effects.
   Most programs accept exactly this and no more.
2. **Permission enumeration** — read the attached policies/role to see what the
   key can do (describe, not use).
3. **One consequential read** — the smallest action that answers the
   reportability gate: list bucket names, describe (not reveal) one secret, read
   one non-sensitive test object. Compare with an unauthenticated denial.
4. **Chain impact** — snapshot-to-attacker, role assumption, cross-service
   pivots: only where the program's rules explicitly allow, each destination
   scope-checked.

The line between "demonstrated unlock" (reportable critical) and "used the key"
(banned) is the program's, not the tooling's — which is exactly why it is a grant
you copy from their rules. Never persist credentials into cloud CLI profiles or
shared provider context.

## Host/port/protocol swap matrix

Swapping host, port, scheme and representation is the core SSRF technique, not an
extra permission — unlimited against your own controlled receivers; against
internal services under the `internal` grant.

| Control | Standard comparisons |
|---|---|
| Host | canonical name, IDN/Unicode, case/trailing dot, userinfo tricks, decimal/octal/hex IPv4, short forms, IPv6 compressed/mapped — one change per attempt against a receiver that logs the **actual** destination |
| Port | explicit ports on allowlisted hosts; port-bearing authority forms; what the validator strips vs what the fetcher dials |
| Scheme | http/https by default; file, gopher, dict, ftp, ldap, tftp under the `protocol` grant or owned lab — support is a fetch-library property, not a consequence of accepting the scheme string |
| Representation | encodings at the layer that actually decodes; path normalization; duplicate parameters; fragment/backslash separators |

Record accepted input **and** the receiver's dialed destination. Fetcher
libraries differ (Java URLConnection, curl, Go net/http, Python requests each
parse edge cases differently) — never assume one parser's result for another.

## Internal service triage (`internal` grant)

When an internal case is chain-ready, these are the classic high-value targets —
confirm each is in scope/supplied before any request:

| Service | Typical port | What it gives |
|---|---|---|
| Redis | 6379 | Write primitives: file write, module load — execution-equivalent under `execution` rules; state-changing writes need explicit program allowance |
| Docker API | 2375/2376 | Container create with mounted socket → host takeover |
| Kubernetes API / kubelet | 6443/10250 | Pod exec with a readable serviceaccount token |
| etcd | 2379 | Unauthenticated read → cluster secrets → cluster admin |
| Jenkins / GitLab | 8080/… | Script consoles; RCE-equivalent when unauthenticated or token-reachable |
| Elasticsearch / Memcached / Consul | 9200/11211/8500 | Data disclosure; scripting engines; service registration |
| Internal admin panels | any | Unauthenticated actions on the real application |

`internal-canary` first proves reachability on one exact destination with a
direct-access negative control; `internal-auth` then demonstrates the trust
boundary on supplied test resources. A banner or 200 is reachability, not impact.

## Blind escalation (no readback needed)

- **Error-based readback** — malformed URLs that make the fetcher throw exceptions
  echoing fragments of the internal response.
- **Redirect exfil** — an internal endpoint whose response (or a parameter in it)
  drives a 30x to your collaborator: turns blind read into an out-of-band signal.
- **DNS chunking** — data encoded across subdomain labels resolving to your
  receiver.
- **Timing oracles** — internal-state-dependent delay through the fetcher.
- **Blind protocol side effects** — the gopher scheme still lands writes while the
  response stays invisible; the receiver's own logs are your readback.

## Execution branch (`execution` grant or owned lab)

`execution-chain` activates after `cross-protocol` or `credential-use` is
observed. Owned lab by default; any target when the program's rules explicitly
cover execution proofs. Use an inert canary (idempotent, non-destructive) with a
fixed negative control, on the exact sink whose prerequisites you demonstrated.
The inert-canary discipline is about proof quality, not caution: a `whoami`-class
canary with a negative control is a complete, reproducible finding that survives
triage. SNI/TLS-routing hypotheses stay blocked with the present browser/MCP
(no arbitrary ClientHello) — record them rather than switching clients.

## Evidence and reporting

For every chain edge: fresh-token replay, distinct negative control, exact
timestamps, minimal demonstrated impact, and `finding link` for each proven edge.
The reportability gate (`recon/prompts/validator.md`) still decides
report/no-report: demonstrated person/test-account harm, platform harm, a private
credential actually unlocking a forbidden test resource, or a complete chain.
A permitted internal read does not need execution to be reportable; severity
describes what was shown at the highest demonstrated rung.
