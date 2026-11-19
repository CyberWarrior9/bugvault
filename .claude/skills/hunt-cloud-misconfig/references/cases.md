# Case cards (proposed families; only offline event recording is implemented)

Every card is scoped by `(provider, scope, principal/session, operation,
resource/version, context, policy snapshot)`. `CM-00..CM-18` are taxonomy
labels, not automatically executed checks or provider-certified behavior.

| Card | Candidate boundary | Defeating control / next proof |
|---|---|---|
| CM-00 | Source and owner binding | Shared provider hostname or cloud IP alone identifies no owner |
| CM-01/02 | List/read versus write/overwrite/delete | Separate operations; public-by-design object, signed request, object ACL, explicit deny, versioning; safe owned canary readback |
| CM-03 | Signed URL/SAS lifetime, method, object or audience | Bound delegation might be intended; do not relabel it anonymous |
| CM-04/12 | Public service/network exposure versus data/function authz | Reachable port and successful health check do not prove unauthorized data |
| CM-05/06/14 | Effective IAM/RBAC/trust/org controls | Session conditions, explicit denies, source identity and downstream KMS/key policies may defeat an apparent allow |
| CM-07/08/09 | Workload/browser/federated identity or metadata | Public RUM/Cognito/Firebase config is not a credential; identity-only receipt is not access to a resource |
| CM-10/11 | Secret references, backup, registry, state, snapshots | Existence or metadata is not value read; owned synthetic content and actual consumer needed |
| CM-13 | CDN/origin/CORS/cache | Header allowlist is not a credentialed browser read or cached private response |
| CM-15/16 | CI/artifact consumer or stale dependency | Stored bytes are not consumed; bind exact digest, trigger and runtime identity |
| CM-17/18 | Observability, root-cause grouping, replay/cleanup | Missing logs need complete observer scope; no status code alone is impact |

The full [family matrix](../../../../reports/Cloud%20misconfiguration%20hunting%20plan.md)
is a research plan, not a test list already completed. Do not assume current
Azure/GCP defaults from the secondary website; primary reviews are still pending.
