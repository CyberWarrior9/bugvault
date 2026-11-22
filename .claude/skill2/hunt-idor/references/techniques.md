# IDOR technique matrix, provenance and exclusions

## Request-shape variant matrix (stage 2)

One variation per attempt; repeat the A→A control whenever anything else
changes. These are request shapes, not payloads — the proof is always V's
marker in the response.

| Family | Variations | Notes |
|---|---|---|
| Location | path ↔ query ↔ body ↔ header; add the never-asked-for parameter (`/messages` → `/messages?user_id=<V>`) | The authz check often guards only the location the UI uses |
| Wrapping | array `{"id":[x]}`; object `{"id":{"id":x}}`; duplicate JSON keys `{"userid":A,"userid":V}`; HPP both orders `?id=A&id=V` then `?id=V&id=A`; `id[]=` forms | Different frameworks unmarshal the last/first differently — both orders matter |
| Type/encoding | numeric ↔ string ↔ UUID; base64-decoded opaque IDs; hashids-style IDs compared across several of your own objects to learn the scheme; extension swap (`/user_data/2341` → `.json`/`.xml`/`.txt`); content-type swap (JSON ↔ form ↔ XML) | Decode-first: an ID that decodes to an email or username tells you the object space |
| Alias paths | `/me/../<V-id>`; `/api/users/me` resolved then traversal appended; parameter-name swap on the same endpoint (`album_id` → `account_id`) | Works where `/me` is authorized by session and the rest of the path is normalized after the check |
| Method | every granted method on the same object path; override headers (`X-HTTP-Method-Override`, `_method`) where the program allows; GET-delete patterns (`GET /users/delete/<id>`) | A 403 on one verb is not a verdict on the object |
| Version | `/v3/...` → `/v1/...` siblings (the engine seeds these as version-sibling assets); outdated mobile-API hosts | Old versions predate the authz middleware |
| GraphQL | object/node IDs in variables; aliases/batches querying A's and V's nodes in one request; field-level authz vs node-level | Compare against the REST twin when both exist |
| Edge values | `0`, `-1`, null, empty, wildcard — on A/V-owned objects only | Sometimes bypasses existence checks, occasionally crashes them (that's a finding of another class) |

## Depth ladder summary

1. Direct horizontal swap (read, with marker + two controls)
2. Request-shape variants (matrix above)
3. Vertical (BFLA: function endpoints, unexposed methods) and cross-tenant
4. Write/delete IDOR (grants + disposable V objects; V observes the change)
5. Chain targets by object type (see SKILL.md table)

Skipping stages makes results worse, not faster: a write test before a read
proof cannot be interpreted, and most "patched" endpoints fall at stage 2.

## Provenance (0xN0RMXL/BugBountySkills, MIT, pinned)

Pinned commit `0accf5fdc71ec7f03273aebb99268a8609f8dfd4` (2026-04-25); root
licence MIT, blob `1ac4928622f501e16a036938433418bead16cf86`. Only IDOR files
were read. Technique ideas were adapted, not copied:

| File | Blob SHA | Used | Excluded |
|---|---|---|---|
| `CHECKLISTS/idor.md` | `e6f8cef68db2eb35b253acbf8eb4e0d988549a97` | sequential/UUIDv1 predictability, verb tampering, HPP, identity headers, tier pairs, BFLA, edge IDs | "enumerate users first" when no second account exists (never a substitute for a V account you control) |
| `CHECKLISTS/checklist_pack_2/IDOR Vulnerability/idor.md` | `d958e7c646181cc2e60a4996f53b443360c6086b` | parameter-name swap, add-missing-param, JSON/array/object wrapping, extension+content-type swap, traversal alias, old-version swap, decode-first | admin-path case swapping (`/aDmin`, a path-prefix bypass, not object-level); wildcard/global brute of hidden params (arjun/paramminer not integrated or dispatched here); unattributed example responses |
| `SKILL_FILES/VULNERABILITIES/WEB/idor_bola_bfla.md` | `27d41a5f249e1d938b687cf9c2724f1a7680df29` | "me"-alias, plural collection `?ids=`, mass-assignment adjacency note, chain section, not-a-bug trap | stated CVSS/severity ranges (unverified, not imported as fact); "UUID brute via timing oracle" (unsupported); `alg=none` JWT re-signing (that is the JWT skill's territory, linked via hunt-auth-bypass) |

`SKILL_FILES/PAYLOADS` contains no IDOR file (15 payload documents, none for
this class) — IDOR is identity substitution, not a payload-list vulnerability.
No other files from the repository were read for this skill.

## Not-a-bug traps

Public profiles by design, share links, signed/expiring URLs, and objects the
program's own docs declare public. The marker test resolves the question:
if V's private marker is what came back, it was a boundary; if the same data is
served unauthenticated, the finding is missing authentication (different class,
often lower severity, sometimes intended).
