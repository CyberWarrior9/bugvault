---
name: captured-auth-mapping
description: Import the operator's authorized HAR browsing into BugVault with separate account, role, tenant and workflow labels; deduplicate repeated captures and produce mapping leads without replaying requests.
---

# Captured authenticated mapping

Use operator-controlled canary accounts. Let the operator log in normally; do not guess credentials or automate MFA. Import offline:

```bash
python3 -m recon import-har <campaign> alice.har --account alice --role member --tenant team-a --workflow-state draft
```

Reuse stable, nonsensitive labels. Same file bytes and labels deduplicate; different labels remain distinct observations. Renaming the file does not create new samples. Distinct captures may legitimately contain similar requests.

Keep header/cookie values and bodies out of the operational import; retain parameter names and nonsensitive ID-shaped values. URLs/path identifiers and local raw HAR files can still be sensitive. Keep campaign artifacts private.

Output captured-context inventory, not an authorization verdict. Different object IDs across accounts are later-validation leads only. Implementation: `recon/har.py`, `recon/store.py`.
