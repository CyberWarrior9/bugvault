# 10-Campaigns

One folder per engagement, created by `python3 -m recon init <name> --seed <domain>`.

| File | Who writes it | What |
|---|---|---|
| `scope.json` | you | THE authority: program in/out scope + `policy.mode` from the program rules. Enforced in code. |
| `recon.md` | `recon report` / `run` | surface inventory ranked by freshness, leads, policy-skipped work |
| `coverage.md` | `recon report` / `cov` | coarse endpoint-family × bug-class backlog; not security completeness |
| `intel.md` | `recon report` | out-of-scope discoveries, never contacted |
| `.recon/` | recon engine | SQLite state + raw response bodies (never commit) |

Campaign folders are gitignored (see `.gitignore`): they contain target data and this repo
has a GitHub remote.

See `recon/README.md` for phase/tool counts, offline scanner imports, account/role/tenant
capture contexts, deduplication rules and remaining DNS/egress isolation limitations.
