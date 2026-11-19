"""Local-only, synthetic test declarations and redacted artifact helpers."""
import json
import hashlib
from pathlib import Path

from recon.campaign import Campaign
from recon.pipeline import Recon


def campaign(root, *, active=False, grants=False):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    data = {"program": "owned synthetic lab", "seeds": [], "in_scope": ["127.0.0.1"],
            "out_of_scope": [], "policy": {"mode": "active" if active else "passive", "max_rps": 5,
                                                  "allowed_methods": ["GET", "HEAD", "POST"] if active else
                                                  ["GET", "HEAD"], "max_requests": 30,
                                                  "max_campaign_requests": 30}}
    if grants:
        data.update({"program_url": "https://example.invalid/published-test-rules",
                     "business_logic": {"policy_reviewed": "2026-11-16", "families": ["BL-10"],
                                        "owned_accounts": ["a", "v"], "permits": ["state-changing"],
                                        "budget": {"requests": 12, "per_host": 12, "objects": 4}},
                     "race": {"policy_reviewed": "2026-11-16", "families": ["RC-03", "RC-08", "RC-21"],
                              "burst": {"max_parallelism": 4, "max_runs": 5, "max_points": 3}}})
    (root / "scope.json").write_text(json.dumps(data))
    return Recon(Campaign.load(root), log=lambda _: None)


def declaration(port=12345, policy="declared", contexts=True, family="BL-10", kind="coupon"):
    base = f"http://127.0.0.1:{port}"
    value = {"schema": 1,
             "workflow": {"key": "coupon", "revision": 1, "label": "synthetic owned coupon",
                          "policy_source": "owned-lab-contract-v1", "policy_status": policy,
                          "crown_jewel": "entitlement", "states": ["new", "used"],
                          "edges": [["new", "used"]], "requires": []},
             "operations": [
                 {"key": "claim", "url": base + "/claim", "method": "POST", "fields": ["coupon", "quantity"],
                  "transition": ["new", "used"], "checks": ["slot"], "consumes": ["slot"]},
                 {"key": "redeem", "url": base + "/redeem", "method": "POST", "fields": ["coupon"],
                  "transition": ["new", "used"], "checks": ["slot"], "writes": ["slot"]}],
             "resources": [{"key": "slot", "kind": kind, "owned": True, "shared": True,
                            "disposable": True}],
             "invariants": [{"key": "once", "rule": "at most one successful owned consumption",
                             "family": family, "resource": "slot", "oracle": "persisted-state",
                             "predicate": {"type": "at-most-count", "limit": 1},
                             "deadline_seconds": 30, "cleanup": "delete owned fixture"}]}
    if contexts:
        value["lab_contexts"] = [{"account": acct, "role": "tester", "tenant": "owned",
                                  "session": "s" + acct} for acct in ("a", "v")]
    return value


def artifact(root, name, text):
    path = Path(root) / name
    path.write_text(text)
    return name


def evidence(root, marker, control_marker, *, count=2, suffix=""):
    return [f"before={artifact(root, 'before'+suffix+'.txt', 'owned fresh ' + marker)}",
            f"after={artifact(root, 'after'+suffix+'.txt', 'owned effects ' + str(count) + ' ' + marker)}",
            f"oracle={artifact(root, 'oracle'+suffix+'.txt', 'authoritative owned effects ' + str(count) + ' ' + marker)}",
            f"control={artifact(root, 'control'+suffix+'.txt', 'owned effects 1 ' + control_marker)}"]


def event(root, context, marker, *, outcome="observed", count=2, suffix=""):
    control = "ctrl_" + hashlib.sha256(marker.encode()).hexdigest()[:20]
    return {"context": context, "invariant": "once", "case": "BL-10", "outcome": outcome,
            "impact_tier": "T1", "marker": marker, "control_marker": control,
            "control": "atomicity", "objects": 1, "object_ref": "owned-fixture-" + marker,
            "attacker_gain": "one extra owned synthetic grant",
            "next_play": "P1-entitlement-action",
            "projections": {"effects": count}, "control_projections": {"effects": 1},
            "baseline_projections": {"effects": 1},
            "facts": {"committed": "yes", "effected": "yes"},
            "artifacts": evidence(root, marker, control, count=count, suffix=suffix)}
