"""Pure offline evidence triage for an *operator assertion*, never an RCE verdict.

No code or payloads are executed here. Even 'eligible-for-validator' only says that a
complete set of receipts meets syntactic/contrast rules. A human must establish actual
server execution, actor control, authorization and causal meaning.

**Live execution evidence is accepted** (decision D4, `plans/artex-adoption.md` §5.5).
A receipt may carry `channel: "live-target"` as well as `"owned-lab"`: command output
captured from an in-scope target, hash-bound, with the exact request recorded, proves
execution when a benign identity or marker command (`id`, `hostname`, `uname`, or
writing a unique marker and reading it back) appears in the response and in no request
or control. The bar does not drop with the channel — a live receipt needs the same eight
roles, three distinct markers, complete identity-encoded captures and strictly ordered
times as a lab one. What changed is that passing them is no longer refused for being
live.

`direct-output` and `owner-worker-log` remain the only effect channels that establish
execution. Callback, timing and processing do not, on any channel.
"""
from __future__ import annotations

from .callbacks import timestamp, valid_marker

#: Channels whose receipts may reach `eligible-for-validator`.
PROVING_CHANNELS = frozenset({"owned-lab", "live-target"})

REQUIRED = frozenset({"baseline", "trigger", "replay-request", "verification",
                      "negative-control", "positive-control", "effect", "cleanup"})
CHANNELS = frozenset({"direct-output", "owner-worker-log", "callback", "timing",
                      "processing", "unknown"})
STATES = frozenset({"blocked", "inconclusive", "negative", "observed", "execution-claimed"})


def assess(claim, artifacts, qualified):
    """Assess bounded captured *data*, not whether a server actually ran anything."""
    state, channel = claim["state"], claim["effect_channel"]
    if state != "execution-claimed":
        return {"assessment": "behavior-observed" if state == "observed" else state,
                "reasons": ["operator observation only"], "verification_eligible": False}
    reasons = []
    if claim["channel"] not in PROVING_CHANNELS:
        reasons.append("execution receipts come from an owned lab or a live in-scope "
                       "target; this channel establishes nothing")
    if not qualified:
        reasons.append("source-qualified sink and exact asset are required")
    if not claim.get("binding"):
        reasons.append("owned actor, worker and object binding is required")
    if channel not in ("direct-output", "owner-worker-log"):
        reasons.append("callback, timing or processing does not establish execution")
    needed = set(REQUIRED)
    if channel == "owner-worker-log":
        needed.update(("worker-log", "worker-replay"))
    missing = sorted(needed - artifacts.keys())
    if missing:
        reasons.append("missing roles: " + ",".join(missing))
    marker_set = claim.get("markers", {})
    if (not isinstance(marker_set, dict) or set(marker_set) != {"effect", "replay", "control"}
            or any(not valid_marker(x) for x in marker_set.values())
            or len(set(marker_set.values())) != 3):
        reasons.append("three distinct bounded owned markers are required")
    fidelity = claim.get("fidelity", {})
    response_roles = ("baseline", "effect", "verification", "negative-control", "positive-control")
    if (not isinstance(fidelity, dict) or any(fidelity.get(role) !=
            {"complete": True, "encoding": "identity"} for role in response_roles)):
        reasons.append("complete identity-encoded baseline, effects and control captures required")
    times = claim.get("times", {})
    try:
        if set(times) != {"baseline", "trigger", "replay", "negative", "cleanup"}:
            raise ValueError("missing attempt times")
        ordered = [timestamp(times[k]) for k in ("baseline", "trigger", "replay", "negative", "cleanup")]
        if ordered != sorted(ordered) or len(set(ordered)) != len(ordered):
            raise ValueError("attempt times not strictly ordered")
    except (ValueError, TypeError, KeyError, AttributeError):
        reasons.append("strictly ordered timezone-aware attempt times required")
    if not reasons:
        primary, replay, control = (marker_set[k].encode() for k in ("effect", "replay", "control"))
        if any(not artifacts[role] for role in needed):
            reasons.append("all required receipts must contain captured bytes")
        if artifacts["trigger"] == artifacts["replay-request"] or (
                artifacts["negative-control"] == artifacts["positive-control"]):
            reasons.append("fresh replay request and matched control captures must be distinct")
        if (primary not in artifacts["effect"] or replay not in artifacts["verification"]):
            reasons.append("effect and replay markers missing in their independent receipts")
        for role in ("baseline", "trigger", "replay-request", "negative-control", "positive-control"):
            if primary in artifacts[role] or replay in artifacts[role]:
                reasons.append("claimed output marker appears in a request or control: " + role)
        if (primary in artifacts["verification"] or replay in artifacts["effect"]):
            reasons.append("fresh replay marker is not independent")
        if (control not in artifacts["negative-control"] or
                control not in artifacts["positive-control"] or
                primary in artifacts["negative-control"] or replay in artifacts["negative-control"]):
            reasons.append("matched negative and healthy control lack distinct control marker")
        if channel == "owner-worker-log" and (primary not in artifacts["worker-log"] or
                replay not in artifacts["worker-replay"]):
            reasons.append("worker evidence does not bind both lab attempts")
        if (channel == "owner-worker-log" and
                artifacts["worker-log"] == artifacts["effect"] and
                artifacts["worker-replay"] == artifacts["verification"]):
            reasons.append("a response echo is not an independent worker log")
        if len({artifacts[k] for k in ("effect", "verification", "negative-control")}) != 3:
            reasons.append("effect, verification and negative must be distinct bytes")
    return {"assessment": "eligible-for-validator" if not reasons else "inconclusive",
            "reasons": reasons or ["lab receipts require independent semantic review"],
            "verification_eligible": not reasons}
