"""Event-driven recon queue (ARTEX's planner idea, made deterministic and resumable).

A NEW asset triggers the next jobs for its kind; jobs persist in SQLite so a crashed or
interrupted run resumes where it stopped. Jobs that need a louder mode than the program
allows are marked `skipped` with the reason (visible in the report) and re-queued
automatically if the campaign's mode is raised later.

    domain   -> crtsh, wayback (passive) + host for the apex
    host     -> probe (active)
    service  -> wellknown, jsharvest (active); runtime once a SPA is detected
    js       -> jsparse (active)
    sourcemap-> mapparse (active)
"""
from __future__ import annotations

import ipaddress
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

from .campaign import Campaign, OutOfScope, PolicyViolation
from .extract import endpoint_key, is_static, looks_api, origin_of, query_keys, VERSION_SEG
from .net import BudgetExceeded, FetchError, PassiveClient, RateLimiter, RequestBudget, ScopedClient
from .score import applicable_classes, is_inferred_only
from .fingerprint import packs_for
from .store import Store

JOB_NEEDS = {
    "crtsh": "passive", "wayback": "passive",
    "probe": "active", "wellknown": "active", "jsharvest": "active",
    "jsparse": "active", "mapparse": "active", "runtime": "active",
}
ON_NEW = {
    "domain": ["crtsh", "wayback"],
    "host": ["probe"],
    "service": ["wellknown", "jsharvest"],
    "js": ["jsparse"],
    "sourcemap": ["mapparse"],
}
URL_KINDS = {"service", "endpoint", "js", "sourcemap", "route"}
MAX_JS_PER_ORIGIN = 300


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


class Recon:
    def __init__(self, campaign: Campaign, store: Optional[Store] = None,
                 log: Callable[[str], None] = print):
        self.campaign = campaign
        self.scope = campaign.scope
        self.policy = campaign.policy
        self.store = store or Store(campaign.db_path, campaign.bodies_dir)
        limiter = RateLimiter(campaign.policy.max_rps)
        budget = RequestBudget(campaign.policy.max_requests, campaign.policy.max_seconds)
        self.client = ScopedClient(campaign, self.store, limiter, budget=budget)
        self.passive = PassiveClient(campaign, self.store, limiter, budget=budget)
        self.log = log

    # ------------------------------------------------------------ asset intake
    def _in_scope(self, kind: str, value: str) -> bool:
        if kind in URL_KINDS:
            return self.scope.is_in(value)
        if kind in ("domain", "host", "ip"):
            return self.scope.host_in(value)
        return False

    def add(self, kind: str, value: str, source: Optional[str] = None,
            attrs: Optional[Dict[str, Any]] = None, in_scope: Optional[bool] = None) -> int:
        attrs = dict(attrs or {})
        if source:
            attrs["sources"] = list(attrs.get("sources", [])) + [source]
        if in_scope is None:
            in_scope = self._in_scope(kind, value)
        host = urlsplit(value).hostname if kind in URL_KINDS else value
        aid, created = self.store.upsert_asset(kind, value, host=host, in_scope=in_scope,
                                               attrs=attrs)
        if created and in_scope:
            for job in ON_NEW.get(kind, []):
                self.enqueue(job, aid)
        return aid

    def intel(self, value: str, note: str, source: str) -> int:
        """Out-of-scope discovery: recorded for the report, never contacted."""
        return self.add("intel", value, source=source, attrs={"notes": [note]}, in_scope=False)

    def enqueue(self, kind: str, asset_id: int) -> bool:
        return self.store.enqueue(kind, asset_id, JOB_NEEDS[kind])

    def add_endpoint(self, url: str, source: str, method: Optional[str] = None,
                     params: Iterable[str] = (), extra: Optional[Dict[str, Any]] = None
                     ) -> Optional[int]:
        try:
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https", "ws", "wss") or not parts.hostname:
                return None
            if parts.username is not None or parts.password is not None:
                return None
            key = endpoint_key(url)  # validates the port before touching state
        except ValueError:
            return None
        if is_static(parts.path):
            return None
        if not self.scope.is_in(url):
            self.intel(origin_of(url), f"endpoint host seen via {source}: {parts.path[:120]}",
                       source)
            return None
        method = method.upper() if method else None
        attrs: Dict[str, Any] = {"methods": [method] if method else [],
                                 "params": [p for p in params if p],
                                 "api_like": looks_api(parts.path)}
        attrs.update(extra or {})
        basis = attrs.pop("basis", None) or {
            "har": "captured-real-traffic", "runtime": "synthetic-ui",
            "version-sibling": "inferred", "js": "static-reference",
            "sourcemap": "static-reference", "inline": "static-reference",
        }.get(source, "discovered-reference")
        attrs["bases"] = list(attrs.get("bases", [])) + [basis]
        existed = self.store.find_asset("endpoint", key) is not None
        aid = self.add("endpoint", key, source=source, attrs=attrs)
        self.store.operation(aid, method, {"params": attrs["params"], "sources": [source],
                                           "bases": attrs["bases"]})
        self.store.variant(aid, method, parts.path, query_keys(url))
        if not existed and source != "version-sibling":
            self._version_siblings(key)
        return aid

    def _version_siblings(self, key: str) -> None:
        """/api/v3/users -> candidates /api/v1/users, /api/v2/users (NOT requested)."""
        m = VERSION_SEG.search(urlsplit(key).path)
        if not m or int(m.group(1)) < 2:
            return
        n = int(m.group(1))
        for k in range(max(1, n - 3), n):
            sib = VERSION_SEG.sub(f"/v{k}", key, count=1)
            if self.store.find_asset("endpoint", sib) is None:
                self.add("endpoint", sib, source="version-sibling",
                         attrs={"sibling_of": [key], "api_like": True})

    def service_for(self, url: str) -> int:
        origin = origin_of(url)
        found = self.store.find_asset("service", origin)
        return found["id"] if found else self.add("service", origin, source="derived")

    def add_seed(self, seed: str) -> None:
        if "://" in seed:
            self.add("service", origin_of(seed), source="seed")
        elif _is_ip(seed):
            self.add("host", seed.strip("[]"), source="seed")
        else:
            self.add("domain", seed.lower().rstrip("."), source="seed")
            if self.scope.host_in(seed):
                self.add("host", seed.lower().rstrip("."), source="seed")

    # ------------------------------------------------------------ run loop
    def run(self, max_jobs: int = 2000) -> Dict[str, int]:
        from . import active, runtime, sources  # local import: handlers import pipeline types
        handlers: Dict[str, Callable[["Recon", Dict[str, Any]], None]] = {
            "crtsh": sources.job_crtsh, "wayback": sources.job_wayback,
            "probe": active.job_probe, "wellknown": active.job_wellknown,
            "jsharvest": active.job_jsharvest, "jsparse": active.job_jsparse,
            "mapparse": active.job_mapparse, "runtime": runtime.job_runtime,
        }
        requeued = self.store.requeue(["skipped"], self.policy.allows)
        if requeued:
            self.log(f"[recon] re-queued {requeued} job(s) now allowed by mode {self.policy.mode!r}")
        for seed in self.campaign.seeds:
            self.add_seed(seed)
        stats = {"done": 0, "skipped": 0, "failed": 0}
        for _ in range(max_jobs):
            job = self.store.next_job()
            if job is None:
                break
            asset = self.store.get_asset(job["asset_id"])
            label = f"{job['kind']}({asset['value'][:80]})"
            if not self.policy.allows(job["need"]):
                self.store.finish_job(job["id"], "skipped",
                                      f"policy: needs {job['need']!r}, mode is {self.policy.mode!r}")
                stats["skipped"] += 1
                continue
            try:
                self.client.budget.check()
                self.log(f"[recon] {label}")
                handlers[job["kind"]](self, asset)
                self.store.finish_job(job["id"], "done")
                stats["done"] += 1
            except BudgetExceeded as e:
                self.store.finish_job(job["id"], "skipped", str(e))
                stats["skipped"] += 1
                break
            except PolicyViolation as e:
                self.store.finish_job(job["id"], "skipped", str(e))
                stats["skipped"] += 1
            except OutOfScope as e:
                self.store.finish_job(job["id"], "done", f"blocked: {e}")
                stats["done"] += 1
            except FetchError as e:
                self.store.finish_job(job["id"], "failed", str(e)[:300])
                stats["failed"] += 1
            except Exception as e:  # keep the queue moving; the note says why
                self.store.finish_job(job["id"], "failed", f"{type(e).__name__}: {e}"[:300])
                stats["failed"] += 1
                self.log(f"[recon] FAILED {label}: {type(e).__name__}: {e}")
        stats["coverage_rows_added"] = self.refresh_coverage()
        return stats

    def refresh_coverage(self) -> int:
        n = 0
        for e in self.store.assets("endpoint", in_scope=True):
            if not is_inferred_only(e):
                n += self.store.seed_coverage(e["id"], applicable_classes(e))
        for s in self.store.assets("service", in_scope=True):
            n += self.store.seed_coverage(s["id"], packs_for(s["attrs"].get("tech", [])))
        return n
