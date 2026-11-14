"""Bounded source fallback, durable result recovery, and failure/stall suppression.

This controls configured intel providers, not arbitrary agent tool calls. Policy and
budget failures stop the chain; they are never reasons to switch execution paths.
"""
from __future__ import annotations

import hashlib
import json
import time

from .campaign import PolicyViolation
from .net import FetchError
from .store import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS provider_cache(
  provider TEXT NOT NULL, query_key TEXT NOT NULL, state TEXT NOT NULL,
  result TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0, expires REAL NOT NULL,
  PRIMARY KEY(provider,query_key));
CREATE TABLE IF NOT EXISTS provider_events(
  id INTEGER PRIMARY KEY, provider TEXT NOT NULL, query_key TEXT NOT NULL,
  attempt INTEGER NOT NULL, state TEXT NOT NULL, error_type TEXT, created TEXT NOT NULL);
"""


class ProviderError(RuntimeError):
    """Expected transport/CLI/schema failure, distinct from a valid empty result."""


class SourceRunner:
    def __init__(self, ctx):
        self.ctx = ctx
        self.db = ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()

    def _event(self, provider, key, attempt, state, error=None):
        cursor = self.db.execute("INSERT INTO provider_events(provider,query_key,attempt,state,error_type,created) "
                                 "VALUES(?,?,?,?,?,?)", (provider, key, attempt, state, error, now()))
        self.db.commit()
        return cursor.lastrowid

    def first_result(self, query: str, sources, *, refresh: bool = False):
        """Return first useful result plus attempt IDs; maximum two tries per source.

        `sources` is an operator/code-owned sequence of (provider name, callable).
        Query strings are hashed, not copied into event logs. Payload policy remains
        the provider's responsibility; this runner does not authorize disclosure.
        """
        key = hashlib.sha256(query.encode()).hexdigest()
        events = []
        for provider, call in sources:
            cached = self.db.execute("SELECT * FROM provider_cache WHERE provider=? AND query_key=?",
                                     (provider, key)).fetchone()
            if not refresh and cached and cached["expires"] > time.time():
                state = "recovered" if cached["state"] in ("success", "empty") else "suppressed"
                events.append(self._event(provider, key, 0, state))
                if cached["state"] == "success":
                    return json.loads(cached["result"]), events
                continue
            # Write-ahead attempts make interrupted provider work visible on resume.
            self.db.execute("UPDATE provider_events SET state='interrupted' "
                            "WHERE provider=? AND query_key=? AND state='started'", (provider, key))
            self.db.commit()
            failures = cached["failures"] if cached else 0
            for attempt in range(1, 3):
                self.ctx.client.budget.check()
                event = self._event(provider, key, attempt, "started")
                events.append(event)
                try:
                    result = call()
                    if not isinstance(result, list):
                        raise ProviderError("provider result is not a list")
                except PolicyViolation:
                    self.db.execute("UPDATE provider_events SET state='blocked',error_type='PolicyViolation' WHERE id=?",
                                    (event,))
                    self.db.commit()
                    raise
                except (FetchError, ProviderError, TimeoutError) as exc:
                    self.db.execute("UPDATE provider_events SET state='failed',error_type=? WHERE id=?",
                                    (type(exc).__name__, event))
                    self.db.commit()
                    continue
                except Exception as exc:
                    self.db.execute("UPDATE provider_events SET state='error',error_type=? WHERE id=?",
                                    (type(exc).__name__, event))
                    self.db.commit()
                    raise  # programming errors are not silently treated as a source miss
                state = "success" if result else "empty"
                self.db.execute("UPDATE provider_events SET state=? WHERE id=?", (state, event))
                self.db.execute("INSERT OR REPLACE INTO provider_cache VALUES(?,?,?,?,?,?)",
                                (provider, key, state, json.dumps(result), 0, time.time() + 3600))
                self.db.commit()
                if result:
                    return result, events
                break
            else:
                failures += 1
                self.db.execute("INSERT OR REPLACE INTO provider_cache VALUES(?,?,?,?,?,?)",
                                (provider, key, "stalled" if failures >= 3 else "failed", "[]",
                                 failures, time.time() + (3600 if failures >= 3 else 30)))
                self.db.commit()
        return [], events
