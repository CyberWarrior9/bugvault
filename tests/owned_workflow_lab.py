"""Finite, in-process owned commerce fixture. No HTTP, clock sleeps or real value.

Each schedule is a declared ordering of check/commit steps; it models an application
interleaving, NOT a synchronized network send. The authoritative oracle is the
ledger/receiver below, not a returned status or a cache/UI view.
"""


class OwnedCommerce:
    def __init__(self):
        self.reset()

    def reset(self):
        self.balance = 100  # synthetic USD minor units; exponent 2
        self.captured = 100
        self.debits = []
        self.refunds = []
        self.effects = []
        self.receiver = []
        self.rows = {"route": False, "version": False}
        self.keys = {}
        self.trace = []
        self.clock = 0  # explicitly controlled fake clock
        self.entitlement = False
        self.protected = "none"
        self.queue = []
        self.acks = []
        self.sessions = set()

    def run(self, kind, *, fixed=False, schedule="overlap", writers=None, amount=60):
        """Two phases per member, one chosen finite schedule, no retry."""
        if writers is None:
            writers = ["claim", "redeem"]
        if not 2 <= len(writers) <= 8 or len(set(writers)) != len(writers):
            raise ValueError("2..8 exact writers required")
        if schedule == "overlap":
            steps = [(i, "check") for i in range(len(writers))] + [
                (i, "commit") for i in range(len(writers))]
        elif schedule == "serial":
            steps = [(i, phase) for i in range(len(writers)) for phase in ("check", "commit")]
        elif schedule == "reverse":
            steps = [(i, phase) for i in reversed(range(len(writers))) for phase in ("check", "commit")]
        else:
            raise ValueError("unsupported finite schedule")
        checked = {}
        receipts = {w: {"sent": 1, "committed": False, "effected": False} for w in writers}
        for index, phase in steps:
            writer = writers[index]
            intent = "one-owned-intent" if kind == "idempotency" else writer
            if phase == "check":
                if kind == "debit":
                    state = (self.balance, self.balance >= amount)
                elif kind == "refund":
                    state = (sum(n for _, n in self.refunds),
                             sum(n for _, n in self.refunds) + amount <= self.captured)
                elif kind == "skew":
                    state = (sum(self.rows.values()), sum(self.rows.values()) < 1)
                elif kind == "idempotency":
                    state = (len(self.effects), intent not in self.keys)
                else:
                    limit = 2 if kind == "fanout" else 1
                    state = (len(self.effects), len(self.effects) < limit)
                checked[writer] = state
                self.trace.append(f"check:{writer}:{state[0]}:{state[1]}")
            else:
                if writer not in checked:
                    raise AssertionError("commit without check")
                stale_value, allowed = checked[writer]
                if fixed:
                    if kind == "debit":
                        allowed = self.balance >= amount
                    elif kind == "refund":
                        allowed = sum(n for _, n in self.refunds) + amount <= self.captured
                    elif kind == "skew":
                        allowed = sum(self.rows.values()) < 1
                    elif kind == "idempotency":
                        allowed = intent not in self.keys
                    else:
                        allowed = len(self.effects) < (2 if kind == "fanout" else 1)
                if not allowed:
                    self.trace.append(f"commit-refused:{writer}:atomicity")
                    continue
                if kind == "debit":
                    # The broken branch overwrites another committed debit.
                    self.balance = (self.balance if fixed else stale_value) - amount
                    self.debits.append((intent, amount))
                elif kind == "refund":
                    self.refunds.append((intent, amount))
                elif kind == "skew":
                    self.rows[writer] = True
                elif kind == "idempotency":
                    self.keys[intent] = writer
                self.effects.append(intent)
                receipts[writer]["committed"] = True
                self.trace.extend((f"write:{writer}", f"commit:{writer}", f"effect:{writer}"))
                receipts[writer]["effected"] = True
                self.trace.append(f"ack:{writer}")
        return {"writers": writers, "receipts": receipts, "trace": self.trace[:],
                "balance": self.balance, "debits": self.debits[:], "refunds": self.refunds[:],
                "effects": self.effects[:], "rows": self.rows.copy()}

    def quote(self, *, fixed, quantity, product="owned-item", currency="USD", version=1,
              client_minor=25):
        quote = {"product": "owned-item", "quantity": 1, "currency": "USD", "version": 1,
                 "minor": 25}
        sent = {"product": product, "quantity": quantity, "currency": currency, "version": version,
                "minor": client_minor}
        valid = (product == quote["product"] and quantity == quote["quantity"] and
                 currency == quote["currency"] and version == quote["version"])
        if fixed and not valid:
            self.trace.append("commit-refused:quote-binding")
            return None
        if fixed:
            sent["minor"] = quote["minor"]
        self.trace.extend(("check:quote", "write:owned-order", "commit:owned-order", "effect:owned-order"))
        self.receiver.append(sent.copy())
        return sent

    def publish_then_use(self, *, fixed, early):
        self.trace.append("check:prerequisite")
        if early:
            self.trace.append("write:partial-construction")
            if not fixed:
                self.receiver.append("protected-owned-action")
                self.trace.append("effect:protected-owned-action")
            else:
                self.trace.append("commit-refused:incomplete-state")
        self.entitlement = True
        self.trace.append("commit:approved-entitlement")
        if not early:
            self.receiver.append("protected-owned-action")
            self.trace.append("effect:protected-owned-action")
        return self.receiver[:]

    def keyed(self, key, account, params, *, fixed, ttl=10):
        """Same principal+operation+resource+key+parameters within the fake TTL."""
        record = self.keys.get(key)
        if record and self.clock < record["expires"]:
            if fixed and (account != record["account"] or params != record["params"]):
                self.trace.append("commit-refused:key-scope-or-body")
                return None
            self.trace.append("ack:cached-result")
            return record["result"]
        result = {"account": account, "amount": params, "version": self.clock}
        self.keys[key] = {"account": account, "params": params, "result": result,
                          "expires": self.clock + ttl}
        self.trace.extend(("commit:key", "effect:owned-result"))
        self.receiver.append(result)
        return result

    def deliver(self, event_id, version, *, fixed, acknowledge=True):
        self.queue.append((event_id, version))
        self.trace.append(f"enqueue:{event_id}:{version}")
        if not fixed or event_id not in self.keys:
            if not fixed or version > self.clock:
                self.clock = version
                self.receiver.append((event_id, version))
                self.trace.append(f"effect:{event_id}:{version}")
            self.keys[event_id] = version
        if acknowledge:
            self.acks.append(event_id)
            self.trace.append(f"ack:{event_id}")

    def timeout(self, intent, *, committed, fixed):
        self.trace.append(f"sent:{intent}")
        if committed:
            if not fixed or intent not in self.keys:
                self.receiver.append(intent)
                self.keys[intent] = "committed"
                self.trace.extend((f"commit:{intent}", f"effect:{intent}"))
        self.trace.append(f"response-lost:{intent}")
        return "unknown"  # A timeout is not a denial or a safe retry.

    def saga(self, *, fixed, compensate):
        self.receiver.append("original-effect")
        self.trace.extend(("commit:local", "effect:original", "failure:later-step"))
        self.entitlement = False  # local DB rollback is not an external undo
        if fixed and compensate:
            self.receiver.append("compensating-effect")
            self.trace.append("effect:compensation")
        return {"local": self.entitlement, "receiver": self.receiver[:],
                "obligation": "resolved" if fixed and compensate else "open"}

    def reserved_action(self, *, account, owned_object, role="member", fixed=False,
                        required_grants=2):
        """Declared lab contract: reserved action also requires an admin role."""
        self.trace.append(f"check:reserved:{account}:{role}:{owned_object}")
        if len(self.effects) < required_grants or fixed and role != "admin":
            self.trace.append("commit-refused:missing-entitlement-or-role")
            return False
        self.receiver.append({"account": account, "role": role, "object": owned_object,
                              "action": "reserved-once"})
        self.trace.extend(("commit:reserved", "effect:reserved", "ack:reserved"))
        return True

    def consume_owned_artifact(self, *, fixed, schedule, token="owned-once-token"):
        """A/V use exactly one known owned artifact. Sessions are synthetic only."""
        if token != "owned-once-token":
            raise ValueError("unknown artifact; never guess a token")
        result = self.run("slot", fixed=fixed, schedule=schedule,
                          writers=["account-a", "account-v"])
        for account in result["effects"]:
            self.sessions.add((account, token))
            self.trace.append(f"effect:session:{account}:{token}")
        return {"artifact": token, "consumptions": result["effects"],
                "sessions": set(self.sessions), "trace": self.trace[:]}

    def credit_one_owned_resource(self, vulnerable, fixed, *, cap_minor=10):
        excess = max(0, len(vulnerable["effects"]) - len(fixed["effects"]))
        delta = excess * 10
        if delta > cap_minor:
            raise ValueError("synthetic credit exceeds declared cap")
        if delta:
            self.receiver.append({"owned-credit-minor": delta})
            self.trace.extend(("commit:credit", f"effect:credit:{delta}", "ack:credit"))
        return delta
