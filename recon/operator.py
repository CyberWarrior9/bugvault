"""Offline operator queue: blocked work asks a human and pauses only itself.

Adopted from ARTEX's `ask_operator` (see `plans/artex-adoption.md` §3.3). A unit of
work that hits something only a human can clear — a CAPTCHA, an emailed or texted
one-time code, a 2FA prompt, an account lockout, a missing binary or key — records one
question here and stops. Everything else keeps running: the queue blocks the asking
intent, never the engagement.

Four properties this module guarantees, because they are what make an unattended run
safe rather than merely convenient:

* **No timeout.** A pending question waits for a human indefinitely. Nothing here
  auto-approves, auto-denies or expires, so a silent operator can never be read as
  consent.
* **No grant.** Answering cannot widen scope, add an allowed method, raise a budget or
  authorize an action the campaign rules refuse. This module holds no scope, policy or
  budget writer, and every entry records `grants: "none"`. A question whose answer
  would need a grant belongs in `scope.json` under the program's written rules.
* **Only the asker blocks.** `blocked_intents()` names exactly the intents with a
  pending question, so a scheduler skips those and continues with the rest.
* **Never evade.** The reasons are the blocks BugVault already stops on. Recording one
  is the end of that attempt, not the start of a bypass.

Offline: no network traffic. Entries live in the engagement's private directory at
mode 0600, appended under an exclusive lock so parallel workers cannot interleave.
Operator answers are handed back nonce-framed as data (`recon/untrusted.py`), because
a pasted response body is still target text.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from .store import now
from .untrusted import frame

__all__ = ["OperatorQueue", "REASONS", "MAX_QUESTION", "MAX_ANSWER"]

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
INTENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# The blocks BugVault already stops on, plus a plain decision request. `environment`
# carries the one copy-pastable command the operator should run in their own terminal.
REASONS = ("captcha", "otp", "2fa", "lockout", "environment", "decision")

MAX_QUESTION = 2000
MAX_ANSWER = 4000
STATES = ("pending", "answered", "withdrawn")


class OperatorQueue:
    """The private per-engagement queue of questions for the human operator."""

    def __init__(self, ctx, name: str):
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError("engagement id must be a 1..64 character lowercase slug")
        state = ctx.campaign.state_dir
        self.ctx = ctx
        self.path = state / "engagements" / name
        if state.is_symlink() or self.path.is_symlink() or self.path.parent.is_symlink():
            raise ValueError("engagement directory cannot be a symlink")
        self.queue_file = self.path / "operator-queue.jsonl"
        self.lock_file = self.path / "operator-queue.lock"

    # ---- storage -----------------------------------------------------------

    def _ensure_dir(self) -> None:
        self.path.mkdir(parents=True, mode=0o700, exist_ok=True)

    def _read(self) -> list[dict]:
        if not self.queue_file.is_file():
            return []
        if self.queue_file.is_symlink():
            raise ValueError("operator queue cannot be a symlink")
        out = []
        for line in self.queue_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def _write_all(self, entries: list[dict]) -> None:
        """Rewrite the queue atomically, preserving mode 0600."""
        fd, tmp = tempfile.mkstemp(prefix=".operator-", dir=str(self.path))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                for entry in entries:
                    stream.write(json.dumps(entry, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.queue_file)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _locked(self):
        """Exclusive lock around a read-modify-write, for parallel workers."""
        self._ensure_dir()
        fd = os.open(self.lock_file, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    @staticmethod
    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

    # ---- attachments -------------------------------------------------------

    def _attachment(self, given: str) -> dict:
        """Record a screenshot that is already inside the engagement directory.

        Nothing is copied in from elsewhere: a path outside the engagement is refused,
        so the queue cannot be used to pull arbitrary local files into private state.
        """
        path = Path(given)
        root = self.path.resolve()
        resolved = (root / path if not path.is_absolute() else path).resolve()
        if resolved.is_symlink() or not resolved.is_file():
            raise ValueError("attachment must be an existing regular file")
        if root not in resolved.parents:
            raise ValueError("attachment must live inside the engagement directory")
        if resolved.stat().st_size > 10 << 20:
            raise ValueError("attachment is larger than 10 MiB")
        if resolved.suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp", ".gif"):
            raise ValueError("attachment must be a png, jpg, jpeg, webp or gif image")
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        return {"path": str(resolved.relative_to(root)), "sha256": digest}

    # ---- operations --------------------------------------------------------

    def ask(self, intent: str, question: str, reason: str, attachment: str = "") -> dict:
        """Record one question and report the intent as blocked. Never sends anything."""
        if not isinstance(intent, str) or not INTENT.fullmatch(intent):
            raise ValueError("intent ref must be a 1..64 character lowercase slug")
        if reason not in REASONS:
            raise ValueError(f"reason must be one of {', '.join(REASONS)}")
        text = " ".join(str(question).split())
        if not text:
            raise ValueError("a question is required")
        if len(text) > MAX_QUESTION:
            raise ValueError(f"question is longer than {MAX_QUESTION} characters")

        fd = self._locked()
        try:
            entries = self._read()
            if any(e["intent"] == intent and e["state"] == "pending" for e in entries):
                raise ValueError(f"intent {intent} already has a pending question; "
                                 "answer or withdraw it before asking another")
            entry = {
                "ref": max((e["ref"] for e in entries), default=0) + 1,
                "intent": intent,
                "reason": reason,
                "question": text,
                "state": "pending",
                "asked": now(),
                "answered": None,
                "answer": None,
                # Recorded on every entry so an answer is never mistaken for authority.
                "grants": "none",
            }
            if attachment:
                entry["attachment"] = self._attachment(attachment)
            entries.append(entry)
            self._write_all(entries)
            return entry
        finally:
            self._unlock(fd)

    def answer(self, ref: int, text: str) -> dict:
        """Record the operator's reply. The reply is data, and grants nothing."""
        body = str(text).strip()
        if not body:
            raise ValueError("an answer is required")
        if len(body) > MAX_ANSWER:
            raise ValueError(f"answer is longer than {MAX_ANSWER} characters")

        fd = self._locked()
        try:
            entries = self._read()
            for entry in entries:
                if entry["ref"] != int(ref):
                    continue
                if entry["state"] != "pending":
                    raise ValueError(f"entry {ref} is already {entry['state']}")
                entry["answer"] = body
                entry["answered"] = now()
                entry["state"] = "answered"
                self._write_all(entries)
                return entry
            raise ValueError(f"no queue entry with ref {ref}")
        finally:
            self._unlock(fd)

    def withdraw(self, ref: int, note: str = "") -> dict:
        """Drop a question the asking intent no longer needs (it was killed, say)."""
        fd = self._locked()
        try:
            entries = self._read()
            for entry in entries:
                if entry["ref"] != int(ref):
                    continue
                if entry["state"] != "pending":
                    raise ValueError(f"entry {ref} is already {entry['state']}")
                entry["state"] = "withdrawn"
                entry["answered"] = now()
                if note:
                    entry["note"] = " ".join(str(note).split())[:200]
                self._write_all(entries)
                return entry
            raise ValueError(f"no queue entry with ref {ref}")
        finally:
            self._unlock(fd)

    # ---- reads -------------------------------------------------------------

    def entries(self, state: str = "") -> list[dict]:
        if state and state not in STATES:
            raise ValueError(f"state must be one of {', '.join(STATES)}")
        rows = self._read()
        return [e for e in rows if not state or e["state"] == state]

    def blocked_intents(self) -> list[str]:
        """Intents with a pending question. Everything else keeps running."""
        return sorted({e["intent"] for e in self._read() if e["state"] == "pending"})

    def is_blocked(self, intent: str) -> bool:
        return intent in set(self.blocked_intents())

    def resume_input(self, intent: str) -> str:
        """The answered reply for `intent`, nonce-framed as data for the worker.

        An operator may paste a response body or command output, so the reply is
        handed over framed rather than trusted as instructions. It carries no grant.
        """
        answered = [e for e in self._read()
                    if e["intent"] == intent and e["state"] == "answered" and e["answer"]]
        if not answered:
            return ""
        latest = max(answered, key=lambda e: e["ref"])
        return frame(latest["answer"], "operator-answer",
                     label=f"ref {latest['ref']} ({latest['reason']})")

    def status(self) -> dict:
        rows = self._read()
        counts = {state: sum(1 for e in rows if e["state"] == state) for state in STATES}
        return {
            "schema_version": 1,
            "queue": str(self.queue_file),
            "total": len(rows),
            "counts": counts,
            "blocked_intents": self.blocked_intents(),
            "reasons": {r: sum(1 for e in rows if e["reason"] == r) for r in REASONS},
            # Stated in the output so a reader of the JSON sees the same contract.
            "timeout": "none; a pending question waits for a human indefinitely",
            "grants": "none; an answer never widens scope, methods or budgets",
        }
