"""Offline review regressions for takeover policy, identity and evidence freshness."""
from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon import takeover
from recon.pipeline import Recon
from recon.store import now
from recon.takeover import TakeoverLedger
from tests.test_recon import write_campaign


TIME = "2026-11-15T12:00:00Z"
LATER = "2026-11-15T14:00:00Z"
HOST = "old.acme.test"
TARGET = "unclaimed.herokuapp.com"


def observation(name=HOST, record_type="CNAME", value=TARGET, **overrides):
    return {"name": name, "record_type": record_type, "value": value,
            "result": "answer", "resolver": "owned-fixture", "observed_at": TIME,
            "vantage": "recursive", **overrides}


def capture(*observations):
    return {"schema": 1, "source": "owned offline review fixture",
            "observations": list(observations)}


def control(name="bvcontrol1a.acme.test", record_type="CNAME", **overrides):
    return observation(name, record_type, "", result="nxdomain",
                       vantage="wildcard-control", control_for=HOST, **overrides)


class TakeoverReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for target, message in (("socket.socket", "offline tests must not open sockets"),
                                ("socket.getaddrinfo", "offline tests must not resolve DNS")):
            guard = patch(target, side_effect=AssertionError(message))
            guard.start()
            self.addCleanup(guard.stop)
        self.root = Path(self.temp.name) / "camp"
        self.campaign = write_campaign(self.root, "active", [],
                                       in_scope=["acme.test", "*.acme.test"])
        self.ctx = Recon(self.campaign, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.ledger = TakeoverLedger(self.ctx)

    def candidate(self):
        self.ledger.import_capture(capture(
            observation(),
            observation(TARGET, "A", "", result="nxdomain"),
            observation(TARGET, "AAAA", "", result="nxdomain"),
            control()))
        return next(c["id"] for c in self.ledger.plan()["candidates"]
                    if c["name"] == HOST and c["record_type"] == "CNAME")

    def artifact(self, name, text):
        path = self.root / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return str(path.relative_to(self.root))

    def precheck(self, cid, **overrides):
        return {"schema": 1, "candidate": cid, "stage": "precheck", "state": "observed",
                "note": "Owned offline fixture; no provider or live DNS verification",
                "channel": "owned-lab",
                "artifacts": {"review": self.artifact("review.txt", "owned fixture review")},
                **overrides}

    def live_recording_grant(self):
        self.campaign.raw.update({
            "program_url": "https://program.example/rules",
            "rules": ["Owned fixture recording only; no traffic is executed"],
            "takeover": {"rules_reviewed": now()[:10], "grants": ["claim"], "budget": 20}})

    def event_count(self):
        return self.ctx.store.db.execute("SELECT count(*) FROM to_events").fetchone()[0]

    def test_excluded_class_blocks_live_observed_prechecks_and_retains_blocked_evidence(self):
        cid = self.candidate()
        self.live_recording_grant()
        # Establish that the other live-recording gates really are satisfied.
        self.ledger.record(self.precheck(cid, channel="burp", requests=1))
        self.campaign.raw["excluded_bug_classes"] = ["subdomain-takeover"]
        before = self.event_count()
        for channel in ("browser", "burp", "native", "scanner"):
            with self.subTest(channel=channel), self.assertRaises(ValueError):
                self.ledger.record(self.precheck(cid, channel=channel, requests=1))
        self.assertEqual(self.event_count(), before)

        blocked = self.ledger.record(self.precheck(
            cid, state="blocked", channel="burp", requests=0,
            note="Program excludes subdomain takeover; preserve the supplied review"))
        event = next(e for e in self.ledger.show(cid)["events"] if e["id"] == blocked["event_id"])
        self.assertEqual(event["state"], "blocked")
        ref = event["data"]["artifacts"]["review"]
        raw = (self.root / ref["path"]).read_bytes()
        self.assertEqual(raw, b"owned fixture review")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), ref["sha256"])
        self.assertFalse(blocked["executed"])
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        self.assertTrue(self.ledger.verify()["ok"])

    def test_exclusion_changes_policy_hash_and_stales_prior_event_without_rewriting_it(self):
        cid = self.candidate()
        self.ledger.record(self.precheck(cid))
        before = self.ledger.show(cid)
        prior = before["events"][0]
        self.assertFalse(prior["stale"])
        self.assertEqual(prior["policy"], self.ledger._policy())

        self.campaign.raw["excluded_bug_classes"] = ["subdomain-takeover"]
        after = self.ledger.show(cid)
        self.assertNotEqual(prior["policy"], self.ledger._policy())
        self.assertEqual(after["events"][0]["policy"], prior["policy"])
        self.assertEqual(after["snapshot"], before["snapshot"])
        self.assertTrue(after["events"][0]["stale"])
        self.assertEqual(self.event_count(), 1)

    def test_sql_candidate_name_change_fails_verification_and_cannot_record_success(self):
        cid = self.candidate()
        self.ctx.store.db.execute("UPDATE to_candidates SET name=? WHERE id=?", ("other.acme.test", cid))
        self.ctx.store.db.commit()
        self.assertFalse(self.ledger.verify()["ok"])
        with self.assertRaises(ValueError):
            self.ledger.record(self.precheck(cid))
        self.assertEqual(self.event_count(), 0)

    def test_sql_candidate_record_type_and_value_changes_cannot_record_success(self):
        cid = self.candidate()
        original = dict(self.ctx.store.db.execute("SELECT * FROM to_candidates WHERE id=?", (cid,)).fetchone())
        for column, value in (("record_type", "NS"), ("value", "other.herokuapp.com")):
            with self.subTest(column=column):
                try:
                    self.ctx.store.db.execute(f"UPDATE to_candidates SET {column}=? WHERE id=?", (value, cid))
                    self.ctx.store.db.commit()
                    self.assertFalse(self.ledger.verify()["ok"])
                    with self.assertRaises(ValueError):
                        self.ledger.record(self.precheck(cid))
                    self.assertEqual(self.event_count(), 0)
                finally:
                    self.ctx.store.db.execute(f"UPDATE to_candidates SET {column}=? WHERE id=?", (original[column], cid))
                    self.ctx.store.db.commit()

    def test_sql_candidate_asset_rebinding_fails_verification_and_cannot_record_success(self):
        cid = self.candidate()
        other, _ = self.ctx.store.upsert_asset("host", "other.acme.test", host="other.acme.test")
        self.ctx.store.db.execute("UPDATE to_candidates SET asset_id=? WHERE id=?", (other, cid))
        self.ctx.store.db.commit()
        self.assertFalse(self.ledger.verify()["ok"])
        with self.assertRaises(ValueError):
            self.ledger.record(self.precheck(cid))
        self.assertEqual(self.event_count(), 0)

    def test_snapshot_binds_each_candidate_identity_column(self):
        self.ctx.store.upsert_asset("host", HOST, host=HOST, attrs={"cname": TARGET, "resolves": False})
        self.ledger.sync()
        cid = self.ledger.plan()["candidates"][0]["id"]
        candidate = self.ledger._get(cid)
        baseline = self.ledger._snapshot(cid)
        # No DNS rows or trust edges: keep captured data identical so that only
        # the candidate row's identity can change the hash in these unit contrasts.
        changes = {"id": cid + 100, "asset_id": candidate["asset_id"] + 100,
                   "name": "other.acme.test", "record_type": "NS", "value": "other.herokuapp.com"}
        for column, value in changes.items():
            with self.subTest(column=column):
                changed = {**deepcopy(candidate), column: value}
                with patch.object(self.ledger, "_get", return_value=changed):
                    self.assertNotEqual(self.ledger._snapshot(cid), baseline)

    def test_unrelated_txt_import_does_not_stale_existing_precheck(self):
        cid = self.candidate()
        self.ledger.record(self.precheck(cid))
        before = self.ledger.show(cid)
        self.ledger.import_capture(capture(observation("unrelated.acme.test", "TXT", "unrelated marker")))
        after = self.ledger.show(cid)
        self.assertEqual(after["data"], before["data"])
        self.assertEqual(after["snapshot"], before["snapshot"])
        self.assertFalse(after["events"][0]["stale"])
        self.assertTrue(self.ledger.verify()["ok"])

    def test_related_target_observation_change_stales_precheck(self):
        cid = self.candidate()
        self.ledger.record(self.precheck(cid))
        before = self.ledger.show(cid)
        self.ledger.import_capture(capture(observation(TARGET, "A", "", result="nxdomain", observed_at=LATER)))
        after = self.ledger.show(cid)
        self.assertEqual(after["data"], before["data"])
        self.assertNotEqual(after["snapshot"], before["snapshot"])
        self.assertTrue(after["events"][0]["stale"])

    def test_related_wildcard_control_change_stales_precheck(self):
        cid = self.candidate()
        self.ledger.record(self.precheck(cid))
        before = self.ledger.show(cid)
        # The unchanged anchor is required to bind this control in its own input.
        self.ledger.import_capture(capture(observation(), control("bvcontrol2b.acme.test")))
        after = self.ledger.show(cid)
        self.assertEqual(after["data"], before["data"])
        self.assertNotEqual(after["snapshot"], before["snapshot"])
        self.assertTrue(after["events"][0]["stale"])

    def test_related_referral_observation_change_stales_precheck(self):
        parent = observation(record_type="NS", value="ns1.provider.test", vantage="parent-referral", zone=HOST)
        child = observation(record_type="NS", value="ns2.provider.test", vantage="child-authoritative")
        self.ledger.import_capture(capture(parent, child, control(record_type="NS")))
        cid = next(c["id"] for c in self.ledger.plan()["candidates"] if c["value"] == parent["value"])
        self.ledger.record(self.precheck(cid))
        before = self.ledger.show(cid)
        self.ledger.import_capture(capture({**child, "observed_at": LATER}))
        after = self.ledger.show(cid)
        self.assertEqual(after["data"], before["data"])
        self.assertNotEqual(after["snapshot"], before["snapshot"])
        self.assertTrue(after["events"][0]["stale"])

    def test_legacy_resolved_host_retains_candidate_and_events_as_inactive_history(self):
        aid, _ = self.ctx.store.upsert_asset("host", HOST, host=HOST,
                                            attrs={"cname": TARGET, "resolves": False})
        self.ledger.sync()
        candidate = self.ledger.plan()["candidates"][0]
        cid = candidate["id"]
        self.assertTrue(candidate["active"])
        self.ledger.record(self.precheck(cid))

        self.ctx.store.update_attrs(aid, {"resolves": True})
        self.ledger.sync()
        history = self.ledger.show(cid)
        self.assertFalse(history["active"])
        self.assertEqual(history["data"], candidate["data"])
        self.assertEqual(len(history["events"]), 1)
        self.assertTrue(history["events"][0]["stale"])
        self.assertIn(cid, {c["id"] for c in self.ledger.plan()["candidates"]})
        self.ledger.sync()
        self.assertFalse(self.ledger.show(cid)["active"])
        with self.assertRaises(ValueError):
            self.ledger.record(self.precheck(cid))
        self.assertEqual(self.event_count(), 1)

    def import_many_observations(self):
        result = self.ledger.import_capture(capture(*[
            observation(f"address{n}.acme.test", "A", "192.0.2.1") for n in range(200)]))
        row = self.ctx.store.db.execute("SELECT path FROM to_inputs WHERE id=?", (result["input_id"],)).fetchone()
        return (self.root / row["path"]).resolve()

    def test_verify_reads_each_input_a_constant_number_of_times(self):
        source = self.import_many_observations()
        self.assertEqual(source.parent, (self.campaign.state_dir / "takeover").resolve())
        original = takeover.local_bytes
        for attempt in range(2):
            reads = []

            def counted(root, path):
                if (Path(root) / path).resolve() == source:
                    reads.append(path)
                return original(root, path)

            with self.subTest(verify=attempt), patch.object(takeover, "local_bytes", side_effect=counted):
                self.assertTrue(self.ledger.verify()["ok"])
                self.assertGreaterEqual(len(reads), 1)
                self.assertLessEqual(len(reads), 4, "one capture must not be reread for every DNS observation")

    def test_verify_rechecks_input_after_a_previous_successful_verify(self):
        source = self.import_many_observations()
        self.assertTrue(self.ledger.verify()["ok"])
        source.write_bytes(source.read_bytes() + b"\n")
        self.assertFalse(self.ledger.verify()["ok"])

    def test_campaign_observation_cap_rejects_before_evidence_or_ledger_writes(self):
        tables = ("to_inputs", "to_dns", "to_sources", "to_sightings", "to_edges", "to_candidates", "to_events")

        def counts():
            return {table: self.ctx.store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    for table in tables}

        # Existing ledger tests exercise the full 2,000-observation boundary;
        # this reduced bound checks that the aggregate gate precedes all writes.
        with patch("recon.takeover_dns.MAX_OBSERVATIONS", 4):
            self.ledger.import_capture(capture(*[
                observation(f"first{n}.acme.test", "A", "192.0.2.1") for n in range(3)]))
            before = counts()
            files = sorted(self.ledger.directory.iterdir())
            with patch.object(self.ledger, "_keep", wraps=self.ledger._keep) as keep:
                with self.assertRaises(ValueError):
                    self.ledger.import_capture(capture(*[
                        observation(f"second{n}.acme.test", "A", "192.0.2.1") for n in range(2)]))
                keep.assert_not_called()
            self.assertEqual(counts(), before)
            self.assertEqual(sorted(self.ledger.directory.iterdir()), files)


if __name__ == "__main__":
    unittest.main()
