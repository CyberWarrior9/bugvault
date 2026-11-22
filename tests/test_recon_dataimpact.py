"""Measured data impact, proof levels and the severity ceiling.

Offline: no target traffic, no model calls.

The contract under test (plans/artex-adoption.md §5.2-5.3, §5.5 as revised 2026-11-22):
  * reach is not impact — a proven primitive with uncharacterised data caps at medium;
  * severity follows what the data IS and how MUCH of it, not the primitive;
  * a measurement must add up: classified items == sampled, sampled <= reachable;
  * raw values are structurally refused; only field names and redacted fingerprints;
  * `impact-proven` needs PoE >= 3, a denominator, and a quote present in the artifact;
  * PoE 4 is earned by the measurement, not asserted.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.campaign import Campaign
from recon.dataimpact import (CLASSES, MAX_PREFIX, SENSITIVITY, TIERS, MeasurementError,
                              ceiling, summarise, tier_of, validate)
from recon.findings import Findings, StageError, severity_ceiling
from recon.pipeline import Recon

DIGEST = "a" * 64


def _measurement(**over):
    """A valid measurement. `sampled` follows the class counts unless given."""
    base = {"reachable": 10, "enumeration": "complete", "classes": {"build-metadata": 2}}
    base.update(over)
    if "sampled" not in over and isinstance(base.get("classes"), dict):
        counts = [n for n in base["classes"].values() if type(n) is int]
        total = sum(counts) if len(counts) == len(base["classes"]) else 2
        base["sampled"] = total or 1
    return base  # `reachable` is never adjusted, so a bad value stays bad


class ClassificationTests(unittest.TestCase):
    def test_every_class_has_a_known_tier(self):
        self.assertEqual(set(SENSITIVITY.values()) - set(TIERS), set())
        for name, (tier, meaning) in CLASSES.items():
            self.assertIn(tier, TIERS, name)
            self.assertTrue(meaning.strip(), name)

    def test_the_top_tier_present_wins(self):
        self.assertEqual(tier_of({"build-metadata": 9, "cloud-credential": 1}), "credential")
        self.assertEqual(tier_of({"internal-hostname": 4, "pii": 1}), "sensitive")
        self.assertEqual(tier_of({"noise": 100}), "none")
        self.assertEqual(tier_of({}), "none")


class CeilingTests(unittest.TestCase):
    """What the data is worth, which is what the 2026-11-22 decision made decisive."""

    def test_an_uncharacterised_primitive_caps_at_medium(self):
        """Reaching the metadata service is a primitive, not an impact claim."""
        for absent in (None, {}, {"classes": {}}, {"classes": {"pii": 1}}):
            self.assertEqual(ceiling(absent), "medium")

    def test_one_live_credential_is_critical(self):
        self.assertEqual(ceiling({"classes": {"cloud-credential": 1}, "reachable": 1}),
                         "critical")
        for kind in ("session-token", "api-key", "database-credential", "signing-key"):
            self.assertEqual(ceiling({"classes": {kind: 1}, "reachable": 1}), "critical")

    def test_sensitive_data_scales_with_the_count(self):
        """The same bug is a medium, a high or a critical depending on how much."""
        self.assertEqual(ceiling({"classes": {"pii": 1}, "reachable": 1}), "medium")
        self.assertEqual(ceiling({"classes": {"pii": 1}, "reachable": 2}), "high")
        self.assertEqual(ceiling({"classes": {"pii": 1}, "reachable": 99}), "high")
        self.assertEqual(ceiling({"classes": {"pii": 1}, "reachable": 100}), "critical")
        self.assertEqual(ceiling({"classes": {"business-record": 5000}, "reachable": 5000}),
                         "critical")

    def test_internal_structure_is_medium_and_noise_is_low(self):
        self.assertEqual(ceiling({"classes": {"internal-hostname": 40}, "reachable": 40}),
                         "medium")
        self.assertEqual(ceiling({"classes": {"account-identifier": 1}, "reachable": 1}),
                         "medium")
        self.assertEqual(ceiling({"classes": {"noise": 900}, "reachable": 900}), "low")
        self.assertEqual(ceiling({"classes": {"build-metadata": 12}, "reachable": 12}), "low")

    def test_the_same_primitive_rates_differently_on_its_data(self):
        """One env read returning junk versus returning a key: low versus critical."""
        junk = validate(_measurement(reachable=47, sampled=47,
                                     classes={"build-metadata": 40, "noise": 7}))
        keys = validate(_measurement(
            reachable=47, sampled=47,
            classes={"build-metadata": 40, "noise": 6, "cloud-credential": 1},
            subjects=["STS credentials for the prod-api-task role"],
            fingerprints=[{"field": "AWS_SECRET_ACCESS_KEY", "prefix": "wJal",
                           "sha256": DIGEST}]))
        self.assertEqual(junk["ceiling"], "low")
        self.assertEqual(keys["ceiling"], "critical")


class ValidationTests(unittest.TestCase):
    def test_a_good_measurement_normalises(self):
        out = validate(_measurement(reachable=412, sampled=12,
                                    enumeration="bounded-sample",
                                    classes={"cloud-credential": 1, "internal-hostname": 6,
                                             "build-metadata": 5},
                                    subjects=["STS credentials for prod-api-task"],
                                    fingerprints=[{"field": "AWS_SECRET_ACCESS_KEY",
                                                   "prefix": "wJal", "sha256": DIGEST}]))
        self.assertEqual(out["tier"], "credential")
        self.assertEqual(out["ceiling"], "critical")
        self.assertTrue(out["reachable_is_lower_bound"])
        self.assertIn("at least 412 items reachable", summarise(out))
        self.assertIn("credential-tier", summarise(out))

    def test_the_counts_must_add_up(self):
        with self.assertRaisesRegex(MeasurementError, "every item you characterised"):
            validate(_measurement(sampled=5, classes={"noise": 2}))
        with self.assertRaisesRegex(MeasurementError, "cannot exceed"):
            validate(_measurement(reachable=2, sampled=3, classes={"noise": 3}))

    def test_counts_must_be_real_numbers(self):
        for bad in (0, -1, "many", 2.5, True, None):
            with self.assertRaises(MeasurementError):
                validate(_measurement(reachable=bad))
        with self.assertRaisesRegex(MeasurementError, "positive integer"):
            validate(_measurement(classes={"noise": 0}))

    def test_the_class_vocabulary_is_closed(self):
        with self.assertRaisesRegex(MeasurementError, "unknown data classes"):
            validate(_measurement(classes={"very-bad-stuff": 2}))
        with self.assertRaisesRegex(MeasurementError, "must say what the data is"):
            validate(_measurement(classes={}))

    def test_enumeration_basis_is_required(self):
        with self.assertRaisesRegex(MeasurementError, "enumeration must be one of"):
            validate(_measurement(enumeration="guessed"))

    def test_serious_data_must_say_what_it_is_about(self):
        with self.assertRaisesRegex(MeasurementError, "needs data_impact.subjects"):
            validate(_measurement(classes={"pii": 2}))
        self.assertEqual(validate(_measurement(
            classes={"pii": 2}, subjects=["names and emails of 2 other customers"]))["tier"],
            "sensitive")

    def test_a_credential_claim_must_be_bound_by_a_fingerprint(self):
        with self.assertRaisesRegex(MeasurementError, "fingerprints"):
            validate(_measurement(classes={"api-key": 1}, subjects=["Stripe secret key"]))

    # ---- the redaction is structural, not a convention --------------------

    def test_a_raw_value_is_refused_anywhere_in_the_measurement(self):
        for payload in ({"note": "x", "value": "AKIA..."},
                        {"fingerprints": [{"field": "k", "secret": "hunter2"}]},
                        {"subjects": [{"password": "hunter2"}]}):
            with self.assertRaisesRegex(MeasurementError, "looks like a raw value"):
                validate(_measurement(**payload))

    def test_a_long_prefix_is_the_secret_not_a_fingerprint(self):
        with self.assertRaisesRegex(MeasurementError, f"at most {MAX_PREFIX} characters"):
            validate(_measurement(
                classes={"api-key": 1}, subjects=["Stripe key"],
                fingerprints=[{"field": "STRIPE_KEY", "prefix": "sk_live_51Hxxxx",
                               "sha256": DIGEST}]))

    def test_a_fingerprint_needs_a_field_and_a_real_digest(self):
        for bad in ({"field": "K", "prefix": "ab", "sha256": "short"},
                    {"prefix": "ab", "sha256": DIGEST},
                    {"field": "K", "prefix": "ab"}):
            with self.assertRaises(MeasurementError):
                validate(_measurement(classes={"api-key": 1}, subjects=["key"],
                                      fingerprints=[bad]))

    def test_unknown_keys_are_refused(self):
        with self.assertRaisesRegex(MeasurementError, "unknown keys"):
            validate(_measurement(exfiltrated="everything"))


class SeverityCeilingTests(unittest.TestCase):
    def test_the_stage_and_the_data_both_cap_and_the_lower_wins(self):
        critical = validate(_measurement(
            classes={"cloud-credential": 1}, subjects=["role credentials"],
            fingerprints=[{"field": "K", "prefix": "ab", "sha256": DIGEST}]))
        self.assertEqual(severity_ceiling("lead", 0), "none")
        self.assertEqual(severity_ceiling("confirmed", 2), "medium")
        self.assertEqual(severity_ceiling("confirmed", 4), "medium")
        # PoE 3 allows high, but credential data would allow critical: the lower wins.
        self.assertEqual(severity_ceiling("impact-proven", 3, critical), "high")
        self.assertEqual(severity_ceiling("impact-proven", 4, critical), "critical")
        # PoE 4 allows critical, but noise data caps it at low.
        noise = validate(_measurement(classes={"noise": 2}))
        self.assertEqual(severity_ceiling("impact-proven", 4, noise), "low")
        # No measurement at all caps at medium however good the proof level.
        self.assertEqual(severity_ceiling("impact-proven", 4, None), "medium")


class FindingGateTests(unittest.TestCase):
    """The gates as `recon finding move` applies them."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.root.mkdir(parents=True)
        (self.root / "scope.json").write_text(json.dumps({
            "program": "lab", "seeds": [], "in_scope": ["app.example.test"],
            "out_of_scope": [], "policy": {"mode": "active", "max_rps": 2}}))
        self.ctx = Recon(Campaign.load(self.root), log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.fx = Findings(self.ctx)
        self.asset = self.ctx.add("endpoint", "https://app.example.test/api/orders/1", "fixture")

    def art(self, name, text):
        path = Path(self.tmp.name) / name
        path.write_text(text)
        return path

    def confirmed(self, bug_class="idor-bola"):
        fid, _ = self.fx.add(f"{bug_class} finding", bug_class, asset_id=self.asset)
        self.fx.move(fid, "confirmed", replay=self.art(f"r-{fid}.txt", "200 other tenant"),
                     control=self.art(f"c-{fid}.txt", "403 forbidden"))
        return fid

    def prove(self, fid, **kw):
        kw.setdefault("impact", self.art(f"i-{fid}.txt", "tenant=acme row=1"))
        kw.setdefault("poe_level", 3)
        kw.setdefault("quote", "tenant=acme")
        kw.setdefault("measurement", "3 of 40 ids returned another tenant's rows")
        kw.setdefault("data_impact", _measurement(
            reachable=40, sampled=3, classes={"business-record": 3},
            subjects=["3 other tenants' order records"]))
        return self.fx.move(fid, "impact-proven", **kw)

    def test_the_happy_path_records_the_proof_level_and_the_measurement(self):
        fid = self.confirmed()
        out = self.prove(fid, severity="high")
        self.assertEqual(out["stage"], "impact-proven")
        self.assertEqual(out["poe_level"], 3)
        self.assertEqual(out["severity"], "high")
        evidence = self.fx.events(fid)[-1]["evidence"]
        self.assertEqual(evidence["data_impact"]["tier"], "sensitive")
        self.assertEqual(evidence["data_impact"]["ceiling"], "high")
        self.assertIn("40 items reachable", evidence["data_impact_summary"])

    def test_impact_proven_needs_a_real_proof_level(self):
        fid = self.confirmed()
        with self.assertRaisesRegex(StageError, "needs --poe-level 3 or 4"):
            self.prove(fid, poe_level=2)

    def test_a_measurement_needs_a_denominator(self):
        fid = self.confirmed()
        with self.assertRaisesRegex(StageError, "needs --measurement"):
            self.prove(fid, measurement="")
        with self.assertRaisesRegex(StageError, "no denominator"):
            self.prove(fid, measurement="several tenants were affected")
        # An honest refusal to count is accepted, with a reason.
        self.assertEqual(self.prove(
            fid, measurement="not measurable: the endpoint returns one object per call "
                             "and the id space is opaque")["stage"], "impact-proven")

    def test_the_quote_must_be_in_the_bound_artifact(self):
        fid = self.confirmed()
        with self.assertRaisesRegex(StageError, "needs --quote"):
            self.prove(fid, quote="")
        with self.assertRaisesRegex(StageError, "not present verbatim"):
            self.prove(fid, quote="tenant=some-other-company")

    def test_a_header_counts_as_a_result_not_only_a_body(self):
        """ARTEX checks the response body alone; a Set-Cookie is a result too."""
        fid = self.confirmed("ato")
        out = self.prove(fid, impact=self.art("h.txt", "HTTP/1.1 200 OK\r\n"
                                                        "Set-Cookie: session=victim-abc\r\n"),
                         quote="Set-Cookie: session=victim-abc",
                         measurement="1 of 1 password-reset flows yielded the victim session",
                         data_impact=_measurement(
                             reachable=1, sampled=1, classes={"session-token": 1},
                             subjects=["the victim account's session cookie"],
                             fingerprints=[{"field": "Set-Cookie:session", "prefix": "vict",
                                            "sha256": DIGEST}]))
        self.assertEqual(out["stage"], "impact-proven")

    def test_a_data_exposure_class_must_measure_the_data(self):
        """The 2026-11-22 rule: reaching the surface is not the impact."""
        fid = self.confirmed("ssrf")
        with self.assertRaisesRegex(StageError, "claims data exposure"):
            self.prove(fid, data_impact=None)

    def test_poe_4_is_earned_by_the_measurement_not_asserted(self):
        fid = self.confirmed()
        with self.assertRaisesRegex(StageError, "PoE 4 needs data worth critical"):
            self.prove(fid, poe_level=4)  # 3 business records supports only high
        out = self.prove(fid, poe_level=4, severity="critical", data_impact=_measurement(
            reachable=5000, sampled=20, enumeration="bounded-sample",
            classes={"business-record": 20},
            subjects=["other tenants' orders, enumerable across the whole id space"]))
        self.assertEqual((out["poe_level"], out["severity"]), (4, "critical"))

    def test_a_state_change_is_rated_without_a_data_measurement(self):
        """An access-control finding that *renames* an object reads no data to count."""
        fid = self.confirmed("csrf")   # defaults to state-change
        self.assertEqual(self.prove(fid, data_impact=None)["stage"], "impact-proven")
        out = self.prove(self.confirmed("race-conditions"), poe_level=4, data_impact=None,
                         severity="critical",
                         measurement="1 of 1 owned objects double-spent")
        self.assertEqual(out["severity"], "critical")

    def test_a_data_class_may_declare_an_action_impact_and_it_is_recorded(self):
        fid = self.confirmed("access-control")
        with self.assertRaisesRegex(StageError, "claims data exposure"):
            self.prove(fid, data_impact=None)
        out = self.prove(fid, data_impact=None, impact_kind="state-change",
                         measurement="1 of 1 other-tenant objects renamed from A's session")
        self.assertEqual(out["stage"], "impact-proven")
        # The declaration is on the record, so a validator can see and dispute it.
        self.assertEqual(self.fx.events(fid)[-1]["evidence"]["impact_kind"], "state-change")

    def test_an_unknown_impact_kind_is_refused(self):
        with self.assertRaisesRegex(StageError, "impact kind must be one of"):
            self.prove(self.confirmed("csrf"), impact_kind="whatever")

    def test_severity_above_the_ceiling_is_refused_then_allowed_with_a_reason(self):
        fid = self.confirmed()
        with self.assertRaisesRegex(StageError, "above the 'high' ceiling"):
            self.prove(fid, severity="critical")
        out = self.prove(fid, severity="critical",
                         override="program rules rate any cross-tenant read critical")
        self.assertEqual(out["severity"], "critical")
        recorded = self.fx.events(fid)[-1]["evidence"]["severity_override"]
        self.assertEqual((recorded["claimed"], recorded["ceiling"]), ("critical", "high"))
        self.assertIn("program rules", recorded["reason"])

    def test_an_uncharacterised_read_cannot_be_called_critical(self):
        """The 2026-11-22 rule, at the point it bites: a data claim with no measurement."""
        fid = self.confirmed("info-disclosure")
        with self.assertRaisesRegex(StageError, "claims data exposure"):
            self.prove(fid, severity="critical", data_impact=None)
        # Declaring data-exposure but measuring only noise caps the rating at low.
        with self.assertRaisesRegex(StageError, "above the 'low' ceiling"):
            self.prove(fid, severity="critical", poe_level=3,
                       measurement="1 of 1 bundles read",
                       data_impact=_measurement(classes={"build-metadata": 3}))

    def test_a_measurement_is_validated_on_every_transition(self):
        """Regression: `--data-impact` was only checked on the impact-proven move, so a
        raw value passed on any other transition was silently accepted and dropped."""
        fid = self.confirmed("ssrf")
        self.prove(fid, data_impact=_measurement(
            reachable=5, sampled=1, classes={"internal-hostname": 1},
            subjects=["one internal host"]))
        leak = _measurement(reachable=5, sampled=1, classes={"api-key": 1},
                            subjects=["a key"],
                            fingerprints=[{"field": "K", "prefix": "ab", "sha256": DIGEST}])
        leak["fingerprints"][0]["value"] = "sk_live_realsecret"
        with self.assertRaisesRegex(StageError, "looks like a raw value"):
            self.fx.move(fid, "reported", data_impact=leak)
        # And a valid measurement supplied elsewhere is recorded, not discarded.
        self.fx.move(fid, "reported", data_impact=_measurement(
            reachable=9, sampled=2, classes={"pii": 2}, subjects=["two customers"]))
        evidence = self.fx.events(fid)[-1]["evidence"]
        self.assertEqual(evidence["data_impact"]["reachable"], 9)
        self.assertIn("sensitive-tier", evidence["data_impact_summary"])

    def test_confirmed_still_caps_at_medium(self):
        fid, _ = self.fx.add("IDOR lead", "idor-bola", asset_id=self.asset)
        with self.assertRaisesRegex(StageError, "above the 'medium' ceiling"):
            self.fx.move(fid, "confirmed", replay=self.art("r9.txt", "200"),
                         control=self.art("c9.txt", "403"), severity="high")

    def test_a_lead_carries_no_severity_claim(self):
        fid, _ = self.fx.add("Maybe something", "info-disclosure", asset_id=self.asset)
        self.assertEqual(self.fx.get(fid)["poe_level"], 0)

    def test_an_old_campaign_gains_the_column_without_losing_rows(self):
        self.ctx.store.db.execute("DROP TABLE finding_events")
        self.ctx.store.db.execute("ALTER TABLE findings RENAME TO findings_old")
        self.ctx.store.db.execute(
            "CREATE TABLE findings(id INTEGER PRIMARY KEY, title TEXT NOT NULL,"
            " bug_class TEXT NOT NULL, asset_id INTEGER, url TEXT, host TEXT,"
            " stage TEXT NOT NULL DEFAULT 'lead', severity TEXT,"
            " tech TEXT NOT NULL DEFAULT '[]', source TEXT NOT NULL DEFAULT 'manual',"
            " priority INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '{}',"
            " dedup_key TEXT UNIQUE, created TEXT, updated TEXT)")
        self.ctx.store.db.execute(
            "INSERT INTO findings(id,title,bug_class,url,stage) "
            "VALUES(1,'legacy','xss','https://app.example.test/x','confirmed')")
        self.ctx.store.db.commit()
        fresh = Findings(self.ctx)
        self.assertEqual(fresh.get(1)["poe_level"], 0)
        self.assertEqual(fresh.get(1)["title"], "legacy")


if __name__ == "__main__":
    unittest.main()
