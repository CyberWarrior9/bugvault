"""Offline DNS/provider-model regressions; no DNS, sockets or provider requests."""
from copy import deepcopy
from datetime import date, datetime, timezone
import unittest
from unittest.mock import patch

from recon.takeover_dns import (RECORD_TYPES, classify, normalize_name, provider_info,
                                validate_capture, validate_provider_records)


AT = "2026-11-16"
TIME = "2026-11-16T10:00:00Z"


def observation(name="old.example.test", kind="CNAME", value="unused.herokuapp.com", **kwargs):
    row = {"name": name, "record_type": kind, "value": value, "result": "answer",
           "resolver": "192.0.2.53", "observed_at": TIME, "vantage": "recursive"}
    row.update(kwargs)
    return row


def capture(*rows):
    return {"schema": 1, "source": "owned offline fixture", "observations": list(rows)}


def provider(status="vulnerable", checked="2026-11-16", **kwargs):
    row = {"provider": "heroku", "status": status, "source": "https://docs.example.test/status", "checked": checked}
    row.update(kwargs)
    return row


def control(kind="CNAME", value="", result="nxdomain", **kwargs):
    name = kwargs.pop("name", "bv-9af37d12.example.test")
    target = kwargs.pop("control_for", "old.example.test")
    return observation(name, kind, value, result=result,
                       vantage="wildcard-control", control_for=target, **kwargs)


def classified(rows, **kwargs):
    return next(r for r in classify(rows, at=AT, **kwargs) if r["name"] == "old.example.test" and r["record_type"] == "CNAME")


class NameTests(unittest.TestCase):
    def test_record_types_and_normalization(self):
        self.assertEqual(RECORD_TYPES, ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA"))
        self.assertEqual(normalize_name("WWW.BÜCHER.Example."), "www.xn--bcher-kva.example")
        self.assertEqual(normalize_name("xn--bcher-kva.example"), "xn--bcher-kva.example")
        self.assertEqual(normalize_name("a"), "a")
        self.assertEqual(normalize_name("*.Example.Test", allow_wildcard=True), "*.example.test")

    def test_unsafe_and_invalid_names(self):
        for value in (None, 3, "", ".", " example.test", "example.test ", "a..test", "a.test..", "-a.test", "a-.test",
                      "a_b.test", "*.test", "a.*.test", "*", "a/test", "a\\test", "a:test", "a@test", "a?test", "a#test",
                      "a;test", "a|test", "a&test", "$(id).test", "a`x`.test", "a\ntest", "a\ttest", "a\x00test",
                      "a\u202etest", "a\u200btest", "a\u3002test", "a\ufe0f.test", "\u0301a.test", "😀.test",
                      "xn--e28h.test", "xn--.test", "xn--garbage-.test", "a" * 64 + ".test"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_name(value)

    def test_total_and_label_length(self):
        valid = ".".join(["a" * 63] * 3 + ["b" * 61])
        self.assertEqual(len(normalize_name(valid)), 253)
        with self.assertRaises(ValueError):
            normalize_name(valid + "b")


class CaptureTests(unittest.TestCase):
    def test_all_record_types_normalize_without_mutation(self):
        raw = capture(observation("OLD.Example.Test.", value="Unused.Herokuapp.Com."),
                      observation(kind="A", value="192.0.2.10"),
                      observation(kind="AAAA", value="2001:0DB8:0:0::1"),
                      observation(kind="NS", value="NS1.Example.Test."),
                      observation(kind="MX", value="0010 Mail.Example.Test."),
                      observation(kind="TXT", value='"v=spf1 include:_spf.example.test -all"'),
                      observation(kind="SOA", value="NS1.Example.Test. Hostmaster.Example.Test. 0001 3600 600 86400 60"))
        original = deepcopy(raw)
        out = validate_capture(raw)
        self.assertEqual(raw, original)
        self.assertEqual(out["observations"][0]["name"], "old.example.test")
        self.assertEqual(out["observations"][0]["value"], "unused.herokuapp.com")
        self.assertEqual(out["observations"][2]["value"], "2001:db8::1")
        self.assertEqual(out["observations"][4]["value"], "10 mail.example.test")
        self.assertTrue(out["observations"][6]["value"].startswith("ns1.example.test hostmaster.example.test 1 "))
        self.assertEqual(out["observations"][0]["observed_at"], "2026-11-16T10:00:00+00:00")
        self.assertEqual(validate_capture(out), out)

    def test_out_of_scope_and_empty_bundle_are_intel(self):
        self.assertEqual(validate_capture(capture())["observations"], [])
        self.assertEqual(validate_capture(capture(observation("outside.unrelated.test")))["observations"][0]["name"],
                         "outside.unrelated.test")

    def test_envelope_and_observation_fields_are_exact(self):
        for raw in ({}, [], {**capture(), "schema": True}, {**capture(), "schema": 2},
                    {**capture(), "source": ""}, {**capture(), "source": "\n"},
                    {**capture(), "observations": {}}, {**capture(), "extra": "no"}):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                validate_capture(raw)
        for field in observation():
            row = observation()
            del row[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_capture(capture(row))
        with self.assertRaises(ValueError):
            validate_capture(capture(observation(unknown="no")))

    def test_bounds(self):
        self.assertEqual(len(validate_capture(capture(*[observation()] * 2000))["observations"]), 2000)
        with self.assertRaises(ValueError):
            validate_capture(capture(*[observation()] * 2001))
        for value in ("a" * 4097, "é" * 2049, "line\nline", "line\rline", "line\tline", "x\x00x", "x\u2028x"):
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                validate_capture(capture(observation(kind="TXT", value=value)))
        self.assertEqual(validate_capture(capture(observation(kind="TXT", value="a" * 4096)))["observations"][0]["value"], "a" * 4096)

    def test_record_shape_validation(self):
        cases = [("A", "2001:db8::1"), ("AAAA", "192.0.2.1"), ("AAAA", "fe80::1%en0"), ("A", "127.1"),
                 ("A", "192.0.2.1;id"), ("CNAME", "https://example.test"), ("NS", "_ns.example.test"),
                 ("MX", "65536 mail.example.test"), ("MX", "10  mail.example.test"), ("MX", "1 ."),
                 ("MX", "mail.example.test"), ("SOA", "ns.test mail.test 1 2 3 4"),
                 ("SOA", "ns.test mail.test 1 2 3 4 4294967296")]
        for kind, value in cases:
            with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                validate_capture(capture(observation(kind=kind, value=value)))
        self.assertEqual(validate_capture(capture(observation(kind="MX", value="0 .")))["observations"][0]["value"], "0 .")

    def test_enum_values_and_negative_values(self):
        for kwargs in ({"record_type": "PTR"}, {"record_type": "a"}, {"result": "NOERROR"}, {"vantage": "parent"},
                       {"result": "nxdomain"}, {"resolver": "https://dns.test"}, {"resolver": "dns.test;id"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                validate_capture(capture(observation(**kwargs)))
        for result in ("nxdomain", "nodata", "servfail", "timeout", "refused"):
            self.assertEqual(validate_capture(capture(observation(value="", result=result)))["observations"][0]["result"], result)
        self.assertEqual(validate_capture(capture(observation(value="")))["observations"][0]["value"], "")

    def test_timestamps_require_zone_and_valid_calendar(self):
        for timestamp in ("2026-11-16", "2026-11-16T10:00:00", "2026-02-30T10:00:00Z", "2026-11-16T10:00Z",
                          "2026-11-16T10:00:00+00:99", "2026-11-16T10:00:00+24:00", TIME + "\n"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                validate_capture(capture(observation(observed_at=timestamp)))
        out = validate_capture(capture(observation(observed_at="2026-11-16T12:00:00+02:00")))
        self.assertEqual(out["observations"][0]["observed_at"], "2026-11-16T10:00:00+00:00")

    def test_certificate_dates_and_parent_referral(self):
        out = validate_capture(capture(observation(kind="NS", value="ns.test", zone="EXAMPLE.TEST.",
                                                  vantage="parent-referral", certificate_not_before=TIME,
                                                  certificate_not_after="2027-11-16T10:00:00Z")))
        self.assertEqual(out["observations"][0]["zone"], "example.test")
        for kwargs in ({"zone": "ample.test"}, {"vantage": "parent-referral"},
                       {"vantage": "parent-referral", "zone": "example.test"},
                       {"certificate_not_before": TIME, "certificate_not_after": "2025-01-01T00:00:00Z"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                validate_capture(capture(observation(**kwargs)))

    def test_control_binding_randomish_and_distinct(self):
        rows = [observation(zone="example.test"), control()]
        self.assertEqual(len(validate_capture(capture(*rows))["observations"]), 2)
        self.assertEqual(len(validate_capture(capture(rows[0], control(control_for="example.test")))["observations"]), 2)
        bad = [control(name="old.example.test"), control(name="random8.evil.test"),
               control(name="aaaaaaaa.example.test"), control(name="12345678.example.test"),
               control(name="test.example.test"), control(name="a.bv-9af37d12.example.test"),
               control(control_for="unobserved.example.test")]
        for row in bad:
            with self.subTest(row=row), self.assertRaises(ValueError):
                validate_capture(capture(rows[0], row))
        with self.assertRaises(ValueError):
            validate_capture(capture(observation(control_for="other.test")))
        row = control()
        del row["control_for"]
        with self.assertRaises(ValueError):
            validate_capture(capture(observation(), row))
        with self.assertRaises(ValueError):
            validate_capture(capture(control()))

    def test_explicit_service_labels_for_dkim_and_spf(self):
        rows = [observation("S1._domainkey.Example.Test.", value="s1._domainkey.vendor.test"),
                observation("_spf.example.test", "TXT", "v=spf1 -all")]
        self.assertEqual(validate_capture(capture(*rows))["observations"][0]["name"], "s1._domainkey.example.test")
        with self.assertRaises(ValueError):
            validate_capture(capture(observation("arbitrary_under.example.test")))


class ProviderTests(unittest.TestCase):
    def test_missing_unknown_and_freshness_boundary(self):
        info = provider_info("heroku", [], at=AT)
        self.assertEqual(info["status"], "unknown")
        self.assertTrue(info["stale"])
        self.assertIsNone(info["checked"])
        info = provider_info("HEROKU", [provider(checked="2026-08-18")], at=AT)
        self.assertEqual(info["age_days"], 90)
        self.assertFalse(info["stale"])
        self.assertTrue(provider_info("heroku", [provider(checked="2026-08-17")], at=AT)["stale"])
        self.assertIn("provider-status-is-an-assertion", info["basis"])
        for absent in (None, ""):
            self.assertEqual(provider_info(absent, [], at=AT)["status"], "unknown")
            self.assertTrue(provider_info(absent, [], at=AT)["stale"])

    def test_latest_record_and_conflicting_sources(self):
        rows = [provider("vulnerable", "2026-01-01"), provider("patched")]
        self.assertEqual(provider_info("heroku", rows, at=AT)["status"], "patched")
        rows.append(provider("edge-case", source="https://other.test/status"))
        info = provider_info("heroku", rows, at=AT)
        self.assertTrue(info["conflict"])
        self.assertEqual(info["status"], "unknown")
        self.assertIsNone(info["source"])

    def test_strict_status_records(self):
        for row in (provider("confirmed"), provider(checked="2026-11-17"), provider(checked="2026-02-30"),
                    provider(checked="2026-1-1"), provider(source="http://docs.test"), provider(source="https://user:pass@docs.test"),
                    provider(source="https://docs.test/#fragment"), provider(source="https://docs.test:99999/"),
                    provider(source="https://docs.test/a\nb"), provider(source="https://docs.test\\evil/"),
                    provider(source="https://docs.test:0/"), provider(provider="heroku;id"), provider(extra=True)):
            with self.subTest(row=row), self.assertRaises(ValueError):
                validate_provider_records([row], at=AT)
        for rows in (None, {}, [provider()] * 2001):
            with self.subTest(type=type(rows)), self.assertRaises(ValueError):
                validate_provider_records(rows, at=AT)

    def test_date_inputs_and_no_mutation(self):
        rows = [provider(source="https://DOCS.Example.Test./status")]
        original = deepcopy(rows)
        for at in (date(2026, 11, 16), datetime(2026, 11, 16, tzinfo=timezone.utc), "2026-11-16T10:00:00Z"):
            self.assertEqual(provider_info("heroku", rows, at=at)["source"], "https://docs.example.test/status")
        self.assertEqual(rows, original)
        with self.assertRaises(ValueError):
            provider_info("heroku", rows, at=datetime(2026, 11, 16))
        info = provider_info("heroku", [provider(source="https://[2001:db8::1]:443/status")], at=AT)
        self.assertEqual(info["source"], "https://[2001:db8::1]:443/status")


class ClassificationTests(unittest.TestCase):
    def missing_target(self, **kwargs):
        return [observation(), observation("unused.herokuapp.com", "A", "", result="nxdomain"), control(**kwargs)]

    def test_cname_potential_is_not_claimability(self):
        lead = classified(self.missing_target(), provider_status=[provider()])
        self.assertEqual(lead["provider"], "heroku")
        self.assertEqual(lead["confidence"], "potential")
        self.assertEqual(lead["address"]["state"], "nxdomain")
        self.assertEqual(lead["address"]["AAAA"], "missing")
        self.assertEqual(lead["wildcard_state"], "negative")
        self.assertIn("claimability-not-established", lead["basis"])
        self.assertNotIn("confirmed", lead.values())
        self.assertNotIn("claimable", lead)

    def test_ipv6_answer_not_dangle_from_missing_ipv4(self):
        rows = [observation(), observation("unused.herokuapp.com", "A", "", result="nodata"),
                observation("unused.herokuapp.com", "AAAA", "2001:db8::1"), control()]
        lead = classified(rows, provider_status=[provider()])
        self.assertEqual(lead["address"], {"name": "unused.herokuapp.com", "state": "resolved", "A": "nodata", "AAAA": "answer"})
        self.assertEqual(lead["confidence"], "candidate")
        self.assertNotIn("cname-target-nxdomain", lead["basis"])

    def test_family_specific_nodata_not_name_wide_nxdomain(self):
        rows = [observation(), observation("unused.herokuapp.com", "A", "", result="nodata"), control()]
        lead = classified(rows, provider_status=[provider()])
        self.assertEqual(lead["address"]["state"], "unknown")
        self.assertEqual(lead["confidence"], "collection-gap")
        rows.append(observation("unused.herokuapp.com", "AAAA", "", result="nodata"))
        lead = classified(rows, provider_status=[provider()])
        self.assertEqual(lead["address"]["state"], "no-address-data")
        self.assertEqual(lead["confidence"], "potential")
        self.assertNotIn("cname-target-nxdomain", lead["basis"])

    def test_transport_errors_and_empty_answers_are_not_nxdomain(self):
        for result in ("timeout", "servfail", "refused", "answer"):
            rows = [observation(), observation("unused.herokuapp.com", "A", "", result=result), control()]
            with self.subTest(result=result):
                lead = classified(rows, provider_status=[provider()])
                self.assertEqual(lead["address"]["state"], "unknown")
                self.assertEqual(lead["confidence"], "collection-gap")
                self.assertNotIn("cname-target-nxdomain", lead["basis"])
        self.assertEqual(classified([observation(value="")])["confidence"], "collection-gap")
        self.assertEqual(classify([], at=AT), [])

    def test_conflicting_answer_nxdomain_is_gap(self):
        rows = self.missing_target() + [observation("unused.herokuapp.com", "AAAA", "2001:db8::1")]
        lead = classified(rows, provider_status=[provider()])
        self.assertEqual(lead["address"]["state"], "inconsistent")
        self.assertEqual(lead["confidence"], "collection-gap")

    def test_disagreeing_resolver_contexts_cannot_be_cherry_picked(self):
        rows = self.missing_target() + [observation(resolver="192.0.2.54"),
                observation("unused.herokuapp.com", "A", "192.0.2.10", resolver="192.0.2.54"),
                control(resolver="192.0.2.54")]
        lead = classified(rows, provider_status=[provider()])
        self.assertEqual(lead["address"]["state"], "inconsistent")
        self.assertEqual(lead["confidence"], "collection-gap")
        self.assertEqual(lead["resolvers"], ["192.0.2.53", "192.0.2.54"])

    def test_nxdomain_from_other_query_type_is_name_wide_but_contradictions_are_gaps(self):
        rows = [observation(), observation("unused.herokuapp.com", "CNAME", "", result="nxdomain"), control()]
        self.assertEqual(classified(rows, provider_status=[provider()])["address"]["state"], "nxdomain")
        rows.append(observation("unused.herokuapp.com", "TXT", "exists"))
        self.assertEqual(classified(rows, provider_status=[provider()])["address"]["state"], "inconsistent")

    def test_suffix_boundary_and_unknown_provider(self):
        rows = [observation(value="herokuapp.com.evil.test"), control(),
                observation("herokuapp.com.evil.test", "A", "", result="nxdomain")]
        lead = classified(rows)
        self.assertIsNone(lead["provider"])
        self.assertEqual(lead["confidence"], "collection-gap")
        self.assertIn("provider-requirements-unknown", lead["gaps"])

    def test_provider_freshness_and_patched_do_not_certify(self):
        rows = self.missing_target()
        self.assertEqual(classified(rows)["confidence"], "provider-stale")
        self.assertEqual(classified(rows, provider_status=[provider(checked="2026-01-01")])["confidence"], "provider-stale")
        self.assertEqual(classified(rows, provider_status=[provider("patched")])["confidence"], "candidate")
        self.assertEqual(classified(rows, provider_status=[provider("unknown")])["confidence"], "collection-gap")
        lead = classified(rows, provider_status=[provider("vulnerable"), provider("patched")])
        self.assertEqual(lead["confidence"], "collection-gap")

    def test_wildcard_matching_answering_unknown_and_missing(self):
        for ctrl, state in ((control(value="unused.herokuapp.com", result="answer"), "matching"),
                            (control(value="other.vendor.test", result="answer"), "answering"),
                            (control(result="timeout"), "unknown"),
                            (control(value="", result="answer"), "unknown")):
            lead = classified(self.missing_target()[:2] + [ctrl], provider_status=[provider()])
            self.assertEqual(lead["wildcard_state"], state)
            self.assertEqual(lead["confidence"], "collection-gap")
        self.assertEqual(classified(self.missing_target()[:2], provider_status=[provider()])["wildcard_state"], "untested")

    def test_conflicting_wildcard_controls_preserve_ambiguity(self):
        rows = self.missing_target() + [control(name="bv-73cae19f.example.test", value="other.test", result="answer")]
        lead = classified(rows, provider_status=[provider()])
        self.assertEqual(lead["wildcard_state"], "inconsistent")
        self.assertEqual(lead["confidence"], "collection-gap")

    def test_comparisons_cannot_borrow_other_resolvers_times_or_types(self):
        for kwargs in ({"resolver": "192.0.2.54"}, {"observed_at": "2025-11-16T10:00:00Z"}):
            rows = [observation(), observation("unused.herokuapp.com", "A", "", result="nxdomain", **kwargs), control()]
            self.assertEqual(classified(rows, provider_status=[provider()])["address"]["state"], "unknown")
            rows = self.missing_target()[:2] + [control(**kwargs)]
            self.assertEqual(classified(rows, provider_status=[provider()])["wildcard_state"], "untested")
        rows = self.missing_target()[:2] + [control(kind="A")]
        self.assertEqual(classified(rows, provider_status=[provider()])["wildcard_state"], "untested")

    def test_latest_capture_replaces_not_erases_historical_records(self):
        rows = self.missing_target()
        rows.append(observation("unused.herokuapp.com", "A", "192.0.2.10", observed_at="2026-11-16T11:00:00Z"))
        original = deepcopy(rows)
        lead = classified(rows, provider_status=[provider()])
        self.assertEqual(lead["address"]["state"], "resolved")
        self.assertEqual(lead["confidence"], "candidate")
        rows.append(observation(value="new.vendor.test", observed_at="2026-11-16T12:00:00Z"))
        leads = classify(rows, at=AT)
        self.assertFalse(any(r["name"] == "old.example.test" and r["value"] == "unused.herokuapp.com" for r in leads))
        self.assertEqual(rows[:len(original)], original)

    def test_zone_control_does_not_cover_arbitrary_deeper_names(self):
        rows = [observation("deep.old.example.test", zone="example.test"),
                control(control_for="example.test")]
        lead = next(r for r in classify(rows, at=AT) if r["name"] == "deep.old.example.test")
        self.assertEqual(lead["wildcard_state"], "untested")

    def test_zone_child_control_is_not_a_same_depth_apex_control(self):
        rows = [observation("example.test", zone="example.test"), control(control_for="example.test")]
        lead = next(r for r in classify(rows, at=AT) if r["name"] == "example.test")
        self.assertEqual(lead["wildcard_state"], "untested")

    def test_a_aaaa_never_infer_recyclable_ip(self):
        for kind, value in (("A", "192.0.2.1"), ("AAAA", "2001:db8::1")):
            lead = classify([observation(kind=kind, value=value)], at=AT)[0]
            self.assertEqual(lead["confidence"], "collection-gap")
            self.assertIn("recyclable-address-ownership-not-established", lead["gaps"])

    def test_ns_recursive_is_not_delegation_candidate(self):
        rows = [observation(kind="NS", value="ns.parent.test"),
                observation(kind="NS", value="ns.child.test", vantage="child-authoritative")]
        for lead in classify(rows, at=AT):
            self.assertEqual(lead["confidence"], "collection-gap")
            self.assertNotEqual(lead["referral_state"], "mismatch")

    def test_parent_and_child_missing_sides_are_collection_gaps(self):
        for vantage, state in (("parent-referral", "child-missing"), ("child-authoritative", "parent-missing")):
            lead = classify([observation(kind="NS", value="ns.test", vantage=vantage, zone="old.example.test")], at=AT)[0]
            self.assertEqual(lead["referral_state"], state)
            self.assertEqual(lead["confidence"], "collection-gap")

    def test_parent_child_mismatch_and_match_are_only_leads(self):
        parent = observation(kind="NS", value="ns.parent.test", vantage="parent-referral", zone="old.example.test")
        child = observation(kind="NS", value="ns.child.test", vantage="child-authoritative", resolver="ns.child.test")
        rows = [parent, child, control(kind="NS")]
        lead = next(r for r in classify(rows, at=AT) if r["value"] == "ns.parent.test")
        self.assertEqual(lead["referral_state"], "mismatch")
        self.assertEqual(lead["confidence"], "potential")
        self.assertIn("ns-mismatch-is-not-claimability", lead["basis"])
        child["value"] = "ns.parent.test"
        self.assertEqual(classify(rows, at=AT)[0]["referral_state"], "match")
        child.update(value="", result="timeout")
        self.assertEqual(classify(rows, at=AT)[0]["referral_state"], "unknown")

    def test_referral_requires_whole_rrsets_not_unions(self):
        rows = [observation(kind="NS", value="ns1.test", zone="old.example.test", vantage="parent-referral"),
                observation(kind="NS", value="ns2.test", zone="old.example.test", vantage="parent-referral"),
                observation(kind="NS", value="ns1.test", vantage="child-authoritative", resolver="ns1.test"), control(kind="NS")]
        self.assertEqual(next(r for r in classify(rows, at=AT) if r["value"] == "ns2.test")["referral_state"], "mismatch")
        rows.append(observation(kind="NS", value="ns2.test", vantage="child-authoritative", resolver="ns2.test"))
        self.assertTrue(all(r["referral_state"] == "inconsistent" for r in classify(rows, at=AT)))

    def test_mx_spf_dkim_dependencies_and_null_mx(self):
        rows = [observation(kind="MX", value="10 mail.external.test"),
                observation(kind="TXT", value="v=spf1 include:_spf.external.test redirect=other.external.test a:a.external.test mx:mx.external.test -all"),
                observation("s1._domainkey.example.test", value="s1._domainkey.external.test"),
                observation("_spf.external.test", "TXT", "", result="nxdomain"),
                observation("s1._domainkey.external.test", "TXT", "v=DKIM1; k=rsa; p=fixture"),
                observation("null.example.test", "MX", "0 .")]
        leads = classify(rows, at=AT)
        mx = next(r for r in leads if r["name"] == "old.example.test" and r["record_type"] == "MX")
        self.assertEqual(mx["dependencies"][0]["name"], "mail.external.test")
        self.assertEqual(mx["dependencies"][0]["state"], "unknown")
        spf = next(r for r in leads if r["record_type"] == "TXT" and r["name"] == "old.example.test")
        self.assertEqual({r["kind"] for r in spf["dependencies"]}, {"spf-include", "spf-redirect", "spf-a", "spf-mx"})
        self.assertEqual(next(r for r in spf["dependencies"] if r["kind"] == "spf-include")["state"], "nxdomain")
        dkim = next(r for r in leads if r["name"] == "s1._domainkey.example.test")
        self.assertEqual(dkim["dependencies"][0]["state"], "answer")
        self.assertEqual(next(r for r in leads if r["name"] == "null.example.test")["dependencies"], [])
        self.assertTrue(all(r["confidence"] == "collection-gap" for r in leads))

    def test_spf_macros_and_malformed_refs_are_unresolved_not_expanded(self):
        rows = [observation(kind="TXT", value="v=spf1 exists:%{i}.vendor.test include:bad/name.test -all")]
        lead = classify(rows, at=AT)[0]
        self.assertEqual(lead["dependencies"], [])
        self.assertIn("spf-macro-reference-unresolved", lead["gaps"])
        self.assertIn("invalid-spf-reference", lead["gaps"])

    def test_implicit_spf_and_mail_fallback_dependencies(self):
        rows = [observation(kind="TXT", value="v=spf1 a mx ptr exists:check.external.test -all"),
                observation(kind="MX", value="", result="nodata"),
                observation("check.external.test", "A", "", result="nodata"),
                observation("check.external.test", "AAAA", "2001:db8::1")]
        leads = classify(rows, at=AT)
        txt = next(r for r in leads if r["record_type"] == "TXT")
        self.assertEqual({r["kind"] for r in txt["dependencies"]}, {"spf-a", "spf-mx", "spf-ptr", "spf-exists"})
        self.assertEqual(next(r for r in txt["dependencies"] if r["kind"] == "spf-exists")["state"], "nodata")
        mx = next(r for r in leads if r["record_type"] == "MX")
        self.assertEqual(mx["dependencies"][0]["kind"], "mx-implicit-address-fallback")

    def test_deterministic_deduplication_no_mutation_and_no_network(self):
        rows = self.missing_target()
        original = deepcopy(rows)
        with patch("socket.getaddrinfo", side_effect=AssertionError("network forbidden")), \
                patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = classify(rows, provider_status=[provider()], at=AT)
            self.assertEqual(result, classify(list(reversed(rows)) + rows, provider_status=[provider()], at=AT))
            provider_info("heroku", [provider()], at=AT)
        self.assertEqual(rows, original)
        self.assertEqual(len(result), 2)  # controls are evidence, not their own candidates

    def test_classify_revalidates_and_keeps_negative_statuses_distinct(self):
        with self.assertRaises(ValueError):
            classify([observation(value="host.test;id")], at=AT)
        with self.assertRaises(ValueError):
            classify([observation(), control(control_for="unobserved.test")], at=AT)
        rows = [observation(kind="A", value="", result="timeout"),
                observation(kind="A", value="", result="nxdomain", resolver="192.0.2.54")]
        lead = classify(rows, at=AT)[0]
        self.assertEqual(lead["results"], ["nxdomain", "timeout"])
        self.assertEqual(lead["confidence"], "collection-gap")
        self.assertEqual(lead["resolvers"], ["192.0.2.53", "192.0.2.54"])


if __name__ == "__main__":
    unittest.main()
