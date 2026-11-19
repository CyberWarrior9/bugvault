"""Offline, privacy and false-positive regressions for takeover trust parsing."""
import hashlib
import json
import unittest
from unittest.mock import patch

from recon.takeover_trust import cookie_context, extract_trust, host_matches


def edges(kind, headers=None, body="", url="https://app.example.test/private/page", **kwargs):
    return [e for e in extract_trust(url, headers or {}, body, **kwargs) if e["kind"] == kind]


class HostMatchingTests(unittest.TestCase):
    def test_exact_and_explicit_wildcard_boundaries(self):
        for candidate, reference, expected in [
                ("dead.example.test", "dead.example.test", True),
                ("DEAD.EXAMPLE.TEST.", "dead.example.test", True),
                ("dead.example.test", "*.example.test", True),
                ("a.dead.example.test", "*.example.test", True),
                ("example.test", "*.example.test", False),
                ("notexample.test", "*.example.test", False),
                ("dead.example.test.attacker.test", "*.example.test", False),
                ("dead.example.test", "example.test", False),
                ("dead.example.test", ".example.test", False),
                ("dead.example.test", "*", False),
                ("https://dead.example.test:8443/x", "https://*.example.test:443/assets/", True),
                ("attacker.test", "https://example.test@attacker.test", False),
                ("x.example.co.uk", "*.example.co.uk", True),
                ("x.other.co.uk", "*.example.co.uk", False),
                ("https://[::1]:8443/", "https://[::1]:443/", True),
                ("bücher.example", "xn--bcher-kva.example", True)]:
            with self.subTest(candidate=candidate, reference=reference):
                self.assertEqual(host_matches(candidate, reference), expected)


class CookieTrustTests(unittest.TestCase):
    def test_multi_cookie_header_forms_and_no_values(self):
        headers = {"sEt-CoOkIe": [
            "session=COOKIE_SECRET_ONE; Domain=example.test; Secure; HttpOnly; SameSite=None; Path=/account\n"
            "prefs=COOKIE_SECRET_TWO; Domain=.example.test; Path=/; SameSite=Lax",
            "__Host-private=COOKIE_SECRET_THREE; Secure; Path=/; HttpOnly"]}
        context = cookie_context("https://app.example.test/start", headers, "dead.example.test")
        self.assertEqual([c["name"] for c in context], ["session", "prefs"])
        self.assertEqual(context[0]["domain"], "example.test")
        self.assertTrue(context[0]["secure"])
        self.assertTrue(context[0]["httponly"])
        self.assertEqual(context[0]["samesite"], "none")
        self.assertEqual(context[0]["path"], "/account")
        self.assertFalse(context[0]["host_only"])
        self.assertEqual(context[0]["public_suffix"], "unknown")
        self.assertFalse(context[0]["session_inferred"])
        self.assertEqual(context[0]["browser_acceptance"], "unknown")
        found = edges("cookie-domain", headers)
        self.assertEqual(len(found), 2)
        self.assertEqual(found[0]["name"], "example.test")
        self.assertNotIn("COOKIE_SECRET", json.dumps(context + found))

    def test_name_value_pairs_and_folded_expires(self):
        headers = [("SET-COOKIE", "a=secret; Domain=example.test; Expires=Wed, 21 Oct 2030 07:28:00 GMT, "
                    "b=other; Domain=.example.test; Path=/b"),
                   ("Set-Cookie", "c=third; Domain=example.test")]
        result = cookie_context("https://app.example.test/", headers, "dead.example.test")
        self.assertEqual([c["name"] for c in result], ["a", "b", "c"])

    def test_har_headers_attribute_whitespace_and_path_redaction(self):
        headers = [{"name": "Set-Cookie", "value":
                    "a=COOKIE_SECRET; DOMAIN = example.test ; PATH = /area?token=PATH_SECRET; HttpOnly"}]
        result = cookie_context("https://app.example.test/", headers, "https://dead.example.test/area")
        self.assertEqual(result[0]["path"], "/area")
        self.assertIsNone(result[0]["path_matches"])
        self.assertTrue(result[0]["httponly"])
        self.assertNotIn("SECRET", json.dumps(result))

    def test_setter_must_be_covered_and_candidate_boundaries(self):
        headers = {"set-cookie": "sid=secret; Domain=example.test"}
        for target in ("notexample.test", "example.test.evil.test", "other.test"):
            self.assertEqual(cookie_context("https://app.example.test/", headers, target), [])
        self.assertEqual(cookie_context("https://attacker.test/", headers, "dead.example.test"), [])
        self.assertEqual(edges("cookie-domain", headers, url="https://attacker.test/"), [])
        self.assertEqual(cookie_context("https://app.example.test/", {
            "Set-Cookie": "a=x; Domain=ample.test"}, "dead.ample.test"), [])

    def test_co_uk_compared_directly_without_two_label_guess(self):
        headers = {"Set-Cookie": "a=x; Domain=example.co.uk"}
        self.assertTrue(cookie_context("https://app.example.co.uk/", headers, "dead.example.co.uk"))
        self.assertFalse(cookie_context("https://app.example.co.uk/", headers, "dead.other.co.uk"))
        for broad in ("co.uk", ".uk", ".com", ".github.io"):
            self.assertEqual(edges("cookie-domain", {"Set-Cookie": f"a=x; Domain={broad}"},
                                   url="https://app.example.co.uk/"), [])
        unknown = cookie_context("https://app.example.custom/", {
            "Set-Cookie": "a=x; Domain=example.custom"}, "dead.example.custom")
        self.assertEqual(unknown[0]["public_suffix"], "unknown")

    def test_malformed_domains_not_graph_edges(self):
        for domain in ("..example.test", "example.test.", "*.example.test", "https://example.test",
                       '"example.test"', "example.test:443", "example.test/", "example.test@evil.test"):
            with self.subTest(domain=domain):
                self.assertEqual(edges("cookie-domain", {"Set-Cookie": f"a=x; Domain={domain}"}), [])

    def test_host_only_and_host_prefix_have_no_sibling_graph_edge(self):
        headers = {"Set-Cookie": "__Host-id=HOST_SECRET; Secure; HttpOnly; Path=/"}
        self.assertEqual(edges("cookie-domain", headers), [])
        self.assertEqual(cookie_context("https://app.example.test/", headers, "dead.example.test"), [])
        record = cookie_context("https://app.example.test/", headers, "app.example.test")[0]
        self.assertTrue(record["host_only"])
        self.assertTrue(record["prefix_valid"])
        for value in ("__Host-id=x; Secure; Domain=example.test; Path=/",
                      "__Host-id=x; Path=/", "__Host-id=x; Secure; Path=/private",
                      "__Host-id=x; Secure", "__Secure-id=x; Domain=example.test"):
            self.assertEqual(cookie_context("https://app.example.test/", {"set-cookie": value},
                                            "app.example.test"), [])

    def test_prefixes_require_secure_setter_and_explicit_root_path(self):
        for value in ("__Secure-id=x; Secure; Domain=example.test",
                      "__Host-id=x; Secure; Path=/"):
            self.assertEqual(cookie_context("http://app.example.test/", {"set-cookie": value},
                                            "app.example.test"), [])
        result = cookie_context("https://app.example.test/", {
            "set-cookie": "__Secure-id=x; Secure; Domain=example.test"}, "dead.example.test")
        self.assertTrue(result[0]["prefix_valid"])

    def test_path_default_and_path_boundaries(self):
        headers = {"set-cookie": "a=x; Domain=example.test; Path=/private"}
        for path, expected in (("/private", True), ("/private/a", True), ("/privateish", False), ("/", False)):
            result = cookie_context("https://app.example.test/a/b", headers,
                                    "https://dead.example.test" + path)
            self.assertEqual(result[0]["path_matches"], expected)
        result = cookie_context("https://app.example.test/account/start", {
            "set-cookie": "a=x; Domain=example.test; Path=invalid"}, "dead.example.test")
        self.assertEqual(result[0]["path"], "/account")
        self.assertFalse(result[0]["path_explicit"])
        self.assertIsNone(result[0]["path_matches"])

    def test_secure_samesite_and_partitioning_are_observations_not_delivery(self):
        result = cookie_context("https://app.example.test/", {
            "set-cookie": "a=x; Domain=example.test; Secure; SameSite=Strict; Partitioned"},
            "http://dead.example.test/")
        self.assertFalse(result[0]["secure_transport_matches"])
        self.assertEqual(result[0]["samesite"], "strict")
        self.assertTrue(result[0]["partitioned"])


class CSPTrustTests(unittest.TestCase):
    def test_directives_hosts_ports_paths_and_default_fallback(self):
        result = extract_trust("https://app.example.test/p", {"CoNtEnT-SeCuRiTy-PoLiCy":
            "default-src https://fallback.example.test; script-src https://*.scripts.example.test:8443/assets/; "
            "connect-src wss://socket.example.test:443/live; child-src frames.example.test"})
        script = [e for e in result if e["kind"] == "csp-script"]
        self.assertEqual([e["name"] for e in script], ["*.scripts.example.test"])
        self.assertEqual(script[0]["details"]["port"], 8443)
        self.assertEqual(script[0]["details"]["path"], "/assets/")
        self.assertEqual(script[0]["details"]["scheme"], "https")
        frame = [e for e in result if e["kind"] == "csp-frame"][0]
        self.assertEqual(frame["details"]["directive"], "child-src")
        self.assertTrue(frame["details"]["fallback"])
        fallback = extract_trust("https://app.example.test/", {
            "CSP": "ignored", "Content-Security-Policy": "default-src https://fallback.example.test"})
        self.assertEqual({e["kind"] for e in fallback}, {"csp-script", "csp-connect", "csp-frame"})

    def test_none_prevents_fallback_duplicate_directive_first_wins(self):
        result = extract_trust("https://app.example.test/", {"Content-Security-Policy":
            "default-src https://fallback.example.test; script-src 'none'; script-src https://ignored.example.test; "
            "frame-src 'none'; connect-src https://connect.example.test"})
        self.assertEqual([(e["kind"], e["name"]) for e in result], [("csp-connect", "connect.example.test")])

    def test_nonce_hash_strict_dynamic_and_reportonly_are_uncertain(self):
        headers = {"Content-Security-Policy-Report-Only":
            "script-src 'nonce-NONCE_SECRET' 'sha256-HASH_SECRET' 'strict-dynamic' https://scripts.example.test; "
            "report-uri https://reports.example.test/csp?token=REPORT_SECRET"}
        result = extract_trust("https://app.example.test/", headers)
        script = [e for e in result if e["kind"] == "csp-script"][0]
        details = script["details"]
        for field in ("nonce_present", "hash_present", "strict_dynamic", "report_only"):
            self.assertTrue(details[field])
        self.assertIn("strict-dynamic-may-ignore-host-sources", details["blocking_uncertainty"])
        self.assertIn("report-only-not-enforced", details["blocking_uncertainty"])
        self.assertEqual([e["details"]["target"] for e in result if e["kind"] == "csp-report"],
                         ["https://reports.example.test/csp"])
        for secret in ("NONCE_SECRET", "HASH_SECRET", "REPORT_SECRET"):
            self.assertNotIn(secret, json.dumps(result))

    def test_multiple_policies_and_script_element_override(self):
        result = extract_trust("https://app.example.test/", {"content-security-policy": [
            "script-src https://one.example.test; script-src-elem https://elem.example.test",
            "script-src 'none'"]})
        self.assertEqual({e["name"] for e in result}, {"one.example.test", "elem.example.test"})
        self.assertTrue(all("other-enforced-policies-may-block" in e["details"]["blocking_uncertainty"]
                            for e in result))

    def test_self_is_exact_scheme_only_and_star_are_not_named_hosts(self):
        result = edges("csp-script", {"Content-Security-Policy":
            "script-src 'self' * https: data: blob: https://lookalike.example.test.evil.test "
            "https://*.example.test:*/scripts"})
        self.assertEqual({e["name"] for e in result}, {
            "app.example.test", "lookalike.example.test.evil.test", "*.example.test"})
        self.assertFalse(host_matches("lookalike.example.test", "lookalike.example.test.evil.test"))

    def test_report_to_group_names_are_not_hosts(self):
        headers = {"Content-Security-Policy": "report-to group.example.test"}
        self.assertEqual(edges("csp-report", headers), [])
        headers["Reporting-Endpoints"] = 'group.example.test="https://collector.example.test/report?code=SECRET"'
        self.assertEqual(edges("csp-report", headers)[0]["name"], "collector.example.test")
        self.assertNotIn("SECRET", json.dumps(extract_trust("https://app.example.test/", headers)))

    def test_frame_ancestors_is_explicit_and_has_no_default_fallback(self):
        result = edges("csp-frame", {"Content-Security-Policy":
            "frame-src 'none'; frame-ancestors https://embed.example.test"})
        self.assertEqual([e["name"] for e in result], ["embed.example.test"])
        self.assertEqual(result[0]["details"]["directive"], "frame-ancestors")
        self.assertFalse(result[0]["details"]["fallback"])

    def test_malformed_report_urls_are_not_fatal_and_relative_reports_are_redacted(self):
        result = edges("csp-report", {"Content-Security-Policy":
            "report-uri https://[/bad /report?token=SECRET"})
        self.assertEqual([e["details"]["target"] for e in result], ["https://app.example.test/report"])
        headers = {"Content-Security-Policy": "report-to csp", "Report-To":
                   '{"group":"csp","endpoints":[{"url":"https://reports.example.test/api?token=SECRET"}]}'}
        self.assertEqual(edges("csp-report", headers)[0]["name"], "reports.example.test")


class CORSTrustTests(unittest.TestCase):
    def test_exact_origin_and_credentials_are_headers_not_read_proof(self):
        result = edges("cors", {"ACCESS-CONTROL-ALLOW-ORIGIN": "https://trusted.example.test:8443",
                                "Access-Control-Allow-Credentials": "true"})
        self.assertEqual(result[0]["name"], "trusted.example.test")
        self.assertTrue(result[0]["details"]["credentials"])
        self.assertFalse(result[0]["details"]["read_proven"])
        self.assertFalse(result[0]["details"]["behavior_proven"])
        self.assertTrue(result[0]["conditional"])
        for value in ("True", "false", "true, true"):
            self.assertFalse(edges("cors", {"Access-Control-Allow-Origin": "https://trusted.example.test",
                                            "Access-Control-Allow-Credentials": value})[0]["details"]["credentials"])

    def test_wildcard_null_origin_lists_paths_and_userinfo_do_not_create_host_edges(self):
        for value in ("*", "null", "https://*.example.test", "https://trusted.example.test/",
                      "https://trusted.example.test/x", "https://trusted.example.test?token=SECRET",
                      "https://u:p@trusted.example.test", "https://a.test https://b.test",
                      "https://a.test, https://b.test", "https://a.test:99999", "https://a.test#", "https://a.test:"):
            with self.subTest(value=value):
                self.assertEqual(edges("cors", {"Access-Control-Allow-Origin": value}), [])
        self.assertEqual(edges("cors", {"Access-Control-Allow-Origin": ["https://a.test", "https://b.test"]}), [])


class OAuthAndContentTests(unittest.TestCase):
    def test_request_redirect_parameters_are_observed_not_accepted_allowlists(self):
        url = ("https://login.example.test/authorize?state=STATE_SECRET&nonce=NONCE_SECRET&code=CODE_SECRET&"
               "redirect_uri=https%3A%2F%2Fdead.example.test%2Fcallback%3Ftoken%3DTOKEN_SECRET%23FRAGMENT_SECRET&"
               "post_logout_redirect_uri=https%3A%2F%2Flogout.example.test%2Fdone")
        result = edges("oauth-redirect", url=url)
        self.assertEqual({e["name"] for e in result}, {"dead.example.test", "logout.example.test"})
        self.assertTrue(all(e["details"]["observed_request"] for e in result))
        self.assertTrue(all(not e["details"]["accepted_allowlist"] for e in result))
        self.assertTrue(all(e["reference"] == "https://login.example.test/authorize" for e in result))
        self.assertEqual(result[0]["details"]["source_url_sha256"], hashlib.sha256(url.encode()).hexdigest())
        self.assertNotIn("SECRET", json.dumps(result))

    def test_html_js_json_literals_and_body_url_params(self):
        body = r'''<input name="redirect_uri" value="https://html.example.test/cb?state=HTML_SECRET">
            <input value=https://unquoted.example.test/cb name=post_logout_redirect_uri>
            <script>const cfg = {redirect_uri: 'https://js.example.test/cb?nonce=JS_SECRET'};
            const data = {"post_logout_redirect_uri":"https:\/\/json.example.test\/bye?code=JSON_SECRET"};</script>
            <a href="https://login.example.test/auth?redirect_uri=https%3A%2F%2Flink.example.test%2Fcb&amp;state=LINK_SECRET">go</a>'''
        result = edges("oauth-redirect", body=body)
        self.assertEqual({e["name"] for e in result}, {
            "html.example.test", "unquoted.example.test", "js.example.test", "json.example.test", "link.example.test"})
        self.assertTrue(all(not e["details"]["observed_request"] for e in result))
        self.assertTrue(all(e["details"]["acceptance"] == "unknown" for e in result))
        self.assertNotIn("SECRET", json.dumps(extract_trust("https://app.example.test/", {}, body)))

    def test_no_provider_config_or_plural_redirect_guessing(self):
        body = '''{"redirect_uris":["https://plural.example.test/cb"],
                   "callback":"https://callback.example.test/cb", "issuer":"https://issuer.example.test"}
                   <script>redirect_uri = base + '/callback'; post_logout_redirect_uri = compute();</script>'''
        self.assertEqual(edges("oauth-redirect", body=body,
                               url="https://login.example.test/?callback=https://other.example.test/cb"), [])
        self.assertTrue(edges("content-reference", body=body))

    def test_content_urls_and_conservative_bare_hosts_not_query_values_or_filenames(self):
        body = '''<script>const host = "old.example.test"; const file = "bundle.js";
            const id = "not a domain"; const token = "SECRET.example.test";
            const state = "STATE.example.test"; const code = "CODE.example.test";
            const url = "https://user:USERINFO_SECRET@cdn.example.test/assets/a.js?token=TOKEN_SECRET#FRAGMENT_SECRET";
            const socket = "wss://socket.example.test/live?code=SOCKET_SECRET";
            const nested = "https://safe.example.test/?token=https://TOKEN_HOST_SECRET.example.test/";
            </script><img src="https://image.example.test/a.png">'''
        result = edges("content-reference", body=body)
        self.assertEqual({e["name"] for e in result}, {"old.example.test", "cdn.example.test",
            "socket.example.test", "safe.example.test", "image.example.test"})
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("STATE.example.test", json.dumps(result))
        self.assertNotIn("CODE.example.test", json.dumps(result))
        self.assertTrue(all("?" not in e["details"]["target"] and "#" not in e["details"]["target"]
                            and "@" not in e["details"]["target"] for e in result))

    def test_content_escaped_urls_and_deduplication(self):
        body = r'''{"url":"https:\/\/old.example.test\/one?token=SECRET", "other":"https:\/\/old.example.test\/one?token=OTHER"}'''
        result = edges("content-reference", body=body)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["details"]["target"], "https://old.example.test/one")

    def test_escaped_quotes_and_sensitive_input_values_are_not_url_references(self):
        body = r'''{"token":"prefix \"https://TOKEN_SECRET.example.test\" suffix",
                    "state":["STATE_SECRET.example.test"], "url":"https:\/\/public.example.test\/"}
                   <input name=nonce value="https://NONCE_SECRET.example.test/">
                   <input name=code value="CODE_SECRET.example.test">
                   <script>const state = "prefix 'https://STATE_SECRET.example.test' suffix";</script>'''
        result = edges("content-reference", body=body)
        self.assertEqual({e["name"] for e in result}, {"public.example.test"})
        self.assertNotIn("SECRET", json.dumps(result))

    def test_ipv6_and_unicode_escaped_urls_are_inert_references(self):
        body = r'''{"ip":"https://[::1]", "url":"https:\u002f\u002fold.example.test/a"}'''
        self.assertEqual({e["name"] for e in edges("content-reference", body=body)}, {"::1", "old.example.test"})

    def test_sensitive_json_subtrees_and_arrays_do_not_export_secret_literals(self):
        body = json.dumps({
            "codes": ["https://FIRST_SECRET.example.test", "SECOND_SECRET.example.test"],
            "state": ["unused", {"nested": "https://STATE_SECRET.example.test"}],
            "token": {"redirect_uri": "https://TOKEN_SECRET.example.test"},
            "public": {"redirect_uri": "https://public.example.test/cb?nonce=SECRET"}})
        result = extract_trust("https://app.example.test/", {}, body)
        self.assertEqual({e["name"] for e in result}, {"public.example.test"})
        self.assertNotIn("SECRET", json.dumps(result))


class HSTSAndSafetyTests(unittest.TestCase):
    def test_hsts_names_only_setter_no_sibling_or_preload_membership_claim(self):
        result = edges("hsts", {"sTrIcT-tRaNsPoRt-SeCuRiTy":
            "max-age=31536000; includeSubDomains; preload"})
        self.assertEqual(result[0]["name"], "app.example.test")
        details = result[0]["details"]
        self.assertEqual(details["max_age"], 31536000)
        self.assertTrue(details["include_subdomains"])
        self.assertTrue(details["preload"])
        self.assertEqual(details["preload_list_membership"], "unknown")
        self.assertFalse(details["sibling_takeover_implied"])
        insecure = edges("hsts", {"Strict-Transport-Security": "max-age=0"}, url="http://app.example.test/")
        self.assertFalse(insecure[0]["details"]["secure_setter"])
        self.assertEqual(insecure[0]["details"]["max_age"], 0)
        for header in ("includeSubDomains", "max-age=-1", "max-age=x", "max-age=1; max-age=2"):
            self.assertEqual(edges("hsts", {"Strict-Transport-Security": header}), [])

    def test_complete_false_retains_observations_without_negative_evidence(self):
        headers = {"Set-Cookie": "a=secret; Domain=example.test",
                   "Content-Security-Policy": "script-src https://scripts.example.test",
                   "Access-Control-Allow-Origin": "https://cors.example.test"}
        result = extract_trust("https://app.example.test/", headers, '"old.example.test"', complete=False)
        self.assertTrue(result)
        self.assertTrue(all(e["conditional"] and e["details"]["incomplete"] for e in result))
        self.assertEqual(extract_trust("https://app.example.test/", {}, complete=False), [])
        self.assertTrue(all(not e["details"]["incomplete"] for e in
                            extract_trust("https://app.example.test/", headers)))

    def test_caps_retain_edges_and_mark_incomplete(self):
        with patch("recon.takeover_trust.MAX_BODY", 100):
            result = extract_trust("https://app.example.test/", {},
                                   '"https://old.example.test/a" ' + "x" * 200)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["details"]["incomplete"])
        with patch("recon.takeover_trust.MAX_REFERENCES", 1):
            result = extract_trust("https://app.example.test/", {},
                                   '"https://one.example.test" "https://two.example.test"')
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["details"]["incomplete"])

    def test_query_field_limit_is_incomplete_not_a_negative(self):
        url = "https://app.example.test/?" + "&".join(f"p{i}=value" for i in range(257))
        result = extract_trust(url, {}, '"https://old.example.test"')
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["details"]["incomplete"])

    def test_capped_headers_and_literals_retain_safe_edges_not_untracked_secrets(self):
        with patch("recon.takeover_trust.MAX_HEADER_VALUE", 40):
            result = extract_trust("https://app.example.test/", {},
                                   '"https://old.example.test"')
            self.assertFalse(result[0]["details"]["incomplete"])
            result = extract_trust("https://app.example.test/", {"Set-Cookie": "a=" + "x" * 100},
                                   '"https://old.example.test"')
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["details"]["incomplete"])
        with patch("recon.takeover_trust.MAX_LITERALS", 1):
            result = extract_trust("https://app.example.test/", {},
                                   '"https://old.example.test"; const token="https://SECRET.example.test"')
        self.assertEqual({e["name"] for e in result}, {"old.example.test"})
        self.assertNotIn("SECRET", json.dumps(result))

    def test_exact_source_path_hash_and_redaction_across_every_edge(self):
        url = "https://user:SOURCE_SECRET@app.example.test/exact/path?state=STATE_SECRET#FRAGMENT_SECRET"
        result = extract_trust(url, {"Set-Cookie": "a=COOKIE_SECRET; Domain=example.test",
            "Strict-Transport-Security": "max-age=123; preload", "Access-Control-Allow-Origin": "https://cors.example.test"},
            '"https://body.example.test/a?token=BODY_SECRET"')
        self.assertEqual(len(result), 4)
        self.assertTrue(all(e["reference"] == "https://app.example.test/exact/path" for e in result))
        self.assertNotIn("SECRET", json.dumps(result))

    def test_parser_never_uses_network_and_bad_input_fails_closed(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("network forbidden")):
            result = extract_trust("https://app.example.test/", {}, '"https://dead.example.test"')
        self.assertTrue(result)
        for url in ("garbage", "javascript:alert(1)", "https://[invalid/", "https://app.example.test:99999/"):
            self.assertEqual(extract_trust(url, {}, ""), [])
        self.assertEqual(extract_trust("https://app.example.test/", None, None), [])


if __name__ == "__main__":
    unittest.main()
