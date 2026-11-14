"""Shared model-independent MCP configuration; no Burp or external network required."""
import fnmatch
import hashlib
import json
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[1]


class BurpConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((REPO / "opencode.json").read_text(encoding="utf-8"))

    def effect(self, action):
        matched = [rule["effect"] for rule in self.config["permissions"]
                   if fnmatch.fnmatchcase(action, rule["action"]) and rule["resource"] == "*"]
        return matched[-1] if matched else None

    def test_same_loopback_endpoint_for_opencode_and_claude_code(self):
        server = self.config["mcp"]["servers"]["burp"]
        native = json.loads((REPO / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["burp"]
        self.assertEqual(server["url"], "http://127.0.0.1:9876/mcp")
        self.assertEqual(native["url"], server["url"])
        self.assertEqual((server["type"], native["type"]), ("remote", "http"))

    def test_project_registration_does_not_select_or_filter_models(self):
        self.assertNotIn("model", self.config)
        self.assertNotIn("providers", self.config)
        self.assertNotIn("agents", self.config)
        self.assertFalse(self.config["mcp"]["servers"]["burp"]["codemode"])
        self.assertNotIn("disabled", self.config["mcp"]["servers"]["burp"])

    def test_bounded_evidence_and_codec_tools_are_available_without_model_rules(self):
        for name in ("get_proxy_http_history", "get_proxy_http_history_regex",
                     "get_proxy_websocket_history", "get_proxy_websocket_history_regex",
                     "get_organizer_items", "get_organizer_items_regex", "get_scanner_issues",
                     "get_active_editor_contents", "url_encode", "url_decode",
                     "base64_encode", "base64_decode", "generate_random_string"):
            with self.subTest(tool=name):
                self.assertEqual(self.effect("burp_" + name), "allow")

    def test_active_sensitive_and_unknown_tools_still_require_approval(self):
        for name in ("send_http1_request", "send_http2_request", "create_repeater_tab",
                     "create_repeater_tab_http2", "send_to_intruder", "set_project_options",
                     "set_user_options", "output_project_options", "output_user_options",
                     "set_task_execution_engine_state", "set_proxy_intercept_state",
                     "set_active_editor_contents", "generate_collaborator_payload",
                     "get_collaborator_interactions", "a_future_tool"):
            with self.subTest(tool=name):
                self.assertEqual(self.effect("burp_" + name), "ask")

    def test_shared_instructions_and_no_downloads_runtime_dependency(self):
        self.assertEqual((REPO / "CLAUDE.md").read_text().strip(), "@AGENTS.md")
        instructions = (REPO / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("every tool-capable", instructions)
        self.assertIn("do not", instructions.lower())
        script = (REPO / "tools/burp/stdio-proxy.sh").read_text(encoding="utf-8")
        self.assertNotIn("Downloads", script)
        self.assertIn("--sse-url http://127.0.0.1:9876", script)
        self.assertIn("tools/burp/mcp-proxy.jar", (REPO / ".gitignore").read_text())
        jar = REPO / "tools/burp/mcp-proxy.jar"
        if jar.exists():
            self.assertIn(hashlib.sha256(jar.read_bytes()).hexdigest(), script)


if __name__ == "__main__":
    unittest.main()
