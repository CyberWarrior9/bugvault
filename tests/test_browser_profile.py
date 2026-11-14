"""Dedicated browser launch policy; unit tests never open a browser or a target."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.browser import launch


class BrowserProfileTests(unittest.TestCase):
    def test_profile_is_private_persistent_and_not_personal(self):
        plan = launch.launch_plan()
        self.assertEqual(Path(plan["profile"]), launch.REPO / ".recon/browser/profile")
        self.assertIn("--user-data-dir=" + plan["profile"], plan["command"])
        self.assertEqual(plan["command"][-1], "about:blank")
        self.assertFalse(plan["browser_control_connected"])

    def test_no_headless_debug_tls_or_sandbox_bypasses(self):
        args = " ".join(launch.launch_plan()["command"])
        for forbidden in ("--headless", "--ignore-certificate-errors", "--no-sandbox",
                          "--remote-debugging", "--disable-web-security", "Downloads"):
            self.assertNotIn(forbidden, args)

    def test_proxy_covers_loopback_web_requests_and_disables_quic(self):
        args = launch.launch_plan()["command"]
        self.assertIn("--proxy-server=http://127.0.0.1:8080", args)
        self.assertIn("--proxy-bypass-list=<-loopback>", args)
        self.assertIn("--disable-quic", args)
        self.assertNotIn("direct://", " ".join(args))

    def test_proxy_must_be_explicit_loopback_without_credentials(self):
        for url in ("http://example.com:8080", "http://127.0.0.1", "socks5://127.0.0.1:8080",
                    "http://u:p@127.0.0.1:8080", "http://127.0.0.1:8080/path",
                    "http://127.0.0.1:8080?q=x", "http://127.0.0.1:9876"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                launch.proxy_address(url)
        self.assertEqual(launch.proxy_address("http://[::1]:8080"), ("::1", 8080))

    def test_prepare_is_repeatable_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = launch.launch_plan(repo=root)
            state = launch.prepare_profile(plan, repo=root)
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            self.assertEqual(Path(plan["profile"]).stat().st_mode & 0o777, 0o700)
            self.assertEqual((state / "launch-plan.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(launch.prepare_profile(plan, repo=root), state)
            self.assertEqual(json.loads((state / "owner.json").read_text())["label"], launch.LABEL)

    def test_existing_unowned_profile_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / ".recon/browser/profile"
            profile.mkdir(parents=True)
            (profile / "existing-user-data").write_text("do not touch")
            with self.assertRaises(ValueError):
                launch.prepare_profile(launch.launch_plan(repo=root), repo=root)
            self.assertEqual((profile / "existing-user-data").read_text(), "do not touch")

    def test_symlinked_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            other = Path(directory) / "personal"
            other.mkdir()
            (root / ".recon").symlink_to(other, target_is_directory=True)
            with self.assertRaises(ValueError):
                launch.prepare_profile(launch.launch_plan(repo=root), repo=root)
            self.assertEqual(list(other.iterdir()), [])

    def test_missing_proxy_fails_before_any_browser_launch(self):
        with patch.object(launch.CHROME.__class__, "is_file", return_value=True), \
                patch.object(launch.socket, "create_connection", side_effect=OSError("unavailable")), \
                patch.object(launch.subprocess, "Popen") as popen, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(launch.main([]), 1)
            popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
