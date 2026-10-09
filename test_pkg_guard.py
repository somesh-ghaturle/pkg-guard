import json
import subprocess
import sys
import unittest
from unittest import mock

import pkg_guard as pg

OLD_POPULARISH = {"age_days": 2000, "downloads": 50000}


class ParseTest(unittest.TestCase):
    def test_commands(self):
        cases = {
            "npm install lodash@4 @types/node@20 --save-dev": [("npm", "lodash"), ("npm", "@types/node")],
            "pnpm add -w app zod": [("npm", "zod")],
            "yarn add react-dom && npm run build": [("npm", "react-dom")],
            "npx -y create-vite my-app": [("npm", "create-vite")],
            "pip install 'requests[socks]>=2' Flask_Login==0.6": [("pypi", "requests"), ("pypi", "flask-login")],
            "python3 -m pip install -r req.txt httpx": [("pypi", "httpx")],
            "uv add pydantic; uv pip install rich": [("pypi", "pydantic"), ("pypi", "rich")],
            "sudo FOO=1 pip3 install numpy": [("pypi", "numpy")],
            "uvx ruff check .": [("pypi", "ruff")],
            "cargo add serde --features derive tokio@1": [("crates", "serde"), ("crates", "tokio")],
            "gem install rails -v 7.1": [("gems", "rails")],
        }
        for cmd, want in cases.items():
            self.assertEqual(pg.parse(cmd), want, cmd)

    def test_ignored(self):
        for cmd in ["npm install", "npm run test", "pip install -e .", "pip install ./dist/x.whl",
                    "npm i github:user/repo", "npm i user/repo", "pip install git+https://x/y.git",
                    "ls -la", "echo 'pip install foo'x", "cargo build"]:
            self.assertEqual(pg.parse(cmd), [], cmd)


class CheckTest(unittest.TestCase):
    def run_check(self, eco, name, info):
        with mock.patch.object(pg, "registry_info", return_value=info):
            return pg.check(eco, name)

    def test_popular_skips_network(self):
        with mock.patch.object(pg, "registry_info", side_effect=AssertionError):
            self.assertIsNone(pg.check("pypi", "requests"))

    def test_missing_with_hint(self):
        r = self.run_check("pypi", "reqeusts", None)
        self.assertIn("does not exist", r)
        self.assertIn("'requests'", r)

    def test_too_new(self):
        self.assertIn("days ago", self.run_check("npm", "shiny-new-lib", {"age_days": 3, "downloads": 9999}))

    def test_too_few_downloads(self):
        self.assertIn("downloads", self.run_check("npm", "obscure-lib", {"age_days": 900, "downloads": 12}))

    def test_typosquat(self):
        r = self.run_check("npm", "lodahs", {"age_days": 100, "downloads": 5000})
        self.assertIn("typosquat of popular package 'lodash'", r)

    def test_established_lookalike_ok(self):
        self.assertIsNone(self.run_check("npm", "lodahs", OLD_POPULARISH))

    def test_normal_ok(self):
        self.assertIsNone(self.run_check("pypi", "tomli", {"age_days": 1500, "downloads": None}))

    def test_allowlist(self):
        with mock.patch.dict("os.environ", {"PKG_GUARD_ALLOW": "internal-thing"}):
            self.assertIsNone(self.run_check("npm", "internal-thing", None))

    def test_network_error_fails_open_unless_configured(self):
        with mock.patch.object(pg, "registry_info", side_effect=OSError("offline")):
            self.assertIsNone(pg.check("npm", "whatever-lib"))
            with mock.patch.dict("os.environ", {"PKG_GUARD_FAIL_CLOSED": "1"}):
                self.assertIn("registry check failed", pg.check("npm", "whatever-lib"))


class HookTest(unittest.TestCase):
    def test_deny_json(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "pip install reqeusts"}}
        with mock.patch.object(pg, "registry_info", return_value=None):
            out = pg.hook_output(payload)["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("reqeusts", out["permissionDecisionReason"])

    def test_allow_paths(self):
        self.assertIsNone(pg.hook_output({"tool_name": "Edit", "tool_input": {}}))
        self.assertIsNone(pg.hook_output({"tool_name": "Bash", "tool_input": {"command": "ls"}}))

    def test_cli_hook_bad_stdin_is_silent(self):
        p = subprocess.run([sys.executable, "pkg_guard.py", "hook"], input="not json",
                           capture_output=True, text=True)
        self.assertEqual((p.returncode, p.stdout), (0, ""))

    def test_cli_hook_allows_non_install(self):
        p = subprocess.run([sys.executable, "pkg_guard.py", "hook"],
                           input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}}),
                           capture_output=True, text=True)
        self.assertEqual((p.returncode, p.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()
