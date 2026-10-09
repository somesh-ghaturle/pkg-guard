import json
import subprocess
import sys
import unittest
from unittest import mock

import pkg_guard as pg

pg.CACHE_FILE = None  # tests never touch the real ~/.cache; CacheTest opts back in

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
            "go get -u github.com/gin-gonic/gin@v1.9.0 golang.org/x/net/...": [
                ("go", "github.com/gin-gonic/gin"), ("go", "golang.org/x/net")],
            "go install -tags x github.com/evil/tool@latest": [("go", "github.com/evil/tool")],
            "go run github.com/evil/tool@v1 --flag arg.com": [("go", "github.com/evil/tool")],
            "go mod download rsc.io/quote": [("go", "rsc.io/quote")],
            # module paths ending in .go are modules, not local files
            "go get github.com/evil/x.go": [("go", "github.com/evil/x.go")],
            "go run github.com/evil/main.go@v1": [("go", "github.com/evil/main.go")],
            # go mod edit adds requirements without go get
            "go mod edit -require=github.com/evil/a@v1 -replace github.com/x/y=github.com/evil/b@v1"
            " -replace=github.com/x/z=../local": [("go", "github.com/evil/a"), ("go", "github.com/evil/b")],
            # ANSI-C quoting
            "bash -c $'npm i evil'": [("npm", "evil")],
            "bash -c $'\\x6epm i evil'": [("npm", "evil")],
            # bash escape grammar, incl. forms Python's unicode_escape rejects
            "bash -c $'\\x6\\x65pm i evil \\u20ac'": [],  # \x6 is one hex digit -> "\x06epm"
            "bash -c $'\\156pm i \\u0065vil'": [("npm", "evil")],
            "bash -c $'n\\x70m i evil \u20ac'": [("npm", "evil"), ("npm", "\u20ac")],
            "bash -c $'npm i evil\\?'": [("npm", "evil?")],
            "echo '$'&&npm i evil": [("npm", "evil")],
            "echo \"$'\"&&npm i evil": [("npm", "evil")],
            "bash -c 'cd app\nnpm i evil'": [("npm", "evil")],
            "np\\\nm i evil": [("npm", "evil")],
            "echo 'a\nb' && npm i evil": [("npm", "evil")],
        }
        for cmd, want in cases.items():
            self.assertEqual(pg.parse(cmd), want, cmd)

    def test_bypasses_are_caught(self):
        evil = [("npm", "evil")]
        cases = {
            # parser differential: quotes, newlines, subshells, redirects
            'echo "a;b" && npm i evil': evil,
            "ls\nnpm i evil": evil,
            "echo $(npm i evil)": evil,
            "echo `npm i evil`": evil,
            "npm i evil 2>&1 >/dev/null": evil,
            "(cd x; npm i evil)": evil,
            # command matching: wrappers, shells, eval, npm verb aliases
            "sudo -u root npm i evil": evil,
            "env A=1 time nohup npm i evil": evil,
            "bash -c 'npm i evil'": evil,
            "bash -lc \"cd app && npm i evil\"": evil,
            "eval npm i evil": evil,
            "npm isntall evil": evil,
            "yarn global add evil": evil,
            "npm exec evil": evil,
            "/usr/local/bin/npm i evil": evil,
            "python3 -mpip install evil": [("pypi", "evil")],
            # flag handling: package-valued flags, aliases, --flag=value
            "npx -p evil some-cmd": evil,
            "npx --package=evil some-cmd": evil,
            "npm i lodash@npm:evil": evil,
            "uvx --with evil ruff": [("pypi", "evil"), ("pypi", "ruff")],
            "uvx --from evil cmd": [("pypi", "evil")],
            "pip install --index-url=https://x evil": [("pypi", "evil")],
        }
        for cmd, want in cases.items():
            self.assertEqual(pg.parse(cmd), want, cmd)

    def test_requirements_file_is_read(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "req.txt"), "w") as f:
                f.write("# deps\nevil==1.0\n-e .\nrequests>=2  # http\n")
            self.assertEqual(pg.parse("pip install -r req.txt", cwd=d),
                             [("pypi", "evil"), ("pypi", "requests")])
            self.assertEqual(pg.parse("pip install --requirement=req.txt", cwd=d)[0], ("pypi", "evil"))

    def test_nested_requirements(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "reqs"))
            with open(os.path.join(d, "reqs", "base.txt"), "w") as f:
                f.write("evil\n-r ../requirements.txt\n")  # cycle back to the top file
            with open(os.path.join(d, "requirements.txt"), "w") as f:
                f.write("-r reqs/base.txt\n--requirement=reqs/base.txt\nrequests\n")
            self.assertEqual(pg.parse("pip install -r requirements.txt", cwd=d),
                             [("pypi", "evil"), ("pypi", "requests")])

    def test_codex_argv_command(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": ["bash", "-lc", "npm i evil"]}}
        with mock.patch.object(pg, "registry_info", return_value=None):
            self.assertIsNotNone(pg.hook_output(payload))

    def test_ignored(self):
        for cmd in ["npm install", "npm run test", "pip install -e .", "pip install ./dist/x.whl",
                    "npm i github:user/repo", "npm i user/repo", "pip install git+https://x/y.git",
                    "ls -la", "echo 'pip install foo'x", "cargo build",
                    "go get ./...", "go install .", "go run main.go", "go get github.com/x/y@none",
                    "go build ./cmd/app", "go test ./..."]:
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

    def test_go(self):
        with mock.patch.object(pg, "registry_info", side_effect=AssertionError):
            self.assertIsNone(pg.check("go", "golang.org/x/net/http2"))  # inside a popular module
            with mock.patch.dict("os.environ", {"GOPRIVATE": "github.com/myorg/*,*.corp.example"}):
                self.assertIsNone(pg.check("go", "github.com/myorg/svc/pkg"))
                self.assertIsNone(pg.check("go", "git.corp.example/team/x"))
        r = self.run_check("go", "github.com/gin-gonlc/gin", {"age_days": 20, "downloads": None})
        self.assertIn("days ago", r)
        r = self.run_check("go", "github.com/gin-gonlc/gin", {"age_days": 100, "downloads": None})
        self.assertIn("typosquat of popular package 'github.com/gin-gonic/gin'", r)

    def test_go_proxy_walks_up_to_module_root(self):
        responses = {
            "https://proxy.golang.org/github.com/!burnt!sushi/toml/sub/@latest": None,
            "https://proxy.golang.org/github.com/!burnt!sushi/toml/@latest": '{"Time": "2024-01-01T00:00:00Z"}',
            "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/list": "v1.10.0\nv0.2.0\nv1.2.0\n",
            "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v0.2.0.info": '{"Time": "2013-01-01T00:00:00Z"}',
            "https://api.deps.dev/v3/projects/github.com%2Fburntsushi%2Ftoml": '{"starsCount": 4700}',
        }
        with mock.patch.object(pg, "fetch", side_effect=lambda u: responses[u]):
            info = pg.registry_info("go", "github.com/BurntSushi/toml/sub")
        self.assertGreater(info["age_days"], 3000)
        self.assertEqual(info["downloads"], 4700)
        # backdated commits make a fresh repo look old; zero stars still blocks it
        responses["https://api.deps.dev/v3/projects/github.com%2Fburntsushi%2Ftoml"] = None
        with mock.patch.object(pg, "fetch", side_effect=lambda u: responses[u]):
            self.assertEqual(pg.registry_info("go", "github.com/BurntSushi/toml")["downloads"], 0)
        self.assertIn("0 repo stars", self.run_check("go", "github.com/x/y", {"age_days": 4000, "downloads": 0}))
        with mock.patch.object(pg, "fetch", return_value=None):
            self.assertIsNone(pg.registry_info("go", "github.com/nope/nope/a/b"))

    def test_allowlist(self):
        with mock.patch.dict("os.environ", {"PKG_GUARD_ALLOW": "internal-thing"}):
            self.assertIsNone(self.run_check("npm", "internal-thing", None))

    def test_network_error_fails_open_unless_configured(self):
        with mock.patch.object(pg, "registry_info", side_effect=OSError("offline")):
            self.assertIsNone(pg.check("npm", "whatever-lib"))
            with mock.patch.dict("os.environ", {"PKG_GUARD_FAIL_CLOSED": "1"}):
                self.assertIn("registry check failed", pg.check("npm", "whatever-lib"))


class ManifestTest(unittest.TestCase):
    def test_manifest_deps(self):
        pkg = ('{"dependencies": {"lodash": "^4", "@types/node": "20", "alias": "npm:evil@1",'
               ' "local": "file:../x", "gh": "user/repo", "ws": "workspace:*"}}')
        self.assertEqual(pg.manifest_deps("a/package.json", pkg), ("npm", {"lodash", "@types/node", "evil"}))
        self.assertEqual(pg.manifest_deps("requirements-dev.txt", "Evil_Pkg>=1  # x\n-e .\n"),
                         ("pypi", {"evil-pkg"}))
        gem = 'gem "rails", "~> 7"\ngem \'evil\'\ngem "mine", path: "../mine"\n'
        self.assertEqual(pg.manifest_deps("Gemfile", gem), ("gems", {"rails", "evil"}))
        self.assertIsNone(pg.manifest_deps("README.md", "evil"))
        gomod = ("module example.com/me\n\ngo 1.22\n\nrequire github.com/a/one v1.0.0\n"
                 "require (\n\tgithub.com/a/two v1.2.0 // indirect\n\t\"github.com/a/three\" v0.1.0\n)\n"
                 "replace github.com/a/one => github.com/evil/one v1.0.0\n"
                 "replace (\n\tgithub.com/a/two => ../local-two\n)\n")
        self.assertEqual(pg.manifest_deps("go.mod", gomod), ("go", {
            "github.com/a/one", "github.com/a/two", "github.com/a/three", "github.com/evil/one"}))

    def test_manifest_bypasses_are_caught(self):
        evil = {"evil"}
        cases = {
            # case-insensitive filesystems: Package.json overwrites package.json
            "app/Package.json": '{"dependencies": {"evil": "1"}}',
            "GEMFILE": 'gem("evil")',
            # overrides swap a transitive dep for another package
            "package.json": '{"overrides": {"lodash": "npm:evil@1"}, "pnpm": {"overrides": {"a": {"b": "npm:evil"}}}}',
            "requirements.txt": "ev\\\nil\nfoo\t# comment\n",
            "Gemfile": "source 'x'; gem 'evil'",
        }
        for path, text in cases.items():
            got = pg.manifest_deps(path, text)[1] - {"foo"}
            self.assertEqual(got, evil, path)

    @unittest.skipIf(pg.tomllib is None, "TOML manifests need Python 3.11+")
    def test_toml_bypasses_are_caught(self):
        self.assertEqual(pg.manifest_deps("pyproject.toml", '[build-system]\nrequires = ["evil"]\n')[1], {"evil"})
        self.assertEqual(pg.manifest_deps("pyproject.toml", '[tool.uv]\ndev-dependencies = ["evil"]\n')[1], {"evil"})
        self.assertEqual(pg.manifest_deps("cargo.toml", '[workspace.dependencies]\nfoo = { package = "evil" }\n')[1],
                         {"evil"})

    @unittest.skipIf(pg.tomllib is None, "TOML manifests need Python 3.11+")
    def test_toml_manifests(self):
        py = ('[project]\ndependencies = ["requests>=2", "evil"]\n'
              '[project.optional-dependencies]\nx = ["extra-evil"]\n'
              '[tool.poetry.dependencies]\npython = "^3.11"\nPoetry_Evil = "1"\nmine = {path = "."}\n')
        self.assertEqual(pg.manifest_deps("pyproject.toml", py),
                         ("pypi", {"requests", "evil", "extra-evil", "poetry-evil"}))
        cargo = ('[dependencies]\nserde = "1"\nrenamed = { package = "evil", version = "1" }\n'
                 'mine = { path = "../mine" }\n[target.\'cfg(unix)\'.dev-dependencies]\nunix-evil = "1"\n')
        self.assertEqual(pg.manifest_deps("Cargo.toml", cargo), ("crates", {"serde", "evil", "unix-evil"}))

    def test_edit_checks_only_added_deps(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "package.json")
            with open(path, "w") as f:
                f.write('{"dependencies": {"already-there": "1"}}')
            calls = []
            def fake_info(eco, name):
                calls.append(name)
                return None
            edit = {"file_path": path, "old_string": '"already-there": "1"',
                    "new_string": '"already-there": "1", "evil": "1"'}
            with mock.patch.object(pg, "registry_info", side_effect=fake_info):
                out = pg.hook_output({"tool_name": "Edit", "tool_input": edit})
                self.assertIn("blocked this dependency edit", out["hookSpecificOutput"]["permissionDecisionReason"])
                self.assertEqual(calls, ["evil"])
                # fail closed: edits we can't apply or results that don't parse
                for bad in [dict(edit, old_string="nope"), dict(edit, new_string='"evil": ')]:
                    self.assertIsNotNone(pg.hook_output({"tool_name": "Edit", "tool_input": bad}))
                # a symlink with an innocent name pointing at a manifest
                os.symlink(path, os.path.join(d, "notes.txt"))
                self.assertIsNotNone(pg.hook_output({"tool_name": "Write", "tool_input": {
                    "file_path": os.path.join(d, "notes.txt"), "content": '{"dependencies": {"evil": "1"}}'}}))
                # a manifest-named symlink to an innocent-named file
                os.rename(path, os.path.join(d, "deps.json"))
                os.symlink(os.path.join(d, "deps.json"), path)
                self.assertIsNotNone(pg.hook_output({"tool_name": "Edit", "tool_input": edit}))
                # a BOM is fine for npm, so it must not hide deps from us
                self.assertIsNotNone(pg.hook_output({"tool_name": "Write", "tool_input": {
                    "file_path": path, "content": '﻿{"dependencies": {"evil": "1"}}'}}))
                # non-manifests and unchanged deps are allowed
                self.assertIsNone(pg.hook_output({"tool_name": "Write", "tool_input":
                                                  {"file_path": os.path.join(d, "x.js"), "content": "evil"}}))
                multi = {"file_path": path, "edits": [{"old_string": "1", "new_string": "2"}]}
                self.assertIsNone(pg.hook_output({"tool_name": "MultiEdit", "tool_input": multi}))
                write = {"file_path": os.path.join(d, "new", "requirements.txt"), "content": "evil\n"}
                self.assertIsNotNone(pg.hook_output({"tool_name": "Write", "tool_input": write}))


class CacheTest(unittest.TestCase):
    def test_caches_only_passes(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(pg, "CACHE_FILE", os.path.join(d, "sub", "ok.json")):
            with mock.patch.object(pg, "registry_info", return_value=OLD_POPULARISH) as reg:
                self.assertIsNone(pg.check("npm", "fine-lib"))
                self.assertIsNone(pg.check("npm", "fine-lib"))
                self.assertEqual(reg.call_count, 1)  # second call served from cache
            with mock.patch.object(pg, "registry_info", return_value=None) as reg:
                pg.check("npm", "missing-lib")
                pg.check("npm", "missing-lib")
                self.assertEqual(reg.call_count, 2)  # blocks are never cached
            with mock.patch.object(pg, "registry_info", side_effect=OSError("offline")):
                pg.check("npm", "offline-lib")
            self.assertEqual(set(pg._cache_load()), {"npm:fine-lib"})  # nor network failures
            with mock.patch.object(pg.time, "time", return_value=pg.time.time() + pg.CACHE_TTL + 1):
                self.assertFalse(pg._cached_ok("npm:fine-lib"))  # expired
            with open(pg.CACHE_FILE, "w") as f:
                f.write("not json")
            self.assertFalse(pg._cached_ok("npm:fine-lib"))  # corrupt file is ignored
            pg._remember_ok("npm:fine-lib")
            self.assertEqual(os.stat(pg.CACHE_FILE).st_mode & 0o777, 0o600)
            os.chmod(pg.CACHE_FILE, 0o666)
            self.assertFalse(pg._cached_ok("npm:fine-lib"))  # writable by others: ignored
            # the agent may not write the cache to whitelist a package
            for payload in [{"tool_name": "Write", "tool_input": {"file_path": pg.CACHE_FILE, "content": "{}"}},
                            {"tool_name": "Bash", "tool_input": {"command": "echo {} > " + pg.CACHE_FILE}}]:
                self.assertIn("cache", pg.hook_output(payload)["hookSpecificOutput"]["permissionDecisionReason"])


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

    def test_cli_hook_crash_denies(self):
        payload = {"tool_name": "Write", "tool_input": {"file_path": 123}}  # join() raises TypeError
        p = subprocess.run([sys.executable, "pkg_guard.py", "hook"], input=json.dumps(payload),
                           capture_output=True, text=True)
        self.assertIn('"deny"', p.stdout)

    @unittest.skipIf(pg.tomllib is None, "TOML manifests need Python 3.11+")
    def test_unexpected_toml_shape_denies(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            w = {"file_path": os.path.join(d, "pyproject.toml"), "content": 'project = "x"\n'}
            self.assertIn("does not parse", pg.check_edit("Write", w)[0])

    def test_cli_hook_allows_non_install(self):
        p = subprocess.run([sys.executable, "pkg_guard.py", "hook"],
                           input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}}),
                           capture_output=True, text=True)
        self.assertEqual((p.returncode, p.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()
