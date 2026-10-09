#!/usr/bin/env python3
"""pkg-guard: block hallucinated / typosquatted package installs by AI coding agents.

Usage:
  pkg_guard.py check "<shell command>"   exit 1 and print reasons if blocked
  pkg_guard.py hook                      PreToolUse hook (Claude Code, Codex): JSON on stdin
"""
import json
import os
import re
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

__version__ = "0.1.0"
UA = "pkg-guard/%s (https://github.com/somesh-ghaturle/pkg-guard)" % __version__
TIMEOUT = 4

# ponytail: hand-picked top names, swap for a generated top-N list if typo recall matters
POPULAR = {
    "npm": """react react-dom vue angular svelte next nuxt express koa fastify lodash underscore
        axios request node-fetch chalk commander yargs debug moment dayjs date-fns uuid dotenv
        typescript eslint prettier jest mocha chai vitest webpack vite rollup esbuild babel-core
        @babel/core tailwindcss postcss autoprefixer sass less jquery bootstrap redux react-redux
        zustand mobx rxjs socket.io ws mongoose sequelize prisma pg mysql mysql2 redis ioredis
        jsonwebtoken bcrypt bcryptjs passport cors body-parser cookie-parser multer nodemon
        concurrently cross-env rimraf glob minimist semver async bluebird classnames
        styled-components immer zod yup joi formik react-router react-router-dom graphql
        apollo-server @apollo/client puppeteer playwright cheerio inquirer ora boxen
        fs-extra chokidar execa got superagent node-sass electron three d3 chart.js
        openai @anthropic-ai/sdk langchain""",
    "pypi": """requests urllib3 numpy pandas scipy matplotlib seaborn scikit-learn tensorflow
        torch torchvision keras flask django fastapi uvicorn gunicorn starlette pydantic
        sqlalchemy alembic psycopg2 psycopg2-binary pymysql redis celery boto3 botocore
        awscli pyyaml jinja2 click typer rich colorama tqdm pillow opencv-python beautifulsoup4
        lxml selenium scrapy httpx aiohttp pytest pytest-cov mock tox black flake8 pylint mypy
        isort ruff setuptools wheel pip virtualenv poetry python-dateutil pytz six attrs
        cryptography pyjwt paramiko openai anthropic langchain transformers datasets
        huggingface-hub tokenizers jupyter notebook ipython networkx sympy statsmodels
        xgboost lightgbm plotly dash streamlit gradio python-dotenv docker kubernetes
        google-cloud-storage protobuf grpcio simplejson ujson orjson marshmallow""",
    "crates": """serde serde_json serde_derive tokio rand clap regex log env_logger anyhow
        thiserror reqwest hyper axum actix-web futures chrono time lazy_static once_cell
        itertools rayon crossbeam bytes uuid tracing tracing-subscriber syn quote
        proc-macro2 libc bitflags byteorder base64 sha2 hex url toml diesel sqlx
        tonic prost tower warp rocket""",
    "gems": """rails rake rack bundler rspec rspec-core puma nokogiri devise sidekiq
        activesupport activerecord actionpack json pg mysql2 redis sinatra thor
        rubocop pry faraday httparty jwt bcrypt capybara factory_bot sprockets
        webpacker jbuilder bootsnap minitest""",
}
POPULAR = {k: set(v.split()) for k, v in POPULAR.items()}

def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


# flags whose next token is not a package, per ecosystem
VALUE_FLAGS = {
    "npm": {"--registry", "-w", "--workspace", "--prefix", "--tag", "--cache", "--omit", "--include",
            "-c", "--call"},
    "pypi": {"-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-e", "--editable",
             "-t", "--target", "-f", "--find-links", "--python", "-p", "--group", "--extra",
             "--source", "--platform", "--python-version", "--implementation", "--abi",
             "--no-binary", "--only-binary", "--root", "--prefix", "--src", "--upgrade-strategy"},
    "crates": {"--version", "--vers", "-F", "--features", "--branch", "--tag", "--rev",
               "--registry", "--root", "--rename", "--target", "--profile", "-j", "--jobs"},
    "gems": {"-v", "--version", "-s", "--source", "-i", "--install-dir", "--platform"},
}
# flags whose value IS a package (npx -p X, uvx --with X, uvx --from X)
PKG_FLAGS = {"npm": {"-p", "--package"}, "pypi": {"--with", "--from"}}
# flags that point installs away from the public registry; registry checks don't apply
OFF_REGISTRY = {"--git", "--path"}
NPM_INSTALL = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
               "isntall", "add", "it", "install-test"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
INSTALLERS = {"npm", "pnpm", "yarn", "bun", "npx", "bunx", "uv", "uvx", "poetry", "pipx", "cargo",
              "gem", "eval", "py"} | SHELLS
PUNCT = "();<>|&`"


def _is_installer(tok):
    b = os.path.basename(tok)
    return b in INSTALLERS or re.match(r"^(pip|python)[0-9.]*$", b) is not None


def _match(tokens):
    """Return (ecosystem, args, runner) for an install command, else None.

    runner=True means only the first positional is a package (npx, uvx, ...).
    """
    # skip wrappers like `sudo -u x`, `env A=1`, `time`, `nohup`: jump to the first installer
    i = next((k for k, tok in enumerate(tokens) if _is_installer(tok)), None)
    if i is None:
        return None
    t = tokens[i:]
    cmd = os.path.basename(t[0])
    if re.match(r"^(python[0-9.]*|py)$", cmd):
        if t[1:3] == ["-m", "pip"]:
            t = t[2:]
        elif t[1:2] == ["-mpip"]:
            t = ["pip"] + t[2:]
        else:
            return None
        cmd = "pip"
    sub = t[1] if len(t) > 1 else ""
    sub2 = t[2] if len(t) > 2 else ""
    if cmd in ("npm", "pnpm", "yarn", "bun") and sub in NPM_INSTALL:
        return "npm", t[2:], False
    if cmd == "yarn" and sub == "global" and sub2 == "add":
        return "npm", t[3:], False
    if cmd in ("pnpm", "yarn") and sub == "dlx" or cmd in ("npm", "bun") and sub in ("exec", "x"):
        return "npm", t[2:], True
    if cmd in ("npx", "bunx"):
        return "npm", t[1:], True
    if re.match(r"^pip[0-9.]*$", cmd) and sub == "install":
        return "pypi", t[2:], False
    if cmd == "uv" and sub == "add" or cmd == "poetry" and sub == "add":
        return "pypi", t[2:], False
    if cmd == "uv" and sub in ("pip", "tool") and sub2 == "install":
        return "pypi", t[3:], False
    if cmd == "uv" and sub == "tool" and sub2 == "run":
        return "pypi", t[3:], True
    if cmd == "pipx" and sub == "install":
        return "pypi", t[2:], False
    if cmd == "pipx" and sub == "run":
        return "pypi", t[2:], True
    if cmd == "uvx":
        return "pypi", t[1:], True
    if cmd == "cargo" and sub in ("add", "install"):
        return "crates", t[2:], False
    if cmd == "gem" and sub == "install":
        return "gems", t[2:], False
    return None


def _clean(eco, arg):
    """Strip version specifiers; return None for paths, URLs, archives."""
    if eco == "npm" and "@npm:" in arg:  # alias: `x@npm:real-pkg` installs real-pkg
        arg = arg.split("@npm:", 1)[1]
    if "://" in arg or arg.startswith((".", "/", "~", "git+", "file:", "github:")):
        return None
    if re.search(r"\.(whl|tar\.gz|tgz|zip|gem)$", arg):
        return None
    if eco == "npm":
        if arg.startswith("@"):
            scope_name = arg[1:].split("@")[0]
            return "@" + scope_name if "/" in scope_name else None
        if "/" in arg or ":" in arg:
            return None  # github shorthand
        return arg.split("@")[0] or None
    if eco == "pypi":
        name = re.split(r"[\[<>=!~;@ ]", arg)[0]
        return re.sub(r"[-_.]+", "-", name).lower() or None
    return arg.split("@")[0] or None


def _segments(command):
    """Split a shell command into simple-command token lists, respecting quotes."""
    for line in command.splitlines():
        lex = shlex.shlex(line, posix=True, punctuation_chars=PUNCT)
        lex.whitespace_split = True
        lex.commenters = ""
        try:
            tokens = list(lex)
        except ValueError:
            tokens = line.split()
        seg, skip = [], False
        for tok in tokens:
            if skip:
                skip = False
            elif tok and all(c in PUNCT for c in tok):
                if "<" in tok or ">" in tok:  # redirect: drop fd number and target file
                    if seg and seg[-1].isdigit():
                        seg.pop()
                    skip = True
                    continue
                yield seg
                seg = []
            else:
                seg.append(tok)
        yield seg


def _requirements(path):
    """Package specs from a requirements file (ponytail: nested -r not followed)."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    specs = [ln.split("#")[0].strip() for ln in lines]
    return [s for s in specs if s and not s.startswith("-")]


def parse(command, cwd=None, _depth=0):
    """Return [(ecosystem, package)] for every install in a shell command."""
    found = []

    def add(eco, arg):
        name = _clean(eco, arg)
        if name and (eco, name) not in found:
            found.append((eco, name))

    for tokens in _segments(command):
        if not tokens or _depth > 3:
            continue
        i = next((k for k, tok in enumerate(tokens) if _is_installer(tok)), None)
        cmd = os.path.basename(tokens[i]) if i is not None else ""
        if cmd in SHELLS:  # bash -c "...", bash -lc "..."
            rest = tokens[i + 1:]
            for k, a in enumerate(rest[:-1]):
                if re.match(r"^-[a-z]*c[a-z]*$", a):
                    found += [p for p in parse(rest[k + 1], cwd, _depth + 1) if p not in found]
            continue
        if cmd == "eval":
            found += [p for p in parse(" ".join(tokens[i + 1:]), cwd, _depth + 1) if p not in found]
            continue
        m = _match(tokens)
        if not m:
            continue
        eco, args, runner = m
        if eco == "crates" and any(a.split("=")[0] in OFF_REGISTRY for a in args):
            continue
        positional, from_flag, skip = [], False, None
        for a in args:
            flag, _, inline = a.partition("=") if a.startswith("--") else (a, "", "")
            if skip:
                if skip == "pkg":
                    add(eco, a)
                elif skip == "req":
                    for spec in _requirements(os.path.join(cwd or ".", a)):
                        add(eco, spec)
                skip = None
            elif flag in PKG_FLAGS.get(eco, ()):
                from_flag = from_flag or flag == "--from" or eco == "npm"
                add(eco, inline) if inline else None
                skip = None if inline else "pkg"
            elif eco == "pypi" and flag in ("-r", "--requirement"):
                if inline:
                    for spec in _requirements(os.path.join(cwd or ".", inline)):
                        add(eco, spec)
                else:
                    skip = "req"
            elif flag in VALUE_FLAGS[eco]:
                skip = None if inline else "val"
            elif not a.startswith("-"):
                positional.append(a)
        if runner:
            # npx -p X cmd / uvx --from X cmd: the positional is a command, not a package
            positional = [] if from_flag else positional[:1]
        for a in positional:
            add(eco, a)
    return found


def fetch_json(url):
    """GET url as JSON; None on 404. Other errors raise."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def _days_since(ts):
    if not ts:
        return None
    dt = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def registry_info(eco, name):
    """Return None if missing, else {"age_days": int|None, "downloads": int|None}."""
    q = urllib.parse.quote(name, safe="@")
    if eco == "npm":
        meta = fetch_json("https://registry.npmjs.org/" + q)
        if meta is None:
            return None
        dl = fetch_json("https://api.npmjs.org/downloads/point/last-week/" + name) or {}
        return {"age_days": _days_since(meta.get("time", {}).get("created")),
                "downloads": dl.get("downloads")}
    if eco == "pypi":
        meta = fetch_json("https://pypi.org/pypi/%s/json" % q)
        if meta is None:
            return None
        uploads = [f["upload_time_iso_8601"] for files in meta.get("releases", {}).values()
                   for f in files if f.get("upload_time_iso_8601")]
        return {"age_days": _days_since(min(uploads)) if uploads else None, "downloads": None}
    if eco == "crates":
        meta = fetch_json("https://crates.io/api/v1/crates/" + q)
        if meta is None:
            return None
        c = meta["crate"]
        return {"age_days": _days_since(c.get("created_at")), "downloads": c.get("recent_downloads")}
    if eco == "gems":
        meta = fetch_json("https://rubygems.org/api/v1/gems/%s.json" % q)
        if meta is None:
            return None
        versions = fetch_json("https://rubygems.org/api/v1/versions/%s.json" % q) or []
        first = min((v["created_at"] for v in versions if v.get("created_at")), default=None)
        return {"age_days": _days_since(first), "downloads": meta.get("downloads")}
    raise ValueError(eco)


MIN_DOWNLOADS = {"npm": 100, "crates": 100, "gems": 1000}  # weekly / 90-day / total


def _edit_distance(a, b):
    """Optimal string alignment distance (Levenshtein + adjacent swaps)."""
    d = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def lookalike(eco, name):
    """Popular package `name` is one edit away from, or None."""
    if name in POPULAR[eco] or len(name) < 4:
        return None
    for p in sorted(POPULAR[eco]):
        if abs(len(p) - len(name)) <= 1 and _edit_distance(name, p) == 1:
            return p
    return None


def check(eco, name):
    """Return a reason string if the package should be blocked, else None."""
    allow = {a.strip() for a in os.environ.get("PKG_GUARD_ALLOW", "").split(",") if a.strip()}
    if name in allow or name in POPULAR[eco]:
        return None
    try:
        info = registry_info(eco, name)
    except Exception as e:  # network down, rate limit, bad JSON
        if os.environ.get("PKG_GUARD_FAIL_CLOSED") == "1":
            return "%s: registry check failed (%s) and PKG_GUARD_FAIL_CLOSED=1" % (name, e)
        print("pkg-guard: could not check %s (%s), allowing" % (name, e), file=sys.stderr)
        return None
    twin = lookalike(eco, name)
    if info is None:
        hint = " Did you mean %r?" % twin if twin else ""
        return "%s: does not exist on %s (hallucinated name?).%s" % (name, eco, hint)
    age, dls = info["age_days"], info["downloads"]
    min_age = _env_int("PKG_GUARD_MIN_AGE_DAYS", 30)
    if age is not None and age < min_age:
        return "%s: first published %d days ago (< %d)." % (name, age, min_age)
    if dls is not None and eco in MIN_DOWNLOADS and dls < MIN_DOWNLOADS[eco]:
        return "%s: only %d downloads (< %d)." % (name, dls, MIN_DOWNLOADS[eco])
    weak = (age is not None and age < 180) or (dls is not None and dls < 100 * MIN_DOWNLOADS.get(eco, 0))
    if twin and weak:
        return "%s: looks like a typosquat of popular package %r." % (name, twin)
    return None


def check_command(command, cwd=None):
    """Return list of block reasons for a shell command."""
    pkgs = parse(command, cwd)
    if not pkgs:
        return []
    with ThreadPoolExecutor(max_workers=8) as ex:
        return [r for r in ex.map(lambda p: check(*p), pkgs) if r]


def hook_output(payload):
    """Map a PreToolUse payload to the deny JSON (or None to allow)."""
    if payload.get("tool_name") != "Bash":
        return None
    cmd = (payload.get("tool_input") or {}).get("command", "")
    if isinstance(cmd, list):  # Codex may send argv, e.g. ["bash", "-lc", "..."]
        cmd = " ".join(shlex.quote(str(a)) for a in cmd)
    reasons = check_command(cmd, payload.get("cwd"))
    if not reasons:
        return None
    msg = ("pkg-guard blocked this install:\n- " + "\n- ".join(reasons) +
           "\nUse a well-known package or the stdlib. If the user confirms the package is "
           "legitimate, they can add it to PKG_GUARD_ALLOW.")
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": msg}}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["hook"]:
        try:
            payload = json.load(sys.stdin)
        except ValueError:
            return 0
        out = hook_output(payload)
        if out:
            print(json.dumps(out))
        return 0
    if argv[:1] == ["check"] and len(argv) > 1:
        reasons = check_command(" ".join(argv[1:]))
        for r in reasons:
            print("BLOCK " + r)
        return 1 if reasons else 0
    if argv[:1] == ["--version"]:
        print(__version__)
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
