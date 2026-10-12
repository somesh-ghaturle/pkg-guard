#!/usr/bin/env python3
"""pkg-guard: block hallucinated / typosquatted package installs by AI coding agents.

Usage:
  pkg_guard.py check "<shell command>"   exit 1 and print reasons if blocked
  pkg_guard.py scan [lockfile ...]       check every package in lockfiles (default: those in .)
  pkg_guard.py hook                      PreToolUse (Claude Code, Codex) / BeforeTool (Gemini CLI)
                                         hook: JSON on stdin
"""
import fnmatch
import json
import os
import re
import shlex
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

__version__ = "0.4.0"
UA = "pkg-guard/%s (https://github.com/somesh-ghaturle/pkg-guard)" % __version__
TIMEOUT = 4

# Hand-picked names; GENERATED_POPULAR at the bottom of the file adds registry top-N lists.
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
    "go": """github.com/gin-gonic/gin github.com/spf13/cobra github.com/spf13/viper
        github.com/stretchr/testify github.com/sirupsen/logrus go.uber.org/zap github.com/gorilla/mux
        github.com/gorilla/websocket github.com/labstack/echo/v4 github.com/gofiber/fiber/v2
        github.com/go-chi/chi/v5 github.com/google/uuid github.com/pkg/errors github.com/golang-jwt/jwt/v5
        gorm.io/gorm github.com/jmoiron/sqlx github.com/lib/pq github.com/jackc/pgx/v5
        github.com/go-sql-driver/mysql github.com/redis/go-redis/v9 github.com/aws/aws-sdk-go-v2
        google.golang.org/grpc google.golang.org/protobuf golang.org/x/net golang.org/x/sync
        golang.org/x/crypto golang.org/x/text golang.org/x/tools github.com/prometheus/client_golang
        github.com/rs/zerolog github.com/urfave/cli/v2 gopkg.in/yaml.v3 github.com/joho/godotenv
        github.com/mattn/go-sqlite3 github.com/go-playground/validator/v10
        github.com/charmbracelet/bubbletea github.com/golang/protobuf github.com/google/go-cmp
        github.com/mitchellh/mapstructure github.com/fsnotify/fsnotify k8s.io/client-go""",
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
    "go": {"-tags", "-modfile", "-o", "-C", "-mod", "-ldflags", "-gcflags", "-asmflags", "-pkgdir",
           "-overlay", "-p", "-exec", "-toolexec", "-buildmode", "-compiler", "-installsuffix"},
}
# flags whose value IS a package (npx -p X, uvx --with X, uvx --from X)
PKG_FLAGS = {"npm": {"-p", "--package"}, "pypi": {"--with", "--from"}}
# flags that point installs away from the public registry; registry checks don't apply
OFF_REGISTRY = {"--git", "--path"}
NPM_INSTALL = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
               "isntall", "add", "it", "install-test"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
INSTALLERS = {"npm", "pnpm", "yarn", "bun", "npx", "bunx", "uv", "uvx", "poetry", "pipx", "cargo",
              "gem", "go", "eval", "py"} | SHELLS
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
    if cmd == "go" and sub in ("get", "install"):
        return "go", t[2:], False
    if cmd == "go" and sub == "mod" and sub2 == "download":
        return "go", t[3:], False
    if cmd == "go" and sub == "mod" and sub2 == "edit":
        args, it = [], iter(t[3:])
        for a in it:
            m = re.match(r"^--?(require|replace)(?:=(.*))?$", a)
            if m:
                v = m.group(2) if m.group(2) is not None else next(it, "")
                args.append(v.split("=", 1)[1] if m.group(1) == "replace" and "=" in v else v)
        return "go", args, False
    if cmd == "go" and sub == "run":  # `go run mod@v` fetches and runs a remote module
        return "go", t[2:], True
    return None


def _clean(eco, arg):
    """Strip version specifiers; return None for paths, URLs, archives."""
    if eco == "npm" and "@npm:" in arg:  # alias: `x@npm:real-pkg` installs real-pkg
        arg = arg.split("@npm:", 1)[1]
    if "://" in arg or arg.startswith((".", "/", "~", "git+", "file:", "github:")):
        return None
    if re.search(r"\.(whl|tar\.gz|tgz|zip|gem)$", arg):
        return None
    if eco == "go":
        path, _, ver = arg.partition("@")
        # no dot in the first element = stdlib or local (fmt, ./..., all); @none removes a dep
        if ver == "none" or "." not in path.split("/")[0] or (not ver and "/" not in path and path.endswith(".go")):
            return None
        return re.sub(r"/\.\.\.$", "", path)
    if eco == "npm":
        if arg.startswith("@"):
            scope_name = arg[1:].split("@")[0]
            return "@" + scope_name if "/" in scope_name else None
        if "/" in arg or ":" in arg:
            return None  # github shorthand
        return arg.split("@")[0] or None
    if eco == "pypi":
        name = re.split(r"[\[<>=!~;@,\s]", arg.strip())[0]
        return re.sub(r"[-_.]+", "-", name).lower() or None
    return arg.split("@")[0] or None


_ANSI_C = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r",
           "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c(raw):
    """Decode the body of bash $'...' with bash's escape rules (never fails)."""
    def repl(m):
        e = m.group(1)
        if e[0] in "xuU":
            return chr(min(int(e[1:], 16), 0x10FFFF))
        if e[0] in "01234567":
            return chr(int(e, 8) & 0xFF)
        if e[0] == "c":
            return chr(ord(e[1]) & 0x1F)
        return _ANSI_C.get(e, "\\" + e)  # unknown escapes stay literal, like bash
    return re.sub(r"\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c.|.)",
                  repl, raw, flags=re.S)


def _normalize(command):
    """Rewrite bash-only syntax shlex doesn't know, tracking quote state like bash does.

    Unquoted newlines become `;`, backslash-newline continuations are joined, `$"..."`
    becomes `"..."`, and `$'...'` is decoded (`$'\\x6epm'` is `npm`) and re-quoted.
    Comments are dropped (a `'` in `# don't` must not open a quote), and `$(...)` /
    backticks inside double quotes, which bash still runs, are appended as commands.
    Heredoc bodies are data (quotes in them mean nothing), unless fed to a shell.
    """
    out, extra, pending, i, q, n = [], [], [], 0, None, len(command)
    word_start = True  # bash only starts a comment with `#` at the start of a word
    while i < n:
        c, nxt = command[i], command[i + 1:i + 2]
        if q is None and c == "<" and nxt == "<" and command[i + 2:i + 3] != "<" and command[i - 1:i] != "<":
            # delimiter word as bash reads it: quoted parts may contain spaces ('E O F')
            m = re.match(r"""<<(-?)[ \t]*((?:[^\s;&|()<>'"\\]|\\.|'[^']*'|"(?:[^"\\]|\\.)*")+)""", command[i:])
            if m:
                raw = m.group(2)
                delim = re.sub(r"""'([^']*)'|"((?:[^"\\]|\\.)*)"|\\(.)""",
                               lambda d: d.group(1) if d.group(1) is not None else
                               re.sub(r"\\(.)", r"\1", d.group(2)) if d.group(2) is not None else d.group(3), raw)
                # the shell may be before the << (bash <<EOF) or piped after it (cat <<EOF | sh)
                after = command[i + m.end():].split("\n", 1)[0]
                words = re.split(r"[;&|(\n]", "".join(out))[-1].split() + re.split(r"[\s;&|()<>]+", after)
                pending.append((delim, m.group(1) == "-", raw != delim,
                                any(os.path.basename(w) in SHELLS for w in words)))
                out.append("<< ")  # redirect + target: _segments drops both
                out.append(raw if re.match(r"^[\w.-]+$", raw) else "EOF")
                i, word_start = i + m.end(), False
                continue
        if q is None and c == "\n" and pending:
            out.append(";")
            i += 1
            for delim, dash, quoted, shell in pending:
                body, closed = [], False
                while i < n:
                    j = command.find("\n", i)
                    j = n if j < 0 else j
                    line, i = command[i:j], j + 1
                    if (line.lstrip("\t") if dash else line) == delim:
                        closed = True
                        break
                    body.append(line)
                text = "\n".join(body)
                if shell or not closed:  # `bash <<EOF` runs it; unterminated: not a real heredoc
                    extra.append(text)
                elif not quoted:  # <<EOF (unquoted) still runs $(...) and backticks in the body
                    extra.append('"%s"' % text.replace('"', '\\"'))
            pending, word_start = [], True
            out.append(";")
            continue
        if q is None and c == "#" and word_start:
            j = command.find("\n", i)
            i = n if j < 0 else j
            continue
        if q == '"' and (c == "`" or c == "$" and nxt == "("):
            j, depth = (i + 1, 0) if c == "`" else (i + 2, 1)
            while j < n:
                if command[j] == "\\":
                    j += 2
                    continue
                if c == "`" and command[j] == "`":
                    break
                if c == "$" and command[j] in "'\"":  # skip quoted text: ")" there doesn't close
                    k = j + 1
                    while k < n and command[k] != command[j]:
                        k += 2 if command[j] == '"' and command[k] == "\\" else 1
                    j = k + 1
                    continue
                if c == "$":
                    depth += {"(": 1, ")": -1}.get(command[j], 0)
                    if depth == 0:
                        break
                j += 1
            extra.append(command[i + (1 if c == "`" else 2):j])
            out.append(command[i:j + 1])
            i, word_start = j + 1, False
            continue
        if q is None and c == "\\":
            if nxt != "\n":  # backslash-newline vanishes and leaves word_start as it was
                out.append(command[i:i + 2])
                word_start = False
            i += 2
            continue
        if q is None and c == "$" and nxt == "'":
            j, buf = i + 2, []
            while j < n and command[j] != "'":
                step = 2 if command[j] == "\\" else 1
                buf.append(command[j:j + step])
                j += step
            out.append(shlex.quote(_ansi_c("".join(buf))))
            i, word_start = j + 1, False
            continue
        if q is None and c == "$" and nxt == '"':
            i += 1
            continue
        if q is None and c == "\n":
            c = ";"
        elif q is None and c in "'\"":
            q = c
        elif q == c:
            q = None
        elif q == '"' and c == "\\":
            # bash drops the backslash in "\$" and "\`"; shlex keeps it
            out.append(nxt if nxt in "$`" else command[i:i + 2])
            i, word_start = i + 2, False
            continue
        out.append(c)
        word_start = q is None and c in " \t;&|()<>"
        i += 1
    return "".join(out) + "".join(";" + _normalize(e) for e in extra)


def _segments(command):
    """Split a shell command into simple-command token lists, respecting quotes."""
    command = _normalize(command)
    lex = shlex.shlex(command, posix=True, punctuation_chars=PUNCT)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        tokens = list(lex)
    except ValueError:  # unbalanced quotes: bash won't run it either
        tokens = command.replace(";", " ; ").split()
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


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def _requirement_specs(text, base=None, _seen=None):
    """Package specs from requirements-file text; follows `-r other.txt` relative to `base`."""
    specs = []
    text = re.sub(r"\\\r?\n", "", text)  # pip joins backslash-continued lines: "ev\<NL>il" is evil
    for ln in text.splitlines():
        s = re.sub(r"(^|\s)#.*", "", ln).strip()
        m = re.match(r"^(?:-r|--requirement)[\s=]*(\S+)$", s)
        if m and base is not None:
            path = os.path.normpath(os.path.join(base, m.group(1)))
            specs += _requirements(path, _seen)
        elif s and not s.startswith("-"):
            specs.append(s)
    return specs


def _requirements(path, _seen=None):
    """Package specs from a requirements file, following nested -r includes."""
    _seen = set() if _seen is None else _seen
    if path in _seen or len(_seen) > 20:
        return []
    _seen.add(path)
    return _requirement_specs(_read(path) or "", os.path.dirname(path), _seen)


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


def fetch(url):
    """GET url as text; None on 404/410 (not found). Other errors raise."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read().decode()
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):
            return None
        raise


def fetch_json(url):
    text = fetch(url)
    return None if text is None else json.loads(text)


def _go_info(path):
    """Go module info via proxy.golang.org. `path` may be a package inside a module."""
    root = path
    # ponytail: walk up at most 3 parents to find the module root; deeper package paths read as missing
    for _ in range(4):
        esc = re.sub(r"[A-Z]", lambda m: "!" + m.group().lower(), root)  # proxy case-encoding
        base = "https://proxy.golang.org/%s/@" % esc
        latest = fetch_json(base + "latest")
        if latest is not None:
            break
        if root.count("/") < 2:
            return None
        root = root.rsplit("/", 1)[0]
    else:
        return None
    tags = (fetch(base + "v/list") or "").split()
    first = min(tags, key=lambda v: [int(x) for x in re.findall(r"\d+", v.split("-")[0])], default=None)
    # The proxy's Time is the git commit time, which the author controls (backdated commits),
    # so age alone is weak for Go. Repo stars from deps.dev are the signal they can't set.
    info = fetch_json(base + "v/%s.info" % first) if first else latest
    stars = None
    if root.split("/")[0] in ("github.com", "gitlab.com", "bitbucket.org"):
        proj = fetch_json("https://api.deps.dev/v3/projects/" +
                          urllib.parse.quote("/".join(root.split("/")[:3]).lower(), safe=""))
        stars = (proj or {}).get("starsCount") or 0  # not indexed = nobody depends on it
    # ponytail: vanity domains (go.uber.org/...) get no star signal; map them via deps.dev if needed
    return {"age_days": _days_since((info or latest).get("Time")), "downloads": stars}


def _days_since(ts):
    if not ts:
        return None
    dt = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


_npm_downloads = {}  # name -> weekly downloads, prefetched in bulk by scan()


def _npm_prefetch(names):
    """Fill _npm_downloads with bulk queries (128 unscoped names per request)."""
    plain = sorted(n for n in names if not n.startswith("@"))
    for i in range(0, len(plain), 128):
        try:
            data = fetch_json("https://api.npmjs.org/downloads/point/last-week/" + ",".join(plain[i:i + 128]))
        except Exception:
            continue  # per-package lookups will retry
        data = data or {}
        for v in [data] if "package" in data else data.values():  # one name answers unwrapped
            if isinstance(v, dict) and isinstance(v.get("downloads"), int):
                _npm_downloads[v.get("package")] = v["downloads"]


def registry_info(eco, name):
    """Return None if missing, else {"age_days": int|None, "downloads": int|None}."""
    q = urllib.parse.quote(name, safe="@")
    if eco == "npm":
        meta = fetch_json("https://registry.npmjs.org/" + q)
        if meta is None:
            return None
        dls = _npm_downloads.get(name)
        if dls is None:
            try:
                dls = (fetch_json("https://api.npmjs.org/downloads/point/last-week/" + name) or {}).get("downloads")
            except Exception:  # the downloads API rate-limits hard; still check existence and age
                if os.environ.get("PKG_GUARD_FAIL_CLOSED") == "1":
                    raise
        latest = meta.get("versions", {}).get(meta.get("dist-tags", {}).get("latest"), {})
        scripts = set(latest.get("scripts") or {}) | ({"install"} if latest.get("gypfile") else set())
        return {"age_days": _days_since(meta.get("time", {}).get("created")),
                "downloads": dls,
                "install_scripts": sorted(INSTALL_HOOKS & scripts)}
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
    if eco == "go":
        return _go_info(name)
    raise ValueError(eco)


INSTALL_HOOKS = {"preinstall", "install", "postinstall"}  # npm runs these on `npm install`
MIN_DOWNLOADS = {"npm": 100, "crates": 100, "gems": 1000, "go": 10}  # weekly / 90-day / total / repo stars
UNITS = {"go": "repo stars"}


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


def _go_private(path):
    """True if GOPRIVATE/GONOPROXY globs cover `path` (matched per path-element prefix, like go)."""
    pats = ",".join(os.environ.get(v, "") for v in ("GOPRIVATE", "GONOPROXY")).split(",")
    elems = path.split("/")
    return any(fnmatch.fnmatchcase("/".join(elems[:p.count("/") + 1]), p) for p in pats if p.strip())


# Packages that passed every check, keyed "eco:name" -> unix time. Blocks and network
# failures are never cached, so a corrected name or a recovered registry is rechecked.
# ponytail: the agent can write this file too; pkg-guard is a guard against mistakes, not a sandbox
CACHE_FILE = os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"),
                          "pkg-guard", "pkg-guard-ok.json")
CACHE_TTL = 24 * 3600
_cache_lock = threading.Lock()


def _cache_load():
    try:
        st = os.stat(CACHE_FILE)
        if st.st_uid != os.getuid() or st.st_mode & 0o022:  # someone else could have written it
            return {}
        with open(CACHE_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError, TypeError):
        return {}
    now = time.time()
    return {k: t for k, t in data.items() if isinstance(t, (int, float)) and 0 <= now - t < CACHE_TTL} \
        if isinstance(data, dict) else {}


def _cached_ok(key):
    return bool(CACHE_FILE) and key in _cache_load()


def _remember_ok(key):
    if not CACHE_FILE:
        return
    with _cache_lock:
        data = _cache_load()
        data[key] = time.time()
        tmp = "%s.%d.tmp" % (CACHE_FILE, os.getpid())
        try:
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                json.dump(data, f)
            os.replace(tmp, CACHE_FILE)  # atomic: concurrent hooks never see a half-written file
        except OSError:
            pass  # read-only home etc.: just don't cache


def check(eco, name):
    """Return a reason string if the package should be blocked, else None."""
    allow = {a.strip() for a in os.environ.get("PKG_GUARD_ALLOW", "").split(",") if a.strip()}
    if name in allow or name in POPULAR[eco]:
        return None
    if eco == "go" and (_go_private(name) or any(name.startswith(p + "/") for p in POPULAR["go"])):
        return None
    key = "%s:%s" % (eco, name)
    if _cached_ok(key):
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
        return "%s: only %d %s (< %d)." % (name, dls, UNITS.get(eco, "downloads"), MIN_DOWNLOADS[eco])
    weak = (age is not None and age < 180) or (dls is not None and dls < 100 * MIN_DOWNLOADS.get(eco, 0))
    if twin and weak:
        return "%s: looks like a typosquat of popular package %r." % (name, twin)
    if weak and info.get("install_scripts"):
        return "%s: runs %s on install and is young or little-used (%s days old, %s weekly downloads)." % (
            name, "/".join(info["install_scripts"]), age, dls)
    _remember_ok(key)
    return None


def check_command(command, cwd=None):
    """Return list of block reasons for a shell command."""
    pkgs = parse(command, cwd)
    if not pkgs:
        return []
    with ThreadPoolExecutor(max_workers=8) as ex:
        return [r for r in ex.map(lambda p: check(*p), pkgs) if r]


try:
    import tomllib
except ImportError:  # ponytail: Python < 3.11 skips TOML manifests, vendor a parser if 3.9/3.10 matter
    tomllib = None


def _toml(text):
    """Parsed TOML; raises ValueError if invalid (caller decides fail-open vs closed)."""
    return tomllib.loads(text) if tomllib else {}


def _npm_deps(text):
    data = json.loads(text) if text.strip() else {}  # raises ValueError if invalid
    out = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section) if isinstance(data, dict) else None
        for k, v in (deps if isinstance(deps, dict) else {}).items():
            v = str(v).strip()
            if v.startswith("npm:"):  # "alias": "npm:real-pkg@1"
                k = v[4:]
            elif re.match(r"^[a-z+]+:", v) or "/" in v:  # file:, link:, workspace:, git+..., urls, user/repo
                continue
            name = _clean("npm", k)
            if name:
                out.add(name)

    def aliases(v):  # overrides/resolutions can swap any transitive dep: "lodash": "npm:evil@1"
        if isinstance(v, dict):
            for x in v.values():
                aliases(x)
        elif isinstance(v, str) and v.startswith("npm:") and _clean("npm", v[4:]):
            out.add(_clean("npm", v[4:]))
    if isinstance(data, dict):
        pnpm = data.get("pnpm") if isinstance(data.get("pnpm"), dict) else {}
        aliases({"o": data.get("overrides"), "r": data.get("resolutions"), "p": pnpm.get("overrides")})
    return out


def _pyproject_deps(data):
    proj, poetry = data.get("project", {}), data.get("tool", {}).get("poetry", {})
    specs = list(proj.get("dependencies", [])) + list(data.get("build-system", {}).get("requires", []))
    specs += list(data.get("tool", {}).get("uv", {}).get("dev-dependencies", []))
    for group in data.get("tool", {}).get("pdm", {}).get("dev-dependencies", {}).values():
        specs += [g for g in group if isinstance(g, str)]
    for group in list(proj.get("optional-dependencies", {}).values()) + list(data.get("dependency-groups", {}).values()):
        specs += [g for g in group if isinstance(g, str)]
    tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    tables += [g.get("dependencies", {}) for g in poetry.get("group", {}).values()]
    for t in tables:
        specs += [k for k, v in t.items()
                  if k != "python" and not (isinstance(v, dict) and {"git", "path", "url"} & set(v))]
    return specs


def _cargo_deps(data):
    out = set()
    # [workspace.dependencies] can rename (`foo = {package = "evil"}`) for members to inherit
    for t in [data, data.get("workspace", {})] + list(data.get("target", {}).values()):
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for k, v in t.get(section, {}).items():
                if isinstance(v, dict):
                    if {"git", "path", "registry"} & set(v):
                        continue
                    k = v.get("package", k)
                out.add(k)
    return out


def _gem_deps(text):
    # ponytail: regex over Ruby source; catches `gem "x"`, `gem("x")`, `a; gem 'x'`, not metaprogramming
    out = set()
    for ln in re.split(r"[\n;]", text):
        m = re.match(r"""^\s*gem\s*\(?\s*["']([^"']+)["'](.*)""", ln)
        if m and not re.search(r"\b(git|github|path):|:(git|github|path)\s*=>", m.group(2)):
            out.add(m.group(1))
    return out


def _gomod_deps(text):
    """Modules from go.mod `require` lines and `replace ... => module version` targets."""
    out, block = set(), None
    for ln in text.splitlines():
        ln = re.sub(r"//.*", "", ln).strip()
        m = re.match(r"^(require|replace)\s*\($", ln)
        if m:
            block = m.group(1)
            continue
        if ln == ")":
            block = None
            continue
        m = re.match(r"^(require|replace)\s+(.*)$", ln)
        kind, rest = (m.group(1), m.group(2)) if m else (block, ln)
        if kind == "require":
            parts = rest.split()
            name = _clean("go", parts[0].strip('"')) if parts else None
        elif kind == "replace" and "=>" in rest:
            parts = rest.split("=>", 1)[1].split()  # local-path targets have no version
            name = _clean("go", parts[0].strip('"')) if len(parts) == 2 else None
        else:
            name = None
        if name:
            out.add(name)
    return out


def manifest_deps(path, text):
    """Return (ecosystem, {names}) declared in a dependency manifest, else None.

    Raises ValueError if a JSON/TOML manifest doesn't parse.
    """
    base = os.path.basename(path).lower()  # macOS/Windows: Package.json IS package.json
    text = text.lstrip("﻿")  # npm and cargo accept a BOM; json.loads doesn't
    if base == "package.json":
        return "npm", _npm_deps(text)
    if re.match(r"^requirements.*\.(txt|in)$", base):
        specs = _requirement_specs(text, os.path.dirname(path))
    elif base == "pyproject.toml":
        specs = _pyproject_deps(_toml(text))
    elif base == "cargo.toml":
        return "crates", _cargo_deps(_toml(text))
    elif base == "gemfile":
        return "gems", _gem_deps(text)
    elif base == "go.mod":
        return "go", _gomod_deps(text)
    else:
        return None
    return "pypi", {n for n in (_clean("pypi", s) for s in specs) if n}


def _npm_lock(data):
    """Registry packages in package-lock.json / npm-shrinkwrap.json (lockfile v1-v3)."""
    out = set()

    def add(name, e):
        if not isinstance(e, dict) or e.get("link") or e.get("bundled"):
            return
        if not _registry_tarball(str(e.get("resolved") or e.get("version") or "")):
            return
        alias = str(e.get("version", "")).startswith("npm:") and e["version"][4:].rsplit("@", 1)[0]
        n = _clean("npm", e.get("name") or alias or name)  # the real package behind an alias
        if n:
            out.add(n)

    for key, e in (data.get("packages") or {}).items():
        if "node_modules/" in key:
            add(key.rsplit("node_modules/", 1)[1], e)

    def walk(deps):  # v1: nested "dependencies"
        for name, e in (deps or {}).items():
            add(name, e)
            walk(e.get("dependencies") if isinstance(e, dict) else None)
    if not data.get("packages"):
        walk(data.get("dependencies"))
    return out


def _toml_lock(data, eco, public):
    """[[package]] names in uv.lock / poetry.lock / Cargo.lock that come from the public registry."""
    out = set()
    for p in data.get("package") or []:
        src = p.get("source")
        if eco == "pypi" and isinstance(src, dict):  # uv: {registry = ...} vs git/path/editable/virtual
            ok = "registry" in src and public(str(src["registry"]))
        elif eco == "pypi":  # poetry: no source = PyPI
            ok = src is None
        else:  # cargo: no source = workspace member
            ok = isinstance(src, str) and public(src)
        if ok and p.get("name"):
            out.add(_clean(eco, p["name"]))
    return out - {None}


def _npm_spec_name(spec):
    """Package name from `name@range` (scope-aware); follows `alias@npm:real@range`."""
    spec = spec.strip().strip("'\"")
    if "@npm:" in spec:
        spec = spec.split("@npm:", 1)[1]
    at = spec.find("@", 1)  # skip a leading scope @
    return _clean("npm", spec[:at] if at > 0 else spec)


def _registry_tarball(res):
    """False for git/file/link sources and plain tarball URLs; registry tarballs have /-/."""
    return not (re.match(r"^(git|file:|link:|github:|workspace:|patch:|portal:|exec:)", res) or
                "://" in res and "/-/" not in res)


def _yarn_lock(text):
    """yarn.lock v1 (classic) and Berry: one block per resolved package."""
    out = set()
    for block in re.split(r"\n(?=\S)", text):
        lines = block.split("\n")
        head = lines[0].rstrip()
        if head.startswith("#") or not head.endswith(":") or head.startswith("__metadata"):
            continue
        body = "\n".join(lines[1:])
        m = re.search(r'^\s+resolution:\s*"?([^"\n]+)"?$', body, re.M)  # Berry
        if m:
            name, _, proto = m.group(1).rpartition("@")
            if proto.startswith("npm:"):
                out.add(_clean("npm", name))
            continue
        m = re.search(r'^\s+resolved\s+"?([^"\s]+)"?', body, re.M)  # classic
        if m and not _registry_tarball(m.group(1)):
            continue
        out.add(_npm_spec_name(head[:-1].split(",")[0]))
    return out - {None}


def _pnpm_lock(text):
    """pnpm-lock.yaml v5-v9: keys of the `packages:` section."""
    out, section, name = set(), None, None
    for ln in text.split("\n"):
        if re.match(r"^\S", ln):
            section = ln.rstrip()
            continue
        if section != "packages:":
            continue
        m = re.match(r"^  (\S.*):\s*$", ln)
        if m:
            key = re.sub(r"\(.*$", "", m.group(1).strip("'\"")).lstrip("/")  # drop (peer) suffixes
            if re.match(r"^(@[^/]+/)?[^@/]+/\d", key):  # v5: /name/1.2.3_peer
                name = _clean("npm", key.rsplit("/", 1)[0])
            else:  # v6+: name@1.2.3, @scope/name@1.2.3
                at = key.rfind("@")
                ver = key[at + 1:]
                name = _clean("npm", key[:at]) if at > 0 and not re.search(r"[:/]", ver) else None
            if name:
                out.add(name)
        elif name and re.match(r"^    resolution:", ln) and (
                "type:" in ln or "tarball:" in ln and not _registry_tarball(ln.split("tarball:", 1)[1].strip(" }"))):
            out.discard(name)  # git, directory, or plain tarball
    return out


def _gemfile_lock(text):
    """Gemfile.lock: specs under GEM sections that point at rubygems.org."""
    out = set()
    for sec in re.split(r"\n(?=\S)", text):
        if not sec.startswith("GEM") or not re.search(r"^  remote: https?://(index\.)?rubygems\.org/?$", sec, re.M):
            continue
        out |= set(re.findall(r"^    ([^\s(]+) \(", sec, re.M))  # 6-space lines are their dependencies
    return out


def _go_sum(text):
    """go.sum: modules whose source was downloaded (lines without /go.mod)."""
    out = set()
    for ln in text.split("\n"):
        parts = ln.split()
        if len(parts) == 3 and not parts[1].endswith("/go.mod"):
            name = _clean("go", parts[0])
            if name:
                out.add(name)
    return out


def lockfile_deps(path, text):
    """Return (ecosystem, {names}) pinned in a lockfile, else None."""
    base = os.path.basename(path).lower()
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        return "npm", _npm_lock(json.loads(text))
    if base in ("uv.lock", "poetry.lock"):
        return "pypi", _toml_lock(_toml(text), "pypi", lambda r: "pypi.org" in r)
    if base == "cargo.lock":
        return "crates", _toml_lock(_toml(text), "crates", lambda r: "crates.io" in r)
    if base == "yarn.lock":
        return "npm", _yarn_lock(text)
    if base == "pnpm-lock.yaml":
        return "npm", _pnpm_lock(text)
    if base == "gemfile.lock":
        return "gems", _gemfile_lock(text)
    if base == "go.sum":
        return "go", _go_sum(text)
    return None


LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock",
             "poetry.lock", "Cargo.lock", "Gemfile.lock", "go.sum")


def scan(paths):
    """Return block reasons for every package pinned in the given lockfiles."""
    pkgs, reasons = set(), []
    for path in paths:
        text = _read(path)
        try:
            found = lockfile_deps(path, text) if text is not None else None
        except Exception as e:
            reasons.append("%s: does not parse (%s)" % (path, e))
            continue
        if found is None:
            reasons.append("%s: not a lockfile pkg-guard can read" % path)
        elif not tomllib and os.path.basename(path).lower() in ("uv.lock", "poetry.lock", "cargo.lock"):
            reasons.append("%s: needs Python 3.11+ (tomllib)" % path)
        else:
            pkgs |= {(found[0], n) for n in found[1]}
    print("pkg-guard: checking %d packages from %s" % (len(pkgs), ", ".join(paths)), file=sys.stderr)
    _npm_prefetch([n for e, n in pkgs if e == "npm" and n not in POPULAR["npm"]])
    # ponytail: 8 parallel lookups; crates.io asks crawlers for 1/s, throttle if big Cargo.lock scans get blocked
    with ThreadPoolExecutor(max_workers=8) as ex:
        return reasons + [r for r in ex.map(lambda p: check(*p), sorted(pkgs)) if r]


def _edited_text(tool, inp, old):
    """File content after a Write/Edit/MultiEdit, or None if the edit can't apply."""
    if tool == "Write":
        return inp.get("content", "")  # None: an apply_patch that won't apply
    text = old or ""
    for e in (inp.get("edits") if tool == "MultiEdit" else [inp]) or []:
        o, n = e.get("old_string", ""), e.get("new_string", "")
        if o not in text:
            return None  # the edit itself will fail
        text = text.replace(o, n) if e.get("replace_all") else text.replace(o, n, 1)
    return text


def check_edit(tool, inp, cwd=None):
    """Return block reasons for dependencies a file edit adds to a manifest.

    Without this, `npm i evil` is caught but writing "evil" into package.json and
    running a bare `npm install` is not.
    """
    path = os.path.join(cwd or ".", inp.get("file_path", ""))
    if manifest_deps(path, "") is None:  # also catch an innocent name symlinked to a manifest
        path = os.path.realpath(path)
        if manifest_deps(path, "") is None:
            return []
    name = os.path.basename(path)
    old = _read(path) or ""
    new = _edited_text(tool, inp, old)
    # fail closed: if we can't see the result (agent edits may normalize quotes/whitespace
    # differently from us) or can't parse it, we can't tell what it adds
    if new is None:
        return ["%s: pkg-guard could not apply this edit to check it. Re-read the file and "
                "retry with its exact text." % name]
    try:
        eco, after = manifest_deps(path, new)
    except Exception as e:  # bad syntax, or valid syntax with unexpected shapes (`project = "x"`)
        return ["%s: does not parse (%s), so pkg-guard can't check its dependencies." % (name, e)]
    try:
        before = manifest_deps(path, old)[1]
    except Exception:
        before = set()  # broken before: check everything
    added = sorted(after - before)
    with ThreadPoolExecutor(max_workers=8) as ex:
        return [r for r in ex.map(lambda n: check(eco, n), added) if r]


_UNI = str.maketrans({**dict.fromkeys("‐‑‒–—―−", "-"),
                      **dict.fromkeys("‘’‚‛", "'"),
                      **dict.fromkeys("“”„‟", '"'),
                      **dict.fromkeys("          "
                                      "  　", " ")})


def _seek(lines, pattern, start, eof=False):
    """Codex's seek_sequence: first match from `start`, exact, then ever looser."""
    if not pattern:
        return start
    if len(pattern) > len(lines):
        return None
    start = max(start, len(lines) - len(pattern)) if eof else start
    for norm in (lambda s: s, str.rstrip, str.strip, lambda s: s.strip().translate(_UNI)):
        for i in range(start, len(lines) - len(pattern) + 1):
            if all(norm(a) == norm(b) for a, b in zip(lines[i:i + len(pattern)], pattern)):
                return i
    return None


def _apply_chunks(text, chunks):
    """New file text after Codex applies update `chunks`, or None if it would fail."""
    lines = re.split(r"\r\n|\r|\n", text)
    if lines[-1] == "":
        lines.pop()  # the final newline ends the last line; it isn't a line of its own
    reps, at = [], 0
    for c in chunks:
        if c["ctx"] is not None:
            i = _seek(lines, [c["ctx"]], at)
            if i is None:
                return None
            at = i + 1
        old, new, keep = c["old"], c["new"], c["keep"]
        if not old:  # pure insertion: Codex appends it at the end of the file
            reps.append((len(lines), 0, new))
            continue
        i = _seek(lines, old, at, c["eof"])
        if i is None and old[-1] == "":
            old, new = old[:-1], new[:-1] if new and new[-1] == "" else new
            keep = [(o, n) for o, n in keep if o < len(old) and n < len(new)]
            i = _seek(lines, old, at, c["eof"])
        if i is None:
            return None
        # context lines keep the file's own text (fuzzy matches may differ in whitespace/quotes)
        o0 = n0 = 0
        for o, n in keep + [(len(old), len(new))]:
            if (o, n) != (o0, n0) or o == len(old):
                reps.append((i + o0, o - o0, new[n0:n]))
            o0, n0 = o + 1, n + 1
        at = i + len(old)
    for start, length, repl in sorted(reps, key=lambda r: r[0], reverse=True):
        lines[start:start + length] = repl
    return "\n".join(lines) + "\n"


def _patch_edits(patch, cwd=None):
    """[(tool, tool_input)] Write calls equivalent to a Codex apply_patch patch.

    Mirrors codex-rs/apply-patch (parser + seek_sequence) so the patch can't put a
    dependency anywhere other than where we look. Content None = Codex would reject it.
    """
    files, cur, mode = [], None, "start"
    for ln in patch.strip().split("\n"):
        ln = ln[:-1] if ln.endswith("\r") else ln
        head = ln.rstrip() if mode == "update" else ln.strip()  # Codex trims less inside updates
        m = re.match(r"^\*\*\* (Add|Delete|Update) File: (.*)$", head)
        if mode in ("start", "end") and head == "*** Begin Patch":
            mode = "files"
        elif head == "*** End Patch" and mode != "start":
            mode = "end"
        elif m and mode not in ("start", "end"):
            cur = {"op": m.group(1), "path": m.group(2), "move": None, "add": [], "chunks": []}
            files.append(cur)
            mode = {"Add": "add", "Delete": "files", "Update": "update"}[m.group(1)]
        elif mode == "add" and ln.startswith("+"):
            cur["add"].append(ln[1:])
        elif mode == "update":
            chunks = cur["chunks"]
            if head.startswith("*** Move to: ") and not chunks and cur["move"] is None:
                cur["move"] = head[13:]
            elif head == "@@" or head.startswith("@@ "):
                chunks.append({"ctx": head[3:] if head != "@@" else None, "old": [], "new": [],
                               "keep": [], "eof": False})
            elif head == "*** End of File" and chunks:
                chunks[-1]["eof"] = True
            elif ln[:1] in ("", " ", "+", "-"):
                if not chunks:
                    chunks.append({"ctx": None, "old": [], "new": [], "keep": [], "eof": False})
                c, tag, body = chunks[-1], ln[:1] or " ", ln[1:]
                if tag == " ":
                    c["keep"].append((len(c["old"]), len(c["new"])))
                if tag in " -":
                    c["old"].append(body)
                if tag in " +":
                    c["new"].append(body)
    out, state = [], {}  # later hunks see earlier ones' results, as when Codex applies them in order

    def resolve(p):
        return os.path.join(cwd or ".", p)  # not normpath: `symlink/..` isn't the parent dir
    for f in files:
        src = resolve(f["path"])
        if f["op"] == "Delete":
            state[src] = ""
            continue
        if f["op"] == "Add":
            text = "".join(a + "\n" for a in f["add"])
        else:
            old = state[src] if src in state else _read(src)
            text = None if old is None else _apply_chunks(old, f["chunks"])
        dest = resolve(f["move"]) if f.get("move") else src
        state[dest] = text or ""
        out.append(("Write", {"file_path": dest, "content": text}))
    return out


# Gemini CLI tool names -> the Claude Code tool with the same arguments
GEMINI_TOOLS = {"run_shell_command": "Bash", "write_file": "Write", "replace": "Edit"}


def _deny(msg, payload):
    """Deny JSON in the dialect of whichever agent sent `payload`."""
    if payload.get("hook_event_name") == "BeforeTool":  # Gemini CLI
        return {"decision": "deny", "reason": msg}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": msg}}


def hook_output(payload):
    """Map a PreToolUse / BeforeTool payload to the deny JSON (or None to allow)."""
    tool, inp, cwd = payload.get("tool_name"), payload.get("tool_input") or {}, payload.get("cwd")
    if payload.get("hook_event_name") == "BeforeTool":
        tool = GEMINI_TOOLS.get(tool)
        if inp.get("dir_path"):
            cwd = os.path.join(cwd or ".", inp["dir_path"])
        if inp.get("allow_multiple"):
            inp = dict(inp, replace_all=True)
    cache_dir = os.path.dirname(CACHE_FILE or "") or None
    edits = None
    if tool in ("Write", "Edit", "MultiEdit"):
        edits = [(tool, inp)]
    elif tool == "apply_patch":  # Codex: {"command": "*** Begin Patch ..."}
        edits = _patch_edits(str(inp.get("command", "")), cwd)
    if edits is not None:
        reasons, what = [], "dependency edit"
        for t, i in edits:
            target = os.path.realpath(os.path.join(cwd or ".", i.get("file_path", "")))
            if cache_dir and target.startswith(os.path.realpath(cache_dir) + os.sep):
                reasons.append("%s is pkg-guard's cache; writing it would skip the checks." % target)
            else:
                reasons += check_edit(t, i, cwd)
    elif tool == "Bash":
        cmd = inp.get("command", "")
        if isinstance(cmd, list):  # Codex may send argv, e.g. ["bash", "-lc", "..."]
            cmd = " ".join(shlex.quote(str(a)) for a in cmd)
        reasons, what = check_command(cmd, cwd), "install"
        raw = "\n".join(map(str, inp["command"])) if isinstance(inp.get("command"), list) else cmd
        for m in re.finditer(r"\*\*\* Begin Patch", raw):  # apply_patch run through the shell
            line = raw[:m.start()].rstrip("\n").rsplit("\n", 1)[-1]
            cd = re.search(r"\bcd\s+(['\"]?)([^'\"\s]+)\1\s*&&\s*apply_patch\b", line)
            wd = os.path.join(cwd or ".", cd.group(2)) if cd else cwd
            end = raw.find("*** End Patch", m.start())
            patch = raw[m.start():] if end < 0 else raw[m.start():end + len("*** End Patch")]
            reasons += [r for t, i in _patch_edits(patch, wd) for r in check_edit(t, i, wd)]
        # ponytail: substring match; a determined agent can still reach the file indirectly
        if CACHE_FILE and os.path.basename(CACHE_FILE) in cmd:
            reasons.append("the command touches pkg-guard's cache (%s)." % CACHE_FILE)
    else:
        return None
    if not reasons:
        return None
    msg = ("pkg-guard blocked this %s:\n- " % what + "\n- ".join(reasons) +
           "\nUse a well-known package or the stdlib. If the user confirms the package is "
           "legitimate, they can add it to PKG_GUARD_ALLOW.")
    return _deny(msg, payload)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["hook"]:
        try:
            payload = json.load(sys.stdin)
        except ValueError:
            return 0
        try:
            out = hook_output(payload)
        except Exception as e:  # a crashing hook lets the tool call through; deny instead
            out = _deny("pkg-guard internal error: %r" % e, payload if isinstance(payload, dict) else {})
        if out:
            print(json.dumps(out))
        return 0
    if argv[:1] == ["check"] and len(argv) > 1:
        reasons = check_command(" ".join(argv[1:]))
        for r in reasons:
            print("BLOCK " + r)
        return 1 if reasons else 0
    if argv[:1] == ["scan"]:
        paths = argv[1:] or [f for f in LOCKFILES if os.path.exists(f)]
        if not paths:
            print("pkg-guard: no lockfile here (%s)" % ", ".join(LOCKFILES), file=sys.stderr)
            return 2
        reasons = scan(paths)
        for r in reasons:
            print("BLOCK " + r)
        return 1 if reasons else 0
    if argv[:1] == ["--version"]:
        print(__version__)
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


GENERATED_POPULAR = {  # by scripts/gen_popular.py on 2026-10-11; do not edit by hand
    "npm": """
        @adobe/css-tools @alloc/quick-lru @aws-sdk/client-sso @aws-sdk/core
        @aws-sdk/credential-provider-env @aws-sdk/credential-provider-http
        @aws-sdk/credential-provider-ini @aws-sdk/credential-provider-node
        @aws-sdk/credential-provider-process @aws-sdk/credential-provider-web-identity
        @aws-sdk/middleware-host-header @aws-sdk/middleware-logger
        @aws-sdk/middleware-recursion-detection @aws-sdk/middleware-user-agent
        @aws-sdk/nested-clients @aws-sdk/region-config-resolver @aws-sdk/token-providers
        @aws-sdk/types @aws-sdk/util-endpoints @aws-sdk/util-user-agent-browser
        @aws-sdk/util-user-agent-node @aws-sdk/xml-builder @babel/code-frame @babel/compat-data
        @babel/core @babel/generator @babel/helper-annotate-as-pure
        @babel/helper-compilation-targets @babel/helper-create-class-features-plugin
        @babel/helper-define-polyfill-provider @babel/helper-globals
        @babel/helper-member-expression-to-functions @babel/helper-module-imports
        @babel/helper-module-transforms @babel/helper-optimise-call-expression
        @babel/helper-plugin-utils @babel/helper-replace-supers @babel/helper-string-parser
        @babel/helper-validator-identifier @babel/helper-validator-option @babel/helpers
        @babel/parser @babel/plugin-syntax-import-attributes @babel/plugin-syntax-json-strings
        @babel/plugin-syntax-jsx @babel/plugin-syntax-logical-assignment-operators
        @babel/plugin-syntax-nullish-coalescing-operator @babel/plugin-syntax-numeric-separator
        @babel/plugin-syntax-object-rest-spread @babel/plugin-syntax-optional-catch-binding
        @babel/plugin-syntax-top-level-await @babel/plugin-syntax-typescript
        @babel/plugin-transform-block-scoping @babel/plugin-transform-classes
        @babel/plugin-transform-computed-properties @babel/plugin-transform-for-of
        @babel/plugin-transform-modules-commonjs @babel/plugin-transform-parameters
        @babel/plugin-transform-react-jsx-source @babel/plugin-transform-spread @babel/runtime
        @babel/template @babel/traverse @babel/types @bcoe/v8-coverage @colors/colors
        @csstools/color-helpers @csstools/css-calc @csstools/css-parser-algorithms
        @csstools/css-tokenizer @emnapi/core @emnapi/runtime @emnapi/wasi-threads
        @esbuild/linux-x64 @eslint-community/eslint-utils @eslint-community/regexpp
        @eslint/config-array @eslint/config-helpers @eslint/core @eslint/eslintrc @eslint/js
        @eslint/object-schema @eslint/plugin-kit @floating-ui/core @floating-ui/dom
        @floating-ui/react-dom @floating-ui/utils @hookform/resolvers @humanfs/core
        @humanfs/node @humanwhocodes/retry @img/sharp-libvips-linuxmusl-x64 @img/sharp-linux-x64
        @img/sharp-linuxmusl-x64 @inquirer/type @isaacs/cliui @istanbuljs/schema @jest/console
        @jest/environment @jest/expect-utils @jest/fake-timers @jest/globals @jest/reporters
        @jest/schemas @jest/source-map @jest/test-result @jest/transform @jest/types
        @jridgewell/gen-mapping @jridgewell/remapping @jridgewell/resolve-uri
        @jridgewell/sourcemap-codec @jridgewell/trace-mapping @napi-rs/wasm-runtime
        @noble/hashes @nodelib/fs.scandir @nodelib/fs.stat @nodelib/fs.walk
        @octokit/openapi-types @octokit/types @openai/codex @opentelemetry/api
        @opentelemetry/api-logs @opentelemetry/core @opentelemetry/instrumentation
        @opentelemetry/resources @opentelemetry/sdk-metrics @opentelemetry/sdk-trace-base
        @opentelemetry/semantic-conventions @pkgjs/parseargs @pkgr/core @protobufjs/aspromise
        @protobufjs/codegen @protobufjs/eventemitter @protobufjs/fetch @protobufjs/inquire
        @protobufjs/pool @protobufjs/utf8 @radix-ui/number @radix-ui/primitive
        @radix-ui/react-arrow @radix-ui/react-avatar @radix-ui/react-collapsible
        @radix-ui/react-collection @radix-ui/react-compose-refs @radix-ui/react-context
        @radix-ui/react-dialog @radix-ui/react-direction @radix-ui/react-dismissable-layer
        @radix-ui/react-dropdown-menu @radix-ui/react-focus-guards @radix-ui/react-focus-scope
        @radix-ui/react-id @radix-ui/react-label @radix-ui/react-menu @radix-ui/react-popover
        @radix-ui/react-popper @radix-ui/react-portal @radix-ui/react-presence
        @radix-ui/react-primitive @radix-ui/react-progress @radix-ui/react-roving-focus
        @radix-ui/react-scroll-area @radix-ui/react-select @radix-ui/react-separator
        @radix-ui/react-tabs @radix-ui/react-toggle @radix-ui/react-tooltip
        @radix-ui/react-use-callback-ref @radix-ui/react-use-controllable-state
        @radix-ui/react-use-escape-keydown @radix-ui/react-use-layout-effect
        @radix-ui/react-use-previous @radix-ui/react-use-size @radix-ui/react-visually-hidden
        @radix-ui/rect @rolldown/pluginutils @rollup/pluginutils @rollup/rollup-linux-x64-gnu
        @rollup/rollup-linux-x64-musl @sinclair/typebox @sindresorhus/is @sinonjs/commons
        @sinonjs/fake-timers @smithy/config-resolver @smithy/core
        @smithy/credential-provider-imds @smithy/fetch-http-handler @smithy/hash-node
        @smithy/is-array-buffer @smithy/middleware-endpoint @smithy/middleware-retry
        @smithy/middleware-serde @smithy/middleware-stack @smithy/node-config-provider
        @smithy/property-provider @smithy/protocol-http @smithy/querystring-builder
        @smithy/querystring-parser @smithy/service-error-classification
        @smithy/shared-ini-file-loader @smithy/signature-v4 @smithy/smithy-client @smithy/types
        @smithy/url-parser @smithy/util-base64 @smithy/util-body-length-browser
        @smithy/util-buffer-from @smithy/util-defaults-mode-browser
        @smithy/util-defaults-mode-node @smithy/util-endpoints @smithy/util-hex-encoding
        @smithy/util-middleware @smithy/util-retry @smithy/util-stream @smithy/util-uri-escape
        @smithy/util-utf8 @swc/helpers @tailwindcss/node @tailwindcss/oxide
        @tailwindcss/oxide-linux-x64-gnu @tailwindcss/oxide-linux-x64-musl @tanstack/query-core
        @tanstack/react-query @testing-library/dom @testing-library/jest-dom @tootallnate/once
        @types/babel__core @types/babel__generator @types/babel__template @types/body-parser
        @types/chai @types/d3-array @types/d3-color @types/d3-ease @types/d3-interpolate
        @types/d3-path @types/d3-shape @types/d3-time @types/d3-timer @types/deep-eql
        @types/estree @types/express @types/express-serve-static-core @types/hast
        @types/istanbul-lib-coverage @types/istanbul-lib-report @types/istanbul-reports
        @types/json-schema @types/json5 @types/lodash @types/mdast @types/ms @types/node
        @types/prop-types @types/qs @types/range-parser @types/react @types/react-dom
        @types/send @types/serve-static @types/stack-utils @types/unist @types/ws @types/yargs
        @types/yargs-parser @typescript-eslint/eslint-plugin @typescript-eslint/parser
        @typescript-eslint/project-service @typescript-eslint/scope-manager
        @typescript-eslint/tsconfig-utils @typescript-eslint/type-utils @typescript-eslint/types
        @typescript-eslint/typescript-estree @typescript-eslint/utils
        @typescript-eslint/visitor-keys @ungap/structured-clone @vitest/expect @vitest/mocker
        @vitest/pretty-format @vitest/runner @vitest/snapshot @vitest/spy @vitest/utils abbrev
        abort-controller accepts acorn acorn-jsx acorn-walk agent-base aggregate-error ajv
        ajv-formats ajv-keywords ansi-colors ansi-escapes ansi-regex ansi-styles any-promise
        anymatch arg argparse aria-hidden aria-query array-buffer-byte-length array-flatten
        array-includes array-union array.prototype.findlastindex array.prototype.flat
        array.prototype.flatmap arraybuffer.prototype.slice arrify assertion-error ast-types
        async async-function asynckit autoprefixer available-typed-arrays axios axobject-query
        babel-jest babel-plugin-istanbul babel-plugin-jest-hoist babel-plugin-polyfill-corejs3
        babel-preset-jest balanced-match base64-js baseline-browser-mapping binary-extensions bl
        bluebird bn.js body-parser boolbase brace-expansion braces browserslist bser buffer
        buffer-crc32 buffer-from bytes cacache call-bind call-bind-apply-helpers call-bound
        callsites camelcase camelcase-css caniuse-lite chai chalk char-regex chardet chokidar
        chownr ci-info cjs-module-lexer class-variance-authority clean-stack cli-cursor
        cli-spinners cli-truncate cli-width cliui clone clsx color color-convert color-name
        color-string colorette combined-stream commander concat-map content-disposition
        content-type convert-source-map cookie cookie-signature core-js core-js-compat
        core-util-is cors cosmiconfig cross-spawn css-select css-tree css-what cssesc cssom
        cssstyle csstype d3-array d3-color d3-ease d3-format d3-interpolate d3-path d3-scale
        d3-shape d3-time d3-time-format d3-timer data-uri-to-buffer data-urls data-view-buffer
        data-view-byte-length data-view-byte-offset date-fns dayjs debug decamelize decimal.js
        decimal.js-light decompress-response dedent deep-eql deep-is deepmerge
        define-data-property define-lazy-prop define-properties define-property delayed-stream
        depd dequal destroy detect-libc detect-node-es didyoumean diff diff-sequences dir-glob
        dlv doctrine dom-accessibility-api dom-helpers dom-serializer domelementtype domhandler
        domutils dotenv dunder-proto eastasianwidth ecdsa-sig-formatter ee-first
        electron-to-chromium emoji-regex encodeurl end-of-stream enhanced-resolve entities
        env-paths error-ex es-abstract es-define-property es-errors es-module-lexer
        es-object-atoms es-set-tostringtag es-shim-unscopables es-to-primitive esbuild escalade
        escape-html escape-string-regexp escodegen eslint eslint-config-prettier
        eslint-import-resolver-node eslint-module-utils eslint-plugin-import eslint-plugin-react
        eslint-scope eslint-visitor-keys espree esprima esquery esrecurse estraverse
        estree-walker esutils etag event-target-shim eventemitter3 events execa expect
        expect-type express extend extend-shallow fast-deep-equal fast-equals fast-glob
        fast-json-stable-stringify fast-levenshtein fast-uri fast-xml-parser fastq fb-watchman
        fdir fflate figures file-entry-cache file-type fill-range finalhandler find-cache-dir
        find-up flat-cache flatted follow-redirects for-each foreground-child form-data
        forwarded fraction.js fresh fs-extra fs.realpath function-bind function.prototype.name
        functions-have-names gaxios gcp-metadata gensync get-caller-file get-east-asian-width
        get-intrinsic get-nonce get-package-type get-proto get-stream get-symbol-description
        get-tsconfig glob glob-parent glob-to-regexp globals globalthis globby
        google-auth-library google-logging-utils gopd graceful-fs graphemer has-bigints has-flag
        has-property-descriptors has-proto has-symbols has-tostringtag hasown hosted-git-info
        html-encoding-sniffer html-escaper htmlparser2 http-cache-semantics http-errors
        http-proxy-agent https-proxy-agent human-signals iconv-lite ieee754 ignore immediate
        immer import-fresh import-in-the-middle import-local imurmurhash indent-string inflight
        inherits ini inquirer internal-slot internmap ip-address ipaddr.js is-array-buffer
        is-arrayish is-async-function is-bigint is-binary-path is-boolean-object is-buffer
        is-callable is-core-module is-data-view is-date-object is-descriptor is-docker
        is-extendable is-extglob is-finalizationregistry is-fullwidth-code-point
        is-generator-function is-glob is-interactive is-map is-negative-zero is-number
        is-number-object is-obj is-path-inside is-plain-obj is-plain-object
        is-potential-custom-element-name is-promise is-regex is-set is-shared-array-buffer
        is-stream is-string is-symbol is-typed-array is-unicode-supported is-weakmap is-weakref
        is-weakset is-wsl isarray isexe isobject istanbul-lib-coverage istanbul-lib-instrument
        istanbul-lib-report istanbul-lib-source-maps istanbul-reports jackspeak jest
        jest-changed-files jest-circus jest-cli jest-diff jest-docblock jest-environment-node
        jest-get-type jest-haste-map jest-leak-detector jest-matcher-utils jest-message-util
        jest-mock jest-regex-util jest-resolve jest-resolve-dependencies jest-runner
        jest-runtime jest-snapshot jest-util jest-validate jest-watcher jest-worker jiti jose
        js-tokens js-yaml jsdom jsesc json-buffer json-parse-even-better-errors
        json-schema-traverse json-stable-stringify-without-jsonify json5 jsonfile jsonwebtoken
        jwa jws keyv kind-of kleur leven levn lie lightningcss lightningcss-linux-x64-gnu
        lightningcss-linux-x64-musl lilconfig lines-and-columns loader-utils locate-path lodash
        lodash.isplainobject lodash.merge log-symbols long loose-envify loupe lru-cache
        lz-string magic-string make-dir make-error make-fetch-happen math-intrinsics mdn-data
        media-typer merge-descriptors merge-stream merge2 methods micromark-util-character
        micromark-util-symbol micromark-util-types micromatch mime mime-db mime-types mimic-fn
        mimic-response min-indent minimatch minimist minipass minizlib mkdirp ms mute-stream mz
        nanoid natural-compare negotiator neo-async node-addon-api node-fetch node-gyp
        node-int64 node-releases nopt normalize-package-data normalize-path normalize-url
        npm-run-path nth-check nwsapi object-assign object-hash object-inspect object-keys
        object.assign object.entries object.fromentries object.values on-finished once onetime
        open optionator ora own-keys p-limit p-locate p-map p-try package-json-from-dist pako
        parent-module parse-json parse5 parseurl path-exists path-is-absolute path-key
        path-parse path-scurry path-to-regexp path-type pathe pathval picocolors picomatch pify
        pirates pkg-dir pnpm possible-typed-array-names postcss postcss-import postcss-js
        postcss-load-config postcss-nested postcss-selector-parser postcss-value-parser
        prelude-ls prettier pretty-format proc-log process process-nextick-args progress prompts
        prop-types protobufjs proxy-addr proxy-from-env psl pump punycode pure-rand qs
        queue-microtask range-parser raw-body react react-dom react-hook-form react-is
        react-remove-scroll react-remove-scroll-bar react-transition-group read-cache read-pkg
        readable-stream readdirp recharts redent reflect.getprototypeof regenerator-runtime
        regexp.prototype.flags regexpu-core regjsparser require-directory require-from-string
        requires-port resolve resolve-cwd resolve-from resolve-pkg-maps restore-cursor retry
        reusify rfdc rimraf rollup run-parallel rxjs safe-array-concat safe-buffer
        safe-push-apply safe-regex-test safe-stable-stringify safer-buffer sax saxes scheduler
        schema-utils semver send serialize-javascript serve-static set-function-length
        set-function-name set-proto setimmediate setprototypeof sharp shebang-command
        shebang-regex shell-quote side-channel side-channel-list side-channel-map
        side-channel-weakmap siginfo signal-exit sisteransi slash slice-ansi smart-buffer socks
        socks-proxy-agent source-map source-map-js source-map-support spdx-expression-parse
        split2 sprintf-js ssri stack-utils statuses std-env stop-iteration-iterator
        string-length string-width string.prototype.matchall string.prototype.trim
        string.prototype.trimend string.prototype.trimstart string_decoder strip-ansi strip-bom
        strip-final-newline strip-indent strip-json-comments strnum sucrase supports-color
        supports-preserve-symlinks-flag symbol-tree synckit tailwindcss tapable tar tar-fs
        tar-stream terser terser-webpack-plugin test-exclude thenify thenify-all through
        through2 tiny-invariant tinybench tinyexec tinyglobby tinyrainbow tldts-core tmp
        to-regex-range toidentifier tough-cookie tr46 ts-api-utils ts-interface-checker ts-node
        tsconfig-paths tslib tsx type-check type-detect type-fest type-is typed-array-buffer
        typed-array-byte-length typed-array-byte-offset typed-array-length typescript
        typescript-eslint uglify-js unbox-primitive undici-types unique-filename unist-util-is
        unist-util-stringify-position unist-util-visit unist-util-visit-parents universalify
        unpipe unplugin update-browserslist-db uri-js util util-deprecate utils-merge uuid vary
        victory-vendor vite vitest w3c-xmlserializer watchpack web-streams-polyfill
        webidl-conversions webpack webpack-sources webpack-virtual-modules whatwg-encoding
        whatwg-mimetype whatwg-url which which-boxed-primitive which-builtin-type
        which-collection which-typed-array why-is-node-running word-wrap wordwrap wrap-ansi
        wrappy write-file-atomic ws xml-name-validator xmlbuilder xmlchars xtend y18n yallist
        yaml yargs yargs-parser yocto-queue zod zod-to-json-schema""",
    "pypi": """
        absl-py accelerate adal aenum agate agent-client-protocol aioboto3 aiobotocore aiodns
        aiofile aiofiles aiohappyeyeballs aiohttp aiohttp-retry aioitertools aiosignal aiosqlite
        alabaster alembic altair amazon-ion amqp annotated-doc annotated-types ansicolors
        anthropic antlr4-python3-runtime anyio apache-airflow-providers-common-sql appdirs
        apscheduler argcomplete argon2-cffi argon2-cffi-bindings arrow asgiref asn1crypto
        ast-serialize astroid asttokens async-lru async-timeout asyncpg attrs authlib av
        aws-cdk-asset-awscli-v1 aws-lambda-powertools aws-requests-auth aws-xray-sdk awscli
        awscrt awswrangler azure-common azure-core azure-cosmos azure-identity
        azure-keyvault-keys azure-keyvault-secrets azure-mgmt-core
        azure-monitor-opentelemetry-exporter azure-servicebus azure-storage-blob
        azure-storage-file-datalake azure-storage-queue babel backoff backports-tarfile
        backports-zstd bandit basedpyright bcrypt beartype beautifulsoup4 bidict billiard
        bitarray black blake3 bleach blinker blis boltons boolean-py boto3 boto3-stubs botocore
        botocore-stubs bracex brotli bs4 build bytecode cachecontrol cached-property cachetools
        caio catalogue cattrs cbor2 cchardet celery certifi cffi cfgv chardet charset-normalizer
        claude-agent-sdk cleo click click-didyoumean click-option-group click-plugins click-repl
        clickhouse-connect cloudpathlib cloudpickle cobble colorama coloredlogs colorlog comm
        confection configargparse confluent-kafka contourpy coverage cramjam crashtest crc32c
        cron-descriptor croniter cryptography cssselect cssselect2 cuda-bindings cuda-pathfinder
        cuda-toolkit curl-cffi cycler cyclonedx-python-lib cyclopts cymem cython dacite daff
        dask dask-expr databricks-labs-blueprint databricks-sdk databricks-sql-connector
        dataclasses-json datadog datadog-api-client datamodel-code-generator datasets dateparser
        db-dtypes dbt-adapters dbt-common dbt-core dbt-extractor dbt-protos ddtrace debugpy
        decorator deepdiff defusedxml delta-spark deprecated deprecation deptry diff-cover dill
        diskcache distlib distro django django-cors-headers django-filter djangorestframework
        dnspython docker docopt docstring-parser docutils duckdb dulwich dunamai durationpy
        ecdsa editables einops elastic-transport elasticsearch email-validator emoji entrypoints
        envier et-xmlfile eval-type-backport events exceptiongroup execnet executing face
        factory-boy faker fakeredis fastapi fastapi-cli fastapi-cloud-cli fastar fastavro
        fastcore fastjsonschema fastmcp fastmcp-slim fastspec fastuuid feedparser filelock
        filetype findpython fire firebase-admin flake8 flask flask-cors flask-login flatbuffers
        flit-core fonttools fpdf2 fqdn freezegun frozendict frozenlist fsspec ftfy future gcsfs
        genai-prices genson geopandas gevent ghapi gitdb gitpython glom google-ads
        google-api-core google-api-python-client google-auth google-auth-httplib2
        google-auth-oauthlib google-cloud-aiplatform google-cloud-appengine-logging
        google-cloud-audit-log google-cloud-bigquery google-cloud-bigquery-storage
        google-cloud-bigtable google-cloud-core google-cloud-firestore google-cloud-kms
        google-cloud-logging google-cloud-monitoring google-cloud-pubsub
        google-cloud-resource-manager google-cloud-secret-manager google-cloud-spanner
        google-cloud-speech google-cloud-storage google-cloud-tasks google-crc32c google-genai
        google-pasta google-re2 google-resumable-media googleapis-common-protos gql graphene
        graphql-core graphql-relay graphviz great-expectations greenlet gremlinpython griffe
        griffelib grimp groq grpc-google-iam-v1 grpc-interceptor grpcio grpcio-health-checking
        grpcio-status grpcio-tools grpclib gspread gunicorn h11 h2 h3 h5py hatch-vcs hatchling
        hf-xet hiredis holidays hpack html2text html5lib httpcore httpcore2 httplib2 httptools
        httpx httpx-sse httpx2 huey huggingface-hub humanfriendly humanize hvac hyperframe
        hyperlink hypothesis id identify idna ijson imageio imageio-ffmpeg imagesize
        immutabledict import-linter importlib-metadata importlib-resources incremental inflect
        inflection iniconfig inquirerpy installer invoke ipdb ipykernel ipython
        ipython-pygments-lexers ipywidgets isodate isoduration isort itsdangerous jaraco-classes
        jaraco-context jaraco-functools jedi jeepney jinja2 jira jiter jmespath joblib joserfc
        jpype1 json-repair json5 jsonconversion jsonlines jsonpatch jsonpath-ng jsonpath-python
        jsonpickle jsonpointer jsonref jsonschema jsonschema-path jsonschema-specifications
        jupyter-builder jupyter-client jupyter-core jupyter-events jupyter-lsp jupyter-server
        jupyter-server-terminals jupyterlab jupyterlab-pygments jupyterlab-server
        jupyterlab-widgets jwcrypto kafka-python keyring kiwisolver kombu kubernetes langchain
        langchain-anthropic langchain-classic langchain-community langchain-core
        langchain-google-genai langchain-google-vertexai langchain-openai langchain-protocol
        langchain-text-splitters langcodes langfuse langgraph langgraph-checkpoint
        langgraph-prebuilt langgraph-sdk langsmith lark lazy-loader lazy-object-proxy ldap3
        leather levenshtein libcst librt license-expression lightgbm limits linkify-it-py
        litellm llvmlite locket lockfile logfire-api loguru lupa lxml lxml-html-clean lz4 magika
        makefun mako mammoth markdown markdown-it-py markdownify markitdown markupsafe
        marshmallow mashumaro matplotlib matplotlib-inline maturin maxminddb mccabe mcp
        mcp-types mdit-py-plugins mdurl mergedeep mistralai mistune ml-dtypes mlflow
        mlflow-skinny mlflow-tracing mmh3 mock modal more-itertools moto mpmath msal
        msal-extensions msgpack msgspec msrest msrestazure multidict multiprocess multitasking
        murmurhash mypy mypy-boto3-s3 mypy-extensions mysql-connector-python mysqlclient
        narwhals natsort nbclient nbconvert nbformat nest-asyncio nest-asyncio2 networkx
        nexus-rpc nh3 ninja nltk nodeenv nodejs-wheel-binaries notebook notebook-shim numba
        numpy nvidia-cublas nvidia-cublas-cu12 nvidia-cuda-cupti nvidia-cuda-cupti-cu12
        nvidia-cuda-nvrtc nvidia-cuda-nvrtc-cu12 nvidia-cuda-runtime nvidia-cuda-runtime-cu12
        nvidia-cudnn-cu12 nvidia-cudnn-cu13 nvidia-cufft nvidia-cufft-cu12 nvidia-cufile
        nvidia-curand nvidia-curand-cu12 nvidia-cusolver nvidia-cusolver-cu12 nvidia-cusparse
        nvidia-cusparse-cu12 nvidia-cusparselt-cu13 nvidia-ml-py nvidia-nccl-cu12
        nvidia-nccl-cu13 nvidia-nvjitlink nvidia-nvjitlink-cu12 nvidia-nvshmem-cu13 nvidia-nvtx
        oauth2client oauthlib olefile omegaconf onnxruntime openai openapi-pydantic
        openapi-schema-validator openapi-spec-validator opencv-python opencv-python-headless
        openpyxl opensearch-py opentelemetry-api opentelemetry-distro
        opentelemetry-exporter-otlp opentelemetry-exporter-otlp-proto-common
        opentelemetry-exporter-otlp-proto-grpc opentelemetry-exporter-otlp-proto-http
        opentelemetry-exporter-prometheus opentelemetry-instrumentation
        opentelemetry-instrumentation-aiohttp-client opentelemetry-instrumentation-asgi
        opentelemetry-instrumentation-dbapi opentelemetry-instrumentation-django
        opentelemetry-instrumentation-fastapi opentelemetry-instrumentation-flask
        opentelemetry-instrumentation-grpc opentelemetry-instrumentation-httpx
        opentelemetry-instrumentation-logging opentelemetry-instrumentation-psycopg2
        opentelemetry-instrumentation-redis opentelemetry-instrumentation-requests
        opentelemetry-instrumentation-sqlalchemy opentelemetry-instrumentation-threading
        opentelemetry-instrumentation-urllib opentelemetry-instrumentation-urllib3
        opentelemetry-instrumentation-wsgi opentelemetry-proto
        opentelemetry-resourcedetector-gcp opentelemetry-sdk opentelemetry-semantic-conventions
        opentelemetry-semantic-conventions-ai opentelemetry-util-http opt-einsum optuna oracledb
        ordered-set orderly-set orjson ormsgpack oscrypto oss2 outcome overrides
        packageurl-python packaging pandas pandas-gbq pandas-stubs pandocfilters papermill
        paramiko parse parsedatetime parso partd passlib pathable pathlib-abc pathspec
        pathvalidate patsy pbr pbs-installer pdf2image pdfminer-six pdfplumber peewee pendulum
        pexpect pfzy pg8000 pgvector phonenumbers pillow pillow-heif pip pip-api pip-audit
        pip-requirements-parser pkginfo platformdirs playwright plotly pluggy ply poetry
        poetry-core poetry-plugin-export polars polars-runtime-32 portalocker postgrest posthog
        pre-commit prek preshed prettytable progressbar2 prometheus-client prompt-toolkit
        propcache proto-plus protobuf psutil psycopg psycopg-binary psycopg-pool psycopg2
        psycopg2-binary ptyprocess pure-eval puremagic py py-cpuinfo py-key-value-aio
        py-partiql-parser py-serializable py-spy py4j pyarrow pyarrow-hotfix pyasn1
        pyasn1-modules pyathena pybase64 pybind11 pybreaker pycares pycodestyle pycountry
        pycparser pycryptodome pycryptodomex pydantic pydantic-ai-slim pydantic-core
        pydantic-extra-types pydantic-graph pydantic-settings pydata-google-auth pydeck pydot
        pydub pydyf pyee pyflakes pygithub pygments pyiceberg pyjwt pylint pymdown-extensions
        pymongo pymssql pymupdf pymysql pynacl pyodbc pyopenssl pyotp pyparsing pypdf pypdf2
        pypdfium2 pyperclip pyphen pyproj pyproject-hooks pyright pyroaring pyrsistent pysocks
        pyspark pyspnego pytesseract pytest pytest-asyncio pytest-cov pytest-django pytest-env
        pytest-html pytest-httpx pytest-json-ctrf pytest-metadata pytest-mock pytest-randomly
        pytest-rerunfailures pytest-runner pytest-split pytest-timeout pytest-xdist
        python-dateutil python-discovery python-docx python-dotenv python-engineio
        python-http-client python-jose python-json-logger python-magic python-multipart
        python-pptx python-slugify python-socketio python-utils pytimeparse pytokens pytz
        pywavelets pywin32 pyyaml pyzmq qrcode questionary rapidfuzz ratelimit readme-renderer
        realtime redis redshift-connector referencing regex reportlab requests requests-aws4auth
        requests-file requests-mock requests-oauthlib requests-toolbelt requirements-parser
        resolvelib responses respx retry retrying rfc3339-validator rfc3986 rfc3986-validator
        rfc3987-syntax rich rich-argparse rich-click rich-rst rich-toolkit rignore rpds-py rsa
        ruamel-yaml ruamel-yaml-clib ruff s3fs s3transfer safetensors sagemaker schema
        scikit-image scikit-learn scipy scramp seaborn secretstorage selenium semantic-version
        semgrep semver send2trash sendgrid sentence-transformers sentencepiece sentry-sdk
        service-identity setproctitle setuptools setuptools-scm shapely shellingham shortuuid
        simple-salesforce simple-websocket simplejson six skops slack-sdk slowapi smart-open
        smmap sniffio snowballstemmer snowflake-connector-python snowflake-sqlalchemy
        snowplow-tracker socksio sortedcontainers sounddevice soundfile soupsieve spacy
        spacy-legacy spacy-loggers sphinx sphinxcontrib-applehelp sphinxcontrib-devhelp
        sphinxcontrib-htmlhelp sphinxcontrib-jsmath sphinxcontrib-qthelp
        sphinxcontrib-serializinghtml sqlalchemy sqlalchemy-utils sqlglot sqlmodel sqlparse
        srsly sse-starlette sshtunnel stack-data starlette statsmodels stevedore storage3
        strands-agents streamlit strenum strictyaml stripe structlog supabase supabase-auth
        supabase-functions swebench swifter sympy synchronicity tabulate tblib temporalio
        tenacity tensorboard termcolor terminado testcontainers text-unidecode texttable textual
        thinc threadpoolctl thrift tifffile tiktoken time-machine tinycss2 tinyhtml5 tld
        tldextract tokenizers toml tomli tomli-w tomlkit toolz torch torchvision tornado tox
        tqdm traitlets transformers tree-sitter tree-sitter-languages trino trio trio-websocket
        triton trove-classifiers truststore twilio twine twisted ty typedload typeguard typer
        typer-slim types-awscrt types-cachetools types-certifi types-cffi types-paramiko
        types-protobuf types-pyopenssl types-python-dateutil types-pytz types-pyyaml types-redis
        types-requests types-s3transfer types-setuptools types-toml types-urllib3
        typing-extensions typing-inspect typing-inspection tzdata tzlocal ua-parser
        ua-parser-builtins uc-micro-py ujson uncalled-for unidecode unidiff universal-pathlib
        uri-template uritemplate urllib3 uuid-utils uv uv-build uvicorn uvloop validators vcrpy
        vcs-versioning vine virtualenv vulture wandb wasabi watchdog watchfiles watchtower
        wcmatch wcwidth weasel weasyprint webcolors webencodings websocket-client websockets
        werkzeug wheel whitenoise widgetsnbextension wrapt wsproto xgboost xlrd xlsxwriter
        xmltodict xxhash yamllint yarl yfinance youtube-transcript-api zeep zipp zope-event
        zope-interface zopfli zstandard""",
    "crates": """
        Inflector actix-http actix-rt actix-web addr2line adler adler2 adler32 aead aes aes-gcm
        ahash aho-corasick aligned-vec alloc-no-stdlib alloc-stdlib allocator-api2
        android-tzdata android_system_properties anes ansi_term anstream anstyle anstyle-parse
        anstyle-query anstyle-wincon anyhow approx arbitrary arc-swap ark-ff ark-ff-asm
        ark-ff-macros ark-serialize ark-std arrayref arrayvec arrow arrow-arith arrow-array
        arrow-buffer arrow-cast arrow-data arrow-ipc arrow-ord arrow-row arrow-schema
        arrow-select arrow-string ascii asn1-rs asn1-rs-derive asn1-rs-impl assert-json-diff
        assert_cmd async-broadcast async-channel async-compression async-executor
        async-global-executor async-io async-lock async-process async-recursion async-signal
        async-std async-stream async-stream-impl async-task async-trait atoi atomic atomic-waker
        atty autocfg aws-config aws-credential-types aws-lc-rs aws-lc-sys aws-runtime aws-sdk-s3
        aws-sdk-sso aws-sdk-ssooidc aws-sdk-sts aws-sigv4 aws-smithy-async aws-smithy-checksums
        aws-smithy-eventstream aws-smithy-http aws-smithy-http-client aws-smithy-json
        aws-smithy-observability aws-smithy-query aws-smithy-runtime aws-smithy-runtime-api
        aws-smithy-types aws-smithy-xml aws-types axum axum-core axum-macros backoff backon
        backtrace base16ct base64 base64-simd base64ct bigdecimal bincode bindgen bit-set
        bit-vec bit_field bitflags bitvec blake2 blake3 block-buffer block-padding block2
        blocking borsh borsh-derive brotli brotli-decompressor bs58 bstr bumpalo bytecheck
        bytecheck_derive bytecount bytemuck bytemuck_derive byteorder byteorder-lite bytes
        bytes-utils bytesize bytestring bzip2 bzip2-sys camino cargo-platform cargo_metadata
        cast castaway cbc cbindgen cc cesu8 cexpr cfg-expr cfg-if cfg_aliases chacha20
        chacha20poly1305 chrono chrono-tz chrono-tz-build ciborium ciborium-io ciborium-ll
        cipher clang-sys clap clap_builder clap_complete clap_derive clap_lex cmake cmov
        codespan-reporting color_quant colorchoice colored combine comfy-table compact_str
        compression-codecs compression-core concurrent-queue config console const-oid
        const-random const-random-macro const_format const_format_proc_macros constant_time_eq
        convert_case cookie cookie_store core-foundation core-foundation-sys cpp_demangle
        cpufeatures crc crc-catalog crc32c crc32fast criterion criterion-plot critical-section
        crossbeam crossbeam-channel crossbeam-deque crossbeam-epoch crossbeam-queue
        crossbeam-utils crossterm crossterm_winapi crunchy crypto-bigint crypto-common
        crypto-mac cssparser csv csv-core ctor ctr ctrlc ctutils curve25519-dalek
        curve25519-dalek-derive darling darling_core darling_macro dashmap data-encoding
        deadpool deadpool-runtime debugid der der-parser deranged derivative derive_arbitrary
        derive_builder derive_builder_core derive_builder_macro derive_more derive_more-impl
        dialoguer diff difflib digest dirs dirs-next dirs-sys dirs-sys-next displaydoc dlv-list
        doc-comment document-features dotenvy downcast downcast-rs dtoa dtoa-short dunce
        dyn-clone ecdsa ed25519 ed25519-dalek educe either elliptic-curve embedded-io ena
        encode_unicode encoding_rs endian-type enum-as-inner enum-ordinalize
        enum-ordinalize-derive enum_dispatch enumflags2 enumflags2_derive env_filter env_logger
        equator equator-macro equivalent erased-serde errno etcetera event-listener
        event-listener-strategy eyre fallible-iterator fallible-streaming-iterator fancy-regex
        fastrand fdeflate ff fiat-crypto filetime find-msvc-tools fixedbitset flatbuffers flate2
        float-cmp fluent-uri flume fnv foldhash foreign-types foreign-types-shared
        form_urlencoded fraction fragile fs-err fs2 fs_extra fsevent-sys funty futures
        futures-channel futures-core futures-executor futures-intrusive futures-io futures-lite
        futures-macro futures-sink futures-task futures-timer futures-util fxhash generic-array
        gethostname getopts getrandom ghash gif gimli git2 glam glob globset globwalk
        gloo-timers governor group h2 half handlebars hash32 hashbrown hashlink hdrhistogram
        headers headers-core heapless heck hermit-abi hex hickory-proto hickory-resolver hkdf
        hmac home hostname html5ever http http-body http-body-util http-range-header httparse
        httpdate humantime hybrid-array hyper hyper-rustls hyper-timeout hyper-tls hyper-util
        iana-time-zone iana-time-zone-haiku icu_collections icu_locale_core icu_locid
        icu_locid_transform icu_locid_transform_data icu_normalizer icu_normalizer_data
        icu_properties icu_properties_data icu_provider icu_provider_macros id-arena ident_case
        idna idna_adapter ignore image image-webp indenter indexmap indicatif indoc infer
        inotify inotify-sys inout insta instant integer-encoding inventory io-lifetimes ipnet
        ipnetwork iri-string is-terminal is_terminal_polyfill itertools itoa jiff jiff-static
        jni jni-sys jobserver jpeg-decoder js-sys json-patch json5 jsonpath-rust jsonptr
        jsonschema jsonwebtoken k256 k8s-openapi keccak kv-log-macro lalrpop-util language-tags
        lazy_static lazycell leb128fmt lexical-core lexical-parse-float lexical-parse-integer
        lexical-util lexical-write-float lexical-write-integer libc libgit2-sys libloading libm
        libredox libsqlite3-sys libz-sys linked-hash-map linux-raw-sys litemap litrs lock_api
        log logos logos-derive lru lru-cache lru-slab lz4-sys lz4_flex maplit markup5ever
        match_cfg matchers matches matchit matrixmultiply md-5 md5 memchr memmap2 memoffset
        metrics metrics-util mime mime_guess minimal-lexical miniz_oxide mio mockall
        mockall_derive moka moxcms multer multimap nalgebra native-tls ndarray
        new_debug_unreachable nibble_vec nix nohash-hasher nom normalize-line-endings notify
        ntapi nu-ansi-term num num-bigint num-bigint-dig num-complex num-conv num-derive
        num-integer num-iter num-rational num-traits num_cpus num_enum num_enum_derive
        num_threads number_prefix objc2 objc2-core-foundation objc2-encode objc2-foundation
        object object_store oid-registry once_cell once_cell_polyfill oorandom opaque-debug
        openssl openssl-macros openssl-probe openssl-src openssl-sys opentelemetry
        opentelemetry-http opentelemetry-otlp opentelemetry-proto
        opentelemetry-semantic-conventions opentelemetry_sdk option-ext ordered-float
        ordered-multimap os_pipe os_str_bytes ouroboros ouroboros_macro outref overload
        owo-colors p256 p384 parking parking_lot parking_lot_core parquet parse-zoneinfo
        password-hash paste pastey pathdiff pbkdf2 peeking_take_while pem pem-rfc7468
        percent-encoding pest pest_derive pest_generator pest_meta petgraph phf phf_codegen
        phf_generator phf_macros phf_shared pin-project pin-project-internal pin-project-lite
        pin-utils piper pkcs1 pkcs8 pkg-config plain plotters plotters-backend plotters-svg png
        polling poly1305 polyval portable-atomic portable-atomic-util potential_utf powerfmt
        ppv-lite86 precomputed-hash predicates predicates-core predicates-tree pretty_assertions
        prettyplease primeorder proc-macro-crate proc-macro-error proc-macro-error-attr
        proc-macro-error-attr2 proc-macro-error2 proc-macro-hack proc-macro2
        proc-macro2-diagnostics procfs prometheus proptest prost prost-build prost-derive
        prost-reflect prost-types protobuf psm ptr_meta ptr_meta_derive pulldown-cmark pxfm pyo3
        pyo3-build-config pyo3-ffi pyo3-macros pyo3-macros-backend quanta quick-error quick-xml
        quinn quinn-proto quinn-udp quote r-efi radium radix_trie rand rand_chacha rand_core
        rand_distr rand_hc rand_pcg rand_xorshift rand_xoshiro raw-cpuid raw-window-handle
        rawpointer rayon rayon-core rcgen redis redox_syscall redox_users ref-cast ref-cast-impl
        regex regex-automata regex-lite regex-syntax relative-path remove_dir_all rend reqwest
        reqwest-middleware resolv-conf rfc6979 rgb ring rkyv rkyv_derive rmp rmp-serde ron
        roxmltree rsa rstest rstest_macros rusqlite rust-ini rust_decimal rustc-demangle
        rustc-hash rustc_version rusticata-macros rustix rustls rustls-native-certs
        rustls-pemfile rustls-pki-types rustls-platform-verifier rustls-webpki rustversion
        rusty-fork ryu salsa20 same-file scc schannel schemars schemars_derive scoped-tls
        scopeguard scroll sct sdd seahash sec1 secp256k1 secp256k1-sys secrecy
        security-framework security-framework-sys selectors semver semver-parser seq-macro serde
        serde-untagged serde-value serde-wasm-bindgen serde_bytes serde_cbor serde_core
        serde_derive serde_derive_internals serde_json serde_path_to_error serde_qs serde_repr
        serde_spanned serde_urlencoded serde_with serde_with_macros serde_yaml serial_test
        serial_test_derive sha-1 sha1 sha1_smol sha2 sha3 sharded-slab shell-words shlex
        signal-hook signal-hook-mio signal-hook-registry signature simd-adler32 simdutf8 similar
        simple_asn1 siphasher sketches-ddsketch slab slotmap smallvec smawk smol_str snafu
        snafu-derive snap socket2 spin spki sqlparser sqlx sqlx-core sqlx-macros
        sqlx-macros-core sqlx-mysql sqlx-postgres sqlx-sqlite stable_deref_trait stacker
        static_assertions string_cache string_cache_codegen stringprep strsim structopt
        structopt-derive strum strum_macros subtle syn sync_wrapper synstructure sysinfo
        system-configuration system-configuration-sys tagptr take_mut tap tar target-lexicon
        tempfile tendril term termcolor terminal_size termtree textwrap thiserror thiserror-impl
        thread_local threadpool thrift tiff tikv-jemalloc-sys tikv-jemallocator time time-core
        time-macros tiny-keccak tinystr tinytemplate tinyvec tinyvec_macros tokio
        tokio-io-timeout tokio-macros tokio-native-tls tokio-retry tokio-rustls tokio-stream
        tokio-test tokio-tungstenite tokio-util toml toml_datetime toml_edit toml_parser
        toml_write toml_writer tonic tonic-build tonic-prost tower tower-http tower-layer
        tower-service tracing tracing-appender tracing-attributes tracing-core tracing-futures
        tracing-log tracing-opentelemetry tracing-serde tracing-subscriber triomphe try-lock
        ttf-parser tungstenite twox-hash typed-arena typed-builder typed-builder-macro typeid
        typenum ucd-trie unarray unicase unicode-bidi unicode-ident unicode-linebreak
        unicode-normalization unicode-properties unicode-segmentation unicode-width unicode-xid
        unicode_categories unindent universal-hash unsafe-libyaml untrusted ureq ureq-proto url
        urlencoding utf-8 utf16_iter utf8_iter utf8parse uuid valuable value-bag vcpkg vec_map
        version-compare version_check void vsimd vte wait-timeout waker-fn walkdir want wasi
        wasip2 wasip3 wasite wasm-bindgen wasm-bindgen-backend wasm-bindgen-futures
        wasm-bindgen-macro wasm-bindgen-macro-support wasm-bindgen-shared wasm-encoder
        wasm-metadata wasm-streams wasmparser web-sys web-time webpki webpki-root-certs
        webpki-roots weezl which whoami widestring winapi winapi-i686-pc-windows-gnu winapi-util
        winapi-x86_64-pc-windows-gnu windows windows-collections windows-core windows-future
        windows-implement windows-interface windows-link windows-numerics windows-registry
        windows-result windows-strings windows-sys windows-targets windows-threading
        windows_aarch64_gnullvm windows_aarch64_msvc windows_i686_gnu windows_i686_gnullvm
        windows_i686_msvc windows_x86_64_gnu windows_x86_64_gnullvm windows_x86_64_msvc winnow
        winreg wiremock wit-bindgen wit-bindgen-core wit-bindgen-rt wit-bindgen-rust
        wit-bindgen-rust-macro wit-component wit-parser write16 writeable wyz x509-parser xattr
        xml-rs xmlparser xxhash-rust yaml-rust yansi yasna yoke yoke-derive zbus zbus_macros
        zbus_names zerocopy zerocopy-derive zerofrom zerofrom-derive zeroize zeroize_derive
        zerotrie zerovec zerovec-derive zip zlib-rs zmij zopfli zstd zstd-safe zstd-sys
        zune-core zune-jpeg zvariant zvariant_derive zvariant_utils""",
}
for _eco, _names in GENERATED_POPULAR.items():
    POPULAR[_eco] |= set(_names.split())


if __name__ == "__main__":
    sys.exit(main())
