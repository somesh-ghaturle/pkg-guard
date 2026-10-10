#!/usr/bin/env python3
"""pkg-guard: block hallucinated / typosquatted package installs by AI coding agents.

Usage:
  pkg_guard.py check "<shell command>"   exit 1 and print reasons if blocked
  pkg_guard.py hook                      PreToolUse hook (Claude Code, Codex): JSON on stdin
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

__version__ = "0.2.0"
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
    if eco == "go":
        return _go_info(name)
    raise ValueError(eco)


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


def _edited_text(tool, inp, old):
    """File content after a Write/Edit/MultiEdit, or None if the edit can't apply."""
    if tool == "Write":
        return inp.get("content", "")
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


def hook_output(payload):
    """Map a PreToolUse payload to the deny JSON (or None to allow)."""
    tool, inp = payload.get("tool_name"), payload.get("tool_input") or {}
    cache_dir = os.path.dirname(CACHE_FILE or "") or None
    if tool in ("Write", "Edit", "MultiEdit"):
        target = os.path.realpath(os.path.join(payload.get("cwd") or ".", inp.get("file_path", "")))
        if cache_dir and target.startswith(os.path.realpath(cache_dir) + os.sep):
            reasons = ["%s is pkg-guard's cache; writing it would skip the checks." % target]
        else:
            reasons = check_edit(tool, inp, payload.get("cwd"))
        what = "dependency edit"
    elif tool == "Bash":
        cmd = inp.get("command", "")
        if isinstance(cmd, list):  # Codex may send argv, e.g. ["bash", "-lc", "..."]
            cmd = " ".join(shlex.quote(str(a)) for a in cmd)
        reasons, what = check_command(cmd, payload.get("cwd")), "install"
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
        try:
            out = hook_output(payload)
        except Exception as e:  # a crashing hook lets the tool call through; deny instead
            out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                          "permissionDecisionReason": "pkg-guard internal error: %r" % e}}
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
