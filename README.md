# pkg-guard

AI coding agents sometimes install packages that don't exist. Attackers register
those hallucinated names, plus one-letter typos of popular packages, and wait
("slopsquatting"). **pkg-guard** is a hook that checks every install command your
agent runs and blocks the suspicious ones before they execute.

```
$ pkg-guard check "pip install reqeusts"
BLOCK reqeusts: does not exist on pypi (hallucinated name?). Did you mean 'requests'?

$ pkg-guard check "npm i lodahs"
BLOCK lodahs: looks like a typosquat of popular package 'lodash'.
```

The agent sees the reason and fixes its own command.

- **Works with** Claude Code, Codex, and Gemini CLI. One script speaks all three hook protocols.
- **Covers** npm, pnpm, yarn, bun, npx, pip, uv, uvx, poetry, pipx, cargo, gem, and go (`go get`, `go install`, `go run mod@v`).
- **Single file, Python stdlib only.** The guard adds no dependencies of its own. Read it in five minutes.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/somesh-ghaturle/pkg-guard/main/docs/architecture-dark.svg">
  <img alt="pkg-guard architecture: the agent's tool call goes through the hook adapter and parser to the package checks, which consult the pass cache, the popular lists and the public registries. The CLI's check and scan commands feed the same parser." src="https://raw.githubusercontent.com/somesh-ghaturle/pkg-guard/main/docs/architecture-light.svg">
</picture>

The interactive version (zoom, search, trace a path) is [`docs/architecture.html`](https://github.com/somesh-ghaturle/pkg-guard/blob/main/docs/architecture.html); download and open it in a browser.

## What gets blocked

| Signal | Rule |
|---|---|
| Doesn't exist | Registry returns 404. Suggests the popular name it resembles. |
| Too new | First published less than 30 days ago (`PKG_GUARD_MIN_AGE_DAYS`) |
| Too few users | npm: fewer than 100 weekly downloads. crates: fewer than 100 in 90 days. gems: fewer than 1,000 total. Go (GitHub/GitLab/Bitbucket): fewer than 10 repo stars, since Go publish times come from git commits and can be backdated. |
| Typosquat | One edit away from a popular package, and young or little-used |
| Install script (npm) | Latest version runs `preinstall`/`install`/`postinstall` code, and the package is young (< 180 days) or little-used (< 10,000 weekly downloads) |

It also catches the usual ways around a naive regex: `bash -lc "..."`, `$(...)`,
`sudo`/`env` wrappers, `npm isntall`, `npm i x@npm:evil`, `npx -p evil`,
`uvx --with evil`, and `pip install -r requirements.txt` (nested `-r` included).

It also checks file edits (Claude Code `Write`/`Edit`, Codex `apply_patch`, Gemini CLI `write_file`/`replace`): dependencies the agent adds to
`package.json`, `requirements*.txt`, `pyproject.toml`, `Cargo.toml`, `Gemfile`, or `go.mod`
are checked before the edit is written, so a later bare `npm install` can't sneak them in.

## Install

### Claude Code (plugin: hook + skill)

```
/plugin marketplace add somesh-ghaturle/pkg-guard
/plugin install pkg-guard@pkg-guard
```

### Codex

```bash
pipx install slopsquat-guard
```

Then add the hook to `~/.codex/config.toml`, or use [`examples/codex-hooks.json`](examples/codex-hooks.json) as `~/.codex/hooks.json`:

```toml
[[hooks.PreToolUse]]
matcher = "Bash|apply_patch"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "pkg-guard hook"
timeout = 20
```

Optionally give Codex the skill too, so it picks safer packages up front:
`git clone https://github.com/somesh-ghaturle/pkg-guard /tmp/pkg-guard && mkdir -p ~/.codex/skills && cp -r /tmp/pkg-guard/skills/pkg-guard ~/.codex/skills/`

### Gemini CLI (extension: hook + skill)

```bash
gemini extensions install https://github.com/somesh-ghaturle/pkg-guard
```

It checks `run_shell_command` plus `write_file`/`replace` edits to manifests. Without the extension: `pipx install slopsquat-guard`, then merge [`examples/gemini-settings.json`](examples/gemini-settings.json) into `~/.gemini/settings.json`.

### Claude Code without the plugin

Run `pipx install slopsquat-guard`, then add [`examples/claude-settings.json`](examples/claude-settings.json) to `~/.claude/settings.json`.

If an agent can't find `pkg-guard`, use the full path that `which pkg-guard` prints (pipx installs to `~/.local/bin`).

### As a CLI

```bash
pipx install slopsquat-guard             # the PyPI name; the command is pkg-guard
pkg-guard check "npm install some-lib"   # exit 1 if blocked
pkg-guard scan                           # check every package in ./package-lock.json, uv.lock, ...
```

The PyPI package is **`slopsquat-guard`**. `pkg-guard` on PyPI is a different, unrelated project.

`scan` reads `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry),
`pnpm-lock.yaml`, `uv.lock`, `poetry.lock`, `Cargo.lock` (the TOML ones need Python 3.11+),
`Gemfile.lock` and `go.sum`, skips git/path/workspace entries, and
applies the same rules to every registry package, transitive ones included. Use it once
when you add pkg-guard to an existing repo, or in CI.

## Configuration

| Env var | Effect |
|---|---|
| `PKG_GUARD_ALLOW=a,b` | Always allow these packages (internal or private names) |
| `PKG_GUARD_MIN_AGE_DAYS=30` | Minimum package age |
| `GOPRIVATE` / `GONOPROXY` | Go modules matching these globs are skipped, like `go` does (env vars only, not `go env -w`) |
| `XDG_CACHE_HOME` | Packages that pass are cached for 24h in `$XDG_CACHE_HOME/pkg-guard/pkg-guard-ok.json` (default `~/.cache`). Blocks are never cached. Delete the file to recheck everything. |
| `PKG_GUARD_FAIL_CLOSED=1` | Block when the registry can't be reached. The default is to allow and warn, so offline work keeps going. |

## Limits

pkg-guard catches agent **mistakes**: hallucinated names, typos, packages too new
to trust. It is not a sandbox against an agent that is trying to get around it. A
prompt-injected agent can still install through a variable (`P=npm; $P i x`), a script
file, or `python -c "import subprocess..."`. The command parser follows bash's quoting,
comments, heredocs and `$(...)` rules so ordinary commands can't hide an install by
accident, but no static check can see every way a shell can run code.

It is a heuristic guard, not a sandbox. It checks install commands and manifest edits made through the agent's edit tools. It does not check imports, and it does not see manifests changed by shell commands (`echo evil >> requirements.txt`). `pyproject.toml` and `Cargo.toml` edits are
only checked on Python 3.11+ (needs `tomllib`). Go modules on vanity domains (`go.uber.org/...`) get no star signal, and their age can be backdated. The pass cache is a convenience, not a security boundary: the hook refuses agent writes to it, but a determined agent could still reach it indirectly. Packages from custom indexes are
still checked against the public registry. Tarball and git URLs are not checked. Codex `apply_patch` patches are applied with a port of Codex's own matching rules; a patch Codex would reject is denied.

## Development

```bash
python3 -m unittest -v
python3 scripts/gen_popular.py   # refresh the top-1000 npm/PyPI/crates lists in pkg_guard.py
```

MIT licensed.
