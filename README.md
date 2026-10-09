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

- **Works with** Claude Code and Codex. Both use the same hook protocol, and one script covers both.
- **Covers** npm, pnpm, yarn, bun, npx, pip, uv, uvx, poetry, pipx, cargo, and gem.
- **Single file, Python stdlib only.** The guard adds no dependencies of its own. Read it in five minutes.

## What gets blocked

| Signal | Rule |
|---|---|
| Doesn't exist | Registry returns 404. Suggests the popular name it resembles. |
| Too new | First published less than 30 days ago (`PKG_GUARD_MIN_AGE_DAYS`) |
| Too few users | npm: fewer than 100 weekly downloads. crates: fewer than 100 in 90 days. gems: fewer than 1,000 total. |
| Typosquat | One edit away from a popular package, and young or little-used |

It also catches the usual ways around a naive regex: `bash -lc "..."`, `$(...)`,
`sudo`/`env` wrappers, `npm isntall`, `npm i x@npm:evil`, `npx -p evil`,
`uvx --with evil`, and `pip install -r requirements.txt` (nested `-r` included).

In Claude Code it also checks file edits: dependencies the agent adds to
`package.json`, `requirements*.txt`, `pyproject.toml`, `Cargo.toml`, or `Gemfile`
are checked before the edit is written, so a later bare `npm install` can't sneak them in.

## Install

### Claude Code (plugin: hook + skill)

```
/plugin marketplace add somesh-ghaturle/pkg-guard
/plugin install pkg-guard@pkg-guard
```

### Codex

```bash
git clone https://github.com/somesh-ghaturle/pkg-guard ~/.pkg-guard
mkdir -p ~/.codex/skills && cp -r ~/.pkg-guard/skills/pkg-guard ~/.codex/skills/
```

Then add the hook to `~/.codex/config.toml`, or use [`examples/codex-hooks.json`](examples/codex-hooks.json) as `~/.codex/hooks.json`:

```toml
[[hooks.PreToolUse]]
matcher = "Bash"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "python3 ~/.pkg-guard/pkg_guard.py hook"
timeout = 20
```

### Claude Code without the plugin

Add [`examples/claude-settings.json`](examples/claude-settings.json) to `~/.claude/settings.json`, using your own path to the script.

### As a CLI

```bash
pipx install git+https://github.com/somesh-ghaturle/pkg-guard
pkg-guard check "npm install some-lib"   # exit 1 if blocked
```

## Configuration

| Env var | Effect |
|---|---|
| `PKG_GUARD_ALLOW=a,b` | Always allow these packages (internal or private names) |
| `PKG_GUARD_MIN_AGE_DAYS=30` | Minimum package age |
| `PKG_GUARD_FAIL_CLOSED=1` | Block when the registry can't be reached. The default is to allow and warn, so offline work keeps going. |

## Limits

pkg-guard is a heuristic guard, not a sandbox. It checks install commands and, in
Claude Code, manifest edits. It does not check imports, and in Codex it does not see
manifest edits made with `apply_patch`, and it does not see manifests changed by shell commands (`echo evil >> requirements.txt`). `pyproject.toml` and `Cargo.toml` edits are
only checked on Python 3.11+ (needs `tomllib`). Packages from custom indexes are
still checked against the public registry. Tarball and git URLs are not checked.

## Development

```bash
python3 -m unittest -v
```

MIT licensed.
