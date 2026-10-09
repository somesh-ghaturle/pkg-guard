# pkg-guard plan

Goal: stop AI coding agents from installing packages that don't exist, are brand new,
have almost no users, or look like typosquats of popular packages.

## Design (fixed decisions)

- **One file, stdlib only**: `pkg_guard.py`, Python 3.9+. No deps, so the guard itself
  adds no supply-chain risk. Anyone can read the whole thing.
- **One hook script for both agents**: Claude Code and Codex both send
  `{"tool_name": "Bash", "tool_input": {"command": ...}}` on stdin and both accept
  `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
  "permissionDecisionReason": "..."}}`.
- **Fail open on network errors** (offline dev must keep working);
  `PKG_GUARD_FAIL_CLOSED=1` flips it.
- **Escape hatch**: `PKG_GUARD_ALLOW=pkg1,pkg2` (set by the human, in the agent's env).
- **Every new check ships with an offline test** (registry mocked) in `test_pkg_guard.py`.

## Detection rules

| Signal | Rule |
|---|---|
| Missing | registry 404 → deny, with "did you mean X?" from the popular list |
| Too new | first publish < `PKG_GUARD_MIN_AGE_DAYS` (default 30) → deny |
| Too few users | npm weekly < 100, crates 90-day < 100, gems total < 1000 → deny |
| Typosquat | 1 edit away from a popular package, not popular itself, and < 180 days old or low-ish downloads → deny |

## v0.1 — done

1. **Core** — command parser, registry checks, typosquat check, `pkg-guard check` CLI, offline tests. ✅
2. **Hooks** — `pkg-guard hook`, Claude Code + Codex config snippets, end-to-end CLI tests. ✅
3. **Skill + plugin** — `skills/pkg-guard/SKILL.md`, plugin + marketplace manifests. ✅
4. **Ship** — README, CI (3.9 + 3.13), tag `v0.1.0` ✅. Repo public: pending (owner flips it).

## v0.2 — close the remaining holes

Ordered by how much risk each one removes.

1. **Manifest edits** — the agent can skip `npm i evil` by writing `"evil": "^1"` into
   `package.json` and running bare `npm install`. Hook `Edit|Write|MultiEdit` (Claude) /
   `apply_patch` (Codex) on `package.json`, `requirements*.txt`, `pyproject.toml`,
   `Cargo.toml`, `Gemfile`: diff old vs new dependency names, check only the added ones.
   Update plugin hook matcher + example configs. ✅ (Claude Code; Codex `apply_patch`
   pending — need its PreToolUse payload shape first. TOML manifests need Python 3.11+.)
2. **Nested `-r` in requirements files** — follow includes (cycle-safe). ✅
3. **Go modules** — `go get x`, `go install x@v`. Existence via `proxy.golang.org/<mod>/@v/list`,
   age via `@latest` `Time`. No download counts; typosquat vs a small popular list.
4. **Result cache** — `~/.cache/pkg-guard/cache.json`, 24h TTL for "ok" results only
   (never cache blocks or failures, so a fixed name is rechecked). Cuts latency and rate limits.
5. **Release v0.2.0** — README/SKILL updates, bump version in `pkg_guard.py`,
   `pyproject.toml`, `plugin.json`; tag.

## v0.3 — better signals, more agents

1. **Gemini CLI adapter** — `pkg-guard hook --format gemini` (BeforeTool event, its own
   deny JSON). Example `settings.json`.
2. **Install-script signal (npm)** — latest version has `preinstall/install/postinstall`
   and the package is young or low-download → deny with that reason.
3. **Generated popular list** — script that pulls top-N names per registry into
   `popular.txt`-style data embedded in the file; improves typosquat recall.
4. **Release v0.3.0.**

## Maybe later (needs evidence it's worth it)

- Maintainer-change signal (npm `maintainers` diff between recent versions).
- Dependency-confusion check: package installed via custom `--index-url` also exists
  on the public registry under the same name.
- Lockfile scanning (`package-lock.json`, `uv.lock`) as a one-shot `pkg-guard scan` CLI.
