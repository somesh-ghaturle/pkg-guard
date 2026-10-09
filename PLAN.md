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

## Detection rules

| Signal | Rule |
|---|---|
| Missing | registry 404 → deny, with "did you mean X?" from the popular list |
| Too new | first publish < `PKG_GUARD_MIN_AGE_DAYS` (default 30) → deny |
| Too few users | npm weekly < 100, crates 90-day < 100, gems total < 1000 → deny |
| Typosquat | 1 edit away from a popular package, not popular itself, and < 180 days old or low-ish downloads → deny |

Ecosystems: npm (npm/pnpm/yarn/bun, npx/bunx/dlx), PyPI (pip, uv, poetry, pipx, uvx),
crates.io (cargo), RubyGems (gem).

## Phases

1. **Core** — command parser, registry checks, typosquat check, `pkg-guard check "<cmd>"` CLI,
   offline unit tests (registry mocked).
2. **Hooks** — `pkg-guard hook` (stdin → deny JSON). Config snippets for Claude Code
   (`settings.json`) and Codex (`hooks.json` / `config.toml`). End-to-end test feeding a real payload.
3. **Skill + plugin** — `skills/pkg-guard/SKILL.md` (agent-agnostic: pick deps carefully,
   never guess names). Claude Code plugin + marketplace manifest so install is
   `/plugin marketplace add somesh-ghaturle/pkg-guard`.
4. **Ship** — README with demo, GitHub Actions CI (3.9 + 3.13), tag v0.1.0, flip repo public.

## Later (not v0.1)

- Gemini CLI adapter (different hook output format), Go modules.
- Install-script (`postinstall`) signal, maintainer-change signal.
- Result cache; lockfile / `requirements.txt` scanning; dependency-confusion check on custom indexes.
