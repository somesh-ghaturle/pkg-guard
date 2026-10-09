---
name: pkg-guard
description: Use before adding, installing, or recommending any third-party package (npm, pip, uv, poetry, cargo, gem, go, npx, uvx), and whenever an install command was blocked by pkg-guard. Prevents installing hallucinated, brand-new, or typosquatted packages.
---

# Choosing dependencies safely

Package names you remember can be wrong. Attackers register commonly hallucinated
names ("slopsquatting") and one-letter typos of popular packages. Installing one
runs attacker code on the user's machine.

## Before any install

1. **Do you need a package?** Prefer the standard library or a dependency the
   project already has. Check the manifest (`package.json`, `pyproject.toml`,
   `requirements*.txt`, `Cargo.toml`, `Gemfile`) and the lockfile first.
2. **Never guess a name.** Only install a package whose exact name you have seen
   in this project, its docs, or the official docs of the library. If unsure,
   tell the user what you need and ask, or look it up before installing.
3. **Check spelling** against the well-known name (`requests`, not `request` on
   PyPI; `serde_json`, not `serde-json` for cargo add).
4. **Pin to what the project uses** — match the existing version style.

## Verify a command without running it

```bash
python3 /path/to/pkg_guard.py check "npm install some-lib"   # exit 1 = blocked, prints why
```

## When pkg-guard blocks an install

- **"does not exist"** — the name is wrong. Use the suggested name if one is
  given, otherwise find the real package. Do not retry with variations.
- **"first published N days ago" / "only N downloads"** — tell the user which
  package and why; pick an established alternative unless they confirm it.
- **"looks like a typosquat"** — almost certainly the wrong package. Switch to
  the popular one it resembles.
- Never try to bypass the guard (rewriting the command, piping through other
  tools, editing hook settings). If the user confirms the package is legitimate,
  they can add it to the `PKG_GUARD_ALLOW` environment variable themselves.
