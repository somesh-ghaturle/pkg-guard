#!/usr/bin/env python3
"""Regenerate the GENERATED_POPULAR block in pkg_guard.py from registry top-N lists.

  python3 scripts/gen_popular.py [N]     (default 1000 per registry)

Review the diff before committing: every name in the block skips registry checks.
gems and go have no public ranking API and keep their hand-picked lists.
"""
import json
import os
import re
import sys
import textwrap
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UA = "pkg-guard popular-list generator (https://github.com/somesh-ghaturle/pkg-guard)"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def npm(n):
    # wooorm/npm-high-impact: npm packages ranked by downloads and dependents
    src = get("https://cdn.jsdelivr.net/npm/npm-high-impact/lib/top.js")
    return re.findall(r"^\s*'([^']+)',?$", src, re.M)[:n]


def pypi(n):
    rows = json.loads(get("https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"))["rows"]
    return [re.sub(r"[-_.]+", "-", r["project"]).lower() for r in rows[:n]]


def crates(n):
    names, query = [], "?sort=downloads&per_page=100"
    while query and len(names) < n:  # seek pagination: deep `page=` requests get cut off
        data = json.loads(get("https://crates.io/api/v1/crates" + query))
        names += [c["name"] for c in data["crates"]]
        query = data["meta"].get("next_page")
        time.sleep(1)  # crates.io crawler policy: 1 request per second
    return names[:n]


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    lists = {"npm": npm(n), "pypi": pypi(n), "crates": crates(n)}
    for eco, names in lists.items():
        if len(names) < n // 2:  # a source changed shape; don't silently shrink the list
            sys.exit("%s: only %d names, refusing to write" % (eco, len(names)))
    lines = ["GENERATED_POPULAR = {  # by scripts/gen_popular.py on %s; do not edit by hand" % time.strftime("%Y-%m-%d")]
    for eco, names in lists.items():
        body = textwrap.fill(" ".join(sorted(set(names))), 96, initial_indent=" " * 8, subsequent_indent=" " * 8,
                             break_on_hyphens=False, break_long_words=False)
        lines.append('    "%s": """\n%s""",' % (eco, body))
    lines.append("}")
    path = os.path.join(ROOT, "pkg_guard.py")
    with open(path) as f:
        src = f.read()
    new, count = re.subn(r"^GENERATED_POPULAR = \{.*?^\}$", lambda _: "\n".join(lines), src, flags=re.S | re.M)
    if count != 1:
        sys.exit("GENERATED_POPULAR block not found in pkg_guard.py")
    with open(path, "w") as f:
        f.write(new)
    print("wrote %s" % ", ".join("%s=%d" % (e, len(v)) for e, v in lists.items()))


if __name__ == "__main__":
    main()
