#!/usr/bin/env python3
"""Turn the Archify page docs/architecture.html into README-safe animated SVGs.

  python3 scripts/readme_svg.py      writes docs/architecture-{light,dark}.svg

GitHub strips scripts and <style> from README markdown, but an SVG shown via <img>
keeps its own CSS and SMIL animation. Each arrow gets a dot that travels along it.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"


def theme_vars(css, theme):
    block = re.search(r'\[data-theme="%s"\]\s*\{([^}]*)\}' % theme, css).group(1)
    return re.sub(r"/\*.*?\*/", "", block, flags=re.S)


def class_rules(css, classes):
    """Rules whose selectors use only these classes (e.g. `.c-backend`, `svg .s-cloud`)."""
    out = []
    for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        sel = re.sub(r"/\*.*?\*/", "", sel, flags=re.S).strip()
        parts = [p.strip() for p in sel.split(",")]
        if all(re.fullmatch(r"(svg )?(\.[\w-]+ ?)+", p) and
               set(re.findall(r"\.([\w-]+)", p)) <= classes for p in parts):
            out.append("%s { %s }" % (sel, " ".join(body.split())))
    return out


def main():
    html = open(os.path.join(ROOT, "docs", "architecture.html")).read()
    css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", html, re.S))
    svg = re.search(r"<svg\b.*?</svg>", html, re.S).group(0)
    svg = re.sub(r'\s(tabindex|role|aria-pressed)="[^"]*"', "", svg)
    classes = {c for attr in re.findall(r'class="([^"]+)"', svg) for c in attr.split()}
    rules = class_rules(css, classes)
    # one travelling dot per arrow, staggered in draw order
    dots = []
    edges = re.findall(r'<path data-edge-from[^>]*?d="([^"]+)" class="a-([\w-]+)"', svg)
    for i, (d, kind) in enumerate(edges):
        dots.append('<circle r="3.5" class="pulse m-%s"><animateMotion dur="2.4s" begin="%.1fs" '
                    'repeatCount="indefinite" path="%s"/></circle>' % (kind, i * 0.3, d))
    svg = svg.replace("<!-- Components -->", "\n".join(dots) + "\n<!-- Components -->", 1)
    w, h = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg).groups()
    for theme in ("light", "dark"):
        style = ("<style>\n:root { %s }\n%s\n"
                 "text { font-family: %s; }\n"
                 "@media (prefers-reduced-motion: reduce) { .pulse { display: none; } }\n</style>" % (
                     " ".join(theme_vars(css, theme).split()), "\n".join(rules), FONT))
        out = re.sub(r"<svg\b[^>]*>",
                     '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %s %s" width="%s" height="%s" '
                     'role="img" aria-label="pkg-guard architecture">\n%s\n'
                     '<rect width="100%%" height="100%%" style="fill: var(--bg)"/>' % (w, h, w, h, style), svg, 1)
        with open(os.path.join(ROOT, "docs", "architecture-%s.svg" % theme), "w") as f:
            f.write(out)
    print("wrote docs/architecture-{light,dark}.svg (%d arrows animated)" % len(dots))


if __name__ == "__main__":
    main()
