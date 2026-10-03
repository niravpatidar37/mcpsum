# /// script
# requires-python = ">=3.12"
# dependencies = ["fonttools==4.66.1"]
# ///
"""Build every mcpsum brand asset from source, reproducibly.

    uv run assets/brand/tools/build_brand.py

Requires `resvg` on PATH for the PNG exports (`cargo install resvg --locked --version 0.48.1`).

The wordmark is set in JetBrains Mono ExtraBold and converted to outlines, so
the logos render identically without the font installed. The font is fetched
from the pinned upstream release and verified by SHA-256 (it is not vendored).
JetBrains Mono is licensed under the SIL Open Font License 1.1, which permits
using its outlines in artwork such as a logo.
"""

from __future__ import annotations

import hashlib
import io
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

OUT = pathlib.Path(__file__).resolve().parents[1]
FONT_URL = "https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip"
FONT_SHA256 = "6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf"

# Palette. One accent, two tones so it passes contrast on both GitHub themes.
INK = "#0B0F14"          # mark on light backgrounds
SNOW = "#F2F0EA"         # mark on dark backgrounds
AMBER_ON_LIGHT = "#9A6200"
AMBER_ON_DARK = "#F0B429"
MUTED_ON_DARK = "#9AA4B2"
GITHUB_LIGHT_BG = "#FFFFFF"
GITHUB_DARK_BG = "#0D1117"


# ----------------------------------------------------------------- contrast

def _lum(hex_color: str) -> float:
    rgb = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# ----------------------------------------------------------------- fonts

def load_fonts() -> dict[str, TTFont]:
    cache = OUT / "tools" / ".cache" / "JetBrainsMono-2.304.zip"
    if not cache.exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(FONT_URL, timeout=60) as r:  # noqa: S310 (pinned https URL)
            cache.write_bytes(r.read())
    data = cache.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != FONT_SHA256:
        cache.unlink()
        sys.exit(f"font archive checksum mismatch: {digest}")
    z = zipfile.ZipFile(io.BytesIO(data))
    return {
        w: TTFont(io.BytesIO(z.read(f"fonts/ttf/JetBrainsMono-{w}.ttf")))
        for w in ("ExtraBold", "Medium")
    }


def _ntos(n: float) -> str:
    s = f"{n:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def text_path(font: TTFont, text: str, size: float, x: float, baseline: float, tracking: float = 0.0) -> tuple[str, float]:
    """Outline `text` as an SVG path. Returns (d, advance width)."""
    glyphs, cmap = font.getGlyphSet(), font.getBestCmap()
    scale = size / font["head"].unitsPerEm
    pen = SVGPathPen(glyphs, ntos=_ntos)
    cursor = x
    for ch in text:
        name = cmap[ord(ch)]
        glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, cursor, baseline)))
        cursor += font["hmtx"][name][0] * scale + tracking
    return pen.getCommands(), cursor - x - tracking


def x_height(font: TTFont, size: float) -> float:
    return font["OS/2"].sxHeight * size / font["head"].unitsPerEm


# ----------------------------------------------------------------- the mark

def mark(fg: str, accent: str, *, x: float = 0, y: float = 0, size: float = 64) -> str:
    """The {#} mark on a 64-unit grid: JSON braces around a hash."""
    s = size / 64
    return (
        f'<g transform="translate({_ntos(x)} {_ntos(y)}) scale({_ntos(s)})" fill="none" stroke-linecap="round" stroke-linejoin="round">'
        f'<path stroke="{fg}" stroke-width="5.5" d="M21 10C13 10 15.5 23 15.5 27.5C15.5 30.5 12.5 32 9.5 32C12.5 32 15.5 33.5 15.5 36.5C15.5 41 13 54 21 54"/>'
        f'<path stroke="{fg}" stroke-width="5.5" d="M43 10C51 10 48.5 23 48.5 27.5C48.5 30.5 51.5 32 54.5 32C51.5 32 48.5 33.5 48.5 36.5C48.5 41 51 54 43 54"/>'
        f'<path stroke="{accent}" stroke-width="4.25" d="M29 21L26.5 43M38.5 21L36 43M23.5 27.5H41.5M22.5 36.5H40.5"/>'
        "</g>"
    )


def favicon_mark() -> str:
    """Small-size variant: own tile, heavier strokes, upright hash."""
    return (
        f'<rect width="32" height="32" rx="7" fill="{INK}"/>'
        '<g fill="none" stroke-linecap="round" stroke-linejoin="round">'
        f'<path stroke="{SNOW}" stroke-width="2.9" d="M10.5 6C7.2 6 8.2 11.3 8.2 13.6C8.2 15 6.9 16 5.6 16C6.9 16 8.2 17 8.2 18.4C8.2 20.7 7.2 26 10.5 26"/>'
        f'<path stroke="{SNOW}" stroke-width="2.9" d="M21.5 6C24.8 6 23.8 11.3 23.8 13.6C23.8 15 25.1 16 26.4 16C25.1 16 23.8 17 23.8 18.4C23.8 20.7 24.8 26 21.5 26"/>'
        f'<path stroke="{AMBER_ON_DARK}" stroke-width="2.3" d="M14.1 10.8V21.2M17.9 10.8V21.2M11.6 13.9H20.4M11.6 18.1H20.4"/>'
        "</g>"
    )


def favicon16_mark() -> str:
    """Hand-hinted 16px variant: every stroke on the pixel grid (crispEdges),
    1px strokes with 2px gaps, and a 1px moat between braces and hash so the
    four hash strokes stay distinct instead of blurring into one blob."""
    return (
        f'<rect width="16" height="16" rx="3" fill="{INK}"/>'
        '<g fill="none" stroke-width="1" stroke-linecap="square" shape-rendering="crispEdges">'
        f'<path stroke="{SNOW}" d="M4.5 2.5H3.5V7.5H2.5V8.5H3.5V13.5H4.5"/>'
        f'<path stroke="{SNOW}" d="M11.5 2.5H12.5V7.5H13.5V8.5H12.5V13.5H11.5"/>'
        f'<path stroke="{AMBER_ON_DARK}" d="M6.5 4.5V11.5M9.5 4.5V11.5M5.5 6.5H10.5M5.5 9.5H10.5"/>'
        "</g>"
    )


def svg(width: float, height: float, body: str, title: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_ntos(width)}" height="{_ntos(height)}" '
        f'viewBox="0 0 {_ntos(width)} {_ntos(height)}" role="img" aria-label="{title}">'
        f"<title>{title}</title>{body}</svg>\n"
    )


def lockup(fonts: dict[str, TTFont], fg: str, accent: str) -> str:
    size, gap = 46.0, 16.0
    xh = x_height(fonts["ExtraBold"], size)
    baseline = 32 + xh / 2
    d_mcp, w_mcp = text_path(fonts["ExtraBold"], "mcp", size, 64 + gap, baseline, tracking=-0.6)
    d_sum, w_sum = text_path(fonts["ExtraBold"], "sum", size, 64 + gap + w_mcp - 0.6, baseline, tracking=-0.6)
    width = 64 + gap + w_mcp - 0.6 + w_sum + 2
    body = mark(fg, accent) + f'<path fill="{fg}" d="{d_mcp}"/><path fill="{accent}" d="{d_sum}"/>'
    return svg(width, 64, body, "mcpsum")


def social(fonts: dict[str, TTFont]) -> str:
    W, H, left = 1280, 640, 96
    eb, md = fonts["ExtraBold"], fonts["Medium"]
    parts = [f'<rect width="{W}" height="{H}" fill="{INK}"/>']
    parts.append(mark(SNOW, AMBER_ON_DARK, x=left - 12, y=96, size=128))
    wsize = 92
    base = 96 + 64 + x_height(eb, wsize) / 2
    d1, w1 = text_path(eb, "mcp", wsize, left + 136, base, tracking=-1.2)
    d2, _ = text_path(eb, "sum", wsize, left + 136 + w1 - 1.2, base, tracking=-1.2)
    parts.append(f'<path fill="{SNOW}" d="{d1}"/><path fill="{AMBER_ON_DARK}" d="{d2}"/>')
    for i, line in enumerate(("Stop MCP servers from", "rug-pulling your AI agent.")):
        d, _ = text_path(md, line, 54, left, 340 + i * 70)
        parts.append(f'<path fill="{SNOW}" d="{d}"/>')
    d, _ = text_path(md, "Lockfile + runtime reference monitor for MCP tools", 27, left, 480)
    parts.append(f'<path fill="{MUTED_ON_DARK}" d="{d}"/>')
    d, _ = text_path(md, "github.com/niravpatidar37/mcpsum", 24, left, 566)
    parts.append(f'<path fill="{AMBER_ON_DARK}" d="{d}"/>')
    return svg(W, H, "".join(parts), "mcpsum: stop MCP servers from rug-pulling your AI agent")


# ----------------------------------------------------------------- safety gate

FORBIDDEN = [
    (re.compile(r"<\s*script", re.I), "script element"),
    (re.compile(r"\son[a-z]+\s*=", re.I), "event handler attribute"),
    (re.compile(r"<\s*foreignObject", re.I), "foreignObject"),
    (re.compile(r"(?:xlink:)?href\s*=\s*\"(?!#)", re.I), "external reference"),
    (re.compile(r"url\(\s*['\"]?(?!#)", re.I), "external url()"),
    (re.compile(r"javascript:", re.I), "javascript: URL"),
]


def check_safe(name: str, text: str) -> None:
    for pattern, what in FORBIDDEN:
        if pattern.search(text):
            sys.exit(f"{name}: unsafe SVG content ({what})")


# ----------------------------------------------------------------- main

def main() -> None:
    checks = {
        "accent on GitHub light": contrast(AMBER_ON_LIGHT, GITHUB_LIGHT_BG),
        "accent on GitHub dark": contrast(AMBER_ON_DARK, GITHUB_DARK_BG),
        "ink on GitHub light": contrast(INK, GITHUB_LIGHT_BG),
        "snow on GitHub dark": contrast(SNOW, GITHUB_DARK_BG),
        "favicon hash on tile": contrast(AMBER_ON_DARK, INK),
    }
    for label, ratio in checks.items():
        print(f"contrast {label}: {ratio:.2f}:1")
        if ratio < 3.0:
            sys.exit(f"contrast below WCAG 3:1 for graphics: {label}")

    fonts = load_fonts()
    files = {
        "icon.svg": svg(64, 64, mark(INK, AMBER_ON_LIGHT), "mcpsum"),
        "icon-dark.svg": svg(64, 64, mark(SNOW, AMBER_ON_DARK), "mcpsum"),
        "favicon.svg": svg(32, 32, favicon_mark(), "mcpsum"),
        "favicon-16.svg": svg(16, 16, favicon16_mark(), "mcpsum"),
        "logo.svg": lockup(fonts, INK, AMBER_ON_LIGHT),
        "logo-dark.svg": lockup(fonts, SNOW, AMBER_ON_DARK),
        "social-preview.svg": social(fonts),
    }
    for name, text in files.items():
        check_safe(name, text)
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {name} ({len(text)} bytes)")

    resvg = shutil.which("resvg")
    if not resvg:
        sys.exit("resvg not found on PATH; install it to export PNGs")
    renders = [
        ("favicon-16.svg", "favicon-16.png", 16),
        ("favicon.svg", "favicon-32.png", 32),
        ("favicon.svg", "avatar-512.png", 512),
        ("social-preview.svg", "social-preview.png", 1280),
    ]
    for src, dst, width in renders:
        # List-form argv, no shell: nothing here is shell-interpreted. All
        # arguments are constants from `renders` plus the absolute resvg path
        # from shutil.which, so no untrusted input reaches this call.
        argv = [resvg, "-w", str(width), str(OUT / src), str(OUT / dst)]
        subprocess.run(argv, check=True, shell=False)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        print(f"rendered {dst} ({(OUT / dst).stat().st_size} bytes)")


if __name__ == "__main__":
    main()
