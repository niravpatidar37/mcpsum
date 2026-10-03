# mcpsum brand assets

The mark is **`{#}`**: JSON braces around a hash, meaning *your tool definitions, pinned*.

| File | Use |
|---|---|
| `logo.svg` / `logo-dark.svg` | Lockup (mark + wordmark) for light / dark backgrounds. README header. |
| `icon.svg` / `icon-dark.svg` | Mark alone, transparent background. |
| `favicon.svg`, `favicon-32.png` | Browser tab / docs favicon (own tile, works on light and dark tabs). |
| `favicon-16.svg`, `favicon-16.png` | Hand-hinted 16px variant, pixel-aligned so the hash stays legible. |
| `avatar-512.png` | GitHub org / social avatar. |
| `social-preview.png` (from `social-preview.svg`) | Repository social preview (Settings → Social preview), 1280×640. |

## Colors

| Token | Hex | Contrast | Use |
|---|---|---|---|
| Ink | `#0B0F14` | 19.2:1 on `#FFFFFF` | Mark and wordmark on light backgrounds; favicon tile |
| Snow | `#F2F0EA` | 16.6:1 on `#0D1117` | Mark and wordmark on dark backgrounds |
| Amber (light) | `#9A6200` | 5.1:1 on `#FFFFFF` | Hash and "sum" on light backgrounds |
| Amber (dark) | `#F0B429` | 10.2:1 on `#0D1117` | Hash and "sum" on dark backgrounds |

Contrast is checked against GitHub's light (`#FFFFFF`) and dark (`#0D1117`)
backgrounds by the build script, which fails below WCAG's 3:1 minimum for
graphics. Every pairing above also clears 4.5:1.

## Usage

- Keep clear space around the lockup of at least the height of the hash.
- Below 120px wide, use the mark alone; below 24px, use the favicon variants.
- Do not recolor, stretch, rotate, outline, add effects, or set the wordmark in another font.
- Use the dark variants on dark backgrounds; never place the light lockup on a dark surface.

## Rebuilding

All assets are generated from `tools/build_brand.py`, so they are reproducible
and reviewable as code:

```sh
cargo install resvg --locked --version 0.48.1   # PNG export
uv run assets/brand/tools/build_brand.py
```

The script fetches JetBrains Mono v2.304 from its official release, verifies
its SHA-256, outlines the wordmark, checks color contrast, rejects any SVG
containing scripts, event handlers, `foreignObject` or external references,
and renders the PNGs.

## Licensing

- The wordmark uses outlines of **JetBrains Mono** (SIL Open Font License 1.1,
  © The JetBrains Mono Project Authors), which permits use in artwork such as logos.
  The font itself is not redistributed here.
- The code in this repository is Apache-2.0. Apache-2.0 (section 6) does not
  grant trademark rights: the mcpsum name and logo identify this project. Use
  them to refer to mcpsum, not to suggest endorsement of another product.
