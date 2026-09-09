# 🎨 Hetzer Branding Assets

This directory contains the canonical branding banners and graphics for Hetzer.

## Files

| File | Type | Description |
|:-----|:-----|:------------|
| [`hetzer-banner.svg`](hetzer-banner.svg) | **Source of Truth** | Native vector SVG banner (900×380 px) with pure geometric coordinates, circuit traces, and macOS terminal chrome. |
| [`hetzer-banner.jpg`](hetzer-banner.jpg) | **Derived Artifact** | High-quality JPEG (900×380 px, quality 98) rendered directly from the SVG for GitHub repository headers and social cards. |

## ⚠️ Important Rules

1. **Do NOT paint or patch over `hetzer-banner.jpg`**.
   Never draw solid boxes or paint over the raster image with bitmap editing tools. This creates visible compression banding and font rendering discrepancies.
2. **Always edit `hetzer-banner.svg` first**.
   Modify vector paths, typography, colors, or pill badges in the SVG.
3. **Regenerate via automated command**:
   ```bash
   npm run render:banner
   ```
   or:
   ```bash
   node scripts/render-banner.mjs
   ```

For the complete technical specification, pixel grid coordinate math, letter geometries (including letter `Z` stepped tiers), and fallback rendering workflows, see:
👉 [**`docs/banner-spec.md`**](../docs/banner-spec.md)
