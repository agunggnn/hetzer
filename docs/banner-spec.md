# 🎨 Hetzer Banner Specification & Generation Guide

This document defines the canonical geometric architecture, design system, and deterministic rendering pipeline for Hetzer's repository and documentation branding banners.

---

## 📌 Source of Truth Architecture

* **Canonical Vector Source**: [`assets/hetzer-banner.svg`](file:///E:/GitHub/shadow-core/assets/hetzer-banner.svg)
* **Derived Raster Artifact**: [`assets/hetzer-banner.jpg`](file:///E:/GitHub/shadow-core/assets/hetzer-banner.jpg)
* **Automation Script**: [`scripts/render-banner.mjs`](file:///E:/GitHub/shadow-core/scripts/render-banner.mjs) (`npm run render:banner`)

> [!IMPORTANT]
> **Zero Raster Patching Rule**: Never modify [`assets/hetzer-banner.jpg`](file:///E:/GitHub/shadow-core/assets/hetzer-banner.jpg) directly with image editors, brush tools, or solid fill boxes. Doing so causes visible JPEG compression boundary artifacts and font anti-aliasing mismatches. All visual changes **must** be made in the SVG vector geometry and re-rendered through the automated script.

---

## 📐 Canvas & Frame Geometry

The banner uses a fixed 900 × 380 pixel viewport styled as a floating dark macOS-style terminal window with subtle cyberpunk circuit traces.

```
+-------------------------------------------------------------------------------+
| (0,0)                                                             (900,0)     |
|   +-----------------------------------------------------------------------+   |
|   | (20,20) [Window Titlebar: H=38px]                           (880,20)  |   |
|   |  (●)(●)(●)            hetzer ~ credential-safety-layer                |   |
|   |-----------------------------------------------------------------------|   |
|   |                                                                       |   |
|   |          H      E      T      Z      E      R     (y=109..207)        |   |
|   |                                                                       |   |
|   |  ---------------------- [Divider y=235] ----------------------------  |   |
|   |       Credential Safety Layer & Leak-Reduction Tools... (y=265)       |   |
|   |                                                                       |   |
|   |   [⚡ Bounded Sniffer] [🔒 AES-256-GCM Vault] [🛡️ Skills] [📦 0 Docker]|   |
|   +-----------------------------------------------------------------------+   |
| (0,380)                                                           (900,380)   |
+-------------------------------------------------------------------------------+
```

### Canvas Specifications
* **Outer Canvas**: `viewBox="0 0 900 380"`, background fill `#090d16`.
* **Terminal Window Frame**:
  * Position: `x="20" y="20" width="860" height="340" rx="12"`
  * Body Fill: `#0d121f`, border: `stroke="#1f293d" stroke-width="1.2"`
* **Titlebar**:
  * Background: Top-clipped path `fill="#131a2b"`, height 38px (`y=20` to `y=58`).
  * Divider Line: `x1="20" y1="58" x2="880" y2="58" stroke="#1f293d"`
  * Window Controls: 3 circles (`r="6"` at `y="39"`):
    * Close: `cx="42"` (`#ff5f56`)
    * Minimize: `cx="62"` (`#ffbd2e`)
    * Maximize: `cx="82"` (`#27c93f`)
  * Header Text: `x="450" y="43" fill="#64748b" font-family="'JetBrains Mono', monospace" font-size="12"`:
    `hetzer ~ credential-safety-layer`

---

## 🔤 Letter Grid & Wordmark Geometry (`H E T Z E R`)

The wordmark is modeled on classic retro 16-bit ANSI shadow terminal block fonts (as output by [`cli/core/banner.mjs`](file:///E:/GitHub/shadow-core/cli/core/banner.mjs)).

### Vertical Row Grid
All letters span vertically from **`y = 109`** to **`y = 207`** (total height = 98px), divided into 5 standard ANSI rows:
* **Row 1 (Top Bar)**: `y = 109` to `127` (height 18px)
* **Row 2 (Upper Tier)**: `y = 127` to `148` (height 21px)
* **Row 3 (Mid Tier / Crossbar)**: `y = 148` to `168` (height 20px)
* **Row 4 (Lower Tier)**: `y = 168` to `188` (height 20px)
* **Row 5 (Bottom Bar)**: `y = 188` to `207` (height 19px)

Subtle horizontal grid lines are overlaid at `y = 128, 148, 168, 188` (`stroke="#0d121f" stroke-width="1" opacity="0.35"`).

### Letter Horizontal Spans (X Coordinates)

| Letter | X Start | X End | Width | Structure Notes |
|:------:|:-------:|:-----:|:-----:|:----------------|
| **`H`** | 234 | 296 | 62px | Dual 18px pillars (`234..252` and `278..296`), crossbar at `y=149..167`. |
| **`E`** | 304 | 366 | 62px | Left spine (`304..322`), 3 horizontal bars (top `109..127`, mid `149..167`, bot `189..207`). |
| **`T`** | 375 | 446 | 71px | Top bar (`375..446`, `y=109..127`), centered stem (`401..420`, `y=127..207`). |
| **`Z`** | 455 | 516 | 61px | **Stepped ANSI Diagonal**: see detailed specification below. |
| **`E`** | 525 | 587 | 62px | Identical to first `E`, shifted horizontally by `+221px`. |
| **`R`** | 596 | 649 | 53px | Left spine (`596..614`), upper loop (`614..640/649`), stepped diagonal leg. |

---

## ⚡ Canonical Geometry for Letter `Z`

> [!WARNING]
> **Anti-Regression Notice**: Do not replace `Z` with side-notched rectangular cutouts (an hourglass or I-beam shape). `Z` requires a true diagonal slope represented as 3 discrete stepped tiers to preserve the terminal ANSI block aesthetic.

### Correct Vector Path for `Z`
```svg
M 455 109 H 516 V 127 H 508 V 148 H 499 V 168 H 490 V 188 H 516 V 207 H 455 V 188 H 464 V 168 H 473 V 148 H 482 V 127 H 455 Z
```

### Coordinate Step Breakdown
* **Top Horizontal Bar**: `(455, 109)` to `(516, 109)`, down to `(516, 127)`.
* **Diagonal Right Edge Steps**:
  * Step 1 (Row 2): Left to `508`, down to `y=148`.
  * Step 2 (Row 3): Left to `499` (-9px step), down to `y=168`.
  * Step 3 (Row 4): Left to `490` (-9px step), down to `y=188`.
  * Step to Bottom Bar: Right to `516`, down to `y=207`.
* **Bottom Horizontal Bar**: `(516, 207)` left to `(455, 207)`, up to `(455, 188)`.
* **Diagonal Left Edge Steps**:
  * Step 3 (Row 4): Right to `464` (+9px step), up to `y=168`.
  * Step 2 (Row 3): Right to `473` (+9px step), up to `y=148`.
  * Step 1 (Row 2): Right to `482` (+9px step), up to `y=127`.
  * Step to Top Bar: Left to `455`, up to `y=109` (closes path).

---

## 🔮 Circuit Shadow Layering

The wordmark features 3 stacked layers to create depth and a cyberpunk glow:

1. **Outer Cyan Circuit Trace**:
   * Stroke: `#00d9f5`, `stroke-width="1.8"`, `stroke-linejoin="miter"`
   * Transform: `translate(6, 6)`
   * Opacity: `0.4`
2. **Inner Emerald Circuit Trace**:
   * Stroke: `#00f5a0`, `stroke-width="1.8"`, `stroke-linejoin="miter"`
   * Transform: `translate(3, 3)`
   * Opacity: `0.65`
3. **Solid Silhouette Fill**:
   * Gradient: Linear gradient `cyber-grad` (`#00f5a0` at 0% to `#00d9f5` at 100%)
   * Filter: Glow filter with drop shadow (`stdDeviation="6" flood-color="#00f5a0" flood-opacity="0.35"`)
   * Rule: `fill-rule="evenodd"`

---

## 🏷️ Subtitle & Feature Badges

### Divider Line
* Geometry: `x="160" y="235" width="580" height="1"`
* Gradient: Fade from `#1f293d` transparent to solid to transparent.

### Subtitle Text
* Position: `x="450" y="265" text-anchor="middle"`
* Font: `'JetBrains Mono', monospace`, `font-size="13.5"`
* Text:
  * `<tspan fill="#00f5a0" font-weight="600">Credential Safety Layer</tspan>`
  * `<tspan fill="#e2e8f0"> & Leak-Reduction Tools for Autonomous AI Agents</tspan>`

### 4 Feature Pills
Height: 28px (`y=290` to `y=318`), corner radius `rx="6"`, background `#1e293b` (opacity 0.8), border `stroke="#334155" stroke-width="1"`:

1. **Bounded Sniffer**: `x="145" width="130"`
   * Text: `⚡ <tspan fill="#38bdf8" font-weight="600">Bounded</tspan> Sniffer` (`x=210 y=308`)
2. **AES-256-GCM Vault**: `x="290" width="155"`
   * Text: `🔒 <tspan fill="#38bdf8" font-weight="600">AES-256-GCM</tspan> Vault` (`x=367 y=308`)
3. **Universal Skills**: `x="460" width="140"`
   * Text: `🛡️ <tspan fill="#38bdf8" font-weight="600">Universal</tspan> Skills` (`x=530 y=308`)
4. **0 Docker Overhead**: `x="615" width="145"`
   * Text: `📦 <tspan fill="#38bdf8" font-weight="600">0 Docker</tspan> Overhead` (`x=687 y=308`)

---

## 🚀 How to Generate & Regenerate the Banner

### Method 1: Automated npm Command (Recommended)

Simply run:
```bash
npm run render:banner
```
or directly via Node:
```bash
node scripts/render-banner.mjs
```

**What the script does automatically**:
1. Automatically discovers headless Edge or Chrome on Windows, macOS, or Linux.
2. Captures an exact pixel screenshot of `assets/hetzer-banner.svg` at `--window-size=900,380` and `--force-device-scale-factor=1`.
3. Encodes directly to high-quality JPEG (quality 98) using available system image libraries (Python Pillow, Windows PowerShell System.Drawing, macOS `sips`, or ImageMagick).
4. Verifies the resulting artifact matches exact 900 × 380 dimensions.

### Method 2: Manual CLI Fallback

If running manually on Windows:
```powershell
# 1. Capture SVG via Headless Edge
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" `
  --headless=new `
  --disable-gpu `
  --hide-scrollbars `
  --screenshot="assets\temp.png" `
  --window-size=900,380 `
  --force-device-scale-factor=1 `
  "file:///E:/GitHub/shadow-core/assets/hetzer-banner.svg"

# 2. Convert to JPEG with Python Pillow (quality 98)
python -c "from PIL import Image; Image.open('assets/temp.png').convert('RGB').save('assets/hetzer-banner.jpg', 'JPEG', quality=98)"

# 3. Remove temporary file
Remove-Item assets\temp.png
```

---

## ✅ Quality Checklist Prior to Committing

Before committing banner updates:
- [ ] Run `npm run check` (validates all source files and checks for sensitive strings).
- [ ] Inspect [`assets/hetzer-banner.jpg`](file:///E:/GitHub/shadow-core/assets/hetzer-banner.jpg) visually at 100% scale.
- [ ] Verify the letter **`Z`** has crisp diagonal steps rather than rectangular notches.
- [ ] Verify pill text reflects current empirical capabilities (`Bounded Sniffer`, not `Sub-2ms`).
- [ ] Confirm file size of `assets/hetzer-banner.jpg` is approximately 70–80 KB.
