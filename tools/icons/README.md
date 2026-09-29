# Icon tooling

Helpers for the per-object icons stored at `objects/<name>/icon/icon.svg`.

- [`file-type-label.js`](#file-type-label) — stamp a file type (`csv`, `json`, …) into the base `file` icon at runtime.
- [`gen-file-type-icons.js`](#gen-file-type-icons) — pre-render static `file-<type>.svg` icons for common file types.
- [`gen-icon-list.sh`](#gen-icon-list) — regenerate the `objects.md` object → icon table.

---

## <a name="file-type-label"></a>`file-type-label.js` — stamp a file type into the `file` icon

The `file` object has a single icon (`objects/file/icon/icon.svg`): a plain document.
`file-type-label.js` takes that same document and **knocks the file type out of its body
as compact pixel art** (like `csv` or `json`), so you don't need a separate image per type.

Because the label is a transparent hole rather than painted-on text, the result stays
**monochrome** and follows the current text color (`currentColor`) — it reads correctly on
light and dark backgrounds, and at small sizes. No web fonts, no dependencies.

### Loading it

It's a UMD module, so it works three ways:

```html
<!-- 1. browser, plain <script> — exposes a `fileTypeLabel` global -->
<script src="tools/icons/file-type-label.js"></script>
```

```js
// 2. CommonJS / Node
const { fileIcon } = require('./tools/icons/file-type-label.js');

// 3. ES module (no bundler): load via <script> above, then re-export
export const { fileIcon } = fileTypeLabel;
```

### Stamping a type

`fileIcon(type, opts?)` returns an SVG **string**.

```js
const svg = fileTypeLabel.fileIcon('csv');     // -> '<svg …>…</svg>'
document.querySelector('#icon').innerHTML = svg;
```

Set an explicit pixel size with `opts.size` (otherwise the SVG scales to its container):

```js
fileTypeLabel.fileIcon('json', { size: 48 });  // adds width="48" height="48"
```

### Coloring it

The icon paints with `currentColor`, so set the CSS `color` of any ancestor:

```html
<span style="color:#5a3cff">
  <script>document.write(fileTypeLabel.fileIcon('pdf'));</script>
</span>
```

### Behavior / limits

| Input | Result |
|-------|--------|
| `'csv'`, `'CSV'` | same icon — input is case-insensitive |
| `'json'`, `'yara'` | fine; **≤ 4 characters** stays crisp, longer is accepted but shrinks |
| characters outside `A–Z 0–9` (e.g. `.`, `$`) | silently dropped (`'.csv'` → `csv`) |
| `''`, `null`, all-unknown | returns the plain `file` icon, no label |

Each call gets a **unique mask id**, so you can inline many labelled icons in one page
without them colliding (a shared id would make every icon render the first one's label).

Supported glyphs: `A–Z` and `0–9` (5×7 pixel font defined in `FONT`).

### Minimal page

```html
<script src="tools/icons/file-type-label.js"></script>
<div id="row" style="color:#222"></div>
<script>
  const types = ['csv', 'json', 'pdf', 'xml', 'zip'];
  document.getElementById('row').innerHTML =
    types.map(t => `<span style="width:48px;display:inline-block">${fileTypeLabel.fileIcon(t)}</span>`).join('');
</script>
```

---

## <a name="gen-file-type-icons"></a>`gen-file-type-icons.js` — pre-rendered static icons

For contexts where running JS isn't an option (the MISP UI, docs, an `<img src>`), a fixed
set of file types is pre-rendered to standalone SVGs at `objects/file/icon/file-<type>.svg`
(e.g. `file-csv.svg`, `file-pdf.svg`). They're produced from the **same** pixel font as the
runtime helper — `gen-file-type-icons.js` just calls `fileIcon()` and writes one file per
type, with a stable per-type mask id.

```bash
node tools/icons/gen-file-type-icons.js   # regenerate the file-<type>.svg set
```

The covered types are the 30 most common on a threat-intel platform (executables, maldocs,
archives, email, IOC data, captures) plus the 10 most-used types worldwide (images, media,
presentations, web). Edit the `CTI_TYPES` / `COMMON_TYPES` arrays in the script to change the
set, then rerun. The base `objects/file/icon/icon.svg` is never touched.

---

## <a name="gen-icon-list"></a>`gen-icon-list.sh` — regenerate the icon table

Writes `objects.md`: a table of every object and its icon (if any), followed by a **File type
icons** table listing every `objects/file/icon/file-*.svg` variant. Run it **from this
directory** (it resolves objects via the relative path `../../objects/`):

```bash
cd tools/icons
./gen-icon-list.sh
```
