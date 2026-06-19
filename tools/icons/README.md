# Icon tooling

Helpers for the per-object icons stored at `objects/<name>/icon/icon.svg`.

- [`file-type-label.js`](#file-type-label) — stamp a file type (`csv`, `json`, …) into the base `file` icon.
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

## <a name="gen-icon-list"></a>`gen-icon-list.sh` — regenerate the icon table

Writes `objects.md`, a table of every object and its icon (if any). Run it **from this
directory** (it resolves objects via the relative path `../../objects/`):

```bash
cd tools/icons
./gen-icon-list.sh
```
