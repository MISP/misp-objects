/*
 * file-type-label.js — stamp a file-type label (csv, json, …) into the base
 * MISP `file` object icon, as compact pixel art knocked out of the document
 * body. The label is a transparent hole (via an SVG <mask>), so the icon stays
 * monochrome / currentColor and reads correctly on any background.
 *
 * No dependencies, no web fonts. Usage:
 *
 *   // browser (global): <script src="file-type-label.js"></script>
 *   el.innerHTML = fileTypeLabel.fileIcon('csv');
 *
 *   // module:
 *   import { fileIcon } from './file-type-label.js';   // see note at bottom
 *   const svg = fileIcon('json', { size: 48 });
 *
 * Labels of up to ~4 characters stay legible; longer strings are accepted but
 * shrink. Characters outside A-Z 0-9 are dropped (case-insensitive input).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.fileTypeLabel = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Base `file` document path (MDI), including the folded-corner subpath.
  var FILE_PATH = 'M13 9V3.5L18.5 9M6 2c-1.11 0-2 .89-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6z';

  // 5 wide x 7 tall pixel glyphs (rows separated by '|').
  var FONT = {
    A: '.###.|#...#|#...#|#####|#...#|#...#|#...#',
    B: '####.|#...#|#...#|####.|#...#|#...#|####.',
    C: '.###.|#...#|#....|#....|#....|#...#|.###.',
    D: '####.|#...#|#...#|#...#|#...#|#...#|####.',
    E: '#####|#....|#....|####.|#....|#....|#####',
    F: '#####|#....|#....|####.|#....|#....|#....',
    G: '.###.|#...#|#....|#.###|#...#|#...#|.###.',
    H: '#...#|#...#|#...#|#####|#...#|#...#|#...#',
    I: '.###.|..#..|..#..|..#..|..#..|..#..|.###.',
    J: '..###|...#.|...#.|...#.|...#.|#..#.|.##..',
    K: '#...#|#..#.|#.#..|##...|#.#..|#..#.|#...#',
    L: '#....|#....|#....|#....|#....|#....|#####',
    M: '#...#|##.##|#.#.#|#.#.#|#...#|#...#|#...#',
    N: '#...#|#...#|##..#|#.#.#|#..##|#...#|#...#',
    O: '.###.|#...#|#...#|#...#|#...#|#...#|.###.',
    P: '####.|#...#|#...#|####.|#....|#....|#....',
    Q: '.###.|#...#|#...#|#...#|#.#.#|#..#.|.##.#',
    R: '####.|#...#|#...#|####.|#.#..|#..#.|#...#',
    S: '.####|#....|#....|.###.|....#|....#|####.',
    T: '#####|..#..|..#..|..#..|..#..|..#..|..#..',
    U: '#...#|#...#|#...#|#...#|#...#|#...#|.###.',
    V: '#...#|#...#|#...#|#...#|.#.#.|.#.#.|..#..',
    W: '#...#|#...#|#...#|#.#.#|#.#.#|#.#.#|.#.#.',
    X: '#...#|#...#|.#.#.|..#..|.#.#.|#...#|#...#',
    Y: '#...#|#...#|.#.#.|..#..|..#..|..#..|..#..',
    Z: '#####|....#|...#.|..#..|.#...|#....|#####',
    '0': '.###.|#...#|#..##|#.#.#|##..#|#...#|.###.',
    '1': '..#..|.##..|..#..|..#..|..#..|..#..|.###.',
    '2': '.###.|#...#|....#|...#.|..#..|.#...|#####',
    '3': '####.|....#|....#|.###.|....#|....#|####.',
    '4': '...#.|..##.|.#.#.|#..#.|#####|...#.|...#.',
    '5': '#####|#....|####.|....#|....#|#...#|.###.',
    '6': '.###.|#....|#....|####.|#...#|#...#|.###.',
    '7': '#####|....#|...#.|..#..|.#...|.#...|.#...',
    '8': '.###.|#...#|#...#|.###.|#...#|#...#|.###.',
    '9': '.###.|#...#|#...#|.####|....#|....#|.###.'
  };

  // Label band inside the document body (viewBox 0 0 24 24).
  var BAND_CX = 12.0, BAND_CY = 16.3, BAND_W = 13.0, BAND_H = 8.0;
  var GLYPH_W = 5, GLYPH_H = 7, GAP = 1;

  var uid = 0;
  function r(n) { return Math.round(n * 100) / 100; }

  function clean(type) {
    return String(type == null ? '' : type)
      .toUpperCase()
      .split('')
      .filter(function (ch) { return Object.prototype.hasOwnProperty.call(FONT, ch); });
  }

  function labelRects(chars) {
    var n = chars.length;
    if (n === 0) return '';
    var cols = GLYPH_W * n + GAP * (n - 1);
    var s = Math.min(BAND_W / cols, BAND_H / GLYPH_H);   // px size, keep aspect
    var blockW = cols * s, blockH = GLYPH_H * s;
    var ox = BAND_CX - blockW / 2, oy = BAND_CY - blockH / 2;
    var out = [];
    for (var gi = 0; gi < n; gi++) {
      var gx = ox + gi * (GLYPH_W + GAP) * s;
      var rows = FONT[chars[gi]].split('|');
      for (var row = 0; row < rows.length; row++) {
        for (var col = 0; col < rows[row].length; col++) {
          if (rows[row][col] === '#') {
            out.push('<rect x="' + r(gx + col * s) + '" y="' + r(oy + row * s) +
                     '" width="' + r(s) + '" height="' + r(s) + '"/>');
          }
        }
      }
    }
    return out.join('');
  }

  /**
   * Return an SVG string of the file icon labelled with `type`.
   * @param {string} type   e.g. "csv", "json" (A-Z 0-9; others dropped)
   * @param {object} [opts] { size?: number (px, sets width/height) }
   */
  function fileIcon(type, opts) {
    opts = opts || {};
    var chars = clean(type);
    var dim = opts.size ? ' width="' + opts.size + '" height="' + opts.size + '"' : '';
    var head = '<svg xmlns="http://www.w3.org/2000/svg"' + dim + ' viewBox="0 0 24 24">';

    if (chars.length === 0) {  // nothing to stamp -> plain file icon
      return head + '<path fill="currentColor" d="' + FILE_PATH + '"/></svg>';
    }

    var id = 'ft-' + (uid++);  // unique per call: avoids duplicate-id collisions
    return head +
      '<mask id="' + id + '">' +
        '<path d="' + FILE_PATH + '" fill="white"/>' +
        '<g fill="black">' + labelRects(chars) + '</g>' +
      '</mask>' +
      '<path d="' + FILE_PATH + '" fill="currentColor" mask="url(#' + id + ')"/>' +
    '</svg>';
  }

  return { fileIcon: fileIcon, FONT: FONT, FILE_PATH: FILE_PATH };
}));

/*
 * ES-module note: this file is UMD (global / CommonJS). To consume it as an
 * ES module without a bundler, either load it with a <script> and read the
 * `fileTypeLabel` global, or append:  export const { fileIcon } = fileTypeLabel;
 * in a thin wrapper. Kept UMD here so it works in plain pages and Node alike.
 */
