#!/usr/bin/env node
/*
 * Generate static file-type icon variants into objects/file/icon/.
 *
 * These are the build-time counterpart to the runtime helper: the pixel font
 * lives only in file-type-label.js, and this script stamps it into one SVG per
 * type (file-<type>.svg) for use where running JS isn't an option.
 *
 * Run:  node tools/icons/gen-file-type-icons.js
 */
const fs = require('fs');
const path = require('path');
const { fileIcon } = require('./file-type-label.js');

// The 30 most common file types seen on a threat-information sharing platform.
const CTI_TYPES = [
  // executables / malware
  'exe', 'dll', 'elf', 'apk', 'jar', 'ps1', 'vbs', 'bat', 'sh', 'py', 'js',
  // documents (maldocs / phishing)
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'rtf', 'lnk',
  // archives / delivery
  'zip', 'rar', '7z', 'iso',
  // email
  'eml', 'msg',
  // data / IOCs
  'json', 'xml', 'csv', 'txt',
  // web / network
  'html', 'pcap',
];

// The 10 most-used file types worldwide that aren't already covered above.
const COMMON_TYPES = [
  'jpg', 'png', 'gif', 'svg',   // images
  'mp3', 'mp4',                 // audio / video
  'ppt', 'pptx',                // presentations
  'css',                        // web
  'gz',                         // compression
];

const TYPES = [...CTI_TYPES, ...COMMON_TYPES];

const outDir = path.join(__dirname, '..', '..', 'objects', 'file', 'icon');

let n = 0;
for (const t of TYPES) {
  // Stable, per-type mask id (instead of the runtime counter) so regeneration
  // is deterministic and the files stay collision-free even if several are
  // inlined into one document.
  const svg = fileIcon(t).replace(/ft-\d+/g, 'ft-' + t);
  fs.writeFileSync(path.join(outDir, `file-${t}.svg`), svg);
  n++;
}
console.log(`Wrote ${n} file-type icons to ${path.relative(process.cwd(), outDir)}/`);
