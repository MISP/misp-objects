# Timesketch timeline entries and selected Plaso observations

Version 4 extends the existing `timesketch-timeline` template with optional source
references and annotation context. Its UUID, core fields (`datetime`, `timestamp`,
`timestamp_desc`, `message`) and existing requirements remain unchanged.
`timesketch_message` remains available for existing message-based workflows.

The additions support selected/annotated timeline exchange:

- `event-id`, `source-index`, `sketch-id`, `timeline-id`, `timeline-name` and
  `source-url` locate the source entry. Document IDs are scoped by this context;
  they must not become IDs or index targets for a new ingestion.
- `source-tags`, `source-labels`, `source-comments` preserve JSON annotation
  snapshots, including author, time and sketch scope where supplied. `selected`
  preserves an explicit selection flag. A search hit is not inherently selected.
  These fields neither confirm malicious activity nor automatically apply MISP
  tags or active Timesketch annotations.
- `parser`, `data-type`, `display-name` and JSON `pathspec` retain Plaso parser
  and nested dfVFS evidence references. Unmapped source context stays in JSON
  `raw-event`, including serialized Plaso `date_time` values.
- `source-format`, `source-sha256` and `row-number` identify the exact imported
  export and one-based record ordinal. The hash describes export bytes, not the
  disk image, EVTX or other evidence referenced inside an entry.
- `datetime-raw` preserves the original datetime; `datetime-unit` explicitly
  describes a numeric datetime as `s`, `ms`, `us` or `ns`. The existing `timestamp`
  always means integer microseconds since the Unix epoch. Units are not inferred
  from magnitude. Only known-offset, consistent times representable without
  sub-microsecond rounding should populate normalized `datetime`.

New fields default to non-IDS and non-correlating. Importers should also apply
those settings to the original core fields when exchanging forensic context.
Optional text fields allow source values without imposing version-dependent
Timesketch/Plaso enumerations. They do not replace the original evidence.

A source `file` object can retain the exact export attachment, filename, byte
count and SHA-256. Following the relationship catalogue's direction, the source
file points to derived timeline objects with `derived-from`. If an importer
filters an input file, it should omit the full attachment to avoid disclosing
excluded entries, while retaining the original hash and only selected raw rows.

The accompanying MISP modules import JSON/JSONL/CSV selections and export
supported timestamped observations as Timesketch JSONL. They extend file exchange
alongside existing Timesketch playbooks; no new object family or native Plaso
storage format is introduced.
