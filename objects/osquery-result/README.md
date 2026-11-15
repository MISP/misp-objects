# osquery snapshot and differential context

This template represents a returned osquery row or an explicitly empty logged
snapshot/batch execution. Existing `query` and hunt-finding templates do not carry
the combination of host/query identity, row action, schedule markers and raw
result context. Generic query columns remain JSON rather than being classified
as process/file/socket entities by column names alone.

`host-identifier` may be a UUID or custom identifier; do not assume it is a DNS
hostname. Keep the exact native `scheduled-name`, including pack scope, alongside
`query-name` and optional `pack-name`. Split pack/query names only with explicit
context or the existing MISP exporter's unambiguous hashed query suffix.

`record-type: row` requires a real returned row in `row` and an applicable
`row-action` (`snapshot`, `added`, `removed`). `record-type: empty-result` indicates
an explicitly empty snapshot or batch: omit `row` and `row-index`, retain a zero
`row-count`, and omit `row-action` for an empty differential batch. It is not a
matched finding or an automatically benign conclusion. Event-format logging does
not report the total execution row count; `row-count` is per source log record.

`unix-time` is native Unix seconds; `execution-time` is the normalized query
execution/log time. Preserve human-readable `calendar-time` and any original
collector timestamp separately. Never infer units from magnitude, label schedule
`epoch` as a timestamp, or interpret query execution time as entity lifecycle time.
Keep zero epoch/counter values. Preserve decorations as source metadata.

`source-indicators` retains a JSON array of source event/object/attribute references
from hunting exports. Preserve each reference as a unit: one deduplicated query
may originate from multiple events or object attributes. These are contextual
references; they do not automatically import indicators, fetch source events or
establish a malicious verdict. Exact export bytes can be attached to a source
`file`, which points to result objects with the catalogue's `derived-from` direction.
`source-sha256` identifies those bytes; context supplied separately is not
authenticated by the file hash.

Preserve `row` column types and unmodeled log metadata in `record-context`.
Scope records by source export, host, query and record/row ordinals; PID, row values
or counters alone must not merge observations across hosts/runs. `removed` rows
do not mark MISP data as deleted or prove remediation. All fields default to
non-IDS and non-correlating; imported observations start as `unreviewed`.
