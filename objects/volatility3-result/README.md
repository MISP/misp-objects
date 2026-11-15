# Volatility 3 result context

This template represents one plugin result row, including processes, command
lines, network context, suspicious memory regions and YARA matches. Reuse existing
`process`, `network-socket` and `file` objects for the normalized observations and
source files; a new memory-region or YARA-rule template is not required here.

`plugin`, `result-kind`, `raw-result`, `source-sha256`, `result-index` and `row-path`
are required. Plugin class and Volatility versions are distinct optional fields;
native renderer JSON does not carry them, so a collector must supply that context.
`image-sha256` identifies the producer-referenced memory image. `source-sha256`
identifies the exact imported JSON/JSONL bytes. They must never be substituted for
one another, and missing image hashes must not be invented.

`raw-result` retains source columns, including unavailable values and unmodeled
hexdump/disassembly context. Original bytes can be attached to the export `file`.
Nested renderer `__children` structure is represented by `row-path` and `contains`
links between results, rather than repeating full subtrees in every raw row.
Following the relationship catalogue, source image/export objects point to their
derived exports/results with `derived-from`; results point to normalized process
or socket observations with `derived-from` and may also `describe` them.

`offset-virtual` and `offset-physical` correspond only to explicitly labeled source
columns. Generic `offset`, region addresses and YARA match offsets retain their
plugin/layer-specific scope; `layer-name` can supply additional context. Store
addresses losslessly, preferably as hexadecimal strings, and preserve their source
representation in the raw row.

Process IDs are scoped to an image/run/row, not globally unique identifiers. Only
explicit renderer ancestry consistent with PPID/PID and known creation times
should produce process parent links; flat PID matches are insufficient. Normalized
process/network times require known offsets and precision that can be represented
without rounding. Retain originals in the corresponding `*-raw` field. Network
object creation time is not first-packet time.

`memory-start`, `memory-end`, `memory-protection` and `vad-tag` preserve region
context. `rule-name`, `yara-component` and `match-data` represent a YARA match,
not a rule body. These fields and `review-status: unreviewed` do not independently
confirm malicious activity. Analyst conclusions belong in separate linked records.
All template attributes default to non-IDS and non-correlating.
