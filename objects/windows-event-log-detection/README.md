# Windows event-log detection

This template represents a **reported rule match**, not the detection rule's logic
and not an analyst-confirmed malicious finding. Use it with
`windows-event-log-record` to retain matched event context separately.

The minimum fields are `tool`, `rule-title` and `raw-result`. Preserve `rule-id`,
reported `severity`, rule path/source/status and tool version when supplied.
Missing identifiers must not be fabricated. Rule maturity (`stable`, `test`,
`experimental`, etc.) is not an assessment of the observed activity.

Set `review-status=unreviewed` during import. An analyst's later conclusion belongs
in a separate object, such as `threat-hunt-finding` linked with `related-to`, rather
than being inferred from rule severity, source verdicts or rule status.

For one Chainsaw aggregate, create **one detection and several event-record
objects**, each with its own host/channel/record/source context. Do not flatten
their record IDs and hosts into unrelated multi-valued attributes. A Hayabusa
timeline entry may itself summarize several records: retain composite context
as reported rather than inventing individual events.

Relationships follow the catalogue's source-to-derived direction:

- Source export file → detection: `derived-from`.
- Source export file → reported event-record context: `derived-from`.
- Event-record context → detection based on it: `derived-from`.
- Detection → each matched event-record context: `describes`.

`source-sha256` hashes the exact **export** bytes, not referenced EVTX files.
`result-index` is the one-based detection ordinal in that export. `raw-result`
keeps normalized complete result JSON; preserve the original attachment for exact
bytes and numeric precision. `timestamp-raw` retains the producer timestamp;
populate `detection-time` only when its timezone and precision are known.

All relations default to non-IDS and disabled correlation. Existing `detection`
objects describe an analytic and its response plan; generic `security-finding`
metadata does not preserve rule severity/identity and record membership. Neither
needs modification for these focused detection instances.
