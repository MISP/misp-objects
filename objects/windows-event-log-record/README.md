# Windows event-log record context

This template retains Windows event context **as reported in a forensic export**.
It is not a binary EVTX record or proof that the referenced file was acquired.
For Hayabusa it can represent the context in a timeline entry; for Chainsaw it
represents an individual document, including a member of an aggregate detection.

Preserve computer, channel, provider, Windows Event ID, EventRecordID, source EVTX
reference and event timestamp when available. EventRecordID is scoped to its log
and host: two records with the same ID can represent distinct events. Windows
`event-level` is separate from the matching rule's severity.

`event-index` is the one-based document ordinal within its containing detection.
`raw-event` retains normalized context including unmapped data, and is required
along with `event-index`. A cached result without event data may still preserve
its document/path reference; missing fields remain absent.

Keep exact source export bytes in a separate `file` or `original-imported-file`
object. Link source export → event context with `derived-from`, event context →
its detection with `derived-from`, and detection → matched event context with
`describes`. This follows the relationship catalogue's original-to-derived
direction. Do not use a rule ID as an event record ID.

Keep high-precision, local/ambiguous or otherwise unrepresentable source times in
`timestamp-raw`/raw evidence. Populate `event-time` only when the source has a known
offset and supported precision. Do not substitute collection/import time.

All relations default to non-IDS and disabled correlation. The existing
`python-evtx-event-log` template requires source/type/name fields not guaranteed
by these exports and has no dedicated EventRecordID relation. This template
avoids inventing required metadata while keeping aggregate member identity.
