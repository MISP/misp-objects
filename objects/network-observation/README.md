# Sensor network observations

This template represents individual Zeek/Suricata records with their source,
signature, timestamp and capture context. Reuse `network-connection` for derived
connection tuples and `pcap-metadata` for explicit capture references. Existing
Suricata rule objects describe rule text; a SID/message does not provide a rule body.

`tool`, `log-type`, `record-index`, `raw-record` and `source-sha256` are required.
`sensor` and `tool-version` preserve producer context when supplied. The source
hash identifies the exact imported log/export, not an underlying packet capture.
`capture-file`, `capture-sha256`, `capture-url` and native `packet-number` retain
capture provenance. Do not open referenced paths/URLs or assign a default hash to
a different native capture name. Separate collector context can be retained in
`source-context`; its claims are not authenticated by an external log hash.

Keep `zeek-uid`, `flow-id`, transaction IDs and Community IDs scoped to sensor,
capture and run. Equal IDs or tuples alone must not merge records. Community ID
version/seed/time scope matter when comparing sensors; do not compute IDs using
an assumed seed. Invalid or unsupported IDs stay in raw data instead of normalized
identifier fields. Preserve full unsigned 64-bit flow IDs without floating-point
conversion.

`event-time` is the source observation timestamp, not necessarily the first packet
of a connection. Explicit source flow bounds may populate `flow-start/end` when
consistent. Zeek `conn.ts` defines connection start, while other stream timestamps
do not. Do not round binary duration artifacts into invented end times. Normalize
only known-offset timestamps representable without sub-microsecond rounding; raw
decimal values and original offset context remain in `timestamp-raw`/`raw-record`.

Raw JSON preserves protocol fields, payload references and unmapped content. For
Zeek ASCII logs, raw context includes original lines, escaped columns, type/marker
headers and decoded values so unset, empty and literal values remain distinct even
without the complete log attachment. `record-index` is the original log record
ordinal, not a PCAP packet index. A filtered importer should omit the full source
attachment if it would disclose excluded records, while retaining selected raw
records and the original externally retained export's hash/size/name.

Following the relationship catalogue, capture metadata and source exports point
to derived observations with `derived-from`; observations point to derived
connections and can also `describe` them. Source sensor signatures, notices,
severities and actions remain unreviewed observations, distinct from analyst
conclusions. A blocked/allowed action does not independently prove maliciousness
or remediation. All fields default to non-IDS and non-correlating.
