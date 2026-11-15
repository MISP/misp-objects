# Velociraptor result

This object retains one Velociraptor result row and its collection provenance.
Use existing `process`, `file`, `network-socket` and `windows-service` objects for
typed observations rather than duplicating their fields here.

Required fields are `artifact`, `row`, `row-number` and `source-sha256`. For example:

| Relation | Example |
| --- | --- |
| artifact | `Windows.System.Pslist` |
| client-id | `C.example` |
| server-id | `dfir-production` |
| flow-id | `F.example` |
| hunt-id | `H.example` |
| hostname | `workstation.example` |
| collected-at | `2026-11-15T10:00:00Z` |
| row-number | `1` |
| row | `{"Pid":123,"Ppid":4,"Name":"example.exe"}` |
| source-sha256 | SHA-256 of the exact original export bytes |
| source-format | `jsonl` |
| parser-version | `velociraptor_import/1.0` |

Missing collection context should remain absent. Identifier scope is the
originating deployment; supply `server-id` when combining independent servers.
`collected-at` is an explicitly known collection time, not import time or the
occurrence time of activity described in the row. `row-number` is the one-based
record ordinal, excluding CSV headers and blank JSONL lines.

Keep the original export in a `file` or `original-imported-file` object, then:

- Link the source export to this row with `derived-from`.
- Link this row to mapped observations with `derived-from`.
- Optionally also link this row to mapped observations with `describes`.

The [relationship catalogue](../../relationships/definition.json) defines the
target's information as being based on the source's information. Consequently,
the `derived-from` chain runs from source export to result row to mapped
observation, rather than back toward the original evidence.

The `row` is normalized JSON, not a byte-preserving replacement for the source
export. It may retain fields that the importer cannot map. Original bytes and
numeric/timestamp precision remain authoritative in the source attachment.
All relations default to `to_ids=false` and disabled correlation: collecting a
row is not a finding of malicious activity.

Existing forensic-case/evidence templates describe cases and acquired evidence,
and edr-report describes reports/attachments; none expresses this artifact-row
identity and context. No new relationship type or attribute type is required.
