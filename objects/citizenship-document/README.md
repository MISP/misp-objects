# Citizenship document

Use one object per document attesting a person's citizenship or nationality. The template covers citizenship, naturalisation, registration and nationality certificates, citizenship cards and confirmation letters. Passports, national identity cards, birth certificates and consular birth records can also be represented when they serve as citizenship evidence in the relevant jurisdiction. Their names alone do not establish that they do so. Residence permits and travel documents issued to non-citizens do not establish citizenship.

All document types and acquisition bases are suggestions rather than closed lists. Preserve local terminology, Unicode names, mononyms, original scripts, leading zeros and punctuation in identifiers. A full name is sufficient; separate given, middle and family names are optional. No country, document number, photograph, expiration date or acquisition basis is mandatory. At least one document number, registry reference, full name, name in an original script, attachment or document transcription is needed.

Keep these concepts separate:

- `citizenship`: the citizenship or nationality actually attested by this document. Multiple values are available when the document explicitly attests more than one.
- `issuing-country`: the jurisdiction on whose behalf it was issued.
- `place-of-issue`: its physical place of issue, including a consulate abroad.
- `document-number`: this document's identifier; `person-number` identifies the holder and `registry-reference` identifies an associated register or case.
- `citizenship-date`: when citizenship took effect; `issue-date` and `expiration-date` describe this document's validity. An expired document does not imply expired citizenship.

Use the existing MISP date types for known dates: `date-of-birth` uses YYYY-MM-DD; the other structured dates use `datetime` and can represent a known calendar date without inventing a time of day. Preserve partial, uncertain or non-Gregorian dates verbatim in `document-text` or `text` when they cannot be reliably converted. Omit inapplicable fields rather than using invented values or sentinel dates.

Typical mappings include:

| Case | Useful attributes |
| --- | --- |
| Naturalisation certificate without an expiration date | `document-type`, `document-number`, `full-name`, `citizenship`, `acquisition-basis`, `citizenship-date`, `issue-date`, `issuing-authority` |
| Citizenship card with separate card and person numbers | `document-type`, `document-number`, `person-number`, `full-name`, `citizenship`, `issue-date`, `expiration-date` when present |
| Consular record issued abroad | `document-type`, `registry-reference`, `citizenship`, `issuing-country`, `issuing-authority`, `place-of-issue`, `parent-name` when recorded |
| Unnumbered or partially legible historical certificate | `full-name` or `name-in-original-script`, `attachment`, `document-text`, `text` |
| Electronic citizenship confirmation | `document-type`, `full-name`, `citizenship`, `attachment`, `verification-url` |

Link to `person` objects for the holder or parents instead of duplicating their complete profiles. Link to `forged-document` or `leaked-document` objects for relevant investigative context. Administrative `document-status` and a verification URL do not themselves establish authenticity. Attributes default to `to_ids: false`; general metadata disables correlation while names and identifiers retain it.
