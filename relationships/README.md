# MISP object relationships

`definition.json` is the catalogue of relationship names offered to MISP users.
An object reference has a source and a target; read its description in that order.
For example, `document --authored-by--> person` and
`person --is-author-of--> document` express the same authorship with reversed
endpoints. An `opposite` must point to the relationship that reverses those
endpoints, and the other entry must point back.

Not every relationship needs an opposite. Do not infer that a relationship is
symmetric or transitive merely because it lacks inverse metadata. Friendship
or a reported attitude can be one-sided.

## Download endpoints

A download can involve three distinct objects:

- `process --downloaded/downloads--> file`: downloader to downloaded artifact.
- `file --downloaded-from/downloads-from--> URL`: artifact to origin.

These are not inverse edges: reversing the first would connect the file to the
downloader, not to the URL. Version 56 removes the incorrect inverse metadata
between these pairs while retaining all four identifiers and their endpoint
meanings. Consumers that previously relied on that metadata should review their
reverse-edge handling; the catalogue update does not rewrite stored references.

## Legacy spellings

Existing identifiers remain accepted. Use the following spellings for new
references; the catalogue does not automatically rename old references.
Here `␠` represents one trailing ASCII space.

| Legacy identifier | Preferred identifier |
| --- | --- |
| `is-allied-with␠` | `is-allied-with` |
| `preceeds` | `precedes` |
| `ambivalient-of` | `ambivalent-of` |

`precedes` places the earlier object at the source and the later object at the
target, like `followed-by`. It is not a same-direction alias of `preceded-by`.
`targeted-by` and `is-targeted-by` are both retained; prefer `targeted-by` for
new MISP references because it is the declared opposite of `targets`.

The capitalized XFN identifiers are preserved. In particular,
`source --Child--> target` means the target is the source's child, whereas
`source --Parent--> target` means the target is the source's parent.
These have the directions of `parent-of` and `child-of`, respectively.
Do not lowercase imported labels or infer reciprocal friendship automatically.

## Format tags and standard-specific directions

`format` records the catalogue's vocabulary/format associations. Its tags alone
are not a specification of an exporter mapping or a guarantee that a term is a
native predicate in the named standard. MISP imports catalogue entries
regardless of whether they carry the `misp` tag.

The [STIX 2.1 specification, section 3.7](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
defines `derived-from` with the original object at the source and the derivative
at the target. The catalogue retains this published direction despite its
unintuitive name. `based-on`, `extracted-from` and `retrieved-from` place the
dependent item at the source; converting between them can require reversing
endpoints.

STIX allows user-defined relationship types, but exporters must still enforce
its endpoint types and lowercase ASCII/digit/hyphen restriction. Capitalized XFN
labels and the padded legacy identifier require an explicit export mapping.
Similarly, a `foaf` tag does not establish a native FOAF predicate; consult the
[FOAF vocabulary](https://xmlns.com/foaf/spec/) before choosing a mapping.

## Validation

From the repository root, run:

```bash
jsonschema -i relationships/definition.json schema_relationships.json
./tools/validate_opposites.sh
python3 -B -m unittest discover -s tests -v
```

The shell entry point delegates to a JSON-aware Python validator. It checks
unique names, nonempty descriptions/formats, name whitespace, existing inverse
targets and reciprocal inverse links. The exact historical `is-allied-with␠`
identifier is the sole exception to the name-whitespace rule. XFN capitalization
is valid. An optional path allows validation of another catalogue:

```bash
./tools/validate_opposites.sh /path/to/definition.json
```

These checks also run in `validate_all.sh`. The full script normalizes JSON and
requires a clean Git tree. Normalize edited JSON before committing and bump the
catalogue version whenever its definitions change; retain the catalogue UUID.

## Further vocabulary work

Similar names are not automatically interchangeable. Clarifying imported
payment/award roles (`paid`, `awarded-to`), registrar versus registrant
(`registered`, `registered-to`), and injector/payload/destination roles needs
representative producer data before changing their established meanings.
Domain additions such as document holding or evidentiary relevance should
define their endpoints and explain how they differ from existing relationships.
