# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This is a **data repository**, not an application. It holds the MISP object templates (and their
relationship definitions) consumed by MISP and other information-sharing tools. The "code" here is
limited to validation and documentation-generation scripts; the bulk of changes are additions or
edits to JSON template files. There are ~420 objects under `objects/`.

A MISP *object* is a named bundle of MISP *attributes* describing a real-world entity (a file, a
domain/IP tuple, a bank account, etc.). Each object is one directory: `objects/<name>/definition.json`.

## Layout

- `objects/<name>/definition.json` — one object template per directory. Validated against `schema_objects.json`.
- `objects/<name>/icon/icon.svg` — optional per-object icon (24×24 viewBox, `fill="currentColor"`). Icons are **not** part of `definition.json` (its schema is `additionalProperties: false`); they live in a sibling `icon/` subfolder.
- `relationships/definition.json` — the global list of relationship types usable between objects. Validated against `schema_relationships.json`.
- `schema_objects.json` / `schema_relationships.json` — JSON Schemas. Editing these (e.g. adding a `misp-attribute` type or `meta-category`) is what gates what object files may contain.
- `tools/` — documentation and list generators (see below).
- `binary-icon-list.csv` — manually maintained list of object names (not consumed by any script in-repo).

## Validation and the formatting contract

Two scripts matter, and CI (`.github/workflows/nosetests.yml`, Python 3.9–3.13) runs `./validate_all.sh`.

```bash
./jq_all_the_things.sh   # normalizes every *.json in place; run this after ANY json edit
./validate_all.sh        # full validation; this is what CI runs
```

`jq_all_the_things.sh` rewrites each JSON file with **sorted keys and no insignificant whitespace**
(`jq -S -j` piped through `sponge`). `validate_all.sh` then fails if `git status` is not clean —
i.e. it enforces that you ran the normalizer and committed the result. So the workflow for any edit is:
**edit JSON → run `./jq_all_the_things.sh` → commit the reformatted file.** It also strips the
executable bit from all `*.json` files (another clean-tree check).

`validate_all.sh` additionally:
- validates every `objects/*/definition.json` against `schema_objects.json` (and relationships against their schema) with the `jsonschema` CLI;
- runs `./unique_uuid.py` — **every object's `uuid` must be unique** across the repo;
- runs `tools/validate_opposites.sh` — every relationship `opposite` must name an existing relationship.

Dependencies: `jq`, `moreutils` (provides `sponge`), and the Python `jsonschema` package.

```bash
sudo apt install jq moreutils && pip install jsonschema
```

To validate or normalize a single object without the full suite:

```bash
jq . objects/<name>/definition.json >/dev/null            # syntax check
jsonschema -i objects/<name>/definition.json schema_objects.json   # schema check
```

## Authoring object templates

Required top-level fields: `name`, `meta-category`, `description`, `version`, `uuid`, `attributes`.
Optional: `required` (array), `requiredOneOf` (array).

- `uuid` — generate a **fresh** UUID for a new object; reusing one breaks `unique_uuid.py`.
- `version` — integer; **bump it on every change** to an existing object (MISP uses it to detect updates).
- `meta-category` — must be one of the enum in `schema_objects.json` (`file`, `network`, `financial`, `marine`, `transport`, `misc`, `mobile`, `internal`, `vulnerability`, `climate`, `iot`, `health`, `followthemoney`, `detection`).

Each entry under `attributes` requires `misp-attribute`, `ui-priority`, and `description`. The
`misp-attribute` value must be one of the enum in `schema_objects.json` and is **case-sensitive**
(these are MISP attribute *types*). To use a type not yet listed, add it to that enum first.
Optional per-attribute fields: `categories`, `multiple`, `values_list`, `sane_default`,
`disable_correlation`, `to_ids`, `recommended`, `ui-priority` (lower = shown less prominently).

See the README's `domain-ip` example for a canonical, fully-formed object.

## Documentation generators (run manually, not in CI)

From `tools/`:
- `python3 list_of_objects.py` — prints the markdown bullet list used in the README's "Existing MISP objects" section.
- `adoc_objects.py` + `updated.sh` — render the asciidoctor HTML/PDF docs published to the MISP website.

Icon tooling lives in `tools/icons/` (usage docs: `tools/icons/README.md`):
- `./gen-icon-list.sh` — regenerates `tools/icons/objects.md` (object → icon table). Must be run from inside `tools/icons/` (it uses relative `../../objects/`).
- `file-type-label.js` — runtime generator that stamps a file-type label (e.g. `csv`, `json`) into the base `file` icon as pixel art knocked out of the document body (`fileTypeLabel.fileIcon('csv')`); keeps the icon monochrome/`currentColor`.

## Commit messages

This repo uses gitchangelog conventions: `ACTION: [scope] message`, where ACTION is `new`, `chg`,
or `fix` (e.g. `chg: [icons] Added icons for some objects`, `fix: [malicious-package-report] updated`).
New object templates contributed via PR often appear as plain `Add <name> object template`.
