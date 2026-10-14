#!/usr/bin/env python3
"""Check catalogue constraints that cannot be expressed by the JSON Schema."""

import argparse
import json
import sys
from pathlib import Path


# Preserve this exact historical identifier until existing references migrate.
# New relationships must not introduce leading or trailing whitespace.
LEGACY_WHITESPACE_NAMES = frozenset({"is-allied-with "})


def validate_relationships(catalogue: dict) -> list[str]:
    errors = []
    if not isinstance(catalogue, dict) or not isinstance(catalogue.get("values"), list):
        return ["The catalogue must contain a values array."]

    relationships = {}
    for index, relationship in enumerate(catalogue["values"]):
        if not isinstance(relationship, dict):
            errors.append(f"Relationship at index {index} must be an object.")
            continue

        name = relationship.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"Relationship at index {index} must have a nonempty name.")
            continue
        if name != name.strip() and name not in LEGACY_WHITESPACE_NAMES:
            errors.append(f"Relationship {name!r} has leading or trailing whitespace.")
        if name in relationships:
            errors.append(f"Duplicate relationship name: {name!r}.")
        else:
            relationships[name] = relationship

        description = relationship.get("description")
        if not isinstance(description, str) or not description.strip():
            errors.append(f"Relationship {name!r} must have a nonempty description.")

        formats = relationship.get("format")
        if not isinstance(formats, list) or not formats:
            errors.append(f"Relationship {name!r} must have a nonempty format array.")
        else:
            for value in formats:
                if not isinstance(value, str) or not value.strip() or value != value.strip():
                    errors.append(f"Relationship {name!r} has an invalid format: {value!r}.")

    for name, relationship in relationships.items():
        if "opposite" not in relationship:
            continue
        opposite = relationship["opposite"]
        if not isinstance(opposite, str) or not opposite.strip():
            errors.append(f"Relationship {name!r} must have a nonempty opposite name.")
        elif opposite not in relationships:
            errors.append(f"Relationship {name!r} has an unknown opposite: {opposite!r}.")
        elif relationships[opposite].get("opposite") != name:
            errors.append(f"Opposite {opposite!r} does not point back to {name!r}.")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalogue", nargs="?", type=Path, default=Path("relationships/definition.json"))
    args = parser.parse_args()
    try:
        with args.catalogue.open(encoding="utf-8") as source:
            catalogue = json.load(source)
    except (OSError, ValueError) as error:
        print(f"ERROR: Cannot read {args.catalogue}: {error}", file=sys.stderr)
        return 1

    errors = validate_relationships(catalogue)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"OK, {len(catalogue['values'])} relationship names and declared opposites are valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
