import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft7Validator

from tools.validate_relationships import validate_relationships


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema_relationships.json").read_text(encoding="utf-8"))
CATALOGUE = json.loads((ROOT / "relationships/definition.json").read_text(encoding="utf-8"))


def catalogue():
    return {
        "name": "relationships",
        "description": "Relationships for validation tests.",
        "uuid": "b002c0d6-320f-450d-82c4-b3aa15bbbd6c",
        "version": 1,
        "values": [
            {
                "name": "parent-of",
                "description": "The source is a parent of the target.",
                "format": ["misp"],
                "opposite": "child-of",
            },
            {
                "name": "child-of",
                "description": "The source is a child of the target.",
                "format": ["misp"],
                "opposite": "parent-of",
            },
        ],
    }


class RelationshipValidationTests(unittest.TestCase):
    def test_current_catalogue(self):
        Draft7Validator.check_schema(SCHEMA)
        Draft7Validator(SCHEMA).validate(CATALOGUE)
        self.assertEqual(validate_relationships(CATALOGUE), [])

    def test_duplicate_name_with_different_description(self):
        data = catalogue()
        duplicate = copy.deepcopy(data["values"][0])
        duplicate["description"] = "Another description of the same relation."
        data["values"].append(duplicate)
        # uniqueItems compares whole records, so a separate name check is needed.
        self.assertTrue(Draft7Validator(SCHEMA).is_valid(data))
        self.assertTrue(any("Duplicate relationship name" in error for error in validate_relationships(data)))

    def test_unknown_opposite(self):
        data = catalogue()
        data["values"][0]["opposite"] = "missing"
        self.assertTrue(any("unknown opposite" in error for error in validate_relationships(data)))

    def test_existing_but_nonreciprocal_opposite(self):
        data = catalogue()
        data["values"][1]["opposite"] = "child-of"
        self.assertTrue(any("does not point back" in error for error in validate_relationships(data)))

    def test_missing_reverse_link(self):
        data = catalogue()
        del data["values"][1]["opposite"]
        self.assertTrue(any("does not point back" in error for error in validate_relationships(data)))

    def test_unpaired_relationship_is_allowed(self):
        data = catalogue()
        for relationship in data["values"]:
            del relationship["opposite"]
        self.assertEqual(validate_relationships(data), [])

    def test_explicit_self_inverse_is_allowed(self):
        data = catalogue()
        data["values"] = [{
            "name": "same-as",
            "description": "The source and target denote the same entity.",
            "format": ["misp"],
            "opposite": "same-as",
        }]
        self.assertEqual(validate_relationships(data), [])

    def test_new_padded_names_are_rejected(self):
        for name in [" padded", "padded ", "\tpadded", "padded\n", "is-allied-with  "]:
            with self.subTest(name=name):
                data = catalogue()
                data["values"][0]["name"] = name
                self.assertTrue(any("whitespace" in error for error in validate_relationships(data)))

    def test_exact_legacy_name_and_xfn_case_are_allowed(self):
        data = catalogue()
        data["values"] = [
            {"name": name, "description": "A historical relationship.", "format": ["misp"]}
            for name in ["is-allied-with ", "is-allied-with", "Friend", "Child", "Parent"]
        ]
        self.assertEqual(validate_relationships(data), [])

    def test_literal_names_are_not_regular_expressions(self):
        data = catalogue()
        data["values"][0]["name"] = "literal[1].*"
        data["values"][1]["opposite"] = "literal[1].*"
        self.assertEqual(validate_relationships(data), [])
        data["values"][1]["opposite"] = "literal1-extra"
        self.assertTrue(any("unknown opposite" in error for error in validate_relationships(data)))

    def test_malformed_catalogue_structure(self):
        for data in [None, [], {}, {"values": None}, {"values": "not an array"}, {"values": [None]}]:
            with self.subTest(data=data):
                self.assertTrue(validate_relationships(data))

    def test_blank_or_wrong_type_fields(self):
        cases = [
            ("name", ""), ("name", " \t"), ("name", None),
            ("description", ""), ("description", "\n"), ("description", None),
            ("format", []), ("format", None), ("format", [""]), ("format", ["  "]),
            ("format", ["misp "]), ("format", [123]),
            ("opposite", ""), ("opposite", " \t"), ("opposite", None),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                data = catalogue()
                data["values"][0][key] = value
                self.assertTrue(validate_relationships(data))

    def test_schema_rejects_empty_definition_fields(self):
        cases = [
            ("name", ""), ("name", " \t"), ("description", ""), ("description", "\n"),
            ("format", []), ("format", [""]), ("format", ["\t"]),
            ("opposite", ""), ("opposite", " "),
        ]
        validator = Draft7Validator(SCHEMA)
        for key, value in cases:
            with self.subTest(key=key, value=value):
                data = catalogue()
                data["values"][0][key] = value
                self.assertFalse(validator.is_valid(data))

    def test_schema_still_rejects_unknown_fields_and_duplicate_formats(self):
        validator = Draft7Validator(SCHEMA)
        data = catalogue()
        data["values"][0]["alias"] = "another-name"
        self.assertFalse(validator.is_valid(data))
        data = catalogue()
        data["values"][0]["format"] = ["misp", "misp"]
        self.assertFalse(validator.is_valid(data))

    def run_wrapper(self, content, use_default_path=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relationships/definition.json"
            path.parent.mkdir()
            path.write_text(content, encoding="utf-8")
            command = ["bash", str(ROOT / "tools/validate_opposites.sh")]
            if not use_default_path:
                command.append(str(path))
            return subprocess.run(command, cwd=directory, capture_output=True, text=True)

    def test_wrapper_accepts_compact_json_in_another_directory(self):
        result = self.run_wrapper(json.dumps(catalogue(), separators=(",", ":")))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK,", result.stdout)

    def test_wrapper_preserves_default_path(self):
        result = self.run_wrapper(json.dumps(catalogue()), use_default_path=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrapper_fails_for_nonreciprocal_links(self):
        data = catalogue()
        del data["values"][1]["opposite"]
        result = self.run_wrapper(json.dumps(data))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not point back", result.stderr)
        self.assertNotIn("OK,", result.stdout)

    def test_wrapper_fails_for_invalid_json(self):
        result = self.run_wrapper("{")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot read", result.stderr)

    def test_wrapper_fails_for_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["bash", str(ROOT / "tools/validate_opposites.sh"), str(Path(directory) / "missing.json")],
                capture_output=True, text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot read", result.stderr)

    def test_download_roles_do_not_claim_origin_is_downloader(self):
        relationships = {relationship["name"]: relationship for relationship in CATALOGUE["values"]}
        for name in ["downloaded", "downloaded-from", "downloads", "downloads-from"]:
            with self.subTest(name=name):
                self.assertNotIn("opposite", relationships[name])

    def test_legacy_spellings_and_xfn_labels_are_retained(self):
        names = {relationship["name"] for relationship in CATALOGUE["values"]}
        self.assertTrue({
            "is-allied-with ", "is-allied-with", "preceeds", "precedes",
            "ambivalient-of", "ambivalent-of", "Friend", "Child", "Parent",
        }.issubset(names))

    def test_derived_from_keeps_published_stix_direction(self):
        relationship = next(item for item in CATALOGUE["values"] if item["name"] == "derived-from")
        self.assertIn("target object is based on information from the source object", relationship["description"])


if __name__ == "__main__":
    unittest.main()
