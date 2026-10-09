#!/bin/bash

# Keep the existing entry point while parsing JSON instead of grepping text.
exec python3 "$(dirname "$0")/validate_relationships.py" "$@"
