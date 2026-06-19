#!/usr/bin/env bash

OUTPUT="objects.md"

{
    echo "| Object Name | Icon |"
    echo "|------------|------|"

    for dir in ../objects/*/; do
        [ -d "$dir" ] || continue

        name="$(basename "$dir")"
        icon_path="${dir}icon/icon.svg"

        if [ -f "$icon_path" ]; then
            echo "| ${name} | <img src=\"${icon_path#./}\" width=\"24\"> |"
        else
            echo "| ${name} | |"
        fi
    done
} > "$OUTPUT"

echo "Generated $OUTPUT"
