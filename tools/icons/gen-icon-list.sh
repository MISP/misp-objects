#!/usr/bin/env bash

shopt -s nullglob

OUTPUT="objects.md"

{
    echo "| Object Name | Icon |"
    echo "|------------|------|"

    for dir in ../../objects/*/; do
        [ -d "$dir" ] || continue

        name="$(basename "$dir")"
        icon_path="${dir}icon/icon.svg"

        if [ -f "$icon_path" ]; then
            echo "| ${name} | <img src=\"${icon_path#./}\" width=\"24\"> |"
        else
            echo "| ${name} | |"
        fi
    done

    # File type icon variants generated into the file object's icon directory
    # (see gen-file-type-icons.js).
    variants=(../../objects/file/icon/file-*.svg)
    if [ ${#variants[@]} -gt 0 ]; then
        echo ""
        echo "## File type icons"
        echo ""
        echo "| File Type | Icon |"
        echo "|-----------|------|"
        for icon_path in "${variants[@]}"; do
            type="$(basename "$icon_path" .svg)"   # file-csv
            type="${type#file-}"                    # csv
            echo "| ${type} | <img src=\"${icon_path#./}\" width=\"24\"> |"
        done
    fi
} > "$OUTPUT"

echo "Generated $OUTPUT"
