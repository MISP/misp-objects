#!/bin/bash

set -e
set -x

# Seeds sponge, from moreutils

for dir in objects/*/definition.json
do
    cat ${dir} | jq . | sponge ${dir}
done

cat relationships/definition.json | jq . | sponge relationships/definition.json

cat schema_objects.json | jq . | sponge schema_objects.json
cat schema_relationships.json | jq . | sponge schema_relationships.json
