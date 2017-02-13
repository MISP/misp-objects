#!/bin/bash

set -e
set -x

# Seeds sponge, from moreutils

for dir in objects/*/definition.json
do
    cat ${dir} | jq . | sponge ${dir}
done

cat schema.json | jq . | sponge schema.json
