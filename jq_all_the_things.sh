#!/bin/bash

# Seeds sponge, from moreutils

#Validate all Jsons first
for dir in `find . -name "*.json"`
do
  echo validating ${dir}
  # python3 -c "import json; f_in = open('${dir}'); data = json.load(f_in); f_in.close(); f_out = open('${dir}', 'w'); json.dump(data, f_out, indent=2, sort_keys=True, ensure_ascii=False); f_out.close();"
  cat ${dir} | jq . >/dev/null
  rc=$?
  if [[ $rc != 0 ]]; then exit $rc; fi
  cat ${dir} | jq -r .uuid | uuidparse
done

set -e
set -x

# Seeds sponge, from moreutils

for dir in objects/*/definition.json
do
    cat ${dir} | jq -S -j . | sponge ${dir}
done

cat relationships/definition.json | jq -S -j . | sponge relationships/definition.json

cat schema_objects.json | jq . | sponge schema_objects.json
cat schema_relationships.json | jq . | sponge schema_relationships.json
