#!/bin/bash

opposites=$(cat relationships/definition.json | grep '"opposite"' | cut -d ':' -f 2 | tr -d ' ' | tr -d '"')

for opposite in $opposites
do
  cat relationships/definition.json | grep '"name": "'$opposite'"' >/dev/null 2>&1
  res=$?
  if [ "$res" -eq 1 ]
  then
    echo "'$opposite' not found"
    exit 1
  fi
done

echo "OK, all opposites seem to point to existing relationships"
exit 0
