#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from glob import glob
import json
from typing import Dict

all_uuids: Dict[str, str] = {}
for definition in glob('./objects/*/definition.json'):
    with open(definition, 'r') as f:
        d = json.load(f)
        uuid = d['uuid']
        name = d['name']
        if all_uuids.get(uuid):
            raise Exception('Same uuid for {} and {} ({})'.format(name, all_uuids.get(uuid), uuid))
        all_uuids[uuid] = name
