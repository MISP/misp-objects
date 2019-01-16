#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import json

name_ontology = 'alfred'

relationships_path = Path('..', 'relationships', 'definition.json')

with open(relationships_path) as f:
    relationships = json.load(f)

rel_fast_lookup = {entry['name']: entry for entry in relationships['values']}

ontology_path = Path('alfred-ontology.json')

with open(ontology_path) as f:
    ontology = json.load(f)

links = ontology['data']['linkTypes']


for linktype in links:
    link_name = linktype['name'].lower().replace('_', '-')
    link_description = linktype['description']
    if link_name in rel_fast_lookup:
        if rel_fast_lookup[link_name]['description'] != link_description:
            print(link_name)
            print('\t MISP:', rel_fast_lookup[link_name]['description'])
            print('\t Alfred:', link_description)
        for entry in relationships['values']:
            if entry['name'] == link_name:
                if name_ontology not in entry['format']:
                    entry['format'].append(name_ontology)
                break
        # Update the fast lookup to avoid duplicates.
        rel_fast_lookup = {entry['name']: entry for entry in relationships['values']}
    else:
        if link_name not in rel_fast_lookup:
            linktype['name'] = link_name
            linktype['format'] = [name_ontology]
            relationships['values'].append(linktype)
        else:
            print("Duplicate", link_name)

with open(relationships_path, 'w') as f:
    json.dump(relationships, f, indent=2)
