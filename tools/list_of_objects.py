#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#    A simple converter of MISP objects to asciidoctor format
#    Copyright (C) 2017-2021 Alexandre Dulaunoy
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
import json
import argparse

thisDir = os.path.dirname(__file__)

objects = []

pathObjects = os.path.join(thisDir, '../objects')

for f in os.listdir(pathObjects):
    objectName = f
    objects.append(objectName)

objects.sort()

argParser = argparse.ArgumentParser(description='Generate list of MISP object templates', epilog='Available objects are {0}'.format(objects))
argParser.add_argument('-v', action='store_true', help='Verbose mode')
args = argParser.parse_args()


for mispobject in objects:
    fullPathClusters = os.path.join(pathObjects, '{}/{}'.format(mispobject, 'definition.json'))
    with open(fullPathClusters) as fp:
        c = json.load(fp)
    if not c['description'].endswith('.'):
        c['description'] = c['description'] + "."
    v = "- [objects/{}](https://github.com/MISP/misp-objects/blob/main/objects/{}/definition.json) - {}".format(c['name'], c['name'], c['description'])
    print(v)
