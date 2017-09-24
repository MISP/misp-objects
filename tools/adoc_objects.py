#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#    A simple converter of MISP objects to asciidoctor format
#    Copyright (C) 2017 Alexandre Dulaunoy
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

argParser = argparse.ArgumentParser(description='Generate documentation from MISP objects', epilog='Available objects are {0}'.format(objects))
argParser.add_argument('-v', action='store_true', help='Verbose mode')
args = argParser.parse_args()

def header(adoc=False):
    if adoc is False:
        return False
    doc = adoc
    doc = doc + ":toc: right\n"
#    doc = doc + ":doctype: book\n"
    doc = doc + ":toclevels: 1\n"
    doc = doc + ":toc-title: MISP Objects\n"
    doc = doc + ":icons: font\n"
    doc = doc + ":sectanchors:\n"
    doc = doc + ":sectlinks:\n"
    doc = doc + ":images-cdn: https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/logos/\n"
    doc = doc + "\n= MISP Objects\n\n"
    doc = doc + "Generated from https://github.com/MISP/misp-objects.\n\n"
    doc = doc + "\nimage::{images-cdn}misp-logo.png[MISP logo]\n"
    doc = "{}{}".format(doc, "\nMISP MISP objects to be used in MISP (2.4.80) system and can be used by other information sharing tool. MISP objects are in addition to MISP attributes to allow advanced combinations of attributes. The creation of these objects and their associated attributes are based on real cyber security use-cases and existing practices in information sharing.\n")
    doc = doc + "\n\n"

    return doc

def asciidoc(content=False, adoc=None, t='title',title=''):

    adoc = adoc + "\n"
    output = ""
    if t == 'title':
        output = '== ' + content
    elif t == 'info':
        output = "\n{}.\n\n{} {} {}{}/definition.json[*this location*] {}.\n".format(content, 'NOTE: ', title, 'is a MISP object available in JSON format at https://github.com/MISP/misp-objects/blob/master/objects/',title.lower(),' The JSON format can be freely reused in your application or automatically enabled in https://www.github.com/MISP/MISP[MISP]')
    elif t == 'author':
        output = '\nauthors:: {}\n'.format(' - '.join(content))
    elif t == 'value':
        output = '=== ' + content
    elif t == 'description':
        output = '\n{}\n'.format(content)
    elif t == 'attributes':
        #output = '\n{}\n'.format
        #output = '[cols=\",a\"]\n'
        output = output + '|===\n'
        output = output + '|Object attribute | MISP attribute type | Description | Disable correlation\n'
        adoc = adoc + output
        for v in content['attributes']:
            disableCorrelation = 'icon:minus[] '
            description = 'icon:minus[] '
            if 'disable_correlation' in content['attributes'][v]:
                if content['attributes'][v]['disable_correlation']:
                    disableCorrelation = 'icon:check[] '
            if 'description' in content['attributes'][v]:
                if content['attributes'][v]['description']:
                    values = ''
                if 'values_list' in content['attributes'][v]:
                    values = content['attributes'][v]['values_list']
                    description = '{} {}'.format(content['attributes'][v]['description'],values)
                if 'sane_default' in content['attributes'][v]:
                    values = content['attributes'][v]['sane_default']
                    description = '{} {}'.format(content['attributes'][v]['description'],values)
            output = '\n| {} | {} a| {} a| {}\n'.format(v, content['attributes'][v]['misp-attribute'], description ,disableCorrelation)
            adoc = adoc + output
        output = '\n|===\n'
    adoc = adoc + output
    return adoc

adoc = ""
print (header(adoc=adoc))

for mispobject in objects:
    fullPathClusters = os.path.join(pathObjects, '{}/{}'.format(mispobject,'definition.json'))
    with open(fullPathClusters) as fp:
        c = json.load(fp)
    title = c['name']
    adoc = asciidoc(content=title, adoc=adoc, t='title')
    adoc = asciidoc(content=c['description'], adoc=adoc, t='info', title=title)
    adoc = asciidoc(content=c, adoc=adoc, t='attributes', title=title)

with open('../relationships/definition.json') as filerelationships:
    rel = json.load(filerelationships)

    output = '== Relationships\n'
    output = output + '\n{}\n'.format(rel['description'])
    output = output + '\nRelationships are part of MISP object and available in JSON format at https://github.com/MISP/misp-objects/blob/master/relationships/definition.json[this location]. The JSON format can be freely reused in your application or automatically enabled in https://www.github.com/MISP/MISP[MISP].\n'
    output = output + '|===\n'
    output = output + '|Name of relationship | Description | Format\n'
    for relationship in rel['values']:
        output = output + '\n| {} | {} | {}\n'.format(relationship['name'], relationship['description'], str(relationship['format']))
    output = output + '\n|===\n'
    adoc = adoc + output

print (adoc)
