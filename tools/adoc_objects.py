#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#    A simple converter of MISP objects to asciidoctor format
#    Copyright (C) 2017-2019 Alexandre Dulaunoy
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
    dedication = "\n[dedication]\n== Funding and Support\nThe MISP project is financially and resource supported by https://www.circl.lu/[CIRCL Computer Incident Response Center Luxembourg ].\n\nimage:{images-misp}logo.png[CIRCL logo]\n\nA CEF (Connecting Europe Facility) funding under CEF-TC-2016-3 - Cyber Security has been granted from 1st September 2017 until 31th August 2019 as ***Improving MISP as building blocks for next-generation information sharing***.\n\nimage:{images-misp}en_cef.png[CEF funding]\n\nIf you are interested to co-fund projects around MISP, feel free to get in touch with us.\n\n"
    doc = doc + ":toc: right\n"
    doc = doc + ":toclevels: 1\n"
    doc = doc + ":toc-title: MISP Objects\n"
    doc = doc + ":icons: font\n"
    doc = doc + ":sectanchors:\n"
    doc = doc + ":sectlinks:\n"
    doc = doc + ":images-cdn: https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/logos/\n"
    doc = doc + ":images-misp: https://www.misp-project.org/assets/images/\n"
    doc = doc + "\n= MISP Objects\n\n"
    doc = doc + "= Introduction\n"
    doc = doc + "\nimage::{images-cdn}misp-logo.png[MISP logo]\n"
    doc = doc + "The MISP threat sharing platform is a free and open source software helping information sharing of threat intelligence including cyber security indicators, financial fraud or counter-terrorism information. The MISP project includes multiple sub-projects to support the operational requirements of analysts and improve the overall quality of information shared.\n\n"
    doc = doc + ""
    doc = "{}{}".format(doc, "\nMISP objects are used in MISP (starting from version 2.4.80) system and can be used by other information sharing tool.  MISP objects are in addition to MISP attributes to allow advanced combinations of attributes. The creation of these objects and their associated attributes are based on real cyber security use-cases and existing practices in information sharing. The objects are just shared like any other attributes in MISP even if the other MISP instances don't have the template of the object.\n")
    doc = doc + "The following document is generated from the machine-readable JSON describing the https://github.com/MISP/misp-objects[MISP objects]."
    doc = doc + "\n\n"
    doc = doc + "<<<\n"
    doc = doc + dedication
    doc = doc + "<<<\n"
    doc = doc + "= MISP objects\n"
    return doc


def asciidoc(content=False, adoc=None, t='title', title=''):

    adoc = adoc + "\n"
    output = ""
    if t == 'title':
        output = '== ' + content
    elif t == 'info':
        content = content.rstrip('.')
        output = "\n{}.\n\n{} {} {}{}/definition.json[*this location*] {}.\n".format(content, 'NOTE: ', title, 'is a MISP object available in JSON format at https://github.com/MISP/misp-objects/blob/main/objects/', title.lower(), ' The JSON format can be freely reused in your application or automatically enabled in https://www.github.com/MISP/MISP[MISP]')
    elif t == 'author':
        output = '\nauthors:: {}\n'.format(' - '.join(content))
    elif t == 'value':
        output = '=== ' + content
    elif t == 'description':
        content = content.rstrip('.')
        output = '\n{}\n'.format(content)
    elif t == 'attributes':
        # output = '\n{}\n'.format
        # output = '[cols=\",a\"]\n'
        output = output + '|===\n'
        output = output + '|Object attribute | MISP attribute type | Description | Disable correlation | Multiple\n'
        adoc = adoc + output
        for v in content['attributes']:
            disableCorrelation = 'icon:minus[] '
            description = 'icon:minus[] '
            multiple = 'icon:minus[] '
            if 'disable_correlation' in content['attributes'][v]:
                if content['attributes'][v]['disable_correlation']:
                    disableCorrelation = 'icon:check[] '
            if 'multiple' in content['attributes'][v]:
                if content['attributes'][v]['multiple']:
                    multiple = 'icon:check[] '
            if 'description' in content['attributes'][v]:
                if content['attributes'][v]['description']:
                    description = '{}'.format(content['attributes'][v]['description'])
                if 'values_list' in content['attributes'][v]:
                    values = content['attributes'][v]['values_list']
                    description = '{} {}'.format(content['attributes'][v]['description'], values)
                if 'sane_default' in content['attributes'][v]:
                    values = content['attributes'][v]['sane_default']
                    description = '{} {}'.format(content['attributes'][v]['description'], values)
            output = '\n| {} | {} a| {} a| {} a| {}\n'.format(v, content['attributes'][v]['misp-attribute'], description, disableCorrelation, multiple)
            adoc = adoc + output
        output = '\n|===\n'
    adoc = adoc + output
    return adoc


adoc = ""
print(header(adoc=adoc))

for mispobject in objects:
    fullPathClusters = os.path.join(pathObjects, '{}/{}'.format(mispobject, 'definition.json'))
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
    output = output + '\nRelationships are part of MISP object and available in JSON format at https://github.com/MISP/misp-objects/blob/main/relationships/definition.json[this location]. The JSON format can be freely reused in your application or automatically enabled in https://www.github.com/MISP/MISP[MISP].\n'
    output = output + '|===\n'
    output = output + '|Name of relationship | Description | Format\n'
    for relationship in rel['values']:
        output = output + '\n| {} | {} | {}\n'.format(relationship['name'], relationship['description'], str(relationship['format']))
    output = output + '\n|===\n'
    adoc = adoc + output


print(adoc)
