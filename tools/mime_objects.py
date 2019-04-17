#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#    A simple tool to build to file metadata misp-objects.
#    Copyright (C) 2019 Roger Johnston
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
from dateutil.parser import *
from datetime import *
import magic
import subprocess
import re
import uuid


class ExifDefinition:
    def __init__(self):
        self.exiftool_repo = 'https://github.com/exiftool/exiftool.git'
        self.tmp_dir = '/tmp/'
        self.exiftool_t_files = []
        self.mimetype_misp_objects = {}

    def clone_exiftool(self):
        """
        Git clone Phil Harvey's ExifTool to self.tmp_dir.
        See: https://www.sno.phy.queensu.ca/~phil/exiftool/
        :return:
        """
        p1 = subprocess.Popen(("git", "clone", "https://github.com/exiftool/exiftool.git"), stdout=subprocess.PIPE,
                              cwd=self.tmp_dir)
        p1.wait()

    def strip_mime_name(self, mime_name):
        """
        Remove non-alphanumerics from string.
        :param mime_name:
        :return:
        """
        return re.sub(r'\W', '-', mime_name)

    def generate_exiftool_t_files(self):
        """
        Generates a list of ExifTool test file paths.
        :return:
        """
        for root, dirs, files in os.walk(self.tmp_dir + 'exiftool/t/images/'):
            for name in files:
                a_file = os.path.join(root, name)
                self.exiftool_t_files.append(a_file)

    def build_mime_type_list(self):
        """
        Uses python-magic to build a dict of MIME types.
        :return:
        """
        for each_file in self.exiftool_t_files:
            # Magic used to find MIME type.
            mime_type = self.strip_mime_name(magic.from_file(each_file, mime=True))

            if mime_type not in self.mimetype_misp_objects:
                self.mimetype_misp_objects[mime_type] = {}

    def add_exif_tags(self):
        """
        Populates each MIME type dictionary with the relevant ExifTool tags.
        :return:
        """
        for each_file in self.exiftool_t_files:
            # exiftool flags:
            # -g2 : print category names
            # https://www.sno.phy.queensu.ca/~phil/exiftool/#groups
            # -n : no print conversion
            # -j : export as json
            # -l : use long output format (description)
            # -b : binary output
            p = subprocess.Popen(("exiftool", "-g2", "-j", "-l", "-b", each_file), stdout=subprocess.PIPE)
            output = p.communicate()[0]

            # Decode subprocess bytes output as UTF-8.
            metadata = json.loads(output.decode('utf-8'))[0]


            mime_type = self.strip_mime_name(magic.from_file(each_file, mime=True))

            for k, v in metadata.items():
                sanitized_key_name = self.strip_mime_name(k)

                if sanitized_key_name not in self.mimetype_misp_objects[mime_type]:
                    self.mimetype_misp_objects[mime_type][sanitized_key_name] = {}

                if isinstance(v, dict):
                    print(v)
                    for j, w in v.items():
                        # if j == 'SourceFile'
                        if self.strip_mime_name(j) not in self.mimetype_misp_objects[mime_type][sanitized_key_name]:
                            self.mimetype_misp_objects[mime_type][sanitized_key_name][self.strip_mime_name(j)] = w

    def create_mime_definitions(self):
        """
        Creates a misp-object folder and definition for each MIME type in self.mimetype_misp_objects.
        :return:
        """
        for mime, groups in self.mimetype_misp_objects.items():
            for group_name, group_keys in groups.items():
                if group_name == 'ExifTool':
                    continue
                if group_name == 'SourceFile':
                    continue

                # Create a folder for each misp-object.
                folder = '../objects/MIME-' + mime + '-' + group_name.lower()
                try:
                    os.mkdir(folder)
                except FileExistsError:
                    pass

                f = open(folder + '/definition.json', 'w')

                # Default definition values.
                mime_definition = {'name': mime,
                                   'meta-category': 'file',
                                   'description': 'Object describing file metadata.',
                                   'version': 1,
                                   'requiredOneof': [],
                                   'uuid': str(uuid.uuid4()),
                                   'attributes': {}
                                   }

                if isinstance(group_keys, dict):
                    for k, v in group_keys.items():
                        mime_definition['requiredOneof'].append(k)

                        # Default attribute values.
                        text_attribute = {"misp-attribute": "text", "ui-priority": 0, "disable_correlation": True}

                        # Set attribute description value.
                        if isinstance(v, dict):
                            text_attribute["description"] = v['desc']
                        else:
                            text_attribute["description"] = v

                        # Set misp-attribute to MIME type.
                        if 'MIME' in k or 'MimeType' in k:
                            text_attribute["misp-attribute"] = 'mime-type'

                        # Check if attribute is a valid datetime.
                        try:
                            is_date = parse(v['val'])
                            if isinstance(is_date, datetime):
                                text_attribute["misp-attribute"] = 'datetime'
                        except TypeError:
                            pass
                        except ValueError:
                            pass
                        except OverflowError:
                            pass

                        mime_definition['attributes'][k] = text_attribute
                else:
                    text_attribute = {"misp-attribute": "text", "ui-priority": 0, "disable_correlation": True}
                    text_attribute["description"] = group_keys
                    mime_definition['attributes'][group_name] = text_attribute

                f.write(json.dumps(mime_definition, sort_keys=True, indent=4))
                f.close()

    def run(self):
        self.clone_exiftool()
        self.generate_exiftool_t_files()
        self.build_mime_type_list()
        self.add_exif_tags()
        self.create_mime_definitions()


if __name__ == '__main__':
    build_objects = ExifDefinition()
    build_objects.run()
