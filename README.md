# misp-objects

MISP objects to be used in MISP (3.0) system and can be used by other information sharing tool. MISP objects
are in addition to MISP attributes to allow advanced combinations of attributes. The creation of these objects
and their associated attributes are based on real cyber security use-cases and existing practices in information sharing.

Feel free to propose your own MISP objects to be included in MISP. The system is similar to the [misp-taxonomies](https://github.com/MISP/misp-taxonomies) where anyone can contribute their own objects to be included in MISP without modifying software.

## Format of MISP objects

~~~~json
{
        "name": "domain|ip",
        "meta-category": "network",
        "description": "A domain and IP address seen as a tuple in a specific time frame.",
        "version": 1,
        "attributes" :
        {
                "ip": {
                        "misp-attribute": "ip-dst",
                        "misp-usage-frequency": 1,
                        "categories": ["Network activity","External analysis"]
                },
                "domain": {
                        "misp-attribute": "domain",
                        "misp-usage-frequency": 1,
                        "categories": ["Network activity","External analysis"]
                },
                "first-seen": {
                        "misp-attribute": "datetime",
                        "misp-usage-frequency": 0
                },
                "last-seen": {
                        "misp-attribute": "datetime",
                        "misp-usage-frequency": 0
                }

        },
        "required": ["ip","domain"]
}
~~~~

A MISP object is described in a simple JSON file containing the following element.

* **name** is the name of the your object.
* **meta-category** is the category where the object falls into. (file, network, financial)
* **description** is a summary of the object description.
* **version** is the version number as a decimal value.
* **required** is an array containing the minimal required attributes to describe the object.
* **requiredOneOf** is an array containing the attributes where at least one need to be present to describe the object.
* **attributes** contains another JSON object listing all the attributes composing the object.

Each attribute must contain a reference **misp-attribute** to reference an existing attribute definition in MISP.
An array **categories** must be used to described in which categories the attribute is. The **misp-usage-frequency**
is describing the usage frequency of an attribute. This helps to display only the most frequently used attributes and
allowing advanced users to show all the attributes depending of their configuration.

## Existing MISP objects

* [objects/domain-ip](objects/domain-ip/definition.json) - A domain and IP address seen as a tuple in a specific time frame.
* [objects/file](objects/file/definition.json) - File object describing a file with meta-information.
* [objects/whois](objects/whois/definition.json) - Whois records information for a domain name.

## License

~~~~

Copyright (C) 2016 Andras Iklody
Copyright (C) 2016 Alexandre Dulaunoy
Copyright (C) 2016 CIRCL - Computer Incident Response Center Luxembourg

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

~~~~
