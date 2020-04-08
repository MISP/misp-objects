# misp-objects

[![Build Status](https://travis-ci.org/MISP/misp-objects.svg?branch=master)](https://travis-ci.org/MISP/misp-objects)

MISP objects used in MISP (starting from 2.4.80) system and can be used by other information sharing tool. MISP objects
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
        "uuid": "f47559d7-6c16-40e8-a6b0-eda4a008376f",
        "attributes" :
        {
                "ip": {
                        "misp-attribute": "ip-dst",
                        "ui-priority": 1,
                        "categories": ["Network activity","External analysis"]
                },
                "domain": {
                        "misp-attribute": "domain",
                        "ui-priority": 1,
                        "categories": ["Network activity","External analysis"]
                },
                "first-seen": {
                        "misp-attribute": "datetime",
                        "disable_correlation": true,
                        "ui-priority": 0
                },
                "last-seen": {
                        "misp-attribute": "datetime",
                        "disable_correlation": true,
                        "ui-priority": 0
                }

        },
        "required": ["ip","domain"]
}
~~~~

A MISP object is described in a simple JSON file containing the following element.

* **name** is the name of the your object.
* **meta-category** is the category where the object falls into. (file, network, financial, misc, internal)
* **description** is a summary of the object description.
* **version** is the version number as a decimal value.
* **required** is an array containing the minimal required attributes to describe the object.
* **requiredOneOf** is an array containing the attributes where at least one need to be present to describe the object.
* **attributes** contains another JSON object listing all the attributes composing the object.

Each attribute must contain a reference **misp-attribute** to reference an existing attribute definition in MISP (MISP attributes types are case-sensitive).
An array **categories** shall be used to described in which categories the attribute is. The **ui-priority**
describes the usage frequency of an attribute. This helps to only display the most frequently used attributes and
allowing advanced users to show all the attributes depending of their configuration. An optional **multiple** field
shall be set to true if multiple elements of the same key can be used in the object. An optional **values_list**
where this list of value can be selected as a value for an attribute. An optional **sane_default** where this list of value recommend
potential a sane default for an attribute. An optional **disable_correlation** boolean field to suggest the disabling of correlation
for a specific attribute. An optional **to_ids** boolean field to disable the IDS flag of an attribute.

## Existing MISP objects

* [objects/ail-leak](objects/ail-leak/definition.json) - Information leak object as defined by the [AIL Analysis Information Leak framework](https://www.github.com/CIRCL/AIL-framework).
* [objects/ais-info](objects/ais-info/definition.json) - Object describing Automated Indicator Sharing (AIS) information source markings.
* [objects/android-permission](objects/android-permission/definition.json) - A set of android permissions - one or more permission(s) which can be linked to other objects (e.g. file).
* [objects/asn](objects/asn/definition.json) - Autonomous system object describing a BGP autonomous system which can include one or more network operators management an entity (e.g. ISP) along with their routing policy, routing prefixes or alike.
* [objects/attack-pattern](objects/attack-pattern/definition.json) - Attack Pattern object describing a common attack pattern enumeration and classification.
* [objects/authenticode-signerinfo](objects/authenticode-signerinfo/definition.json) - Authenticode signer info.
* [objects/av-signature](objects/av-signature/definition.json) - Antivirus detection signature.
* [objects/bank-account](objects/bank-account/definition.json) - Object describing bank account information based on account description from goAML 4.0.
* [objects/bgp-hijack](objects/bgp-hijack/definition.json) - Object encapsulating BGP Hijack description as specified, for example, by bgpstream.com
* [objects/btc-transaction](objects/btc-transaction/definition.json) - Object describing BTC transaction (often attached to a btc-wallet object.
* [objects/btc-wallet](objects/btc-wallet/definition.json) - Object describing a BTC wallet.
* [objects/cap-alert](objects/cap-alert/definition.json) - Common Alerting Protocol Version (CAP) alert object.
* [objects/cap-info](objects/cap-info/definition.json) - Common Alerting Protocol Version (CAP) info object.
* [objects/cap-resource](objects/cap-resource/definition.json) - Common Alerting Protocol Version (CAP) resource object.
* [objects/coin-address](objects/coin-address/definition.json) - An address used in a cryptocurrency.
* [objects/cookie](objects/cookie/definition.json) - A cookie object describes an HTTP cookie including its use in malicious cases.
* [objects/course-of-action](objects/course-of-action/definition.json) - An object describing a Course of Action such as a specific measure taken to prevent or respond to an attack.
* [objects/cowrie](objects/cowrie/definition.json) - A cowrie object describes cowrie honeypot sessions.
* [objects/credential](objects/credential/definition.json) - A credential object describes one or more credential(s) including password(s), api key(s) or decryption key(s).
* [objects/ddos](objects/ddos/definition.json) - DDoS object describes a current DDoS activity from a specific or/and to a specific target.
* [objects/device](objects/device/definition.json) - An object to describe a device such as a computer, laptop or alike.
* [objects/diameter-attack](objects/diameter-attack/definition.json) - Attack as seen on diameter authentication against a GSM, UMTS or LTE network.
* [objects/dns-record](objects/dns-record/definition.json) - A DNS record object to describe the associated records for a domain.
* [objects/domain-ip](objects/domain-ip/definition.json) - A domain and IP address seen as a tuple in a specific time frame.
* [objects/elf](objects/elf/definition.json) - Object describing an Executable and Linkable Format (ELF).
* [objects/elf-section](objects/elf-section/definition.json) - Object describing a section of an Executable and Linkable Format (ELF).
* [objects/email](objects/email/definition.json) - An email object.
* [objects/employee](objects/employee/definition.json) - An employee object.
* [objects/exploit-poc](objects/exploit-poc/definition.json) - Exploit-poc object describing a proof of concept or exploit of a vulnerability. This object has often a relationship with a vulnerability object.
* [objects/facial-composite](objects/facial-composite/definition.json) A facial composite object.
* [objects/fail2ban](objects/fail2ban/definition.json) - A fail2ban object.
* [objects/file](objects/file/definition.json) - File object describing a file with meta-information.
* [objects/forensic-case](objects/forensic-case/definition.json) - An object template to describe a digital forensic case.
* [objects/forensic-evidence](objects/forensic-evidence/definition.json) - An object template to describe a digital forensic evidence.
* [objects/geolocation](objects/geolocation/definition.json) - A geolocation object to describe a location.
* [objects/gtp-attack](objects/gtp-attack/definition.json) - GTP attack object as seen on a GSM, UMTS or LTE network.
* [objects/http-request](objects/http-request/definition.json) - A single HTTP request header object.
* [objects/imsi-catcher](objects/imsi-catcher/definition.json) - Object describing IMSI catcher associated event.
* [objects/interpol-notice](objects/interpol-notice/definition.json) - Object used to represent an Interpol notice
* [objects/ip-api-address](objects/ip-api-address/definition.json) - Object describing IP Address information, as defined in [ip-api.com](http://ip-api.com).
* [objects/ip-port](objects/ip-port/definition.json) - An IP address and a port seen as a tuple (or as a triple) in a specific time frame.
* [objects/ja3](objects/ja3/definition.json) - A ja3 object which describes an SSL client fingerprint in an easy to produce and shareable way.
* [objects/legal-entity](objects/legal-entity/definition.json) - Object describing a legal entity, such as an organisation.
* [objects/lnk](objects/lnk/definition.json) - Object describing a Windows LNK (Windows Shortcut) file.
* [objects/macho](objects/macho/definition.json) - Object describing a Mach object file format.
* [objects/macho-section](objects/macho-section/definition.json) - Object describing a section of a Mach object file format.
* [objects/mactime-timeline-analysis](objects/mactime-timeline-analysis/definition.json) - Mactime template, used in forensic investigations to describe the timeline of a file activity.
* [objects/malware-config](objects/malware-config/definition.json) - Object describing a malware configuration recovered or extracted from a malicious binary.
* [objects/microblog](objects/microblog/definition.json) - Object describing microblog post like Twitter or Facebook.
* [objects/mutex](objects/mutex/definition.json) - Object to describe mutual exclusion locks (mutex) as seen in memory or computer program.
* [objects/netflow](objects/netflow/definition.json) - Netflow object describes an network object based on the Netflowv5/v9 minimal definition.
* [objects/network-connection](objects/network-connection/definition.json) - Network object describes a local or remote network connection.
* [objects/network-socket](objects/network-socket/definition.json) - Object to describe a local or remote network connections based on the socket data structure.
* [objects/original-imported-file](objects/original-imported-file/definition.json) - Object to describe the original files used to import data in MISP.
* [objects/organization](objects/organization/definition.json) - An object which describes an organization.
* [objects/passive-dns](objects/passive-dns/definition.json) - Passive DNS records as expressed in [draft-dulaunoy-dnsop-passive-dns-cof-01](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof-01).
* [objects/paste](objects/paste/definition.json) - Object describing a paste or similar post from a website allowing to share privately or publicly posts.
* [objects/pe](objects/pe/definition.json) - Portable Executable (PE) object.
* [objects/pe-section](objects/pe-section/definition.json)  - Portable Executable (PE) object - section description.
* [objects/person](objects/person/definition.json) - A person object which describes a person or an identity.
* [objects/phishing](objects/phishing/definition.json) - Phishing template to describe a phishing website and its analysis.
* [objects/phishing-kit](objects/phishing-kit/definition.json) - Object to describe a phishing kit.
* [objects/phone](objects/phone/definition.json) - A phone or mobile phone object.
* [objects/process](objects/process/definition.json) - A process object.
* [objects/regexp](objects/regexp/definition.json) - An object describing a regular expression (regex or regexp). The object can be linked via a relationship to other attributes or objects to describe how it can be represented as a regular expression.
* [objects/registry-key](objects/registry-key/definition.json) - A registry-key object.
* [objects/r2graphity](objects/r2graphity/definition.json) - Indicators extracted from binary files using radare2 and graphml.
* [objects/report](objects/report/definition.json) - Object to describe metadata used to generate an executive level report.
* [objects/research-scanner](objects/research-scanner/definition.json) - Information related to known scanning activity (e.g. from research projects)
* [objects/rtir](objects/rtir/definition.json) - RTIR - Request Tracker for Incident Response.
* [objects/sandbox-report](objects/sandbox-report/definition.json) - Sandbox report object.
* [objects/sb-signature](objects/sb-signature/definition.json) - Sandbox detection signature object.
* [objects/script](objects/script/definition.json) - Object describing a computer program written to be run in a special run-time environment. The script or shell script can be used for malicious activities but also as support tools for threat analysts.
* [objects/shell-commands](objects/shell-commands/definition.json) - Object describing a series of shell commands executed. This object can be linked with malicious files in order to describe a specific execution of shell commands.
* [objects/shodan](objects/shodan/definition.json) - A shodan object to describe a shodan report.
* [objects/shortened-link](objects/shortened-link/definition.json) - Shortened link and its redirect target.
* [objects/short-message-service](objects/short-message-service/definition.json) - Short Message Service (SMS) object template describing one or more SMS message(s).
* [objects/ss7-attack](objects/ss7-attack/definition.json) - SS7 object of an attack seen on a GSM, UMTS or LTE network via SS7 logging.
* [objects/stix2-pattern](objects/stix2-pattern/definition.json) - An object describing a STIX pattern. The object can be linked via a relationship to other attributes or objects to describe how it can be represented as a STIX pattern.
* [objects/ssh-authorized-keys](objects/ssh-authorized-keys/definition.json) - SSH authorized keys object to store keys and option from SSH authorized_keys file.
* [objects/suricata](objects/suricata/definition.json) - Suricata rule with context.
* [objects/target-system](objects/target-system/definition.json) - Description about an targeted system, this could potentially be a compromised internal system.
* [objects/threatgrid-report](objects/threatgrid-report/definition.json) - A threatgrid report object.
* [objects/timecode](objects/timecode/definition.json) - Timecode object to describe a start of video sequence (e.g. CCTV evidence) and the end of the video sequence.
* [objects/timesketch-timeline](objects/timesketch-timeline/definition.json) - A timesketch timeline object based on mandatory field in timesketch to describe a log entry.
* [objects/timestamp](objects/timestamp/definition.json) - A generic timestamp object to represent time including first time and last time seen. Relationship will then define the kind of time relationship.
* [objects/tor-hiddenservice](objects/tor-hiddenservice/definition.json) - Tor hidden service (Onion Service) object to describe a Tor hidden service.
* [objects/tor-node](objects/tor-node/definition.json) - Tor node description which are part of the Tor network at a time.
* [objects/tracking-id](objects/tracking-id/definition.json) - Analytics and tracking ID such as used in Google Analytics or other analytic platform.
* [objects/transaction](objects/transaction/definition.json) - Object describing a financial transaction.
* [objects/url](objects/url/definition.json) - url object describes an url along with its normalized field (e.g. using faup parsing library) and its metadata.
* [objects/user-account](objects/user-account/definition.json) - Object describing a user account (UNIX, Windows, etc).
* [objects/vehicle](objects/vehicle/definition.json) - Vehicle object template to describe a vehicle information and registration.
* [objects/victim](objects/victim/definition.json) - a victim object to describe the organisation being targeted or abused.
* [objects/virustotal-graph](objects/virustotal-graph/definition.json) - VirusTotal graph.
* [objects/virustotal-report](objects/virustotal-report/definition.json) - VirusTotal report.
* [objects/vulnerability](objects/vulnerability/definition.json) - Vulnerability object to describe software or hardware vulnerability as described in a CVE.
* [objects/weakness](objects/weakness/definition.json) - Weakness object as described in a CWE.
* [objects/whois](objects/whois/definition.json) - Whois records information for a domain name.
* [objects/x509](objects/x509/definition.json) - x509 object describing a X.509 certificate.
* [objects/yabin](objects/yabin/definition.json) - yabin.py generates Yara rules from function prologs, for matching and hunting binaries. ref: [yabin](https://github.com/AlienVault-OTX/yabin).
* [objects/yara](objects/yara/definition.json) - YARA object describing a YARA rule along with the version supported and context (such as memory, network, disk).

## MISP objects relationships

The MISP object model is open and allows user to use their own relationships. MISP provides a list of default relationships that can be used if you plan to share your events with other MISP communities.

- [relationships](relationships/definition.json) - list of predefined default relationships which can be used to link MISP objects together and explain the context of the relationship.

## How to contribute MISP objects?

Fork the project, create a new directory in the [objects directory](objects/) matching your object name. Objects must be composed
of existing MISP attributes. If you are missing a specific attributes, feel free to open an issue in the [MISP project](https://www.github.com/MISP/MISP).

We recommend to add a **text** attribute in a object to allow users to add comments or correlating text.

If the unparsed object can be included, a **raw-base64** attribute can be used in the object to import the whole object.

Every object needs a **uuid** which can be created using **uuidgen -r** on a linux command line.

When the object is created, the `validate_all.sh` and `jq_all_the_things.sh` is run for validation, pull a request on this project. We usually merge the objects if it fits existing use-cases.

## MISP objects documentation

The MISP objects are documented at the following location in [HTML](https://www.misp-project.org/objects.html) and [PDF](https://www.misp-project.org/objects.pdf).

The documentation is automatically generated from the MISP objects template expressed in JSON.

## What are the advantages of MISP objects versus existing standards?

MISP objects are dynamically used objects that are contributed by users of MISP (the threat sharing platform) or other information sharing platforms.

The aim is to allow a dynamic update of objects definition in operational distributed sharing systems like MISP. Security threats and their related indicators are quite dynamic, standardized formats are quite static and new indicators require a significant time before being standardized.

The MISP objects model allows to add new combined indicators format based on their usage without changing the underlying code base of MISP or other threat sharing platform using it. The definition of the objects can be then propagated along with the indicators itself.

## License

~~~~

Copyright (C) 2016-2019 Andras Iklody
Copyright (C) 2016-2019 Alexandre Dulaunoy
Copyright (C) 2016-2019 CIRCL - Computer Incident Response Center Luxembourg

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
