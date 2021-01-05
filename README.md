# misp-objects

![Python application](https://github.com/MISP/misp-objects/workflows/Python%20application/badge.svg)

MISP objects used in MISP (starting from 2.4.80) system and can be used by other information sharing tool. MISP objects
are in addition to MISP attributes to allow advanced combinations of attributes. The creation of these objects
and their associated attributes are based on real cyber security use-cases and existing practices in information sharing.

Feel free to propose your own MISP objects to be included in MISP. The system is similar to the [misp-taxonomies](https://github.com/MISP/misp-taxonomies) where anyone can contribute their own objects to be included in MISP without modifying software.

## Format of MISP object template

### An example with 'domain-ip' of MISP object template

~~~~json
{
  "attributes": {
    "domain": {
      "categories": [
        "Network activity",
        "External analysis"
      ],
      "description": "Domain name",
      "misp-attribute": "domain",
      "multiple": true,
      "ui-priority": 1
    },
    "first-seen": {
      "description": "First time the tuple has been seen",
      "disable_correlation": true,
      "misp-attribute": "datetime",
      "ui-priority": 0
    },
    "ip": {
      "categories": [
        "Network activity",
        "External analysis"
      ],
      "description": "IP Address",
      "misp-attribute": "ip-dst",
      "multiple": true,
      "ui-priority": 1
    },
    "last-seen": {
      "description": "Last time the tuple has been seen",
      "disable_correlation": true,
      "misp-attribute": "datetime",
      "ui-priority": 0
    },
    "port": {
      "categories": [
        "Network activity",
        "External analysis"
      ],
      "description": "Associated TCP port with the domain",
      "misp-attribute": "port",
      "multiple": true,
      "ui-priority": 1
    },
    "registration-date": {
      "description": "Registration date of domain",
      "disable_correlation": false,
      "misp-attribute": "datetime",
      "ui-priority": 0
    },
    "text": {
      "description": "A description of the tuple",
      "disable_correlation": true,
      "misp-attribute": "text",
      "recommended": false,
      "ui-priority": 1
    }
  },
  "description": "A domain and IP address seen as a tuple in a specific time frame.",
  "meta-category": "network",
  "name": "domain-ip",
  "required": [
    "ip",
    "domain"
  ],
  "uuid": "43b3b146-77eb-4931-b4cc-b66c60f28734",
  "version": 8
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

- [objects/ail-leak](objects/ail-leak/definition.json) - An information leak as defined by the AIL Analysis Information Leak framework.
- [objects/ais-info](objects/ais-info/definition.json) - Automated Indicator Sharing (AIS) Information Source Markings.
- [objects/android-app](objects/android-app/definition.json) - Indicators related to an Android app.
- [objects/android-permission](objects/android-permission/definition.json) - A set of android permissions - one or more permission(s) which can be linked to other objects (e.g. malware, app).
- [objects/annotation](objects/annotation/definition.json) - An annotation object allowing analysts to add annotations, comments, executive summary to a MISP event, objects or attributes.
- [objects/anonymisation](objects/anonymisation/definition.json) - Anonymisation object describing an anonymisation technique used to encode MISP attribute values. Reference: https://www.caida.org/tools/taxonomy/anonymization.xml.
- [objects/asn](objects/asn/definition.json) - Autonomous system object describing an autonomous system which can include one or more network operators management an entity (e.g. ISP) along with their routing policy, routing prefixes or alike.
- [objects/attack-pattern](objects/attack-pattern/definition.json) - Attack pattern describing a common attack pattern enumeration and classification.
- [objects/authentication-failure-report](objects/authentication-failure-report/definition.json) - Authentication Failure Report.
- [objects/authenticode-signerinfo](objects/authenticode-signerinfo/definition.json) - Authenticode Signer Info.
- [objects/av-signature](objects/av-signature/definition.json) - Antivirus detection signature.
- [objects/bank-account](objects/bank-account/definition.json) - An object describing bank account information based on account description from goAML 4.0.
- [objects/bgp-hijack](objects/bgp-hijack/definition.json) - Object encapsulating BGP Hijack description as specified, for example, by bgpstream.com.
- [objects/bgp-ranking](objects/bgp-ranking/definition.json) - BGP Ranking object describing the ranking of an ASN for a given day, along with its position, 1 being the most malicious ASN of the day, with the highest ranking. This object is meant to have a relationship with the corresponding ASN object and represents its ranking for a specific date.
- [objects/blog](objects/blog/definition.json) - Blog post like Medium or WordPress.
- [objects/boleto](objects/boleto/definition.json) - A common form of payment used in Brazil.
- [objects/btc-transaction](objects/btc-transaction/definition.json) - An object to describe a Bitcoin transaction. Best to be used with bitcoin-wallet.
- [objects/btc-wallet](objects/btc-wallet/definition.json) - An object to describe a Bitcoin wallet. Best to be used with bitcoin-transactions.
- [objects/cap-alert](objects/cap-alert/definition.json) - Common Alerting Protocol Version (CAP) alert object.
- [objects/cap-info](objects/cap-info/definition.json) - Common Alerting Protocol Version (CAP) info object.
- [objects/cap-resource](objects/cap-resource/definition.json) - Common Alerting Protocol Version (CAP) resource object.
- [objects/coin-address](objects/coin-address/definition.json) - An address used in a cryptocurrency.
- [objects/command](objects/command/definition.json) - Command functionalities related to specific commands executed by a program, whether it is malicious or not. Command-line are attached to this object for the related commands.
- [objects/command-line](objects/command-line/definition.json) - Command line and options related to a specific command executed by a program, whether it is malicious or not.
- [objects/cookie](objects/cookie/definition.json) - An HTTP cookie (web cookie, browser cookie) is a small piece of data that a server sends to the user's web browser. The browser may store it and send it back with the next request to the same server. Typically, it's used to tell if two requests came from the same browser — keeping a user logged-in, for example. It remembers stateful information for the stateless HTTP protocol. (as defined by the Mozilla foundation.
- [objects/cortex](objects/cortex/definition.json) - Cortex object describing a complete cortex analysis. Observables would be attribute with a relationship from this object.
- [objects/cortex-taxonomy](objects/cortex-taxonomy/definition.json) - Cortex object describing an Cortex Taxonomy (or mini report).
- [objects/course-of-action](objects/course-of-action/definition.json) - An object describing a specific measure taken to prevent or respond to an attack.
- [objects/covid19-csse-daily-report](objects/covid19-csse-daily-report/definition.json) - CSSE COVID-19 Daily report.
- [objects/covid19-dxy-live-city](objects/covid19-dxy-live-city/definition.json) - COVID 19 from dxy.cn - Aggregation by city.
- [objects/covid19-dxy-live-province](objects/covid19-dxy-live-province/definition.json) - COVID 19 from dxy.cn - Aggregation by province.
- [objects/cowrie](objects/cowrie/definition.json) - Cowrie honeypot object template.
- [objects/cpe-asset](objects/cpe-asset/definition.json) - An asset which can be defined by a CPE. This can be a generic asset. CPE is a structured naming scheme for information technology systems, software, and packages.
- [objects/credential](objects/credential/definition.json) - Credential describes one or more credential(s) including password(s), api key(s) or decryption key(s).
- [objects/credit-card](objects/credit-card/definition.json) - A payment card like credit card, debit card or any similar cards which can be used for financial transactions.
- [objects/crypto-material](objects/crypto-material/definition.json) - Cryptographic materials such as public or/and private keys.
- [objects/cytomic-orion-file](objects/cytomic-orion-file/definition.json) - Cytomic Orion File Detection.
- [objects/cytomic-orion-machine](objects/cytomic-orion-machine/definition.json) - Cytomic Orion File at Machine Detection.
- [objects/dark-pattern-item](objects/dark-pattern-item/definition.json) - An Item whose User Interface implements a dark pattern.
- [objects/ddos](objects/ddos/definition.json) - DDoS object describes a current DDoS activity from a specific or/and to a specific target. Type of DDoS can be attached to the object as a taxonomy.
- [objects/device](objects/device/definition.json) - An object to define a device.
- [objects/diameter-attack](objects/diameter-attack/definition.json) - Attack as seen on diameter authentication against a GSM, UMTS or LTE network.
- [objects/dns-record](objects/dns-record/definition.json) - A set of DNS records observed for a specific domain.
- [objects/domain-crawled](objects/domain-crawled/definition.json) - A domain crawled over time.
- [objects/domain-ip](objects/domain-ip/definition.json) - A domain/hostname and IP address seen as a tuple in a specific time frame.
- [objects/elf](objects/elf/definition.json) - Object describing a Executable and Linkable Format.
- [objects/elf-section](objects/elf-section/definition.json) - Object describing a section of an Executable and Linkable Format.
- [objects/email](objects/email/definition.json) - Email object describing an email with meta-information.
- [objects/employee](objects/employee/definition.json) - An employee and related data points.
- [objects/exploit-poc](objects/exploit-poc/definition.json) - Exploit-poc object describing a proof of concept or exploit of a vulnerability. This object has often a relationship with a vulnerability object.
- [objects/facebook-account](objects/facebook-account/definition.json) - Facebook account.
- [objects/facebook-group](objects/facebook-group/definition.json) - Public or private facebook group.
- [objects/facebook-page](objects/facebook-page/definition.json) - Facebook page.
- [objects/facebook-post](objects/facebook-post/definition.json) - Post on a Facebook wall.
- [objects/facial-composite](objects/facial-composite/definition.json) - An object which describes a facial composite.
- [objects/fail2ban](objects/fail2ban/definition.json) - Fail2ban event.
- [objects/favicon](objects/favicon/definition.json) - A favicon, also known as a shortcut icon, website icon, tab icon, URL icon, or bookmark icon, is a file containing one or more small icons, associated with a particular website or web page. The object template can include the murmur3 hash of the favicon to facilitate correlation.
- [objects/file](objects/file/definition.json) - File object describing a file with meta-information.
- [objects/forensic-case](objects/forensic-case/definition.json) - An object template to describe a digital forensic case.
- [objects/forensic-evidence](objects/forensic-evidence/definition.json) - An object template to describe a digital forensic evidence.
- [objects/forged-document](objects/forged-document/definition.json) - Object describing a forged document.
- [objects/ftm-Airplane](objects/ftm-Airplane/definition.json) - .
- [objects/ftm-Assessment](objects/ftm-Assessment/definition.json) - .
- [objects/ftm-Asset](objects/ftm-Asset/definition.json) - .
- [objects/ftm-Associate](objects/ftm-Associate/definition.json) - Non-family association between two people.
- [objects/ftm-Audio](objects/ftm-Audio/definition.json) - .
- [objects/ftm-BankAccount](objects/ftm-BankAccount/definition.json) - .
- [objects/ftm-Call](objects/ftm-Call/definition.json) - .
- [objects/ftm-Company](objects/ftm-Company/definition.json) - .
- [objects/ftm-Contract](objects/ftm-Contract/definition.json) - An contract or contract lot issued by an authority. Multiple lots may be awarded to different suppliers (see ContractAward).
.
- [objects/ftm-ContractAward](objects/ftm-ContractAward/definition.json) - A contract or contract lot as awarded to a supplier.
- [objects/ftm-CourtCase](objects/ftm-CourtCase/definition.json) - .
- [objects/ftm-CourtCaseParty](objects/ftm-CourtCaseParty/definition.json) - .
- [objects/ftm-Debt](objects/ftm-Debt/definition.json) - A monetary debt between two parties.
- [objects/ftm-Directorship](objects/ftm-Directorship/definition.json) - .
- [objects/ftm-Document](objects/ftm-Document/definition.json) - .
- [objects/ftm-Documentation](objects/ftm-Documentation/definition.json) - .
- [objects/ftm-EconomicActivity](objects/ftm-EconomicActivity/definition.json) - A foreign economic activity.
- [objects/ftm-Email](objects/ftm-Email/definition.json) - .
- [objects/ftm-Event](objects/ftm-Event/definition.json) - .
- [objects/ftm-Family](objects/ftm-Family/definition.json) - Family relationship between two people.
- [objects/ftm-Folder](objects/ftm-Folder/definition.json) - .
- [objects/ftm-HyperText](objects/ftm-HyperText/definition.json) - .
- [objects/ftm-Image](objects/ftm-Image/definition.json) - .
- [objects/ftm-Land](objects/ftm-Land/definition.json) - .
- [objects/ftm-LegalEntity](objects/ftm-LegalEntity/definition.json) - A legal entity may be a person or a company.
- [objects/ftm-License](objects/ftm-License/definition.json) - A grant of land, rights or property. A type of Contract.
- [objects/ftm-Membership](objects/ftm-Membership/definition.json) - .
- [objects/ftm-Message](objects/ftm-Message/definition.json) - .
- [objects/ftm-Organization](objects/ftm-Organization/definition.json) - .
- [objects/ftm-Ownership](objects/ftm-Ownership/definition.json) - .
- [objects/ftm-Package](objects/ftm-Package/definition.json) - .
- [objects/ftm-Page](objects/ftm-Page/definition.json) - .
- [objects/ftm-Pages](objects/ftm-Pages/definition.json) - .
- [objects/ftm-Passport](objects/ftm-Passport/definition.json) - Passport.
- [objects/ftm-Payment](objects/ftm-Payment/definition.json) - A monetary payment between two parties.
- [objects/ftm-Person](objects/ftm-Person/definition.json) - An individual.
- [objects/ftm-PlainText](objects/ftm-PlainText/definition.json) - .
- [objects/ftm-PublicBody](objects/ftm-PublicBody/definition.json) - A public body, such as a ministry, department or state company.
- [objects/ftm-RealEstate](objects/ftm-RealEstate/definition.json) - A piece of land or property.
- [objects/ftm-Representation](objects/ftm-Representation/definition.json) - A mediatory, intermediary, middleman, or broker acting on behalf of a legal entity.
- [objects/ftm-Row](objects/ftm-Row/definition.json) - .
- [objects/ftm-Sanction](objects/ftm-Sanction/definition.json) - A sanction designation.
- [objects/ftm-Succession](objects/ftm-Succession/definition.json) - Two entities that legally succeed each other.
- [objects/ftm-Table](objects/ftm-Table/definition.json) - .
- [objects/ftm-TaxRoll](objects/ftm-TaxRoll/definition.json) - A tax declaration of an individual.
- [objects/ftm-UnknownLink](objects/ftm-UnknownLink/definition.json) - .
- [objects/ftm-UserAccount](objects/ftm-UserAccount/definition.json) - .
- [objects/ftm-Vehicle](objects/ftm-Vehicle/definition.json) - .
- [objects/ftm-Vessel](objects/ftm-Vessel/definition.json) - A boat or ship.
- [objects/ftm-Video](objects/ftm-Video/definition.json) - .
- [objects/ftm-Workbook](objects/ftm-Workbook/definition.json) - .
- [objects/geolocation](objects/geolocation/definition.json) - An object to describe a geographic location.
- [objects/git-vuln-finder](objects/git-vuln-finder/definition.json) - Export from git-vuln-finder.
- [objects/github-user](objects/github-user/definition.json) - GitHub user.
- [objects/gitlab-user](objects/gitlab-user/definition.json) - GitLab user. Gitlab.com user or self-hosted GitLab instance.
- [objects/gtp-attack](objects/gtp-attack/definition.json) - GTP attack object as seen on a GSM, UMTS or LTE network.
- [objects/http-request](objects/http-request/definition.json) - A single HTTP request header.
- [objects/ilr-impact](objects/ilr-impact/definition.json) - Institut Luxembourgeois de Regulation - Impact.
- [objects/ilr-notification-incident](objects/ilr-notification-incident/definition.json) - Institut Luxembourgeois de Regulation - Notification d'incident.
- [objects/image](objects/image/definition.json) - Object describing an image file.
- [objects/impersonation](objects/impersonation/definition.json) - Represent an impersonating account.
- [objects/imsi-catcher](objects/imsi-catcher/definition.json) - IMSI Catcher entry object based on the open source IMSI cather.
- [objects/instant-message](objects/instant-message/definition.json) - Instant Message (IM) object template describing one or more IM message.
- [objects/instant-message-group](objects/instant-message-group/definition.json) - Instant Message (IM) group object template describing a public or private IM group, channel or conversation.
- [objects/intel471-vulnerability-intelligence](objects/intel471-vulnerability-intelligence/definition.json) - Intel 471 vulnerability intelligence object.
- [objects/intelmq_event](objects/intelmq_event/definition.json) - IntelMQ Event.
- [objects/intelmq_report](objects/intelmq_report/definition.json) - IntelMQ Report.
- [objects/internal-reference](objects/internal-reference/definition.json) - Internal reference.
- [objects/interpol-notice](objects/interpol-notice/definition.json) - An object which describes a Interpol notice.
- [objects/iot-device](objects/iot-device/definition.json) - An IoT device.
- [objects/iot-firmware](objects/iot-firmware/definition.json) - A firmware for an IoT device.
- [objects/ip-api-address](objects/ip-api-address/definition.json) - IP Address information. Useful if you are pulling your ip information from ip-api.com.
- [objects/ip-port](objects/ip-port/definition.json) - An IP address (or domain or hostname) and a port seen as a tuple (or as a triple) in a specific time frame.
- [objects/irc](objects/irc/definition.json) - An IRC object to describe an IRC server and the associated channels.
- [objects/ja3](objects/ja3/definition.json) - JA3 is a new technique for creating SSL client fingerprints that are easy to produce and can be easily shared for threat intelligence. Fingerprints are composed of Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats. https://github.com/salesforce/ja3.
- [objects/keybase-account](objects/keybase-account/definition.json) - Information related to a keybase account, from API Users Object.
- [objects/leaked-document](objects/leaked-document/definition.json) - Object describing a leaked document.
- [objects/legal-entity](objects/legal-entity/definition.json) - An object to describe a legal entity.
- [objects/lnk](objects/lnk/definition.json) - LNK object describing a Windows LNK binary file (aka Windows shortcut).
- [objects/macho](objects/macho/definition.json) - Object describing a file in Mach-O format.
- [objects/macho-section](objects/macho-section/definition.json) - Object describing a section of a file in Mach-O format.
- [objects/mactime-timeline-analysis](objects/mactime-timeline-analysis/definition.json) - Mactime template, used in forensic investigations to describe the timeline of a file activity.
- [objects/malware-config](objects/malware-config/definition.json) - Malware configuration recovered or extracted from a malicious binary.
- [objects/meme-image](objects/meme-image/definition.json) - Object describing a meme (image).
- [objects/microblog](objects/microblog/definition.json) - Microblog post like a Twitter tweet or a post on a Facebook wall.
- [objects/mutex](objects/mutex/definition.json) - Object to describe mutual exclusion locks (mutex) as seen in memory or computer program.
- [objects/narrative](objects/narrative/definition.json) - Object describing a narrative.
- [objects/netflow](objects/netflow/definition.json) - Netflow object describes an network object based on the Netflowv5/v9 minimal definition.
- [objects/network-connection](objects/network-connection/definition.json) - A local or remote network connection.
- [objects/network-socket](objects/network-socket/definition.json) - Network socket object describes a local or remote network connections based on the socket data structure.
- [objects/news-agency](objects/news-agency/definition.json) - News agencies compile news and disseminate news in bulk.
- [objects/news-media](objects/news-media/definition.json) - News media are forms of mass media delivering news to the general public.
- [objects/organization](objects/organization/definition.json) - An object which describes an organization.
- [objects/original-imported-file](objects/original-imported-file/definition.json) - Object describing the original file used to import data in MISP.
- [objects/parler-account](objects/parler-account/definition.json) - Parler account.
- [objects/parler-comment](objects/parler-comment/definition.json) - Parler comment.
- [objects/parler-post](objects/parler-post/definition.json) - Parler post (parley).
- [objects/passive-dns](objects/passive-dns/definition.json) - Passive DNS records as expressed in draft-dulaunoy-dnsop-passive-dns-cof-01.
- [objects/paste](objects/paste/definition.json) - Paste or similar post from a website allowing to share privately or publicly posts.
- [objects/pcap-metadata](objects/pcap-metadata/definition.json) - Network packet capture metadata.
- [objects/pe](objects/pe/definition.json) - Object describing a Portable Executable.
- [objects/pe-section](objects/pe-section/definition.json) - Object describing a section of a Portable Executable.
- [objects/person](objects/person/definition.json) - An object which describes a person or an identity.
- [objects/pgp-meta](objects/pgp-meta/definition.json) - Metadata extracted from a PGP keyblock, message or signature.
- [objects/phishing](objects/phishing/definition.json) - Phishing template to describe a phishing website and its analysis.
- [objects/phishing-kit](objects/phishing-kit/definition.json) - Object to describe a phishing-kit.
- [objects/phone](objects/phone/definition.json) - A phone or mobile phone object which describe a phone.
- [objects/process](objects/process/definition.json) - Object describing a system process.
- [objects/publication](objects/publication/definition.json) - An object to describe a book, journal, or academic publication.
- [objects/python-etvx-event-log](objects/python-etvx-event-log/definition.json) - Event log object template to share information of the activities conducted on a system. .
- [objects/r2graphity](objects/r2graphity/definition.json) - Indicators extracted from files using radare2 and graphml.
- [objects/reddit-account](objects/reddit-account/definition.json) - Reddit account.
- [objects/reddit-comment](objects/reddit-comment/definition.json) - A Reddit post comment.
- [objects/reddit-post](objects/reddit-post/definition.json) - A Reddit post.
- [objects/reddit-subreddit](objects/reddit-subreddit/definition.json) - Public or private subreddit.
- [objects/regexp](objects/regexp/definition.json) - An object describing a regular expression (regex or regexp). The object can be linked via a relationship to other attributes or objects to describe how it can be represented as a regular expression.
- [objects/registry-key](objects/registry-key/definition.json) - Registry key object describing a Windows registry key with value and last-modified timestamp.
- [objects/regripper-NTUser](objects/regripper-NTUser/definition.json) - Regripper Object template designed to present user specific configuration details extracted from the NTUSER.dat hive.
- [objects/regripper-sam-hive-single-user](objects/regripper-sam-hive-single-user/definition.json) - Regripper Object template designed to present user profile details extracted from the SAM hive.
- [objects/regripper-sam-hive-user-group](objects/regripper-sam-hive-user-group/definition.json) - Regripper Object template designed to present group profile details extracted from the SAM hive.
- [objects/regripper-software-hive-BHO](objects/regripper-software-hive-BHO/definition.json) - Regripper Object template designed to gather information of the browser helper objects installed on the system.
- [objects/regripper-software-hive-appInit-DLLS](objects/regripper-software-hive-appInit-DLLS/definition.json) - Regripper Object template designed to gather information of the DLL files installed on the system.
- [objects/regripper-software-hive-application-paths](objects/regripper-software-hive-application-paths/definition.json) - Regripper Object template designed to gather information of the application paths.
- [objects/regripper-software-hive-applications-installed](objects/regripper-software-hive-applications-installed/definition.json) - Regripper Object template designed to gather information of the applications installed on the system.
- [objects/regripper-software-hive-command-shell](objects/regripper-software-hive-command-shell/definition.json) - Regripper Object template designed to gather information of the shell commands executed on the system.
- [objects/regripper-software-hive-software-run](objects/regripper-software-hive-software-run/definition.json) - Regripper Object template designed to gather information of the applications set to run on the system.
- [objects/regripper-software-hive-userprofile-winlogon](objects/regripper-software-hive-userprofile-winlogon/definition.json) - Regripper Object template designed to gather user profile information when the user logs onto the system, gathered from the software hive.
- [objects/regripper-software-hive-windows-general-info](objects/regripper-software-hive-windows-general-info/definition.json) - Regripper Object template designed to gather general windows information extracted from the software-hive.
- [objects/regripper-system-hive-firewall-configuration](objects/regripper-system-hive-firewall-configuration/definition.json) - Regripper Object template designed to present firewall configuration information extracted from the system-hive.
- [objects/regripper-system-hive-general-configuration](objects/regripper-system-hive-general-configuration/definition.json) - Regripper Object template designed to present general system properties extracted from the system-hive.
- [objects/regripper-system-hive-network-information](objects/regripper-system-hive-network-information/definition.json) - Regripper object template designed to gather network information from the system-hive.
- [objects/regripper-system-hive-services-drivers](objects/regripper-system-hive-services-drivers/definition.json) - Regripper Object template designed to gather information regarding the services/drivers from the system-hive.
- [objects/report](objects/report/definition.json) - Metadata used to generate an executive level report.
- [objects/research-scanner](objects/research-scanner/definition.json) - Information related to known scanning activity (e.g. from research projects).
- [objects/rogue-dns](objects/rogue-dns/definition.json) - Rogue DNS as defined by CERT.br.
- [objects/rtir](objects/rtir/definition.json) - RTIR - Request Tracker for Incident Response.
- [objects/sandbox-report](objects/sandbox-report/definition.json) - Sandbox report.
- [objects/sb-signature](objects/sb-signature/definition.json) - Sandbox detection signature.
- [objects/scheduled-event](objects/scheduled-event/definition.json) - Event object template describing a gathering of individuals in meatspace.
- [objects/scrippsco2-c13-daily](objects/scrippsco2-c13-daily/definition.json) - Daily average C13 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-c13-monthly](objects/scrippsco2-c13-monthly/definition.json) - Monthly average C13 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-co2-daily](objects/scrippsco2-co2-daily/definition.json) - Daily average CO2 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-co2-monthly](objects/scrippsco2-co2-monthly/definition.json) - Monthly average CO2 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-o18-daily](objects/scrippsco2-o18-daily/definition.json) - Daily average O18 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-o18-monthly](objects/scrippsco2-o18-monthly/definition.json) - Monthly average O18 concentrations (ppm) derived from flask air samples.
- [objects/script](objects/script/definition.json) - Object describing a computer program written to be run in a special run-time environment. The script or shell script can be used for malicious activities but also as support tools for threat analysts.
- [objects/shell-commands](objects/shell-commands/definition.json) - Object describing a series of shell commands executed. This object can be linked with malicious files in order to describe a specific execution of shell commands.
- [objects/shodan-report](objects/shodan-report/definition.json) - Shodan Report for a given IP.
- [objects/short-message-service](objects/short-message-service/definition.json) - Short Message Service (SMS) object template describing one or more SMS message. Restriction of the initial format 3GPP 23.038 GSM character set doesn't apply.
- [objects/shortened-link](objects/shortened-link/definition.json) - Shortened link and its redirect target.
- [objects/social-media-group](objects/social-media-group/definition.json) - Social media group object template describing a public or private group or channel.
- [objects/splunk](objects/splunk/definition.json) - Splunk / Splunk ES object.
- [objects/ss7-attack](objects/ss7-attack/definition.json) - SS7 object of an attack seen on a GSM, UMTS or LTE network via SS7 logging.
- [objects/ssh-authorized-keys](objects/ssh-authorized-keys/definition.json) - An object to store ssh authorized keys file.
- [objects/stix2-pattern](objects/stix2-pattern/definition.json) - An object describing a STIX pattern. The object can be linked via a relationship to other attributes or objects to describe how it can be represented as a STIX pattern.
- [objects/suricata](objects/suricata/definition.json) - An object describing one or more Suricata rule(s) along with version and contextual information.
- [objects/target-system](objects/target-system/definition.json) - Description about an targeted system, this could potentially be a compromissed internal system.
- [objects/threatgrid-report](objects/threatgrid-report/definition.json) - ThreatGrid report.
- [objects/timecode](objects/timecode/definition.json) - Timecode object to describe a start of video sequence (e.g. CCTV evidence) and the end of the video sequence.
- [objects/timesketch-timeline](objects/timesketch-timeline/definition.json) - A timesketch timeline object based on mandatory field in timesketch to describe a log entry.
- [objects/timesketch_message](objects/timesketch_message/definition.json) - A timesketch message entry.
- [objects/timestamp](objects/timestamp/definition.json) - A generic timestamp object to represent time including first time and last time seen. Relationship will then define the kind of time relationship.
- [objects/tor-hiddenservice](objects/tor-hiddenservice/definition.json) - Tor hidden service (onion service) object.
- [objects/tor-node](objects/tor-node/definition.json) - Tor node (which protects your privacy on the internet by hiding the connection between users Internet address and the services used by the users) description which are part of the Tor network at a time.
- [objects/tracking-id](objects/tracking-id/definition.json) - Analytics and tracking ID such as used in Google Analytics or other analytic platform.
- [objects/transaction](objects/transaction/definition.json) - An object to describe a financial transaction.
- [objects/translation](objects/translation/definition.json) - Used to keep a text and its translation.
- [objects/trustar_report](objects/trustar_report/definition.json) - TruStar Report.
- [objects/tsk-chats](objects/tsk-chats/definition.json) - An Object Template to gather information from evidential or interesting exchange of messages identified during a digital forensic investigation.
- [objects/tsk-web-bookmark](objects/tsk-web-bookmark/definition.json) - An Object Template to add evidential bookmarks identified during a digital forensic investigation.
- [objects/tsk-web-cookie](objects/tsk-web-cookie/definition.json) - An TSK-Autopsy Object Template to represent cookies identified during a forensic investigation.
- [objects/tsk-web-downloads](objects/tsk-web-downloads/definition.json) - An Object Template to add web-downloads.
- [objects/tsk-web-history](objects/tsk-web-history/definition.json) - An Object Template to share web history information.
- [objects/tsk-web-search-query](objects/tsk-web-search-query/definition.json) - An Object Template to share web search query information.
- [objects/twitter-account](objects/twitter-account/definition.json) - Twitter account.
- [objects/twitter-list](objects/twitter-list/definition.json) - Twitter list.
- [objects/twitter-post](objects/twitter-post/definition.json) - Twitter post (tweet).
- [objects/url](objects/url/definition.json) - url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.
- [objects/user-account](objects/user-account/definition.json) - .
- [objects/vehicle](objects/vehicle/definition.json) - Vehicle object template to describe a vehicle information and registration.
- [objects/victim](objects/victim/definition.json) - Victim object describes the target of an attack or abuse.
- [objects/virustotal-graph](objects/virustotal-graph/definition.json) - VirusTotal graph.
- [objects/virustotal-report](objects/virustotal-report/definition.json) - VirusTotal report.
- [objects/vulnerability](objects/vulnerability/definition.json) - Vulnerability object describing a common vulnerability enumeration which can describe published, unpublished, under review or embargo vulnerability for software, equipments or hardware.
- [objects/weakness](objects/weakness/definition.json) - Weakness object describing a common weakness enumeration which can describe usable, incomplete, draft or deprecated weakness for software, equipment of hardware.
- [objects/whois](objects/whois/definition.json) - Whois records information for a domain name or an IP address.
- [objects/x509](objects/x509/definition.json) - x509 object describing a X.509 certificate.
- [objects/yabin](objects/yabin/definition.json) - yabin.py generates Yara rules from function prologs, for matching and hunting binaries. ref: https://github.com/AlienVault-OTX/yabin.
- [objects/yara](objects/yara/definition.json) - An object describing a YARA rule (or a YARA rule name) along with its version.
- [objects/youtube-channel](objects/youtube-channel/definition.json) - A YouTube channel.
- [objects/youtube-comment](objects/youtube-comment/definition.json) - A YouTube video comment.
- [objects/youtube-playlist](objects/youtube-playlist/definition.json) - A YouTube playlist.
- [objects/youtube-video](objects/youtube-video/definition.json) - A YouTube video.


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

### MISP Object JSON files

The MISP objects (JSON files) are dual-licensed under:

- [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/legalcode) (CC0 1.0) - Public Domain Dedication.

or

~~~~
 Copyright (c) 2016-2020 Alexandre Dulaunoy - a@foo.be
 Copyright (c) 2016-2020 CIRCL - Computer Incident Response Center Luxembourg
 Copyright (c) 2016-2020 Andras Iklody
 Copyright (c) 2016-2020 Raphael Vinot
 Copyright (c) 2016-2020 Various contributors to MISP Project

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 OF THE POSSIBILITY OF SUCH DAMAGE.
~~~~~

If a specific author of a taxonomy wants to license it under a different license, a pull request can be requested.


### Software

~~~~

Copyright (C) 2016-2020 Andras Iklody
Copyright (C) 2016-2020 Alexandre Dulaunoy
Copyright (C) 2016-2020 CIRCL - Computer Incident Response Center Luxembourg

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
