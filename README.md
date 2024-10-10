# misp-objects

![Python application](https://github.com/MISP/misp-objects/workflows/Python%20application/badge.svg)

MISP objects used in MISP system and can be used by other information sharing tools. MISP objects
are in addition to MISP attributes to allow advanced combinations of attributes. The creation of these objects
and their associated attributes are based on real cyber security use-cases and existing practices in information sharing.

Feel free to propose your own MISP objects template to be included in MISP. The system is similar to the [misp-taxonomies](https://github.com/MISP/misp-taxonomies) where anyone can contribute their own objects to be included in MISP without modifying software.

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

A MISP object is described in a simple JSON file containing the following elements.

* **name** is the name of the your object.
* **meta-category** is the category where the object falls into. (such as file, network, financial, misc, internal...)
* **description** is a summary of the object description.
* **version** is the version number as a decimal value.
* **required** is an array containing the minimal required attributes to describe the object.
* **requiredOneOf** is an array containing the attributes where at least one needs to be present to describe the object.
* **attributes** contains another JSON object listing all the attributes composing the object.

Each attribute must contain a reference **misp-attribute** to reference an existing attribute definition in MISP (MISP attributes types are case-sensitive).
An array **categories** shall be used to describe in which categories the attribute is. The **ui-priority**
describes the usage frequency of an attribute. This helps to only display the most frequently used attributes and
allowing advanced users to show all the attributes depending of their configuration. An optional **multiple** field
shall be set to true if multiple elements of the same key can be used in the object. An optional **values_list**
where this list of values can be selected as a value for an attribute. An optional **sane_default** where this list of value recommend
potential a sane default for an attribute. An optional **disable_correlation** boolean field to suggest the disabling of correlation
for a specific attribute. An optional **to_ids** boolean field to disable the IDS flag of an attribute.

## Existing MISP objects

- [objects/ADS](https://github.com/MISP/misp-objects/blob/main/objects/ADS/definition.json) - An object defining ADS - Alerting and Detection Strategy by PALANTIR. Can be used for detection engineering.
- [objects/abuseipdb](https://github.com/MISP/misp-objects/blob/main/objects/abuseipdb/definition.json) - AbuseIPDB checks an ip address, domain name, or subnet against a central blacklist.
- [objects/ai-chat-prompt](https://github.com/MISP/misp-objects/blob/main/objects/ai-chat-prompt/definition.json) - Object describing an AI prompt such as ChatGPT.
- [objects/ail-leak](https://github.com/MISP/misp-objects/blob/main/objects/ail-leak/definition.json) - An information leak as defined by the AIL Analysis Information Leak framework.
- [objects/ais](https://github.com/MISP/misp-objects/blob/main/objects/ais/definition.json) - Automatic Identification System (AIS) is an automatic tracking system that uses transceivers on ships.
- [objects/ais-info](https://github.com/MISP/misp-objects/blob/main/objects/ais-info/definition.json) - Automated Indicator Sharing (AIS) Information Source Markings.
- [objects/android-app](https://github.com/MISP/misp-objects/blob/main/objects/android-app/definition.json) - Indicators related to an Android app.
- [objects/android-permission](https://github.com/MISP/misp-objects/blob/main/objects/android-permission/definition.json) - A set of android permissions - one or more permission(s) which can be linked to other objects (e.g. malware, app).
- [objects/annotation](https://github.com/MISP/misp-objects/blob/main/objects/annotation/definition.json) - An annotation object allowing analysts to add annotations, comments, executive summary to a MISP event, objects or attributes.
- [objects/anonymisation](https://github.com/MISP/misp-objects/blob/main/objects/anonymisation/definition.json) - Anonymisation object describing an anonymisation technique used to encode MISP attribute values. Reference: https://www.caida.org/tools/taxonomy/anonymization.xml.
- [objects/apivoid-email-verification](https://github.com/MISP/misp-objects/blob/main/objects/apivoid-email-verification/definition.json) - Apivoid email verification API result. Reference: https://www.apivoid.com/api/email-verify/.
- [objects/artifact](https://github.com/MISP/misp-objects/blob/main/objects/artifact/definition.json) - The Artifact object permits capturing an array of bytes (8-bits), as a base64-encoded string, or linking to a file-like payload. From STIX 2.1 (6.1).
- [objects/asn](https://github.com/MISP/misp-objects/blob/main/objects/asn/definition.json) - Autonomous system object describing an autonomous system which can include one or more network operators managing an entity (e.g. ISP) along with their routing policy, routing prefixes or alike.
- [objects/attack-pattern](https://github.com/MISP/misp-objects/blob/main/objects/attack-pattern/definition.json) - Attack pattern describing a common attack pattern enumeration and classification.
- [objects/attack-step](https://github.com/MISP/misp-objects/blob/main/objects/attack-step/definition.json) - An object defining a singular attack-step. Especially useful for red/purple teaming, but can also be used for actual attacks.
- [objects/attacker-infra](https://github.com/MISP/misp-objects/blob/main/objects/attacker-infra/definition.json) - Attacker Infrastructure.
- [objects/authentication-failure-report](https://github.com/MISP/misp-objects/blob/main/objects/authentication-failure-report/definition.json) - Authentication Failure Report.
- [objects/authenticode-signerinfo](https://github.com/MISP/misp-objects/blob/main/objects/authenticode-signerinfo/definition.json) - Authenticode Signer Info.
- [objects/av-signature](https://github.com/MISP/misp-objects/blob/main/objects/av-signature/definition.json) - Antivirus detection signature.
- [objects/availability-impact](https://github.com/MISP/misp-objects/blob/main/objects/availability-impact/definition.json) - Availability Impact object as described in STIX 2.1 Incident object extension.
- [objects/bank-account](https://github.com/MISP/misp-objects/blob/main/objects/bank-account/definition.json) - An object describing bank account information based on account description from goAML 4.0.
- [objects/bgp-hijack](https://github.com/MISP/misp-objects/blob/main/objects/bgp-hijack/definition.json) - Object encapsulating BGP Hijack description as specified, for example, by bgpstream.com.
- [objects/bgp-ranking](https://github.com/MISP/misp-objects/blob/main/objects/bgp-ranking/definition.json) - BGP Ranking object describing the ranking of an ASN for a given day, along with its position, 1 being the most malicious ASN of the day, with the highest ranking. This object is meant to have a relationship with the corresponding ASN object and represents its ranking for a specific date.
- [objects/blog](https://github.com/MISP/misp-objects/blob/main/objects/blog/definition.json) - Blog post like Medium or WordPress.
- [objects/boleto](https://github.com/MISP/misp-objects/blob/main/objects/boleto/definition.json) - A common form of payment used in Brazil.
- [objects/btc-transaction](https://github.com/MISP/misp-objects/blob/main/objects/btc-transaction/definition.json) - An object to describe a Bitcoin transaction. Best to be used with bitcoin-wallet.
- [objects/btc-wallet](https://github.com/MISP/misp-objects/blob/main/objects/btc-wallet/definition.json) - An object to describe a Bitcoin wallet. Best to be used with btc-transaction object.
- [objects/c2-list](https://github.com/MISP/misp-objects/blob/main/objects/c2-list/definition.json) - List of C2-servers with common ground, e.g. extracted from a blog post or ransomware analysis.
- [objects/cap-alert](https://github.com/MISP/misp-objects/blob/main/objects/cap-alert/definition.json) - Common Alerting Protocol Version (CAP) alert object.
- [objects/cap-info](https://github.com/MISP/misp-objects/blob/main/objects/cap-info/definition.json) - Common Alerting Protocol Version (CAP) info object.
- [objects/cap-resource](https://github.com/MISP/misp-objects/blob/main/objects/cap-resource/definition.json) - Common Alerting Protocol Version (CAP) resource object.
- [objects/cert-pl-phishing](https://github.com/MISP/misp-objects/blob/main/objects/cert-pl-phishing/definition.json) - cert.pl phishing object template representing an url along with some metadata as such phash, html-structure or partial-hash.
- [objects/cloth](https://github.com/MISP/misp-objects/blob/main/objects/cloth/definition.json) - Describes clothes a natural person wears.
- [objects/coin-address](https://github.com/MISP/misp-objects/blob/main/objects/coin-address/definition.json) - An address used in a cryptocurrency.
- [objects/command](https://github.com/MISP/misp-objects/blob/main/objects/command/definition.json) - Command functionalities related to specific commands executed by a program, whether it is malicious or not. Command-line are attached to this object for the related commands.
- [objects/command-line](https://github.com/MISP/misp-objects/blob/main/objects/command-line/definition.json) - Command line and options related to a specific command executed by a program, whether it is malicious or not.
- [objects/concordia-mtmf-intrusion-set](https://github.com/MISP/misp-objects/blob/main/objects/concordia-mtmf-intrusion-set/definition.json) - Intrusion Set - Phase Description.
- [objects/confidentiality-impact](https://github.com/MISP/misp-objects/blob/main/objects/confidentiality-impact/definition.json) - Confidentiality Impact object as described in STIX 2.1 Incident object extension.
- [objects/cookie](https://github.com/MISP/misp-objects/blob/main/objects/cookie/definition.json) - An HTTP cookie (web cookie, browser cookie) is a small piece of data that a server sends to the user's web browser. The browser may store it and send it back with the next request to the same server. Typically, it's used to tell if two requests came from the same browser — keeping a user logged-in, for example. It remembers stateful information for the stateless HTTP protocol. As defined by the Mozilla foundation.
- [objects/cortex](https://github.com/MISP/misp-objects/blob/main/objects/cortex/definition.json) - Cortex object describing a complete Cortex analysis. Observables would be attribute with a relationship from this object.
- [objects/cortex-taxonomy](https://github.com/MISP/misp-objects/blob/main/objects/cortex-taxonomy/definition.json) - Cortex object describing a Cortex Taxonomy (or mini report).
- [objects/course-of-action](https://github.com/MISP/misp-objects/blob/main/objects/course-of-action/definition.json) - An object describing a specific measure taken to prevent or respond to an attack.
- [objects/covid19-csse-daily-report](https://github.com/MISP/misp-objects/blob/main/objects/covid19-csse-daily-report/definition.json) - CSSE COVID-19 Daily report.
- [objects/covid19-dxy-live-city](https://github.com/MISP/misp-objects/blob/main/objects/covid19-dxy-live-city/definition.json) - COVID 19 from dxy.cn - Aggregation by city.
- [objects/covid19-dxy-live-province](https://github.com/MISP/misp-objects/blob/main/objects/covid19-dxy-live-province/definition.json) - COVID 19 from dxy.cn - Aggregation by province.
- [objects/cowrie](https://github.com/MISP/misp-objects/blob/main/objects/cowrie/definition.json) - Cowrie honeypot object template.
- [objects/cpe-asset](https://github.com/MISP/misp-objects/blob/main/objects/cpe-asset/definition.json) - An asset which can be defined by a CPE. This can be a generic asset. CPE is a structured naming scheme for information technology systems, software, and packages.
- [objects/credential](https://github.com/MISP/misp-objects/blob/main/objects/credential/definition.json) - Credential describes one or more credential(s) including password(s), api key(s) or decryption key(s).
- [objects/credit-card](https://github.com/MISP/misp-objects/blob/main/objects/credit-card/definition.json) - A payment card like credit card, debit card or any similar cards which can be used for financial transactions.
- [objects/crowdsec-ip-context](https://github.com/MISP/misp-objects/blob/main/objects/crowdsec-ip-context/definition.json) - CrowdSec Threat Intelligence - IP CTI search.
- [objects/crowdstrike-report](https://github.com/MISP/misp-objects/blob/main/objects/crowdstrike-report/definition.json) - An Object Template to encode an Crowdstrike detection report.
- [objects/crypto-material](https://github.com/MISP/misp-objects/blob/main/objects/crypto-material/definition.json) - Cryptographic materials such as public or/and private keys.
- [objects/cryptocurrency-transaction](https://github.com/MISP/misp-objects/blob/main/objects/cryptocurrency-transaction/definition.json) - An object to describe a cryptocurrency transaction.
- [objects/cs-beacon-config](https://github.com/MISP/misp-objects/blob/main/objects/cs-beacon-config/definition.json) - Cobalt Strike Beacon Config.
- [objects/cytomic-orion-file](https://github.com/MISP/misp-objects/blob/main/objects/cytomic-orion-file/definition.json) - Cytomic Orion File Detection.
- [objects/cytomic-orion-machine](https://github.com/MISP/misp-objects/blob/main/objects/cytomic-orion-machine/definition.json) - Cytomic Orion File at Machine Detection.
- [objects/dark-pattern-item](https://github.com/MISP/misp-objects/blob/main/objects/dark-pattern-item/definition.json) - An Item whose User Interface implements a dark pattern.
- [objects/ddos](https://github.com/MISP/misp-objects/blob/main/objects/ddos/definition.json) - DDoS object describes a current DDoS activity from a specific or/and to a specific target. Type of DDoS can be attached to the object as a taxonomy or using the type field.
- [objects/ddos-claim](https://github.com/MISP/misp-objects/blob/main/objects/ddos-claim/definition.json) - DDoS-claim object describes a current claim of DDoS activity.
- [objects/ddos-config](https://github.com/MISP/misp-objects/blob/main/objects/ddos-config/definition.json) - DDoS-claim object describes a current claim of DDoS activity.
- [objects/device](https://github.com/MISP/misp-objects/blob/main/objects/device/definition.json) - An object to define a device.
- [objects/diameter-attack](https://github.com/MISP/misp-objects/blob/main/objects/diameter-attack/definition.json) - Attack as seen on the diameter signaling protocol supporting LTE networks.
- [objects/diamond-event](https://github.com/MISP/misp-objects/blob/main/objects/diamond-event/definition.json) - A diamond model event object consisting of the four diamond features advesary, infrastructure, capability and victim, several meta-features and ioc attributes.
- [objects/directory](https://github.com/MISP/misp-objects/blob/main/objects/directory/definition.json) - Directory object describing a directory with meta-information.
- [objects/dkim](https://github.com/MISP/misp-objects/blob/main/objects/dkim/definition.json) - DomainKeys Identified Mail - DKIM.
- [objects/dns-record](https://github.com/MISP/misp-objects/blob/main/objects/dns-record/definition.json) - A set of DNS records observed for a specific domain.
- [objects/domain-crawled](https://github.com/MISP/misp-objects/blob/main/objects/domain-crawled/definition.json) - A domain crawled over time.
- [objects/domain-ip](https://github.com/MISP/misp-objects/blob/main/objects/domain-ip/definition.json) - A domain/hostname and IP address seen as a tuple in a specific time frame.
- [objects/edr-report](https://github.com/MISP/misp-objects/blob/main/objects/edr-report/definition.json) - An Object Template to encode an EDR detection report.
- [objects/elf](https://github.com/MISP/misp-objects/blob/main/objects/elf/definition.json) - Object describing a Executable and Linkable Format.
- [objects/elf-section](https://github.com/MISP/misp-objects/blob/main/objects/elf-section/definition.json) - Object describing a section of an Executable and Linkable Format.
- [objects/email](https://github.com/MISP/misp-objects/blob/main/objects/email/definition.json) - Email object describing an email with meta-information.
- [objects/employee](https://github.com/MISP/misp-objects/blob/main/objects/employee/definition.json) - An employee and related data points.
- [objects/error-message](https://github.com/MISP/misp-objects/blob/main/objects/error-message/definition.json) - An error message which can be related to the processing of data such as import, export scripts from the original MISP instance.
- [objects/event](https://github.com/MISP/misp-objects/blob/main/objects/event/definition.json) - Event object as described in STIX 2.1 Incident object extension.
- [objects/exploit](https://github.com/MISP/misp-objects/blob/main/objects/exploit/definition.json) - Exploit object describes a program in binary or source code form used to abuse one or more vulnerabilities.
- [objects/exploit-poc](https://github.com/MISP/misp-objects/blob/main/objects/exploit-poc/definition.json) - Exploit-poc object describing a proof of concept or exploit of a vulnerability. This object has often a relationship with a vulnerability object.
- [objects/external-impact](https://github.com/MISP/misp-objects/blob/main/objects/external-impact/definition.json) - External Impact object as described in STIX 2.1 Incident object extension.
- [objects/facebook-account](https://github.com/MISP/misp-objects/blob/main/objects/facebook-account/definition.json) - Facebook account.
- [objects/facebook-group](https://github.com/MISP/misp-objects/blob/main/objects/facebook-group/definition.json) - Public or private facebook group.
- [objects/facebook-page](https://github.com/MISP/misp-objects/blob/main/objects/facebook-page/definition.json) - Facebook page.
- [objects/facebook-post](https://github.com/MISP/misp-objects/blob/main/objects/facebook-post/definition.json) - Post on a Facebook wall.
- [objects/facebook-reaction](https://github.com/MISP/misp-objects/blob/main/objects/facebook-reaction/definition.json) - Reaction to facebook posts.
- [objects/facial-composite](https://github.com/MISP/misp-objects/blob/main/objects/facial-composite/definition.json) - An object which describes a facial composite.
- [objects/fail2ban](https://github.com/MISP/misp-objects/blob/main/objects/fail2ban/definition.json) - Fail2ban event.
- [objects/favicon](https://github.com/MISP/misp-objects/blob/main/objects/favicon/definition.json) - A favicon, also known as a shortcut icon, website icon, tab icon, URL icon, or bookmark icon, is a file containing one or more small icons, associated with a particular website or web page. The object template can include the murmur3 hash of the favicon to facilitate correlation.
- [objects/file](https://github.com/MISP/misp-objects/blob/main/objects/file/definition.json) - File object describing a file with meta-information.
- [objects/flowintel-cm-case](https://github.com/MISP/misp-objects/blob/main/objects/flowintel-cm-case/definition.json) - A case as defined by flowintel-cm.
- [objects/flowintel-cm-task](https://github.com/MISP/misp-objects/blob/main/objects/flowintel-cm-task/definition.json) - A task as defined by flowintel-cm.
- [objects/flowintel-cm-task-note](https://github.com/MISP/misp-objects/blob/main/objects/flowintel-cm-task-note/definition.json) - A task's note as defined by flowintel-cm.
- [objects/forensic-case](https://github.com/MISP/misp-objects/blob/main/objects/forensic-case/definition.json) - An object template to describe a digital forensic case.
- [objects/forensic-evidence](https://github.com/MISP/misp-objects/blob/main/objects/forensic-evidence/definition.json) - An object template to describe a digital forensic evidence.
- [objects/forged-document](https://github.com/MISP/misp-objects/blob/main/objects/forged-document/definition.json) - Object describing a forged document.
- [objects/ftm-Airplane](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Airplane/definition.json) - An airplane, helicopter or other flying vehicle.
- [objects/ftm-Assessment](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Assessment/definition.json) - Assessment with meta-data.
- [objects/ftm-Asset](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Asset/definition.json) - A piece of property which can be owned and assigned a monetary value.
- [objects/ftm-Associate](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Associate/definition.json) - Non-family association between two people.
- [objects/ftm-Audio](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Audio/definition.json) - Audio with meta-data.
- [objects/ftm-BankAccount](https://github.com/MISP/misp-objects/blob/main/objects/ftm-BankAccount/definition.json) - An account held at a bank and controlled by an owner. This may also be used to describe more complex arrangements like correspondent bank settlement accounts.
- [objects/ftm-Call](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Call/definition.json) - Phone call object template including the call and all associated meta-data.
- [objects/ftm-Company](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Company/definition.json) - A legal entity representing an association of people, whether natural, legal or a mixture of both, with a specific objective.
- [objects/ftm-Contract](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Contract/definition.json) - An contract or contract lot issued by an authority. Multiple lots may be awarded to different suppliers (see ContractAward).
.
- [objects/ftm-ContractAward](https://github.com/MISP/misp-objects/blob/main/objects/ftm-ContractAward/definition.json) - A contract or contract lot as awarded to a supplier.
- [objects/ftm-CourtCase](https://github.com/MISP/misp-objects/blob/main/objects/ftm-CourtCase/definition.json) - Court case.
- [objects/ftm-CourtCaseParty](https://github.com/MISP/misp-objects/blob/main/objects/ftm-CourtCaseParty/definition.json) - Court Case Party.
- [objects/ftm-Debt](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Debt/definition.json) - A monetary debt between two parties.
- [objects/ftm-Directorship](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Directorship/definition.json) - Directorship.
- [objects/ftm-Document](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Document/definition.json) - Document.
- [objects/ftm-Documentation](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Documentation/definition.json) - Documentation.
- [objects/ftm-EconomicActivity](https://github.com/MISP/misp-objects/blob/main/objects/ftm-EconomicActivity/definition.json) - A foreign economic activity.
- [objects/ftm-Email](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Email/definition.json) - Email.
- [objects/ftm-Event](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Event/definition.json) - Event.
- [objects/ftm-Family](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Family/definition.json) - Family relationship between two people.
- [objects/ftm-Folder](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Folder/definition.json) - Folder.
- [objects/ftm-HyperText](https://github.com/MISP/misp-objects/blob/main/objects/ftm-HyperText/definition.json) - HyperText.
- [objects/ftm-Image](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Image/definition.json) - Image.
- [objects/ftm-Land](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Land/definition.json) - Land.
- [objects/ftm-LegalEntity](https://github.com/MISP/misp-objects/blob/main/objects/ftm-LegalEntity/definition.json) - A legal entity may be a person or a company.
- [objects/ftm-License](https://github.com/MISP/misp-objects/blob/main/objects/ftm-License/definition.json) - A grant of land, rights or property. A type of Contract.
- [objects/ftm-Membership](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Membership/definition.json) - Membership.
- [objects/ftm-Message](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Message/definition.json) - Message.
- [objects/ftm-Organization](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Organization/definition.json) - Organization.
- [objects/ftm-Ownership](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Ownership/definition.json) - Ownership.
- [objects/ftm-Package](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Package/definition.json) - Package.
- [objects/ftm-Page](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Page/definition.json) - Page.
- [objects/ftm-Pages](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Pages/definition.json) - Pages.
- [objects/ftm-Passport](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Passport/definition.json) - Passport.
- [objects/ftm-Payment](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Payment/definition.json) - A monetary payment between two parties.
- [objects/ftm-Person](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Person/definition.json) - An individual.
- [objects/ftm-PlainText](https://github.com/MISP/misp-objects/blob/main/objects/ftm-PlainText/definition.json) - Plaintext.
- [objects/ftm-PublicBody](https://github.com/MISP/misp-objects/blob/main/objects/ftm-PublicBody/definition.json) - A public body, such as a ministry, department or state company.
- [objects/ftm-RealEstate](https://github.com/MISP/misp-objects/blob/main/objects/ftm-RealEstate/definition.json) - A piece of land or property.
- [objects/ftm-Representation](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Representation/definition.json) - A mediatory, intermediary, middleman, or broker acting on behalf of a legal entity.
- [objects/ftm-Row](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Row/definition.json) - Row.
- [objects/ftm-Sanction](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Sanction/definition.json) - A sanction designation.
- [objects/ftm-Succession](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Succession/definition.json) - Two entities that legally succeed each other.
- [objects/ftm-Table](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Table/definition.json) - Table.
- [objects/ftm-TaxRoll](https://github.com/MISP/misp-objects/blob/main/objects/ftm-TaxRoll/definition.json) - A tax declaration of an individual.
- [objects/ftm-UnknownLink](https://github.com/MISP/misp-objects/blob/main/objects/ftm-UnknownLink/definition.json) - Unknown Link.
- [objects/ftm-UserAccount](https://github.com/MISP/misp-objects/blob/main/objects/ftm-UserAccount/definition.json) - User Account.
- [objects/ftm-Vehicle](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Vehicle/definition.json) - Vehicle.
- [objects/ftm-Vessel](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Vessel/definition.json) - A boat or ship.
- [objects/ftm-Video](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Video/definition.json) - Video.
- [objects/ftm-Workbook](https://github.com/MISP/misp-objects/blob/main/objects/ftm-Workbook/definition.json) - Workbook.
- [objects/game-cheat](https://github.com/MISP/misp-objects/blob/main/objects/game-cheat/definition.json) - Describes a game cheat or a cheatware.
- [objects/Generalizing Persuasion Framework](https://github.com/MISP/misp-objects/blob/main/objects/Generalizing Persuasion Framework/definition.json) - By placing their work within the GP Framework, scholars will help the field resolve inconsistencies, identify and address open questions, and ensure collective progress. The GP Framework is not meant to compete with other theories (such as the ELM) but rather to fill in two gaps. First, it allows one to consider how individual persuasion studies connect to one another and why studies may arrive at contradictory conclusions. Second, it highlights the sources of variations that should be studied. (James N. Druckman).
- [objects/geolocation](https://github.com/MISP/misp-objects/blob/main/objects/geolocation/definition.json) - An object to describe a geographic location.
- [objects/git-vuln-finder](https://github.com/MISP/misp-objects/blob/main/objects/git-vuln-finder/definition.json) - Export from git-vuln-finder.
- [objects/github-user](https://github.com/MISP/misp-objects/blob/main/objects/github-user/definition.json) - GitHub user.
- [objects/gitlab-user](https://github.com/MISP/misp-objects/blob/main/objects/gitlab-user/definition.json) - GitLab user. Gitlab.com user or self-hosted GitLab instance.
- [objects/google-safe-browsing](https://github.com/MISP/misp-objects/blob/main/objects/google-safe-browsing/definition.json) - Google Safe checks a URL against Google's constantly updated list of unsafe web resources.
- [objects/google-threat-intelligence-report](https://github.com/MISP/misp-objects/blob/main/objects/google-threat-intelligence-report/definition.json) - Google Threat Intelligence report that provides an assessment (verdict, severity and scoring) and combined information from VirusTotal and Mandiant.
- [objects/greynoise-ip](https://github.com/MISP/misp-objects/blob/main/objects/greynoise-ip/definition.json) - GreyNoise IP Information.
- [objects/gtp-attack](https://github.com/MISP/misp-objects/blob/main/objects/gtp-attack/definition.json) - GTP attack object as attack as seen on the GTP signaling protocol supporting GPRS/LTE networks.
- [objects/hashlookup](https://github.com/MISP/misp-objects/blob/main/objects/hashlookup/definition.json) - hashlookup object as described on hashlookup services from circl.lu - https://www.circl.lu/services/hashlookup.
- [objects/hhhash](https://github.com/MISP/misp-objects/blob/main/objects/hhhash/definition.json) - An object describing a HHHash object with the hash value along with the crawling parameters. For more information: https://www.foo.be/2023/07/HTTP-Headers-Hashing_HHHash.
- [objects/http-request](https://github.com/MISP/misp-objects/blob/main/objects/http-request/definition.json) - A single HTTP request header.
- [objects/identity](https://github.com/MISP/misp-objects/blob/main/objects/identity/definition.json) - Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, systems or groups (e.g., the finance sector).  The Identity SDO can capture basic identifying information, contact information, and the sectors that the Identity belongs to. Identity is used in STIX to represent, among other things, targets of attacks, information sources, object creators, and threat actor identities. (ref. STIX 2.1 - 4.5).
- [objects/ilr-impact](https://github.com/MISP/misp-objects/blob/main/objects/ilr-impact/definition.json) - Institut Luxembourgeois de Regulation - Impact.
- [objects/ilr-notification-incident](https://github.com/MISP/misp-objects/blob/main/objects/ilr-notification-incident/definition.json) - Institut Luxembourgeois de Regulation - Notification d'incident.
- [objects/image](https://github.com/MISP/misp-objects/blob/main/objects/image/definition.json) - Object describing an image file.
- [objects/impersonation](https://github.com/MISP/misp-objects/blob/main/objects/impersonation/definition.json) - Represent an impersonating account.
- [objects/imsi-catcher](https://github.com/MISP/misp-objects/blob/main/objects/imsi-catcher/definition.json) - IMSI Catcher entry object based on the open source IMSI cather.
- [objects/incident](https://github.com/MISP/misp-objects/blob/main/objects/incident/definition.json) - Incident object template as described in STIX 2.1 Incident object and its core extension.
- [objects/infrastructure](https://github.com/MISP/misp-objects/blob/main/objects/infrastructure/definition.json) - The Infrastructure object represents a type of TTP and describes any systems, software services and any associated physical or virtual resources intended to support some purpose (e.g., C2 servers used as part of an attack, device or server that are part of defense, database servers targeted by an attack, etc.). While elements of an attack can be represented by other objects, the Infrastructure object represents a named group of related data that constitutes the infrastructure. STIX 2.1 - 4.8.
- [objects/instant-message](https://github.com/MISP/misp-objects/blob/main/objects/instant-message/definition.json) - Instant Message (IM) object template describing one or more IM message.
- [objects/instant-message-group](https://github.com/MISP/misp-objects/blob/main/objects/instant-message-group/definition.json) - Instant Message (IM) group object template describing a public or private IM group, channel or conversation.
- [objects/integrity-impact](https://github.com/MISP/misp-objects/blob/main/objects/integrity-impact/definition.json) - Integrity Impact object as described in STIX 2.1 Incident object extension.
- [objects/intel471-vulnerability-intelligence](https://github.com/MISP/misp-objects/blob/main/objects/intel471-vulnerability-intelligence/definition.json) - Intel 471 vulnerability intelligence object.
- [objects/intelmq_event](https://github.com/MISP/misp-objects/blob/main/objects/intelmq_event/definition.json) - IntelMQ Event.
- [objects/intelmq_report](https://github.com/MISP/misp-objects/blob/main/objects/intelmq_report/definition.json) - IntelMQ Report.
- [objects/internal-reference](https://github.com/MISP/misp-objects/blob/main/objects/internal-reference/definition.json) - Internal reference.
- [objects/interpol-notice](https://github.com/MISP/misp-objects/blob/main/objects/interpol-notice/definition.json) - An object which describes a Interpol notice.
- [objects/intrusion-set](https://github.com/MISP/misp-objects/blob/main/objects/intrusion-set/definition.json) - A object template describing an Intrusion Set as defined in STIX 2.1. An Intrusion Set is a grouped set of adversarial behaviors and resources with common properties that is believed to be orchestrated by a single organization. An Intrusion Set may capture multiple Campaigns or other activities that are all tied together by shared attributes indicating a commonly known or unknown Threat Actor. New activity can be attributed to an Intrusion Set even if the Threat Actors behind the attack are not known. Threat Actors can move from supporting one Intrusion Set to supporting another, or they may support multiple Intrusion Sets.  Where a Campaign is a set of attacks over a period of time against a specific set of targets to achieve some objective, an Intrusion Set is the entire attack package and may be used over a very long period of time in multiple Campaigns to achieve potentially multiple purposes.  While sometimes an Intrusion Set is not active, or changes focus, it is usually difficult to know if it has truly disappeared or ended. Analysts may have varying level of fidelity on attributing an Intrusion Set back to Threat Actors and may be able to only attribute it back to a nation state or perhaps back to an organization within that nation state.
- [objects/iot-device](https://github.com/MISP/misp-objects/blob/main/objects/iot-device/definition.json) - An IoT device.
- [objects/iot-firmware](https://github.com/MISP/misp-objects/blob/main/objects/iot-firmware/definition.json) - A firmware for an IoT device.
- [objects/ip-api-address](https://github.com/MISP/misp-objects/blob/main/objects/ip-api-address/definition.json) - IP Address information. Useful if you are pulling your ip information from ip-api.com.
- [objects/ip-port](https://github.com/MISP/misp-objects/blob/main/objects/ip-port/definition.json) - An IP address (or domain or hostname) and a port seen as a tuple (or as a triple) in a specific time frame.
- [objects/irc](https://github.com/MISP/misp-objects/blob/main/objects/irc/definition.json) - An IRC object to describe an IRC server and the associated channels.
- [objects/ja3](https://github.com/MISP/misp-objects/blob/main/objects/ja3/definition.json) - JA3 is a new technique for creating SSL client fingerprints that are easy to produce and can be easily shared for threat intelligence. Fingerprints are composed of Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats. https://github.com/salesforce/ja3.
- [objects/ja3s](https://github.com/MISP/misp-objects/blob/main/objects/ja3s/definition.json) - JA3S is JA3 for the Server side of the SSL/TLS communication and fingerprints how servers respond to particular clients. JA3S fingerprints are composed of Server Hello packet; SSL Version, Cipher, SSLExtensions. https://github.com/salesforce/ja3.
- [objects/ja4-plus](https://github.com/MISP/misp-objects/blob/main/objects/ja4-plus/definition.json) - JA4 is a technique for creating network fingerprints that are easy to produce and can be easily shared for threat intelligence. https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md.
- [objects/jarm](https://github.com/MISP/misp-objects/blob/main/objects/jarm/definition.json) - Jarm object to describe an TLS/SSL implementation used for malicious or legitimate use-case.
- [objects/keybase-account](https://github.com/MISP/misp-objects/blob/main/objects/keybase-account/definition.json) - Information related to a keybase account, from API Users Object.
- [objects/language-content](https://github.com/MISP/misp-objects/blob/main/objects/language-content/definition.json) - The Language Content object represents text content for objects represented in languages other than that of the original object. Language content may be a translation of the original object by a third-party, a first-source translation by the original publisher, or additional official language content provided at the time of creation. STIX 2.1 ref 7.1.
- [objects/leaked-document](https://github.com/MISP/misp-objects/blob/main/objects/leaked-document/definition.json) - Object describing a leaked document.
- [objects/legal-entity](https://github.com/MISP/misp-objects/blob/main/objects/legal-entity/definition.json) - An object to describe a legal entity.
- [objects/lnk](https://github.com/MISP/misp-objects/blob/main/objects/lnk/definition.json) - LNK object describing a Windows LNK binary file (aka Windows shortcut).
- [objects/macho](https://github.com/MISP/misp-objects/blob/main/objects/macho/definition.json) - Object describing a file in Mach-O format.
- [objects/macho-section](https://github.com/MISP/misp-objects/blob/main/objects/macho-section/definition.json) - Object describing a section of a file in Mach-O format.
- [objects/mactime-timeline-analysis](https://github.com/MISP/misp-objects/blob/main/objects/mactime-timeline-analysis/definition.json) - Mactime template, used in forensic investigations to describe the timeline of a file activity.
- [objects/malware](https://github.com/MISP/misp-objects/blob/main/objects/malware/definition.json) - Malware is a type of TTP that represents malicious code.
- [objects/malware-analysis](https://github.com/MISP/misp-objects/blob/main/objects/malware-analysis/definition.json) - Malware Analysis captures the metadata and results of a particular static or dynamic analysis performed on a malware instance or family.
- [objects/malware-config](https://github.com/MISP/misp-objects/blob/main/objects/malware-config/definition.json) - Malware configuration recovered or extracted from a malicious binary.
- [objects/meme-image](https://github.com/MISP/misp-objects/blob/main/objects/meme-image/definition.json) - Object describing a meme (image).
- [objects/microblog](https://github.com/MISP/misp-objects/blob/main/objects/microblog/definition.json) - Microblog post like a Twitter tweet or a post on a Facebook wall.
- [objects/monetary-impact](https://github.com/MISP/misp-objects/blob/main/objects/monetary-impact/definition.json) - Monetary Impact object as described in STIX 2.1 Incident object extension.
- [objects/mutex](https://github.com/MISP/misp-objects/blob/main/objects/mutex/definition.json) - Object to describe mutual exclusion locks (mutex) as seen in memory or computer program.
- [objects/narrative](https://github.com/MISP/misp-objects/blob/main/objects/narrative/definition.json) - Object describing a narrative.
- [objects/netflow](https://github.com/MISP/misp-objects/blob/main/objects/netflow/definition.json) - Netflow object describes an network object based on the Netflowv5/v9 minimal definition.
- [objects/network-connection](https://github.com/MISP/misp-objects/blob/main/objects/network-connection/definition.json) - A local or remote network connection.
- [objects/network-profile](https://github.com/MISP/misp-objects/blob/main/objects/network-profile/definition.json) - Elements that can be used to profile, pivot or identify a network infrastructure, including domains, ip and urls.
- [objects/network-socket](https://github.com/MISP/misp-objects/blob/main/objects/network-socket/definition.json) - Network socket object describes a local or remote network connections based on the socket data structure.
- [objects/network-traffic](https://github.com/MISP/misp-objects/blob/main/objects/network-traffic/definition.json) - Generic network traffic that originates from a source and is addressed to a destination.
- [objects/news-agency](https://github.com/MISP/misp-objects/blob/main/objects/news-agency/definition.json) - News agencies compile news and disseminate news in bulk.
- [objects/news-media](https://github.com/MISP/misp-objects/blob/main/objects/news-media/definition.json) - News media are forms of mass media delivering news to the general public.
- [objects/open-data-security](https://github.com/MISP/misp-objects/blob/main/objects/open-data-security/definition.json) - An object describing an open dataset available and described under the open data security model. ref. https://github.com/CIRCL/open-data-security.
- [objects/organization](https://github.com/MISP/misp-objects/blob/main/objects/organization/definition.json) - An object which describes an organization.
- [objects/original-imported-file](https://github.com/MISP/misp-objects/blob/main/objects/original-imported-file/definition.json) - Object describing the original file used to import data in MISP.
- [objects/paloalto-threat-event](https://github.com/MISP/misp-objects/blob/main/objects/paloalto-threat-event/definition.json) - Palo Alto Threat Log Event.
- [objects/parler-account](https://github.com/MISP/misp-objects/blob/main/objects/parler-account/definition.json) - Parler account.
- [objects/parler-comment](https://github.com/MISP/misp-objects/blob/main/objects/parler-comment/definition.json) - Parler comment.
- [objects/parler-post](https://github.com/MISP/misp-objects/blob/main/objects/parler-post/definition.json) - Parler post (parley).
- [objects/passive-dns](https://github.com/MISP/misp-objects/blob/main/objects/passive-dns/definition.json) - Passive DNS records as expressed in draft-dulaunoy-dnsop-passive-dns-cof-07. See https://tools.ietf.org/id/draft-dulaunoy-dnsop-passive-dns-cof-07.html.
- [objects/passive-dns-dnsdbflex](https://github.com/MISP/misp-objects/blob/main/objects/passive-dns-dnsdbflex/definition.json) - DNSDBFLEX object. This object is used at farsight security. Roughly based on Passive DNS records as expressed in draft-dulaunoy-dnsop-passive-dns-cof-07. See https://tools.ietf.org/id/draft-dulaunoy-dnsop-passive-dns-cof-07.html.
- [objects/passive-ssh](https://github.com/MISP/misp-objects/blob/main/objects/passive-ssh/definition.json) - Passive-ssh object as described on passive-ssh services from circl.lu - https://github.com/D4-project/passive-ssh.
- [objects/paste](https://github.com/MISP/misp-objects/blob/main/objects/paste/definition.json) - Paste or similar post from a website allowing to share privately or publicly posts.
- [objects/pcap-metadata](https://github.com/MISP/misp-objects/blob/main/objects/pcap-metadata/definition.json) - Network packet capture metadata.
- [objects/pe](https://github.com/MISP/misp-objects/blob/main/objects/pe/definition.json) - Object describing a Portable Executable.
- [objects/pe-optional-header](https://github.com/MISP/misp-objects/blob/main/objects/pe-optional-header/definition.json) - Object describing a Portable Executable Optional Header.
- [objects/pe-section](https://github.com/MISP/misp-objects/blob/main/objects/pe-section/definition.json) - Object describing a section of a Portable Executable.
- [objects/Deception PersNOna](https://github.com/MISP/misp-objects/blob/main/objects/Deception PersNOna/definition.json) - Fake persona with tasks.
- [objects/person](https://github.com/MISP/misp-objects/blob/main/objects/person/definition.json) - An object which describes a person or an identity.
- [objects/personification](https://github.com/MISP/misp-objects/blob/main/objects/personification/definition.json) - An object which describes a person or an identity.
- [objects/pgp-meta](https://github.com/MISP/misp-objects/blob/main/objects/pgp-meta/definition.json) - Metadata extracted from a PGP keyblock, message or signature.
- [objects/phishing](https://github.com/MISP/misp-objects/blob/main/objects/phishing/definition.json) - Phishing template to describe a phishing website and its analysis.
- [objects/phishing-kit](https://github.com/MISP/misp-objects/blob/main/objects/phishing-kit/definition.json) - Object to describe a phishing-kit.
- [objects/phone](https://github.com/MISP/misp-objects/blob/main/objects/phone/definition.json) - A phone or mobile phone object which describe a phone.
- [objects/phone-number](https://github.com/MISP/misp-objects/blob/main/objects/phone-number/definition.json) - Phone number based on the E.164 international public telecommunication numbering plan.
- [objects/physical-impact](https://github.com/MISP/misp-objects/blob/main/objects/physical-impact/definition.json) - Physical Impact object as described in STIX 2.1 Incident object extension.
- [objects/postal-address](https://github.com/MISP/misp-objects/blob/main/objects/postal-address/definition.json) - A postal address.
- [objects/probabilistic-data-structure](https://github.com/MISP/misp-objects/blob/main/objects/probabilistic-data-structure/definition.json) - Probabilistic data structure object describe a space-efficient data structure such as Bloom filter or similar structure.
- [objects/process](https://github.com/MISP/misp-objects/blob/main/objects/process/definition.json) - Object describing a system process.
- [objects/publication](https://github.com/MISP/misp-objects/blob/main/objects/publication/definition.json) - An object to describe a book, journal, or academic publication.
- [objects/python-etvx-event-log](https://github.com/MISP/misp-objects/blob/main/objects/python-etvx-event-log/definition.json) - Event log object template to share information of the activities conducted on a system. .
- [objects/query](https://github.com/MISP/misp-objects/blob/main/objects/query/definition.json) - An object describing a query, along with its format.
- [objects/r2graphity](https://github.com/MISP/misp-objects/blob/main/objects/r2graphity/definition.json) - Indicators extracted from files using radare2 and graphml.
- [objects/ransom-negotiation](https://github.com/MISP/misp-objects/blob/main/objects/ransom-negotiation/definition.json) - An object to describe ransom negotiations, as seen in ransomware incidents.
- [objects/ransomware-group-post](https://github.com/MISP/misp-objects/blob/main/objects/ransomware-group-post/definition.json) - Ransomware group post as monitored by ransomlook.io or others.
- [objects/reddit-account](https://github.com/MISP/misp-objects/blob/main/objects/reddit-account/definition.json) - Reddit account.
- [objects/reddit-comment](https://github.com/MISP/misp-objects/blob/main/objects/reddit-comment/definition.json) - A Reddit post comment.
- [objects/reddit-post](https://github.com/MISP/misp-objects/blob/main/objects/reddit-post/definition.json) - A Reddit post.
- [objects/reddit-subreddit](https://github.com/MISP/misp-objects/blob/main/objects/reddit-subreddit/definition.json) - Public or private subreddit.
- [objects/regexp](https://github.com/MISP/misp-objects/blob/main/objects/regexp/definition.json) - An object describing a regular expression (regex or regexp). The object can be linked via a relationship to other attributes or objects to describe how it can be represented as a regular expression.
- [objects/registry-key](https://github.com/MISP/misp-objects/blob/main/objects/registry-key/definition.json) - Registry key object describing a Windows registry key with value and last-modified timestamp.
- [objects/registry-key-value](https://github.com/MISP/misp-objects/blob/main/objects/registry-key-value/definition.json) - Registry key value object describing a Windows registry key value, with its data, data type and name values. To be used when a registry key has multiple values.
- [objects/regripper-NTUser](https://github.com/MISP/misp-objects/blob/main/objects/regripper-NTUser/definition.json) - Regripper Object template designed to present user specific configuration details extracted from the NTUSER.dat hive.
- [objects/regripper-sam-hive-single-user](https://github.com/MISP/misp-objects/blob/main/objects/regripper-sam-hive-single-user/definition.json) - Regripper Object template designed to present user profile details extracted from the SAM hive.
- [objects/regripper-sam-hive-user-group](https://github.com/MISP/misp-objects/blob/main/objects/regripper-sam-hive-user-group/definition.json) - Regripper Object template designed to present group profile details extracted from the SAM hive.
- [objects/regripper-software-hive-BHO](https://github.com/MISP/misp-objects/blob/main/objects/regripper-software-hive-BHO/definition.json) - Regripper Object template designed to gather information of the browser helper objects installed on the system.
- [objects/regripper-software-hive-appInit-DLLS](https://github.com/MISP/misp-objects/blob/main/objects/regripper-software-hive-appInit-DLLS/definition.json) - Regripper Object template designed to gather information of the DLL files installed on the system.
- [objects/regripper-software-hive-application-paths](https://github.com/MISP/misp-objects/blob/main/objects/regripper-software-hive-application-paths/definition.json) - Regripper Object template designed to gather information of the application paths.
- [objects/regripper-software-hive-applications-installed](https://github.com/MISP/misp-objects/blob/main/objects/regripper-software-hive-applications-installed/definition.json) - Regripper Object template designed to gather information of the applications installed on the system.
- [objects/regripper-software-hive-command-shell](https://github.com/MISP/misp-objects/blob/main/objects/regripper-software-hive-command-shell/definition.json) - Regripper Object template designed to gather information of the shell commands executed on the system.
- [objects/regripper-software-hive-software-run](https://github.com/MISP/misp-objects/blob/main/objects/regripper-software-hive-software-run/definition.json) - Regripper Object template designed to gather information of the applications set to run on the system.
- [objects/regripper-software-hive-userprofile-winlogon](https://github.com/MISP/misp-objects/blob/main/objects/regripper-software-hive-userprofile-winlogon/definition.json) - Regripper Object template designed to gather user profile information when the user logs onto the system, gathered from the software hive.
- [objects/regripper-software-hive-windows-general-info](https://github.com/MISP/misp-objects/blob/main/objects/regripper-software-hive-windows-general-info/definition.json) - Regripper Object template designed to gather general windows information extracted from the software-hive.
- [objects/regripper-system-hive-firewall-configuration](https://github.com/MISP/misp-objects/blob/main/objects/regripper-system-hive-firewall-configuration/definition.json) - Regripper Object template designed to present firewall configuration information extracted from the system-hive.
- [objects/regripper-system-hive-general-configuration](https://github.com/MISP/misp-objects/blob/main/objects/regripper-system-hive-general-configuration/definition.json) - Regripper Object template designed to present general system properties extracted from the system-hive.
- [objects/regripper-system-hive-network-information](https://github.com/MISP/misp-objects/blob/main/objects/regripper-system-hive-network-information/definition.json) - Regripper object template designed to gather network information from the system-hive.
- [objects/regripper-system-hive-services-drivers](https://github.com/MISP/misp-objects/blob/main/objects/regripper-system-hive-services-drivers/definition.json) - Regripper Object template designed to gather information regarding the services/drivers from the system-hive.
- [objects/report](https://github.com/MISP/misp-objects/blob/main/objects/report/definition.json) - Report object to describe a report along with its metadata.
- [objects/research-scanner](https://github.com/MISP/misp-objects/blob/main/objects/research-scanner/definition.json) - Information related to known scanning activity (e.g. from research projects).
- [objects/risk-assessment-report](https://github.com/MISP/misp-objects/blob/main/objects/risk-assessment-report/definition.json) - Risk assessment report object which includes the assessment report from a risk assessment platform such as MONARC.
- [objects/rogue-dns](https://github.com/MISP/misp-objects/blob/main/objects/rogue-dns/definition.json) - Rogue DNS as defined by CERT.br.
- [objects/rtir](https://github.com/MISP/misp-objects/blob/main/objects/rtir/definition.json) - RTIR - Request Tracker for Incident Response.
- [objects/sandbox-report](https://github.com/MISP/misp-objects/blob/main/objects/sandbox-report/definition.json) - Sandbox report.
- [objects/sb-signature](https://github.com/MISP/misp-objects/blob/main/objects/sb-signature/definition.json) - Sandbox detection signature.
- [objects/scan-result](https://github.com/MISP/misp-objects/blob/main/objects/scan-result/definition.json) - Scan result object to add meta-data and the output of the scan result by itself.
- [objects/scheduled-event](https://github.com/MISP/misp-objects/blob/main/objects/scheduled-event/definition.json) - Event object template describing a gathering of individuals in meatspace.
- [objects/scheduled-task](https://github.com/MISP/misp-objects/blob/main/objects/scheduled-task/definition.json) - Windows scheduled task description.
- [objects/scrippsco2-c13-daily](https://github.com/MISP/misp-objects/blob/main/objects/scrippsco2-c13-daily/definition.json) - Daily average C13 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-c13-monthly](https://github.com/MISP/misp-objects/blob/main/objects/scrippsco2-c13-monthly/definition.json) - Monthly average C13 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-co2-daily](https://github.com/MISP/misp-objects/blob/main/objects/scrippsco2-co2-daily/definition.json) - Daily average CO2 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-co2-monthly](https://github.com/MISP/misp-objects/blob/main/objects/scrippsco2-co2-monthly/definition.json) - Monthly average CO2 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-o18-daily](https://github.com/MISP/misp-objects/blob/main/objects/scrippsco2-o18-daily/definition.json) - Daily average O18 concentrations (ppm) derived from flask air samples.
- [objects/scrippsco2-o18-monthly](https://github.com/MISP/misp-objects/blob/main/objects/scrippsco2-o18-monthly/definition.json) - Monthly average O18 concentrations (ppm) derived from flask air samples.
- [objects/script](https://github.com/MISP/misp-objects/blob/main/objects/script/definition.json) - Object describing a computer program written to be run in a special run-time environment. The script or shell script can be used for malicious activities but also as support tools for threat analysts.
- [objects/security-playbook](https://github.com/MISP/misp-objects/blob/main/objects/security-playbook/definition.json) - The security-playbook object provides meta-information and allows managing, storing, and sharing cybersecurity playbooks and orchestration workflows.
- [objects/shadowserver-malware-url-report](https://github.com/MISP/misp-objects/blob/main/objects/shadowserver-malware-url-report/definition.json) - This report identifies URLs that were observed in exploitation attempts in the last 24 hours. They are assumed to contain a malware payload or serve as C2 controllers. If a payload was successfully downloaded in the last 24 hours, it’s SHA256 hash will also be published. The data is primarily sourced from honeypots (in which case they will often be IoT related), but other sources are possible. As always, you only receive information on IPs found on your network/constituency or in the case of a National CSIRT, your country. Ref: https://www.shadowserver.org/what-we-do/network-reporting/malware-url-report/.
- [objects/shadowserver-scan-http-proxy](https://github.com/MISP/misp-objects/blob/main/objects/shadowserver-scan-http-proxy/definition.json) - This report identifies open HTTP proxy servers on multiple ports. While HTTP proxies have legitimate uses, they are also used for attacks or other forms of abuse. https://www.shadowserver.org/what-we-do/network-reporting/open-http-proxy-report/.
- [objects/shell-commands](https://github.com/MISP/misp-objects/blob/main/objects/shell-commands/definition.json) - Object describing a series of shell commands executed. This object can be linked with malicious files in order to describe a specific execution of shell commands.
- [objects/shodan-report](https://github.com/MISP/misp-objects/blob/main/objects/shodan-report/definition.json) - Shodan Report for a given IP.
- [objects/short-message-service](https://github.com/MISP/misp-objects/blob/main/objects/short-message-service/definition.json) - Short Message Service (SMS) object template describing one or more SMS message. Restriction of the initial format 3GPP 23.038 GSM character set doesn't apply.
- [objects/shortened-link](https://github.com/MISP/misp-objects/blob/main/objects/shortened-link/definition.json) - Shortened link and its redirect target.
- [objects/sigma](https://github.com/MISP/misp-objects/blob/main/objects/sigma/definition.json) - An object describing a Sigma rule (or a Sigma rule name).
- [objects/sigmf-archive](https://github.com/MISP/misp-objects/blob/main/objects/sigmf-archive/definition.json) - An object representing an archive containing one or multiple recordings in the Signal Metadata Format Specification (SigMF).
- [objects/sigmf-expanded-recording](https://github.com/MISP/misp-objects/blob/main/objects/sigmf-expanded-recording/definition.json) - An object representing a single IQ/RF sample in the Signal Metadata Format Specification (SigMF).
- [objects/sigmf-recording](https://github.com/MISP/misp-objects/blob/main/objects/sigmf-recording/definition.json) - An object representing a single IQ/RF sample in the Signal Metadata Format Specification (SigMF).
- [objects/social-media-group](https://github.com/MISP/misp-objects/blob/main/objects/social-media-group/definition.json) - Social media group object template describing a public or private group or channel.
- [objects/software](https://github.com/MISP/misp-objects/blob/main/objects/software/definition.json) - The Software object represents high-level properties associated with software, including software products. STIX 2.1 - 6.14.
- [objects/spearphishing-attachment](https://github.com/MISP/misp-objects/blob/main/objects/spearphishing-attachment/definition.json) - Spearphishing Attachment.
- [objects/spearphishing-link](https://github.com/MISP/misp-objects/blob/main/objects/spearphishing-link/definition.json) - Spearphishing Link.
- [objects/splunk](https://github.com/MISP/misp-objects/blob/main/objects/splunk/definition.json) - Splunk / Splunk ES object.
- [objects/ss7-attack](https://github.com/MISP/misp-objects/blob/main/objects/ss7-attack/definition.json) - SS7 object of an attack as seen on the SS7 signaling protocol supporting GSM/GPRS/UMTS networks.
- [objects/ssh-authorized-keys](https://github.com/MISP/misp-objects/blob/main/objects/ssh-authorized-keys/definition.json) - An object to store ssh authorized keys file.
- [objects/stairwell](https://github.com/MISP/misp-objects/blob/main/objects/stairwell/definition.json) - Stairwell leverages automated analysis, YARA rule libraries, shared malware feeds, privately run AV verdicts, static & dynamic analysis, malware unpacking, and variant discovery.
- [objects/stix2-pattern](https://github.com/MISP/misp-objects/blob/main/objects/stix2-pattern/definition.json) - An object describing a STIX pattern. The object can be linked via a relationship to other attributes or objects to describe how it can be represented as a STIX pattern.
- [objects/stock](https://github.com/MISP/misp-objects/blob/main/objects/stock/definition.json) - Object to describe stock market.
- [objects/submarine](https://github.com/MISP/misp-objects/blob/main/objects/submarine/definition.json) - Submarine description.
- [objects/suricata](https://github.com/MISP/misp-objects/blob/main/objects/suricata/definition.json) - An object describing one or more Suricata rule(s) along with version and contextual information.
- [objects/target-system](https://github.com/MISP/misp-objects/blob/main/objects/target-system/definition.json) - Description about an targeted system, this could potentially be a compromissed internal system.
- [objects/task](https://github.com/MISP/misp-objects/blob/main/objects/task/definition.json) - Task object as described in STIX 2.1 Incident object extension.
- [objects/tattoo](https://github.com/MISP/misp-objects/blob/main/objects/tattoo/definition.json) - Describes tattoos on a natural person's body.
- [objects/telegram-account](https://github.com/MISP/misp-objects/blob/main/objects/telegram-account/definition.json) - Information related to a telegram account.
- [objects/telegram-bot](https://github.com/MISP/misp-objects/blob/main/objects/telegram-bot/definition.json) - Information related to a telegram bot.
- [objects/temporal-event](https://github.com/MISP/misp-objects/blob/main/objects/temporal-event/definition.json) - A temporal event consists of some temporal and spacial boundaries. Spacial boundaries can be physical, virtual or hybrid.
- [objects/thaicert-group-cards](https://github.com/MISP/misp-objects/blob/main/objects/thaicert-group-cards/definition.json) - Adversary group cards inspired by ThaiCERT.
- [objects/threatgrid-report](https://github.com/MISP/misp-objects/blob/main/objects/threatgrid-report/definition.json) - ThreatGrid report.
- [objects/timecode](https://github.com/MISP/misp-objects/blob/main/objects/timecode/definition.json) - Timecode object to describe a start of video sequence (e.g. CCTV evidence) and the end of the video sequence.
- [objects/timesketch-timeline](https://github.com/MISP/misp-objects/blob/main/objects/timesketch-timeline/definition.json) - A timesketch timeline object based on mandatory field in timesketch to describe a log entry.
- [objects/timesketch_message](https://github.com/MISP/misp-objects/blob/main/objects/timesketch_message/definition.json) - A timesketch message entry.
- [objects/timestamp](https://github.com/MISP/misp-objects/blob/main/objects/timestamp/definition.json) - A generic timestamp object to represent time including first time and last time seen. Relationship will then define the kind of time relationship.
- [objects/tor-hiddenservice](https://github.com/MISP/misp-objects/blob/main/objects/tor-hiddenservice/definition.json) - Tor hidden service (onion service) object.
- [objects/tor-node](https://github.com/MISP/misp-objects/blob/main/objects/tor-node/definition.json) - Tor node (which protects your privacy on the internet by hiding the connection between users Internet address and the services used by the users) description which are part of the Tor network at a time.
- [objects/traceability-impact](https://github.com/MISP/misp-objects/blob/main/objects/traceability-impact/definition.json) - Traceability Impact object as described in STIX 2.1 Incident object extension.
- [objects/tracking-id](https://github.com/MISP/misp-objects/blob/main/objects/tracking-id/definition.json) - Analytics and tracking ID such as used in Google Analytics or other analytic platform.
- [objects/transaction](https://github.com/MISP/misp-objects/blob/main/objects/transaction/definition.json) - An object to describe a financial transaction.
- [objects/translation](https://github.com/MISP/misp-objects/blob/main/objects/translation/definition.json) - Used to keep a text and its translation.
- [objects/transport-ticket](https://github.com/MISP/misp-objects/blob/main/objects/transport-ticket/definition.json) - A transport ticket.
- [objects/trustar_report](https://github.com/MISP/misp-objects/blob/main/objects/trustar_report/definition.json) - TruStar Report.
- [objects/tsk-chats](https://github.com/MISP/misp-objects/blob/main/objects/tsk-chats/definition.json) - An Object Template to gather information from evidential or interesting exchange of messages identified during a digital forensic investigation.
- [objects/tsk-web-bookmark](https://github.com/MISP/misp-objects/blob/main/objects/tsk-web-bookmark/definition.json) - An Object Template to add evidential bookmarks identified during a digital forensic investigation.
- [objects/tsk-web-cookie](https://github.com/MISP/misp-objects/blob/main/objects/tsk-web-cookie/definition.json) - An TSK-Autopsy Object Template to represent cookies identified during a forensic investigation.
- [objects/tsk-web-downloads](https://github.com/MISP/misp-objects/blob/main/objects/tsk-web-downloads/definition.json) - An Object Template to add web-downloads.
- [objects/tsk-web-history](https://github.com/MISP/misp-objects/blob/main/objects/tsk-web-history/definition.json) - An Object Template to share web history information.
- [objects/tsk-web-search-query](https://github.com/MISP/misp-objects/blob/main/objects/tsk-web-search-query/definition.json) - An Object Template to share web search query information.
- [objects/twitter-account](https://github.com/MISP/misp-objects/blob/main/objects/twitter-account/definition.json) - Twitter account.
- [objects/twitter-list](https://github.com/MISP/misp-objects/blob/main/objects/twitter-list/definition.json) - Twitter list.
- [objects/twitter-post](https://github.com/MISP/misp-objects/blob/main/objects/twitter-post/definition.json) - Twitter post (tweet).
- [objects/typosquatting-finder](https://github.com/MISP/misp-objects/blob/main/objects/typosquatting-finder/definition.json) - Typosquatting info.
- [objects/typosquatting-finder-result](https://github.com/MISP/misp-objects/blob/main/objects/typosquatting-finder-result/definition.json) - Typosquatting result.
- [objects/url](https://github.com/MISP/misp-objects/blob/main/objects/url/definition.json) - url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.
- [objects/user-account](https://github.com/MISP/misp-objects/blob/main/objects/user-account/definition.json) - User-account object, defining aspects of user identification, authentication, privileges and other relevant data points.
- [objects/user-action](https://github.com/MISP/misp-objects/blob/main/objects/user-action/definition.json) - Represent an user action.
- [objects/vehicle](https://github.com/MISP/misp-objects/blob/main/objects/vehicle/definition.json) - Vehicle object template to describe a vehicle information and registration.
- [objects/victim](https://github.com/MISP/misp-objects/blob/main/objects/victim/definition.json) - Victim object describes the target of an attack or abuse.
- [objects/virustotal-graph](https://github.com/MISP/misp-objects/blob/main/objects/virustotal-graph/definition.json) - VirusTotal graph.
- [objects/virustotal-report](https://github.com/MISP/misp-objects/blob/main/objects/virustotal-report/definition.json) - VirusTotal report.
- [objects/virustotal-submission](https://github.com/MISP/misp-objects/blob/main/objects/virustotal-submission/definition.json) - VirusTotal Submission.
- [objects/vulnerability](https://github.com/MISP/misp-objects/blob/main/objects/vulnerability/definition.json) - Vulnerability object describing a common vulnerability enumeration which can describe published, unpublished, under review or embargo vulnerability for software, equipments or hardware.
- [objects/weakness](https://github.com/MISP/misp-objects/blob/main/objects/weakness/definition.json) - Weakness object describing a common weakness enumeration which can describe usable, incomplete, draft or deprecated weakness for software, equipment of hardware.
- [objects/whois](https://github.com/MISP/misp-objects/blob/main/objects/whois/definition.json) - Whois records information for a domain name or an IP address.
- [objects/windows-service](https://github.com/MISP/misp-objects/blob/main/objects/windows-service/definition.json) - Windows service and detailed about a service running a Windows operating system.
- [objects/x-header](https://github.com/MISP/misp-objects/blob/main/objects/x-header/definition.json) - X header generic object for SMTP, HTTP or any other protocols using X headers.
- [objects/x509](https://github.com/MISP/misp-objects/blob/main/objects/x509/definition.json) - x509 object describing a X.509 certificate.
- [objects/yabin](https://github.com/MISP/misp-objects/blob/main/objects/yabin/definition.json) - yabin.py generates Yara rules from function prologs, for matching and hunting binaries. ref: https://github.com/AlienVault-OTX/yabin.
- [objects/yara](https://github.com/MISP/misp-objects/blob/main/objects/yara/definition.json) - An object describing a YARA rule (or a YARA rule name) along with its version.
- [objects/youtube-channel](https://github.com/MISP/misp-objects/blob/main/objects/youtube-channel/definition.json) - A YouTube channel.
- [objects/youtube-comment](https://github.com/MISP/misp-objects/blob/main/objects/youtube-comment/definition.json) - A YouTube video comment.
- [objects/youtube-playlist](https://github.com/MISP/misp-objects/blob/main/objects/youtube-playlist/definition.json) - A YouTube playlist.
- [objects/youtube-video](https://github.com/MISP/misp-objects/blob/main/objects/youtube-video/definition.json) - A YouTube video.

## MISP objects relationships

The MISP object model is open and allows user to use their own relationships. MISP provides a list of default relationships that can be used if you plan to share your events with other MISP communities.

- [relationships](relationships/definition.json) - list of predefined default relationships which can be used to link MISP objects together and explain the context of the relationship.

## How to contribute MISP objects?

Fork the project, create a new directory in the [objects directory](objects/) matching your object name. Objects must be composed
of existing MISP attributes. If you are missing any specific attributes, feel free to open an issue in the [MISP project](https://www.github.com/MISP/MISP).

We recommend to add a **text** attribute in an object to allow users to add comments or correlate text.

If the unparsed object can be included, a **raw-base64** attribute can be used in the object to import the whole object.

Every object needs a **uuid** which can be created using **uuidgen -r** on a linux command line.

When the object is created, the `validate_all.sh` and `jq_all_the_things.sh` is run for validation, pull a request on this project. We usually merge the objects if it fits existing use-cases.

### Best practices when creating MISP object templates

- Use lower-case names without underscore or special characters (except minus) for the field names
- Add a description in the object template explaining the scope and use-cases of your object templates
- If the object is the mapping of an existing format, add a reference into the description of the object template
- `first-seen` and `last-seen` are not required in a object template as an object has those fields by default. If you need additional temporal information, add new specific field(s).
- Be lax on the number of fields required by default (e.g. use `requiredOneOf`).
- Review existing object templates before creating a new one. When doing a pull-request, don't hesitate to add the logic why a new template is required.

## MISP objects documentation

The MISP objects are documented at the following location in [HTML](https://www.misp-project.org/objects.html) and [PDF](https://www.misp-project.org/objects.pdf).

The documentation is automatically generated from the MISP objects template expressed in JSON.

## What are the advantages of MISP objects versus existing standards?

MISP objects are dynamically used objects that are contributed by users of MISP (the threat sharing platform) or other information sharing platforms.

The aim is to allow a dynamic update of objects definition in operational distributed sharing systems like MISP. Security threats and their related indicators are quite dynamic, standardized formats are quite static and new indicators require a significant time before being standardized.

The MISP object model allows for adding new combined indicator formats based on their usage without changing the underlying code base of MISP or other threat sharing platform using it. The definition of the objects can then be propagated along with the indicators itself.

## License

### MISP Object JSON files

The MISP objects (JSON files) are dual-licensed under:

- [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/legalcode) (CC0 1.0) - Public Domain Dedication.

or

~~~~
 Copyright (c) 2016-2024 Alexandre Dulaunoy - a@foo.be
 Copyright (c) 2016-2024 CIRCL - Computer Incident Response Center Luxembourg
 Copyright (c) 2016-2024 Andras Iklody
 Copyright (c) 2016-2024 Raphael Vinot
 Copyright (c) 2016-2024 Christian Studer
 Copyright (c) 2016-2024 Various contributors to MISP Project

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

Copyright (C) 2016-2024 Andras Iklody
Copyright (C) 2016-2024 Alexandre Dulaunoy
Copyright (C) 2016-2024 CIRCL - Computer Incident Response Center Luxembourg

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
