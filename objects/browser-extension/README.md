# browser-extension

**Category:** misc  
**UUID:** 7749dcb5-57d7-4337-99e1-1d9448f1739e  
**Version:** 1

Browser extension supply chain threat intelligence. Captures compromised or malicious extension release events, including permission escalation diffs, C2 infrastructure, and analysis verdicts.

## Motivation

Browser extensions are an established and escalating supply chain attack surface. Threat actors compromise extensions through phishing developer accounts, leaked store API keys, and purchasing legitimate extensions outright — then push silent malicious updates to millions of users through the official store update mechanism, bypassing endpoint controls that treat signed store updates as trusted.

**Documented incidents (2024–2026):**

- **December 2024 — Cyberhaven + 35 extensions (~2.6M users):** A phishing attack against Cyberhaven's developer account enabled a malicious Christmas Eve update. The campaign simultaneously compromised ~35 other Chrome extensions (Internxt VPN, Lumos, ParrotTalks, and others), replacing legitimate builds with versions that exfiltrated session cookies and identity tokens to attacker infrastructure.
- **December 2025 — Trust Wallet v2.68 (~$8.5M stolen):** A leaked Chrome Web Store API key allowed attackers to bypass internal release controls and push a malicious update (v2.68) to ~1M users. The update drained cryptocurrency from 2,520 wallet addresses within hours of publication.
- **2025 — RedDirection campaign (~2.3M users):** 18 Chrome and Edge extensions — including verified, long-standing tools such as colour pickers and volume controls — were silently converted to malicious versions after their developer accounts were compromised. Extensions hijacked browsing sessions, tracked all visited URLs, and redirected users to phishing pages.
- **June 2025 — Operation Phantom Enigma:** Targeted campaign against Brazilian banking customers; malicious extensions bypassed 2FA and exfiltrated banking credentials from 722 confirmed victims.
- **May 2026 — Nx Console VS Code extension:** Malicious version published for 11–18 minutes before takedown; during that window ~3,800 GitHub internal repositories were exfiltrated via stolen developer credentials.

Socket's threat intelligence programme ([socket.dev/blog/the-growing-risk-of-malicious-browser-extensions](https://socket.dev/blog/the-growing-risk-of-malicious-browser-extensions)) documents over 3.2M users impacted by malicious extensions in 2024–2025 alone, with attack capabilities including full webRequest interception, keylogging, screen capture, and TOTP seed theft.

**The intelligence gap:** No existing MISP object captures extension-level threat intelligence. Analysts sharing IoCs for these attacks currently resort to generic `url`, `domain`, or `file` objects, losing the structural context that makes the intelligence actionable: which permissions were added, which version introduced the malicious behaviour, what the attacker infrastructure looks like, and whether this is a store-compromise or a purchase-and-weaponise pattern.

This object enables structured sharing of:
- Compromised extension release events (version A clean → version B malicious)
- Permission escalation diffs (`permissions-added`, `host-permissions-added`)
- C2 and exfiltration infrastructure linked to a specific extension update
- Verdict and confidence from automated or manual analysis

## Attributes

| Attribute | Type | Multiple | Description |
|-----------|------|----------|-------------|
| `id` *(required)* | text | | Extension store ID (Chrome Web Store item ID or Firefox AMO slug) |
| `name` | text | | Human-readable extension name |
| `ecosystem` | text | | Distribution channel: `chrome`, `firefox`, `edge` |
| `version-malicious` | text | | First version with malicious behaviour |
| `version-clean` | text | | Last known-clean version |
| `publisher` | text | | Developer account name |
| `store-url` | url | | Link to the store listing |
| `manifest-version` | text | | `mv2` or `mv3` |
| `permissions-added` | text | ✓ | Permissions newly granted in the malicious version |
| `host-permissions-added` | text | ✓ | New host permission patterns (e.g. `<all_urls>`) |
| `malicious-file` | filename | ✓ | Files inside the CRX/XPI with malicious code |
| `c2-url` | url | ✓ | C2 URL contacted by the extension |
| `exfil-url` | url | ✓ | Exfiltration endpoint (if distinct from C2) |
| `attack-pattern` | text | | Short attack label (e.g. `webRequest credential intercept`) |
| `crx-sha256` | sha256 | | SHA-256 of the malicious CRX/XPI |
| `verdict` | text | | `suspicious`, `malicious`, `clean`, `insufficient_data` |
| `confidence` | float | | 0.0–1.0 confidence score |
| `analysis-source` | text | | `manual`, `automated`, `vendor` |
| `first-seen` | datetime | | When the malicious version was first observed |
| `description` | text | | Free-text threat summary |

## ATT&CK Mapping

| Technique | ID | Relevance |
|-----------|----|-----------|
| Supply Chain Compromise: Software Supply Chain | T1195.002 | Malicious update pushed through official store |
| Browser Session Hijacking | T1185 | webRequest interception of authenticated sessions |
| Steal Web Session Cookie | T1539 | Cookie exfiltration via content script |
| Exfiltration Over Web Service | T1567 | HTTPS exfil to attacker-controlled endpoint |
| Masquerading | T1036 | Legitimate extension name concealing malicious payload |

## Example

A compromised `productivity-helper` v1.5.1 silently gained `<all_urls>` host permission and a service worker that POSTs all web request bodies to an attacker endpoint:

```json
{
  "name": "browser-extension",
  "meta-category": "software",
  "description": "Compromised Chrome extension — productivity-helper v1.5.1",
  "Attribute": [
    {"object_relation": "id",                     "value": "abcdefghijklmnop"},
    {"object_relation": "name",                   "value": "productivity-helper"},
    {"object_relation": "ecosystem",              "value": "chrome"},
    {"object_relation": "version-malicious",      "value": "1.5.1"},
    {"object_relation": "version-clean",          "value": "1.5.0"},
    {"object_relation": "publisher",              "value": "prodtools-dev"},
    {"object_relation": "manifest-version",       "value": "mv3"},
    {"object_relation": "permissions-added",      "value": "webRequest"},
    {"object_relation": "permissions-added",      "value": "webRequestBlocking"},
    {"object_relation": "host-permissions-added", "value": "<all_urls>"},
    {"object_relation": "malicious-file",         "value": "bg.js"},
    {"object_relation": "c2-url",                 "value": "https://collect.attacker.example.com/beacon"},
    {"object_relation": "attack-pattern",         "value": "webRequest full-body intercept and exfiltration"},
    {"object_relation": "verdict",                "value": "malicious"},
    {"object_relation": "confidence",             "value": "0.95"},
    {"object_relation": "analysis-source",        "value": "automated"},
    {"object_relation": "first-seen",             "value": "2024-12-25T00:00:00Z"}
  ]
}
```

## Relationships

Suggested object relationships:

| Related object | Relationship verb | Notes |
|---------------|-------------------|-------|
| `domain` / `url` | `communicates-with` | C2 or exfil endpoint |
| `file` | `drops` | CRX/XPI via `crx-sha256` |
| `threat-actor` | `attributed-to` | Actor behind the compromise |
| `vulnerability` | `related-to` | If a browser API vuln was exploited |
| `software` | `related-to` | The legitimate extension being impersonated |
