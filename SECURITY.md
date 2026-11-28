# Security policy

## Reporting a vulnerability

Use the private GitHub Security Advisory form at [Report a vulnerability](https://github.com/draarivpatel-ui/capgate/security/advisories/new). Do not open a public issue, pull request or discussion with exploit details.

Never include a live secret, token, cookie, private key, victim hostname or proprietary payload in a report. Use synthetic values and redacted transcripts.

## Supported versions

| Version | Status |
| --- | --- |
| latest `main` | Supported |

Security fixes are applied to the latest state of the default branch.

## Scope

This policy covers the static CapGate browser application and its Node modules, including tool-call inspection, shell parsing, policy evaluation, benchmark output, URL-hash state, receipts and audit exports.

In scope:

- A cross-site scripting or HTML injection path through tool-call input, benchmark corpus text, policy data, share links, imported text or report output.
- A parser, canonicalization or policy-evaluation bypass that marks a blocked command, path, URL or secret access as allowed.
- A share-link decoder or serialization flaw that bypasses validation, corrupts another policy state, or executes attacker-controlled code.
- A report export or spreadsheet escaping flaw that makes generated output execute a formula or script when opened.
- A digest or receipt verification bypass that makes altered audit output validate as untampered.

Out of scope:

- Browser vulnerabilities, operating system compromise or physical access to the machine.
- Damage caused by modified copies of the static application that do not come from this repository.
- Attacks that only demonstrate why a dangerous example command in the benchmark corpus is unsafe.

## Coordinated disclosure

- Acknowledgment: within 3 business days.
- Initial triage: within 14 calendar days.
- Fix or mitigation target: within 90 calendar days for confirmed reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.
