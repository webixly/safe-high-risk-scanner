# Security Policy

**Important:** This tool is intended for educational and research use only and should be used **only** against systems for which you have explicit, written authorization. Do not use this tool against targets you do not own or are not authorized to test.

---

## Reporting a Vulnerability

If you discover a security issue in this repository (code bug, logic flaw, or other), please follow these steps:

1. **Do not disclose the vulnerability publicly.** Public disclosure may put users at risk.
2. Open a **private GitHub Issue** labeled `SECURITY` or send an email to the contact below with `SECURITY` in the subject line.
   - Email: `aymenmoh20000@gmail.com` ← **replace this** with your actual contact email.
   - Alternatively, use GitHub Security Advisories for a private disclosure.
3. Provide the following information where possible:
   - A concise description of the issue and its potential impact.
   - Reproduction steps (preferably on a local/test environment).
   - The repository commit or version you tested against.
   - Environment details (Python version, OS) and minimal proof-of-concept (PoC) if appropriate.
   - Any logs, screenshots, or other artifacts (avoid including real secrets).

We will acknowledge receipt of your report within **72 hours** and provide an initial assessment.

---

## Response Process & Timeline

- **Acknowledgement:** within 72 hours.
- **Initial Triage:** within 7 days to determine severity and next steps.
- **Mitigation/Patch:** for critical issues, we aim to provide a fix or mitigation guidance within 30 days where feasible.
- **Public Disclosure:** we will not publicly disclose the vulnerability until a patch or mitigation guidance is available, unless an agreed-upon alternative is reached with the reporter.

Note: Timelines depend on the complexity of the issue and availability of necessary information.

---

## Safe Reporting Guidelines

- Do **not** include real credentials, API keys, personal data, or other secrets in reports.
- If you need to demonstrate an exploit, provide reproducible steps on a local or isolated test environment.
- Keep PoC code minimal and non-destructive. Do not include weaponized exploits that could damage systems or data.

---

## What to Report

Please report issues in the code or repository that could reasonably be considered security vulnerabilities, including but not limited to:

- Remote code execution (RCE) or any code path enabling arbitrary command execution.
- Hard-coded secrets, API keys, or credentials in the repository.
- Logic flaws in the project that could lead to unauthorized access, data leakage, or privilege escalation.
- Any behavior that causes the project to perform network actions without clear user consent that could damage third parties.

---

## What We Do Not Consider a Security Issue (under this policy)

- Results of scans or findings that are the result of running this tool against external systems (those are the responsibility of the user running the tool).
- Issues in third-party libraries that do not directly affect the safety of this repository (unless they are used in an unsafe way by this project).
- Documentation typos, feature requests, or general bugs that do not have security implications.

---

## Repository Safety Practices

- Do not commit secrets or credentials into the repository. Use environment variables or CI secrets (e.g., GitHub Secrets).
- `cve_cache_high_risk.json`, `high_risk_report.md`, and the `REPORTS/` directory are included in `.gitignore` to avoid committing sensitive output.
- We recommend using GitHub Dependabot and code scanning tools for additional automated checks.

---

## CVE / Coordinated Disclosure

If a genuine vulnerability is discovered in the project and requires assignment of a CVE or public advisory, we will coordinate with the reporter to prepare an advisory and follow responsible disclosure practices (including reasonable embargo periods for fixes).

---

## Emergency / Critical Reports

For urgent issues (active exploitation, major data exposure), please use an email subject line containing both `SECURITY` and `URGENT`. We will prioritize triage and response.

- Contact (urgent): `aymenmoh20000@gmail.com` ← **replace** with your preferred emergency contact.

---

## Safe Harbor

We value good-faith security research. If you follow this disclosure policy and do not publicly disclose the issue before a fix is available, we will not pursue action against you for discovering or reporting the issue. Please refrain from testing production systems beyond what is necessary to reproduce an issue in a controlled environment.

---

## Optional: Encrypted Reports

If you prefer to send encrypted reports, include your PGP public key (or fingerprint) here and we will use it to encrypt our response:

- PGP key / fingerprint: `-- insert PGP key or fingerprint here if available --`

---

## Document Version

- Last updated: 2025-11-04  
- Maintainer / Security contact: `webixly` — replace with your name and email above.

