# Safe High-Risk Indicator Scanner (Passive)

[![Build: CI](https://github.com/<YOUR_USER>/<YOUR_REPO>/actions/workflows/ci.yml/badge.svg)](https://github.com/<YOUR_USER>/<YOUR_REPO>/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Issues](https://img.shields.io/github/issues/<YOUR_USER>/<YOUR_REPO>)](https://github.com/<YOUR_USER>/<YOUR_REPO>/issues)
[![Security Policy](https://img.shields.io/badge/Security-Policy-yellow.svg)](./SECURITY.md)

---

## Short Project Description (Executive)

**Safe High-Risk Indicator Scanner** is a passive (GET-only) reconnaissance tool designed for academic and educational use.  
It identifies high-risk indicators on web applications — such as exposed admin panels, backup files, directory listings, upload endpoints, debug traces, and correlates detected technologies with public CVE records (NVD) for awareness and remediation guidance. **This tool does NOT perform exploitation.**

This repository provides a reproducible, documented, and ethically constrained implementation suitable for university projects, demonstrations, and security research under explicit authorization.

---

## Table of Contents

1. [Key Features](#key-features)  
2. [Intended Use & Legal Notice](#intended-use--legal-notice)  
3. [Quick Start (Install & Run)](#quick-start-install--run)  
4. [Command Overview & Example](#command-overview--example)  
5. [Output / Report Example](#output--report-example)  
6. [Architecture & Design](#architecture--design)  
7. [Testing & CI](#testing--ci)  
8. [Limitations & Known Risks](#limitations--known-risks)  
9. [Contributing & Code of Conduct](#contributing--code-of-conduct)  
10. [Security / Responsible Disclosure](#security--responsible-disclosure)  
11. [Citation / Academic Use](#citation--academic-use)  
12. [License & Contact](#license--contact)

---

## Key Features

- Passive GET-only checks of known sensitive paths (admin pages, backups, phpinfo, robots, sitemap).  
- HTTP header and cookie analysis (HSTS, CSP, X-Frame-Options, Secure/HttpOnly cookie flags).  
- HTML analysis: form detection (including file-upload forms), generator meta, JS libraries fingerprinting.  
- TLS certificate basic inspection (expiration, protocol).  
- Heuristic product fingerprinting (Server, X-Powered-By, CMS generator, JS libs) and keyword-based NVD queries.  
- Local CVE caching to minimize external queries and avoid rate limits.  
- Generates a human-readable Markdown report `high_risk_report.md` with findings and remediation guidance.  
- Designed for packaging (PyInstaller) and CI-friendly operation.

---

## Intended Use & Legal Notice

**Important — Read before use:**  
This tool is intended **only** for use on systems you own or for which you have explicit written permission to test. Unauthorized scanning of systems is illegal and unethical.

By using this software you confirm you have the right to scan the specified target(s) and accept responsibility for compliance with applicable laws and policies.

---

## Quick Start (Install & Run)

> Tested with Python 3.10+. Use a virtual environment.

```bash
# Clone repository
git clone https://github.com/<YOUR_USER>/<YOUR_REPO>.git
cd <YOUR_REPO>

# Create virtual environment and install dependencies
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows (PowerShell)
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt

# Optional: set NVD API key for higher rate limits
export NVD_API_KEY="your_api_key_here"    # Linux/macOS
setx NVD_API_KEY "your_api_key_here"      # Windows (restart may be needed)

# Run the scanner
python src/scanner.py
# Enter the target URL when prompted (e.g., example.com or https://example.com)
