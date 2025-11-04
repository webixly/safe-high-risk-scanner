#!/usr/bin/env python3
"""
Safe High-Risk Indicator Scanner (Passive)
- Scans a target URL you own/are authorized to test.
- Detects high-risk indicators (admin panels, backup dumps, upload forms, dir listing, debug hints).
- Fingerprints tech heuristically (Server/CMS/JS libs).
- Queries NVD for CVEs and filters for likely full-compromise vectors (RCE, auth bypass, pre-auth, priv-esc).
- NO exploitation, NO intrusive actions. GET-only checks for a small set of paths.

Notes:
- Set NVD_API_KEY env var (optional) to improve rate limits.
- Designed to package cleanly with PyInstaller/auto-py-to-exe (pyfiglet is optional and safely handled).
"""


import re
import json
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional
import pyautogui, time, os, pyfiglet
from termcolor import cprint, colored 
from colorama import Fore, Style, init
import requests
from bs4 import BeautifulSoup

os.system('cls' if os.name == 'nt'else 'clear')
banner = pyfiglet.figlet_format("Cyber Tool ",font='ansi_shadow')
cprint(banner, "cyan")

cprint("   >>> Cyber Security Tool by @p4bl0.py <<<\n","yellow",attrs=["bold"])
time.sleep(2)

cprint("   >>> Wait please .............<<<\n","red",attrs=["bold"])

time.sleep(2)


TIMEOUT = 10
REPORT_FILE = "high_risk_report.md"
USER_AGENT = "SafeHighRiskScanner/1.0"
NVD_API_SLEEP = 1.2
NVD_API_KEY = os.environ.get("NVD_API_KEY")

COMMON_SECURITY_HEADERS = [
    "Strict-Transport-Security","Content-Security-Policy","X-Frame-Options",
    "X-Content-Type-Options","Referrer-Policy","Permissions-Policy",
    "Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy",
]

EXPOSED_PATHS = [
    "/robots.txt","/sitemap.xml","/.well-known/security.txt","/.git/HEAD","/.env",
    "/server-status","/phpinfo.php","/.DS_Store","/.gitignore"
]

SENSITIVE_ADMIN_PATHS = [
    "/wp-admin/","/wp-login.php","/administrator/","/user/login","/typo3/",
    "/umbraco/","/manager/html","/phpmyadmin/","/pma/","/adminer.php",
    "/cfide/administrator/index.cfm","/geoserver/web/","/_admin/","/admin/","/login",
    "/setup.php","/install.php"
]

BACKUP_FILES = [
    "/backup.zip","/db.sql","/database.sql","/site-backup.tar.gz",
    "/www.zip","/web.zip","/dump.sql","/.git/config","/config.php.bak"
]

JS_LIB_HINTS = {
    "jquery": re.compile(r"jquery[-.]?(\d+(?:\.\d+){0,3})?(\.min)?\.js(?:\?.*)?$", re.I),
    "bootstrap": re.compile(r"bootstrap(?:\.bundle)?[-.]?(\d+(?:\.\d+){0,3})?(\.min)?\.js", re.I),
    "react": re.compile(r"react[-.]?(\d+(?:\.\d+){0,3})?(\.min)?\.js", re.I),
    "vue": re.compile(r"vue[-.]?(\d+(?:\.\d+){0,3})?(\.min)?\.js", re.I),
    "angular": re.compile(r"angular[-.]?(\d+(?:\.\d+){0,3})?(\.min)?\.js", re.I),
}

HIGH_RISK_KEYWORDS = [
    r"\bremote code execution\b", r"\bRCE\b", r"\bcode execution\b",
    r"\bunauthenticated\b", r"\bpre-auth\b", r"\bpreauth\b",
    r"\bprivilege escalation\b", r"\bprivesc\b",
    r"\bauthentication bypass\b", r"\bcommand injection\b",
    r"\barbitrary file upload\b", r"\barbitrary file write\b",
    r"\bdeserialization\b"
]


def status(msg: str):
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    print(f"[{now}] {msg}")

def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url.strip("/")
    return url

def fetch(url: str) -> Tuple[requests.Response, requests.Session]:
    ses = requests.Session()
    ses.headers.update({"User-Agent": USER_AGENT})
    resp = ses.get(url, timeout=TIMEOUT, allow_redirects=True)
    return resp, ses

def check_https_redirect(origin_url: str) -> Optional[bool]:
    http_url = re.sub(r"^https://", "http://", origin_url, flags=re.I)
    try:
        r = requests.get(http_url, timeout=TIMEOUT, allow_redirects=False, headers={"User-Agent": USER_AGENT})
        return r.status_code in (301,302,307,308) and "https://" in r.headers.get("Location","")
    except Exception:
        return None

def get_tls_info(host: str, port: int = 443) -> Dict[str, Optional[str]]:
    info = {"tls_version": None, "not_after": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info["tls_version"] = ssock.version()
                cert = ssock.getpeercert()
                if "notAfter" in cert: info["not_after"] = cert["notAfter"]
    except Exception:
        pass
    return info

def analyze_headers(resp: requests.Response):
    found = {h: resp.headers.get(h) for h in COMMON_SECURITY_HEADERS}
    cookie_flags = []
    set_cookie = resp.headers.get("Set-Cookie")
    if set_cookie:
        parts = re.split(r", (?=[^ ;=]+?=)", set_cookie)
        for line in parts:
            pieces = [p.strip() for p in line.split(";")]
            if not pieces or "=" not in pieces[0]:
                continue
            name, _ = pieces[0].split("=", 1)
            attrs = {"secure": False, "httponly": False, "samesite": None}
            for attr in pieces[1:]:
                kv = attr.split("=", 1)
                k = kv[0].strip().lower()
                v = kv[1].strip() if len(kv) == 2 else None
                if k == "secure": attrs["secure"] = True
                elif k == "httponly": attrs["httponly"] = True
                elif k == "samesite": attrs["samesite"] = (v or "").lower()
            cookie_flags.append({"name": name, **attrs})
    else:
        for c in resp.cookies:
            cookie_flags.append({"name": c.name, "secure": bool(getattr(c, "secure", False)), "httponly": False, "samesite": None})
    return found, cookie_flags

def analyze_forms(html: str):
    soup = BeautifulSoup(html, "html.parser")
    forms_info = []
    for f in soup.find_all("form"):
        method = (f.get("method") or "GET").upper()
        inputs = [i.get("name","") for i in f.find_all(["input","textarea","select"])]
        has_csrf_like = any(re.search(r"csrf|token|authenticity", (name or ""), re.I) for name in inputs)
        # Upload hints
        upload = (
            re.search(r"type=['\"]file['\"]", str(f), re.I) or
            re.search(r"enctype=['\"]multipart/form-data['\"]", str(f), re.I)
        ) is not None
        forms_info.append({"method": method, "inputs_count": len(inputs), "csrf_token_hint": has_csrf_like, "upload_form": upload})
    return forms_info

def detect_technologies(html: str, headers: Dict[str, str]) -> Dict[str, Optional[str]]:
    tech = {"server": headers.get("Server"), "x_powered_by": headers.get("X-Powered-By"), "cms": None, "cms_name": None, "cms_version": None, "js_libs": []}
    soup = BeautifulSoup(html, "html.parser")
    gen = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
    if gen and gen.get("content"):
        content = gen.get("content")
        tech["cms"] = content
        m = re.search(r"(WordPress|Joomla|Drupal)[^\d]*([\d.]+)?", content, re.I)
        if m:
            tech["cms_name"] = m.group(1).title()
            tech["cms_version"] = (m.group(2) or "").strip() or None

    for s in soup.find_all("script"):
        src = (s.get("src") or "").strip()
        if not src: continue
        base = src.split("/")[-1]
        for name, pat in JS_LIB_HINTS.items():
            mm = pat.search(base)
            if mm:
                ver = mm.group(1) or None
                if not ver:
                    mm2 = re.search(r"/(\d+(?:\.\d+){1,3})/", src)
                    if mm2: ver = mm2.group(1)
                tech["js_libs"].append({"name": name, "version": ver, "src": src})
                break
    return tech

def gather_products_for_cve(headers: Dict[str, str], tech: Dict[str, Optional[str]]) -> List[Dict[str, Optional[str]]]:
    products = []
    server = (tech.get("server") or "").strip()
    if server:
        if "apache" in server.lower():
            m = re.search(r"Apache/?\s*([0-9.]+)", server, re.I)
            ver = m.group(1) if m else None
            products.append({"product": "Apache HTTP Server", "version": ver, "source": "Server header"})
        elif "nginx" in server.lower():
            m = re.search(r"nginx/?\s*([0-9.]+)", server, re.I)
            ver = m.group(1) if m else None
            products.append({"product": "nginx", "version": ver, "source": "Server header"})
    xpb = (tech.get("x_powered_by") or "").strip()
    if xpb:
        m = re.search(r"PHP/?\s*([0-9.]+)", xpb, re.I)
        if m:
            products.append({"product": "PHP", "version": m.group(1), "source": "X-Powered-By"})
    cms_name = tech.get("cms_name"); cms_ver = tech.get("cms_version")
    if cms_name:
        products.append({"product": cms_name, "version": cms_ver, "source": "meta generator"})
    for lib in tech.get("js_libs", []):
        name = lib["name"].strip().lower()
        disp = {"jquery":"jQuery","bootstrap":"Bootstrap","react":"React","vue":"Vue.js","angular":"AngularJS"}.get(name, name)
        products.append({"product": disp, "version": lib.get("version"), "source": f"script tag ({lib.get('src')})"})
    return products

# -----------------------
# NVD integration
# -----------------------
def query_nvd(product: str, version: Optional[str]) -> List[Dict]:
    """Keyword-based NVD query; passive and general. Filters later for high-risk keywords."""
    results = []
    if not product:
        return results
    q = f"{product} {version}" if version else product
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": q, "resultsPerPage": 200}
    headers = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        status(f"Querying NVD: {q}")
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        if resp.status_code == 200:
            j = resp.json()
            items = j.get("vulnerabilities", []) or []
            for it in items:
                cv = it.get("cve") or {}
                cve_id = cv.get("id")
                desc = ""
                descs = cv.get("descriptions") or []
                if isinstance(descs, list) and descs:
                    desc = descs[0].get("value","")
                sev = "UNKNOWN"; metrics = cv.get("metrics") or {}
                try:
                    # Extract any cvss baseSeverity present
                    for _, vv in metrics.items():
                        if isinstance(vv, list) and vv:
                            sv = vv[0].get("cvssData", {}).get("baseSeverity")
                            if sv: sev = sv; break
                except Exception:
                    pass
                results.append({
                    "id": cve_id, "title": desc or q, "severity": (sev or "UNKNOWN").upper(),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "published": cv.get("published")
                })
        else:
            status(f"Warning: NVD HTTP {resp.status_code} for {q}")
    except Exception as e:
        status(f"NVD error for {q}: {e}")
    time.sleep(NVD_API_SLEEP)
    return results

def regex_any(patterns, text):
    for pat in patterns:
        if re.search(pat, text or "", re.I):
            return True
    return False

def filter_high_risk_cves(cve_map: Dict) -> List[Dict]:
    """Return CVEs that are CRITICAL/HIGH and look like full-compromise vectors (RCE, pre-auth bypass, etc.)."""
    high = []
    for key, info in (cve_map or {}).items():
        for c in info.get("cves", []):
            desc = (c.get("title") or "")
            sev  = (c.get("severity") or "UNKNOWN").upper()
            if sev in ("CRITICAL","HIGH") and regex_any(HIGH_RISK_KEYWORDS, desc):
                prod, ver = key.split("||", 1)
                high.append({
                    "product": prod, "version": ver or None,
                    "id": c.get("id"), "severity": sev, "title": c.get("title"),
                    "url": c.get("url"), "published": c.get("published")
                })
    return high

# -----------------------
# Passive high-risk indicators
# -----------------------
def check_admin_panels(base_url: str) -> List[Tuple[str, int]]:
    out = []
    ses = requests.Session()
    ses.headers.update({"User-Agent": USER_AGENT})
    for p in SENSITIVE_ADMIN_PATHS:
        url = urllib.parse.urljoin(base_url, p)
        try:
            r = ses.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (200, 401) or re.search(r"login|password|username", r.text, re.I):
                out.append((p, r.status_code))
        except Exception:
            pass
    return out

def detect_directory_listing(html: str) -> bool:
    return bool(re.search(r"<title>Index of /|Directory listing for /|<h1>Index of /", html or "", re.I))

def detect_upload_forms(forms: List[Dict]) -> bool:
    return any(f.get("upload_form") for f in forms)

def detect_debug_hints(resp: requests.Response) -> List[str]:
    hits = []
    hdr_blob = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
    if re.search(r"X-Debug-Token|Django|DEBUG=True|Laravel|Whoops|Symfony|X-Drupal-Cache|X-Powered-By: Express", hdr_blob + resp.text, re.I):
        hits.append("Possible debug headers/pages exposed")
    return hits

def check_backup_files(base_url: str) -> List[Tuple[str, int, Optional[int]]]:
    out = []
    ses = requests.Session()
    ses.headers.update({"User-Agent": USER_AGENT})
    for p in BACKUP_FILES:
        url = urllib.parse.urljoin(base_url, p)
        try:
            r = ses.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 200 and int(r.headers.get("Content-Length","0") or 0) > 0:
                out.append((p, r.status_code, int(r.headers.get("Content-Length","0") or 0)))
        except Exception:
            pass
    return out


CVE_CACHE_FILE = "cve_cache_high_risk.json"

def load_cve_cache() -> Dict:
    if os.path.exists(CVE_CACHE_FILE):
        try:
            with open(CVE_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cve_cache(cache: Dict):
    with open(CVE_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

def update_cve_cache_for_products(products: List[Dict]) -> Tuple[Dict, Dict]:
    status("Updating CVE cache (NVD keyword search per detected product)...")
    cache = load_cve_cache()
    changes = {}
    for p in products:
        prod = p["product"]; ver = p.get("version")
        key = f"{prod}||{ver or ''}"
        status(f"  -> {prod} {ver or ''}")
        cached = cache.get(key, {"cves": [], "last_checked": None})
        cached_ids = {c.get("id") for c in cached.get("cves", []) if c.get("id")}
        live = query_nvd(prod, ver)
        live_ids = {c.get("id") for c in live if c.get("id")}
        new_ids = {i for i in live_ids if i not in cached_ids}
        if new_ids:
            merged = {c["id"]: c for c in cached.get("cves", []) if c.get("id")}
            for c in live:
                if c.get("id"): merged[c["id"]] = c
            cache[key] = {"cves": list(merged.values()), "last_checked": datetime.now(timezone.utc).isoformat()}
            changes[key] = {"product": prod, "version": ver, "added": sorted(list(new_ids))}
        else:
            cache.setdefault(key, {})["last_checked"] = datetime.now(timezone.utc).isoformat()
            cache[key].setdefault("cves", cached.get("cves", []))
    save_cve_cache(cache)
    return cache, changes

# -----------------------
# Report
# -----------------------
def make_report(target_url, status_code, redirects, headers, cookie_flags, tls, forms, tech,
                admin_panels, dir_listing, upload_forms, debug_hints, backup_files,
                cve_cache, cve_changes, high_risk_cves):
    status("Building report...")
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"# High-Risk Security Indicators for {target_url}")
    lines.append(f"_Generated: {now}_\n")

    # Summary
    lines.append("## Summary")
    missing = [h for h,v in headers.items() if not v]
    if missing: lines.append(f"- Missing security headers: {', '.join(missing)}")
    if redirects is False: lines.append("- HTTP→HTTPS redirect: **NOT enforced**")
    if tls.get("tls_version"): lines.append(f"- TLS: **{tls.get('tls_version')}**, expires: **{tls.get('not_after')}**")
    if any((not c['secure']) for c in cookie_flags): lines.append("- Some cookies lack `Secure`")
    if any((not c['httponly']) for c in cookie_flags): lines.append("- Some cookies lack `HttpOnly`")

    # Indicators
    lines.append("\n## Potential Full Compromise Indicators (Passive)")
    if admin_panels:
        lines.append("- Sensitive admin panels reachable:")
        for p, sc in admin_panels:
            lines.append(f"  - {p} → status={sc}")
    else:
        lines.append("- No common admin panels detected as exposed.")
    lines.append(f"- Directory listing detected: {bool(dir_listing)}")
    lines.append(f"- File upload forms detected: {bool(upload_forms)}")
    if debug_hints:
        for d in debug_hints: lines.append(f"- Debug hint: {d}")
    else:
        lines.append("- No obvious debug hints found.")
    if backup_files:
        lines.append("- Potential backup/dump files:")
        for p, sc, cl in backup_files:
            lines.append(f"  - {p} → status={sc} | size={cl}")
    else:
        lines.append("- No common backup/dump files detected.")

    # Tech
    lines.append("\n## Technology Fingerprint (heuristic)")
    lines.append(f"- Server: {tech.get('server')}")
    lines.append(f"- X-Powered-By: {tech.get('x_powered_by')}")
    lines.append(f"- CMS/Generator: {tech.get('cms')}")
    if tech.get("js_libs"):
        lines.append("- JS Libraries (guessed):")
        for j in tech["js_libs"]:
            lines.append(f"  - {j['name']} {j.get('version') or ''}  ({j.get('src')})")
    else:
        lines.append("- JS Libraries: None")

    # CVEs
    lines.append("\n## CVE Matches (cached)")
    any_cache = False
    for key, info in (cve_cache or {}).items():
        if not info.get("cves"): continue
        any_cache = True
        prod, ver = key.split("||", 1)
        lines.append(f"- **{prod} {ver or ''}** — last_checked: {info.get('last_checked')}")
        for c in info.get("cves", []):
            lines.append(f"  - {c.get('id')} — {c.get('title','')}  _(severity: {c.get('severity')})_  {c.get('url','')}")
    if not any_cache: lines.append("- No CVEs found in cache for detected products.")

    if cve_changes:
        lines.append("\n## New CVEs discovered this run")
        for key, ch in cve_changes.items():
            lines.append(f"- {ch['product']} {ch.get('version') or ''} → added: {', '.join(ch['added'])}")
    else:
        lines.append("\n## New CVEs discovered this run\n- None")

    lines.append("\n## High-Risk CVEs (potential full compromise)")
    if high_risk_cves:
        for c in high_risk_cves:
            ver = f" {c['version']}" if c.get("version") else ""
            dt = f" | published: {c['published']}" if c.get("published") else ""
            lines.append(f"- {c['product']}{ver} — {c['id']} ({c['severity']}): {c['title']}  {c['url']}{dt}")
    else:
        lines.append("- None matched RCE/Auth-bypass keywords at CRITICAL/HIGH severity.")

    # Remediation
    lines.append("\n## Remediation (quick wins)")
    if redirects is False: lines.append("- Enforce HTTP→HTTPS redirection.")
    if "Content-Security-Policy" in missing: lines.append("- Add a tailored Content-Security-Policy.")
    if "Strict-Transport-Security" in missing: lines.append("- Enable HSTS after full HTTPS readiness.")
    if any((not c['secure']) for c in cookie_flags): lines.append("- Set `Secure` on auth/session cookies.")
    if any((not c['httponly']) for c in cookie_flags): lines.append("- Set `HttpOnly` on auth/session cookies.")
    if admin_panels: lines.append("- Restrict admin panels (VPN/IP allowlist/SSO/MFA).")
    if dir_listing: lines.append("- Disable directory listing on the web server.")
    if upload_forms: lines.append("- Review upload endpoints with strict validation and storage isolation.")
    if debug_hints: lines.append("- Disable debug headers/pages in production.")
    if backup_files: lines.append("- Remove public backup/dump files and rotate secrets.")

    lines.append("\n---\nNote: This tool is passive and informational only. For exploitation or proof-of-control, engage authorized penetration testing with explicit written permission.")
    return "\n".join(lines)

# -----------------------
# main
# -----------------------
def main():
    
    target_input = input("Enter the website URL: ").strip()
    target = normalize_url(target_input)
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname

    try:
        status(f"Fetching {target} ...")
        resp, ses = fetch(target)

        status("Analyzing HTTP headers/cookies...")
        headers, cookie_flags = analyze_headers(resp)

        status("Checking HTTP->HTTPS redirect...")
        https_redirect = check_https_redirect(target)

        status("Getting TLS info...")
        tls_info = get_tls_info(host)

        status("Parsing page/forms...")
        forms = analyze_forms(resp.text)

        status("Detecting technologies...")
        tech = detect_technologies(resp.text, resp.headers)

        status("Identifying products for CVE lookup...")
        detected_products = gather_products_for_cve(resp.headers, tech)
        if detected_products:
            for dp in detected_products:
                status(f" - {dp['product']} {dp.get('version') or ''} (source: {dp.get('source')})")
        else:
            status("No confident product/version detected.")

        status("Updating CVE cache & querying NVD...")
        cve_cache, cve_changes = update_cve_cache_for_products(detected_products)

        # Passive high-risk indicators
        status("Checking high-risk passive indicators...")
        admin_panels = check_admin_panels(target)
        dir_listing = detect_directory_listing(resp.text)
        upload_forms = detect_upload_forms(forms)
        debug_hints = detect_debug_hints(resp)
        backup_files = check_backup_files(target)

        # Filter high-risk CVEs (CRITICAL/HIGH + keywords)
        high_risk_cves = filter_high_risk_cves(cve_cache)

        status("Rendering report...")
        report = make_report(
            target_url=target,
            status_code=resp.status_code,
            redirects=https_redirect,
            headers=headers,
            cookie_flags=cookie_flags,
            tls=tls_info,
            forms=forms,
            tech=tech,
            admin_panels=admin_panels,
            dir_listing=dir_listing,
            upload_forms=upload_forms,
            debug_hints=debug_hints,
            backup_files=backup_files,
            cve_cache=cve_cache,
            cve_changes=cve_changes,
            high_risk_cves=high_risk_cves
        )

        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            f.write(report)
        status(f"[+] Report written to {REPORT_FILE}")
        status("Done.")

    except requests.exceptions.RequestException as e:
        status(f"[!] Request error: {e}")
    except Exception as e:
        status(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    try:
        main()
    finally:
        input("\nPress Enter to exit...")
