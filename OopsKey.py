#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║    Google API Key Web Auditor + Validator v4.0       ║
╚══════════════════════════════════════════════════════╝

What changed in v4.0 (scanner fixes):
  - Scans entire raw HTML text for keys (not just <script> blocks)
  - Reads <link rel="preload"> and <link rel="modulepreload"> JS hints
  - Recursively follows JS→JS references to catch webpack lazy chunks
  - Streaming fetch with 5 MB per-file cap and 150-file total guard
  - Unified scan_text_for_findings() removes duplicate scan logic

Usage:
    python3 OopsKey.py --test-patterns
    python3 OopsKey.py --key AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    python3 OopsKey.py https://example.com --validate
    python3 OopsKey.py https://example.com --validate --depth 2
    python3 OopsKey.py https://example.com --validate --billing-only
    python3 OopsKey.py https://example.com --validate --free-only
    python3 OopsKey.py https://example.com --validate --out report.json

Dependencies:
    pip3 install requests beautifulsoup4
"""

import re
import json
import argparse
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List, Dict, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — PATTERN ENGINE
#
# Google API keys: AIza + exactly 35 alphanumeric/dash/underscore = 39 chars total
# 11 strategies cover minified JS, JSON, template literals, env vars,
# assignments, URL params, data attributes, concatenation, and bare text.
# ═══════════════════════════════════════════════════════════════════════════════

_CORE = r'AIza[0-9A-Za-z\-_]{35}'

PATTERNS: Dict[str, re.Pattern] = {

    # Plain token with word boundaries
    "bare": re.compile(
        r'(?<![A-Za-z0-9\-_])(' + _CORE + r')(?![A-Za-z0-9\-_])'
    ),

    # "AIza..."
    "double_quoted": re.compile(r'"(' + _CORE + r')"'),

    # 'AIza...'
    "single_quoted": re.compile(r"'(" + _CORE + r")'"),

    # key=AIza..., apiKey: "AIza...", credential = 'AIza...'
    "assignment": re.compile(
        r'(?:api[_-]?key|apikey|key|token|credential|secret)\s*[:=]\s*["\']?('
        + _CORE + r')["\']?',
        re.IGNORECASE
    ),

    # ?key=AIza... or &key=AIza...
    "url_param": re.compile(r'[?&]key=(' + _CORE + r')'),

    # {"apiKey": "AIza..."}
    "json_property": re.compile(
        r'"(?:key|apiKey|api_key|apikey|token|APIKEY)"\s*:\s*"(' + _CORE + r')"',
        re.IGNORECASE
    ),

    # `...AIza...`
    "template_literal": re.compile(
        r'`[^`]{0,200}(' + _CORE + r')[^`]{0,200}`'
    ),

    # + "AIza..."
    "concatenation": re.compile(r'\+\s*["\'](' + _CORE + r')["\']'),

    # GOOGLE_API_KEY=AIza..., GCP_KEY="AIza..."
    "env_style": re.compile(
        r'(?:GOOGLE|MAPS|FIREBASE|GCP|YOUTUBE)[_A-Z]*KEY[_A-Z]*\s*[=:]\s*["\']?('
        + _CORE + r')["\']?',
        re.IGNORECASE
    ),

    # data-api-key="AIza..."
    "data_attribute": re.compile(
        r'data-[a-zA-Z\-]*key[a-zA-Z\-]*=["\'](' + _CORE + r')["\']',
        re.IGNORECASE
    ),

    # n.apiKey="AIza..." (minified JS property)
    "minified_property": re.compile(
        r'[a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z_$]*[Kk]ey[a-zA-Z_$]*\s*=\s*["\']('
        + _CORE + r')["\']'
    ),
}


def extract_keys(text: str) -> List[Dict]:
    """
    Run all patterns against text.
    Returns deduplicated list of { key, detected_via[] }.
    """
    found: Dict[str, List[str]] = {}

    for pattern_name, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            try:
                key = match.group(1)
            except IndexError:
                key = match.group(0)

            if not key.startswith("AIza"):
                continue
            if key not in found:
                found[key] = []
            if pattern_name not in found[key]:
                found[key].append(pattern_name)

    return [{"key": k, "detected_via": v} for k, v in found.items()]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — PATTERN ENGINE SELF-TESTS
# ═══════════════════════════════════════════════════════════════════════════════

_TEST_KEY = "AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

TEST_VECTORS = [
    ("bare",             _TEST_KEY),
    ("double_quoted",    f'"{_TEST_KEY}"'),
    ("single_quoted",    f"'{_TEST_KEY}'"),
    ("assignment  =",    f"key = '{_TEST_KEY}'"),
    ("assignment  :",    f"apiKey: '{_TEST_KEY}'"),
    ("url_param",        f"https://example.com?key={_TEST_KEY}"),
    ("json_property",    f'{{"apiKey": "{_TEST_KEY}"}}'),
    ("template_literal", f'const url = `https://api.example.com?k={_TEST_KEY}`'),
    ("concatenation",    f'var u = base + "{_TEST_KEY}"'),
    ("env_style",        f"GOOGLE_MAPS_API_KEY={_TEST_KEY}"),
    ("data_attribute",   f'<div data-api-key="{_TEST_KEY}">'),
    ("minified_js",      f'n.apiKey="{_TEST_KEY}",n.authDomain'),
]


def run_pattern_tests():
    print("\n  Pattern Engine Self-Tests")
    print(f"  Test key : {_TEST_KEY}\n")
    print(f"  {'Test Case':<24} {'Detected?':<12} {'Via Pattern(s)'}")
    print(f"  {'-'*24} {'-'*12} {'-'*35}")

    passed = 0
    for desc, text in TEST_VECTORS:
        results = extract_keys(text)
        if results:
            passed += 1
            via = ", ".join(results[0]["detected_via"])
            print(f"  {desc:<24} {'✅ YES':<12} {via}")
        else:
            print(f"  {desc:<24} {'❌ MISSED':<12} —")

    print(f"\n  Result: {passed}/{len(TEST_VECTORS)} patterns passed\n")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — STATIC VALIDATOR
# ═══════════════════════════════════════════════════════════════════════════════

def static_validate(key: str) -> Tuple[bool, str]:
    if not key.startswith("AIza"):
        return False, "Invalid prefix (expected AIza)"
    if len(key) != 39:
        return False, f"Invalid length ({len(key)} chars, expected 39)"
    if not re.match(r'^[A-Za-z0-9\-_]+$', key[4:]):
        return False, "Invalid characters in key body"
    return True, "Format OK"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — WEB SCANNER (v4 — major rewrite)
#
# Scan strategy (in order):
#   1. Raw HTML text        — catches keys in meta tags, data attrs, any context
#   2. Inline <script>      — targeted source labeling for inline blocks
#   3. External JS (HTML)   — <script src>, <link rel="preload">, <link rel="modulepreload">
#   4. JS → JS recursion    — webpack chunks, dynamic imports, lazy routes
#   5. Crawl linked pages   — controlled by --depth flag
#
# Guards:
#   MAX_JS_FILE_SIZE   = 5 MB per file    (streamed, avoids memory spikes)
#   MAX_JS_FILES_TOTAL = 150 files        (per full scan run)
#   JS_RECURSION_DEPTH = 2 levels         (JS file that references another JS file)
# ═══════════════════════════════════════════════════════════════════════════════

MAX_JS_FILE_SIZE   = 5 * 1024 * 1024  # 5 MB
MAX_JS_FILES_TOTAL = 150
JS_RECURSION_DEPTH = 2

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# Patterns for locating JS file references inside JS source code.
# Covers:
#   - Absolute paths:  "/static/js/2.abc123.chunk.js"
#   - Relative paths:  "./vendors.js", "../common.chunk.js"
#   - Chunk patterns:  any *.chunk.js, *.bundle.js reference
_JS_REF_PATTERNS: List[re.Pattern] = [
    # Absolute path strings
    re.compile(r'["\'`](/[a-zA-Z0-9][a-zA-Z0-9/._\-]{2,}?\.js)["\'`]'),
    # Relative paths ./
    re.compile(r'["\'`](\./[a-zA-Z0-9/._\-]+?\.js)["\'`]'),
    # Relative paths ../
    re.compile(r'["\'`](\.\./[a-zA-Z0-9/._\-]+?\.js)["\'`]'),
    # Named chunk patterns anywhere: "vendors~main.abc.chunk.js"
    re.compile(r'["\'`]([a-zA-Z0-9_\-~]+\.[a-f0-9]{6,}\.(?:chunk|bundle)\.js)["\'`]'),
]


# ── Fetch helper ───────────────────────────────────────────────────────────────

def safe_get(url: str, timeout: int = 8) -> Optional[str]:
    """
    Streaming GET with a hard size cap.
    Returns decoded text or None on any failure / oversize.
    """
    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.get(url, timeout=timeout, headers=HEADERS, stream=True, verify=False)
        if r.status_code != 200:
            return None

        # Honour Content-Length if present
        cl = r.headers.get("Content-Length")
        if cl and int(cl) > MAX_JS_FILE_SIZE:
            return None

        chunks = []
        received = 0
        for chunk in r.iter_content(chunk_size=65_536):
            received += len(chunk)
            if received > MAX_JS_FILE_SIZE:
                return None
            chunks.append(chunk)

        return b"".join(chunks).decode("utf-8", errors="ignore")

    except Exception:
        return None


# ── Key-finding helper ─────────────────────────────────────────────────────────

def scan_text_for_findings(text: str, source: str, source_url: str) -> List[Dict]:
    """Scan any text string and return a findings list."""
    findings = []
    for item in extract_keys(text):
        key = item["key"]
        _, sv_msg = static_validate(key)
        findings.append({
            "source":            source,
            "source_url":        source_url,
            "key":               key,
            "detected_via":      item["detected_via"],
            "static_validation": sv_msg,
        })
    return findings


# ── HTML extraction helpers ────────────────────────────────────────────────────

def extract_all_js_from_html(base_url: str, html: str) -> List[str]:
    """
    Return all same-host JS URLs declared anywhere in an HTML page:
      - <script src="...">
      - <link rel="preload" as="script" href="...">
      - <link rel="modulepreload" href="...">
    """
    base_host = urlparse(base_url).netloc
    soup      = BeautifulSoup(html, "html.parser")
    js_urls: Set[str] = set()

    # Standard script tags
    for tag in soup.find_all("script", src=True):
        full = urljoin(base_url, tag["src"])
        if urlparse(full).netloc == base_host:
            js_urls.add(full)

    # Preload / modulepreload hints
    for tag in soup.find_all("link"):
        rel      = tag.get("rel", [])
        rel      = [rel] if isinstance(rel, str) else rel
        href     = tag.get("href", "")
        as_attr  = tag.get("as", "")
        is_pre   = "preload" in rel or "modulepreload" in rel
        is_js    = as_attr == "script" or href.endswith(".js")

        if is_pre and is_js and href:
            full = urljoin(base_url, href)
            if urlparse(full).netloc == base_host:
                js_urls.add(full)

    return list(js_urls)


def extract_inline_scripts(html: str) -> List[str]:
    """Return text content of all inline <script> blocks."""
    soup = BeautifulSoup(html, "html.parser")
    return [
        tag.string
        for tag in soup.find_all("script")
        if not tag.get("src") and tag.string
    ]


def extract_same_host_links(base_url: str, html: str) -> List[str]:
    """Return same-host page hrefs for depth crawling."""
    base_host = urlparse(base_url).netloc
    soup      = BeautifulSoup(html, "html.parser")
    links: Set[str] = set()

    for tag in soup.find_all("a", href=True):
        full = urljoin(base_url, tag["href"])
        p    = urlparse(full)
        if p.netloc == base_host and p.scheme in ("http", "https"):
            links.add(p._replace(fragment="").geturl())

    return list(links)


# ── JS → JS reference extractor ───────────────────────────────────────────────

def extract_js_refs_from_js(
    js_url:    str,
    js_text:   str,
    base_host: str
) -> List[str]:
    """
    Find same-host JS file references embedded inside a JS file.
    Resolves absolute (/path) and relative (./path) references.
    Used to follow webpack lazy chunks and dynamic imports.
    """
    found: Set[str] = set()
    parsed = urlparse(js_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for pattern in _JS_REF_PATTERNS:
        for match in pattern.finditer(js_text):
            path = match.group(1)

            if path.startswith("/"):
                resolved = f"{origin}{path}"
            else:
                resolved = urljoin(js_url, path)

            if urlparse(resolved).netloc == base_host:
                # Skip obvious non-assets (node_modules refs, test files, etc.)
                if "node_modules" in resolved or "test" in resolved.lower():
                    continue
                found.add(resolved)

    return list(found)


# ── Recursive JS scanner ───────────────────────────────────────────────────────

def fetch_and_scan_js_recursive(
    seed_urls:     List[str],
    visited_js:    Set[str],
    base_host:     str,
    current_depth: int = 0,
) -> Tuple[List[str], List[Dict]]:
    """
    Fetch each JS URL, scan for keys, then recurse into any JS files
    that are referenced within that code (webpack chunks, dynamic imports).

    Bounded by:
      JS_RECURSION_DEPTH — how many JS→JS hops to follow
      MAX_JS_FILES_TOTAL — absolute ceiling on total files scanned
    """
    all_urls:     List[str]  = []
    all_findings: List[Dict] = []

    for url in seed_urls:
        if url in visited_js:
            continue
        if len(visited_js) >= MAX_JS_FILES_TOTAL:
            print(f"  [!] JS file limit ({MAX_JS_FILES_TOTAL}) reached — stopping recursion")
            break

        visited_js.add(url)
        all_urls.append(url)

        indent = "  " + ("  " * current_depth)
        print(f"{indent}[→] JS ({current_depth})  : {url}")

        js_text = safe_get(url)
        if not js_text:
            continue

        # Scan this file for keys
        findings = scan_text_for_findings(js_text, "external_js", url)
        if findings:
            print(f"{indent}    ✅ Found {len(findings)} key(s)")
        all_findings.extend(findings)

        # Recurse into JS files referenced from within this file
        if current_depth < JS_RECURSION_DEPTH:
            child_urls = [
                u for u in extract_js_refs_from_js(url, js_text, base_host)
                if u not in visited_js
            ]
            if child_urls:
                child_all_urls, child_findings = fetch_and_scan_js_recursive(
                    child_urls, visited_js, base_host, current_depth + 1
                )
                all_urls.extend(child_all_urls)
                all_findings.extend(child_findings)

    return all_urls, all_findings


# ── Page scanner ──────────────────────────────────────────────────────────────

def scan_page(
    url:           str,
    visited_js:    Set[str],
    visited_pages: Set[str],
    depth:         int,
    max_depth:     int,
) -> Dict:
    """
    Orchestrates a full scan of one HTML page:
      1. Raw HTML text scan   — catches keys anywhere in the page source
      2. Inline script scan   — targeted source labeling
      3. External JS (HTML)   — <script src>, preload, modulepreload
      4. JS → JS recursion    — webpack chunks, lazy imports
      5. Linked page crawl    — controlled by --depth
    """
    result = {
        "page_url":               url,
        "javascript_files":       [],
        "inline_scripts_scanned": 0,
        "findings":               [],
    }

    if url in visited_pages:
        return result
    visited_pages.add(url)

    print(f"\n  [→] Scanning page  : {url}")

    html = safe_get(url)
    if html is None:
        result["error"] = f"Could not fetch: {url}"
        print(f"       ⚠️  Could not fetch page")
        return result

    # ── 1. Scan entire raw HTML text ─────────────────────────────────────────
    # Catches keys in meta tags, data-* attributes, and any non-script context
    html_findings = scan_text_for_findings(html, "html_source", url)
    result["findings"].extend(html_findings)
    if html_findings:
        print(f"       ✅ HTML source: {len(html_findings)} key(s) found")

    # ── 2. Inline <script> blocks ────────────────────────────────────────────
    inline_scripts = extract_inline_scripts(html)
    result["inline_scripts_scanned"] += len(inline_scripts)
    for script_text in inline_scripts:
        inline_findings = scan_text_for_findings(script_text, "inline_script", url)
        result["findings"].extend(inline_findings)
    if inline_scripts:
        print(f"       ✅ Inline scripts: {len(inline_scripts)} block(s) scanned")

    # ── 3 + 4. External JS files + recursive chunk following ─────────────────
    seed_js_urls = extract_all_js_from_html(url, html)
    print(f"       ✅ JS seeds found: {len(seed_js_urls)} (from <script> + preload hints)")

    all_js_urls, js_findings = fetch_and_scan_js_recursive(
        seed_urls=seed_js_urls,
        visited_js=visited_js,
        base_host=urlparse(url).netloc,
        current_depth=0,
    )
    result["javascript_files"].extend(all_js_urls)
    result["findings"].extend(js_findings)

    # ── 5. Crawl same-host linked pages (controlled by --depth) ─────────────
    if depth < max_depth:
        for link in extract_same_host_links(url, html):
            if link not in visited_pages:
                sub = scan_page(link, visited_js, visited_pages, depth + 1, max_depth)
                result["javascript_files"].extend(sub.get("javascript_files", []))
                result["findings"].extend(sub.get("findings", []))
                result["inline_scripts_scanned"] += sub.get("inline_scripts_scanned", 0)

    return result


def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Collapse findings with the same key across multiple sources.
    Merges locations[] and detected_via[] lists.
    """
    seen: Dict[str, Dict] = {}

    for f in findings:
        key = f["key"]
        if key not in seen:
            seen[key] = {**f, "locations": [f["source_url"]]}
        else:
            if f["source_url"] not in seen[key]["locations"]:
                seen[key]["locations"].append(f["source_url"])
            for via in f.get("detected_via", []):
                if via not in seen[key]["detected_via"]:
                    seen[key]["detected_via"].append(via)

    return list(seen.values())


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — RESPONSE BODY PARSER
#
# Many Google APIs return HTTP 200 with an error status in the JSON body.
#
#   Pattern A — Maps family (Elevation, Geocoding, Directions, etc.)
#     HTTP 200 + top-level "status" string
#     e.g. {"status": "REQUEST_DENIED", "error_message": "..."}
#
#   Pattern B — Error object (Vision, NLP, Translation, Gemini, YouTube, Books)
#     HTTP 200 or 4xx + {"error": {"code": N, "message": "..."}}
#
#   Pattern C — Clean 200 with no error indicators → genuine success
#
#   Pattern D — Non-200 HTTP status → derive from HTTP code directly
# ═══════════════════════════════════════════════════════════════════════════════

MAPS_STATUS_MAP: Dict[str, Dict] = {
    "OK":               {"result": "ACTIVE",        "detail": "Key active and authorized"},
    "ZERO_RESULTS":     {"result": "ACTIVE",        "detail": "Key active — query returned zero results"},
    "REQUEST_DENIED":   {"result": "DENIED",        "detail": "Request denied — key invalid, missing, or restricted"},
    "OVER_DAILY_LIMIT": {"result": "BILLING_ISSUE", "detail": "Over daily limit — billing not enabled or quota exhausted"},
    "OVER_QUERY_LIMIT": {"result": "QUOTA",         "detail": "Query limit exceeded"},
    "INVALID_REQUEST":  {"result": "INVALID",       "detail": "Invalid request parameters (not a key issue)"},
    "UNKNOWN_ERROR":    {"result": "SERVER_ERROR",  "detail": "Google-side unknown error — retry recommended"},
    "NOT_FOUND":        {"result": "NOT_FOUND",     "detail": "Resource not found"},
}

HTTP_STATUS_MAP: Dict[int, Dict] = {
    400: {"result": "RESTRICTED",   "detail": "Bad request — key may be restricted"},
    401: {"result": "UNAUTHORIZED", "detail": "Unauthenticated — key not valid"},
    403: {"result": "DENIED",       "detail": "Permission denied — API not enabled or restricted"},
    404: {"result": "NOT_FOUND",    "detail": "Endpoint not found"},
    429: {"result": "QUOTA",        "detail": "Quota or rate limit exceeded"},
    500: {"result": "SERVER_ERROR", "detail": "Google-side server error"},
}


def parse_response_body(response: requests.Response) -> Tuple[Dict, Optional[str]]:
    """
    Parse a Google API response into a normalised result dict.
    Returns (result_dict, raw_body_status_string_or_None).
    """

    # Pattern D: non-200 HTTP
    if response.status_code != 200:
        result = HTTP_STATUS_MAP.get(
            response.status_code,
            {"result": "UNKNOWN", "detail": f"Unexpected HTTP {response.status_code}"}
        )
        return result, None

    # Attempt JSON body inspection
    try:
        body = response.json()
    except ValueError:
        return {"result": "ACTIVE", "detail": "Key active (non-JSON 200 response)"}, None

    # Pattern A: Maps-family "status" string
    if "status" in body and isinstance(body["status"], str):
        raw    = body["status"]
        mapped = MAPS_STATUS_MAP.get(
            raw,
            {"result": "UNKNOWN", "detail": f"Unrecognised Maps status: {raw}"}
        )
        if "error_message" in body:
            mapped = {**mapped, "detail": body["error_message"]}
        return mapped, raw

    # Pattern B: nested error object
    if "error" in body and isinstance(body["error"], dict):
        err     = body["error"]
        code    = err.get("code",    0)
        message = err.get("message", "No message provided")
        raw     = f"error:{code}"
        result  = HTTP_STATUS_MAP.get(code, {"result": "ERROR", "detail": f"API error {code}"})
        return {**result, "detail": message}, raw

    # Pattern C: clean 200
    return {"result": "ACTIVE", "detail": "Key active and authorized for this API"}, None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — GOOGLE API DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class GoogleAPI:
    name:         str
    category:     str
    billing:      bool
    method:       str
    url_template: str
    body:         Optional[dict]
    notes:        str = ""


GOOGLE_APIS: List[GoogleAPI] = [

    # ── Free ─────────────────────────────────────────────────────────────────
    GoogleAPI("Books API",          "Content",   False, "GET",
        "https://www.googleapis.com/books/v1/volumes?q=a&key={key}",
        None, "Free — standard key probe"),
    GoogleAPI("Blogger API",        "Content",   False, "GET",
        "https://www.googleapis.com/blogger/v3/blogs/2399953?key={key}",
        None, "Free — public blog metadata"),
    GoogleAPI("PageSpeed Insights", "Web Tools", False, "GET",
        "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://google.com&key={key}",
        None, "Free — public analysis endpoint"),
    GoogleAPI("YouTube Data API v3","Media",     False, "GET",
        "https://www.googleapis.com/youtube/v3/search?part=snippet&q=a&maxResults=1&key={key}",
        None, "Free quota — search"),
    GoogleAPI("Custom Search API",  "Search",    False, "GET",
        "https://www.googleapis.com/customsearch/v1?q=a&key={key}",
        None, "100 queries/day free"),

    # ── Billing — Maps ────────────────────────────────────────────────────────
    GoogleAPI("Maps Geocoding API",   "Maps", True, "GET",
        "https://maps.googleapis.com/maps/api/geocode/json?address=a&key={key}",
        None, "Billing enabled"),
    GoogleAPI("Maps Places API",      "Maps", True, "GET",
        "https://maps.googleapis.com/maps/api/place/findplacefromtext/json"
        "?input=a&inputtype=textquery&key={key}",
        None, "Billing enabled"),
    GoogleAPI("Maps Directions API",  "Maps", True, "GET",
        "https://maps.googleapis.com/maps/api/directions/json?origin=a&destination=b&key={key}",
        None, "Billing enabled"),
    GoogleAPI("Maps Elevation API",   "Maps", True, "GET",
        "https://maps.googleapis.com/maps/api/elevation/json?locations=0,0&key={key}",
        None, "Billing enabled — body status parsed"),
    GoogleAPI("Maps Distance Matrix", "Maps", True, "GET",
        "https://maps.googleapis.com/maps/api/distancematrix/json?origins=a&destinations=b&key={key}",
        None, "Billing enabled"),
    GoogleAPI("Maps Time Zone API",   "Maps", True, "GET",
        "https://maps.googleapis.com/maps/api/timezone/json?location=0,0&timestamp=0&key={key}",
        None, "Billing enabled"),
    GoogleAPI("Maps Roads API",       "Maps", True, "GET",
        "https://roads.googleapis.com/v1/snapToRoads?path=0,0&key={key}",
        None, "Billing enabled"),
    GoogleAPI("Maps Static API",      "Maps", True, "GET",
        "https://maps.googleapis.com/maps/api/staticmap?size=1x1&key={key}",
        None, "Billing enabled — binary response on success"),
    GoogleAPI("Maps Geolocation API", "Maps", True, "POST",
        "https://www.googleapis.com/geolocation/v1/geolocate?key={key}",
        {}, "Billing enabled"),

    # ── Billing — AI / ML ────────────────────────────────────────────────────
    GoogleAPI("Gemini (model list)", "AI",       True, "GET",
        "https://generativelanguage.googleapis.com/v1beta/models?key={key}",
        None, "Billing — model list only, no generation"),
    GoogleAPI("Cloud Translation",   "AI/Lang",  True, "GET",
        "https://translation.googleapis.com/language/translate/v2/languages?key={key}",
        None, "Billing — language list only"),
    GoogleAPI("Natural Language API","AI/Lang",  True, "POST",
        "https://language.googleapis.com/v1/documents:analyzeEntities?key={key}",
        {"document": {"type": "PLAIN_TEXT", "content": "Google"}},
        "Billing — minimal entity analysis"),
    GoogleAPI("Cloud Vision API",    "AI/Vision",True, "POST",
        "https://vision.googleapis.com/v1/images:annotate?key={key}",
        {"requests": [{
            "image": {"source": {"imageUri":
                "https://upload.wikimedia.org/wikipedia/commons/4/47/"
                "PNG_transparency_demonstration_1.png"
            }},
            "features": [{"type": "LABEL_DETECTION", "maxResults": 1}]
        }]},
        "Billing — single label on 1x1 transparent PNG"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — KEY VALIDATOR
# ═══════════════════════════════════════════════════════════════════════════════

def _test_single_api(api: GoogleAPI, key: str) -> Dict:
    url = api.url_template.replace("{key}", key)
    out = {
        "api":             api.name,
        "category":        api.category,
        "billing_enabled": api.billing,
        "notes":           api.notes,
        "http_status":     None,
        "body_status":     None,
        "result":          None,
        "detail":          None,
        "error":           None,
    }

    try:
        r = (
            requests.get(url, timeout=6)
            if api.method == "GET"
            else requests.post(url, json=api.body, timeout=6)
        )
        out["http_status"] = r.status_code
        parsed, raw        = parse_response_body(r)
        out["body_status"] = raw
        out["result"]      = parsed["result"]
        out["detail"]      = parsed["detail"]

    except requests.exceptions.ConnectionError:
        out["error"]  = "Connection failed"
        out["result"] = "UNREACHABLE"
    except requests.exceptions.Timeout:
        out["error"]  = "Request timed out"
        out["result"] = "TIMEOUT"
    except Exception as e:
        out["error"]  = str(e)
        out["result"] = "ERROR"

    return out


def validate_key(
    key:          str,
    billing_only: bool = False,
    free_only:    bool = False
) -> Dict:
    apis = GOOGLE_APIS
    if billing_only: apis = [a for a in apis if a.billing]
    if free_only:    apis = [a for a in apis if not a.billing]

    results = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_test_single_api, api, key): api for api in apis}
        for f in as_completed(futures):
            results.append(f.result())

    active         = [r for r in results if r["result"] == "ACTIVE"]
    billing_active = [r for r in active  if r["billing_enabled"]]
    severity       = "HIGH" if billing_active else ("MEDIUM" if active else "LOW")

    return {
        "key":                f"{key[:8]}{'*' * (len(key) - 8)}",
        "raw_key":            key,
        "severity":           severity,
        "total_tested":       len(results),
        "active_count":       len(active),
        "billing_risk_count": len(billing_active),
        "api_results":        sorted(results, key=lambda x: x.get("result", "")),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

STATUS_ICONS = {
    "ACTIVE":        "✅ ACTIVE",
    "RESTRICTED":    "⚠️  RESTRICTED",
    "DENIED":        "🔒 DENIED",
    "BILLING_ISSUE": "💳 BILLING ISSUE",
    "QUOTA":         "⏱️  QUOTA",
    "UNAUTHORIZED":  "🔑 UNAUTHORIZED",
    "INVALID":       "⛔ INVALID",
    "UNREACHABLE":   "🔌 UNREACHABLE",
    "TIMEOUT":       "⏱️  TIMEOUT",
    "SERVER_ERROR":  "🔥 SERVER ERR",
    "NOT_FOUND":     "🔍 NOT FOUND",
    "ERROR":         "❌ ERROR",
    "UNKNOWN":       "❓ UNKNOWN",
}

SEV_ICONS = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


def print_banner():
    print("""
  ╔══════════════════════════════════════════════════════╗
  ║    Google API Key Web Auditor + Validator v4.0       ║
  ╚══════════════════════════════════════════════════════╝
    """)


def print_scan_findings(findings: List[Dict]):
    if not findings:
        print("  No API keys found.\n")
        return

    print(f"\n  {'KEY':<43} {'SOURCE':<15} {'DETECTED VIA':<38} VALID")
    print(f"  {'-'*43} {'-'*15} {'-'*38} {'-'*5}")

    for f in findings:
        key    = f["key"]
        #masked = f"{key[:8]}{'*' * (len(key) - 8)}"
        masked = f["key"]
        source = f.get("source", "")[:14]
        via    = ", ".join(f.get("detected_via", []))[:37]
        valid  = "✅" if f.get("static_validation") == "Format OK" else "❌"
        print(f"  {masked:<43} {source:<15} {via:<38} {valid}")

    print()


def print_validation_result(validation: Dict):
    print(f"\n  ── Validation: {validation['key']} ────────────────────────────────")
    print(
        f"  {'API':<36} {'Cat':<12} {'Billing':<9} "
        f"{'HTTP':<6} {'Body Status':<24} Result"
    )
    print(
        f"  {'-'*36} {'-'*12} {'-'*9} "
        f"{'-'*6} {'-'*24} {'-'*22}"
    )

    for r in validation["api_results"]:
        billing     = "💰 YES" if r["billing_enabled"] else "  free"
        icon        = STATUS_ICONS.get(r.get("result", ""), "❓")
        http        = str(r["http_status"]) if r["http_status"] else "-"
        body_status = str(r["body_status"]) if r["body_status"] else "-"
        print(
            f"  {r['api']:<36} {r['category']:<12} {billing:<9} "
            f"{http:<6} {body_status:<24} {icon}"
        )

    sev  = validation["severity"]
    icon = SEV_ICONS.get(sev, "⚪")
    print(f"\n  Severity         : {icon} {sev}")
    print(f"  Active APIs      : {validation['active_count']} / {validation['total_tested']}")

    if validation["billing_risk_count"]:
        print(f"  Billing exposure : ⚠️  {validation['billing_risk_count']} billing-enabled API(s) accessible")
        for r in validation["api_results"]:
            if r["result"] == "ACTIVE" and r["billing_enabled"]:
                print(f"     💰 {r['api']} ({r['category']})")

    print()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Google API Key Web Auditor + Validator v4.0",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python OopsKey.py --test-patterns\n"
            "  python OopsKey.py --key AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
            "  python OopsKey.py https://example.com --validate\n"
            "  python OopsKey.py https://example.com --validate --depth 2\n"
            "  python OopsKey.py https://example.com --validate --billing-only\n"
        )
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("url",             nargs="?",     help="Target URL to scan")
    mode.add_argument("--key",           metavar="KEY", help="Validate a single known key")
    mode.add_argument("--test-patterns", action="store_true", help="Run pattern self-tests and exit")

    parser.add_argument("--depth",        type=int, default=0,
                        help="Same-host HTML page crawl depth (default: 0 = single page)")
    parser.add_argument("--validate",     action="store_true",
                        help="Validate all discovered keys against Google APIs")
    parser.add_argument("--billing-only", action="store_true",
                        help="Only test billing-enabled APIs during validation")
    parser.add_argument("--free-only",    action="store_true",
                        help="Only test free APIs during validation")
    parser.add_argument("--out",          default="audit_report.json",
                        help="Output JSON report path (default: audit_report.json)")

    args = parser.parse_args()
    print_banner()

    # ── Mode 1: Pattern self-tests ───────────────────────────────────────────
    if args.test_patterns:
        run_pattern_tests()
        return

    # ── Mode 2: Single key validation ───────────────────────────────────────
    if args.key:
        print(f"  Mode  : Single key validation")
        print(f"  Key   : {args.key[:8]}{'*' * (len(args.key) - 8)}\n")

        valid, sv_msg = static_validate(args.key)
        print(f"  Static check : {'✅' if valid else '❌'} {sv_msg}")

        if not valid:
            print("\n  Key format invalid — aborting.\n")
            return

        print(f"  Running across {len(GOOGLE_APIS)} API endpoints...\n")
        result = validate_key(args.key, args.billing_only, args.free_only)
        print_validation_result(result)

        report = {
            "tool":                "gapi_full_audit_v4",
            "authorized_use_only": True,
            "mode":                "single_key",
            "timestamp":           datetime.utcnow().isoformat(),
            "static_validation":   sv_msg,
            "validation":          result,
        }
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Report saved → {args.out}\n")
        return

    # ── Mode 3: Full web scan ────────────────────────────────────────────────
    if not args.url:
        parser.print_help()
        return

    print(f"  Target         : {args.url}")
    print(f"  HTML depth     : {args.depth}")
    print(f"  JS recursion   : {JS_RECURSION_DEPTH} level(s)")
    print(f"  JS file cap    : {MAX_JS_FILES_TOTAL}")
    print(f"  Validate       : {'Yes' if args.validate else 'No  (add --validate to enable)'}\n")

    scan = scan_page(
        url=args.url,
        visited_js=set(),
        visited_pages=set(),
        depth=0,
        max_depth=args.depth,
    )

    unique_findings = deduplicate_findings(scan.get("findings", []))
    js_files        = list(set(scan.get("javascript_files", [])))

    print(f"\n  ── Scan Summary ──────────────────────────────────────────────────")
    print(f"  JS files scanned     : {len(js_files)}")
    print(f"  Inline scripts found : {scan.get('inline_scripts_scanned', 0)}")
    print(f"  Unique keys found    : {len(unique_findings)}")

    print_scan_findings(unique_findings)

    # ── Validate discovered keys ─────────────────────────────────────────────
    validations = {}

    if args.validate and unique_findings:
        print(f"  Validating {len(unique_findings)} unique key(s)...\n")
        for f in unique_findings:
            key = f["key"]
            v   = validate_key(key, args.billing_only, args.free_only)
            validations[key] = v
            print_validation_result(v)
    elif args.validate and not unique_findings:
        print("  No keys found to validate.\n")

    # ── Write report ─────────────────────────────────────────────────────────
    report = {
        "tool":                "gapi_full_audit_v4",
        "authorized_use_only": True,
        "mode":                "web_scan",
        "timestamp":           datetime.utcnow().isoformat(),
        "target_url":          args.url,
        "crawl_depth":         args.depth,
        "js_recursion_depth":  JS_RECURSION_DEPTH,
        "summary": {
            "js_files_scanned":       len(js_files),
            "inline_scripts_scanned": scan.get("inline_scripts_scanned", 0),
            "unique_keys_found":      len(unique_findings),
        },
        "javascript_files": js_files,
        "findings":         unique_findings,
        "validations":      validations,
    }

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    print(f"  Report saved → {args.out}\n")


if __name__ == "__main__":
    main()
