# 🔍 OopsKey — Google API Key Web Auditor & Validator

> This tool is intended for use during authorized penetration testing and security assessments only.
> Unauthorized use against systems you do not own or have explicit written permission to test is illegal.

---

## Overview

`OopsKey` is a Python-based red-team utility that:

- Crawls a target URL and all same-host JavaScript assets to discover exposed Google API keys
- Follows webpack lazy chunks, dynamic imports, and `<link rel="preload">` hints that traditional scanners miss
- Validates discovered keys against 18 Google API endpoints using accurate response body parsing
- Produces structured JSON reports suitable for inclusion in penetration test deliverables

---

## Features

### 🕷️ Scanner
| Feature | Detail |
|---|---|
| Raw HTML scanning | Catches keys in meta tags, data attributes, and any non-script context |
| Inline `<script>` scanning | Dedicated source labeling for inline JS blocks |
| External JS discovery | Reads `<script src>`, `<link rel="preload">`, `<link rel="modulepreload">` |
| Webpack chunk recursion | Follows JS → JS references up to 2 levels deep |
| Same-host page crawling | Configurable depth crawl, never follows external domains |
| File size guard | Streaming fetch with 5 MB per-file cap |
| Total file cap | Hard ceiling of 150 JS files per scan run |

### 🔑 Pattern Engine (11 Strategies)
| Pattern | Example |
|---|---|
| `bare` | `AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` |
| `double_quoted` | `"AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"` |
| `single_quoted` | `'AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'` |
| `assignment` | `apiKey: 'AIzaXX...'`, `key = "AIzaXX..."` |
| `url_param` | `?key=AIzaXX...`, `&key=AIzaXX...` |
| `json_property` | `{"apiKey": "AIzaXX..."}` |
| `template_literal` | `` `https://maps.example.com?key=AIzaXX...` `` |
| `concatenation` | `var url = base + "AIzaXX..."` |
| `env_style` | `GOOGLE_MAPS_API_KEY=AIzaXX...` |
| `data_attribute` | `<div data-api-key="AIzaXX...">` |
| `minified_property` | `n.apiKey="AIzaXX...",n.authDomain` |

### ✅ Validator (18 Google APIs)

**Free / Low Risk**
- Books API
- Blogger API
- PageSpeed Insights
- YouTube Data API v3
- Custom Search API

**Billing-Enabled — Maps**
- Geocoding API
- Places API
- Directions API
- Elevation API
- Distance Matrix
- Time Zone API
- Roads API
- Static Maps API
- Geolocation API

**Billing-Enabled — AI / ML**
- Gemini (model list — no generation)
- Cloud Translation API
- Natural Language API
- Cloud Vision API

### 📊 Response Body Parsing
Unlike tools that only inspect HTTP status codes, `OopsKey` parses
Google's JSON response bodies to catch cases like:

```json
HTTP 200
{"status": "REQUEST_DENIED", "error_message": "This API key is not authorized..."}
```

| Pattern | Applies To |
|---|---|
| Top-level `status` field | All Maps-family APIs |
| Nested `{"error": {"code": N}}` | Vision, NLP, Translation, Gemini, YouTube |
| Non-JSON binary 200 | Maps Static API (image response = active key) |
| Clean 200 with content | Books, Blogger, PageSpeed |

---

## Requirements

- Python `3.8+`
- See `requirements.txt`

```
pip install -r requirements.txt
```

---

## Installation

```bash
git clone https://github.com/LMGsec/OopsKey.git
cd OopsKey
pip install -r requirements.txt
```
## Note on lxml 
lxml is listed as the recommended BeautifulSoup parser backend. If you have trouble installing it (e.g., on Alpine Linux or some ARM platforms), you can remove it from requirements.txt — beautifulsoup4 will fall back to Python's built-in html.parser automatically. No code changes needed.

---

## Usage

### Run pattern engine self-tests
Verifies all 11 detection strategies are working before a live scan.
```bash
python OopsKey.py --test-patterns
```

### Validate a single known key
No URL scanning — tests a key you already have directly against all 18 APIs.
```bash
python OopsKey.py --key AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Scan a URL and validate discovered keys
```bash
python OopsKey.py https://example.com --validate
```

### Crawl same-host pages 2 levels deep
```bash
python OopsKey.py https://example.com --validate --depth 2
```

### Test billing-enabled APIs only (fastest, highest impact for reports)
```bash
python OopsKey.py https://example.com --validate --billing-only
```

### Test free APIs only (zero financial risk during initial scoping)
```bash
python OopsKey.py https://example.com --validate --free-only
```

### Custom output report filename
```bash
python OopsKey.py https://example.com --validate --out client_acme_report.json
```

---

## Arguments

| Argument | Type | Default | Description |
|---|---|---|---|
| `url` | positional | — | Target URL to scan |
| `--key` | string | — | Validate a single known key (skips URL scan) |
| `--test-patterns` | flag | — | Run pattern engine self-tests and exit |
| `--depth` | int | `0` | Same-host HTML page crawl depth |
| `--validate` | flag | — | Validate all discovered keys against Google APIs |
| `--billing-only` | flag | — | Only test billing-enabled APIs during validation |
| `--free-only` | flag | — | Only test free APIs during validation |
| `--out` | string | `audit_report.json` | Output JSON report file path |

---

## Output

### Console (scan)
```
  ╔══════════════════════════════════════════════════════╗
  ║    Google API Key Web Auditor + Validator v4.0       ║
  ╚══════════════════════════════════════════════════════╝

  Target         : https://example.com
  HTML depth     : 0
  JS recursion   : 2 level(s)
  JS file cap    : 150
  Validate       : Yes

  [→] Scanning page  : https://example.com
       ✅ HTML source: 0 key(s) found
       ✅ Inline scripts: 3 block(s) scanned
       ✅ JS seeds found: 12 (from <script> + preload hints)
    [→] JS (0)  : https://example.com/static/js/main.abc123.js
    [→] JS (0)  : https://example.com/static/js/vendors.def456.js
      [→] JS (1)  : https://example.com/static/js/2.ghi789.chunk.js
          ✅ Found 1 key(s)

  ── Scan Summary ──────────────────────────────────────────────────
  JS files scanned     : 14
  Inline scripts found : 3
  Unique keys found    : 1

  KEY (masked)                                SOURCE          DETECTED VIA                           VALID
  ------------------------------------------- --------------- -------------------------------------- -----
  AIzaXXXX*******************************     external_js     double_quoted, assignment              ✅
```

### Console (validation)
```
  ── Validation: AIzaXXXX******************************* ────────────────────────────────
  API                                  Cat          Billing   HTTP   Body Status              Result
  ------------------------------------ ------------ --------- ------ ------------------------ ----------------------
  Books API                            Content        free    200    -                        ✅ ACTIVE
  Maps Geocoding API                   Maps         💰 YES    200    OK                       ✅ ACTIVE
  Maps Elevation API                   Maps         💰 YES    200    REQUEST_DENIED           🔒 DENIED
  Gemini (model list)                  AI           💰 YES    200    error:400                🔒 DENIED
  Cloud Vision API                     AI/Vision    💰 YES    403    -                        🔒 DENIED

  Severity         : 🟡 MEDIUM
  Active APIs      : 2 / 18
  Billing exposure : ⚠️  1 billing-enabled API(s) accessible
     💰 Maps Geocoding API (Maps)
```

### JSON Report Structure
```json
{
  "tool": "OopsKey_v4",
  "authorized_use_only": true,
  "mode": "web_scan",
  "timestamp": "2024-01-15T10:30:00.000000",
  "target_url": "https://example.com",
  "crawl_depth": 0,
  "js_recursion_depth": 2,
  "summary": {
    "js_files_scanned": 14,
    "inline_scripts_scanned": 3,
    "unique_keys_found": 1
  },
  "javascript_files": ["..."],
  "findings": [
    {
      "source": "external_js",
      "source_url": "https://example.com/static/js/2.ghi789.chunk.js",
      "key": "AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      "detected_via": ["double_quoted", "assignment"],
      "static_validation": "Format OK",
      "locations": ["https://example.com/static/js/2.ghi789.chunk.js"]
    }
  ],
  "validations": {
    "AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX": {
      "key": "AIzaXXXX*******************************",
      "severity": "MEDIUM",
      "total_tested": 18,
      "active_count": 2,
      "billing_risk_count": 1,
      "api_results": ["..."]
    }
  }
}
```

---

## Severity Ratings

| Rating | Meaning |
|---|---|
| 🔴 `HIGH` | Key is active on one or more billing-enabled APIs — direct financial exposure |
| 🟡 `MEDIUM` | Key is active on free APIs only — information disclosure, potential abuse vector |
| 🟢 `LOW` | Key found but denied on all tested APIs — likely rotated, restricted, or invalid |

---

## Scanner Limits

| Limit | Value | Reason |
|---|---|---|
| JS file size cap | 5 MB | Prevents memory spikes on minified bundles |
| Total JS files | 150 | Prevents runaway crawls on large SPAs |
| JS→JS recursion depth | 2 levels | Catches webpack chunks without infinite loops |
| Request timeout | 6–8 seconds | Per-request cap to keep scans responsive |

---

## ⚠️ Legal & Ethical Notice

This tool is provided for:

- Authorized penetration testing engagements
- Security research on systems you own
- Red-team assessments with explicit written authorization
- Defensive security reviews and API key audits

**You must have written authorization before scanning any system.**

The authors accept no liability for misuse of this tool.

---

## Contributing

Pull requests are welcome. Please ensure any additions:

- Do not add exploitation or abuse capabilities
- Include pattern engine test vectors for new detection strategies
- Include docstrings for new functions
- Pass all existing `--test-patterns` checks

---

## License

LMGSecurity — see `LICENSE` for details.
