"""
app/waf.py — WAF core engine (analyze + pattern loading + logging)

SSRF‑fix v2.2  (full code restore)
─────────────────────────────────
• Re‑added the missing tail of the module (pattern‑scan loop completion,
  `_log_block`, `_log_allow`, etc.).
• In‑memory `BLOCKED_COUNTS` is now incremented alongside Mongo for
  dashboards that rely on it.
• Everything else (CSRF detection, Host‑aware SSRF fix, request counters)
  retained from v2.1.
"""

IS_DEV_MODE = False  # Set to False in production

# ──────────────── Imports ────────────────
import os
import re
import logging
from pathlib import Path
from datetime import datetime
from time import time
import base64
import urllib.parse

import requests
from flask import request
from logging.handlers import RotatingFileHandler
from plyer import notification
from pymongo import MongoClient

# ─── MongoDB Setup ───────────────────────────────────
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
_mongo_client = MongoClient(MONGO_URI)
_mongo_db = _mongo_client.get_database("waf_db")
_events_coll = _mongo_db.get_collection("events")

# ──────────────── IP & Rate‑Limit Tracking ────────────────
BLOCKED_IPS: dict[str, list] = {}
MAX_ATTEMPTS = 3
BLOCK_TIME_SECONDS = 300

BRUTE_FORCE_WINDOW = 60  # seconds
BRUTE_FORCE_LIMIT = 20   # attempts per window
LOGIN_FAILURES: dict[str, list] = {}

total_requests_count = 0    # all allowed + blocked
allowed_requests_count = 0  # only allowed
blocked_requests_count = 0  # only blocked
__all__ = ["total_requests_count", "allowed_requests_count", "blocked_requests_count"]
STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

MONGO_COUNTER_ID = "global_counters"

def _client_ip() -> str:
    if not request:
        return "unknown"
    return request.headers.get("X-Forwarded-For", request.remote_addr)

# ──────────────── Paths / Files ────────────────
BASE_DIR = Path(__file__).parent
PATTERN_DIR = BASE_DIR / "patterns"
LOG_DIR = BASE_DIR.parent / "logs"
LOG_FILE = LOG_DIR / "waf.log"

SQLI_FILE = PATTERN_DIR / "sqli_patterns.txt"
XSS_FILE  = PATTERN_DIR / "xss_patterns.txt"
LFI_FILE  = PATTERN_DIR / "lfi_patterns.txt"
RCE_FILE  = PATTERN_DIR / "rce_patterns.txt"
SSRF_FILE = PATTERN_DIR / "ssrf_patterns.txt"

# ──────────────── Logging Setup ────────────────
LOG_DIR.mkdir(exist_ok=True)
logger = logging.getLogger("waf")
logger.setLevel(logging.DEBUG)  # <== Change to DEBUG so you see all logs
if not logger.handlers:
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    logger.propagate = False

# ──────────────── Geo‑IP Helpers ────────────────

def _country_flag(code: str) -> str:
    return "" if len(code) != 2 else chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)


def _get_geo(ip: str) -> str:
    if ip in {"127.0.0.1", "unknown"} or ip.startswith("192.168."):
        return "Localhost"
    try:
        data = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if data.get("status") == "success":
            return f"{_country_flag(data.get('countryCode', ''))} {data.get('country', 'Unknown')}, {data.get('city', '')}"
    except Exception:
        return "Geo lookup failed"
    return "Unknown"

# ──────────────── Pattern Loading ────────────────

def _load_patterns(path: Path):
    pats = []
    if not path.exists():
        logger.warning(f"Pattern file not found: {path}")
        return pats
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                pats.append(re.compile(line, re.IGNORECASE))
            except re.error as err:
                logger.warning(f"Invalid regex in {path.name}: {line!r} ({err})")
    return pats

SSRF_PATTERNS = _load_patterns(SSRF_FILE)
SQLI_PATTERNS = _load_patterns(SQLI_FILE)
XSS_PATTERNS  = _load_patterns(XSS_FILE)
LFI_PATTERNS  = _load_patterns(LFI_FILE)
RCE_PATTERNS  = _load_patterns(RCE_FILE)

# ──────────────── Obfuscation Decoding ────────────────

def decode_obfuscated(value: str) -> list[str]:
    out = {value}
    try: out.add(urllib.parse.unquote(value))
    except Exception: pass
    try: out.add(base64.b64decode(value + "==").decode("utf-8", "ignore"))
    except Exception: pass
    try: out.add(bytes.fromhex(value.replace("\\x", "")).decode("utf-8", "ignore"))
    except Exception: pass
    return list(filter(None, out))

# ──────────────── logging ────────────────
MONGO_COUNTER_ID = "global_counters"

def _load_counters():
    global total_requests_count, allowed_requests_count, blocked_requests_count
    doc = _mongo_db.counters.find_one({"_id": MONGO_COUNTER_ID})
    if doc:
        total_requests_count   = doc.get("total_requests", 0)
        allowed_requests_count = doc.get("allowed_requests", 0)
        blocked_requests_count = doc.get("blocked_requests", 0)
    else:
        _mongo_db.counters.insert_one({
            "_id": MONGO_COUNTER_ID,
            "total_requests": 0,
            "allowed_requests": 0,
            "blocked_requests": 0
        })

# Load counters on server start
_load_counters()
# ──────────────── CSRF Detection ────────────────
def _detect_csrf(req):
    if req is None:
        return False, ""

    if req.method not in STATE_CHANGING_METHODS:
        return False, ""

    # Must be an authenticated user (session cookie must exist)
    if not req.cookies.get("session"):
        return False, ""

    # Check CSRF token
    token_hdr = req.headers.get("X-CSRF-Token")
    token_ck = req.cookies.get("csrf_token")
    token_ok = token_hdr and token_ck and token_hdr == token_ck
    
    # Check Origin or Referer
    host = req.host.split(":")[0].lower()
    hdr_host_ok = False
    for hdr in (req.headers.get("Origin"), req.headers.get("Referer")):
        if hdr:
            try:
                parsed_host = urllib.parse.urlparse(hdr).hostname
                if parsed_host and parsed_host.lower() == host:
                    hdr_host_ok = True
                    break
            except Exception:
                pass

    if token_ok and hdr_host_ok:
        return False, ""

    reasons = []
    if not token_ok:
        reasons.append("missing or mismatched CSRF token")
    if not hdr_host_ok:
        reasons.append("Origin/Referer not same-origin")

    return True, "; ".join(reasons)



# ──────────────── Brute‑Force Helper ────────────────

def _record_brute_force(ip: str) -> bool:
    now = time()
    LOGIN_FAILURES.setdefault(ip, []).append(now)
    LOGIN_FAILURES[ip] = [t for t in LOGIN_FAILURES[ip] if t > now - BRUTE_FORCE_WINDOW]
    if len(LOGIN_FAILURES[ip]) > BRUTE_FORCE_LIMIT:
        BLOCKED_IPS[ip] = [MAX_ATTEMPTS + 1, now]
        logger.warning(f"🚨 Brute force triggered for {ip}")
        return True
    return False

# ──────────────── Main WAF Logic ────────────────

def analyze_request(payload: str, request_obj=None) -> str:
    global total_requests_count
    total_requests_count += 1
    
    ip = _client_ip()
    now = time()
    if (ban := BLOCKED_IPS.get(ip)) and now - ban[1] < BLOCK_TIME_SECONDS and ban[0] >= MAX_ATTEMPTS:
        logger.warning(f"Blocked request from banned IP: {ip}")
        return "🚫 IP Blocked (too many suspicious requests)"
    if _record_brute_force(ip):
        return "🚫 IP Blocked (too many requests)"

    # CSRF check
    if request_obj:
     print("[DEBUG] request.cookies:", dict(request_obj.cookies))  # <=== ADD THIS
    is_csrf, reason = _detect_csrf(request_obj)
    if is_csrf:
        _log_block("CSRF", payload, reason)
        return f"🚫 Blocked (CSRF: {reason})"


    # ─── Assemble scan targets ───────────────────────
    targets: list[tuple[str, str]] = [("payload/body", payload)]
    if request_obj:
        targets += [(f"query param: {k}", v) for k, v in request_obj.args.items()]
        for k, v in request_obj.headers.items():
            k_low = k.lower()

            # In dev mode we ignore User‑Agent, and we also ignore same‑origin Host/Origin/Referer headers
            if IS_DEV_MODE and k_low == "user-agent":
                continue

            if k_low in {"host", "origin", "referer"}:
                try:
                    hdr_host = v
                    if k_low in {"origin", "referer"}:
                        hdr_host = urllib.parse.urlparse(v).hostname or ""
                    hdr_host = hdr_host.split(":")[0].lower()
                except Exception:
                    hdr_host = ""

                server_host = request_obj.host.split(":")[0].lower() if request_obj.host else ""

                if hdr_host == server_host or (IS_DEV_MODE and hdr_host in {"localhost", "127.0.0.1"}):
                    # Same‑origin ⇒ safe, skip scanning so we don't raise SSRF FP
                    continue

            targets.append((f"header: {k}", v))
        targets += [(f"cookie: {k}", v) for k, v in request_obj.cookies.items()]
        targets.append(("path", request_obj.path))

    # ─── Pattern scanning ────────────────
    for source, val in targets:
        for dec in decode_obfuscated(val):
            for plist, ptype in (
                (SQLI_PATTERNS, "SQLi"), (XSS_PATTERNS, "XSS"), (LFI_PATTERNS, "LFI"),
                (RCE_PATTERNS, "RCE"), (SSRF_PATTERNS, "SSRF"),
            ):
                if any(r.search(dec) for r in plist):
                    _log_block(ptype, dec, "matched-pattern")
                    return f"🚫 Blocked ({ptype} → {source}: {dec})"

    _log_allow(payload)
    return "✅ Allowed (no threat detected)"

# ──────────────── Logging Helpers ────────────────

def _log_block(attack_type: str, payload: str, pattern: str):
    global blocked_requests_count
    blocked_requests_count += 1
    try:
        _mongo_db.counters.update_one(
            {"_id": MONGO_COUNTER_ID},
            {"$inc": {"blocked_requests": 1, "total_requests": 1}}
        )
    except Exception as e:
        logger.warning(f"MongoDB counter update failed in _log_block: {e}")

    ip  = _client_ip()
    geo = _get_geo(ip)

    now = time()
    BLOCKED_IPS[ip] = [BLOCKED_IPS.get(ip, [0, now])[0] + 1, now]

    emoji = {
        "SQLi": "🛑", "XSS": "🚨", "LFI": "📂", "RCE": "💣", "SSRF": "🌐", "CSRF": "🔐"
    }.get(attack_type, "⚠️")
    severity = {
        "SQLi": "High", "RCE": "High", "SSRF": "High",
        "XSS": "Medium", "LFI": "Medium", "CSRF": "Medium"
    }.get(attack_type, "Unknown")

    try:
        notification.notify(
            title=f"{emoji} {attack_type} Blocked! ({severity})",
            message=f"🌍 IP: {ip}\n📍 {geo}\n🔺 Severity: {severity}\n💬 {payload[:80]}",
            timeout=6
        )
    except Exception as e:
        logger.warning(f"Notification failed: {e}")

    logger.info(
        f"{attack_type} BLOCK | severity={severity} | ip={ip:15s} {geo:30s} | pattern={pattern} | payload={payload[:200]}"
    )

    try:
        _events_coll.insert_one({
            "timestamp": datetime.utcnow(),
            "ip": ip,
            "geo": geo,
            "attack_type": attack_type,
            "pattern": pattern,
            "payload": payload[:5000],
            "strikes": BLOCKED_IPS[ip][0],
            "severity": severity
        })
    except Exception as e:
        logger.warning(f"MongoDB insert failed in _log_block: {e}")

def _log_allow(payload: str):
    global allowed_requests_count
    allowed_requests_count += 1
    try:
        _mongo_db.counters.update_one(
            {"_id": MONGO_COUNTER_ID},
            {"$inc": {"allowed_requests": 1, "total_requests": 1}}
        )
    except Exception as e:
        logger.warning(f"MongoDB counter update failed in _log_allow: {e}")

    logger.debug(f"ALLOW | total_allowed={allowed_requests_count} | ip={_client_ip():15s} | payload={payload[:200]}")