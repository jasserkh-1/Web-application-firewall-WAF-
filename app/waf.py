"""
app/waf.py — WAF core engine (analyze + pattern loading + logging)
"""

# ──────────────── Imports ────────────────
import re
import logging
from pathlib import Path
from datetime import datetime
from flask import request
from logging.handlers import RotatingFileHandler
import requests
from plyer import notification
from time import time
import urllib.parse
import base64
import binascii

# ──────────────── IP Block Tracking ────────────────
BLOCKED_IPS = {}
MAX_ATTEMPTS = 3
BLOCK_TIME_SECONDS = 300  # 5 min

BRUTE_FORCE_WINDOW = 60   # seconds
BRUTE_FORCE_LIMIT = 20     # max attempts in that window
LOGIN_FAILURES = {}       # { ip: [timestamps of fails] }

def _client_ip() -> str:
    if not request:
        return "unknown"
    return request.headers.get("X-Forwarded-For", request.remote_addr)

# ──────────────── Config ────────────────
BASE_DIR     = Path(__file__).parent
PATTERN_DIR  = BASE_DIR / "patterns"
LOG_DIR      = BASE_DIR.parent / "logs"
LOG_FILE     = LOG_DIR / "waf.log"

SQLI_FILE    = PATTERN_DIR / "sqli_patterns.txt"
XSS_FILE     = PATTERN_DIR / "xss_patterns.txt"
LFI_FILE     = PATTERN_DIR / "lfi_patterns.txt"
RCE_FILE     = PATTERN_DIR / "rce_patterns.txt"

# ──────────────── Logging Setup ────────────────
LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("waf")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = RotatingFileHandler(
        LOG_FILE, maxBytes=5_000_000, backupCount=5, encoding="utf-8"
    )
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False

# ──────────────── Geo IP ────────────────
def _get_geo(ip: str) -> str:
    if ip == "127.0.0.1" or ip.startswith("192.168.") or ip == "unknown":
        return "Localhost"
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = res.json()
        if data["status"] == "success":
            country = data.get("country", "Unknown")
            city = data.get("city", "")
            emoji = _country_flag(data.get("countryCode", ""))
            return f"{emoji} {country}, {city}"
    except Exception:
        return "Geo lookup failed"
    return "Unknown"

def _country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)

# ──────────────── Pattern Loading ────────────────
def _load_patterns(file_path: Path):
    patterns = []
    if not file_path.exists():
        logger.warning(f"Pattern file not found: {file_path}")
        return patterns

    with file_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    patterns.append(re.compile(line, re.IGNORECASE))
                except re.error as err:
                    logger.warning(f"Invalid regex in {file_path.name}: {line!r} ({err})")
    return patterns

SQLI_PATTERNS = _load_patterns(SQLI_FILE)
XSS_PATTERNS  = _load_patterns(XSS_FILE)
LFI_PATTERNS  = _load_patterns(LFI_FILE)
RCE_PATTERNS  = _load_patterns(RCE_FILE)
# ──────────────── decoding  ────────────────
def decode_obfuscated(value: str) -> list[str]:
    decoded_versions = [value]

    # URL decode
    try:
        url_decoded = urllib.parse.unquote(value)
        if url_decoded != value:
            decoded_versions.append(url_decoded)
    except Exception:
        pass

    # Base64 decode
    try:
        b64_decoded = base64.b64decode(value + '===').decode('utf-8', errors='ignore')
        if b64_decoded and b64_decoded != value:
            decoded_versions.append(b64_decoded)
    except Exception:
        pass

    # Hex decode (like \x41\x42)
    try:
        hex_decoded = bytes.fromhex(value.replace('\\x', '')).decode('utf-8', errors='ignore')
        if hex_decoded and hex_decoded != value:
            decoded_versions.append(hex_decoded)
    except Exception:
        pass

    return list(set(decoded_versions))  # remove duplicates
# ──────────────── Brute-Force Helper ────────────────
def record_brute_force(ip: str) -> bool:
    """
    Record this request as a 'failed' or 'risky' event for the IP,
    check if it exceeds BRUTE_FORCE_LIMIT in BRUTE_FORCE_WINDOW.
    If so, add IP to BLOCKED_IPS and return True (blocked).
    Otherwise, return False (not blocked).
    """
    now = time()
    window_start = now - BRUTE_FORCE_WINDOW

    # Get existing timestamps (if any), remove old
    timestamps = LOGIN_FAILURES.get(ip, [])
    timestamps = [t for t in timestamps if t > window_start]

    # Append this attempt
    timestamps.append(now)
    LOGIN_FAILURES[ip] = timestamps

    # Check if exceeds limit
    if len(timestamps) > BRUTE_FORCE_LIMIT:
        BLOCKED_IPS[ip] = [MAX_ATTEMPTS + 1, now]
        logger.warning(f"🚨 Brute force / rate-limit triggered for IP: {ip}")
        return True

    return False

# ──────────────── Main WAF Logic ────────────────
def analyze_request(payload: str, request_obj=None) -> str:
    ip = _client_ip()
    now = time()

    # 1. Check if IP is already blocked
    if ip in BLOCKED_IPS:
        hit_count, last_seen = BLOCKED_IPS[ip]
        if now - last_seen < BLOCK_TIME_SECONDS and hit_count >= MAX_ATTEMPTS:
            logger.warning(f"Blocked request from banned IP: {ip}")
            return "🚫 IP Blocked (too many suspicious requests)"

    # 2. Check / record brute-force attempt
    #    - If *all* requests should count, uncomment next lines:
    if record_brute_force(ip):
        return "🚫 IP Blocked (too many requests)"

    # Collect potential malicious inputs
    scan_targets = []
    scan_targets.append(("payload/body", payload))

    if request_obj:
        for key, val in request_obj.args.items():
            scan_targets.append((f"query param: {key}", val))
        for key, val in request_obj.headers.items():
            scan_targets.append((f"header: {key}", val))
        for key, val in request_obj.cookies.items():
            scan_targets.append((f"cookie: {key}", val))
        scan_targets.append(("path", request_obj.path))

    # 3. Pattern Matching for SQLi, XSS, LFI, RCE
    for source, value in scan_targets:
      for decoded in decode_obfuscated(value):
        for pattern in SQLI_PATTERNS:
            print(f"[DEBUG] Checking {source}: {decoded}")

            if pattern.search(decoded):
                _log_block("SQLi", decoded, pattern.pattern)
                return f"🚫 Blocked (SQLi → {source}: {decoded})"
        for pattern in XSS_PATTERNS:
            print(f"[DEBUG] Checking {source}: {decoded}")

            if pattern.search(decoded):
                _log_block("XSS", decoded, pattern.pattern)
                return f"🚫 Blocked (XSS → {source}: {decoded})"
        for pattern in LFI_PATTERNS:
            print(f"[DEBUG] Checking {source}: {decoded}")

            if pattern.search(decoded):
                _log_block("LFI", decoded, pattern.pattern)
                return f"🚫 Blocked (LFI → {source}: {decoded})"
        for pattern in RCE_PATTERNS:
            print(f"[DEBUG] Checking {source}: {decoded}")

            if pattern.search(decoded):
                _log_block("RCE", decoded, pattern.pattern)
                return f"🚫 Blocked (RCE → {source}: {decoded})"


    # 4. Allowed
    _log_allow(payload)
    return "✅ Allowed (no threat detected)"

# ──────────────── Logging Helpers ────────────────
def _log_block(attack_type: str, payload: str, pattern: str):
    ip = _client_ip()
    geo = _get_geo(ip)

    # Track IP strike count
    now = time()
    if ip in BLOCKED_IPS:
        BLOCKED_IPS[ip][0] += 1
        BLOCKED_IPS[ip][1] = now
    else:
        BLOCKED_IPS[ip] = [1, now]

    # Emoji per attack type
    emoji = {
        "SQLi": "🛑",
        "XSS":  "🚨",
        "LFI":  "📂",
        "RCE":  "💣",
    }.get(attack_type, "⚠️")

    # Desktop notification
    title = f"{emoji} {attack_type} Blocked!"
    message = f"🌍 IP: {ip}\n📍 Location: {geo}\n💬 Payload: {payload[:80]}"
    notification.notify(title=title, message=message, timeout=6)

    logger.info(f"{attack_type} BLOCK | ip={ip:15s} {geo:30s} | pattern={pattern} | payload={payload}")

def _log_allow(payload: str):
    logger.debug(f"ALLOW | ip={_client_ip():15s} | payload={payload}")

