"""
PhishGuard — Cyber Threat Intelligence (CTI) Service
======================================================
Async-first forensics module.  All I/O runs concurrently via asyncio.gather()
in the /scan endpoint so a single slow lookup never stalls the pipeline.

Function map
------------
  dns_lookup()         →  Live A/AAAA DNS resolution  (dnspython async)
  whois_lookup()       →  Live WHOIS domain-age query  (python-whois + thread)
  check_virustotal()   →  VirusTotal API stub           (mock — no key needed)
  check_urlhaus()      →  URLhaus API stub              (mock — no key needed)

Swapping stubs for production
------------------------------
Each stub function contains a commented-out PRODUCTION block.
Un-comment it, install aiohttp, add your API keys to .env, and delete the mock.

Python ≥ 3.9 required (asyncio.to_thread, str.removeprefix).
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception
import dns.resolver
import whois as pywhois  # pip install python-whois  (import alias avoids shadowing)

logger = logging.getLogger("phishguard.cti")

# ---------------------------------------------------------------------------
# Tuneable timeouts (seconds)
# ---------------------------------------------------------------------------
DNS_TIMEOUT: float = 3.0      # Per-record-type DNS query deadline
WHOIS_TIMEOUT: float = 8.0    # Total budget for the synchronous WHOIS syscall
HTTP_TIMEOUT: float = 4.0     # Budget for real external API calls (production)


# ===========================================================================
# 1.  DNS FORENSICS
# ===========================================================================

async def dns_lookup(hostname: str) -> Dict[str, Any]:
    """
    Passive DNS lookup: resolve A (IPv4) and AAAA (IPv6) records for *hostname*.

    Why it matters for phishing detection
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    • No A records for a live hostname → possible domain squatting / DNS hijack.
    • Resolution to a private IP (10.x, 192.168.x) → possible DNS cache poisoning.
    • Unusually low TTL or single-IP answers → bulletproof hosting indicator.

    Parameters
    ----------
    hostname : str
        Bare hostname, e.g. ``"secure-paypal-verify.tk"``

    Returns
    -------
    dict with keys:
        hostname     str        — echoed input
        a_records    list[str]  — IPv4 addresses (may be empty)
        aaaa_records list[str]  — IPv6 addresses (often empty — not suspicious)
        error        str|None   — human-readable error if lookup failed
    """
    result: Dict[str, Any] = {
        "hostname": hostname,
        "a_records": [],
        "aaaa_records": [],
        "error": None,
    }

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT  # Hard wall-clock limit for the full resolution chain

    # --- A records (IPv4) -------------------------------------------------
    try:
        answer = await resolver.resolve(hostname, "A")
        result["a_records"] = [rr.address for rr in answer]
        logger.debug("DNS A  %-40s → %s", hostname, result["a_records"])

    except dns.asyncresolver.NXDOMAIN:
        result["error"] = "NXDOMAIN — hostname does not exist in DNS"
    except dns.asyncresolver.NoAnswer:
        result["error"] = "No A records published for this hostname"
    except dns.exception.Timeout:
        result["error"] = f"DNS A query timed out after {DNS_TIMEOUT}s"
    except dns.asyncresolver.NoNameservers:
        result["error"] = "No authoritative nameservers responded"
    except Exception as exc:
        result["error"] = f"DNS A lookup error: {type(exc).__name__}: {exc}"
        logger.warning("Unexpected DNS error for %s: %s", hostname, exc)

    # --- AAAA records (IPv6) — failure is non-fatal -----------------------
    try:
        answer = await resolver.resolve(hostname, "AAAA")
        result["aaaa_records"] = [rr.address for rr in answer]
        logger.debug("DNS AAAA %-40s → %s", hostname, result["aaaa_records"])
    except Exception:
        pass  # IPv6 absence is routine; do not overwrite the A-record error

    return result


# ===========================================================================
# 2.  WHOIS FORENSICS
# ===========================================================================

async def whois_lookup(domain: str) -> Dict[str, Any]:
    """
    Extract WHOIS registration metadata, focusing on domain age.

    Why domain age matters
    ~~~~~~~~~~~~~~~~~~~~~~
    Phishing actors register fresh domains specifically to dodge blocklists.
    Domains < 30 days old that host login forms are extremely high risk.

    Implementation note
    ~~~~~~~~~~~~~~~~~~~~
    ``python-whois`` is synchronous and can block for several seconds while it
    negotiates with WHOIS servers.  We offload the call to a thread via
    ``asyncio.to_thread()`` — the event loop stays unblocked throughout,
    preserving the sub-500 ms target for all parallel CTI tasks.

    Parameters
    ----------
    domain : str
        Registerable domain, e.g. ``"secure-paypal-verify.tk"``

    Returns
    -------
    dict with keys:
        domain           str        — echoed input
        creation_date    str|None   — ISO-8601 UTC timestamp of registration
        domain_age_days  int|None   — days since creation (None if unavailable)
        registrar        str|None   — registrar name from WHOIS
        error            str|None   — human-readable error if lookup failed
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "creation_date": None,
        "domain_age_days": None,
        "registrar": None,
        "error": None,
    }

    def _blocking_whois() -> Optional[pywhois.WhoisEntry]:
        """
        Synchronous WHOIS call — executed inside a thread-pool worker.
        Must not call any asyncio primitives.
        """
        try:
            return pywhois.whois(domain)
        except Exception as exc:
            logger.debug("whois(%s) raised: %s", domain, exc)
            return None

    try:
        # asyncio.to_thread wraps the blocking call in a default thread-pool
        # executor, returning a coroutine that the event loop can await without
        # blocking.  asyncio.wait_for adds a hard timeout on top.
        w: Optional[pywhois.WhoisEntry] = await asyncio.wait_for(
            asyncio.to_thread(_blocking_whois),
            timeout=WHOIS_TIMEOUT,
        )

        if w is None:
            result["error"] = "WHOIS query returned no usable data"
            return result

        # creation_date may be a single datetime or a list of datetimes
        creation_date: Any = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Take the earliest date

        if isinstance(creation_date, datetime):
            # Normalise to a timezone-aware UTC datetime for consistent delta maths
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_days: int = (now - creation_date).days

            result["creation_date"] = creation_date.isoformat()
            result["domain_age_days"] = age_days
            result["registrar"] = str(w.registrar).strip() if w.registrar else None
            logger.debug("WHOIS %-40s → %d days old, registrar=%s",
                         domain, age_days, result["registrar"])
        else:
            result["error"] = "creation_date field could not be parsed as a datetime"

    except asyncio.TimeoutError:
        result["error"] = f"WHOIS query timed out after {WHOIS_TIMEOUT}s"
        logger.warning("WHOIS timeout for domain: %s", domain)
    except Exception as exc:
        result["error"] = f"WHOIS lookup failed: {type(exc).__name__}: {exc}"
        logger.warning("Unexpected WHOIS error for %s: %s", domain, exc)

    return result


# ===========================================================================
# 3.  VIRUSTOTAL STUB
# ===========================================================================

async def check_virustotal(url: str) -> Dict[str, Any]:
    """
    Query the VirusTotal URL scan API for multi-engine malware/phishing verdicts.

    ╔══════════════════════════════════════════════════════════════════════╗
    ║  STUB — deterministic mock responses, no API key required           ║
    ║                                                                      ║
    ║  To enable the REAL VirusTotal v3 integration:                      ║
    ║  1. pip install aiohttp                                              ║
    ║  2. export VIRUSTOTAL_API_KEY="<your_key>"                          ║
    ║  3. Uncomment the PRODUCTION block below, delete the MOCK block.    ║
    ║  4. Remove "mock": True from the return dict.                        ║
    ╚══════════════════════════════════════════════════════════════════════╝

    Parameters
    ----------
    url : str  — Full URL to evaluate

    Returns
    -------
    dict with keys:
        source             str   — "VirusTotal"
        flagged            bool  — True if any engines flagged this URL
        malicious_engines  int   — count of AV engines that detected malicious activity
        total_engines      int   — total engines that scanned the URL
        status             str   — "malicious" | "clean" | "error"
        mock               bool  — True in stub mode; remove in production
    """

    # ── PRODUCTION IMPLEMENTATION ──────────────────────────────────────────
    # import os, base64
    # import aiohttp
    #
    # API_KEY = os.environ["VIRUSTOTAL_API_KEY"]
    # # VirusTotal v3 uses base64url-encoded URL as the resource identifier
    # url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    #
    # async with aiohttp.ClientSession() as session:
    #     async with session.get(
    #         f"https://www.virustotal.com/api/v3/urls/{url_id}",
    #         headers={"x-apikey": API_KEY},
    #         timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
    #     ) as resp:
    #         if resp.status == 404:
    #             # URL not yet in VT database; trigger a fresh analysis
    #             async with session.post(
    #                 "https://www.virustotal.com/api/v3/urls",
    #                 headers={"x-apikey": API_KEY},
    #                 data={"url": url},
    #             ) as post_resp:
    #                 pass  # analysis queued; return early or poll for result
    #         data = await resp.json()
    #
    # stats = data["data"]["attributes"]["last_analysis_stats"]
    # malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
    # total = sum(stats.values())
    # return {
    #     "source": "VirusTotal",
    #     "flagged": malicious > 0,
    #     "malicious_engines": malicious,
    #     "total_engines": total,
    #     "status": "malicious" if malicious > 0 else "clean",
    # }
    # ──────────────────────────────────────────────────────────────────────

    # ── MOCK IMPLEMENTATION ───────────────────────────────────────────────
    await asyncio.sleep(0.015)  # Simulate ~15 ms network round-trip latency

    # Deterministically flag URLs whose paths contain phishing-bait vocabulary
    PHISHING_BAIT_KEYWORDS: frozenset[str] = frozenset({
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "password", "credential", "banking", "wallet",
        "paypal", "amazon", "microsoft", "apple", "google", "dropbox",
    })

    url_lower = url.lower()
    flagged = any(kw in url_lower for kw in PHISHING_BAIT_KEYWORDS)
    malicious_count = 9 if flagged else 0

    logger.debug("VT stub | flagged=%s url=%s", flagged, url[:80])
    return {
        "source": "VirusTotal",
        "flagged": flagged,
        "malicious_engines": malicious_count,
        "total_engines": 72,
        "status": "malicious" if flagged else "clean",
        "mock": True,  # ← Delete this field when using the real API
    }


# ===========================================================================
# 4.  URLHAUS STUB
# ===========================================================================

async def check_urlhaus(url: str) -> Dict[str, Any]:
    """
    Query the abuse.ch URLhaus database for URLs actively distributing malware.

    ╔══════════════════════════════════════════════════════════════════════╗
    ║  STUB — deterministic mock responses, no API key required           ║
    ║                                                                      ║
    ║  URLhaus is FREE and requires no key for basic URL lookups.         ║
    ║  To enable the REAL URLhaus integration:                            ║
    ║  1. pip install aiohttp                                              ║
    ║  2. Uncomment the PRODUCTION block below, delete the MOCK block.    ║
    ║  3. Remove "mock": True from the return dict.                        ║
    ╚══════════════════════════════════════════════════════════════════════╝

    Parameters
    ----------
    url : str  — Full URL to evaluate

    Returns
    -------
    dict with keys:
        source       str       — "URLhaus"
        flagged      bool      — True if URL is in the URLhaus malware feed
        threat_type  str|None  — e.g. "phishing", "malware_download", None
        status       str       — "malicious" | "clean" | "error"
        mock         bool      — True in stub mode; remove in production
    """

    # ── PRODUCTION IMPLEMENTATION ──────────────────────────────────────────
    # import aiohttp
    #
    # async with aiohttp.ClientSession() as session:
    #     async with session.post(
    #         "https://urlhaus-api.abuse.ch/v1/url/",
    #         data={"url": url},
    #         timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
    #     ) as resp:
    #         data = await resp.json(content_type=None)  # URLhaus returns text/html MIME
    #
    # query_status = data.get("query_status", "not_found")
    #
    # if query_status == "is_malware":
    #     return {
    #         "source": "URLhaus",
    #         "flagged": True,
    #         "threat_type": data.get("threat", "malware_distribution"),
    #         "status": "malicious",
    #     }
    # return {
    #     "source": "URLhaus",
    #     "flagged": False,
    #     "threat_type": None,
    #     "status": "clean",
    # }
    # ──────────────────────────────────────────────────────────────────────

    # ── MOCK IMPLEMENTATION ───────────────────────────────────────────────
    await asyncio.sleep(0.015)  # Simulate ~15 ms network round-trip latency

    # Free TLDs that are routinely abused for malware / phishing distribution
    ABUSED_TLDS: frozenset[str] = frozenset({
        ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom TLDs (frequently abused)
        ".xyz", ".top", ".pw", ".cc", ".su",  # Other commonly abused TLDs
    })

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    flagged = any(hostname.endswith(tld) for tld in ABUSED_TLDS)
    threat = "phishing" if flagged else None

    logger.debug("URLhaus stub | flagged=%s url=%s", flagged, url[:80])
    return {
        "source": "URLhaus",
        "flagged": flagged,
        "threat_type": threat,
        "status": "malicious" if flagged else "clean",
        "mock": True,  # ← Delete this field when using the real API
    }
