
from __future__ import annotations

import ipaddress
import math
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────────────
# Module-level constants
# ─────────────────────────────────────────────────────────────────────────────

# High-risk TLDs empirically associated with phishing activity.
# Sources: SpamHaus TLD abuse table, APWG eCrime reports (2022-2024).
# Freenom free domains (.tk/.ml/.ga/.cf/.gq) historically account for
# >50% of phishing domains by volume despite minimal legitimate use.
HIGH_RISK_TLDS: frozenset = frozenset({
    ".tk",  ".ml",  ".ga",   ".cf",  ".gq",    # Freenom — top-abused globally
    ".xyz", ".top", ".work", ".click",           # Bulk-registration targets
    ".loan", ".win", ".bid", ".stream",           # High historical phish rate
    ".pw",  ".cc",  ".su",                        # Obscure / legacy vectors
    ".zip", ".mov",                               # Google gTLD abuse (2023+)
})

# Keywords commonly injected into phishing URLs to mimic legitimate services.
# Presence of these in the hostname or path is a significant red flag.
PHISHING_KEYWORDS: List[str] = [
    "login",    # Mimics authentication portals
    "secure",   # False legitimacy signal
    "update",   # Lures users to "update" credentials
    "verify",   # Account verification phishing flows
    "account",  # Targets account-management pages
]

# Characters tracked for count-based features.
# Obfuscation characters (%, @) are disproportionately common in phishing
# URLs because they encode misleading content or confuse URL parsers.
TRACKED_CHARS: Dict[str, str] = {
    "count_slash":      "/",   # Excessive depth → obfuscated paths
    "count_hyphen":     "-",   # Brand spoofing: paypal-secure.com
    "count_underscore": "_",   # Unusual in legitimate domain names
    "count_at":         "@",   # http://legit.com@evil.com trick
    "count_equals":     "=",   # Query parameter flooding
    "count_percent":    "%",   # URL-encoding obfuscation (%2F, %40)
    "count_question":   "?",   # Multiple ? → malformed / suspicious
}

# Canonical feature name ordering.
# THIS ORDER IS CONTRACT — must stay identical in train.py and inference.
FEATURE_NAMES: List[str] = [
    # ── Group 1: Length-based ────────────────────────────────────────
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    # ── Group 2: Character-based ─────────────────────────────────────
    "count_slash",
    "count_hyphen",
    "count_underscore",
    "count_at",
    "count_equals",
    "count_percent",
    "count_question",
    # ── Group 3: Structural ───────────────────────────────────────────
    "digit_letter_ratio",
    "num_dots",
    "subdomain_depth",
    # ── Group 4: Semantic keywords ────────────────────────────────────
    "has_login",
    "has_secure",
    "has_update",
    "has_verify",
    "has_account",
    # ── Group 5: Randomness ───────────────────────────────────────────
    "hostname_entropy",
    # ── Group 6: Metadata stubs ───────────────────────────────────────
    "is_ip_address",
    "is_https",
    "tld_risk_score",
    "domain_age_days",
]

assert len(FEATURE_NAMES) == 24, "Feature count invariant violated."


# ─────────────────────────────────────────────────────────────────────────────
# Internal helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _safe_parse(url: str) -> Optional[object]:
   
    try:
        # Normalise: ensure the URL has a scheme so urlparse can split
        # the netloc (hostname) component correctly.
        if not re.match(r"^[a-zA-Z][a-zA-Z\d+\-.]*://", url):
            url = "http://" + url
        return urlparse(url)
    except Exception:
        # Malformed URLs must never crash the extension or backend.
        return None


def _shannon_entropy(text: str) -> float:
   
    if not text:
        return 0.0

    # Build character frequency table in a single pass.
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _digit_letter_ratio(text: str) -> float:
    
    letters = sum(ch.isalpha() for ch in text)
    digits  = sum(ch.isdigit() for ch in text)
    return digits / letters if letters > 0 else 0.0


def _is_ip_address(hostname: str) -> int:
    
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return 1
    except ValueError:
        return 0


def _tld_risk_score(hostname: str) -> int:
   
    host_lower = hostname.lower()
    for tld in HIGH_RISK_TLDS:
        if host_lower.endswith(tld):
            return 1
    return 0


def _subdomain_depth(hostname: str) -> int:
   
    if not hostname:
        return 0
    parts = [p for p in hostname.split(".") if p]  # ignore empty splits
    return max(0, len(parts) - 2)


# ─────────────────────────────────────────────────────────────────────────────
# Metadata stub functions
# ─────────────────────────────────────────────────────────────────────────────
# These functions define the *interface contract* between the ML pipeline
# and the production backend.  During training, they return sentinel values
# so the model learns a statistical prior over missing/unknown metadata.
# In production FastAPI inference, each stub is replaced by a live API call
# while keeping the return type identical.

def get_is_https(parsed) -> int:
   
    if parsed is None:
        return 0
    return 1 if parsed.scheme.lower() == "https" else 0


def get_domain_age_days(hostname: str) -> int:
   
    # --- STUB: replace with live whois call in production ---
    return -1


# ─────────────────────────────────────────────────────────────────────────────
# Primary extractor class
# ─────────────────────────────────────────────────────────────────────────────

class URLFeatureExtractor:
   
    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def extract(self, url: str) -> Dict[str, float]:
       
        parsed    = _safe_parse(url)
        lower_url = url.lower()

        # ── Group 1: Length-based features ───────────────────────────
        # Raw length signals provide a strong first-pass discriminator:
        # phishing URLs are often bloated with obfuscation padding while
        # legitimate URLs tend to be concise and human-readable.
        url_length   = len(url)
        host_length  = len(parsed.netloc) if parsed else 0
        path_length  = len(parsed.path)   if parsed else 0
        query_length = len(parsed.query)  if parsed else 0

        # ── Group 2: Character-based features ────────────────────────
        # Count each tracked character across the entire lowercased URL.
        char_counts: Dict[str, int] = {
            feat_name: lower_url.count(char)
            for feat_name, char in TRACKED_CHARS.items()
        }

        # ── Group 3: Structural features ─────────────────────────────
        # Extract and clean hostname (strip port number if present).
        netloc         = parsed.netloc if parsed else ""
        hostname_clean = netloc.split(":")[0]  # remove :port suffix

        digit_ratio     = _digit_letter_ratio(lower_url)
        num_dots        = lower_url.count(".")
        sub_depth       = _subdomain_depth(hostname_clean)

        # ── Group 4: Semantic keyword flags ──────────────────────────
        # Boolean (0/1) presence of high-signal phishing keywords.
        # Checked against the entire lowercased URL so they catch
        # occurrences in path, query, and fragment — not just hostname.
        keyword_flags: Dict[str, int] = {
            f"has_{kw}": int(kw in lower_url)
            for kw in PHISHING_KEYWORDS
        }

        # ── Group 5: Randomness metric ────────────────────────────────
        # Entropy is intentionally computed on the *hostname only* (not
        # the full URL) to isolate the DGA detection signal from the
        # predictable structure of paths and query strings.
        hostname_entropy = _shannon_entropy(hostname_clean)

        # ── Group 6: Metadata features (stubs) ───────────────────────
        is_ip    = _is_ip_address(hostname_clean)
        is_https = get_is_https(parsed)
        tld_risk = _tld_risk_score(hostname_clean)
        dom_age  = get_domain_age_days(hostname_clean)  # stub → -1

        # ── Assemble the ordered feature dictionary ───────────────────
        features: Dict[str, float] = {
            # Group 1
            "url_length":         float(url_length),
            "host_length":        float(host_length),
            "path_length":        float(path_length),
            "query_length":       float(query_length),
            # Group 2
            **{k: float(v) for k, v in char_counts.items()},
            # Group 3
            "digit_letter_ratio": float(digit_ratio),
            "num_dots":           float(num_dots),
            "subdomain_depth":    float(sub_depth),
            # Group 4
            **{k: float(v) for k, v in keyword_flags.items()},
            # Group 5
            "hostname_entropy":   float(hostname_entropy),
            # Group 6
            "is_ip_address":      float(is_ip),
            "is_https":           float(is_https),
            "tld_risk_score":     float(tld_risk),
            "domain_age_days":    float(dom_age),
        }

        # Invariant check: ensure we produced exactly 24 features.
        assert set(features.keys()) == set(FEATURE_NAMES), (
            "Feature set mismatch — check FEATURE_NAMES contract."
        )
        return features

    def extract_vector(self, url: str) -> List[float]:
        """
        Return features as a plain list in canonical ``FEATURE_NAMES`` order.

        Preferred for building numpy arrays in batch-scoring scenarios
        (e.g. FastAPI endpoint, Jupyter evaluation notebooks).

        Parameters
        ----------
        url : str
            Raw URL string.

        Returns
        -------
        List[float]
            24-element list ordered by ``FEATURE_NAMES``.
        """
        feat_dict = self.extract(url)
        return [feat_dict[name] for name in FEATURE_NAMES]


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(url: str) -> Dict[str, float]:
    
    return URLFeatureExtractor().extract(url)


# ─────────────────────────────────────────────────────────────────────────────
# Smoke test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # ── Test URLs covering a range of attack patterns ─────────────────
    test_cases = [
        # (url, expected_label)
        ("https://www.google.com/search?q=python+docs",       "LEGITIMATE"),
        ("http://paypa1-secure.login.tk/verify?user=admin@x", "PHISHING"),
        ("http://192.168.1.1/account/update?token=abc%20xyz", "PHISHING"),
        ("https://ftp.mozilla.org/pub/firefox/releases/",     "LEGITIMATE"),
        ("http://secure-update.verify.account.xyz/login/",    "PHISHING"),
        ("https://cdn.jsdelivr.net/npm/bootstrap@5/dist/",    "LEGITIMATE"),
        ("http://xn--p1acf.xn--80aqecdr1a/secure/verify",    "PHISHING"),  # IDN
    ]

    extractor = URLFeatureExtractor()

    print("\n" + "=" * 70)
    print("  URLFeatureExtractor — Smoke Test")
    print("=" * 70)

    for url, label in test_cases:
        feats  = extractor.extract(url)
        vector = extractor.extract_vector(url)
        print(f"\n  [{label}] {url[:65]}")
        print(f"  {'Feature':<22}  {'Value':>10}")
        print(f"  {'-'*35}")
        for name, value in feats.items():
            print(f"  {name:<22}  {value:>10.4f}")
        print(f"\n  Vector ({len(vector)} dims): "
              f"[{', '.join(f'{v:.3f}' for v in vector[:6])} …]")

    print("\n[✓] All features extracted successfully.")
    print(f"[✓] Feature count: {len(FEATURE_NAMES)} (invariant satisfied)")
