

from __future__ import annotations

import gzip
import io
import logging
import os
import time
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
import requests

# Local module — must be importable from the same directory
from feature_extractor import FEATURE_NAMES, URLFeatureExtractor


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration constants
# ─────────────────────────────────────────────────────────────────────────────

# ── PhishTank ────────────────────────────────────────────────────────────────
# Hourly-updated CSV of community-verified, currently-online phishing URLs.
# With API key: rate-limit waived.  Without: 1 request per 5 minutes.
PHISHTANK_API_KEY: Optional[str] = os.environ.get("PHISHTANK_API_KEY")
PHISHTANK_URL_ANON: str = "http://data.phishtank.com/data/online-valid.csv.gz"

# ── URLhaus (abuse.ch) ───────────────────────────────────────────────────────
# CSV feed of currently-online URLs used for malware/botnet distribution.
# Complementary to PhishTank: covers malware droppers, not just phish pages.
URLHAUS_CSV_URL: str = "https://urlhaus.abuse.ch/downloads/csv_online/"

# ── Tranco Top-1M ────────────────────────────────────────────────────────────
# Research-oriented top-1M domain list, more stable than Alexa/Majestic.
# We take the top-N and prefix "https://" to form valid URLs.
TRANCO_URL: str = "https://tranco-list.eu/top-1m.csv.gz"
TRANCO_SAMPLE_SIZE: int = 40_000   # domains → legitimate URL samples

# ── ISCX URL 2016 (Kaggle) ───────────────────────────────────────────────────
# Local path; skipped gracefully if absent.  Provides ~651K labelled URLs
# across benign / phishing / malicious / defacement / spam categories.
ISCX_CSV_PATH: str = "iscx_url2016.csv"

# ── Shared request settings ───────────────────────────────────────────────────
REQUEST_TIMEOUT: int   = 90   # seconds per network request
REQUEST_HEADERS: dict  = {
    "User-Agent": "PhishGuard/2.0 (phishing-detection-research; "
                  "contact: phishguard-research@example.com)"
}

# ── Output ────────────────────────────────────────────────────────────────────
# Intermediate CSV saved by build_dataset() for human inspection.
DATASET_OUTPUT_PATH: str = "phishguard_dataset.csv"

# ── ISCX type → binary label mapping ─────────────────────────────────────────
# Only 'benign' and its alias 'legitimate' map to label 0.
# All other threat categories are treated as malicious (label 1).
ISCX_LABEL_MAP: dict = {
    "benign":     0,
    "legitimate": 0,   # alternate column value in some Kaggle versions
    "phishing":   1,
    "malicious":  1,
    "defacement": 1,
    "spam":       1,
}


# ─────────────────────────────────────────────────────────────────────────────
# Source 1 — PhishTank
# ─────────────────────────────────────────────────────────────────────────────

def fetch_phishtank(
    api_key:    Optional[str] = PHISHTANK_API_KEY,
    cache_path: str           = "phishtank_cache.csv",
) -> pd.DataFrame:
   
    if api_key:
        download_url = f"http://data.phishtank.com/data/{api_key}/online-valid.csv.gz"
    else:
        download_url = PHISHTANK_URL_ANON

    log.info("PhishTank → downloading from %s …", download_url)

    try:
        resp = requests.get(
            download_url,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()

        # Decompress gzip payload entirely in memory — no temp files.
        with gzip.open(io.BytesIO(resp.content)) as gz:
            df = pd.read_csv(
                gz,
                usecols=["url", "verified", "online"],
                low_memory=False,
            )

        # Retain only verified + online phishing URLs (highest confidence).
        df = df[
            (df["verified"].str.lower() == "yes") &
            (df["online"].str.lower()   == "yes")
        ].copy()

        df = df[["url"]].dropna()
        df["label"] = 1
        df.to_csv(cache_path, index=False)
        log.info("PhishTank → %d verified phishing URLs loaded.", len(df))
        return df

    except Exception as exc:
        log.warning("PhishTank download failed (%s). Checking local cache …", exc)

    # ── Fallback: local cache ─────────────────────────────────────────
    if Path(cache_path).exists():
        log.info("PhishTank → using cached data from '%s'.", cache_path)
        cached = pd.read_csv(cache_path)
        if "label" not in cached.columns:
            cached["label"] = 1
        return cached[["url", "label"]]

    log.error("PhishTank → no cache found.  Source will be skipped.")
    return pd.DataFrame(columns=["url", "label"])


# ─────────────────────────────────────────────────────────────────────────────
# Source 2 — URLhaus (abuse.ch)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_urlhaus(cache_path: str = "urlhaus_cache.csv") -> pd.DataFrame:
    
    log.info("URLhaus → downloading from %s …", URLHAUS_CSV_URL)

    try:
        resp = requests.get(
            URLHAUS_CSV_URL,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()

        # Strip comment lines (lines starting with '#') before CSV parsing.
        lines      = [ln for ln in resp.text.splitlines() if not ln.startswith("#")]
        clean_body = "\n".join(lines)

        # URLhaus CSV columns (no header after comment strip):
        # id, dateadded, url, url_status, last_online, threat, tags,
        # urlhaus_link, reporter
        df = pd.read_csv(
            io.StringIO(clean_body),
            header=None,
            names=[
                "id", "dateadded", "url", "url_status",
                "last_online", "threat", "tags",
                "urlhaus_link", "reporter",
            ],
            quotechar='"',
            on_bad_lines="skip",
            low_memory=False,
        )

        df = df[["url"]].dropna()
        df["label"] = 1
        df.to_csv(cache_path, index=False)
        log.info("URLhaus → %d malicious URLs loaded.", len(df))
        return df

    except Exception as exc:
        log.warning("URLhaus download failed (%s). Checking local cache …", exc)

    # ── Fallback: local cache ─────────────────────────────────────────
    if Path(cache_path).exists():
        log.info("URLhaus → using cached data from '%s'.", cache_path)
        cached = pd.read_csv(cache_path)
        if "label" not in cached.columns:
            cached["label"] = 1
        return cached[["url", "label"]]

    log.error("URLhaus → no cache found.  Source will be skipped.")
    return pd.DataFrame(columns=["url", "label"])


# ─────────────────────────────────────────────────────────────────────────────
# Source 3 — Tranco Top-1M (legitimate domains)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_tranco(
    sample_size: int = TRANCO_SAMPLE_SIZE,
    cache_path:  str = "tranco_cache.csv",
) -> pd.DataFrame:
   
    log.info("Tranco → downloading top %d domains from %s …", sample_size, TRANCO_URL)

    try:
        resp = requests.get(
            TRANCO_URL,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT * 2,   # larger file — generous timeout
        )
        resp.raise_for_status()

        with gzip.open(io.BytesIO(resp.content)) as gz:
            df = pd.read_csv(
                gz,
                header=None,
                names=["rank", "domain"],
                nrows=sample_size,
            )

        # Prepend HTTPS scheme to form valid, parseable URLs.
        df["url"]   = "https://" + df["domain"].str.strip()
        df          = df[["url"]].dropna()
        df["label"] = 0
        df.to_csv(cache_path, index=False)
        log.info("Tranco → %d legitimate domains loaded.", len(df))
        return df

    except Exception as exc:
        log.warning("Tranco download failed (%s). Checking local cache …", exc)

    # ── Fallback: local cache ─────────────────────────────────────────
    if Path(cache_path).exists():
        log.info("Tranco → using cached data from '%s'.", cache_path)
        cached = pd.read_csv(cache_path)
        if "label" not in cached.columns:
            cached["label"] = 0
        return cached[["url", "label"]]

    log.error("Tranco → no cache found.  Source will be skipped.")
    return pd.DataFrame(columns=["url", "label"])


# ─────────────────────────────────────────────────────────────────────────────
# Source 4 — ISCX URL 2016 (Kaggle benchmark)
# ─────────────────────────────────────────────────────────────────────────────

def load_iscx(csv_path: str = ISCX_CSV_PATH) -> pd.DataFrame:
    
    if not Path(csv_path).exists():
        log.warning(
            "ISCX URL 2016 → '%s' not found.  "
            "Download from Kaggle (see module docstring) to include this source.",
            csv_path,
        )
        return pd.DataFrame(columns=["url", "label"])

    log.info("ISCX URL 2016 → loading from '%s' …", csv_path)

    try:
        df = pd.read_csv(csv_path, low_memory=False)

        # ── Column detection ──────────────────────────────────────────
        col_lower = {c.lower(): c for c in df.columns}

        url_col   = next(
            (col_lower[k] for k in ("url", "urls") if k in col_lower),
            None,
        )
        label_col = next(
            (col_lower[k] for k in ("type", "label", "class", "category")
             if k in col_lower),
            None,
        )

        if url_col is None or label_col is None:
            log.error(
                "ISCX → cannot detect URL/label columns. "
                "Available columns: %s", list(df.columns),
            )
            return pd.DataFrame(columns=["url", "label"])

        df = df[[url_col, label_col]].rename(
            columns={url_col: "url", label_col: "raw_type"}
        ).dropna()

        # ── Label mapping ─────────────────────────────────────────────
        raw_values = df["raw_type"].astype(str).str.lower().str.strip()

        if raw_values.str.isnumeric().all():
            # Already numeric — assume 0=legitimate, 1=malicious
            df["label"] = pd.to_numeric(df["raw_type"], errors="coerce")
        else:
            # Categorical strings → binary map via ISCX_LABEL_MAP
            df["label"] = raw_values.map(ISCX_LABEL_MAP)

        df = df[["url", "label"]].dropna()
        df["label"] = df["label"].astype(int)
        df = df[df["label"].isin([0, 1])]   # discard unmapped rows

        n_legit = (df["label"] == 0).sum()
        n_mal   = (df["label"] == 1).sum()
        log.info(
            "ISCX URL 2016 → %d URLs  (legitimate: %d, malicious: %d).",
            len(df), n_legit, n_mal,
        )
        return df

    except Exception as exc:
        log.error("ISCX load failed: %s", exc)
        return pd.DataFrame(columns=["url", "label"])


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction (batch)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_features_batch(
    urls:       List[str],
    batch_size: int = 5_000,
) -> np.ndarray:
   
    extractor = URLFeatureExtractor()
    vectors   = []
    total     = len(urls)

    for i, url in enumerate(urls):
        if i % batch_size == 0 and total > 0:
            pct = 100 * i / total
            log.info("  Extracting features: %d / %d  (%.0f%%) …", i, total, pct)
        try:
            vectors.append(extractor.extract_vector(str(url).strip()))
        except Exception:
            vectors.append([0.0] * len(FEATURE_NAMES))

    log.info("  Extracting features: %d / %d  (100%%) — done.", total, total)
    return np.array(vectors, dtype=float)


# ─────────────────────────────────────────────────────────────────────────────
# Master pipeline entry point
# ─────────────────────────────────────────────────────────────────────────────

def build_dataset(
    use_phishtank: bool = True,
    use_urlhaus:   bool = True,
    use_tranco:    bool = True,
    use_iscx:      bool = True,
    max_malicious: int  = 50_000,
    max_legit:     int  = 50_000,
    output_csv:    str  = DATASET_OUTPUT_PATH,
    random_state:  int  = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    
    rng = np.random.default_rng(random_state)

    log.info("╔══════════════════════════════════════════════════════╗")
    log.info("║  PhishGuard :: Data Pipeline — Ingestion Starting   ║")
    log.info("╚══════════════════════════════════════════════════════╝")

    # ── Stage 1: Fetch all enabled sources ───────────────────────────
    frames: list = []

    if use_phishtank:
        frames.append(fetch_phishtank())
        time.sleep(1)   # polite inter-source delay

    if use_urlhaus:
        frames.append(fetch_urlhaus())
        time.sleep(1)

    if use_tranco:
        frames.append(fetch_tranco())
        time.sleep(1)

    if use_iscx:
        frames.append(load_iscx())

    # ── Stage 2: Merge ────────────────────────────────────────────────
    non_empty = [f for f in frames if not f.empty]
    if not non_empty:
        raise RuntimeError(
            "All data sources returned empty results.  "
            "Check network connectivity and verify that ISCX CSV is present."
        )

    raw = pd.concat(non_empty, ignore_index=True)
    log.info("Combined raw rows (all sources, pre-cleaning): %d", len(raw))

    # ── Stage 3: Clean ────────────────────────────────────────────────
    raw["url"]   = raw["url"].astype(str).str.strip()
    raw          = raw[raw["url"].str.len() >= 10]   # drop degenerate URLs
    raw          = raw.dropna(subset=["label"])
    raw["label"] = raw["label"].astype(int)
    raw          = raw[raw["label"].isin([0, 1])]    # keep only valid labels

    # ── Stage 4: Deduplicate ──────────────────────────────────────────
    before_dedup = len(raw)
    raw          = raw.drop_duplicates(subset=["url"])
    dropped      = before_dedup - len(raw)
    log.info(
        "Deduplication: %d → %d rows  (%d exact duplicates removed).",
        before_dedup, len(raw), dropped,
    )

    # ── Stage 5: Cap each class ───────────────────────────────────────
    legit_df = raw[raw["label"] == 0].copy()
    mal_df   = raw[raw["label"] == 1].copy()

    if len(legit_df) > max_legit:
        legit_df = legit_df.sample(n=max_legit, random_state=random_state)
        log.info("Legitimate class capped at %d URLs.", max_legit)

    if len(mal_df) > max_malicious:
        mal_df = mal_df.sample(n=max_malicious, random_state=random_state)
        log.info("Malicious class capped at %d URLs.", max_malicious)

    df      = pd.concat([legit_df, mal_df], ignore_index=True)
    n_total = len(df)
    n_legit = int((df["label"] == 0).sum())
    n_mal   = int((df["label"] == 1).sum())
    log.info(
        "Dataset composition: %d total  "
        "(legitimate: %d [%.1f%%], malicious: %d [%.1f%%])",
        n_total,
        n_legit, 100 * n_legit / n_total,
        n_mal,   100 * n_mal   / n_total,
    )

    # ── Stage 6: Feature extraction ───────────────────────────────────
    log.info("Extracting 24-dimensional feature vectors for %d URLs …", n_total)
    X = _extract_features_batch(df["url"].tolist())
    y = df["label"].values.astype(int)

    # ── Stage 7: Shuffle ──────────────────────────────────────────────
    # Destroy any ordering effect introduced by source concatenation.
    idx  = rng.permutation(len(y))
    X, y = X[idx], y[idx]

    # ── Stage 8: Save intermediate CSV ───────────────────────────────
    out_df          = pd.DataFrame(X, columns=FEATURE_NAMES)
    out_df["label"] = y
    out_df.to_csv(output_csv, index=False)
    log.info(
        "Feature dataset saved → '%s'  (%d rows × %d columns)",
        output_csv, *out_df.shape,
    )

    log.info("╔══════════════════════════════════════════════════════╗")
    log.info("║  Data pipeline complete.                            ║")
    log.info("║  X shape: %-10s  y shape: %-18s  ║", str(X.shape), str(y.shape))
    log.info("╚══════════════════════════════════════════════════════╝")

    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# Standalone smoke test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("=" * 60)
    log.info("  data_pipeline.py — Standalone Smoke Test")
    log.info("=" * 60)

    # Test each source loader individually
    log.info("\n--- Source 1: PhishTank ---")
    pt = fetch_phishtank()
    log.info("  Shape: %s  |  label dist: %s", pt.shape,
             pt["label"].value_counts().to_dict() if not pt.empty else "empty")

    log.info("\n--- Source 2: URLhaus ---")
    uh = fetch_urlhaus()
    log.info("  Shape: %s  |  label dist: %s", uh.shape,
             uh["label"].value_counts().to_dict() if not uh.empty else "empty")

    log.info("\n--- Source 3: Tranco (1 000-domain sample) ---")
    tr = fetch_tranco(sample_size=1_000)
    log.info("  Shape: %s  |  label dist: %s", tr.shape,
             tr["label"].value_counts().to_dict() if not tr.empty else "empty")

    log.info("\n--- Source 4: ISCX URL 2016 ---")
    ix = load_iscx()
    log.info("  Shape: %s  |  label dist: %s", ix.shape,
             ix["label"].value_counts().to_dict() if not ix.empty else "empty")

    log.info("\n--- Full build_dataset() (500 samples per class) ---")
    X_test, y_test = build_dataset(
        max_malicious=500,
        max_legit=500,
        output_csv="smoke_test_dataset.csv",
    )
    unique, counts = np.unique(y_test, return_counts=True)
    log.info("  X: %s  |  y: %s", X_test.shape,
             dict(zip(["legitimate", "malicious"], counts)))

    log.info("\n[✓] Smoke test complete.  All sources processed.")
