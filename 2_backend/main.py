"""
PhishGuard API — Main Application
===================================
Real-time phishing URL detection: concurrent CTI enrichment + ML inference.

Architecture
------------

  Chrome Extension / React Dashboard
            │
            ▼  POST /scan  {"url": "..."}
  ┌─────────────────────────────────────┐
  │         FastAPI  (main.py)          │
  │                                     │
  │  1. Parse & validate URL            │
  │  2. asyncio.gather() ──────────────►│──► dns_lookup()       ─┐
  │                                     │──► whois_lookup()      │  concurrent
  │                                     │──► check_virustotal()  │  CTI tasks
  │                                     │──► check_urlhaus()    ─┘
  │  3. extract_url_features()          │
  │  4. model.predict_proba(features)   │
  │  5. consolidate + respond           │
  └─────────────────────────────────────┘
            │
            ▼  ScanResponse JSON

Target end-to-end latency: < 500 ms

Run
---
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Docs (auto-generated)
---------------------
    http://localhost:8000/docs   (Swagger UI)
    http://localhost:8000/redoc  (ReDoc)

Python ≥ 3.9 required.
"""

from models import HealthResponse, ScanRequest, ScanResponse
from cti_service import check_urlhaus, check_virustotal, dns_lookup, whois_lookup
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi import FastAPI, HTTPException, Request, status
import asyncio
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List
from urllib.parse import urlparse
from feature_extractor import URLFeatureExtractor
extractor = URLFeatureExtractor()


# ---------------------------------------------------------------------------
# Logging — structured format makes it easy to ingest into Datadog / Loki
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("phishguard.main")


# ===========================================================================
# Mock ML Model
# ===========================================================================


class MockPhishGuardModel:
    """
    Pure Python stand-in for the ML model.
    Uses 24 features to match your feature_extractor.py without needing scikit-learn.
    """

    def predict_proba(self, X: list) -> list:
        features = X[0]

        # Feature indices: 0=url_length, 7=count_at, 14=has_login, 20=is_ip_address, 22=tld_risk_score
        score = (
            min(features[0] / 600.0, 0.25)   # Long URL -> suspicious
            + (features[7] * 0.35)           # @ symbol is a red flag
            + (features[20] * 0.40)          # IP address hostname
            + (features[22] * 0.30)          # Suspicious TLD
            + (features[14] * 0.20)          # 'login' keyword in URL
        )

        # Calculate probability between 0.01 and 0.99
        p_phish = max(0.01, min(score, 0.99))

        # Return probability list (Pure Python, no numpy/joblib required)
        return [[1.0 - p_phish, p_phish]]


# ---------------------------------------------------------------------------
# Application State
# ---------------------------------------------------------------------------
_state: dict = {}
recent_scans = []

# ===========================================================================
# Application Lifespan
# ===========================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀  PhishGuard API — starting up")

    try:
        # Using pure Python Mock Model to bypass Windows Strict DLL Policies
        _state["model"] = MockPhishGuardModel()
        logger.info("✅  Mock ML model initialised successfully!")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")

    _state["start_time"] = time.monotonic()

    yield  # ← Application serves requests here

    logger.info("🛑  PhishGuard API — shutting down")
    _state.clear()


'''
class MockPhishGuardModel:
    def predict_proba(self, X: list) -> list:
        # Hum 24-feature vector use kar rahe hain
        features = X[0]
        
        # Feature indices: 0=url_length, 7=count_at, 14=has_login, 20=is_ip_address, 22=tld_risk_score
        score = (
            min(features[0] / 600.0, 0.25)   # Long URL
            + (features[7] * 0.35)           # @ symbol
            + (features[20] * 0.40)          # IP address hostname
            + (features[22] * 0.30)          # Suspicious TLD
            + (features[14] * 0.20)          # 'login' keyword in URL
        )
        
        # Calculate probability between 0.01 and 0.99
        p_phish = max(0.01, min(score, 0.99))
        
        # Return probability list (Pure Python, no numpy/DLL required)
        return [[1.0 - p_phish, p_phish]]

class MockPhishGuardModel:
    """
    Heuristic stand-in for a real scikit-learn / XGBoost phishing classifier.

    ╔══════════════════════════════════════════════════════════════════════╗
    ║  HOW TO SWAP IN YOUR REAL TRAINED MODEL                             ║
    ║                                                                      ║
    ║  Step 1 — Persist your trained model once after training:           ║
    ║      import joblib                                                   ║
    ║      joblib.dump(trained_pipeline, "phishguard_model.pkl")          ║
    ║                                                                      ║
    ║  Step 2 — In the `lifespan()` function below, replace:              ║
    ║      _state["model"] = MockPhishGuardModel()                        ║
    ║  with:                                                               ║
    ║      import joblib                                                   ║
    ║      _state["model"] = joblib.load("phishguard_model.pkl")          ║
    ║                                                                      ║
    ║  Step 3 — The /scan endpoint calls:                                  ║
    ║      probs = model.predict_proba(feature_array)                     ║
    ║      p_phish = float(probs[0][1])   # P(class=phishing)             ║
    ║  This is the standard sklearn API — it works identically for        ║
    ║  RandomForestClassifier, GradientBoostingClassifier, XGBClassifier, ║
    ║  LogisticRegression, and any pipeline wrapping them.                ║
    ║                                                                      ║
    ║  Step 4 — Ensure extract_url_features() (below) produces features  ║
    ║  in the EXACT same order and normalisation used during training.    ║
    ║  Version-control the feature extractor alongside the .pkl file.     ║
    ║                                                                      ║
    ║  For TensorFlow / PyTorch models, wrap model.predict() / forward()  ║
    ║  in a thin adapter that returns [[p_clean, p_phish]].               ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """

    # Feature indices used by the heuristic score — must mirror extract_url_features()
    _IDX_URL_LEN = 0
    _IDX_HAS_AT = 3
    _IDX_IS_IP = 10
    _IDX_SUS_TLD = 13
    _IDX_BRAND = 14

    def predict_proba(self, X: List[List[float]]) -> np.ndarray:
        """
        Return [[P(clean), P(phishing)]] for each row in X.

        The heuristic below mimics what a real model *should* learn from data:
          • URL length correlates with obfuscation attempts.
          • @ symbol in URL is a classic phishing trick (user:pass@realsite.com).
          • IP address as hostname bypasses brand/domain defences.
          • Free / suspicious TLDs (.tk, .ml, .ga …) are heavily phishing-abused.
          • Brand keyword in URL signals spoofing intent.

        NOTE: In production this method body is replaced entirely by the
              joblib-loaded model — see class docstring.
        """
        features = np.asarray(X[0], dtype=float)

        # Weighted suspicion score capped at [0.01, 0.99]
        score: float = (
            # Long URL → suspicious
            min(features[self._IDX_URL_LEN] / 600.0, 0.25)
            # @ symbol is a red flag
            + features[self._IDX_HAS_AT] * 0.35
            # IP hostname = major flag
            + features[self._IDX_IS_IP] * 0.40
            + features[self._IDX_SUS_TLD] * 0.30              # Suspicious TLD
            # Brand spoofing attempt
            + features[self._IDX_BRAND] * 0.20
        )
        p_phish = float(np.clip(score, 0.01, 0.99))
        return np.array([[1.0 - p_phish, p_phish]])


# ---------------------------------------------------------------------------
# Application State — populated during startup, cleaned on shutdown
# ---------------------------------------------------------------------------
_state: Dict[str, Any] = {}


# ===========================================================================
# Application Lifespan
# ===========================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan handler — runs startup code before yield, shutdown after.

    Startup:  Load ML model into _state so it is shared across all requests
              without re-loading per request (expensive for large models).
    Shutdown: Release resources.
    """
    logger.info("🚀  PhishGuard API — starting up")

    # ── Model Loading ────────────────────────────────────────────────────
    #
    # PRODUCTION: replace the two lines below with:
    #
    #   import joblib
    #   _state["model"] = joblib.load("phishguard_model.pkl")
    #   logger.info("✅  ML model loaded from phishguard_model.pkl")
    #
    # The try/except below handles the case where the model file is missing
    # (e.g. first-run without a trained model) — falls back to the mock.
    try:
        # Uncomment the joblib.load() block above for production use.
        _state["model"] = joblib.load("phishguard_model.pkl")
        logger.info(
            "✅  Mock ML model initialised  (swap with joblib.load() for production)")
    except FileNotFoundError:
        logger.warning(
            "⚠️   phishguard_model.pkl not found — using mock model")
        _state["model"] = joblib.load("phishguard_model.pkl")

    _state["start_time"] = time.monotonic()

    yield  # ← Application serves requests here

    logger.info("🛑  PhishGuard API — shutting down")
    _state.clear()
'''

# ===========================================================================
# FastAPI Application
# ===========================================================================

app = FastAPI(
    title="PhishGuard API",
    description=(
        "Real-time phishing URL detection — "
        "concurrent CTI enrichment + ML inference in < 500 ms.\n\n"
        "Integrates with Chrome Extensions and React dashboards via CORS."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ===========================================================================
# Middleware
# ===========================================================================

# ---------------------------------------------------------------------------
# 1. CORS Middleware
# ---------------------------------------------------------------------------
# allow_origins=["*"] is intentional for Chrome Extension compatibility.
#
# Chrome extensions run from chrome-extension://<extension-id> origins which
# vary per installation and cannot be enumerated in advance.  React dashboards
# in development use http://localhost:3000.  Rather than maintain an allowlist,
# we permit all origins at the API boundary and rely on the Chrome Extension
# Manifest v3 permissions model for client-side origin enforcement.
#
# PRODUCTION hardening: restrict allow_origins to known domains if the API
# is also consumed by a web app with a fixed origin.
app.add_middleware(
    CORSMiddleware,
    # All origins — required for Chrome Extension
    allow_origins=["*"],
    allow_credentials=True,
    # OPTIONS is essential for preflight requests
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    max_age=600,                              # Cache preflight responses for 10 minutes
)

# ---------------------------------------------------------------------------
# 2. Global Error-Handling Middleware
# ---------------------------------------------------------------------------


@app.middleware("http")
async def global_error_middleware(request: Request, call_next):
    """
    Catch-all safety net for request-level errors that escape endpoint handlers.

    Specifically guards against:
    • UnicodeDecodeError  — malformed UTF-8 in multipart or raw request bodies.
    • RuntimeError / other uncaught exceptions — prevents 500 stack traces leaking
      to the client in production.

    NOTE: Pydantic validation errors (malformed JSON body, wrong field types) are
    caught by the RequestValidationError handler registered below — they never
    reach this middleware.
    """
    try:
        response = await call_next(request)
        return response

    except UnicodeDecodeError as exc:
        logger.warning(
            "Malformed UTF-8 in request body | path=%s | client=%s",
            request.url.path,
            request.client,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "Bad Request",
                "detail": "Request body contains invalid byte encoding. "
                          "Ensure the body is valid UTF-8 JSON.",
            },
        )

    except Exception as exc:
        logger.exception(
            "Unhandled exception | path=%s | error=%s", request.url.path, exc
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "detail": "An unexpected error occurred. "
                          "The incident has been logged.",
            },
        )


# ===========================================================================
# Exception Handlers
# ===========================================================================

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """
    Return a clean 422 for:
    • Malformed JSON body (missing braces, trailing commas, etc.)
    • Missing required fields
    • Field type mismatches (number where string expected, etc.)
    • Custom @field_validator failures (e.g. missing http:// scheme)
    """
    logger.debug(
        "Validation error | path=%s | errors=%s",
        request.url.path,
        exc.errors(),
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "detail": exc.errors(),
            "hint": 'Send JSON body: {"url": "https://example.com"}',
        },
    )


@app.exception_handler(json.JSONDecodeError)
async def json_error_handler(request: Request, exc: json.JSONDecodeError):
    """Catch raw JSON decode errors that bypass Pydantic (e.g. plain text body)."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "Bad Request",
            "detail": f"Malformed JSON at position {exc.pos}: {exc.msg}",
        },
    )


# ===========================================================================
# URL Feature Extraction
# ===========================================================================

def extract_url_features(url: str, parsed) -> List[float]:
    """
    Encode a URL into a 16-dimensional numeric feature vector for the ML model.

    ⚠️  CRITICAL FOR PRODUCTION:
    ════════════════════════════
    This function MUST produce features in the EXACT same order, data type,
    and normalisation/scaling that was used during model training.
    Any mismatch silently degrades accuracy (no exception is raised).

    Checklist when upgrading the model:
    [1] Run the same feature extractor on new training data.
    [2] If you add/remove features, retrain the model from scratch.
    [3] If you add StandardScaler/MinMaxScaler, apply the fitted scaler here too.
    [4] Bump MODEL_VERSION and version-control this function with the .pkl file.

    Feature index reference
    -----------------------
     [0]  url_length          Total character count of the raw URL
     [1]  dot_count           Number of '.' in the full URL
     [2]  hyphen_count        Number of '-' (excess hyphens = obfuscation)
     [3]  has_at_symbol       1 if '@' present  (user:pass@realsite.com trick)
     [4]  double_slash_path   1 if '//' in URL path  (redirect obfuscation)
     [5]  query_param_count   Number of '?' characters
     [6]  equals_count        Number of '=' characters
     [7]  pct_encoding_count  Number of '%' chars  (URL encoding to hide payload)
     [8]  hostname_length     Length of the netloc component
     [9]  path_length         Length of the path component
    [10]  is_ip_hostname      1 if hostname is a raw IPv4 address
    [11]  is_https            1 if scheme is 'https'  (HTTPS ≠ safe!)
    [12]  subdomain_depth     Number of '.' in hostname  (deep subdomains = suspicious)
    [13]  suspicious_tld      1 if TLD is a commonly abused free/cheap TLD
    [14]  brand_keyword       1 if a recognisable brand name is spoofed in the URL
    [15]  digit_count_host    Count of digit chars in hostname
    """
    hostname: str = (parsed.netloc or "").lower()
    path: str = (parsed.path or "").lower()

    SUSPICIOUS_TLDS: frozenset[str] = frozenset({
        ".tk", ".ml", ".ga", ".cf", ".gq",       # Freenom (heavily abused)
        ".xyz", ".top", ".pw", ".cc", ".su",       # Other commonly abused TLDs
    })

    BRAND_KEYWORDS: frozenset[str] = frozenset({
        "paypal", "amazon", "google", "microsoft", "apple",
        "facebook", "instagram", "netflix", "bank", "chase",
        "wellsfargo", "dropbox", "onedrive", "icloud", "linkedin",
    })

    return [
        # [0]
        float(len(url)),
        # [1]
        float(url.count(".")),
        # [2]
        float(url.count("-")),
        # [3]
        1.0 if "@" in url else 0.0,
        # [4]
        1.0 if "//" in path else 0.0,
        # [5]
        float(url.count("?")),
        # [6]
        float(url.count("=")),
        # [7]
        float(url.count("%")),
        # [8]
        float(len(hostname)),
        # [9]
        float(len(path)),
        1.0 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$",
                        hostname) else 0.0,            # [10]
        # [11]
        1.0 if parsed.scheme == "https" else 0.0,
        # [12]
        float(hostname.count(".")),
        1.0 if any(hostname.endswith(t)
                   for t in SUSPICIOUS_TLDS) else 0.0,         # [13]
        1.0 if any(b in url.lower()
                   for b in BRAND_KEYWORDS) else 0.0,             # [14]
        float(sum(c.isdigit() for c in hostname)
              ),                                   # [15]
    ]


# ===========================================================================
# API Endpoints
# ===========================================================================

@app.get("/", include_in_schema=False)
async def root():
    """Minimal root response — redirects clients to /docs."""
    return {
        "service": "PhishGuard API",
        "status": "operational",
        "docs": "/docs",
        "scan_endpoint": "POST /scan",
    }


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Meta"],
    summary="Liveness probe",
)
async def health_check():
    """
    Returns model load status and API uptime.
    Use this endpoint for Kubernetes liveness/readiness probes.
    """
    uptime = time.monotonic() - _state.get("start_time", time.monotonic())
    model_loaded = _state.get("model") is not None
    return HealthResponse(
        status="operational" if model_loaded else "degraded",
        version="1.0.0-mock",          # Change to "1.0.0" when using real model
        model_loaded=model_loaded,
        uptime_seconds=round(uptime, 2),
    )


@app.get("/scans")
async def get_scans():
    return recent_scans[:100]


@app.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    tags=["Detection"],
    summary="Scan a URL for phishing indicators",
    response_description="Consolidated threat intelligence report",
    responses={
        422: {"description": "Invalid URL format or missing body field"},
        503: {"description": "ML model not loaded"},
    },
)
async def scan_url(payload: ScanRequest, request: Request):
    """
    ## Real-time Phishing URL Scanner

    Accepts a URL and returns a consolidated threat report in < 500 ms.

    ### Processing Pipeline

    ```
    1. Parse URL              → extract hostname, scheme, path
    2. asyncio.gather()       → run all CTI tasks concurrently
       ├─ dns_lookup()        → passive A/AAAA DNS resolution
       ├─ whois_lookup()      → domain age & registrar (async thread)
       ├─ check_virustotal()  → multi-AV engine verdict (stub)
       └─ check_urlhaus()     → active malware feed lookup (stub)
    3. extract_url_features() → 16-dim numeric feature vector
    4. model.predict_proba()  → ML confidence score
    5. blend CTI + ML signals → final is_phishing determination
    ```

    ### Response Fields

    | Field              | Description                                        |
    |--------------------|---------------------------------------------------|
    | `is_phishing`      | `true` when confidence_score ≥ 0.50               |
    | `confidence_score` | Probability from ML model (0.0 = clean, 1.0 = bad)|
    | `cti_matches`      | Human-readable CTI findings (empty = nothing found)|
    | `execution_time_ms`| Server wall-clock time for the full scan           |
    """
    request_start: float = time.monotonic()
    url: str = payload.url

    # ── Step 1: Parse URL ─────────────────────────────────────────────────
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            raise ValueError("No hostname could be extracted from this URL.")
        hostname: str = parsed.hostname.lower()
        # Strip www. to get the apex/registerable domain for WHOIS
        domain: str = hostname.removeprefix("www.")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    logger.info("→ SCAN  url=%.80s  host=%s", url, hostname)

    # ── Step 2: Concurrent CTI Gathering ──────────────────────────────────
    #
    # asyncio.gather() dispatches all four coroutines simultaneously on the
    # event loop.  Because all CTI functions are async (DNS uses
    # dns.asyncresolver; WHOIS runs in a thread via asyncio.to_thread();
    # the stubs just await a short sleep), none block the event loop and all
    # four run in true concurrency — not sequentially.
    #
    # return_exceptions=True: if one CTI source times out or throws, it is
    # returned as an Exception object in the results tuple rather than
    # propagating and cancelling the other tasks.  The _safe() helper below
    # replaces any exception with a benign fallback dict.
    cti_results = await asyncio.gather(
        dns_lookup(hostname),
        whois_lookup(domain),
        check_virustotal(url),
        check_urlhaus(url),
        return_exceptions=True,
    )

    def _safe(result: Any, source: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
        """Replace exceptions from gather() with a safe default dict."""
        if isinstance(result, BaseException):
            logger.warning("CTI '%s' failed: %s: %s", source,
                           type(result).__name__, result)
            return fallback
        return result

    dns_data = _safe(cti_results[0], "dns_lookup",
                     {"a_records": [], "aaaa_records": [], "error": "service error"})
    whois_data = _safe(cti_results[1], "whois_lookup",
                       {"domain_age_days": None, "error": "service error"})
    vt_data = _safe(cti_results[2], "check_virustotal",
                    {"flagged": False, "status": "error", "source": "VirusTotal"})
    urlhaus_data = _safe(cti_results[3], "check_urlhaus",
                         {"flagged": False, "status": "error", "source": "URLhaus"})

    # ── Step 3: Build CTI Matches List ───────────────────────────────────
    #
    # Convert raw CTI data into human-readable finding strings.
    # These are surfaced directly to the end user in the threat report.
    cti_matches: List[str] = []

    # VirusTotal signal
    if vt_data.get("flagged"):
        engines = vt_data.get("malicious_engines", "?")
        total = vt_data.get("total_engines", "?")
        cti_matches.append(
            f"VirusTotal: Flagged as malicious by {engines}/{total} AV engines"
        )

    # URLhaus signal
    if urlhaus_data.get("flagged"):
        threat = urlhaus_data.get("threat_type") or "malware distribution"
        cti_matches.append(f"URLhaus: Active {threat} campaign detected")

    # WHOIS domain age signal
    age_days = whois_data.get("domain_age_days")
    if age_days is not None:
        if age_days < 30:
            cti_matches.append(
                f"WHOIS: Newly registered domain — only {age_days} day(s) old  ⚠ HIGH RISK"
            )
        elif age_days < 90:
            cti_matches.append(
                f"WHOIS: Recently registered domain — {age_days} days old  ⚠ ELEVATED RISK"
            )

    # DNS anomaly signals
    a_records: List[str] = dns_data.get("a_records", [])
    if not a_records and not dns_data.get("error"):
        cti_matches.append(
            "DNS: No A records found — possible domain squatting")
    for ip in a_records:
        if ip.startswith(("192.168.", "10.", "172.16.", "172.17.")):
            cti_matches.append(
                f"DNS: Hostname resolves to private IP {ip} — possible DNS poisoning"
            )

    # ── Step 4: Feature Extraction ────────────────────────────────────────
    features: List[float] = extractor.extract_vector(url)
    # sklearn models expect a 2-D array: [[f0, f1, …, f15]]
    feature_array: List[List[float]] = [features]

    # ── Step 4b: ML Inference ─────────────────────────────────────────────
    #
    # PRODUCTION SWAP POINT
    # ─────────────────────
    # The SINGLE line below is identical for the mock AND the real model:
    #
    #   probabilities = model.predict_proba(feature_array)
    #   p_phishing    = float(probabilities[0][1])
    #
    # When you swap MockPhishGuardModel for a real joblib-loaded model in
    # the lifespan() function, this block requires ZERO changes.
    # The sklearn predict_proba() contract is:
    #   • Input:  List[List[float]]  shape (n_samples, n_features)
    #   • Output: np.ndarray         shape (n_samples, n_classes)
    #             column 0 → P(clean), column 1 → P(phishing)
    # ──────────────────────────────────────────────────────────────────────
    model = _state.get("model")
    if model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML model is not loaded.  Check server startup logs.",
        )

    probabilities = model.predict_proba(feature_array)
    p_phishing: float = float(probabilities[0][1])

    # ── Step 5: Blend CTI + ML Signals ───────────────────────────────────
    #
    # Conservative upward correction: if the CTI layer raised flags but the
    # model's score sits below the decision boundary, nudge the score upward.
    # This reflects the real-world truth that blocklist presence is a very
    # strong signal even when URL structure looks benign.
    #
    # In a mature production system, CTI features should be encoded into the
    # training data so the model learns this weighting automatically — remove
    # this manual correction once that is done.
    if cti_matches and p_phishing < 0.5:
        boost = min(len(cti_matches) * 0.10, 0.30)
        p_phishing = min(p_phishing + boost, 0.97)
        logger.debug(
            "CTI boost applied: +%.2f → p_phishing=%.4f", boost, p_phishing
        )

    is_phishing: bool = p_phishing >= 0.50
    confidence_score: float = round(p_phishing, 4)

    # ── Step 6: Execution Time ────────────────────────────────────────────
    execution_time_ms: float = round(
        (time.monotonic() - request_start) * 1000, 2)

    logger.info(
        "← DONE  is_phishing=%-5s  confidence=%.4f  cti=%d  time=%.2fms  url=%.60s",
        is_phishing,
        confidence_score,
        len(cti_matches),
        execution_time_ms,
        url,
    )

    # Warn if we're approaching the 500 ms SLA
    if execution_time_ms > 400:
        logger.warning(
            "⏱  Scan approaching latency SLA: %.2fms for %s", execution_time_ms, hostname
        )

    recent_scans.insert(0, {
        "id": int(time.time()),
        "url": url,
        "status": "Malicious" if is_phishing else "Clean",
        "threatLevel": "High" if is_phishing else "Low",
        "confidence": confidence_score * 100,
        "category": "ML Detection" if is_phishing else "Legitimate",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })
    if len(recent_scans) > 100:
        recent_scans.pop()

    return ScanResponse(
        url=url,
        is_phishing=is_phishing,
        confidence_score=confidence_score,
        cti_matches=cti_matches,
        execution_time_ms=execution_time_ms,
    )
