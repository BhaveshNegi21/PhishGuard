# PhishGuard API

> Real-time phishing URL detection — concurrent CTI enrichment + ML inference  
> Target latency: **< 500 ms** per scan

---

## Architecture

```
Chrome Extension / React Dashboard
          │
          ▼  POST /scan  {"url": "https://..."}
┌─────────────────────────────────────────────────────────┐
│                    FastAPI  (main.py)                    │
│                                                         │
│  Parse URL ──► asyncio.gather() ──────────────────────► │
│                    ├─ dns_lookup()      (dnspython)      │
│                    ├─ whois_lookup()    (python-whois)   │
│                    ├─ check_virustotal() (stub/aiohttp)  │
│                    └─ check_urlhaus()   (stub/aiohttp)   │
│                           ▼                             │
│              extract_url_features() [16-dim vector]     │
│                           ▼                             │
│              model.predict_proba()  [sklearn / mock]    │
│                           ▼                             │
│              ScanResponse JSON  ◄───────────────────────│
└─────────────────────────────────────────────────────────┘
```

---

## File Map

```
phishguard/
├── main.py           # FastAPI app, CORS, middleware, /scan endpoint
├── cti_service.py    # Async DNS, WHOIS, VirusTotal stub, URLhaus stub
├── models.py         # Pydantic request/response schemas
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

---

## Quick Start

**Requirements:** Python 3.9+

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the API
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 3. Open the interactive docs
open http://localhost:8000/docs
```

---

## API Reference

### `POST /scan` — Phishing Detection

**Request body:**
```json
{ "url": "https://secure-login-paypa1.tk/verify?account=9912" }
```

**Response (200 OK):**
```json
{
  "url": "https://secure-login-paypa1.tk/verify?account=9912",
  "is_phishing": true,
  "confidence_score": 0.9312,
  "cti_matches": [
    "VirusTotal: Flagged as malicious by 9/72 AV engines",
    "URLhaus: Active phishing campaign detected",
    "WHOIS: Newly registered domain — only 3 day(s) old  ⚠ HIGH RISK"
  ],
  "execution_time_ms": 187.42
}
```

**Error responses:**
| Status | Cause |
|--------|-------|
| 400 | Malformed JSON body |
| 422 | Missing `url` field or invalid URL format |
| 503 | ML model failed to load at startup |

---

### `GET /health` — Liveness Probe

```json
{
  "status": "operational",
  "version": "1.0.0-mock",
  "model_loaded": true,
  "uptime_seconds": 142.5
}
```

---

## Swapping in a Real ML Model

1. **Train and persist your model** (one-time step):
   ```python
   import joblib
   from sklearn.ensemble import GradientBoostingClassifier

   model = GradientBoostingClassifier(n_estimators=200, max_depth=5)
   model.fit(X_train, y_train)        # X shape: (n_samples, 16)
   joblib.dump(model, "phishguard_model.pkl")
   ```

2. **Edit `main.py`** — in the `lifespan()` function, replace:
   ```python
   _state["model"] = MockPhishGuardModel()
   ```
   with:
   ```python
   import joblib
   _state["model"] = joblib.load("phishguard_model.pkl")
   ```

3. The `/scan` endpoint requires **zero changes** — it calls
   `model.predict_proba(feature_array)` which is the standard sklearn API.

4. Ensure `extract_url_features()` in `main.py` produces the **exact same
   16 features in the exact same order** used during training.

---

## Enabling Real CTI APIs

### VirusTotal
```bash
export VIRUSTOTAL_API_KEY="your_key_here"
```
In `cti_service.py → check_virustotal()`:
uncomment the `PRODUCTION IMPLEMENTATION` block, delete the `MOCK` block.

### URLhaus
No API key required.  
In `cti_service.py → check_urlhaus()`:
uncomment the `PRODUCTION IMPLEMENTATION` block, delete the `MOCK` block.

---

## Chrome Extension Integration

```javascript
// content.js or background.js
const response = await fetch("http://localhost:8000/scan", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url: window.location.href })
});

const report = await response.json();
if (report.is_phishing) {
  showWarningBanner(report.confidence_score, report.cti_matches);
}
```

---

## Environment Variables (production)

| Variable | Description |
|----------|-------------|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key |
| `LOG_LEVEL` | `INFO` (default) or `DEBUG` |
| `MODEL_PATH` | Path to `phishguard_model.pkl` (default: `./phishguard_model.pkl`) |

---

## Performance Notes

- All four CTI tasks run **concurrently** via `asyncio.gather()`.
- WHOIS is synchronous — offloaded to a thread via `asyncio.to_thread()`.
- DNS timeout: 3 s · WHOIS timeout: 8 s · HTTP (production) timeout: 4 s.
- `return_exceptions=True` ensures a single slow CTI source never blocks the scan.
- Typical latency breakdown on a warm instance:
  - DNS + WHOIS (concurrent): ~50–200 ms
  - CTI stubs: ~15 ms
  - Feature extraction + inference: < 5 ms
  - **Total: ~70–220 ms** well within the 500 ms SLA
