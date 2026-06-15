# PhishGuard 🛡️
### ML-Powered Phishing URL Detection with Cyber Threat Intelligence

PhishGuard is a real-time phishing detection system that combines Machine Learning with active Cyber Threat Intelligence (CTI). It operates as a Chrome browser extension, analyzing URLs on the fly and displaying results on a React-based analyst dashboard.

---

## 📁 Project Structure

```
PhishGuard/
├── 1_ml_pipeline/          # Model training & feature engineering
│   ├── data_pipeline.py    # Dataset loading and preprocessing
│   ├── feature_extractor.py# URL feature extraction (16-dim vector)
│   └── train.py            # Model training (XGBoost / sklearn)
│
├── 2_backend/              # FastAPI REST API
│   ├── main.py             # Core app, /scan and /health endpoints
│   ├── cti_service.py      # VirusTotal, URLhaus, DNS, WHOIS lookups
│   ├── feature_extractor.py# URL feature extraction for inference
│   ├── models.py           # Pydantic request/response schemas
│   ├── phishguard_model.pkl# Serialized trained ML model
│   └── requirements.txt    # Python dependencies
│
├── 3_extension/            # Chrome Browser Extension
│   ├── background.js       # Service worker, URL interception & API calls
│   ├── manifest.json       # Extension config (Manifest V3)
│   ├── warning.html        # Phishing warning page UI
│   └── warning.js          # Warning page logic
│
└── 4_dashboard/            # React Analyst Dashboard
    ├── src/
    │   └── App.jsx         # Main dashboard UI (scan history, charts)
    ├── public/
    ├── package.json
    └── vite.config.js
```

---

## ⚙️ System Architecture

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
│                    ├─ check_virustotal() (aiohttp)       │
│                    └─ check_urlhaus()   (aiohttp)        │
│                           ▼                             │
│              extract_url_features() [16-dim vector]     │
│                           ▼                             │
│              model.predict_proba()  [XGBoost]           │
│                           ▼                             │
│              ScanResponse JSON                          │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Backend API

```bash
cd 2_backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

API docs available at: `http://localhost:8000/docs`

### 2. React Dashboard

```bash
cd 4_dashboard
npm install
npm run dev
```

### 3. Chrome Extension

1. Open Chrome → go to `chrome://extensions/`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked**
4. Select the `3_extension/` folder

---

## 🔌 API Reference

### `POST /scan` — Phishing Detection

**Request:**
```json
{ "url": "https://secure-login-paypa1.tk/verify?account=9912" }
```

**Response:**
```json
{
  "url": "https://secure-login-paypa1.tk/verify?account=9912",
  "is_phishing": true,
  "confidence_score": 0.9312,
  "cti_matches": [
    "VirusTotal: Flagged as malicious by 9/72 AV engines",
    "URLhaus: Active phishing campaign detected",
    "WHOIS: Newly registered domain — only 3 day(s) old ⚠ HIGH RISK"
  ],
  "execution_time_ms": 187.42
}
```

### `GET /health` — Health Check
```json
{ "status": "operational", "model_loaded": true }
```

---

## 🔑 Environment Variables

Create a `.env` file in `2_backend/`:

```
VIRUSTOTAL_API_KEY=your_key_here
```

| Variable | Description |
|----------|-------------|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key |
| `MODEL_PATH` | Path to model file (default: `./phishguard_model.pkl`) |
| `LOG_LEVEL` | `INFO` (default) or `DEBUG` |

---

## 🧠 ML Pipeline

- **Dataset:** PhishTank + Tranco Top 1M + URLhaus + ISCX URL 2016
- **Features:** 16-dimensional URL feature vector (length, special chars, domain age, TLD, entropy, etc.)
- **Model:** XGBoost classifier
- **Target:** ≥95% accuracy, <500ms response time

To retrain the model:
```bash
cd 1_ml_pipeline
python data_pipeline.py   # Prepare dataset
python train.py           # Train and save model
```

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| ML | Python, scikit-learn, XGBoost, Pandas |
| Backend | FastAPI, Python |
| Threat Intel | VirusTotal API, URLhaus API |
| Forensics | python-whois, dnspython |
| Frontend | React, Tailwind CSS, Recharts |
| Extension | JavaScript, Manifest V3 |

---

## 📊 Performance

- All CTI tasks run **concurrently** via `asyncio.gather()`
- Typical total latency: **70–220ms** (well within 500ms target)
- DNS timeout: 3s · WHOIS: 8s · HTTP: 4s

---

## 👥 Mentors

- **Naitik** — 8178596442  
- **Aarsh** — 9520316522
