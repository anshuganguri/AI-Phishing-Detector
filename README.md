# 🛡️ AI Phishing Detector

A full-stack AI-powered web application that detects phishing URLs in real time using machine learning (Random Forest + XGBoost ensemble) combined with NLP-based URL pattern analysis.

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Theory Behind Phishing Detection](#theory-behind-phishing-detection)
3. [ML Algorithms Explanation](#ml-algorithms-explanation)
4. [NLP Logic Explanation](#nlp-logic-explanation)
5. [Feature Extraction Explanation](#feature-extraction-explanation)
6. [Folder Structure](#folder-structure)
7. [Installation & Setup](#installation--setup)
8. [How to Run](#how-to-run)
9. [API Documentation](#api-documentation)
10. [Future Improvements](#future-improvements)

---

## Project Overview

**AI Phishing Detector** analyses URLs submitted by the user and predicts whether they are:

- ✅ **Legitimate** – the URL appears genuine
- 🚨 **Phishing** – the URL exhibits characteristics common in phishing attacks

The system extracts 28+ hand-crafted URL features (length, dots, hyphens, suspicious keywords, HTTPS usage, subdomains, etc.) and combines them with TF-IDF character n-gram features extracted from the raw URL string. A Random Forest and XGBoost ensemble is trained on a labelled dataset and exposed via a Flask REST API. A React + Vite frontend provides a polished dashboard UI.

**Key Features**

| Feature | Description |
|---|---|
| URL Analysis | 28+ structural features extracted per URL |
| NLP Pattern Analysis | TF-IDF character 2–4 grams on raw URL text |
| Dual Model Ensemble | Random Forest + XGBoost soft-voting |
| Confidence Score | Probability output (0–100%) |
| Risk Level | SAFE / LOW / MEDIUM / HIGH |
| Risk Factors | Human-readable explanation of red flags |
| Scan History | In-memory table of all scanned URLs |
| Real-time API | React ↔ Flask communication via Axios |

---

## Theory Behind Phishing Detection

Phishing is a cyberattack where adversaries create fraudulent URLs that mimic legitimate websites (banks, social networks, e-commerce) to steal credentials or personal data.

**Common phishing URL patterns:**
- Typosquatting: replacing letters with digits (`paypa1.com`, `g00gle.com`)
- Brand names embedded in subdomains or paths (`paypal.secure-login.xyz`)
- Suspicious TLDs: `.xyz`, `.info`, `.top`, `.online`
- HTTP instead of HTTPS (no encryption)
- IP-address hostnames rather than domain names
- Excessively long URLs packed with query parameters
- High keyword density: `login`, `verify`, `secure`, `account`

Machine learning approaches these as a classification problem: given a feature vector derived from a URL, predict `0` (legitimate) or `1` (phishing).

---

## ML Algorithms Explanation

### Random Forest Classifier

A Random Forest builds many decision trees on random subsets of training data (bootstrap sampling) and random subsets of features at each split (feature bagging). Final prediction is a majority vote (classification) or average (regression).

**Advantages for URL detection:**
- Robust to noisy/irrelevant features
- Handles mixed numeric and binary features well
- Provides feature importance scores
- Resistant to overfitting due to ensemble averaging

### XGBoost Classifier

XGBoost (Extreme Gradient Boosting) builds trees sequentially, where each tree corrects the errors of the previous ensemble using gradient descent on a differentiable loss function. It adds L1/L2 regularisation to control overfitting.

**Advantages for URL detection:**
- Excellent performance on structured/tabular data
- Handles class imbalance via `scale_pos_weight`
- Fast training with parallel tree construction

### Soft-Voting Ensemble

The final predictor is a `VotingClassifier(voting='soft')` that averages the class probability estimates from RF and XGBoost. Averaging probabilities (soft voting) consistently outperforms hard majority voting.

---

## NLP Logic Explanation

Raw URLs contain rich linguistic patterns that lexical/structural features alone do not capture. We apply **TF-IDF** (Term Frequency–Inverse Document Frequency) vectorisation with **character-level n-grams** (`analyzer='char_wb'`, `ngram_range=(2,4)`).

**Why character n-grams?**
- They capture sub-word patterns: `pay`, `pal`, `ayp` from `paypal`
- They detect obfuscation: `paypa1` produces different 3-grams than `paypal`
- They are language-agnostic and tokenisation-free

**TF-IDF weighting (`sublinear_tf=True`):**
- TF (term frequency): how often the n-gram appears in this URL
- IDF (inverse document frequency): penalises n-grams common across all URLs
- Sublinear scaling (`1 + log(tf)`) reduces dominance of highly repeated tokens

The TF-IDF matrix (3000 features) is **horizontally stacked** with the 28 hand-crafted features using `scipy.sparse.hstack`, giving the model both structural and lexical signals.

---

## Feature Extraction Explanation

Implemented in `backend/utils/feature_extractor.py`:

| Feature | Description |
|---|---|
| `url_length` | Total character count of the URL |
| `hostname_length` | Length of the hostname portion |
| `path_length` | Length of the URL path |
| `num_dots` | Count of `.` characters |
| `num_hyphens` | Count of `-` characters |
| `num_underscores` | Count of `_` characters |
| `num_slashes` | Count of `/` characters |
| `num_question_marks` | Count of `?` characters |
| `num_ampersands` | Count of `&` characters |
| `num_equals` | Count of `=` characters |
| `num_percent` | Count of `%` (URL-encoded chars) |
| `has_at_symbol` | Binary: `@` present |
| `has_double_slash` | Binary: `//` in path |
| `has_ip_address` | Binary: hostname is an IP address |
| `is_https` | Binary: uses HTTPS |
| `digit_count` | Total digits in URL |
| `digit_ratio` | Ratio of digits to URL length |
| `subdomain_count` | Number of subdomain levels beyond root domain |
| `has_subdomain` | Binary: any subdomain present |
| `suspicious_keyword_count` | Count of known phishing keywords |
| `has_suspicious_keyword` | Binary: any suspicious keyword |
| `has_digit_substitution` | Binary: detected letter-digit typosquatting |
| `url_entropy` | Shannon entropy of URL string |
| `has_suspicious_tld` | Binary: TLD in suspicious list |
| `query_length` | Length of query string |
| `num_query_params` | Number of query parameters |
| `brand_in_hostname` | Binary: brand name appears in hostname |
| `brand_in_path` | Binary: brand name appears in path |

---

## Folder Structure

```
AI-Phishing-Detector/
│
├── backend/
│   ├── app.py                   # Flask REST API (main entry point)
│   ├── train_model.py           # Model training script
│   ├── requirements.txt         # Python dependencies
│   ├── data/
│   │   └── urls.csv             # Labelled URL dataset
│   ├── models/                  # Auto-generated model artefacts
│   │   ├── phishing_model.pkl
│   │   ├── tfidf_vectorizer.pkl
│   │   ├── scaler.pkl
│   │   └── model_meta.pkl
│   └── utils/
│       ├── __init__.py
│       └── feature_extractor.py # URL feature extraction logic
│
├── frontend/
│   ├── index.html               # Vite root HTML
│   ├── package.json             # npm dependencies
│   ├── vite.config.js           # Vite configuration
│   └── src/
│       ├── main.jsx             # React entry point
│       ├── App.jsx              # Root component + routing
│       ├── components/
│       │   ├── Header.jsx       # Navigation header
│       │   └── ResultCard.jsx   # Prediction result display
│       ├── pages/
│       │   ├── Home.jsx         # Scanner page
│       │   └── History.jsx      # Scan history page
│       ├── services/
│       │   └── api.js           # Axios API client
│       └── styles/
│           ├── global.css       # CSS variables + reset
│           ├── Header.css
│           └── Home.css
│           └── History.css
│
├── README.md
└── .gitignore
```

---

## Installation & Setup

### Prerequisites

- Python 3.11 or 3.12
- Node.js 18+ and npm 9+

### Backend Setup

```bash
# 1. Navigate to backend
cd AI-Phishing-Detector/backend

# 2. Create a virtual environment (recommended)
python -m venv venv

# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Train the model (generates models/ folder)
python train_model.py
```

### Frontend Setup

```bash
# In a new terminal
cd AI-Phishing-Detector/frontend

# Install npm packages
npm install
```

---

## How to Run

### Start the Backend (Terminal 1)

```bash
cd AI-Phishing-Detector/backend
# Activate venv if not already active
python app.py
```

Flask will start at **http://localhost:5000**

### Start the Frontend (Terminal 2)

```bash
cd AI-Phishing-Detector/frontend
npm run dev
```

Vite dev server starts at **http://localhost:3000**

Open **http://localhost:3000** in your browser.

---

## API Documentation

### `POST /predict`

Analyse a URL for phishing.

**Request**
```json
{ "url": "https://example.com" }
```

**Response**
```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "label": "Legitimate",
  "confidence": 0.9723,
  "phishing_prob": 0.0277,
  "legitimate_prob": 0.9723,
  "risk_level": "SAFE",
  "risk_factors": [],
  "features": {
    "url_length": 19,
    "num_dots": 2,
    "is_https": 1,
    "suspicious_keyword_count": 0
  },
  "timestamp": "2024-01-01T12:00:00"
}
```

---

### `GET /history?limit=50`

Returns up to `limit` recent scan results (newest first).

**Response**: Array of prediction objects (same schema as `/predict`).

---

### `DELETE /history`

Clears all in-memory scan history.

---

### `GET /health`

```json
{ "status": "ok", "model": "loaded", "version": "1.0.0" }
```

---

### `GET /stats`

```json
{
  "total_scanned": 42,
  "phishing": 17,
  "legitimate": 25,
  "model_info": {
    "test_accuracy": 0.9545,
    "test_roc_auc": 0.9912,
    "xgboost_used": true,
    "train_samples": 88
  }
}
```

---

## Future Improvements

1. **WHOIS / DNS lookup** – query domain registration age and registrar reputation
2. **SSL certificate analysis** – check validity, issuer, and expiration
3. **Screenshot-based detection** – use a headless browser to capture the page and run CV/NLP on its visual content
4. **Persistent database** – replace in-memory history with SQLite or PostgreSQL
5. **Larger dataset** – integrate PhishTank, OpenPhish, and DMOZ datasets (millions of samples)
6. **Deep learning** – LSTM/Transformer model operating directly on URL character sequences
7. **Browser extension** – Chrome/Firefox extension for inline threat warnings
8. **User authentication** – JWT-based auth with per-user scan history
9. **Feedback loop** – allow users to flag false positives/negatives to improve the model
10. **Real-time WHOIS age scoring** – penalise very recently registered domains

---

*Built with ❤️ using Flask, React, Scikit-learn, and XGBoost.*
