# app.py
# Flask REST API for AI-Based Phishing URL Detection
# Endpoints:
#   POST /predict   – analyse a URL and return prediction
#   GET  /history   – return the last N scanned URLs
#   GET  /health    – liveness check
#   GET  /stats     – aggregate statistics

import os
import sys
import pickle
import logging
import datetime
from collections import deque

import numpy as np
from flask import Flask, request, jsonify
from scipy.sparse import hstack, csr_matrix

try:
    from flask_cors import CORS
    _CORS_AVAILABLE = True
except ImportError:
    _CORS_AVAILABLE = False
    log_msg = "flask-cors not installed; CORS headers added manually."

# ── Local imports ─────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from utils.feature_extractor import features_to_list, extract_features

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s  %(levelname)-8s  %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger(__name__)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
if _CORS_AVAILABLE:
    CORS(app, resources={r"/*": {"origins": "*"}})
else:
    @app.after_request
    def add_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
        return response

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(__file__)
MODELS_DIR  = os.path.join(BASE_DIR, 'models')
MODEL_PATH  = os.path.join(MODELS_DIR, 'phishing_model.pkl')
TFIDF_PATH  = os.path.join(MODELS_DIR, 'tfidf_vectorizer.pkl')
SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.pkl')
META_PATH   = os.path.join(MODELS_DIR, 'model_meta.pkl')

# ── In-memory scan history (last 100 entries) ──────────────────────────────
MAX_HISTORY = 100
scan_history: deque = deque(maxlen=MAX_HISTORY)

# ── Model globals ─────────────────────────────────────────────────────────────
model  = None
tfidf  = None
scaler = None
meta   = {}


def load_models():
    """Load trained artefacts; auto-train if missing."""
    global model, tfidf, scaler, meta

    if not all(os.path.exists(p) for p in [MODEL_PATH, TFIDF_PATH, SCALER_PATH]):
        log.warning("Model artefacts not found – running train_model.py …")
        from train_model import train
        train()

    with open(MODEL_PATH,  'rb') as f: model  = pickle.load(f)
    with open(TFIDF_PATH,  'rb') as f: tfidf  = pickle.load(f)
    with open(SCALER_PATH, 'rb') as f: scaler = pickle.load(f)
    if os.path.exists(META_PATH):
        with open(META_PATH, 'rb') as f: meta = pickle.load(f)

    log.info("Models loaded successfully.")
    log.info(f"  XGBoost used   : {meta.get('xgboost_used', False)}")
    log.info(f"  Test accuracy  : {meta.get('test_accuracy', 'N/A')}")
    log.info(f"  Test ROC-AUC   : {meta.get('test_roc_auc', 'N/A')}")


def build_single_feature_vector(url: str) -> np.ndarray:
    """Build the same feature matrix used during training for one URL."""
    hand_feats  = np.array([features_to_list(url)], dtype=np.float32)
    hand_sparse = csr_matrix(hand_feats)
    tfidf_feats = tfidf.transform([url])
    combined    = hstack([hand_sparse, tfidf_feats])
    return scaler.transform(combined)


def get_risk_level(prob: float) -> str:
    if prob >= 0.80: return 'HIGH'
    if prob >= 0.50: return 'MEDIUM'
    if prob >= 0.30: return 'LOW'
    return 'SAFE'


def get_risk_details(features: dict, prob: float) -> list:
    """Return human-readable risk factors detected in the URL."""
    issues = []
    if features.get('has_at_symbol'):
        issues.append("Contains '@' symbol – common in obfuscated URLs")
    if features.get('has_ip_address'):
        issues.append("Hostname is a raw IP address instead of a domain name")
    if not features.get('is_https'):
        issues.append("Uses HTTP (not HTTPS) – connection is not encrypted")
    if features.get('has_digit_substitution'):
        issues.append("Typosquatting detected – digits replacing letters in brand names")
    if features.get('suspicious_keyword_count', 0) >= 3:
        issues.append(f"High density of suspicious keywords "
                       f"({features['suspicious_keyword_count']} found)")
    if features.get('subdomain_count', 0) >= 3:
        issues.append(f"Excessive subdomain depth ({features['subdomain_count']} levels)")
    if features.get('has_suspicious_tld'):
        issues.append("Suspicious top-level domain (.xyz, .info, .top, etc.)")
    if features.get('url_length', 0) > 100:
        issues.append(f"Unusually long URL ({features['url_length']} chars)")
    if features.get('num_hyphens', 0) >= 4:
        issues.append(f"Multiple hyphens in hostname ({features['num_hyphens']})")
    if features.get('has_double_slash'):
        issues.append("Double slash found in URL path")
    if features.get('brand_in_hostname') and not features.get('is_https'):
        issues.append("Brand name in hostname with no HTTPS – possible spoofing")
    return issues


# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status' : 'ok',
        'model'  : 'loaded' if model else 'not loaded',
        'version': '1.0.0',
    })


@app.route('/stats', methods=['GET'])
def stats():
    total     = len(scan_history)
    phishing  = sum(1 for r in scan_history if r['is_phishing'])
    legit     = total - phishing
    return jsonify({
        'total_scanned': total,
        'phishing'     : phishing,
        'legitimate'   : legit,
        'model_info'   : {
            'test_accuracy': meta.get('test_accuracy'),
            'test_roc_auc' : meta.get('test_roc_auc'),
            'xgboost_used' : meta.get('xgboost_used'),
            'train_samples': meta.get('train_samples'),
        },
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict whether a URL is phishing or legitimate.

    Request body (JSON):
      { "url": "https://example.com" }

    Response (JSON):
      {
        "url"              : "https://example.com",
        "is_phishing"      : false,
        "label"            : "Legitimate",
        "confidence"       : 0.97,
        "phishing_prob"    : 0.03,
        "legitimate_prob"  : 0.97,
        "risk_level"       : "SAFE",
        "risk_factors"     : [],
        "features"         : { ... },
        "timestamp"        : "2024-01-01T12:00:00"
      }
    """
    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Basic URL sanity check
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url

    try:
        X        = build_single_feature_vector(url)
        proba    = model.predict_proba(X)[0]       # [P(legit), P(phishing)]
        phish_p  = float(proba[1])
        legit_p  = float(proba[0])
        label    = int(model.predict(X)[0])

        features     = extract_features(url)
        risk_level   = get_risk_level(phish_p)
        risk_factors = get_risk_details(features, phish_p)

        confidence = phish_p if label == 1 else legit_p

        result = {
            'url'             : url,
            'is_phishing'     : bool(label == 1),
            'label'           : 'Phishing' if label == 1 else 'Legitimate',
            'confidence'      : round(confidence, 4),
            'phishing_prob'   : round(phish_p,  4),
            'legitimate_prob' : round(legit_p,  4),
            'risk_level'      : risk_level,
            'risk_factors'    : risk_factors,
            'features'        : {k: round(v, 4) if isinstance(v, float) else v
                                  for k, v in features.items()},
            'timestamp'       : datetime.datetime.utcnow().isoformat(),
        }

        scan_history.appendleft(result)
        log.info(f"[Predict]  {url[:60]:<60}  →  {result['label']}  "
                 f"(p={phish_p:.3f})")
        return jsonify(result)

    except Exception as exc:
        log.exception(f"Prediction error for URL: {url}")
        return jsonify({'error': str(exc)}), 500


@app.route('/history', methods=['GET'])
def history():
    """Return recent scan history (latest first)."""
    limit = request.args.get('limit', 50, type=int)
    limit = min(max(limit, 1), MAX_HISTORY)
    return jsonify(list(scan_history)[:limit])


@app.route('/history', methods=['DELETE'])
def clear_history():
    scan_history.clear()
    return jsonify({'message': 'History cleared'})


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    load_models()
    log.info("Starting Flask server on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
