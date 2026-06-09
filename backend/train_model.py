# train_model.py
# Trains a phishing URL detector using:
#   - Hand-crafted URL features  (Random Forest + XGBoost stacking)
#   - NLP TF-IDF character n-grams on the raw URL string
# Saves artefacts to models/ so app.py can load them at startup.

import os
import sys
import pickle
import warnings
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (classification_report, accuracy_score,
                              roc_auc_score, confusion_matrix)
from scipy.sparse import hstack, csr_matrix

# XGBoost – graceful fallback to RF-only if not installed
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    warnings.warn("xgboost not installed – training with Random Forest only.")

# Local feature extractor
sys.path.insert(0, os.path.dirname(__file__))
from utils.feature_extractor import features_to_list, get_feature_names

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(__file__)
DATA_PATH   = os.path.join(BASE_DIR, 'data', 'urls.csv')
MODELS_DIR  = os.path.join(BASE_DIR, 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

MODEL_PATH      = os.path.join(MODELS_DIR, 'phishing_model.pkl')
TFIDF_PATH      = os.path.join(MODELS_DIR, 'tfidf_vectorizer.pkl')
SCALER_PATH     = os.path.join(MODELS_DIR, 'scaler.pkl')
META_PATH       = os.path.join(MODELS_DIR, 'model_meta.pkl')


def load_dataset(path: str) -> pd.DataFrame:
    """Load and validate the CSV dataset."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found at {path}")

    df = pd.read_csv(path)
    required = {'url', 'label'}
    if not required.issubset(df.columns):
        raise ValueError(f"Dataset must contain columns: {required}")

    df = df.dropna(subset=['url', 'label'])
    df['label'] = df['label'].astype(int)
    print(f"[Dataset]  Loaded {len(df)} rows  "
          f"(phishing={df['label'].sum()}, legit={len(df)-df['label'].sum()})")
    return df


def build_feature_matrix(urls: pd.Series,
                          tfidf: TfidfVectorizer,
                          fit_tfidf: bool = False) -> csr_matrix:
    """
    Combine hand-crafted features (dense) with TF-IDF (sparse).
    Returns a single sparse matrix for sklearn.
    """
    # 1. Hand-crafted features
    hand_feats = np.array([features_to_list(u) for u in urls], dtype=np.float32)
    hand_sparse = csr_matrix(hand_feats)

    # 2. TF-IDF character n-grams
    if fit_tfidf:
        tfidf_feats = tfidf.fit_transform(urls)
    else:
        tfidf_feats = tfidf.transform(urls)

    # 3. Horizontal stack
    return hstack([hand_sparse, tfidf_feats])


def train():
    print("=" * 60)
    print("  AI Phishing Detector – Model Training")
    print("=" * 60)

    # ── Load data ──────────────────────────────────────────────────────
    df = load_dataset(DATA_PATH)
    X_urls = df['url']
    y      = df['label'].values

    # ── TF-IDF vectoriser (character 2-4 grams) ────────────────────────
    tfidf = TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(2, 4),
        max_features=3000,
        sublinear_tf=True,
        min_df=1,
    )

    # ── Build full feature matrix ─────────────────────────────────────
    print("\n[Features]  Extracting hand-crafted + TF-IDF features …")
    X = build_feature_matrix(X_urls, tfidf, fit_tfidf=True)
    print(f"[Features]  Matrix shape: {X.shape}")

    # ── Scaler for hand-crafted block (TF-IDF is already normalised) ──
    # We scale the full matrix for RF; XGB is scale-invariant but it's fine.
    scaler = StandardScaler(with_mean=False)   # sparse-compatible
    X_scaled = scaler.fit_transform(X)

    # ── Train / test split ────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[Split]     Train={len(y_train)}, Test={len(y_test)}")

    # ── Random Forest ─────────────────────────────────────────────────
    print("\n[Training]  Random Forest …")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_pred  = rf.predict(X_test)
    rf_proba = rf.predict_proba(X_test)[:, 1]
    print(f"  Accuracy : {accuracy_score(y_test, rf_pred):.4f}")
    print(f"  ROC-AUC  : {roc_auc_score(y_test, rf_proba):.4f}")

    # ── XGBoost ───────────────────────────────────────────────────────
    if XGBOOST_AVAILABLE:
        print("\n[Training]  XGBoost …")
        scale_pos = int((y == 0).sum()) / max(int((y == 1).sum()), 1)
        xgb = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos,
            use_label_encoder=False,
            eval_metric='logloss',
            random_state=42,
            n_jobs=-1,
            verbosity=0,
        )
        xgb.fit(X_train, y_train)
        xgb_pred  = xgb.predict(X_test)
        xgb_proba = xgb.predict_proba(X_test)[:, 1]
        print(f"  Accuracy : {accuracy_score(y_test, xgb_pred):.4f}")
        print(f"  ROC-AUC  : {roc_auc_score(y_test, xgb_proba):.4f}")

        # ── Voting ensemble ───────────────────────────────────────────
        print("\n[Training]  Soft-voting ensemble (RF + XGBoost) …")
        ensemble = VotingClassifier(
            estimators=[('rf', rf), ('xgb', xgb)],
            voting='soft',
            weights=[1, 1],
        )
        ensemble.fit(X_train, y_train)
        final_model = ensemble
    else:
        final_model = rf

    # ── Final evaluation ──────────────────────────────────────────────
    print("\n[Evaluation]  Final model on held-out test set:")
    y_pred  = final_model.predict(X_test)
    y_proba = final_model.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, y_pred,
                                 target_names=['Legitimate', 'Phishing']))
    print(f"  ROC-AUC  : {roc_auc_score(y_test, y_proba):.4f}")
    print("  Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # ── 5-fold CV on full data ─────────────────────────────────────────
    print("\n[CV]  5-fold stratified cross-validation …")
    cv_scores = cross_val_score(rf, X_scaled, y, cv=StratifiedKFold(5),
                                scoring='roc_auc', n_jobs=-1)
    print(f"  ROC-AUC per fold : {np.round(cv_scores, 4)}")
    print(f"  Mean ± Std       : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ── Persist artefacts ─────────────────────────────────────────────
    print("\n[Saving]  Writing model artefacts …")
    with open(MODEL_PATH,  'wb') as f: pickle.dump(final_model, f)
    with open(TFIDF_PATH,  'wb') as f: pickle.dump(tfidf,       f)
    with open(SCALER_PATH, 'wb') as f: pickle.dump(scaler,      f)

    meta = {
        'feature_names'  : get_feature_names(),
        'tfidf_features' : tfidf.max_features,
        'xgboost_used'   : XGBOOST_AVAILABLE,
        'train_samples'  : len(y_train),
        'test_accuracy'  : float(accuracy_score(y_test, y_pred)),
        'test_roc_auc'   : float(roc_auc_score(y_test, y_proba)),
        'cv_mean_auc'    : float(cv_scores.mean()),
    }
    with open(META_PATH, 'wb') as f: pickle.dump(meta, f)

    print(f"\n  Model    → {MODEL_PATH}")
    print(f"  TF-IDF   → {TFIDF_PATH}")
    print(f"  Scaler   → {SCALER_PATH}")
    print(f"  Metadata → {META_PATH}")
    print("\n[Done]  Training complete!\n")
    return meta


if __name__ == '__main__':
    train()
