

from __future__ import annotations

import sys
import warnings
from typing import Dict, Optional, Tuple

import joblib
import numpy as np
import optuna
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_score,
    cross_validate,
    train_test_split,
)
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

# Local modules — must be importable from the same directory
from feature_extractor import FEATURE_NAMES, URLFeatureExtractor
from data_pipeline import build_dataset


# ─────────────────────────────────────────────────────────────────────────────
# Global configuration constants
# ─────────────────────────────────────────────────────────────────────────────

MODEL_OUTPUT_PATH:  str   = "phishguard_model.pkl"
RANDOM_STATE:       int   = 42        # Global reproducibility seed
TEST_SIZE:          float = 0.20      # Hold-out fraction (80 / 20 split)
DECISION_THRESHOLD: float = 0.30      # P(phish) ≥ 0.30 → flag as phishing
N_CV_SPLITS:        int   = 5         # Folds for final cross-validation report
N_TRIALS:           int   = 50        # Optuna TPE trials for hyperparameter search
# NOTE: reduce N_TRIALS to 20 for a ~5-minute quick run;
#       increase to 100 for maximum accuracy (≈20–30 min on a modern CPU).


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_dataset(
    csv_path:      Optional[str] = None,
    use_real_data: bool          = True,
) -> Tuple[np.ndarray, np.ndarray]:
   
    if csv_path is not None:
        print(f"\n[INFO] Loading pre-extracted dataset from '{csv_path}' …")
        df = pd.read_csv(csv_path)

        missing = set(FEATURE_NAMES) - set(df.columns)
        if missing:
            raise ValueError(
                f"CSV is missing {len(missing)} required feature column(s): "
                f"{sorted(missing)}"
            )

        X = df[FEATURE_NAMES].values.astype(float)
        y = df["label"].values.astype(int)

    elif use_real_data:
        print("\n[INFO] Invoking real-world data pipeline …")
        print("[INFO] Sources: PhishTank | URLhaus | Tranco | ISCX URL 2016")
        print("[INFO] (First run: 5–15 min network download.  "
              "Subsequent runs use local cache.)\n")
        X, y = build_dataset()

    else:
        raise RuntimeError(
            "No data source specified.  Either provide a csv_path or set "
            "use_real_data=True to invoke the live data pipeline."
        )

    # Report class distribution — spot severe imbalance early.
    unique, counts  = np.unique(y, return_counts=True)
    class_dist = {
        ("Legitimate" if k == 0 else "Malicious"): int(v)
        for k, v in zip(unique, counts)
    }
    print(f"[INFO] Dataset shape : {X.shape}")
    print(f"[INFO] Class dist    : {class_dist}")
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline construction
# ─────────────────────────────────────────────────────────────────────────────

def build_pipeline(
    best_params:      Optional[Dict] = None,
    scale_pos_weight: float          = 1.0,
) -> Pipeline:
    
    # Suppress Optuna's per-trial logging — we print our own progress.
    optuna.logging.set_verbosity(optuna.logging.WARNING)

    cv = StratifiedKFold(n_splits=n_cv_splits, shuffle=True, random_state=RANDOM_STATE)

    def objective(trial: optuna.Trial) -> float:
        """Single Optuna trial: sample params → 3-fold CV → return mean AUC."""
        params = {
            "n_estimators":     trial.suggest_int("n_estimators",     100,  800),
            "max_depth":        trial.suggest_int("max_depth",         3,    10),
            "learning_rate":    trial.suggest_float("learning_rate",   0.01, 0.30, log=True),
            "subsample":        trial.suggest_float("subsample",       0.50, 1.00),
            "colsample_bytree": trial.suggest_float("colsample_bytree",0.50, 1.00),
            "min_child_weight": trial.suggest_int("min_child_weight",  1,    10),
            "gamma":            trial.suggest_float("gamma",           0.0,  5.0),
        }

        model = XGBClassifier(
            **params,
            scale_pos_weight = scale_pos_weight,
            objective        = "binary:logistic",
            eval_metric      = "logloss",
            n_jobs           = -1,
            random_state     = RANDOM_STATE,
            verbosity        = 0,
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            scores = cross_val_score(
                model, X_train, y_train,
                cv=cv,
                scoring="roc_auc",
                n_jobs=1,   # avoid nested parallelism with XGBoost's n_jobs=-1
            )

        return float(scores.mean())

    # ── Run the study ─────────────────────────────────────────────────
    print(f"\n[INFO] Optuna TPE hyperparameter search: {n_trials} trials …")
    print(f"[INFO] Each trial = {n_cv_splits}-fold CV on "
          f"{len(X_train):,} training samples.")

    study = optuna.create_study(
        direction = "maximize",
        sampler   = optuna.samplers.TPESampler(seed=RANDOM_STATE),
    )

    # Custom progress callback — print every 10 trials
    def _progress_callback(study: optuna.Study, trial: optuna.Trial) -> None:
        if (trial.number + 1) % 10 == 0 or trial.number == 0:
            best_val = study.best_value
            print(f"  Trial {trial.number + 1:>3}/{n_trials}  |  "
                  f"This AUC: {trial.value:.4f}  |  "
                  f"Best AUC so far: {best_val:.4f}")

    study.optimize(objective, n_trials=n_trials, callbacks=[_progress_callback])

    best = study.best_params
    print(f"\n[✓] Optuna complete.  Best ROC-AUC: {study.best_value:.4f}")
    print("  Best hyperparameters:")
    for k, v in best.items():
        print(f"    {k:<22} = {v}")

    return best


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _apply_threshold(
    y_prob:    np.ndarray,
    threshold: float,
) -> np.ndarray:
    
    return (y_prob >= threshold).astype(int)


def print_metrics(
    y_true:      np.ndarray,
    y_pred:      np.ndarray,
    y_prob:      np.ndarray,
    threshold:   float = 0.50,
    split_label: str   = "Evaluation",
) -> None:
   
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    auc  = roc_auc_score(y_true, y_prob)
    cm   = confusion_matrix(y_true, y_pred)

    w = 60
    print(f"\n{'╔' + '═' * (w - 2) + '╗'}")
    print(f"║  {split_label:<{w - 4}}║")
    print(f"║  Threshold applied: {threshold:.2f}{' ' * (w - 24)}║")
    print(f"{'╠' + '═' * (w - 2) + '╣'}")
    print(f"║  Accuracy   : {acc:.4f}{' ' * (w - 19)}║")
    print(f"║  Precision  : {prec:.4f}  ← flagged URLs that are truly phishing   ║")
    print(f"║  Recall     : {rec:.4f}  ← ★ PRIMARY — missed phish = real harm ║")
    print(f"║  F1-Score   : {f1:.4f}{' ' * (w - 19)}║")
    print(f"║  ROC-AUC    : {auc:.4f}  ← threshold-independent ranking quality  ║")
    print(f"{'╠' + '═' * (w - 2) + '╣'}")
    print(f"║  Confusion Matrix                                       ║")
    print(f"║    TN (legit ✓) = {cm[0, 0]:>6}   FP (legit wrongly flagged) = {cm[0, 1]:>6} ║")
    print(f"║    FN (phish ✗) = {cm[1, 0]:>6}   TP (phish correctly caught) = {cm[1, 1]:>6} ║")
    print(f"{'╚' + '═' * (w - 2) + '╝'}")

    print(classification_report(
        y_true, y_pred,
        target_names=["Legitimate (0)", "Phishing (1)"],
        digits=4,
    ))


def print_feature_importances(pipeline: Pipeline) -> None:
    
    classifier   = pipeline.named_steps["classifier"]
    importances  = classifier.feature_importances_   # gain-based by default

    pairs        = sorted(
        zip(FEATURE_NAMES, importances),
        key=lambda x: x[1],
        reverse=True,
    )
    max_imp      = pairs[0][1] if pairs and pairs[0][1] > 0 else 1.0

    print("\n  Top-10 most influential features (XGBoost gain-based importance):")
    print(f"  {'Feature':<25}  {'Importance':>10}  Visual")
    print(f"  {'-' * 65}")
    for name, imp in pairs[:10]:
        bar = "█" * max(1, int(30 * imp / max_imp))
        print(f"  {name:<25}  {imp:>10.4f}  {bar}")

    print("\n  Full feature importance ranking:")
    print(f"  {'Rank':<6}  {'Feature':<25}  {'Importance':>10}")
    print(f"  {'-' * 45}")
    for rank, (name, imp) in enumerate(pairs, start=1):
        print(f"  {rank:<6}  {name:<25}  {imp:>10.4f}")


# ─────────────────────────────────────────────────────────────────────────────
# Main training function
# ─────────────────────────────────────────────────────────────────────────────

def train(
    csv_path:      Optional[str] = None,
    use_real_data: bool          = True,
    threshold:     float         = DECISION_THRESHOLD,
    output:        str           = MODEL_OUTPUT_PATH,
    n_trials:      int           = N_TRIALS,
) -> Pipeline:
   
    banner = "  PhishGuard v2.0.0 — ML Pipeline Training (XGBoost + Optuna)  "
    print("\n" + "╔" + "═" * (len(banner) + 2) + "╗")
    print("║" + banner + "║")
    print("╚" + "═" * (len(banner) + 2) + "╝")

    # ── Step 1: Load data ─────────────────────────────────────────────
    X, y = load_dataset(csv_path=csv_path, use_real_data=use_real_data)

    # ── Step 2: Compute class-imbalance weight ────────────────────────
    # scale_pos_weight = n_negative / n_positive
    # XGBoost uses this during tree building to up-weight the minority
    # (phishing) class — equivalent to class_weight='balanced' in sklearn,
    # but applied at the leaf-weight level rather than the sample level.
    n_legit   = int(np.sum(y == 0))
    n_mal     = int(np.sum(y == 1))
    spw       = n_legit / n_mal if n_mal > 0 else 1.0
    print(f"\n[INFO] scale_pos_weight = {n_legit} / {n_mal} = {spw:.3f}")

    # ── Step 3: Stratified train / test split ─────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size    = TEST_SIZE,
        random_state = RANDOM_STATE,
        stratify     = y,
    )
    print(f"[INFO] Train : {len(y_train):,} samples  |  "
          f"Test : {len(y_test):,} samples")

    # ── Step 4: Optuna hyperparameter search ──────────────────────────
    # Performed entirely on the TRAINING set — test set never touched here.
    best_params = tune_hyperparameters(
        X_train,
        y_train,
        scale_pos_weight = spw,
        n_trials         = n_trials,
    )

    # ── Step 5: Cross-validation report with best hyperparameters ─────
    print(f"\n[INFO] Running {N_CV_SPLITS}-fold stratified cross-validation "
          "with best hyperparameters …")
    cv_pipeline = build_pipeline(best_params=best_params, scale_pos_weight=spw)
    cv          = StratifiedKFold(
        n_splits     = N_CV_SPLITS,
        shuffle      = True,
        random_state = RANDOM_STATE,
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cv_results = cross_validate(
            cv_pipeline, X_train, y_train,
            cv      = cv,
            scoring = ["accuracy", "precision", "recall", "f1", "roc_auc"],
            n_jobs  = 1,
        )

    print(f"\n  Cross-Validation Results (mean ± std, {N_CV_SPLITS} folds):")
    print(f"  {'Metric':<14}  {'Mean':>8}  {'Std':>8}")
    print(f"  {'-' * 35}")
    metric_labels = {
        "accuracy":  "Accuracy",
        "precision": "Precision",
        "recall":    "Recall ★",
        "f1":        "F1-Score",
        "roc_auc":   "ROC-AUC",
    }
    for key, label in metric_labels.items():
        scores = cv_results[f"test_{key}"]
        print(f"  {label:<14}  {scores.mean():>8.4f}  {scores.std():>8.4f}")

    # ── Step 6: Final fit ─────────────────────────────────────────────
    print("\n[INFO] Fitting final pipeline on full training partition …")
    pipeline = build_pipeline(best_params=best_params, scale_pos_weight=spw)
    pipeline.fit(X_train, y_train)

    # ── Step 7: Evaluation on held-out test set ───────────────────────
    # ``predict_proba`` returns P(class=0), P(class=1).  We take column 1.
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    y_pred_default = _apply_threshold(y_prob, threshold=0.50)
    y_pred_custom  = _apply_threshold(y_prob, threshold=threshold)

    print_metrics(
        y_test, y_pred_default, y_prob,
        threshold    = 0.50,
        split_label  = "Hold-out evaluation — DEFAULT threshold (0.50)",
    )
    print_metrics(
        y_test, y_pred_custom, y_prob,
        threshold    = threshold,
        split_label  = f"Hold-out evaluation — CUSTOM threshold ({threshold:.2f})",
    )

    # ── Step 8: Feature importances ───────────────────────────────────
    print_feature_importances(pipeline)

    # ── Step 9: Serialise ─────────────────────────────────────────────
    # ``joblib`` handles large numpy arrays efficiently (memory-mapped
    # serialisation, smaller artefacts than pickle).  compress=3 gives a
    # good size / speed trade-off for the XGBoost booster weights.
    joblib.dump(pipeline, output, compress=3)
    xgb_model = pipeline.named_steps["classifier"]
    print(f"\n[✓] Pipeline serialised → '{output}'")
    print(f"    Classifier   : XGBClassifier")
    print(f"    n_estimators : {xgb_model.n_estimators}")
    print(f"    max_depth    : {xgb_model.max_depth}")
    print(f"    learning_rate: {xgb_model.learning_rate}")
    print(f"    Features     : {len(FEATURE_NAMES)} — "
          f"{', '.join(FEATURE_NAMES[:4])} …")

    return pipeline


# ─────────────────────────────────────────────────────────────────────────────
# Production inference helpers (consumed by FastAPI backend)
# ─────────────────────────────────────────────────────────────────────────────
# These functions are unchanged from v1.0.0 — the FastAPI backend calls them
# by name and must not require any code changes after this upgrade.

def load_pipeline(model_path: str = MODEL_OUTPUT_PATH) -> Pipeline:
    
    return joblib.load(model_path)


def predict_url(
    feature_vector: list,
    pipeline:       Pipeline,
    threshold:      float = DECISION_THRESHOLD,
) -> dict:
   
    X        = np.array(feature_vector, dtype=float).reshape(1, -1)
    prob     = float(pipeline.predict_proba(X)[0, 1])
    is_phish = prob >= threshold

    if prob >= 0.75:
        risk   = "CRITICAL"
        advice = "Block immediately. Very high confidence phishing URL."
    elif prob >= 0.50:
        risk   = "HIGH"
        advice = "Block and log. High confidence phishing URL."
    elif prob >= threshold:
        risk   = "MEDIUM"
        advice = "Flag for analyst review. Suspicious characteristics detected."
    else:
        risk   = "LOW"
        advice = "URL appears legitimate. No blocking action required."

    return {
        "phishing_probability": round(prob, 4),
        "is_phishing":          is_phish,
        "risk_level":           risk,
        "recommendation":       advice,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # ── Option A: Load pre-extracted feature CSV (fast, no download) ──
    # If you have already run data_pipeline.py and saved phishguard_dataset.csv,
    # uncomment the line below and comment out Option B.
    #
    # fitted_pipeline = train(
    #     csv_path      = "phishguard_dataset.csv",
    #     use_real_data = False,
    #     threshold     = DECISION_THRESHOLD,
    #     output        = MODEL_OUTPUT_PATH,
    #     n_trials      = N_TRIALS,
    # )

    # ── Option B: Full pipeline — fetch live data + train (default) ───
    # Downloads from PhishTank, URLhaus, Tranco, and ISCX (if CSV present).
    # First run: ~10–20 min.  Subsequent runs use local cache: ~5–10 min.
    fitted_pipeline = train(
        csv_path      = None,           # None → invoke data pipeline
        use_real_data = True,
        threshold     = DECISION_THRESHOLD,
        output        = MODEL_OUTPUT_PATH,
        n_trials      = N_TRIALS,
    )

    # ── Verify serialisation round-trip ──────────────────────────────
    print("\n[INFO] Verifying model serialisation round-trip …")
    loaded_pipeline = load_pipeline(MODEL_OUTPUT_PATH)
    assert isinstance(loaded_pipeline, Pipeline), "Deserialisation failed."
    print("[✓] Model loaded successfully from disk.")

    # ── Live inference demo ───────────────────────────────────────────
    test_cases = [
        # (url, ground_truth)
        ("https://www.google.com/search?q=openai",                  "LEGITIMATE"),
        ("http://paypa1-secure.login.tk/verify?user=admin@x.com",   "PHISHING"),
        ("http://192.168.1.1/account/update?token=abc%20xyz",       "PHISHING"),
        ("https://github.com/anthropics/anthropic-sdk-python",      "LEGITIMATE"),
        ("http://secure-update.verify.account.xyz/login/",          "PHISHING"),
        ("https://docs.python.org/3/library/urllib.parse.html",     "LEGITIMATE"),
        ("http://amaz0n-secure.login.win/confirm?ref=%7B%22u%22%3A","PHISHING"),
    ]

    extractor = URLFeatureExtractor()
    print("\n" + "╔" + "═" * 75 + "╗")
    print("║" + "  PhishGuard v2.0.0 — Live Inference Demo (XGBoost)".center(75) + "║")
    print("╠" + "═" * 75 + "╣")
    print(f"║  {'URL':<48}  {'Truth':<11}  {'Result':<8}  {'P(phish)':>8} ║")
    print("╠" + "═" * 75 + "╣")

    correct = 0
    for url, truth in test_cases:
        vec    = extractor.extract_vector(url)
        result = predict_url(vec, loaded_pipeline)
        pred   = "PHISHING" if result["is_phishing"] else "LEGIT"
        match  = "✓" if (pred == "PHISHING") == (truth == "PHISHING") else "✗"
        correct += int(match == "✓")
        p_str  = f"{result['phishing_probability']:.3f}"
        print(f"║  {url[:47]:<47}  {truth:<11}  {pred:<8}  {p_str:>8} {match} ║")

    print("╠" + "═" * 75 + "╣")
    print(f"║  Demo accuracy: {correct}/{len(test_cases)} correct"
          f"{' ' * (58 - len(str(correct)))}║")
    print("╚" + "═" * 75 + "╝")

    print(f"\n[✓] Training and inference pipeline complete.")
    print(f"[✓] Model artefact : '{MODEL_OUTPUT_PATH}'")
    print(f"[✓] Dataset CSV    : 'phishguard_dataset.csv'")
    print(f"[✓] Ready for deployment in FastAPI backend.\n")
    sys.exit(0)
