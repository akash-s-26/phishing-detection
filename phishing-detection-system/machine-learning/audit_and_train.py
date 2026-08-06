"""
machine-learning/audit_and_train.py

Performs end-to-end dataset validation, 5-Fold Stratified Cross-Validation,
ROC-AUC evaluation, hyperparameter tuning, model training, and artifact serialization.
"""

import os
import sys
import json
import pickle
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report
)

sys.path.insert(0, os.path.dirname(__file__))
from feature_extraction import FEATURE_COLS, extract_features, features_to_vector


def audit_dataset(csv_path: str) -> pd.DataFrame:
    print("=" * 70)
    print("TASK 8: TRAINING DATASET AUDIT & VALIDATION")
    print("=" * 70)

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}")

    df = pd.read_csv(csv_path)
    total_rows = len(df)
    print(f"Total raw dataset records: {total_rows}")

    # 1. Missing Values
    null_counts = df[FEATURE_COLS + ['label']].isnull().sum().to_dict()
    print(f"Null value breakdown: {null_counts}")

    # 2. Duplicate Records
    duplicates = df.duplicated(subset=FEATURE_COLS + ['label']).sum()
    print(f"Duplicate feature records detected: {duplicates}")

    # Clean dataset
    df_clean = df.dropna(subset=FEATURE_COLS + ['label']).drop_duplicates(subset=FEATURE_COLS + ['label']).copy()
    print(f"Clean records remaining: {len(df_clean)} (Removed {total_rows - len(df_clean)} duplicates/nulls)")

    # 3. Class Balance
    class_counts = df_clean['label'].value_counts().to_dict()
    legit_cnt = class_counts.get(0, 0)
    phish_cnt = class_counts.get(1, 0)
    print(f"Class Distribution: Legitimate (0) = {legit_cnt} ({legit_cnt/len(df_clean)*100:.1f}%), Phishing (1) = {phish_cnt} ({phish_cnt/len(df_clean)*100:.1f}%)")

    # 4. Feature summary statistics
    print("\nFeature Summary Statistics (Clean Data):")
    print(df_clean[FEATURE_COLS].describe().T[['mean', 'std', 'min', '50%', 'max']])
    print("=" * 70)

    return df_clean


def run_pipeline(dataset_path: str, output_dir: str):
    df = audit_dataset(dataset_path)

    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df['label'].values.astype(int)

    # 80/20 Stratified Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Fit scaler on train only (zero data leakage)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save scaler immediately
    scaler_path = os.path.join(output_dir, 'scaler.pkl')
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"\nSaved {scaler_path}")

    # Model definitions
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=250, max_depth=22, min_samples_split=2,
            random_state=42, n_jobs=-1
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=14, min_samples_split=2, random_state=42
        ),
        'Logistic Regression': LogisticRegression(
            C=1.0, max_iter=2000, random_state=42
        ),
        'SVM': CalibratedClassifierCV(
            estimator=LinearSVC(C=1.0, max_iter=2000, random_state=42, dual='auto')
        )
    }

    print("\n" + "=" * 70)
    print("TASK 9: MODEL TRAINING, 5-FOLD CROSS-VALIDATION & EVALUATION")
    print("=" * 70)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    results = []

    for name, model in models.items():
        print(f"\n>>> Training & 5-Fold Cross-Validating: {name}...")

        # 5-fold CV on train set
        cv_res = cross_validate(
            model, X_train_scaled, y_train, cv=cv,
            scoring=['accuracy', 'precision', 'recall', 'f1', 'roc_auc'],
            n_jobs=-1
        )
        print(f"  5-Fold CV Mean Accuracy = {np.mean(cv_res['test_accuracy']):.4f} (±{np.std(cv_res['test_accuracy']):.4f})")
        print(f"  5-Fold CV Mean ROC-AUC  = {np.mean(cv_res['test_roc_auc']):.4f} (±{np.std(cv_res['test_roc_auc']):.4f})")

        # Fit model on full training set
        model.fit(X_train_scaled, y_train)

        # Holdout test set evaluation
        y_pred = model.predict(X_test_scaled)
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test_scaled)[:, 1]
        else:
            y_proba = model.decision_function(X_test_scaled)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        auc = roc_auc_score(y_test, y_proba)
        cm = confusion_matrix(y_test, y_pred).tolist()

        metrics = {
            'model': name,
            'accuracy': round(float(acc), 4),
            'precision': round(float(prec), 4),
            'recall': round(float(rec), 4),
            'f1_score': round(float(f1), 4),
            'roc_auc': round(float(auc), 4),
            'cv_mean_accuracy': round(float(np.mean(cv_res['test_accuracy'])), 4),
            'confusion_matrix': cm
        }
        results.append(metrics)

        print(f"  Holdout Accuracy  = {acc:.4f}")
        print(f"  Holdout Precision = {prec:.4f}")
        print(f"  Holdout Recall    = {rec:.4f}")
        print(f"  Holdout F1-Score  = {f1:.4f}")
        print(f"  Holdout ROC-AUC   = {auc:.4f}")

    best_result = max(results, key=lambda r: r['f1_score'])
    best_name = best_result['model']
    best_model = models[best_name]
    print("\n" + "=" * 70)
    print(f"BEST PERFORMING MODEL: {best_name} (F1 Score = {best_result['f1_score']:.4f}, ROC-AUC = {best_result['roc_auc']:.4f})")
    print("=" * 70)

    # Save primary model
    best_path = os.path.join(output_dir, 'model.pkl')
    with open(best_path, 'wb') as f:
        pickle.dump(best_model, f)
    print(f"Saved best model -> {best_path}")

    # Save metrics JSON
    metrics_path = os.path.join(output_dir, 'model_metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump({'best_model': best_name, 'results': results}, f, indent=2)
    print(f"Saved metrics -> {metrics_path}")

    # Save all models individually for API multi-model comparison
    for name, model in models.items():
        safe_fname = name.lower().replace(' ', '_') + '.pkl'
        model_path = os.path.join(output_dir, safe_fname)
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        print(f"Saved {name} -> {model_path}")


if __name__ == '__main__':
    base_dir = os.path.dirname(__file__)
    dataset_file = os.path.join(base_dir, '..', 'dataset', 'phishing_dataset.csv')
    run_pipeline(dataset_file, base_dir)
