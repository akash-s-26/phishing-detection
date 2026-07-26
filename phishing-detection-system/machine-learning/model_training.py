"""
machine-learning/model_training.py
Trains Random Forest, Logistic Regression, Decision Tree, SVM.
Evaluates each, saves the best as model.pkl (plus all 4 individually).
"""

import os
import pickle
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

from preprocessing import preprocess


def train_random_forest(X_train, y_train):
    m = RandomForestClassifier(
        n_estimators=100, max_depth=10,
        min_samples_split=5, min_samples_leaf=2,
        random_state=42, n_jobs=-1
    )
    m.fit(X_train, y_train)
    return m


def train_logistic_regression(X_train, y_train):
    m = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
    m.fit(X_train, y_train)
    return m


def train_decision_tree(X_train, y_train):
    m = DecisionTreeClassifier(
        max_depth=8, min_samples_split=5,
        min_samples_leaf=2, random_state=42
    )
    m.fit(X_train, y_train)
    return m


def train_svm(X_train, y_train):
    m = SVC(kernel='rbf', C=1.0, gamma='scale', probability=True, random_state=42)
    m.fit(X_train, y_train)
    return m


def evaluate(model, X_test, y_test, name):
    y_pred = model.predict(X_test)
    metrics = {
        'model': name,
        'accuracy': round(accuracy_score(y_test, y_pred), 4),
        'precision': round(precision_score(y_test, y_pred, zero_division=0), 4),
        'recall': round(recall_score(y_test, y_pred, zero_division=0), 4),
        'f1_score': round(f1_score(y_test, y_pred, zero_division=0), 4),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
    }
    print(f"\n{name}")
    print(f"  Accuracy={metrics['accuracy']:.4f}  F1={metrics['f1_score']:.4f}")
    print(classification_report(y_test, y_pred, target_names=['Legit', 'Phishing'], zero_division=0))
    return metrics


def train_all(dataset_path, output_dir):
    X_train, X_test, y_train, y_test, scaler = preprocess(dataset_path, output_dir)

    models = {
        'Random Forest': train_random_forest(X_train, y_train),
        'Logistic Regression': train_logistic_regression(X_train, y_train),
        'Decision Tree': train_decision_tree(X_train, y_train),
        'SVM': train_svm(X_train, y_train),
    }

    results = [evaluate(m, X_test, y_test, n) for n, m in models.items()]
    best = max(results, key=lambda r: r['f1_score'])
    best_model = models[best['model']]
    print(f"\nBest model: {best['model']}  (F1={best['f1_score']:.4f})")

    with open(f'{output_dir}/model.pkl', 'wb') as f:
        pickle.dump(best_model, f)

    with open(f'{output_dir}/model_metrics.json', 'w') as f:
        json.dump({'best_model': best['model'], 'results': results}, f, indent=2)

    # Save all 4 individually too — used for the "model comparison" panel
    for name, model in models.items():
        safe = name.lower().replace(' ', '_')
        with open(f'{output_dir}/{safe}.pkl', 'wb') as f:
            pickle.dump(model, f)

    print(f"\nSaved model.pkl, scaler.pkl, model_metrics.json, and 4 individual models")
    return best_model, scaler


if __name__ == '__main__':
    base = os.path.dirname(__file__)
    train_all(os.path.join(base, '..', 'dataset', 'phishing_dataset.csv'), base)
