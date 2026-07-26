"""
machine-learning/preprocessing.py
Cleans dataset, scales features, splits train/test.
"""

import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from feature_extraction import FEATURE_COLS


def preprocess(csv_path: str, output_dir: str = '.'):
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows")

    df = df.drop_duplicates()
    df = df.dropna(subset=FEATURE_COLS + ['label'])
    print(f"After clean: {len(df)} rows")
    print(f"Class balance:\n{df['label'].value_counts()}")

    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df['label'].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)}  Test: {len(X_test)}")

    # IMPORTANT: fit scaler on train only — never on test data (data leakage)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    with open(f'{output_dir}/scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    print(f"scaler.pkl saved to {output_dir}/")

    return X_train, X_test, y_train, y_test, scaler


if __name__ == '__main__':
    import os
    base = os.path.dirname(__file__)
    preprocess(os.path.join(base, '..', 'dataset', 'phishing_dataset.csv'), base)
