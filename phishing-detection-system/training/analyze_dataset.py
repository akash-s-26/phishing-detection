"""
training/analyze_dataset.py
PhishGuard AI — Dataset Audit & Analysis Script
Analyses raw dataset structure, class distribution, missing values, and URL length statistics.
"""

import os
import json
import pandas as pd
import numpy as np

def analyze_dataset():
    base_dir = os.path.dirname(__file__)
    dataset_path = os.path.join(base_dir, '..', 'dataset', 'phishing_dataset.csv')
    results_dir = os.path.join(base_dir, 'results')
    os.makedirs(results_dir, exist_ok=True)

    print("=" * 70)
    print("PHISHGUARD AI: DATASET AUDIT & ANALYSIS")
    print("=" * 70)

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset missing at {dataset_path}")

    df = pd.read_csv(dataset_path)
    total_raw = len(df)
    print(f"Total raw dataset records: {total_raw}")

    # Check columns
    print(f"Dataset Columns: {list(df.columns)}")

    # Null value check
    null_counts = df[['url', 'label']].isnull().sum().to_dict() if 'url' in df.columns else df.isnull().sum().to_dict()
    print(f"Null values: {null_counts}")

    # Duplicate URLs check
    duplicates = df.duplicated(subset=['url']).sum() if 'url' in df.columns else 0
    print(f"Duplicate URLs: {duplicates}")

    # Clean dataset
    df_clean = df.dropna(subset=['url', 'label']).drop_duplicates(subset=['url']).copy()
    total_clean = len(df_clean)
    print(f"Clean records: {total_clean} (Removed {total_raw - total_clean})")

    # Class balance
    class_counts = df_clean['label'].value_counts().to_dict()
    legit_cnt = int(class_counts.get(0, 0))
    phish_cnt = int(class_counts.get(1, 0))

    print(f"Class Distribution: Legitimate (0) = {legit_cnt} ({legit_cnt/total_clean*100:.1f}%), Phishing (1) = {phish_cnt} ({phish_cnt/total_clean*100:.1f}%)")

    # URL statistics
    url_lengths = df_clean['url'].apply(lambda u: len(str(u)))
    length_stats = {
        'min': int(url_lengths.min()),
        'mean': float(url_lengths.mean()),
        'median': float(url_lengths.median()),
        'max': int(url_lengths.max()),
        'std': float(url_lengths.std())
    }
    print(f"URL Length Stats: Min={length_stats['min']}, Mean={length_stats['mean']:.1f}, Max={length_stats['max']}")

    report = {
        'total_raw_samples': total_raw,
        'total_clean_samples': total_clean,
        'legitimate_samples': legit_cnt,
        'phishing_samples': phish_cnt,
        'class_balance_phishing_ratio': round(phish_cnt / total_clean, 4),
        'url_length_stats': length_stats
    }

    out_path = os.path.join(results_dir, 'dataset_analysis.json')
    with open(out_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Dataset analysis report saved to -> {out_path}\n" + "=" * 70)
    return report

if __name__ == '__main__':
    analyze_dataset()
