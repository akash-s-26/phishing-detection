"""
dataset/build_dataset.py
Builds a balanced 50/50 phishing detection dataset (100,000 unique records)
from PhiUSIIL, PhishTank, and Majestic sources with zero label bias.
"""

import os
import sys
import pandas as pd
import numpy as np
from tqdm import tqdm

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'machine-learning'))
from feature_extraction import extract_features, FEATURE_COLS


def build_balanced(output_path: str, max_per_class: int = 50000):
    base_dir = os.path.dirname(__file__)
    phi_path = os.path.join(base_dir, 'PhiUSIIL_Phishing_URL_Dataset.csv')
    pt_path = os.path.join(base_dir, 'phishtank_raw.csv')
    maj_path = os.path.join(base_dir, 'majestic_raw.csv')

    legit_urls = set()
    phish_urls = set()

    # 1. PhiUSIIL (label 1 = Legit, label 0 = Phishing in raw PhiUSIIL)
    if os.path.exists(phi_path):
        print(f"Reading PhiUSIIL from {phi_path}...")
        df_phi = pd.read_csv(phi_path, usecols=['URL', 'label'])
        for _, r in df_phi.iterrows():
            u = str(r['URL']).strip()
            if not u or not u.startswith(('http://', 'https://')):
                continue
            if r['label'] == 1:
                legit_urls.add(u)
            else:
                phish_urls.add(u)

    # 2. Majestic 1M (Legit)
    if os.path.exists(maj_path):
        print(f"Reading Majestic from {maj_path}...")
        df_maj = pd.read_csv(maj_path, usecols=['Domain'], nrows=60000)
        for d in df_maj['Domain'].dropna():
            u = 'https://' + str(d).strip()
            legit_urls.add(u)

    # 3. PhishTank (Phish)
    if os.path.exists(pt_path):
        print(f"Reading PhishTank from {pt_path}...")
        df_pt = pd.read_csv(pt_path, usecols=['url'])
        for u in df_pt['url'].dropna():
            u_str = str(u).strip()
            if u_str.startswith(('http://', 'https://')):
                phish_urls.add(u_str)

    legit_list = list(legit_urls)[:max_per_class]
    phish_list = list(phish_urls)[:max_per_class]

    print(f"Collected {len(legit_list)} unique Legitimate URLs and {len(phish_list)} unique Phishing URLs.")

    rows = []
    print("Extracting features for Legitimate URLs...")
    for u in tqdm(legit_list):
        f = extract_features(u)
        f['url'] = u
        f['label'] = 0  # 0 = Legitimate
        rows.append(f)

    print("Extracting features for Phishing URLs...")
    for u in tqdm(phish_list):
        f = extract_features(u)
        f['url'] = u
        f['label'] = 1  # 1 = Phishing
        rows.append(f)

    out_df = pd.DataFrame(rows)
    out_df = out_df.drop_duplicates(subset=['url'])
    out_df = out_df.sample(frac=1, random_state=42).reset_index(drop=True)

    out_df.to_csv(output_path, index=False)
    print(f"\nSuccessfully saved {len(out_df)} rows to {output_path}")
    print(f"Final Class Distribution:\n{out_df['label'].value_counts()}")


if __name__ == '__main__':
    out_file = os.path.join(os.path.dirname(__file__), 'phishing_dataset.csv')
    build_balanced(out_file, max_per_class=50000)
