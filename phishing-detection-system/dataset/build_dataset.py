"""
dataset/build_dataset.py
Combines PhishTank + Majestic URLs, extracts features, saves CSV.
Run AFTER feature_extraction.py is written (see next tab).
"""
import pandas as pd, sys, os
sys.path.insert(0, '../machine-learning')
from feature_extraction import extract_features
from tqdm import tqdm

def build():
    rows = []

    # Phishing URLs — label 1
    phish = pd.read_csv('phishtank_raw.csv')
    phish_urls = phish['url'].dropna().unique()[:5000]
    print(f"Phishing: {len(phish_urls)} URLs")
    for url in tqdm(phish_urls, desc='Phishing'):
        f = extract_features(str(url))
        f['url'] = url; f['label'] = 1
        rows.append(f)

    # Legitimate URLs — label 0
    legit = pd.read_csv('majestic_raw.csv')
    legit_urls = ('https://' + legit['Domain']).dropna().unique()[:5000]
    print(f"Legitimate: {len(legit_urls)} URLs")
    for url in tqdm(legit_urls, desc='Legitimate'):
        f = extract_features(str(url))
        f['url'] = url; f['label'] = 0
        rows.append(f)

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv('phishing_dataset.csv', index=False)
    print(f"\nSaved {len(df)} rows")
    print(df['label'].value_counts())

if __name__ == '__main__':
    build()