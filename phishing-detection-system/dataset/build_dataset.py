"""
dataset/build_dataset.py
Combines PhishTank + Majestic URLs or processes PhiUSIIL dataset, extracts features, saves CSV.
"""
import pandas as pd, sys, os, argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'machine-learning'))
from feature_extraction import extract_features
from tqdm import tqdm

def build_from_phiusiil(csv_path, output_path):
    print(f"Loading PhiUSIIL dataset from {csv_path}...")
    df = pd.read_csv(csv_path, usecols=['URL', 'label'])
    print(f"Loaded {len(df)} rows. Raw label distribution:\n{df['label'].value_counts()}")

    rows = []
    for idx, row in tqdm(df.iterrows(), total=len(df), desc='Extracting features'):
        url = str(row['URL']).strip()
        if not url:
            continue
        try:
            f = extract_features(url)
            f['url'] = url
            # Invert PhiUSIIL label: PhiUSIIL has 0=Phishing, 1=Legit.
            # Our system uses 1=Phishing, 0=Legit.
            f['label'] = 1 - int(row['label'])
            rows.append(f)
        except Exception:
            continue

    out_df = pd.DataFrame(rows)
    out_df = out_df.drop_duplicates(subset=['url'] + list(out_df.columns.difference(['url'])))
    out_df = out_df.sample(frac=1, random_state=42).reset_index(drop=True)
    out_df.to_csv(output_path, index=False)
    print(f"\nSaved {len(out_df)} rows to {output_path}")
    print(f"Final label distribution (0=Legit, 1=Phishing):\n{out_df['label'].value_counts()}")
    return out_df

def build(max_phish=65000, max_legit=65000):
    rows = []

    # Phishing URLs — label 1
    phish = pd.read_csv('phishtank_raw.csv', usecols=['url'])
    phish_urls = phish['url'].dropna().unique()
    phish_urls = [str(u).strip() for u in phish_urls if str(u).strip()]
    # Keep only plausible http(s) URLs
    phish_urls = [u for u in phish_urls if u.startswith(('http://', 'https://'))]
    phish_urls = phish_urls[:max_phish]
    print(f"Phishing: {len(phish_urls)} URLs")
    for url in tqdm(phish_urls, desc='Phishing'):
        try:
            f = extract_features(url)
            f['url'] = url; f['label'] = 1
            rows.append(f)
        except Exception:
            continue

    # Legitimate URLs — label 0
    legit = pd.read_csv('majestic_raw.csv', usecols=['Domain'])
    legit_urls = ('https://' + legit['Domain']).dropna().unique()
    legit_urls = [str(u).strip() for u in legit_urls if str(u).strip()]
    legit_urls = [u for u in legit_urls if u.startswith(('http://', 'https://'))]
    # Balance: same number of legit as phishing
    legit_urls = legit_urls[:len(phish_urls)][:max_legit]
    print(f"Legitimate: {len(legit_urls)} URLs")
    for url in tqdm(legit_urls, desc='Legitimate'):
        try:
            f = extract_features(url)
            f['url'] = url; f['label'] = 0
            rows.append(f)
        except Exception:
            continue

    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset=['url'] + list(df.columns.difference(['url'])))
    # Keep balanced classes
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv('phishing_dataset.csv', index=False)
    print(f"\nSaved {len(df)} rows")
    print(df['label'].value_counts())

if __name__ == '__main__':
    base_dir = os.path.dirname(__file__)
    default_phiusiil = os.path.join(base_dir, 'PhiUSIIL_Phishing_URL_Dataset.csv')
    default_output = os.path.join(base_dir, 'phishing_dataset.csv')

    p = argparse.ArgumentParser(description='Build expanded phishing dataset')
    p.add_argument('--phiusiil', type=str, default=default_phiusiil, help='Path to PhiUSIIL CSV dataset')
    p.add_argument('--output', type=str, default=default_output, help='Output path for processed dataset')
    p.add_argument('--max-phish', type=int, default=65000)
    p.add_argument('--max-legit', type=int, default=65000)
    args = p.parse_args()

    if os.path.exists(args.phiusiil):
        build_from_phiusiil(args.phiusiil, args.output)
    else:
        build(args.max_phish, args.max_legit)
