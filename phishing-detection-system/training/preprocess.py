"""
training/preprocess.py
PhishGuard AI — Deep Learning Preprocessing & Tokenization Pipeline
Builds URL character tokenizer, encodes sequence tensors, and generates stratified 70/15/15 splits.
"""

import os
import json
import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import train_test_split

MAX_SEQ_LEN = 150

def build_tokenizer(urls, max_vocab=128):
    chars = set()
    for u in urls:
        for c in str(u):
            chars.add(c)

    sorted_chars = sorted(list(chars))
    # Reserve index 0 for padding '<PAD>', index 1 for unknown '<UNK>'
    char_to_idx = {'<PAD>': 0, '<UNK>': 1}
    for idx, c in enumerate(sorted_chars, start=2):
        if len(char_to_idx) < max_vocab:
            char_to_idx[c] = idx

    idx_to_char = {v: k for k, v in char_to_idx.items()}
    return char_to_idx, idx_to_char


import re

def clean_url_sequence(url: str) -> str:
    u = str(url).strip()
    u = re.sub(r'/[0-9a-fA-F]{20,64}', '/hashid', u)
    return u


def encode_url(url, char_to_idx, max_len=MAX_SEQ_LEN):
    cleaned = clean_url_sequence(url)
    seq = [char_to_idx.get(c, char_to_idx['<UNK>']) for c in str(cleaned)]
    if len(seq) < max_len:
        seq = seq + [char_to_idx['<PAD>']] * (max_len - len(seq))
    else:
        seq = seq[:max_len]
    return seq

import sys
ml_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'machine-learning'))
sys.path.insert(0, ml_dir)
from feature_extraction import extract_features, features_to_normalized_vector

def extract_numerical_features(url):
    feats = extract_features(url)
    return features_to_normalized_vector(feats)


def preprocess_pipeline():
    base_dir = os.path.dirname(__file__)
    dataset_path = os.path.join(base_dir, '..', 'dataset', 'phishing_dataset.csv')
    models_dir = os.path.join(base_dir, '..', 'models')
    data_out_dir = os.path.join(base_dir, 'processed_data')

    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(data_out_dir, exist_ok=True)

    print("=" * 70)
    print("PHISHGUARD AI: DEEP LEARNING PREPROCESSING & TOKENIZATION")
    print("=" * 70)

    df = pd.read_csv(dataset_path).dropna(subset=['url', 'label']).drop_duplicates(subset=['url']).reset_index(drop=True)
    total_samples = len(df)
    print(f"Loaded clean dataset: {total_samples} samples")

    urls = df['url'].values
    labels = df['label'].values.astype(np.int64)

    cleaned_urls = [clean_url_sequence(u) for u in urls]

    # Build tokenizer
    char_to_idx, idx_to_char = build_tokenizer(cleaned_urls)
    vocab_size = len(char_to_idx)
    print(f"Character Vocabulary Size: {vocab_size}")

    # Encode sequence matrix
    print(f"Encoding URL sequences (max_len={MAX_SEQ_LEN})...")
    X_seq = np.array([encode_url(u, char_to_idx) for u in urls], dtype=np.int64)

    # Encode numerical feature matrix
    print("Extracting URL numerical features...")
    X_num = np.array([extract_numerical_features(u) for u in urls], dtype=np.float32)

    # Save tokenizer & preprocessing config
    tokenizer_path = os.path.join(models_dir, 'tokenizer.json')
    with open(tokenizer_path, 'w') as f:
        json.dump({'char_to_idx': char_to_idx, 'idx_to_char': idx_to_char, 'vocab_size': vocab_size, 'max_seq_len': MAX_SEQ_LEN}, f, indent=2)
    print(f"Saved tokenizer -> {tokenizer_path}")

    config_path = os.path.join(models_dir, 'preprocessing_config.json')
    with open(config_path, 'w') as f:
        json.dump({
            'max_seq_len': MAX_SEQ_LEN,
            'vocab_size': vocab_size,
            'num_samples': total_samples,
            'num_features': X_num.shape[1],
            'split_ratios': {'train': 0.70, 'val': 0.15, 'test': 0.15}
        }, f, indent=2)
    print(f"Saved preprocessing config -> {config_path}")

    # Stratified 70/15/15 train/val/test split
    X_seq_train_val, X_seq_test, X_num_train_val, X_num_test, y_train_val, y_test = train_test_split(
        X_seq, X_num, labels, test_size=0.15, random_state=42, stratify=labels
    )

    X_seq_train, X_seq_val, X_num_train, X_num_val, y_train, y_val = train_test_split(
        X_seq_train_val, X_num_train_val, y_train_val, test_size=0.17647, random_state=42, stratify=y_train_val
    )  # 0.85 * 0.17647 ≈ 0.15

    print(f"Train Set: {len(y_train)} samples ({np.mean(y_train)*100:.1f}% Phishing)")
    print(f"Val Set:   {len(y_val)} samples ({np.mean(y_val)*100:.1f}% Phishing)")
    print(f"Test Set:  {len(y_test)} samples ({np.mean(y_test)*100:.1f}% Phishing)")

    # Save split datasets
    np.savez_compressed(
        os.path.join(data_out_dir, 'dataset_splits.npz'),
        X_seq_train=X_seq_train, X_num_train=X_num_train, y_train=y_train,
        X_seq_val=X_seq_val, X_num_val=X_num_val, y_val=y_val,
        X_seq_test=X_seq_test, X_num_test=X_num_test, y_test=y_test
    )
    print(f"Saved compressed data splits -> {os.path.join(data_out_dir, 'dataset_splits.npz')}\n" + "=" * 70)


if __name__ == '__main__':
    preprocess_pipeline()
