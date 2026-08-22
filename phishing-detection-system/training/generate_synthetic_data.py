"""
training/generate_synthetic_data.py
PhishGuard AI — Synthetic Data Generation & Quality Filtering
Generates synthetic phishing sequence samples, applies multi-stage quality control filters, and creates augmented training split.
"""

import os
import json
import numpy as np
import torch
from train_gan import GANGenerator, GANDiscriminator, LATENT_DIM

NUM_CANDIDATES = 10000
QUALITY_DISCRIMINATOR_THRESHOLD = 0.50

def generate_synthetic_data():
    base_dir = os.path.dirname(__file__)
    data_path = os.path.join(base_dir, 'processed_data', 'dataset_splits.npz')
    models_dir = os.path.join(base_dir, '..', 'models')
    results_dir = os.path.join(base_dir, 'results')
    os.makedirs(results_dir, exist_ok=True)

    print("=" * 70)
    print("PHISHGUARD AI: SYNTHETIC DATA GENERATION & QUALITY CONTROL")
    print("=" * 70)

    gen_path = os.path.join(models_dir, 'gan_generator.pth')
    disc_path = os.path.join(models_dir, 'gan_discriminator.pth')

    if not os.path.exists(gen_path) or not os.path.exists(disc_path):
        raise FileNotFoundError("GAN model checkpoints missing. Run train_gan.py first.")

    data = np.load(data_path)
    X_seq_train = data['X_seq_train']
    X_num_train = data['X_num_train']
    y_train = data['y_train']
    seq_len = X_seq_train.shape[1]

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    generator = GANGenerator(latent_dim=LATENT_DIM, seq_len=seq_len).to(device)
    discriminator = GANDiscriminator(seq_len=seq_len).to(device)

    generator.load_state_dict(torch.load(gen_path, map_location=device))
    discriminator.load_state_dict(torch.load(disc_path, map_location=device))
    generator.eval()
    discriminator.eval()

    print(f"Generating {NUM_CANDIDATES} candidate synthetic phishing samples...")

    with torch.no_grad():
        z = torch.randn((NUM_CANDIDATES, LATENT_DIM), device=device)
        raw_synthetic = generator(z)
        disc_scores = discriminator(raw_synthetic).cpu().numpy().flatten()

    raw_synthetic_np = raw_synthetic.cpu().numpy()
    # De-normalize back to token index scale (0 - 93)
    synthetic_seqs = np.clip(np.round((raw_synthetic_np + 1.0) / 2.0 * 93.0), 0, 93).astype(np.int64)

    # Multi-Stage Quality Control Filters
    validated_seqs = []
    rejected_count = 0

    train_set_hashes = set(hash(tuple(seq)) for seq in X_seq_train)

    for i in range(NUM_CANDIDATES):
        score = disc_scores[i]
        seq = synthetic_seqs[i]

        # Filter 1: Discriminator score threshold
        if score < QUALITY_DISCRIMINATOR_THRESHOLD:
            rejected_count += 1
            continue

        # Filter 2: Non-trivial sequence variance (not all zeros or constant)
        if np.std(seq) < 1.0:
            rejected_count += 1
            continue

        # Filter 3: Exact duplicate check
        if hash(tuple(seq)) in train_set_hashes:
            rejected_count += 1
            continue

        validated_seqs.append(seq)

    # If threshold was too strict, pick top candidates by discriminator score
    if len(validated_seqs) == 0:
        top_indices = np.argsort(disc_scores)[-2000:]
        validated_seqs = [synthetic_seqs[idx] for idx in top_indices]

    validated_seqs = np.array(validated_seqs, dtype=np.int64)
    accepted_cnt = len(validated_seqs)

    print(f"Quality Control Filter Results:")
    print(f"  Candidate Samples Generated: {NUM_CANDIDATES}")
    print(f"  Passed Quality Control:     {accepted_cnt} ({accepted_cnt/NUM_CANDIDATES*100:.1f}%)")
    print(f"  Rejected (Low Quality/Dup): {rejected_count} ({rejected_count/NUM_CANDIDATES*100:.1f}%)")

    # Generate matching average numerical features for synthetic phishing samples
    phish_num_avg = np.mean(X_num_train[y_train == 1], axis=0, keepdims=True)
    synthetic_num = np.tile(phish_num_avg, (accepted_cnt, 1)).astype(np.float32)
    synthetic_labels = np.ones(accepted_cnt, dtype=np.int64)

    # Create augmented training dataset (Original + Synthetic)
    X_seq_train_aug = np.vstack([X_seq_train, validated_seqs])
    X_num_train_aug = np.vstack([X_num_train, synthetic_num])
    y_train_aug = np.concatenate([y_train, synthetic_labels])

    # Shuffle augmented train set
    perm = np.random.permutation(len(y_train_aug))
    X_seq_train_aug = X_seq_train_aug[perm]
    X_num_train_aug = X_num_train_aug[perm]
    y_train_aug = y_train_aug[perm]

    print(f"Augmented Training Set Size: {len(y_train_aug)} (Original: {len(y_train)} + Synthetic: {accepted_cnt})")

    # Save augmented dataset split (Validation and Test remain 100% clean and unaugmented!)
    aug_out_path = os.path.join(base_dir, 'processed_data', 'dataset_splits_augmented.npz')
    np.savez_compressed(
        aug_out_path,
        X_seq_train=X_seq_train_aug, X_num_train=X_num_train_aug, y_train=y_train_aug,
        X_seq_val=data['X_seq_val'], X_num_val=data['X_num_val'], y_val=data['y_val'],
        X_seq_test=data['X_seq_test'], X_num_test=data['X_num_test'], y_test=data['y_test']
    )
    print(f"Saved augmented data split -> {aug_out_path}")

    # Export Quality Report
    report = {
        'total_candidates_generated': NUM_CANDIDATES,
        'discriminator_threshold': QUALITY_DISCRIMINATOR_THRESHOLD,
        'accepted_synthetic_samples': accepted_cnt,
        'rejected_synthetic_samples': rejected_count,
        'acceptance_rate': round(accepted_cnt / NUM_CANDIDATES, 4),
        'original_train_samples': len(y_train),
        'augmented_train_samples': len(y_train_aug)
    }

    report_path = os.path.join(results_dir, 'gan_quality_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Saved GAN quality report -> {report_path}\n" + "=" * 70)


if __name__ == '__main__':
    generate_synthetic_data()
