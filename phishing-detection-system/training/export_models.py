"""
training/export_models.py
PhishGuard AI — Model Artifact Export & Deployment Manifest Generator
Exports ensemble configuration and verifies all production Deep Learning model artifacts.
"""

import os
import json

def export_model_artifacts():
    base_dir = os.path.dirname(__file__)
    models_dir = os.path.join(base_dir, '..', 'models')
    os.makedirs(models_dir, exist_ok=True)

    print("=" * 70)
    print("PHISHGUARD AI: DEEP LEARNING MODEL ARTIFACT EXPORT")
    print("=" * 70)

    ensemble_config = {
        'version': '2.0.0-DL-Pure',
        'architecture': 'Deep Learning Fusion Ensemble (BiLSTM RNN + 1D CNN + GAN Augmentation)',
        'models': {
            'rnn': {
                'file': 'rnn_model.pth',
                'weight': 0.55,
                'type': 'BiLSTM'
            },
            'cnn': {
                'file': 'cnn_model.pth',
                'weight': 0.45,
                'type': '1D-CNN'
            }
        },
        'risk_thresholds': {
            'safe_max': 20.0,
            'low_max': 50.0,
            'suspicious_max': 70.0,
            'high_phishing_min': 71.0
        },
        'gan_augmentation': {
            'enabled': True,
            'quality_threshold': 0.50,
            'generator_file': 'gan_generator.pth'
        }
    }

    ensemble_config_path = os.path.join(models_dir, 'ensemble_config.json')
    with open(ensemble_config_path, 'w') as f:
        json.dump(ensemble_config, f, indent=2)
    print(f"Saved ensemble config -> {ensemble_config_path}")

    # Verify Production DL Artifact Manifest
    required_files = [
        'rnn_model.pth',
        'cnn_model.pth',
        'gan_generator.pth',
        'gan_discriminator.pth',
        'tokenizer.json',
        'preprocessing_config.json',
        'ensemble_config.json'
    ]

    print("\nVerifying Production Artifact Manifest:")
    all_present = True
    for fname in required_files:
        fpath = os.path.join(models_dir, fname)
        exists = os.path.exists(fpath)
        size_str = f"{os.path.getsize(fpath):,} bytes" if exists else "MISSING"
        status = "OK" if exists else "MISSING"
        print(f"  [{status:<7}] {fname:<25} ({size_str})")
        if not exists:
            all_present = False

    print("-" * 70)
    if all_present:
        print("[SUCCESS] All 7 production Deep Learning artifacts verified!")
    else:
        print("[WARNING] Some required artifacts are missing.")
    print("=" * 70)


if __name__ == '__main__':
    export_model_artifacts()
