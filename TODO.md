# Phishing Model Retraining with Expanded Dataset

## Steps
- [x] 1. Expand `build_dataset.py` to use all phishing URLs (~60k) + ~60k legit URLs
- [x] 2. Rebuild `phishing_dataset.csv` by running the updated build script (130k rows)
- [x] 3. Update `model_training.py` hyperparameters for the larger dataset (more trees, depth)
- [x] 4. Retrain all 4 models and save best model + metrics
- [x] 5. Verify improved, realistic metrics in `model_metrics.json`
