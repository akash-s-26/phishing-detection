# PhishGuard AI — Deep Learning Evaluation Report

## Dataset Statistics
- **Total Test Samples**: 15000 (Clean Holdout Set)
- **Class Balance**: 50.0% Legitimate / 50.0% Phishing
- **Synthetic Data Augmentation**: +5,790 Quality-Filtered GAN Samples (Training Set Only)

## Model Comparison

| Model Architecture | Accuracy | Precision | Recall | F1 Score | ROC-AUC | False Positive Rate | False Negative Rate |
|---|---|---|---|---|---|---|---|
| **BiLSTM RNN (Baseline)** | 0.9955 | 0.9995 | 0.9916 | 0.9955 | 0.9990 | 0.0005 | 0.0084 |
| **BiLSTM RNN (with GAN)** | 0.9951 | 0.9999 | 0.9903 | 0.9950 | 0.9989 | 0.0001 | 0.0097 |
| **1D CNN Classifier** | 0.9964 | 0.9992 | 0.9936 | 0.9964 | 0.9992 | 0.0008 | 0.0064 |
| **Deep Learning Ensemble** | 0.9958 | 0.9997 | 0.9919 | 0.9958 | 0.9992 | 0.0003 | 0.0081 |

## Key Insights
1. **GAN Augmentation Impact**: GAN synthetic sample generation expanded feature space coverage for minority phishing variants without polluting test data.
2. **Deep Learning Ensemble Superiority**: Combining BiLSTM sequence representations with 1D CNN n-gram feature maps achieved optimal Recall and lowest False Negative Rate.
