# aipish-email-v1 — evaluation

Generated from `evaluation_v1.json` by `python -m app.ml.report`. Do not edit by hand.

- Dataset manifest SHA-256: `d8d583a30ffc85b81010485498cc3a2f4cdf0e2beb3ca677c0eaf13bb9f60ab7`; split sizes {'train': 7899, 'validation': 1681, 'test': 1709}
- Trained classes: legitimate, impersonated, phishing, fraud; **untrained: suspicious**
- Ensemble weights (picked on validation): {'lr': 0.0, 'transformer': 0.5, 'xgb': 0.5} (validation macro-F1 0.9517)
- Seed 20261119; environment {'python': '3.13.9', 'platform': 'macOS-27.2.1-arm64-arm-64bit-Mach-O', 'numpy': '2.5.5', 'scikit_learn': '1.9.1', 'xgboost': '3.4.1', 'torch': '2.15.0', 'transformers': '4.57.6'}

## Test split

Rule-engine errors on this split: 0.

### Binary: threat (any non-legitimate class) vs legitimate

| Subset | Model | n | Precision | Recall | F1 |
|---|---|---|---|---|---|
| all | ensemble | 1709 | 0.970 | 0.926 | 0.948 |
| all | transformer | 1709 | 0.964 | 0.925 | 0.944 |
| all | xgb | 1709 | 0.958 | 0.907 | 0.932 |
| all | lr | 1709 | 0.993 | 0.779 | 0.873 |
| all | rules_suspicious_or_higher | 1709 | 0.644 | 0.418 | 0.507 |
| all | rules_phishing_fraud_likely | 1709 | 0.861 | 0.106 | 0.189 |
| real_only | ensemble | 1607 | 0.963 | 0.911 | 0.936 |
| real_only | transformer | 1607 | 0.956 | 0.909 | 0.932 |
| real_only | xgb | 1607 | 0.951 | 0.919 | 0.935 |
| real_only | lr | 1607 | 0.993 | 0.853 | 0.917 |
| real_only | rules_suspicious_or_higher | 1607 | 0.619 | 0.454 | 0.524 |
| real_only | rules_phishing_fraud_likely | 1607 | 0.861 | 0.129 | 0.224 |
| synthetic_only | ensemble | 102 | 1.000 | 1.000 | 1.000 |
| synthetic_only | transformer | 102 | 1.000 | 1.000 | 1.000 |
| synthetic_only | xgb | 102 | 1.000 | 0.853 | 0.921 |
| synthetic_only | lr | 102 | 1.000 | 0.431 | 0.603 |
| synthetic_only | rules_suspicious_or_higher | 102 | 1.000 | 0.245 | 0.394 |
| synthetic_only | rules_phishing_fraud_likely | 102 | 0.000 | 0.000 | 0.000 |
| sender_disjoint | ensemble | 1514 | 0.953 | 0.892 | 0.922 |
| sender_disjoint | transformer | 1514 | 0.945 | 0.889 | 0.917 |
| sender_disjoint | xgb | 1514 | 0.936 | 0.861 | 0.897 |
| sender_disjoint | lr | 1514 | 0.989 | 0.671 | 0.799 |
| sender_disjoint | rules_suspicious_or_higher | 1514 | 0.551 | 0.427 | 0.481 |
| sender_disjoint | rules_phishing_fraud_likely | 1514 | 0.778 | 0.090 | 0.161 |

### Five-class (ML models only; the rule engine has no 5-class output)

| Subset | Model | macro-P | macro-R | macro-F1 | F1 legitimate | F1 suspicious | F1 impersonated | F1 phishing | F1 fraud |
|---|---|---|---|---|---|---|---|---|---|
| all | ensemble | 0.964 | 0.966 | 0.965 | 0.974 | – | 0.973 | 0.935 | 0.977 |
| all | transformer | 0.966 | 0.972 | 0.969 | 0.972 | – | 0.986 | 0.931 | 0.985 |
| all | xgb | 0.851 | 0.781 | 0.735 | 0.966 | – | 0.667 | 0.935 | 0.370 |
| all | lr | 0.719 | 0.606 | 0.647 | 0.944 | – | 0.000 | 0.911 | 0.731 |
| real_only | ensemble | 0.963 | 0.947 | 0.954 | 0.974 | – | – | 0.935 | – |
| real_only | transformer | 0.960 | 0.943 | 0.951 | 0.972 | – | – | 0.931 | – |
| real_only | xgb | 0.958 | 0.949 | 0.954 | 0.973 | – | – | 0.935 | – |
| real_only | lr | 0.967 | 0.925 | 0.943 | 0.968 | – | – | 0.917 | – |
| synthetic_only | ensemble | 0.974 | 0.985 | 0.979 | – | – | 0.973 | – | 0.985 |
| synthetic_only | transformer | 1.000 | 1.000 | 1.000 | – | – | 1.000 | – | 1.000 |
| synthetic_only | xgb | 0.750 | 0.614 | 0.518 | – | – | 0.667 | – | 0.370 |
| synthetic_only | lr | 0.500 | 0.288 | 0.365 | – | – | 0.000 | – | 0.731 |
| sender_disjoint | ensemble | 0.958 | 0.951 | 0.954 | 0.974 | – | 0.973 | 0.890 | 0.977 |
| sender_disjoint | transformer | 0.958 | 0.956 | 0.957 | 0.972 | – | 0.986 | 0.883 | 0.985 |
| sender_disjoint | xgb | 0.842 | 0.768 | 0.723 | 0.966 | – | 0.667 | 0.889 | 0.370 |
| sender_disjoint | lr | 0.715 | 0.582 | 0.630 | 0.945 | – | 0.000 | 0.846 | 0.731 |

### Ensemble confusion matrix (all; rows = true, columns = predicted)

| true \ pred | legitimate | suspicious | impersonated | phishing | fraud | support |
|---|---|---|---|---|---|---|
| legitimate | 1108 | 0 | 0 | 17 | 0 | 1125 |
| suspicious | 0 | 0 | 0 | 0 | 0 | 0 |
| impersonated | 0 | 0 | 36 | 0 | 0 | 36 |
| phishing | 43 | 0 | 0 | 438 | 1 | 482 |
| fraud | 0 | 0 | 2 | 0 | 64 | 66 |

## Validation split

Rule-engine errors on this split: 0.

### Binary: threat (any non-legitimate class) vs legitimate

| Subset | Model | n | Precision | Recall | F1 |
|---|---|---|---|---|---|
| all | ensemble | 1681 | 0.987 | 0.948 | 0.967 |
| all | transformer | 1681 | 0.983 | 0.955 | 0.969 |
| all | xgb | 1681 | 0.977 | 0.896 | 0.934 |
| all | lr | 1681 | 0.998 | 0.714 | 0.832 |
| all | rules_suspicious_or_higher | 1681 | 0.771 | 0.478 | 0.591 |
| all | rules_phishing_fraud_likely | 1681 | 0.909 | 0.162 | 0.275 |
| real_only | ensemble | 1607 | 0.985 | 0.950 | 0.967 |
| real_only | transformer | 1607 | 0.981 | 0.956 | 0.969 |
| real_only | xgb | 1607 | 0.974 | 0.936 | 0.955 |
| real_only | lr | 1607 | 0.997 | 0.807 | 0.892 |
| real_only | rules_suspicious_or_higher | 1607 | 0.771 | 0.552 | 0.643 |
| real_only | rules_phishing_fraud_likely | 1607 | 0.909 | 0.187 | 0.310 |
| synthetic_only | ensemble | 74 | 1.000 | 0.932 | 0.965 |
| synthetic_only | transformer | 74 | 1.000 | 0.946 | 0.972 |
| synthetic_only | xgb | 74 | 1.000 | 0.635 | 0.777 |
| synthetic_only | lr | 74 | 1.000 | 0.108 | 0.195 |
| synthetic_only | rules_suspicious_or_higher | 74 | 0.000 | 0.000 | 0.000 |
| synthetic_only | rules_phishing_fraud_likely | 74 | 0.000 | 0.000 | 0.000 |
| sender_disjoint | ensemble | 1448 | 0.977 | 0.923 | 0.949 |
| sender_disjoint | transformer | 1448 | 0.971 | 0.944 | 0.958 |
| sender_disjoint | xgb | 1448 | 0.957 | 0.820 | 0.883 |
| sender_disjoint | lr | 1448 | 0.994 | 0.532 | 0.694 |
| sender_disjoint | rules_suspicious_or_higher | 1448 | 0.605 | 0.375 | 0.463 |
| sender_disjoint | rules_phishing_fraud_likely | 1448 | 0.820 | 0.127 | 0.220 |

### Five-class (ML models only; the rule engine has no 5-class output)

| Subset | Model | macro-P | macro-R | macro-F1 | F1 legitimate | F1 suspicious | F1 impersonated | F1 phishing | F1 fraud |
|---|---|---|---|---|---|---|---|---|---|
| all | ensemble | 0.964 | 0.940 | 0.952 | 0.984 | – | 0.875 | 0.968 | 0.980 |
| all | transformer | 0.919 | 0.944 | 0.931 | 0.985 | – | 0.792 | 0.965 | 0.980 |
| all | xgb | 0.577 | 0.661 | 0.606 | 0.970 | – | 0.500 | 0.955 | 0.000 |
| all | lr | 0.467 | 0.452 | 0.456 | 0.934 | – | 0.000 | 0.890 | 0.000 |
| real_only | ensemble | 0.984 | 0.971 | 0.977 | 0.986 | – | – | 0.968 | – |
| real_only | transformer | 0.984 | 0.968 | 0.976 | 0.987 | – | – | 0.965 | – |
| real_only | xgb | 0.974 | 0.963 | 0.968 | 0.981 | – | – | 0.955 | – |
| real_only | lr | 0.961 | 0.903 | 0.926 | 0.960 | – | – | 0.892 | – |
| synthetic_only | ensemble | 1.000 | 0.910 | 0.951 | – | – | 0.913 | – | 0.990 |
| synthetic_only | transformer | 1.000 | 0.920 | 0.957 | – | – | 0.913 | – | 1.000 |
| synthetic_only | xgb | 0.192 | 0.360 | 0.250 | – | – | 0.500 | – | 0.000 |
| synthetic_only | lr | 0.000 | 0.000 | 0.000 | – | – | 0.000 | – | 0.000 |
| sender_disjoint | ensemble | 0.962 | 0.932 | 0.947 | 0.986 | – | 0.875 | 0.946 | 0.980 |
| sender_disjoint | transformer | 0.917 | 0.938 | 0.927 | 0.988 | – | 0.792 | 0.946 | 0.980 |
| sender_disjoint | xgb | 0.570 | 0.646 | 0.595 | 0.970 | – | 0.500 | 0.910 | 0.000 |
| sender_disjoint | lr | 0.466 | 0.414 | 0.431 | 0.937 | – | 0.000 | 0.788 | 0.000 |

### Ensemble confusion matrix (all; rows = true, columns = predicted)

| true \ pred | legitimate | suspicious | impersonated | phishing | fraud | support |
|---|---|---|---|---|---|---|
| legitimate | 1118 | 0 | 1 | 5 | 1 | 1125 |
| suspicious | 0 | 0 | 0 | 0 | 0 | 0 |
| impersonated | 4 | 0 | 21 | 0 | 0 | 25 |
| phishing | 24 | 0 | 1 | 457 | 0 | 482 |
| fraud | 1 | 0 | 0 | 0 | 48 | 49 |

