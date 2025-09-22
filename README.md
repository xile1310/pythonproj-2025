# 📧 Simple Phishing Email Detector
A lightweight **rule-based phishing email detector** built with Streamlit.
It classifies emails as **Safe** or **Phishing** based on configurable rules such as domain whitelists, suspicious keywords, edit distance checks, and URL heuristics.

# How it works?
- Domain check → penalty if sender not in whitelist
- Keyword check → weighted score for suspicious keywords in subject/body
- Edit distance check → catch lookalike domains (e.g., paypa1.com)
- Suspicious URL check → IP-based links, user@host links, claimed-domain mismatch

Final classification:
- Safe if score ≤ 4
- Phishing if score > 4
Rules and thresholds are customizable by config.json

1. Run the Web App
```
pip install -r requirements.txt
```
```
streamlit run app.py
```

2. Evaluate on Dataset
```
python3 evaluate.py --data-dir dataset --out results.csv
```
```yaml
  Example Output:
  === Evaluation Report ===
  Dataset: dataset  |  Total: 4198 (ham=2801, phish=1397)
  Accuracy : 0.7273
  Confusion Matrix  TP=270  FP=18  FN=1127  TN=2783
```

# Configuaration
config.json stores your rules for whitelist domain and keywords.
```json
{
  "legit_domains": ["google.com", "paypal.com", "redhat.com", "singapore.tech.edu.sg"],
  "keywords": ["account", "click", "password", "urgent", "verify"]
}

```



# Phishing Email Rule-Based Detector (Streamlit)

This beginner-friendly Streamlit app detects potential phishing emails using simple rules. Upload any file; the app renames it to `.txt` before processing, tokenizes it, runs rule tests, and outputs per-test results plus a final score.

## Features
- Whitelist Check
- Keyword Position Scoring
- Edit Distance Check
- Suspicious URL Detection
- Final Risk Scoring (score > 10 => Phishing)

## Activating virtual environment
```
python -m venv .venv
```
```
.\.venv\Scripts\Activate.ps1
```

## Installing Dependencies
```
pip install -r requirements.txt
```

## Run
```
streamlit run phish-detector/app.py
```

Dataset reference: SpamAssassin Public Corpus” `https://www.kaggle.com/datasets/beatoa/spamassassin-public-corpus`
