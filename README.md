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
