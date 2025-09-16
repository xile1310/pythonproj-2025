# Phishing Email Rule-Based Detector (Streamlit)

This beginner-friendly Streamlit app detects potential phishing emails using simple rules. Upload any file; the app renames it to `.txt` before processing, tokenizes it, runs rule tests, and outputs per-test results plus a final score.

## Features
- Whitelist Check
- Keyword Position Scoring
- Edit Distance Check
- Suspicious URL Detection
- Final Risk Scoring (score > 10 => Phishing)

## Install (Windows PowerShell)
```powershell
cd $env:USERPROFILE\phish-detector
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run
```powershell
streamlit run app.py
```

## Use
1) Click Browse files to upload any file.  
2) Click Analyze Email  
3) See: Whitelist, Keyword Position, Edit Distance, Suspicious URLs, Final Scoring.  
4) Final score > 10 => Phishing, else Safe.

Dataset reference: SpamAssassin Public Corpus â€” `https://www.kaggle.com/datasets/beatoa/spamassassin-public-corpus`
