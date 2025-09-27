# 📧 Simple Phishing Email Detector
A lightweight **rule-based phishing email detector** built with Streamlit.
It classifies emails as **Safe** or **Phishing** based on configurable rules such as domain whitelists, suspicious keywords, edit distance checks, and URL heuristics.

# How it works?
- Domain check → penalty if sender not in whitelist
- Keyword check → weighted score for suspicious keywords in subject/body
- Edit distance check → catch lookalike domains (e.g., paypa1.com)
- Suspicious URL check → IP-based links, user@host links, claimed-domain mismatch

Final classification:
- Safe if score ≤ 10
- Phishing if score > 10
Rules and thresholds are customizable by config.json

# Getting Started
## (Optional) Activating virtual environment
- A virtual environment is an isolated Python environment that allows you to:
Install packages specific to your project without affecting your system Python
Avoid conflicts between different projects that might need different versions of the same package

### Step 1: Create a virtual environment
- Run this command in your terminal
```
python -m venv .venv
```
### Step 2: Activating the virtual environment
- You should see `(.venv)` in your terminal prompt upon running this command
```
.\.venv\Scripts\Activate.ps1
```

## Installing Dependencies

Once your virtual environment is activated, install the required packages:

```bash
pip install -r requirements.txt
```

This will install:
- **Streamlit 1.36.0** - Web framework for the phishing detector interface
- **OpenPyXL 3.1.0+** - Library for reading/writing Excel files

**Note:** Make sure your virtual environment is activated (you should see `(.venv)` in your terminal prompt) before running this command.

If you encounter any installation issues, try upgrading pip first:
```bash
python -m pip install --upgrade pip
```
1. Run the Web App
```
streamlit run phish-detector-version2/app.py
```

2. Evaluate on Dataset
```
python3 evaluate.py --data-dir dataset --out results.csv
```
```
python .\phish-detector-version2\evaluate.py --data-dir .\phish-detector-version2\dataset --out .\phish-detector-version2\results.csv
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
# Dataset reference
SpamAssassin Public Corpus” `https://www.kaggle.com/datasets/beatoa/spamassassin-public-corpus`
