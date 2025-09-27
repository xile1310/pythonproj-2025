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

# Getting Started

## 🚀 Quick Setup (Recommended)

Choose one of these automated setup options from the `scripts/` folder:

### Option 1: With Virtual Environment (Recommended)
**Best for:** Most users, keeps your system clean
- Double-click `scripts/setup-with-venv.ps1` in Windows Explorer, OR
- Right-click `scripts/setup-with-venv.ps1` → "Run with PowerShell"

### Option 2: Without Virtual Environment
**Best for:** Users who prefer global installation
- Double-click `scripts/setup-without-venv.ps1` in Windows Explorer, OR
- Right-click `scripts/setup-without-venv.ps1` → "Run with PowerShell"

**Note:** If PowerShell scripts are blocked, run this command first:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 📋 Manual Setup (Alternative)

### Virtual Environment Setup
A virtual environment is an isolated Python environment that allows you to:
- Install packages specific to your project without affecting your system Python
- Avoid conflicts between different projects that might need different versions of the same package

#### Step 1: Create a virtual environment
```bash
python -m venv .venv
```

#### Step 2: Activate the virtual environment
```bash
.\.venv\Scripts\Activate.ps1
```

#### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

**Dependencies installed:**
- **Streamlit 1.36.0** - Web framework for the phishing detector interface
- **OpenPyXL 3.1.0+** - Library for reading/writing Excel files

If you encounter any installation issues, try upgrading pip first:
```bash
python -m pip install --upgrade pip
```
# Running the program
- If the scripts ran correctly, the web app should launch itself, if not you can run it manually by running this command in the terminal:
### 1: Run the Web App
- Please ensure the dependencies are all installed properly and your virual environment is activated (If you choose to use it)
```
streamlit run phish-detector-version2/app.py
```
A new window will be launched in your browser.
### 2: Evaluate on Dataset
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
