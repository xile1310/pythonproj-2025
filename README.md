# 📧 Simple Phishing Email Detector
A lightweight **rule-based phishing email detector** built with Streamlit.
It classifies emails as **Safe** or **Phishing** based on configurable rules such as domain whitelists, suspicious keywords, edit distance checks, and URL heuristics.

## How it works?
The detector analyzes emails using four rule-based checks and assigns penalty points:

- **Domain check** → +2 points if sender not in whitelist
- **Keyword check** → +3 points per keyword in subject, +1 point per keyword in body, +2 points if keyword appears early in body
- **Edit distance check** → +5 points for lookalike domains (e.g., paypa1.com vs paypal.com)
- **Suspicious URL check** → +5 points for IP-based links, +4 points for user@host links, +5 points for claimed-domain mismatch

**Final classification:**
- Safe if total score ≤ 10
- Phishing if total score > 10

# 🚀 Getting Started

## Quick Setup (Recommended)

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

## Manual Setup (Alternative)

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
- Please ensure the dependencies are all installed properly and your virual environment is activated (If you choose to use it)
- If the scripts ran correctly, the web app should launch itself, if not you can run it manually by running this command in the terminal:
### 1: Run the Web App
```
streamlit run phish-detector-version2/app.py
```
A new window will be launched in your browser.
### 2: Evaluate on Dataset
- To evaluate large number of email files, upload the files into the dataset and run this command:
```
python3 evaluate.py --data-dir dataset --out results.csv
```
If the command does not work, use this command instead:
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

# ⚙️ Configuration

`config.json` stores your customizable rules for whitelist domains and suspicious keywords.

## Modify Settings
- **Web Interface:** Use the "Settings" tab in the app (recommended)
- **Direct Edit:** Edit `phish-detector-version2/config.json`


## Tips
- Add your company domains to `legit_domains`
- Include common phishing words in `keywords`
- Changes are saved automatically in web interface
