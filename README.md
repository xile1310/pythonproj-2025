# 📧 Simple Phishing Email Detector
A lightweight **rule-based phishing email detector** built with Streamlit.
It classifies emails as **Safe** or **Phishing** based on configurable rules such as domain whitelists, suspicious keywords, edit distance checks, and URL heuristics.

## How it works?
The detector analyzes emails using four rule-based checks and assigns penalty points:

- **Domain check** → +2 points if sender not in whitelist
- **Keyword check** → +3 points per keyword in subject, +1 point per keyword in body, +2 points if keyword appears early in body
- **Edit distance check** → +5 points for lookalike domains (e.g., paypa1.com vs paypal.com)
- **Suspicious URL check** → +5 points for IP-based links, +3 points for user@host links, +4 points for claimed-domain mismatch

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
- **pytest 6.0.0+** - Testing framework for running automated tests

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

### Adding Domains/Keywords
1. **Web Interface:** Type in the "Add domain" or "Add keyword" field and click the respective button
2. **Direct Edit:** Add new entries to the arrays in `config.json`

### Removing Domains/Keywords
1. **Web Interface:** Select items from the "Remove selected" dropdown and click "Remove" button
2. **Direct Edit:** Delete entries from the arrays in `config.json`

### Tips
- Add your company domains to `legit_domains`
- Include common phishing words in `keywords`
- Changes are saved automatically in web interface

# 🧪 Testing

Run tests to verify the detector is working correctly:

## 🌐 Web Interface Testing

The web interface includes a built-in testing feature that allows you to run all tests directly from the browser:

### Accessing the Testing Feature

1. **Launch the web app:**
   ```bash
   streamlit run phish-detector-version2/app.py
   ```

2. **Navigate to the "Help & Testing" tab** in the web interface

3. **Click "🧪 Run All Tests"** button to execute the test suite

### Command Line Testing

```bash
# From phish-detector-version2 directory
cd phish-detector-version2

# Run tests
cd test
pytest -v

# Or run directly
python test_rules.py
```

**Tests include:**
- Whitelist domain checking
- Keyword detection and scoring
- Lookalike domain detection
- URL pattern detection  
- Email classification

**💡 Pro Tip:** Run the web interface tests regularly to ensure the detector maintains accuracy over time!

# 💡 Troubleshooting

## 🚀 Application Launch Issues

**Web app won't start:**
- **Check Python version:** Ensure Python 3.8+ is installed
  ```bash
  python --version
  ```
- **Verify dependencies:** Install all required packages
  ```bash
  pip install -r requirements.txt
  ```
- **Check port availability:** Default port 8501 might be in use
  ```bash
  streamlit run phish-detector-version2/app.py --server.port 8502
  ```
- **Permission issues on Windows:** Run PowerShell as administrator

**Import errors:**
- **Missing modules:** Reinstall dependencies
  ```bash
  pip install --upgrade streamlit openpyxl pytest
  ```
- **Virtual environment:** Ensure you're in the correct environment
  ```bash
  .\.venv\Scripts\Activate.ps1  # Windows
  source .venv/bin/activate     # Linux/Mac
  ```

## 📦 Dependency Version Issues

**Required versions:**
- **Streamlit:** 1.36.0 (web interface)
- **OpenPyXL:** 3.1.0+ (Excel file handling)
- **pytest:** 6.0.0+ (testing framework)
- **Python:** 3.8+ (runtime)

**Version conflicts:**
```bash
# Check installed versions
pip list | findstr streamlit
pip list | findstr openpyxl
pip list | findstr pytest

# Upgrade specific packages
pip install --upgrade streamlit==1.36.0
pip install --upgrade openpyxl>=3.1.0
pip install --upgrade pytest>=6.0.0
```

**Clean installation:**
```bash
# Uninstall and reinstall
pip uninstall streamlit openpyxl pytest
pip install -r requirements.txt
```


