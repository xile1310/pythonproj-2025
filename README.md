# 📧 Advanced Phishing Email Detector
A sophisticated **rule-based phishing email detector** built with Streamlit, featuring multi-layered detection using whitelist verification, keyword analysis, Levenshtein distance typosquat detection, and adaptive scoring.

## 🎯 How It Works
The detector uses a **multi-layered approach** with four integrated detection functions that compute a cumulative risk score:

### Core Detection Functions:

1. **`whitelist_check()`** - **Sender Authentication & URL Detection**
   - Verifies sender domain against trusted whitelist
   - Detects suspicious URLs in non-whitelisted emails
   - **Score**: 0.0 (whitelisted) or 0.8 (URL detected)

2. **`keyword_check()`** - **Suspicious Language Analysis**
   - Scans email content for phishing-related keywords
   - Counts and weights suspicious language patterns
   - **Score**: 1.0 × number of keywords found

3. **`edit_distance_check()`** - **Typosquat Domain Detection**
   - Uses Levenshtein distance algorithm to detect domain similarity
   - Compares found domains against legitimate domains
   - Identifies typosquat attempts (≤2 character differences)
   - **Score**: 1.0 (if typosquat detected)

4. **`safety_checks()`** - **Advanced Content Analysis & Adaptive Scoring**
   - Detects risky file attachments (.exe, .scr, etc.)
   - Identifies safe terms (newsletters, unsubscribe)
   - Implements guardrail logic (reduces false positives for low-keyword emails)
   - Provides adaptive scoring (boosts high-keyword emails)
   - **Score**: Variable based on content analysis

### Key Features:
- **Merged Function Architecture**: URL detection integrated with whitelist checking
- **Dynamic Typosquat Detection**: No predefined suspicious domain lists needed
- **Adaptive Scoring**: Adjusts penalties based on keyword intensity
- **Multi-layered Defense**: Combines sender verification, content analysis, domain similarity, and URL inspection
- **Configurable Thresholds**: All scoring weights and detection thresholds are adjustable

**Final Classification**: Emails with total score ≥ 1.5 are classified as "Phishing", while scores < 1.5 are classified as "Ham".

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
- **pytest 8.4.2+** - Testing framework for running automated tests

If you encounter any installation issues, try upgrading pip first:
```bash
python -m pip install --upgrade pip
```

# 🏃‍♂️ Running the Program

## 1. Run the Web App
```bash
streamlit run phish-detector-version2/app.py
```
A new window will be launched in your browser.

## 2. Evaluate on Datasets

### Basic Evaluation Commands:

**Run evaluation on specific dataset:**
```bash
cd phish-detector-version2
python evaluate.py --data-dir dataset
python evaluate.py --data-dir dataset2
python evaluate.py --data-dir dataset3
python evaluate.py --data-dir dataset4
```

**Run evaluation with Excel output:**
```bash
cd phish-detector-version2
python evaluate.py --data-dir dataset -out results.xlsx
```

### Complete Evaluation (All 4 Datasets):
```bash
cd phish-detector-version2
python evaluate.py --data-dir dataset
python evaluate.py --data-dir dataset2
python evaluate.py --data-dir dataset3
python evaluate.py --data-dir dataset4
```

**Example Output:**
```yaml
=== Evaluation Report ===
Dataset: dataset  |  Total: 4198 (ham=2801, phish=1397)
Accuracy : 0.7249
Confusion Matrix  TP=619  FP=377  FN=778  TN=2424
```

## 3. Run Tests

### Command Line Testing:
```bash
# From phish-detector-version2 directory
cd phish-detector-version2

# Run all tests with verbose output
python -m pytest test/test_rules.py -v

# Run tests without verbose output
python -m pytest test/test_rules.py

# Run specific test class
python -m pytest test/test_rules.py::TestWhitelistCheck -v

# Run specific test method
python -m pytest test/test_rules.py::TestWhitelistCheck::test_whitelisted_domain_score_zero -v
```

### Web Interface Testing

The web interface includes a built-in testing feature:

1. **Launch the web app:**
   ```bash
   streamlit run phish-detector-version2/app.py
   ```

2. **Navigate to the "Help & Testing" tab** in the web interface

3. **Click "🧪 Run All Tests"** button to execute the test suite

**Test Coverage (17 tests):**
- **TestWhitelistCheck (3 tests)**: Whitelisted domain scoring, URL detection, subdomain edge cases
- **TestKeywordCheck (3 tests)**: No keywords, multiple keywords, embedded keyword edge cases
- **TestEditDistanceCheck (3 tests)**: No domains, typosquat detection, exact match edge cases
- **TestSafetyChecks (3 tests)**: No attachments, adaptive boost, multiple attachments edge cases
- **TestClassifyEmail (3 tests)**: Whitelisted senders, low scores, borderline cases
- **TestExtractDomain (2 tests)**: Simple email extraction, multiple @ symbols edge cases

**💡 Pro Tip:** Run tests regularly to ensure the detector maintains accuracy over time!

# ⚙️ Configuration

`config.json` stores your customizable rules for whitelist domains, suspicious keywords, and detection thresholds.

### Adding Domains/Keywords
1. **Web Interface:** Type in the "Add domain" or "Add keyword" field and click the respective button
2. **Direct Edit:** Add new entries to the arrays in `config.json`

### Removing Domains/Keywords
1. **Web Interface:** Select items from the "Remove selected" dropdown and click "Remove" button
2. **Direct Edit:** Delete entries from the arrays in `config.json`

### Tips
- Add your company domains to `legit_domains`
- Include common phishing words in `keywords`
- Adjust `phish_score` threshold (lower = more sensitive, higher = less sensitive)
- Changes are saved automatically in web interface

# 📊 Performance Results

## Current Performance (All 4 Datasets):

| Dataset | Total Emails | Ham | Phish | Accuracy | True Positives | False Positives | False Negatives | True Negatives |
|---------|-------------|-----|-------|---------|------------------|-----------------|-----------------|----------------|
| **dataset** | 4,198 | 2,801 | 1,397 | **72.49%** | 619 | 377 | 778 | 2,424 |
| **dataset2** | 3,051 | 2,550 | 501 | **84.14%** | 195 | 178 | 306 | 2,372 |
| **dataset3** | 1,902 | 1,401 | 501 | **78.50%** | 199 | 107 | 302 | 1,294 |
| **dataset4** | 3,667 | 2,949 | 718 | **78.10%** | 224 | 309 | 494 | 2,640 |

**Overall Statistics:**
- **Total Emails Evaluated**: 12,818 emails across all datasets
- **Average Accuracy**: 78.31% across all datasets
- **Best Performance**: Dataset2 with 84.14% accuracy
- **Detection Capabilities**: 39.6% phishing detection rate, 10.0% false positive rate
