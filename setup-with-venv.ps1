# setup-with-venv.ps1 - Auto-setup script WITH virtual environment
Write-Host "Starting Phishing Detector Setup (WITH Virtual Environment)..." -ForegroundColor Green

# Step 1: Create virtual environment
Write-Host "Creating virtual environment..." -ForegroundColor Yellow
python -m venv .venv

# Step 2: Activate virtual environment and install dependencies
Write-Host "Activating virtual environment and installing dependencies..." -ForegroundColor Yellow
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Step 3: Launch the application
Write-Host "Setup complete! Launching Phishing Detector..." -ForegroundColor Green
Write-Host "A new window will be launched in your browser at http://localhost:8501" -ForegroundColor Cyan
streamlit run phish-detector-version2/app.py
