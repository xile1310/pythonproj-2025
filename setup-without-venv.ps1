# setup-without-venv.ps1 - Auto-setup script WITHOUT virtual environment
Write-Host "Starting Phishing Detector Setup (WITHOUT Virtual Environment)..." -ForegroundColor Green

# Step 1: Install dependencies globally
Write-Host "Installing dependencies globally..." -ForegroundColor Yellow
pip install -r requirements.txt

# Step 2: Launch the application
Write-Host "Setup complete! Launching Phishing Detector..." -ForegroundColor Green
Write-Host "A new window will be launched in your browser at http://localhost:8501" -ForegroundColor Cyan
streamlit run phish-detector-version2/app.py
