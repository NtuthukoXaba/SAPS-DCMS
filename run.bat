@echo off
REM SAPS-DCMS - one-click start for Windows
cd /d "%~dp0"
if not exist .venv (
    echo Creating virtual environment...
    python -m venv .venv
)
call .venv\Scripts\activate
pip install -q -r requirements.txt
python app.py
pause
