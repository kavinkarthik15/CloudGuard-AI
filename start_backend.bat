@echo off
echo Starting CloudGuard AI Backend...
cd /d "d:\CloudGuard AI\backend"
.venv\Scripts\python.exe -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
