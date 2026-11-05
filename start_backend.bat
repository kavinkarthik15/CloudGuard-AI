@echo off
echo Starting CloudGuard AI Backend...
echo NOTE: Backend binds to 127.0.0.1:8000 (local only)
cd /d "d:\CloudGuard AI\backend"
.venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
