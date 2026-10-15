@echo off
cd /d "d:\CloudGuard AI\backend"
.venv\Scripts\python.exe -m pytest tests -v --tb=short
