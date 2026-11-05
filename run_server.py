"""
Server launcher — run from D:/CloudGuard AI using:
  backend\\.venv\\Scripts\\python.exe run_server.py
"""
import subprocess
import sys
import os

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

result = subprocess.run(
    [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"],
    capture_output=False,
)
sys.exit(result.returncode)
