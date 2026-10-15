"""
Test runner script — avoids path-with-spaces shell issues.
Run from D:/CloudGuard AI using:
  backend\\.venv\\Scripts\\python.exe run_tests.py
"""
import subprocess
import sys
import os

os.chdir(os.path.join(os.path.dirname(__file__), "backend"))

result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests", "-v", "--tb=short"],
    capture_output=False,
)
sys.exit(result.returncode)
