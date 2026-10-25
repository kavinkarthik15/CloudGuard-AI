@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo  Phase 4D/4E Verification — CloudGuard AI
echo ============================================================
echo.

echo [1/3] Backend pytest (230 tests expected: verified 230 passed on 2026-10-20)...
cd /d "D:\CloudGuard AI\backend"
.venv\Scripts\python.exe -m pytest --tb=short -q
if %ERRORLEVEL% neq 0 (
    echo.
    echo  BACKEND TESTS FAILED ^(exit %ERRORLEVEL%^)
    exit /b %ERRORLEVEL%
)
echo  Backend tests PASSED
echo.

echo [2/3] Frontend Vitest...
cd /d "D:\CloudGuard AI\frontend"
call npx vitest run
if %ERRORLEVEL% neq 0 (
    echo.
    echo  FRONTEND TESTS FAILED ^(exit %ERRORLEVEL%^)
    exit /b %ERRORLEVEL%
)
echo  Frontend tests PASSED
echo.

echo [3/3] Frontend production build...
call npm run build
if %ERRORLEVEL% neq 0 (
    echo.
    echo  FRONTEND BUILD FAILED ^(exit %ERRORLEVEL%^)
    exit /b %ERRORLEVEL%
)
echo  Frontend build PASSED
echo.
echo ============================================================
echo  ALL PHASE 4D/4E CHECKS PASSED
echo ============================================================
endlocal
exit /b 0
