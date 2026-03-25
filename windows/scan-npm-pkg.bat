@echo off
REM Windows Launcher for npm Package Scanner
REM Requires Git Bash or WSL to be installed

setlocal

set "SCRIPT_DIR=%~dp0"
set "BASH_SCRIPT=%SCRIPT_DIR%..\main_script\npm_scan.sh"

REM Try to find bash (Git Bash first, then WSL)
where bash >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Starting npm Package Scanner...
    echo.
    bash "%BASH_SCRIPT%"
    goto :end
)

REM Try WSL bash
where wsl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Starting npm Package Scanner via WSL...
    echo.
    wsl bash "%BASH_SCRIPT%"
    goto :end
)

REM If neither found, show error
echo ERROR: bash not found!
echo.
echo This script requires either:
echo   1. Git Bash (included with Git for Windows)
echo   2. Windows Subsystem for Linux (WSL)
echo.
echo Please install one of these and try again:
echo   - Git for Windows: https://git-scm.com/download/win
echo   - WSL: Run 'wsl --install' in PowerShell as Administrator
echo.
pause
exit /b 1

:end
endlocal
