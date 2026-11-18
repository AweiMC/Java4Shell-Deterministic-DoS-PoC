@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist out mkdir out
dir /s /b src\*.java > sources.txt 2>nul
javac -encoding UTF-8 -d out @sources.txt
if errorlevel 1 (
  echo.
  echo [build] FAILED - check javac output above
  del sources.txt 2>nul
  pause
  exit /b 1
)
del sources.txt 2>nul
echo [build] OK - com.aweimc.j4shell.Main
pause
