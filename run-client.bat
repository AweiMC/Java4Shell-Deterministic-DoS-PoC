@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist out\com\aweimc\j4shell\Main.class (
  echo [run-client] classes not found - run build.bat first
  pause
  exit /b 1
)
java -cp out com.aweimc.j4shell.Main client --host 127.0.0.1 --port 47470 %*
echo.
echo [run-client] finished (exit code %errorlevel%: 0=TARGET DOWN 1=hit-alive 2=survived 3=error)
pause
