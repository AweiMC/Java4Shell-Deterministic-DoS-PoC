@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist out\com\aweimc\j4shell\Main.class (
  echo [run-server-safe] classes not found - run build.bat first
  pause
  exit /b 1
)
echo [run-server-safe] NEGATIVE CONTROL: -XX:-UseBASE64Intrinsics (server should SURVIVE)
java -Xmx768m -XX:G1HeapRegionSize=1m -Xbatch -XX:-UseBASE64Intrinsics ^
  -cp out com.aweimc.j4shell.Main server --port 47470 --grid 300 %*
echo.
echo [run-server-safe] server exited (code %errorlevel%)
pause
