@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist logs mkdir logs
if not exist out\com\aweimc\j4shell\Main.class (
  echo [run-server] classes not found - run build.bat first
  pause
  exit /b 1
)
echo [run-server] J4Shell-Deterministic-DoS victim starting on 127.0.0.1:47470 (Ctrl+C to stop)
echo [run-server] after a HIT the JVM will SIGSEGV - hs_err goes to logs\
java -Xmx768m -XX:G1HeapRegionSize=1m -Xbatch ^
  -XX:ErrorFile=logs\hs_err_ddh_pid%%p.log ^
  -cp out com.aweimc.j4shell.Main server --port 47470 --grid 300 %*
echo.
echo [run-server] server exited (code %errorlevel%; 1 = SIGSEGV crash, see logs\hs_err_ddh_pid*.log)
pause
