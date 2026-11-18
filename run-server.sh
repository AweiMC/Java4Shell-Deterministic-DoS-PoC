#!/usr/bin/env bash
# Victim server (unpatched JDK 17 + AVX-512 VBMI required for a hit).
cd "$(dirname "$0")" || exit 1
mkdir -p logs
if [ ! -f out/com/aweimc/j4shell/Main.class ]; then
  echo "[run-server] classes not found - run ./build.sh first"
  exit 1
fi
echo "[run-server] J4Shell-Deterministic-DoS victim starting on 127.0.0.1:47470 (Ctrl+C to stop)"
echo "[run-server] after a HIT the JVM will SIGSEGV - hs_err goes to logs/"
exec java -Xmx768m -XX:G1HeapRegionSize=1m -Xbatch \
  -XX:ErrorFile=logs/hs_err_pid%p.log \
  -cp out com.aweimc.j4shell.Main server --port 47470 --grid 300 "$@"
