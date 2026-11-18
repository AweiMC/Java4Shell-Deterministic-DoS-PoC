#!/usr/bin/env bash
# NEGATIVE CONTROL: Base64 intrinsics disabled - the server must SURVIVE (client exit code 2).
cd "$(dirname "$0")" || exit 1
mkdir -p logs
if [ ! -f out/com/aweimc/j4shell/Main.class ]; then
  echo "[run-server-safe] classes not found - run ./build.sh first"
  exit 1
fi
echo "[run-server-safe] NEGATIVE CONTROL: -XX:-UseBASE64Intrinsics (server should SURVIVE)"
exec java -Xmx768m -XX:G1HeapRegionSize=1m -Xbatch -XX:-UseBASE64Intrinsics \
  -cp out com.aweimc.j4shell.Main server --port 47470 --grid 300 "$@"
