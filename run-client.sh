#!/usr/bin/env bash
# Attack client. Exit codes: 0=TARGET DOWN 1=hit-alive 2=survived 3=error.
cd "$(dirname "$0")" || exit 1
if [ ! -f out/com/aweimc/j4shell/Main.class ]; then
  echo "[run-client] classes not found - run ./build.sh first"
  exit 1
fi
java -cp out com.aweimc.j4shell.Main client --host 127.0.0.1 --port 47470 "$@"
code=$?
echo "[run-client] finished (exit code $code: 0=TARGET DOWN 1=hit-alive 2=survived 3=error)"
exit $code
