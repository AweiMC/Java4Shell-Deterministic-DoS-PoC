#!/usr/bin/env bash
# Build the PoC. Path-independent: locates itself via $0.
set -e
cd "$(dirname "$0")"
mkdir -p out
find src -name '*.java' > sources.txt
javac -encoding UTF-8 -d out @sources.txt
rm -f sources.txt
echo "[build] OK - com.aweimc.j4shell.Main"
