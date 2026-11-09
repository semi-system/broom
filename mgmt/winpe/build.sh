#!/bin/bash
# winpe/build.sh — build broom-report.exe ("Add hardware", Windows PE side) → ../scripts/broom-report.exe.
# The exe is committed (embedded as an asset), so a normal build needs no mingw; rerun after changing broom-report.c.
# Needs: mingw-w64 (Debian/Ubuntu: apt install gcc-mingw-w64-x86-64).
set -euo pipefail
cd "$(dirname "$0")"
x86_64-w64-mingw32-gcc -O2 -s -static -Wall -Wextra -o ../scripts/broom-report.exe broom-report.c -lwinhttp
sha256sum ../scripts/broom-report.exe
