#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

GCC=gcc

OUT="build"
mkdir -p "$OUT"

# Set PSH7_DEBUG=1 before running this script to build with logging enabled
# (writes %TEMP%\psh7.log). Off by default - normal builds have no logging
# code or log-file I/O at all.
DEBUG_CFLAGS=""
if [ "${PSH7_DEBUG:-0}" = "1" ]; then
    echo "== PSH7_DEBUG=1: building with logging enabled =="
    DEBUG_CFLAGS="-DPSH7_DEBUG"
fi

MH_SRC="minhook/src"
MH_INC="minhook/include"

echo "Compiling MinHook"
"$GCC" -O2 -c "$MH_SRC/buffer.c"     -I"$MH_INC" -I"$MH_SRC" -o "$OUT/buffer.o"
"$GCC" -O2 -c "$MH_SRC/hook.c"       -I"$MH_INC" -I"$MH_SRC" -o "$OUT/hook.o"
"$GCC" -O2 -c "$MH_SRC/trampoline.c" -I"$MH_INC" -I"$MH_SRC" -o "$OUT/trampoline.o"
"$GCC" -O2 -c "$MH_SRC/hde/hde64.c"  -I"$MH_INC" -I"$MH_SRC" -o "$OUT/hde64.o"

echo "Compiling psh7.dll"
"$GCC" -O2 -shared -Wall $DEBUG_CFLAGS \
    -I"$MH_INC" \
    -o "$OUT/psh7.dll" \
    src/psh7.c \
    "$OUT/buffer.o" "$OUT/hook.o" "$OUT/trampoline.o" "$OUT/hde64.o" \
    -lversion \
    -Wl,--exclude-all-symbols \
    -Wl,--out-implib,"$OUT/psh7.lib"

echo "Compiling inject.exe"
"$GCC" -O2 -municode -o "$OUT/inject.exe" src/inject.c

echo "Done: $OUT/psh7.dll, $OUT/inject.exe"
