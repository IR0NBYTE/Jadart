#!/usr/bin/env bash
# FluBench Phase 0 corpus build: compile the construct app clean and obfuscated,
# extract the arm64 libapp.so from each, and keep the split-debug-info symbols.
#
# Multi-Dart-version sweep is a later expansion (needs FVM + multiple SDKs); this
# builds with whatever `flutter` is on PATH and records its Dart version.
set -euo pipefail

# Needs `flutter` on PATH and a JDK that Gradle accepts. On a Mac with Android Studio the
# bundled runtime is the safe choice, so it is used when JAVA_HOME is unset and it exists.
[ -d /opt/homebrew/bin ] && export PATH="/opt/homebrew/bin:$PATH"
_jbr="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
[ -z "${JAVA_HOME:-}" ] && [ -d "$_jbr" ] && export JAVA_HOME="$_jbr"

HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HERE/app"
ART="$HERE/artifacts"
mkdir -p "$ART"

DART_VER="$(flutter --version 2>/dev/null | grep -oE 'Dart [0-9.]+' | head -1 | awk '{print $2}')"
echo "flutter/dart: $(flutter --version 2>/dev/null | head -1) / Dart $DART_VER"
echo "$DART_VER" > "$ART/dart_version.txt"

cd "$APP"

echo "== clean build =="
flutter build apk --release
unzip -o -q build/app/outputs/flutter-apk/app-release.apk lib/arm64-v8a/libapp.so -d "$ART/clean"

echo "== obfuscated build =="
flutter build apk --release --obfuscate --split-debug-info="$ART/symbols"
unzip -o -q build/app/outputs/flutter-apk/app-release.apk lib/arm64-v8a/libapp.so -d "$ART/obf"

echo "artifacts:"
ls -lh "$ART/clean/lib/arm64-v8a/libapp.so" "$ART/obf/lib/arm64-v8a/libapp.so"
echo "symbols: $(ls "$ART/symbols" 2>/dev/null | tr '\n' ' ')"
