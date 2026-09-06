#!/bin/zsh
# Opens a shell in the XORGate challenge folder with jadart on PATH.
# Double-click it in Finder, or run it from anywhere.

cd "$(dirname "$0")" || exit 1
REPO="$(cd ../.. && pwd)"

if [ -f "$REPO/.venv/bin/activate" ]; then
  source "$REPO/.venv/bin/activate"
else
  echo "No .venv in $REPO. Create one with:"
  echo "  python3 -m venv $REPO/.venv && $REPO/.venv/bin/pip install '$REPO/framework[disasm]'"
fi

print -P ""
print -P "%B%F{cyan}XORGate%f%b   $(jadart --version 2>/dev/null | head -1)"
print -P "%F{242}$(pwd)%f"
print -P ""
print -P "  The licence is compared in compiled code. The flag is a XOR table."
print -P "  Neither falls out of strings. Work it out before opening app/lib/main.dart."
print -P ""
print -P "%F{242}  1.%f jadart info      xorgate.apk             %F{242}# which Dart release%f"
print -P "%F{242}  2.%f jadart verify    xorgate.apk             %F{242}# did the parse really work%f"
print -P "%F{242}  3.%f jadart classes   xorgate.apk -f Gate     %F{242}# the app's own classes%f"
print -P "%F{242}  4.%f strings -n 4 xorgate.apk | grep IR0NBYTE   %F{242}# nothing, on purpose%f"
print -P "%F{242}  5.%f jadart decompile xorgate.apk FlagGate    %F{242}# the licence and the loop%f"
print -P "%F{242}  6.%f jadart constants xorgate.apk             %F{242}# the table the loop reads%f"
print -P ""
print -P "%F{242}  jadart <command> --help  for any of them.%f"
print -P ""

exec "$SHELL" -i
