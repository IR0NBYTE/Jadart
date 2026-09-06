# XORGate

A small Flutter crackme, built to be taken apart with Jadart. One screen, one text
field, one button: type the licence key, get the flag.

```
challenges/xorgate/
  xorgate.apk           the challenge
  play.command          opens a shell here with jadart ready
  app/lib/main.dart     the source, so you can see what the answer was
  app/pubspec.yaml
```

`xorgate.apk` is a release build from Flutter 3.44.4 (Dart 3.12.2), arm64 only, no
obfuscation. Install it on a device or an emulator if you want to play with it first:

```bash
adb install -r xorgate.apk
```

## The point

Neither of the two things you want is a string you can grep for.

The licence is compared inside compiled code. The flag is stored as a table of bytes
XORed against a repeating pad, so it is not a literal either. `strings` on this APK
returns 91,246 lines, and the flag is in none of them. That wall is why people believe
AOT hides their logic.

## Try it

Every command takes the APK directly. There is no need to unzip anything first.

```bash
jadart info      xorgate.apk              # which Dart release, and is it supported
jadart verify    xorgate.apk              # did the parse really work
jadart classes   xorgate.apk -f Gate      # the app's own classes
jadart decompile xorgate.apk FlagGate     # the licence, and the shape of the loop
jadart constants xorgate.apk              # the table the loop reads
```

`decompile` gives you the licence and the algorithm. `constants` gives you the table.
Those two together are the whole challenge, and the second one is where most tooling
stops: a const list is data, not code, and a disassembler will show you the arithmetic
over it without ever telling you what was in it.

Flag format is `IR0NBYTE{...}`. Work it out before you open `app/lib/main.dart`.

A full walkthrough, command by command, is written up here:
<https://github.com/IR0NBYTE/IronByte-Blog/blob/main/posts/flutter-reverse-engineering/02-xorgate-walkthrough.md>

## Rebuilding it

```bash
cd app
flutter create --platforms=android --org me.ir0nbyte --project-name xorgate .
flutter build apk --release --target-platform android-arm64
```

`flutter create` in an existing directory fills in the Android scaffolding around the
`lib/` and `pubspec.yaml` that are already there. Build it with a different Flutter
version and you get a different snapshot format, which is a fine way to check that Jadart
means what it says about epochs.
