# XORGate

A small Flutter crackme, built to be taken apart with Jadart. One screen, one text
field, one button: type the licence key, get the flag.

```
challenges/xorgate/
  app/lib/main.dart     the source, so you can see what the answer was
  app/pubspec.yaml
  bin/libapp.so         the compiled arm64 snapshot, which is what you analyse
```

`bin/libapp.so` is a release build from Flutter 3.44.4 (Dart 3.12.2), arm64, no
obfuscation. That one file is all any of the commands below need.

## The point

Neither of the two things you want is a string in the binary.

The licence is compared inside compiled code, so `strings` never sees it. The flag is
stored as a table of bytes XORed against a repeating pad, so it is not a literal either.
`strings` on this file gives you the pad and the button labels and nothing else, which is
exactly the wall that makes people believe AOT hides their logic.

## Try it

```bash
jadart info      challenges/xorgate/bin/libapp.so    # which Dart release
jadart verify    challenges/xorgate/bin/libapp.so    # did the parse really work
jadart classes   challenges/xorgate/bin/libapp.so -f Gate
jadart strings   challenges/xorgate/bin/libapp.so -g sourdough
jadart decompile challenges/xorgate/bin/libapp.so FlagGate
jadart constants challenges/xorgate/bin/libapp.so
```

`decompile` gives you the licence and the shape of the loop. `constants` gives you the
table the loop reads. Those two together are the whole challenge, and the second one is
where most tooling stops: a const list is data, not code, and a disassembler will show you
the arithmetic over it without ever telling you what was in it.

Flag format is `IR0NBYTE{...}`. Work it out before you open `app/lib/main.dart`.

A full walkthrough, command by command, is written up here:
<https://github.com/IR0NBYTE/IronByte-Blog/blob/main/posts/flutter-reverse-engineering/02-xorgate-walkthrough.md>

## Rebuilding it

```bash
cd app
flutter create --platforms=android --org me.ir0nbyte --project-name xorgate .
flutter build apk --release --target-platform android-arm64
unzip -o build/app/outputs/flutter-apk/app-release.apk lib/arm64-v8a/libapp.so
```

`flutter create` in an existing directory fills in the Android scaffolding around the
`lib/` and `pubspec.yaml` that are already there. Build it with a different Flutter
version and you get a different snapshot format, which is a fine way to check that Jadart
means what it says about epochs.
