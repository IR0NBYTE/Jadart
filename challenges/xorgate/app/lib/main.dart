// XORGate: a deliberately small Flutter crackme.
//
// One screen, one text field, one button. Type the licence, get the flag. The
// point of the exercise is that neither the licence nor the flag can be read
// out of the binary with `strings`: the licence is compared inside compiled
// code, and the flag is stored as a table of bytes XORed against a pad.
//
// Build:  flutter build apk --release
// Target: lib/arm64-v8a/libapp.so inside the APK.

import 'dart:convert';

import 'package:flutter/material.dart';

void main() => runApp(const XorGateApp());

/// The gate. Everything that matters to a reverse engineer is in here.
class FlagGate {
  /// The flag, byte by byte, XORed against [_pad]. Not a string literal, so it
  /// never appears in the snapshot's string pool.
  static const List<int> sealed = [
    0x3a, 0x3d, 0x45, 0x3c, 0x26, 0x36, 0x21, 0x22, 0x13,
    0x0b, 0x5f, 0x07, 0x2d, 0x14, 0x5b, 0x11, 0x52, 0x37,
    0x47, 0x1d, 0x46, 0x2d, 0x0a, 0x5f, 0x01, 0x38, 0x0d,
    0x1d, 0x0c, 0x07, 0x0b, 0x14, 0x1b, 0x44, 0x57, 0x06,
    0x0e,
  ];

  /// The pad, repeated over the table. A literal, because something has to
  /// XOR back.
  static const String pad = 'sourdough';

  /// The licence. Compared in compiled code rather than looked up in a table.
  @pragma('vm:never-inline')
  bool accepts(String licence) {
    return licence == 'CAKE-2026-FREE';
  }

  /// Reassemble the flag. Only ever called once the licence checks out.
  @pragma('vm:never-inline')
  String open(String licence) {
    if (!accepts(licence)) {
      return 'DENIED';
    }
    final out = <int>[];
    for (var i = 0; i < sealed.length; i++) {
      out.add(sealed[i] ^ pad.codeUnitAt(i % pad.length));
    }
    return utf8.decode(out);
  }
}

class XorGateApp extends StatelessWidget {
  const XorGateApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'XORGate',
      theme: ThemeData.dark(useMaterial3: true),
      home: const GateScreen(),
    );
  }
}

class GateScreen extends StatefulWidget {
  const GateScreen({super.key});

  @override
  State<GateScreen> createState() => _GateScreenState();
}

class _GateScreenState extends State<GateScreen> {
  final _controller = TextEditingController();
  final _gate = FlagGate();
  String _result = '';

  void _submit() {
    setState(() => _result = _gate.open(_controller.text.trim()));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('XORGate')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text('Enter your licence key.'),
            const SizedBox(height: 16),
            TextField(
              controller: _controller,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                hintText: 'XXXX-XXXX-XXXX',
              ),
            ),
            const SizedBox(height: 16),
            FilledButton(onPressed: _submit, child: const Text('Unlock')),
            const SizedBox(height: 24),
            SelectableText(_result, style: const TextStyle(fontSize: 16)),
          ],
        ),
      ),
    );
  }
}
