import 'package:flutter/material.dart';
import 'constructs.dart';

void main() => runApp(const FluBenchApp());

class FluBenchApp extends StatelessWidget {
  const FluBenchApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'FluBench',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      home: const FluBenchPage(),
    );
  }
}

class FluBenchPage extends StatefulWidget {
  const FluBenchPage({super.key});

  @override
  State<FluBenchPage> createState() => _FluBenchPageState();
}

class _FluBenchPageState extends State<FluBenchPage> {
  String _out = 'tap run';

  Future<void> _run() async {
    // Runtime seed the AOT compiler cannot fold: forces every construct and its
    // string literals to survive into the snapshot.
    final seed = DateTime.now().microsecondsSinceEpoch.toRadixString(16);
    final sync = benchRunAll(seed);
    final token = await benchFetchToken(seed);
    setState(() => _out = '$sync\n$token');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('FluBench')),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            FilledButton(onPressed: _run, child: const Text('Run constructs')),
            const SizedBox(height: 16),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(_out),
            ),
          ],
        ),
      ),
    );
  }
}
