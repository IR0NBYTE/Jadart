// FluBench constructs. Every public name here is ground truth for the RE
// benchmark: a tool's job is to recover these class/method/function names,
// the string literals, and the call graph from the compiled snapshot.
//
// Two rules keep the benchmark honest against the AOT optimizer:
//   1. @pragma('vm:never-inline') so each construct survives as a distinct
//      function (otherwise inlining erases the name we score on).
//   2. Inputs are threaded from a RUNTIME seed (see benchRunAll), so the
//      compiler cannot constant-fold literals or whole functions away.
// Without these, the corpus measures the optimizer, not the RE tool.

import 'dart:convert';

// C1: secret string comparison (string-literal recovery + equality)
@pragma('vm:never-inline')
bool benchCheckSecret(String input) {
  return input == 'FLUBENCH{str_literal_compare}';
}

// C2: integer arithmetic + loop + branch (tagged-Smi arithmetic, control flow)
@pragma('vm:never-inline')
int benchComputeChecksum(List<int> data) {
  var acc = 0;
  for (final b in data) {
    acc = (acc * 31 + b) & 0xffffffff;
  }
  return acc;
}

// C3: closure that captures a variable
@pragma('vm:never-inline')
int Function(int) benchMakeAdder(int base) {
  return (int x) => base + x;
}

// C4: generic function
@pragma('vm:never-inline')
T benchFirstOrDefault<T>(List<T> items, T fallback) {
  return items.isEmpty ? fallback : items.first;
}

// C5: async function (lowered to a SuspendState machine)
@pragma('vm:never-inline')
Future<String> benchFetchToken(String seed) async {
  await Future<void>.delayed(const Duration(milliseconds: 1));
  return 'FLUBENCH{async_marker}:$seed';
}

// C6: a class with fields and a method
class BenchAccount {
  final String owner;
  int balance;
  BenchAccount(this.owner, this.balance);

  @pragma('vm:never-inline')
  bool benchWithdraw(int amount) {
    if (amount > balance) return false;
    balance -= amount;
    return true;
  }
}

// C7: computed secret (base64 + xor) so the flag is NOT a plaintext literal
@pragma('vm:never-inline')
String benchDecodeFlag(String encoded) {
  final bytes = base64.decode(encoded);
  final out = <int>[];
  for (var i = 0; i < bytes.length; i++) {
    out.add(bytes[i] ^ 0x42);
  }
  return utf8.decode(out);
}

// C8: record type (Dart 3)
@pragma('vm:never-inline')
(int, String) benchMakePair(int id, String name) {
  return (id, name);
}

// Driver: threads a RUNTIME seed through every construct so AOT cannot fold or
// tree-shake them. main.dart passes a value the compiler cannot know.
@pragma('vm:never-inline')
String benchRunAll(String seed) {
  final b = StringBuffer();
  b.writeln(benchCheckSecret(seed));
  b.writeln(benchComputeChecksum(seed.codeUnits));
  b.writeln(benchMakeAdder(seed.length)(seed.length));
  b.writeln(benchFirstOrDefault<int>(seed.codeUnits, -1));
  final acct = BenchAccount(seed, seed.length);
  b.writeln(acct.benchWithdraw(seed.length ~/ 2));
  b.writeln(benchDecodeFlag(base64.encode(seed.codeUnits)));
  b.writeln(benchMakePair(seed.length, seed));
  return b.toString();
}
