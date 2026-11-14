# Reading x86_64 code: a design proposal

Status: a proposal for #448, with nothing built. An x86_64 `libapp.so` parses today
and stops at structure: `disasm`, `lift` and everything on them refuse it
(`framework/jadart/disasm.py:431`). This page says what reading its code would take, in
three stages, and whether to do it.

SDK paths are at commit `f3f72dd63911938effc75feacc86f52022216c67` of dart-lang/sdk, the
commit [whats-coming.md](whats-coming.md) pins. A bare file name stands for a file in one
of three folders:

- `runtime/vm/`: `constants_x64.h`, `constants_x86.h`, `constants_arm64.h`,
  `stack_frame_x64.h`, `instructions_x64.h`, `dispatch_table.h`, `object.h`, `object.cc`,
  `image_snapshot.cc`
- `runtime/vm/compiler/assembler/`: `assembler_x64.h`, `assembler_x64.cc`,
  `assembler_arm64.cc`
- `runtime/vm/compiler/backend/`: `il.cc`, `il_x64.cc`, `flow_graph_compiler.cc`,
  `flow_graph_compiler_x64.cc`, `dart_calling_conventions.cc`

Jadart paths are under `framework/jadart/`. "Not established" means the source read did
not settle it. No x86_64 binary was read, so every x64 fact below is the SDK's word at
one commit and not a measurement.

## Recommendation

Do stage 1 now and stage 2 after it, with a stop between them. Do not start stage 3.

Stage 1 is about 750 lines of code. It turns a refusal into a listing with names, which
is what the requests on blutter's tracker ask for (the issue lists #202, #166 and #49)
and what AOTopsy already prints. It also buys something arm64 work cannot: one app built
for two machines, so each build checks the other's call graph and strings.

The case against is reach. iOS is arm64 only. An APK built for every ABI carries the
arm64 library beside the x86_64 one. Windows desktop is x64 but ships a PE file,
refused by name ([support.md](support.md)). What x86_64 alone unlocks is Linux desktop
apps and APKs split by ABI. The same effort spent on arm64 tier 3, or on gating Dart
3.13 for iOS and arm32, reaches more users per line. That is why stage 3 waits: its
size is the least certain number here, and nobody has asked for it.

## Register roles and the calling convention

| role | arm64 | x86_64 | proof |
|---|---|---|---|
| thread (THR) | `x26` | `r14` | `constants_arm64.h:153`, `constants_x64.h:131` |
| object pool (PP) | `x27`, untagged | `r15`, tagged | `constants_arm64.h:144`, `assembler_arm64.cc:1473`; `constants_x64.h:123`, `assembler_x64.cc:1450-1451` |
| stack pointer | `x15`, not the hardware one | `rsp`, the hardware one | `constants_arm64.h:150`, `constants_x64.h:124` |
| frame pointer | `x29` | `rbp` | `constants_arm64.h:149`, `constants_x64.h:125` |
| return address | `x30` | on the stack, pushed by `call` | `stack_frame_x64.h:19-31`, `stack_frame_x64.h:53` |
| code object | `x24` | `r12` | `constants_arm64.h:146`, `constants_x64.h:128` |
| arguments descriptor | `x4` | `r10` | `constants_arm64.h:152`, `constants_x64.h:127` |
| call site data | `x5` | `rbx` | `constants_arm64.h:151`, `constants_x64.h:126` |
| scratch | `x16`, `x17` | `r11` only | `constants_arm64.h:142-143`, `constants_x64.h:120-121` |
| dispatch table | `x21`, pinned | no register: read from the thread at each call | `constants_arm64.h:145`; `assembler_x64.cc:1522-1524` |
| null | `x22`, pinned | no register: read from the thread | `constants_arm64.h:157`; `assembler_x64.cc:1536-1538`, `1603-1604` |
| heap base, barrier mask | `x28`, pinned | no register: read from the thread | `constants_arm64.h:156`; `assembler_x64.cc:1679`, `1714` |
| argument registers | `x1 x2 x3 x5 x6 x7` | `rdi rsi rdx rbx r8 r9` | `constants_arm64.h:654`, `constants_x64.h:698-699` |
| floating point arguments | `v0` to `v5` | `xmm1` to `xmm6` | `constants_arm64.h:655`, `constants_x64.h:700-701` |
| return value | `x0`, `v0` | `rax`, `xmm0` | `constants_arm64.h:633-635`; `constants_x64.h:646-648`, `il_x64.cc:420-429` |
| write barrier object, value, slot | `x1`, `x0`, `x25` | `rdx`, `rax`, `r13` | `constants_arm64.h:165-167`, `constants_x64.h:139-141` |
| class id at a dispatch call | `x0` | `rcx` | `constants_arm64.h:490`, `constants_x64.h:457` |
| compressed pointer load | 32-bit load, then `add` of `x28` shifted left 32 | 32-bit `mov`, then `add r, [r14 + heap_base]` | `assembler_arm64.cc:1148-1150`, `assembler_x64.cc:1677-1680` |
| `this` | first argument: `x1`, or the stack slot furthest from SP | first argument: `rdi`, or the stack slot furthest from SP | `dart_calling_conventions.cc:56-99`, `object.cc:27855-27884`, `flow_graph_compiler_x64.cc:560-561` |

Arguments go in registers only where the callee allows it; a generic function or a
closure takes all of them on the stack. A switchable instance call also copies the
receiver into `rdx`, the register the monomorphic entry reads (`assembler_x64.cc:2440`).
Three pinned registers of arm64 have no x64 twin, so null, the heap base and the
dispatch table show up as loads from `r14`, as null already does on arm32
(`expr.py:301`).

## The patterns each tier reads

| pattern | arm64, as Jadart reads it today | x86_64, as the SDK emits it |
|---|---|---|
| direct call | `bl`, class and target off the word (`branches.py:40-46`, `disasm.py:1470`) | `E8 rel32`, five bytes; a tail call is `E9 rel32` (`assembler_x64.cc:2651-2670`, `instructions_x64.h:113-115`) |
| pool load | `ldr xN, [x27, #off]`, or `add xD, x27, #hi` then `ldr` (`disasm.py:1318-1322`, `1411-1441`) | `mov r, [r15 + disp]`, the tag taken off in `disp`; one instruction at any index, and the same operand feeds `cmp` (`assembler_x64.cc:1447-1452`, `1609-1612`, `assembler_x64.h:267-270`) |
| call through the pool | a pool load of a Code or Function, then `blr` (`callgraph.py:26-27`, `317-323`) | `mov r11, [r15 + disp]` then `call [r11 + entry]` (`assembler_x64.cc:66-76`); an instance call is two pool loads into `rcx` and `rbx`, then `call rcx` (`flow_graph_compiler_x64.cc:560-568`) |
| dispatch table call | tags load, `ubfx` class id, `add` offset, `ldr t, [x21, idx, lsl #3]`, `blr t` (`expr.py:13106-13115`, `dispatch.py:1-5`) | `mov ecx, [recv - 1]`, `shr ecx, 12` (`assembler_x64.cc:2828-2833`), `mov rax, [r14 + table]`, `call [rax + rcx*8 + off]` with `off = (selector - 16) * 8` (`flow_graph_compiler_x64.cc:603-614`, `dispatch_table.h:22-25`) |
| stack overflow check | `ldr TMP, [THR, #imm]`, `cmp SP, TMP`, `b.ls` (`expr.py:2645-2658`) | `cmp rsp, [r14 + limit]`, `jbe slow`; the slow path is `call [r14 + stub]` (`il_x64.cc:2994-2995`, `2936-2939`) |
| frame setup and teardown | `stp x29, x30` off `x15`, `mov x29, x15`, and the `ldp` back (`expr.py:2622-2638`) | `push rbp`, `mov rbp, rsp`, `sub rsp, n`; then `mov rsp, rbp`, `pop rbp`, `ret` (`assembler_x64.cc:1961-1976`, `2284-2300`, `il_x64.cc:467-468`, `instructions_x64.h:67`, `84`) |
| Smi tag test | `tbz` or `tbnz` on bit 0 (`cfg.py:26`, `270-282`) | `test r, 1`, then `jz` or `jnz` (`assembler_x64.h:1117-1129`); tag is `add r, r`, untag is `sar r, 1` (`assembler_x64.h:1078-1080`) |
| null check | `cmp xN, x22`, `b.eq` (`expr.py:266-277`) | `cmp r, [r14 + null]`, `je slow`; the slow path is a direct call to the null error stub (`il_x64.cc:5709-5710`, `assembler_x64.cc:1603-1604`, `flow_graph_compiler.cc:3169-3177`) |
| allocation stub call | `bl` to a stub named from the object store (`expr.py:360-372`) | a direct call to the class's stub, result in `rax`, type arguments in `rdx` (`il_x64.cc:6824-6827`, `constants_x64.h:300-303`) |
| write barrier | `tst` against `x28`, `b.cc`, `bl` stub (`expr.py:2659-2662`) | tags byte, `shr`, `and r, [r14 + mask]`, `test byte [value - 1], r`, `jz done`, direct call to the wrapper for that register (`assembler_x64.cc:1711-1732`, `flow_graph_compiler_x64.cc:35-39`) |
| monomorphic entry | miss handler at +0, check at +8, normal entry at +24 (`disasm.py:185-193`) | `jmp [r14 + miss]` and a `nop` at +0; at +8 untag `rbx`, class id of `rdx`, `cmp`, `jne miss`; normal entry at +22 (`assembler_x64.cc:2423-2454`, `object.h:6006-6007`) |
| trap after a call that cannot return | `brk` (`cfg.py:55`) | `int3` (`il.cc:5092`, `assembler_x64.h:1392`); the same byte pads between functions (`constants_x64.h:735`, `image_snapshot.cc:1049`) |

## The decoder

Use capstone's x86 mode: one more row in `_DECODERS` (`disasm.py:67`). It is already the
optional dependency, and `disasm_lite` returns each instruction's size. Fourteen
hand-assembled instructions in the shapes above decoded as expected on capstone 5.0.7,
at 2.8 million a second in a loop, against 1.1 million for arm64.

A decoder of our own is the wrong first step. The x64 assembler is 3,011 lines of
emitters with prefixes, ModRM and SSE forms, so even a reader that only finds lengths
is several hundred lines that must be proven against capstone anyway. AOTopsy uses a
full decoder too, Go's `x86asm` (`internal/arch/x86/decode.go`). Our own reader is
worth having later, for speed: `A64Words` finds calls without decoding
(`disasm.py:1485`). x64 has no fixed slots, so `functions` and `xrefs` would take the
decoded path as arm32 does (`callgraph.py:253`).

Variable length breaks four things:

- **The next address.** Rows are `(address, mnemonic, operands)` and the next one is
  `address + 4` in cfg.py (`494`, `607`, `763`, `1564`) and disasm.py (`1256`). Rows
  need to carry their end, the way `Annotated` carries `pool_at` (`disasm.py:1310`).
- **The cut.** 4,000 counts instructions and stays. `truncated_by` works out what was
  left as `size // 4` (`disasm.py:393`); on x64 it can only say how many bytes.
- **Recovery.** A word capstone rejects is printed as `.word` and stepped over
  (`disasm.py:446-496`). On x64 a rejected byte means the sweep has lost its place:
  print the rest of the range as `.byte`, and tiers 2 and 3 refuse that function.
  AOTopsy steps one byte and carries on.
- **The word readers.** `branches.py` classes a branch by the top byte of its word
  (`branches.py:59`). x64 needs a table on the first opcode byte: `E8`, `E9`, `EB`,
  `70` to `7F`, `0F 80` to `0F 8F`, `FF /2`, `FF /4`, `C3`
  (`assembler_x64.cc:40-45`, `1186-1237`).

Linear sweep from a range start should be sound. The snapshot gives each start, and a
payload opens on an instruction. No data in code was found: a switch reads its offsets
from an array in the pool (`il_x64.cc:6667-6683`), a 64-bit constant sits inside its
`mov` (`assembler_x64.cc:57-62`), and a 128-bit one comes from the pool (`1670-1673`).
Padding is instructions: `nop` to align entries and loops (`assembler_x64.cc:2432`,
`2672-2688`, `flow_graph_compiler.cc:720-722`) and `int3` to four bytes after each
payload (`object.h:6059`). "Should", because the two largest files were searched and
not read whole, and x86 decodes a wrong start into code that looks right. So each
binary proves it: every range decodes to its last byte, every branch inside a range
lands on a decoded boundary, and every direct call lands on a range start or on a
flagged range's start plus 8 or 22.

## What is shared and what is not

| file | state | what changes | lines |
|---|---|---|---|
| snapshot, clusters, fill, elf, versions, objstore, held, program | shared | nothing: x64 already parses | 0 |
| `disasm.py` | abstraction first | decoder row, rows that know their end, `.byte` recovery, pool shape with tag 1, pool operands in any position, entry offsets 8 and 22 | 300 |
| `branches.py` | second implementation | the opcode table above, and `exits` for `ret` and indirect `jmp` | 120 |
| `callgraph.py` | second implementation | `call reg` and `call [mem]`, pool calls, dispatch sites | 150 |
| `dispatch.py` | shared, one constant | origin element 16 against 4096 (`dispatch.py:58`) | 15 |
| `expr.py` `detect_dispatch` | second implementation | the x64 dispatch sequence | 90 |
| `cfg.py` | abstraction first | next address, terminators and traps per target, an x64 condition reader | 350 |
| `expr.py` lifter, `fields.py` code half | second implementation | stage 3 only | 1,500 to 3,000 |
| `cli.py`, `export.py`, `hooks.py` | gates | refuse or pass by stage | 80 |
| `tools/build_corpus.py`, `tools/cfgcheck.py` | shared, one target | engine folder, exit check on x64 | 80 |
| `tests/test_core.py` | new tests | per stage | 300 to 400 |

## Stages

Every stage uses one fixture, built from `flubench/app` beside the arm64 one. Flutter
3.44.4 carries Dart 3.12.2, the release the committed fixtures were built with, so the
two libraries hold the same app at the same SDK:

```
cd flubench/app
flutter build apk --release --target-platform android-x64
unzip -o build/app/outputs/flutter-apk/app-release.apk lib/x86_64/libapp.so \
  -d ../artifacts/clean-x64
```

The obfuscated twin adds `--obfuscate --split-debug-info=DIR`. Older releases come from
`tools/build_corpus.py`, pointed at the `android-x64-release` engine folder. Tests skip
without the fixture, as the arm32 ones do.

**Stage 1, tier 1: about 750 lines and 400 of tests.** `disasm`, `functions`, `xrefs`
and `decompile -t 1` print x86_64 with pool entries, stubs and calls named. Gates: the
three boundary checks on every range; decode coverage stated beside arm64's 99.83%;
`benchCheckSecret` loads the literal its source compares, which pins the pool shape as
it did for arm32 (`disasm.py:855-862`); direct edges and strings per function counted
against the arm64 fixture. Tiers 2 and 3 still refuse by name.

**Stage 2, tier 2: about 450 lines and 400 of tests.** Blocks, loops and conditions.
A `jcc` maps onto the condition names cfg.py already reads, by what set the flags:

| jump | after `cmp a, b` or `sub` | after `test a, a` | after `comisd a, b` | cfg.py name |
|---|---|---|---|---|
| `je`, `jne` | `a == b`, `a != b` | `a == 0`, `a != 0` | `a == b`, `a != b` | `eq`, `ne` |
| `jl`, `jge` | signed `<`, `>=` | `a < 0`, `a >= 0` | `?` | `lt`, `ge` |
| `jle`, `jg` | signed `<=`, `>` | `a <= 0`, `a > 0` | `?` | `le`, `gt` |
| `jb`, `jae` | unsigned `<`, `>=` | never, always | `a < b`, `a >= b` | `lo`, `hs` |
| `jbe`, `ja` | unsigned `<=`, `>` | `a == 0`, `a != 0` | `a <= b`, `a > b` | `ls`, `hi` |
| `js`, `jns` | sign of `a - b` | `a < 0`, `a >= 0` | `?` | `mi`, `pl` |
| `jo`, `jno` | the subtraction overflowed, or not | never, always | `?` | `vs`, `vc` |
| `jp`, `jnp` | `?` | `?` | one side is NaN, or neither | new |

The model differs from arm64 in four ways. Almost every arithmetic instruction writes
the flags, so the reader keeps a list of the ones that do not (`mov`, `lea`, `push`,
`pop`, the SSE moves) and prints `?` when anything unlisted sits between the setter and
the jump. After `add`, `jb` is a carry out and not a borrow, which `_carry_out` already
spells (`cfg.py:407`). After `comisd`, `jb`, `jbe` and `je` also hold on NaN, so the
compiler tests `jp` first (`il_x64.cc:995-1000`); `_FP_REL` records that for arm64
(`cfg.py:202`). And an operand can be memory: a null test is `cmp rax, [r14 + off]`.
`inc`, `dec` and a shift by `cl` leave some flags alone and print `?`. Gates: `cfgcheck`
with 0 edge violations and 0 dropped blocks, its exit check on x64 bytes, and the share
of `?` conditions stated beside arm64's. It does not lift expressions.

**Stage 3, tier 3: 1,500 to 3,000 lines, not proposed.** A `Target` for x64 is forty
lines (`expr.py:205`). The rest is not a table: `_step` and `strip_boilerplate` match
arm64 mnemonics at about 150 places, assume three operands where x64 overwrites one,
and never see memory as a destination. Two routes: rewrite
x64 rows into the three-operand rows the lifter reads, or lower x64 into the value DAG
(`lower.py`). `LIFTABLE_ARCHS` (`expr.py:331`) stays shut until `semdiff` passes 9 of 9
and `irfuzz` has an x64 oracle.

## Risks and unknowns

- **No binary was read.** The pool's first element offset and element size, the thread
  offsets of null, true, false, the stack limit and the dispatch table are generated
  values the SDK source does not spell. Each is measured on the fixture before use.
- **A wrong sweep is quiet.** The boundary checks catch a sweep that slips; they do not
  prove there is no data in code. Whether a range can hold a trampoline
  (`image_snapshot.cc:958-991`) is not established.
- **One commit was read.** Register arguments do not exist before 3.4
  (`expr.py:12471-12478`), and older x64 entry offsets and call shapes were not read.
  Each epoch needs its own x64 build before it is claimed.
- **Operands are text.** The operand parsers are regexes on arm syntax
  (`disasm.py:837`, `1301`). x64 prints `qword ptr [rax + rcx*8 + 0x100]`, so a second
  parser is needed, and its mistakes would be silent.
- **Linux desktop is not covered by the fixture.** It needs a Linux host, and whether
  that build compresses pointers is set in the engine's build files, not read here.
- **The two builds may differ for good reasons**, such as inlining, so the comparison
  is a count, not a pass or fail.
- **The sizes come from reading the code**, not from a spike. Stage 3 could be out by a
  factor of two.

Credit: the one-byte recovery, the x64 dispatch shape and reading a condition from its
flag setter were checked against AOTopsy's source, which is BSD licensed.
