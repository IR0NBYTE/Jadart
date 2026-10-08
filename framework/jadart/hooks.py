"""Frida hooks that log a Dart function's arguments and return value, at its real entry.

blutter ships a template instead: it has to be edited before it runs (the hook address is
a placeholder and its first line throws until removed), and it reads every argument from
the Dart stack at [x15 + 8*i]. On Dart 3.4 and later most functions get their fixed
parameters in x1, x2, x3, x5, x6 and x7 (x4 holds the arguments descriptor), so the stack
holds none of them; and where arguments are on the stack, [x15+0] is the LAST one.

What the snapshot proves, and what the hook therefore claims:
- The entry. A Code object with a monomorphic entry opens on the miss handler; calls land
  AOT_ENTRY_OFFSET bytes in, and that is where the hook goes (see disasm.load_instructions).
- The convention, in part. Before 3.4 everything is on the stack, and so it is for the
  kinds the VM always calls that way: closures, tear-offs, dyn: forwarders, dispatchers,
  method extractors, FFI trampolines, field initializers and irregexp. For every other
  function 3.4 passes fixed parameters in registers unless the function is generic or the
  global type flow analysis kept it on the stack, and neither fact is in the snapshot, so
  the hook shows both places and says why.
- Not the type of a value. An even word may be a Smi or an unboxed int, and the hook
  prints both readings. An odd word is named as an object only when it lies inside the
  compressed heap (its upper half equals the heap base in x28) and its header gives a
  class id the snapshot has a class for.

The hooks only observe: onEnter and onLeave log, and nothing writes to the process.
"""
from __future__ import annotations

import json
import re

from .disasm import ISOLATE_INSTRUCTIONS
from .errors import InputError
from .interop import binary_info, visible, _shown, _shown_name, _checks

#: Function kinds MaxNumberOfParametersInRegisters returns 0 for (object.cc, 3.4.0 to
#: 3.12.2): the VM calls them through the stack whatever their signature.
STACK_KINDS = frozenset({
    "ClosureFunction", "ImplicitClosureFunction", "FieldInitializer", "MethodExtractor",
    "NoSuchMethodDispatcher", "InvokeFieldDispatcher", "IrregexpFunction",
    "DynamicInvocationForwarder", "FfiTrampoline"})

#: DartCallingConvention::kCpuRegistersForArgs on arm64, 3.4.0 to 3.12.2.
ARG_REGISTERS = ("x1", "x2", "x3", "x5", "x6", "x7")

#: Where an object header keeps the class id: UntaggedObject::ClassIdTag is bits 12 to 31
#: (SizeTag is 4 bits from bit 8) in raw_object.h for 2.19.6, 3.0.6, 3.3.4, 3.4.4, 3.8.1
#: and 3.12.2. That is the layout in memory, not the snapshot stream's.
HEADER_CID_SHIFT, HEADER_CID_BITS = 12, 20


def _register_cc(dart: str) -> bool:
    """Dart 3.4.0 introduced the register convention; a snapshot hash pins one minor."""
    m = re.match(r"(\d+)\.(\d+)", dart or "")
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (3, 4)


def convention(sym, dart: str) -> str:
    """`stack`, `registers` (fixed parameters in registers unless generic or kept on the
    stack by TFA) or `unknown` (the range has no Function, so its kind is not known)."""
    if not _register_cc(dart):
        return "stack"
    if not sym.kind:
        return "unknown"
    return "stack" if sym.kind in STACK_KINDS else "registers"


def check_target(image, hdr) -> None:
    """The generator covers Android arm64: the calling convention and the heap checks are
    written for arm64, and the module and export names for Android's loader."""
    arch = hdr.arch.name if hdr.arch is not None else ""
    if arch != "arm64":
        raise InputError(f"hook supports Android arm64 builds only; this one is "
                         f"{arch or 'an unknown target'}")
    if image.container != "elf" or "android" not in (hdr.features or "").split():
        raise InputError("hook supports Android arm64 builds only; this one was built "
                         "for another OS")
    if not hdr.arch.compressed:
        # Android arm64 always has them; the heap check in the script depends on it.
        raise InputError("hook expects compressed pointers on Android arm64, and this "
                         "build has none")


_PRIVATE_KEY = re.compile(r"@\d+")


def select(syms: list, targets: list, all_matches: bool = False):
    """Resolve names, `Owner.name` or 0x addresses to ranges.

    Returns (chosen, problems). An address has to be a range start or its entry, since a
    hook anywhere else is on an instruction in the middle of a function. A name that
    matches several ranges is a problem unless all_matches is set, and the problem lists
    them, because 59% of named ranges share their name with another.

    Every piece of a problem that came out of the binary is escaped here, where it is put
    into the text. A name or library url holding a newline would otherwise add lines to
    the list, and a line reading `  0xdeadbeef  Vault.unlock  package:app/secure.dart` is
    indistinguishable from a real candidate to the person or the agent reading it."""
    chosen, problems, seen = [], [], set()
    for t in targets:
        # A range with no name is labelled by its address (disasm.sub_label), and the
        # label reads back as that address.
        a = t[len("sub_"):] if t[:6].lower() == "sub_0x" else t
        if re.fullmatch(r"0x[0-9a-fA-F]+", a):
            addr = int(a, 16)
            hit = [s for s in syms if addr in (s.va, s.entry_va)]
            if not hit:
                inside = next((s for s in syms if s.va <= addr < s.va + s.size), None)
                where = (f"; it is inside "
                         f"{_shown_name(inside) or 'an anonymous range'} "
                         f"at 0x{inside.va:x} (+0x{addr - inside.va:x})" if inside else "")
                problems.append(f"{t} is not the start or the entry of a code range{where}")
        else:
            # A private name carries its library key (_State@1234.build); the key is
            # optional in the target, since nobody types it.
            # And a name is matched as written or as every surface prints it, escaped
            # (fill.visible, #74) and cut when it is long (#94), so a name copied out of
            # the output finds its function.
            bare = _PRIVATE_KEY.sub("", t)

            def spelled(s):
                names = (s.name, s.qualified)
                return (names + tuple(visible(n) for n in names)
                        + tuple(_shown(n) for n in names) + (_shown_name(s),))

            hit = [s for s in syms if s.name and (t in spelled(s) or
                   bare in {_PRIVATE_KEY.sub("", n) for n in spelled(s)})]
            if not hit:
                problems.append(f"no function named {_shown(t)}")
            elif len(hit) > 1 and not all_matches:
                lines = [f"  0x{s.va:x}  {_shown_name(s)}  "
                         f"{_shown(s.library)}" for s in hit[:20]]
                more = [f"  ... {len(hit) - 20} more"] if len(hit) > 20 else []
                problems.append("\n".join(
                    [f"{_shown(t)} names {len(hit)} functions; give Owner.name, an "
                     f"address, or --all:"] + lines + more))
                hit = []
        for s in hit:
            if s.pc_offset not in seen:
                seen.add(s.pc_offset)
                chosen.append(s)
    return chosen, problems


#: Bytes of the entry the generated script compares before it attaches.
GUARD_BYTES = 8


def plan(image, hdr, fr, chosen: list) -> list:
    """What to hook, with the bytes the script checks first.

    The entry and its guard window have to lie inside the instructions image. The offsets
    come from the snapshot, so a crafted one can put them anywhere: a Code flagged as
    having a monomorphic entry but only 8 bytes long sends the entry past the end, where
    the slice below is empty and the script's comparison of no bytes against no bytes
    passes. That would attach to a live process at an address nothing verified."""
    dart = hdr.epoch.dart if hdr.epoch is not None else ""
    out = []
    for s in chosen:
        # The name came out of the binary, so it is escaped before it goes into a message:
        # a newline in it would otherwise add lines that read like jadart's own output.
        who = _shown_name(s) or hex(s.va)
        if s.entry_offset is None:
            if s.entry_error:
                raise InputError(f"{who} cannot be hooked: {s.entry_error}")
            raise InputError(f"the entry of {who} is not known for this target")
        at = s.pc_offset + s.entry_offset
        # code_symbols already refuses these, and says which numbers make them impossible.
        # They stay as a second guard for a CodeSymbol built by hand, since what follows
        # is an address a script attaches to in a live process.
        if s.entry_offset >= s.size:
            raise InputError(
                f"{who} declares an entry 0x{s.entry_offset:x} into a range of "
                f"{s.size} bytes, so the entry is outside its own code")
        if at < 0 or at + GUARD_BYTES > len(image.text):
            raise InputError(
                f"the entry of {who} is at 0x{at:x}, which leaves no {GUARD_BYTES} bytes "
                f"inside the {len(image.text)}-byte instructions image to check before "
                f"hooking")
        out.append({"name": _shown_name(s) or f"anon_{s.va:x}", "va": s.va,
                     "entry_va": s.entry_va, "off": at, "size": s.size,
                     "bytes": image.text[at:at + GUARD_BYTES].hex(), "kind": s.kind,
                     "convention": convention(s, dart), "static": s.static,
                     "library": _shown(s.library)})
    return out


def _classes(fr, hdr) -> dict:
    """Class id -> name, from the snapshot's Class objects and, for the VM's predefined
    classes the snapshot leaves unnamed (strings, doubles, lists), from the epoch's cid
    table, which is class_id.h for that release."""
    names = {}
    table = hdr.epoch.cid_table if hdr.epoch is not None else None
    if table is not None:
        for cid, nm in table.names.items():
            if cid < table.num_predefined:
                names[str(cid)] = nm[:-3] if nm.endswith("Cid") else nm
    for _ref, name_ref, cid, _sup in fr.classes:
        nm = fr.strings.get(name_ref, "")
        if nm:
            names[str(cid & 0xFFFFFFFF)] = _shown(nm)
    return names


def render_frida(image, hdr, fr, syms: list, hooks: list, label: str, version: str) -> str:
    """The script. `syms` is every range, for the whole-binary byte check; `hooks` is
    plan()'s output for the functions to hook."""
    info = binary_info(image, hdr, label)
    data = {
        "anchor": ISOLATE_INSTRUCTIONS,
        "checks": _checks(image, syms),
        "cid": {"shift": HEADER_CID_SHIFT, "mask": (1 << HEADER_CID_BITS) - 1},
        "classes": _classes(fr, hdr),
        "registers": list(ARG_REGISTERS),
        "hooks": [{k: h[k] for k in ("name", "off", "bytes", "convention", "kind",
                                     "static")}
                  for h in hooks],
    }
    header = [
        f"Jadart {version} Frida hooks: {len(hooks)} function(s) in {info['file']}, "
        f"Dart {info['dart']} ({info['epoch']}), {info['arch']}.",
        "Run: frida -U -f <package> -l <this file>  (Frida 16.7 or later, or 17)",
        "The hooks only log. Each one is placed at the address calls land on, found from "
        f"{ISOLATE_INSTRUCTIONS} in libapp.so, after its bytes are checked.",
    ]
    header = ["// " + re.sub(r"[^\x20-\x7e]", "?", line) for line in header]
    body = _FRIDA.replace("{data}", json.dumps(data, ensure_ascii=True,
                                               separators=(",", ":")))
    return "\n".join(header) + "\n" + body


_FRIDA = r"""'use strict';

const MODULE = 'libapp.so';  // the engine's default; an app can rename it in its manifest
const STACK_SLOTS = 4;       // Dart stack words shown on entry; [x15+0] is the LAST stack argument
const SHOW_DOUBLES = true;   // d0-d5, where unboxed double arguments arrive. On by
                             // default: the snapshot does not record which parameters
                             // are unboxed, so leaving these out hides an argument
                             // entirely rather than merely showing less.
const LOG_LIMIT = 200;       // calls logged per function before it goes quiet

const J = {data};

function hex(bytes) {
  return Array.prototype.map.call(new Uint8Array(bytes),
    b => ('0' + b.toString(16)).slice(-2)).join('');
}

function smi(p) {
  // A Smi is the value shifted left once. With compressed pointers the VM keeps
  // 31 bits and reads the low half sign-extended, as done here.
  if (typeof BigInt !== 'function') return '?';
  return (BigInt.asIntN(32, BigInt(p.toString())) >> BigInt(1)).toString();
}

function objectClass(p, ctx) {
  // Every heap object lies in the 4 GB cage whose upper half x28 holds in its low half.
  if (p.shr(32).and(0xffffffff).toUInt32() !== ctx.x28.and(0xffffffff).toUInt32())
    return null;
  try {
    const cid = (p.sub(1).readU32() >>> J.cid.shift) & J.cid.mask;
    const name = J.classes[String(cid)];
    return name === undefined ? null : name + ', cid ' + cid;
  } catch (e) {
    return null;
  }
}

function show(p, ctx) {
  const raw = p.toString();
  if (p.equals(ctx.x22)) return raw + '  null';
  if (p.and(1).isNull()) return raw + '  Smi ' + smi(p) + ' if tagged, or an unboxed int';
  const cls = objectClass(p, ctx);
  return raw + (cls ? '  ' + cls : '  odd, not an object this snapshot has a class for');
}

function enter(h, ctx) {
  const lines = ['[jadart] ' + h.name + ' called'];
  if (h.convention !== 'stack') {
    // Only an instance function takes a receiver. The snapshot records the static bit,
    // so say which it is rather than calling x1 the receiver for a static function.
    const who = h.static === true ? '  fixed parameters'
      : h.static === false ? '  fixed parameters, receiver first'
      : '  fixed parameters, receiver first if this is an instance function';
    lines.push(h.convention === 'registers'
      ? who + ', unless the function is generic or was kept on the stack:'
      : '  kind unknown, so parameters may be in registers or on the stack:');
    for (const r of J.registers) lines.push('    ' + r + ' = ' + show(ctx[r], ctx));
    if (SHOW_DOUBLES) {
      // The snapshot does not record which parameters are unboxed doubles, so these are
      // whatever the registers happen to hold. For a function that takes none they are
      // leftovers, and saying so beats listing them as if they were arguments.
      const ds = [];
      for (let i = 0; i < 6; i++)
        if (ctx['d' + i] !== undefined) ds.push('d' + i + '=' + ctx['d' + i]);
      if (ds.length)
        lines.push('  d0-d5, where an unboxed double argument would arrive; leftovers if '
                   + 'this function takes none:\n    ' + ds.join('  '));
    }
  }
  lines.push('  Dart stack, last stack argument first:');
  for (let i = 0; i < STACK_SLOTS; i++) {
    let v;
    try {
      v = show(ctx.x15.add(8 * i).readPointer(), ctx);
    } catch (e) {
      v = 'unreadable';
    }
    lines.push('    [x15+0x' + (8 * i).toString(16) + '] = ' + v);
  }
  console.log(lines.join('\n'));
}

function install(mod) {
  const base = mod.findExportByName(J.anchor);
  if (base === null) {
    console.log('[jadart] ' + mod.name + ' does not export ' + J.anchor + ', nothing hooked');
    return;
  }
  for (const c of J.checks) {
    const got = hex(base.add(c.off).readByteArray(c.hex.length / 2));
    if (got !== c.hex) {
      console.log('[jadart] bytes at ' + J.anchor + '+0x' + c.off.toString(16) + ' are ' + got +
                  ', expected ' + c.hex + ': not the binary these hooks were made for, nothing hooked');
      return;
    }
  }
  let n = 0;
  for (const h of J.hooks) {
    const at = base.add(h.off);
    const got = hex(at.readByteArray(h.bytes.length / 2));
    if (got !== h.bytes) {
      console.log('[jadart] ' + h.name + ': bytes at ' + at + ' are ' + got + ', expected ' +
                  h.bytes + ' (hooked already?), skipped');
      continue;
    }
    let calls = 0;
    Interceptor.attach(at, {
      onEnter() {
        this.log = ++calls <= LOG_LIMIT;
        if (this.log) enter(h, this.context);
        else if (calls === LOG_LIMIT + 1) console.log('[jadart] ' + h.name + ': ' + LOG_LIMIT + ' calls logged, quiet from now on');
      },
      onLeave() {
        if (!this.log) return;
        let line = '[jadart] ' + h.name + ' returned x0 = ' + show(this.context.x0, this.context);
        if (SHOW_DOUBLES && this.context.d0 !== undefined)
          line += ' (d0 = ' + this.context.d0 + ', the return only if it is an unboxed double)';
        console.log(line);
      }
    });
    n++;
  }
  console.log('[jadart] ' + n + ' of ' + J.hooks.length + ' hooks installed, ' +
              J.anchor + ' at ' + base);
}

let installed = false;
function onModule(mod) {
  if (installed || mod.name !== MODULE) return;
  installed = true;
  install(mod);
}

if (typeof Process.attachModuleObserver === 'function') {
  // Called for every module already loaded, then for each new one before it runs.
  Process.attachModuleObserver({ onAdded: onModule });
} else {
  const mod = Process.findModuleByName(MODULE);
  if (mod !== null) onModule(mod);
  else console.log('[jadart] ' + MODULE + ' is not loaded, and this Frida (before 16.7) cannot ' +
                   'wait for it: attach once the app is running');
}
"""
