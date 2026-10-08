"""Hand what Jadart recovers to IDA, Ghidra, radare2 and Frida, on addresses they can use.

Every address here is built one way: the exported symbol the isolate instructions image
starts at, plus Jadart's pc_offset. That is the address a disassembler shows, and at run
time it is where that export was loaded plus the same offset. Checked on 58 ELF builds
and an iOS dylib, 546,037 ranges, with no disagreement; see InstrImage in disasm.py.

The generated scripts never carry absolute addresses. Each one resolves the anchor symbol
inside the tool, compares a few bytes of known code against what it expects, and applies
nothing if either fails. A database that was rebased still lines up, and a script run
against the wrong build refuses instead of naming the wrong code. blutter's IDA script
writes absolute addresses and unflutter's Ghidra script adds the image base to file
offsets; both mislabel a rebased load without saying so.

Names are made safe per tool, because Dart names are not identifiers: they carry `@`,
`:`, `|`, `-`, `+`, and a stripped build's symbol table adds spaces. IDA refuses those
unless told otherwise, and radare2 runs a shell for `|` and writes a file for `>` when a
name reaches its command line unquoted. So every tool gets a name reduced to
`[A-Za-z0-9_]` with the virtual address appended, which also keeps them unique where
Dart repeats a name (`build` 90 times on one fixture), and the name as written travels
only as data: base64 in radare2, a decoded string in IDA and Ghidra.

The Frida output only observes. It logs what a function is called with and what it
returns, and changes nothing.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

from .disasm import ISOLATE_INSTRUCTIONS
from .errors import InputError
from .fill import NAME_CUT, visible  # hooks imports visible from here too

#: Bumped whenever a field of the `symbols` JSON changes meaning or goes away.
FORMAT_VERSION = 1

FORMATS = ("json", "ida", "ghidra", "r2")


@dataclass
class CodeSymbol:
    """One code range, with every address a tool might want and where its name came from."""
    pc_offset: int              # into the isolate instructions image, as everywhere in Jadart
    size: int
    va: int                     # anchor value + pc_offset: what a disassembler shows
    file_offset: int
    entry_offset: int | None    # bytes from va to the entry calls land on; None = no entry
    name: str                   # "" when the snapshot and the symbol table have none
    origin: str                 # snapshot | symtab | signature | anonymous
    owner: str                  # the class the code belongs to, when the snapshot says
    library: str
    kind: str                   # the Function kind (RegularFunction, ClosureFunction, ...)
    static: bool | None         # None when the static bit could not be calibrated
    #: Why `entry_offset` is None, when the reason is this binary rather than the target.
    #: Empty with a None entry means the architecture has no offset in AOT_ENTRY_OFFSET,
    #: which is a fact about Jadart; a reason here is a fact about the snapshot, and the
    #: two must not be reported with the same sentence.
    entry_error: str = ""

    @property
    def entry_va(self) -> int | None:
        return None if self.entry_offset is None else self.va + self.entry_offset

    @property
    def qualified(self) -> str:
        if not self.name:
            return ""
        # A top-level function's owner is its library's unnamed scope class, so it has none.
        return f"{self.owner}.{self.name}" if self.owner else self.name

    def as_json(self) -> dict:
        """The names as written: `name`, `owner` and `library` each cut at NAME_CUT
        characters, and `qualified` the cut owner and name joined. A class name comes
        back in every function of the class and a library url in every function of the
        library, so one long name printed whole made the document that count times its
        length (#94). `cut`, present only then, gives the full length of each field it
        cut; no name a compiler wrote comes near it."""
        cut = {}

        def part(field, text):
            if len(text) <= NAME_CUT:
                return text
            cut[field] = len(text)
            return text[:NAME_CUT]

        name, owner = part("name", self.name), part("owner", self.owner)
        out = {"pc_offset": self.pc_offset, "va": self.va,
               "file_offset": self.file_offset, "size": self.size,
               "entry_va": self.entry_va, "entry_error": self.entry_error, "name": name,
               "qualified": f"{owner}.{name}" if name and owner else name,
               "origin": self.origin, "owner": owner,
               "library": part("library", self.library), "kind": self.kind,
               "static": self.static}
        if self.name and ("name" in cut or (self.owner and "owner" in cut)):
            cut["qualified"] = len(self.name) + (len(self.owner) + 1 if self.owner else 0)
        if cut:
            out["cut"] = cut
        return out


def code_symbols(image, fr, hdr, sigs: str | None = None, notes: list | None = None) -> list:
    """Every code range as a CodeSymbol, sorted by address.

    Names and origins follow `jadart functions` exactly (0 differences over 9 binaries).
    Libraries do not: this reaches the class through the Code object's owner and through
    PatchClass, so patched library code keeps its class, and a range `functions` leaves
    without a library gets one here (1868 of 8194 on the clean fixture, 904 of 8188 on the
    obfuscated one, 2312 of 11051 on the iOS dylib). It also adds the owner class and the
    kind and static bit of the Function behind the range.

    A range that starts outside the instructions image is dropped rather than given an
    address, so the returned list can be shorter than `image.all_ranges`. How many were
    dropped is appended to `notes` when one is passed, because a shorter list that says
    nothing reads as a binary with fewer functions. If every range is outside, there is no
    answer to give and that is raised instead."""
    if image.anchor_va is None:
        raise InputError(
            f"this binary has no {ISOLATE_INSTRUCTIONS} symbol, so there is no anchor to "
            f"give addresses against")
    from .disasm import function_name_by_pc
    from .program import build_program, static_bit, _FUNCTION_KINDS
    from .signatures import MARK

    # As written: each is escaped where it is printed, and the original travels in base64.
    names = function_name_by_pc(image, fr, raw=True)
    snapshot_pcs = set()
    for ref, name_ref, _ow, _kt in fr.functions:
        cr = image.code_ranges.get(ref)
        if cr is not None and fr.strings.get(name_ref, ""):
            snapshot_pcs.add(cr.pc_offset)
    symtab = dict(image.symbol_names or {})
    matched = {}
    if sigs:
        from .signatures import load, match
        matched = match(image, fr, load(sigs))

    prog = build_program(fr, hdr, raw=True)
    by_ref = {k.ref: k for k in prog.classes}
    func = {ref: (ow, kt) for ref, _nr, ow, kt in fr.functions}
    sbit = static_bit(fr)

    def klass(ref):
        return by_ref.get(ref) or by_ref.get(fr.patch_class.get(ref, -1))

    out = []
    dropped = 0
    for cr in image.all_ranges:
        pc = cr.pc_offset
        nm = names.get(pc, "")
        if nm and pc in snapshot_pcs:
            origin = "snapshot"
        elif nm and pc in symtab:
            origin = "symtab"
        elif pc in matched:
            nm, origin = matched[pc].name + MARK, "signature"
        else:
            origin = "snapshot" if nm else "anonymous"
        owner = library = kind = ""
        static = None
        if cr.owner_ref in func:
            ow, kt = func[cr.owner_ref]
            k = klass(ow)
            if k is not None:
                owner, library = k.name, k.library
            idx = kt & 0x1F
            kind = _FUNCTION_KINDS[idx] if idx < len(_FUNCTION_KINDS) else ""
            static = bool((kt >> sbit) & 1) if sbit is not None else None
        elif cr.owner_ref in by_ref:
            # The Code object belongs to a class rather than a function. That is a fact
            # about the snapshot; what the code does is not named here.
            k = by_ref[cr.owner_ref]
            owner, library = k.name, k.library
        # Absent means no monomorphic entry. For ranges with a Code object that is the
        # payload_info bit; for ranges without one (an obfuscated build discards most Code
        # objects) it rests on DiscardCodeObjects keeping the Code of everything in
        # functions_called_dynamically_, checked on the obfuscated arm64 fixture, where
        # none of the 6421 such ranges carries the miss handler. No obfuscated arm32 or
        # iOS build exists here to check it on a second target.
        entry = (image.entry_offsets or {}).get(pc, 0)
        # A range that starts outside the image is not code this binary carries, so there
        # is no address to give for it. Giving one anyway would put a name, and an r2 or
        # IDA command, on an address the instructions image does not cover.
        if not 0 <= pc < len(image.text):
            dropped += 1
            continue
        # Sizes come from the snapshot too. No real binary has a range running past the
        # end of the image (0 on the clean, obfuscated and iOS fixtures), so a range that
        # does is a crafted one; it is cut at the end rather than sent to a tool as a
        # length to read, where it would name bytes that are not in the image.
        size = min(cr.size, len(image.text) - pc)
        # The entry offset comes from the snapshot as well and can be impossible. That is
        # a different thing from an architecture Jadart has no offset for, and the two get
        # different sentences: this one can name the numbers that make it impossible.
        entry_error = ""
        if entry:
            if entry >= size:
                entry_error = (f"the snapshot puts its entry 0x{entry:x} into a range of "
                               f"{size} bytes, so the entry is outside its own code")
            elif pc + entry >= len(image.text):
                entry_error = (f"the snapshot puts its entry at 0x{pc + entry:x}, past the "
                               f"end of the {len(image.text)}-byte instructions image")
            if entry_error:
                entry = None
        out.append(CodeSymbol(pc_offset=pc, size=size, va=image.anchor_va + pc,
                              file_offset=image.anchor_file_offset + pc, entry_offset=entry,
                              name=nm, origin=origin, owner=owner, library=library,
                              kind=kind, static=static, entry_error=entry_error))
    if dropped and not out:
        raise InputError(
            f"all {dropped} code ranges this snapshot declares start outside the "
            f"{len(image.text)}-byte instructions image that "
            f"{ISOLATE_INSTRUCTIONS} covers, so none of them has an address in this "
            f"binary")
    if dropped and notes is not None:
        notes.append(f"{dropped} of {dropped + len(out)} code ranges start outside the "
                     f"instructions image and are not listed")
    out.sort(key=lambda s: s.pc_offset)
    return out


def binary_info(image, hdr, label: str) -> dict:
    """What a consumer needs to compute its own addresses, whatever it does with them."""
    return {
        "file": label,
        "container": image.container,
        "arch": hdr.arch.name if hdr.arch is not None else "",
        "dart": hdr.epoch.dart if hdr.epoch is not None else "",
        "epoch": hdr.epoch.name if hdr.epoch is not None else "",
        "version_hash": hdr.version_hash,
        "anchor": {"symbol": ISOLATE_INSTRUCTIONS, "va": image.anchor_va,
                   "file_offset": image.anchor_file_offset, "size": len(image.text)},
        # dlsym on Apple prepends the underscore itself, so the runtime name drops it
        "runtime_symbol": (ISOLATE_INSTRUCTIONS[1:] if image.container == "macho"
                           else ISOLATE_INSTRUCTIONS),
    }


def symbols_document(image, hdr, syms: list, label: str, version: str) -> dict:
    return {
        "ok": True,
        "format": "jadart-symbols",
        "format_version": FORMAT_VERSION,
        "jadart": version,
        "binary": binary_info(image, hdr, label),
        "address_rule": ("va = anchor.va + pc_offset; file_offset = anchor.file_offset + "
                         "pc_offset; at run time, the address of runtime_symbol + pc_offset. "
                         "entry_va is where calls land when it differs from va."),
        "count": len(syms),
        "named": sum(1 for s in syms if s.name),
        "functions": [s.as_json() for s in syms],
    }


# ---------------------------------------------------------------------------
# Names and embedded data
# ---------------------------------------------------------------------------

_UNSAFE = re.compile(r"[^A-Za-z0-9_]+")
_PRINTABLE_ONLY = re.compile(r"[^\x20-\x7e]")

def _shown(text: str) -> str:
    """A name from the binary as a comment, a Ghidra symbol or a message shows it: escaped
    and cut at NAME_CUT, as every other surface prints a name (#94). Dart names are short;
    the length is the author's choice, so without a cut one name can inflate a script
    without bound (a 20,000 character name produced a 26 KB comment line)."""
    return visible(text, limit=NAME_CUT)


def safe_name(sym: CodeSymbol, prefix: str) -> str:
    """`prefix` + the name reduced to [A-Za-z0-9_] + the virtual address.

    The address makes it unique and ties it to the one range it names. The prefix keeps
    it off IDA's dummy prefixes (sub_, loc_) and off a leading digit."""
    core = _UNSAFE.sub("_", sym.qualified or sym.name).strip("_")[:180] or "anon"
    return f"{prefix}{core}_{sym.va:x}"


def entry_label(sym: CodeSymbol, prefix: str, sep: str = "_") -> str:
    """The label for the entry inside a range with a monomorphic entry. An anonymous range
    gets its address as well, since two with the same label would lose one to the tool's
    duplicate name check."""
    if sym.name:
        return f"{safe_name(sym, prefix)}{sep}entry"
    return f"{prefix}anon_{sym.va:x}{sep}entry"


def _comment(sym: CodeSymbol) -> str:
    parts = [f"Dart: {_shown(sym.qualified or sym.name)}"]
    if sym.library:
        parts.append(f"library: {_shown(sym.library)}")
    parts.append(f"name from: {sym.origin}")
    if sym.kind:
        parts.append(f"kind: {sym.kind}")
    if sym.entry_offset:
        parts.append(f"calls enter at +0x{sym.entry_offset:x}; the range starts on the "
                     f"monomorphic miss handler")
    return "\n".join(parts)


def _blob(obj) -> str:
    """JSON as base64. A name out of a hostile binary can hold a quote, a backslash or a
    newline; inside base64 none of them can end the string literal it is carried in."""
    raw = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return base64.b64encode(raw).decode("ascii")


def _checks(image, syms: list, n: int = 3) -> list:
    """A few ranges whose first bytes a script compares before applying anything.

    A pick needs 8 readable bytes inside the image: the sizes come from the snapshot, so
    the last range of a crafted one can claim to run past the end, and a short slice would
    weaken the check without saying so. If nothing qualifies the caller is told, rather
    than emitting a script whose header claims it checks the binary while it checks
    nothing."""
    ok = [s for s in syms
          if s.size >= 8 and s.pc_offset >= 0 and s.pc_offset + 8 <= len(image.text)]
    pool = [s for s in ok if s.name] or ok
    if not pool:
        raise InputError(
            "no code range in this binary has 8 bytes inside the instructions image, so "
            "a generated script would have nothing to check the binary against")
    picks = sorted({0, len(pool) // 2, len(pool) - 1})[:n]
    return [{"off": pool[i].pc_offset,
             "hex": image.text[pool[i].pc_offset:pool[i].pc_offset + 8].hex()}
            for i in picks]


def _header(tool: str, info: dict, count: int, named: int, version: str) -> list:
    """Comment lines for the top of a script. The label can hold an archive member name,
    which the APK's author chose; a line break in it would end the comment and run the
    rest as a command, so everything outside printable ASCII becomes `?`."""
    lines = [
        f"Jadart {version} symbols for {tool}: {named} named of {count} code ranges.",
        f"Binary: {info['file']}, Dart {info['dart']} ({info['epoch']}), "
        f"{info['arch']} {info['container']}.",
        f"Every offset is relative to {info['anchor']['symbol']}, so a rebased load still "
        f"lines up; the script checks known code bytes first and applies nothing on a "
        f"mismatch.",
    ]
    return [_PRINTABLE_ONLY.sub("?", line) for line in lines]


# ---------------------------------------------------------------------------
# radare2
# ---------------------------------------------------------------------------

def render_r2(image, hdr, syms: list, label: str, version: str) -> str:
    """A radare2 script: `r2 -i jadart.r2 libapp.so`, or `. jadart.r2` inside a session.

    The anchor is a flag: obj.* on ELF, where the symbol is an OBJECT, and sym.* on Mach-O.
    `?=` and `?==` set $? and `??` runs a command when it is nonzero; `?e` resets $?, so
    each test is computed again before the `q!!` that stops the script. Every name on a command line
    is the reduced one; the Dart name as written goes in as a base64 comment."""
    info = binary_info(image, hdr, label)
    flag = ("sym." if image.container == "macho" else "obj.") + ISOLATE_INSTRUCTIONS
    named = [s for s in syms if s.name]
    lines = [f"# {h}" for h in _header("radare2", info, len(syms), len(named), version)]
    # The binary radare2 has to open is the shared object, never the apk, ipa or directory
    # it came out of: `r2 -i script app.apk` would analyse the zip. Only a shared object is
    # echoed back; every other input points at the member jadart read inside it.
    member = info["file"].split("!")[-1].split("/")[-1]
    if not member.lower().endswith((".so", ".dylib")):
        member = "libapp.so"
    lines.append(f"# Run: r2 -i <this file> {_PRINTABLE_ONLY.sub('?', member)}")
    lines += [f"?= {flag}",
              f"?! ?e jadart: {flag} not found, nothing applied",
              f"?= {flag}",
              "?! q!!"]
    if image.container == "elf":
        size = len(image.text)
        lines += [f"?= `fl @ {flag}` - {size}",
                  f"?? ?e jadart: {flag} is not {size} bytes, wrong binary, nothing applied",
                  f"?= `fl @ {flag}` - {size}",
                  "?? q!!"]
    # The bytes are compared as p8 text. A [4:addr] read in an expression can return the
    # value of an earlier read (radare2 6.0.9), so it failed a correct binary.
    for c in _checks(image, syms):
        where = f"{flag}+0x{c['off']:x}"
        test = f"?== `p8 {len(c['hex']) // 2} @ {where}` {c['hex']}"
        lines += [test,
                  f"?? ?e jadart: code bytes at {where} differ, wrong binary, nothing applied",
                  test,
                  "?? q!!"]
    # Unbounded, af follows calls and runs past a range that ends in a call to a stub that
    # does not return: on the clean fixture `aaa` alone finds 6707 of the 8194 starts and
    # runs 652 functions past their end.
    # Each range is analysed inside its own bounds instead. Functions an earlier analysis
    # (aaa) left in the instructions are removed first, since af does not start inside one
    # and they cross the range bounds; this also makes running the script twice harmless.
    lo, hi = f"`?v {flag}-1`", f"`?v {flag}+{len(image.text)}`"
    lines += [f"af- @@c:afl,addr/gt/{lo},addr/lt/{hi},addr/cols,:quiet",
              "fs+jadart", "e anal.limits=true"]
    for s in syms:
        where = f"{flag}+0x{s.pc_offset:x}"
        lines += [f"e anal.from={where}",
                  f"e anal.to={where}+{s.size}"]
        if s.name:
            nm = safe_name(s, "dart.")
            lines.append(f"f {nm} {s.size} @ {where}")
            lines.append(f"af {nm} @ {where}")
            text = base64.b64encode(_comment(s).encode("utf-8")).decode("ascii")
            lines.append(f"CCu base64:{text} @ {where}")
        else:
            lines.append(f"af @ {where}")
        if s.entry_offset:
            lines.append(f"f {entry_label(s, 'dart.', '.')} 1 @ "
                         f"{flag}+0x{s.pc_offset + s.entry_offset:x}")
    lines.append("e anal.limits=false")
    lines.append("fs-")
    lines.append(f"?e jadart: named {len(named)} functions, defined {len(syms)} ranges")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Ghidra
# ---------------------------------------------------------------------------

_GHIDRA = '''# -*- coding: utf-8 -*-
# {header}
# Ghidra 12 runs Python only when started through pyghidraRun (the GUI, or -H for headless):
#   pyghidraRun -H <project dir> <project name> -import <binary> -postScript <this file>
# Ghidra 11 and older run it as Jython from the Script Manager or analyzeHeadless.
import base64
import json

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import Undefined
from ghidra.app.cmd.function import CreateFunctionCmd
from java.lang import Throwable

DATA = json.loads(base64.b64decode("{blob}").decode("ascii"))
ANCHOR = DATA["anchor"]


def hexbytes(addr, n):
    return "".join("%02x" % (b & 0xff) for b in getBytes(addr, n))


def clean(name):
    # Ghidra rejects only whitespace and control characters in a name
    return "".join(c if ord(c) > 0x20 else "_" for c in name)[:1900] or "anon"


def find_anchor():
    anchors = getSymbols(ANCHOR, None)
    if len(anchors) != 1:
        return None, "expected one %s symbol, found %d" % (ANCHOR, len(anchors))
    base = anchors[0].getAddress()
    for c in DATA["checks"]:
        got = hexbytes(base.add(c["off"]), len(c["hex"]) // 2)
        if got != c["hex"]:
            return None, "bytes at %s+0x%x are %s, expected %s: wrong binary" % (
                ANCHOR, c["off"], got, c["hex"])
    return base, None


def apply(base):
    # The ELF loader types a sized OBJECT symbol as one undefined1[N] array, and inside
    # it disassemble() and createFunction() quietly do nothing. Clear it once.
    covering = getDataContaining(base)
    if covering is not None and Undefined.isUndefinedArray(covering.getDataType()):
        clearListing(covering.getAddress(), covering.getMaxAddress())
    done = labels = failed = 0
    for s in DATA["syms"]:
        ea = base.add(s["off"])
        name = clean(s["name"]) if s["name"] else None
        try:
            if getInstructionAt(ea) is None:
                disassemble(ea)
            fn = getFunctionAt(ea)
            if fn is None:
                body = AddressSet(ea, ea.add(max(s["size"], 1) - 1))
                CreateFunctionCmd(name, ea, body, SourceType.USER_DEFINED).applyTo(currentProgram, monitor)
                fn = getFunctionAt(ea)
            if fn is not None:
                if name:
                    fn.setName(name, SourceType.USER_DEFINED)
                done += 1
            elif name:
                createLabel(ea, name, True, SourceType.USER_DEFINED)
                labels += 1
            if s.get("cmt"):
                setPlateComment(ea, s["cmt"])
            if s.get("entry"):
                createLabel(base.add(s["off"] + s["entry"]), clean(s["entry_name"]), False,
                            SourceType.USER_DEFINED)
        except (Exception, Throwable) as e:  # Jython does not route Java exceptions to Exception
            failed += 1
            printerr("jadart: %s at %s: %s" % (name, ea, e))
    println("jadart: anchor %s, functions=%d labels=%d failed=%d" % (base, done, labels, failed))


BASE, ERROR = find_anchor()
if ERROR:
    printerr("jadart: " + ERROR + ", nothing applied")
else:
    apply(BASE)
'''


def ghidra_name(sym: CodeSymbol) -> str:
    """Ghidra holds the Dart name as written, so it keeps the punctuation the reduced
    names lose; the address is still appended to make it unique.

    Without it 548 of the clean fixture's 5940 named ranges share a name with another
    (`toString` names 18), so the Symbol Tree cannot tell them apart and a crafted name
    can be made identical to a real one. The exact name as written is in the plate
    comment either way."""
    return f"{_shown(sym.qualified or sym.name)}_{sym.va:x}" if sym.name else \
        f"anon_{sym.va:x}"


def ghidra_entry(sym: CodeSymbol) -> str:
    return ghidra_name(sym) + "_entry"


def render_ghidra(image, hdr, syms: list, label: str, version: str) -> str:
    info = binary_info(image, hdr, label)
    named = sum(1 for s in syms if s.name)
    data = {"anchor": ISOLATE_INSTRUCTIONS, "checks": _checks(image, syms),
            "syms": [{"off": s.pc_offset, "size": s.size,
                      "name": ghidra_name(s) if s.name else "",
                      "cmt": _comment(s) if s.name else "", "entry": s.entry_offset or 0,
                      "entry_name": ghidra_entry(s) if s.entry_offset else ""}
                     for s in syms]}
    header = " ".join(_header("Ghidra", info, len(syms), named, version))
    return _GHIDRA.replace("{blob}", _blob(data)).replace("{header}", header)


# ---------------------------------------------------------------------------
# IDA
# ---------------------------------------------------------------------------

_IDA = '''# -*- coding: utf-8 -*-
# {header}
# IDA Pro 7.x to 9.x. GUI: File > Script file. Batch: idat -A -S"<this file> --exit" <binary>
# Not run against IDA itself: no IDA licence was available where this was built, so this
# script was checked against a model of ida_funcs/ida_name/ida_bytes that enforces IDA's
# rules (no overlapping functions, get_func containment, get_next_func ordering) over the
# real file bytes. The radare2 and Ghidra scripts were run against those tools for real.
# Uses ida_name, ida_funcs, ida_bytes, ida_ua and idc only: nothing from ida_struct, which IDA 9 removed.
from __future__ import print_function

import base64
import binascii
import json

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import ida_ua
import idc

DATA = json.loads(base64.b64decode("{blob}").decode("ascii"))
ANCHOR = DATA["anchor"]
BADADDR = ida_idaapi.BADADDR
# Names are already reduced to [A-Za-z0-9_] and unique; SN_NOCHECK is a second guard.
SN_FLAGS = ida_name.SN_NOCHECK | ida_name.SN_NOWARN


def resolve_anchor():
    ea = ida_name.get_name_ea(BADADDR, ANCHOR)
    if ea == BADADDR:
        print("jadart: %s not found in this database, nothing applied" % ANCHOR)
        return None
    for c in DATA["checks"]:
        raw = ida_bytes.get_bytes(ea + c["off"], len(c["hex"]) // 2)
        got = binascii.hexlify(raw).decode("ascii") if raw else ""
        if got != c["hex"]:
            print("jadart: bytes at %s+0x%x are %r, expected %s: wrong binary, nothing applied"
                  % (ANCHOR, c["off"], got, c["hex"]))
            return None
    return ea


def ensure_function(ea, size):
    end = ea + max(size, 1)
    fn = ida_funcs.get_func(ea)
    if fn is not None and fn.start_ea != ea:
        # Auto analysis ran another function on into this range, or made this range a
        # tail chunk of one. Remove it; one that started earlier is put back ending here.
        start = fn.start_ea
        ida_funcs.del_func(start)
        if start < ea:
            ida_funcs.add_func(start, ea)
    # A function auto analysis started inside the range cuts this one short. Calls into a
    # Code object with a monomorphic entry land 24 bytes in, so IDA starts one there.
    nxt = ida_funcs.get_next_func(ea)
    while nxt is not None and nxt.start_ea < end:
        start = nxt.start_ea
        ida_funcs.del_func(start)
        nxt = ida_funcs.get_next_func(start)
    fn = ida_funcs.get_func(ea)
    if fn is None:
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
            ida_ua.create_insn(ea)
        ida_funcs.add_func(ea, end)
    elif fn.end_ea != end:
        ida_funcs.set_func_end(ea, end)
    fn = ida_funcs.get_func(ea)
    return fn is not None and fn.start_ea == ea and fn.end_ea == end


def main():
    base = resolve_anchor()
    if base is None:
        return 1
    funcs = inexact = named = failed = 0
    for s in DATA["syms"]:
        ea = base + s["off"]
        if ensure_function(ea, s["size"]):
            funcs += 1
        else:
            inexact += 1
        if s["name"]:
            if ida_name.set_name(ea, s["name"], SN_FLAGS):
                named += 1
            else:
                failed += 1
                print("jadart: could not name 0x%x as %s" % (ea, s["name"]))
            if ida_funcs.get_func(ea) is not None:
                idc.set_func_cmt(ea, s["cmt"], 1)
            else:
                idc.set_cmt(ea, s["cmt"], 1)
        if s.get("entry"):
            ida_name.set_name(ea + s["entry"], s["entry_name"], SN_FLAGS)
    print("jadart: anchor 0x%x, functions=%d not_exact=%d named=%d failed=%d"
          % (base, funcs, inexact, named, failed))
    return 0 if failed == 0 else 2


rc = main()
if "--exit" in getattr(idc, "ARGV", []):
    idc.qexit(rc)
'''


def render_ida(image, hdr, syms: list, label: str, version: str) -> str:
    info = binary_info(image, hdr, label)
    named = sum(1 for s in syms if s.name)
    data = {"anchor": ISOLATE_INSTRUCTIONS, "checks": _checks(image, syms),
            "syms": [{"off": s.pc_offset, "size": s.size,
                      "name": safe_name(s, "dart_") if s.name else "",
                      "cmt": _comment(s) if s.name else "", "entry": s.entry_offset or 0,
                      "entry_name": entry_label(s, "dart_") if s.entry_offset else ""}
                     for s in syms]}
    header = " ".join(_header("IDA", info, len(syms), named, version))
    return _IDA.replace("{blob}", _blob(data)).replace("{header}", header)


RENDERERS = {"ida": render_ida, "ghidra": render_ghidra, "r2": render_r2}
