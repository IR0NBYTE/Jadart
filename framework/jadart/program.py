"""Recovered-program model + Tier 0 skeleton emitter (jadart M3 / Tier 0+).

Ties the alloc walk + fill walk together and resolves the object graph into a
readable program: classes (with name, superclass, fields, methods) and functions.
`emit_tier0` renders that as skeleton Dart, the "JADX moment": a navigable
class/method/field tree, which no other Flutter RE tool produces. Bodies are out
of scope for Tier 0 (they need the instruction lift).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .stream import ReadStream
from .macho import open_container
from . import versions, cids as C
from .snapshot import images, parse_blob, UnknownEpoch
from .clusters import walk_alloc
from .fillwalk import walk_fill


@dataclass
class Member:
    name: str
    kind: str = "method"    # method | ctor | getter | setter | field
    offset: int = -1        # fields: byte offset in the instance, -1 for a static or when
                            # this Field object did not survive with its offset (fields.py)
    unboxed: bool = False   # fields: the slot holds a raw int/double, not a tagged pointer


@dataclass
class Klass:
    ref: int
    name: str
    class_id: int
    super_name: str = ""
    members: list = field(default_factory=list)
    library: str = ""       # the library url this class was declared in, e.g.
                            # "package:myapp/main.dart" or "dart:core"


@dataclass
class Program:
    epoch_name: str
    dart: str
    strings: dict           # ref -> str
    classes: list           # Klass (all)
    num_objects: int
    num_predefined_cids: int = 0   # from the epoch; 0 falls back to the bundled cid table

    def libraries(self) -> dict:
        """library url -> [Klass], for every class that records one.

        The url comes out of the snapshot, so telling application code from framework code
        needs no reference binary and no list of known packages: an app's own classes sit
        under its own package, e.g. "package:myapp/main.dart"."""
        out: dict = {}
        for k in self.classes:
            if k.library:
                out.setdefault(k.library, []).append(k)
        return out

    def user_classes(self) -> list:
        """Classes with an app/framework cid (>= predefined boundary) and a real name.

        The boundary is the EPOCH's, not the bundled table's. cids.py is generated from a
        newer SDK and reports 176 predefined cids where this epoch has 175, which silently
        dropped the class at cid 175 (`Vector4`) from every Tier 0 listing."""
        b = self.num_predefined_cids or C.NUM_PREDEFINED_CIDS
        return [k for k in self.classes
                if (k.class_id & 0xFFFFFFFF) >= b and k.name and not k.name.startswith("<")]


# FOR_EACH_RAW_FUNCTION_KIND, raw_object.h, in declaration order. Function.kind_tag
# carries the index in its low five bits, so this is per-release data in principle:
# inserting a kind renumbers everything after it, and the cid table proves the SDK does
# that between releases. In practice it has not moved. raw_object.h was fetched for every
# one of the 19 registered releases, 2.19.0-444.2.beta through 3.13.0, and all 19 declare
# exactly this list. When a release newer than 3.13 is registered, repeat that check:
#
#   from tools.sdk_source import fetch
#   re.findall(r"V\((\w+)\)", fetch(tag, "raw_object.h").decode())  # inside the macro
#
# and if the list differs, this table moves onto Epoch beside the cid table.
_FUNCTION_KINDS = (
    "RegularFunction", "ClosureFunction", "ImplicitClosureFunction", "GetterFunction",
    "SetterFunction", "Constructor", "ImplicitGetter", "ImplicitSetter",
    "ImplicitStaticGetter", "FieldInitializer", "MethodExtractor",
    "NoSuchMethodDispatcher", "InvokeFieldDispatcher", "IrregexpFunction",
    "DynamicInvocationForwarder", "FfiTrampoline", "RecordFieldGetter",
)
_KIND_INDEX = {name: i for i, name in enumerate(_FUNCTION_KINDS)}

# Only the kinds that get a label; anything else prints as a plain method.
_FN_KIND = {_KIND_INDEX["Constructor"]: "ctor",
            _KIND_INDEX["GetterFunction"]: "getter",
            _KIND_INDEX["SetterFunction"]: "setter"}


def _decode_fn_kind(kind_tag: int) -> str:
    return _FN_KIND.get(kind_tag & 0x1F, "method")


# Kinds whose staticness the SDK's own comments state by definition, which is what makes
# them usable as witnesses: ImplicitGetter/ImplicitSetter are "for instance fields",
# MethodExtractor returns "a closure on the receiver", the dispatchers and the dynamic
# forwarder all act on a receiver, and ImplicitStaticGetter is "for static fields".
_KIND_INSTANCE = frozenset(_KIND_INDEX[n] for n in (
    "ImplicitGetter", "ImplicitSetter", "MethodExtractor", "NoSuchMethodDispatcher",
    "InvokeFieldDispatcher", "DynamicInvocationForwarder", "RecordFieldGetter"))
_KIND_STATIC = frozenset({_KIND_INDEX["ImplicitStaticGetter"]})


def static_bit(fr) -> int | None:
    """Which bit of Function.kind_tag is StaticBit, calibrated against this binary.

    Not hardcoded, because the position is derived three widths deep,
    `StaticBit = ModifierBits::kNextBit`, and ModifierBits sits above RecognizedBits which
    sits above KindBits (object.h), so any of them can move between releases and a
    wrong constant would silently mislabel every method.

    Instead, solve for it. Some function kinds have a staticness the SDK fixes by
    definition, so the answer is the bit that is 0 for every instance witness and 1 for
    every static one. Returns None when no bit or more than one bit fits, and the caller
    must then decline to claim anything: with only three witness kinds the obfuscated
    build admitted both bit 3 and bit 16, which is exactly the ambiguity this has to
    report rather than resolve by picking. Measured bit 16 on 2.19.6 through 3.12.2,
    obfuscated builds included.
    """
    inst = [kt for _r, _n, _o, kt in fr.functions if (kt & 0x1F) in _KIND_INSTANCE]
    stat = [kt for _r, _n, _o, kt in fr.functions if (kt & 0x1F) in _KIND_STATIC]
    if not inst or not stat:
        return None
    fits = [b for b in range(32)
            if all(not (k >> b) & 1 for k in inst) and all((k >> b) & 1 for k in stat)]
    return fits[0] if len(fits) == 1 else None


def static_function_refs(fr) -> frozenset:
    """Refs of the functions that take no receiver. Empty when the bit is unresolvable,
    which makes every caller fall back to treating functions as instance methods."""
    b = static_bit(fr)
    if b is None:
        return frozenset()
    return frozenset(r for r, _n, _o, kt in fr.functions if (kt >> b) & 1)


def instance_function_refs(fr) -> frozenset:
    """Refs of the Functions that take a receiver: every Function the static bit leaves
    clear, and every Function where the bit does not calibrate, the fallback
    static_function_refs describes.

    Only a Function is ever in it. A range whose Code has some other owner, or no Code at
    all, is the code of no Function this snapshot still describes, so nothing in it says
    the range takes a receiver (#259)."""
    static = static_function_refs(fr)
    return frozenset(r for r, _n, _o, _kt in fr.functions if r not in static)


def receiver_for(owner_ref: int, *, instance_refs: frozenset) -> dict:
    """The lifter's `receiver` argument: x1 holds `this` only where the code is an
    instance method's. `owner_ref` is the owner of the range's Code (CodeRange.owner_ref)
    and `instance_refs` is instance_function_refs(fr). It is keyword-only because it
    replaced a positional set of the STATIC functions: a caller still handing that over
    by position fails here rather than giving every static function `this` (#259).

    Passing `{"x1": "this"}` unconditionally printed a receiver that does not exist in
    every static and top-level function, roughly 450 of them on the corpus binary,
    across about 1,900 output lines. x1 there is the first real parameter, so the rendered
    code attributed a field access to a `this` the function was never handed.

    Asking only whether the owner was static still printed `this` wherever the owner was
    not a Function at all, and an obfuscated build discards most of them. On the obf
    fixture 6,421 ranges have no Code object and 185 a Smi in place of a dropped
    Function; on both fixtures 921 are owned by a Class (allocation stubs), 339 and 338
    by a type (type-testing stubs) and 85 by null (the VM's stubs). `benchCheckSecret`, a
    top-level function, printed `this.sel_0x0(...)` on obf and `x1.sel_0x0(...)` on
    clean. Whether such a range takes a receiver is not stated, so x1 stays a register.

    Nothing else in the snapshot proves it for them either. The dispatch table only
    holds instance methods, but AOT shares one Code between functions whose instructions
    match, and 2 of its 2,563 targets on the clean fixture are owned by a static
    closure: 0x2b5900 is a `return NULL;` that static functions, constructors and
    closures share. The monomorphic-entry flag marks only instance code, but its 78 Code
    objects all have a Function owner on both fixtures, so it adds no range."""
    return {"x1": "this"} if owner_ref in instance_refs else {}


class EntryNames:
    """What the argument registers hold when a function is entered, per code range: the
    lifter's `receiver` map (`names`) and the list a signature line prints (`params`).

    x1 is `this` exactly where `receiver_for` says so. Past that, a register gets a name
    where three things hold, each read from the binary:

    * the release passes fixed parameters in registers at all. That is Dart 3.4 on, and
      the snapshot hash pins the release (hooks._register_cc);
    * the code is a Dart function's, of a kind the VM does not always call through the
      stack (`_function_code`);
    * the body reads the register before it writes it, by the pass every call site
      already asks for a callee's arity (expr.make_arity_resolver, entry_args). Compiled
      Dart reads no register it was not handed, so such a register holds what the caller
      left in it, and in a register of DartCallingConvention::kCpuRegistersForArgs under
      that convention that is an argument.

    Where the resolver declines (an arguments descriptor, stack arguments only, a double
    in a V register) nothing is named and the body keeps its bare registers, as it does
    for an argument register the body never reads.

    The name states which register and nothing more. `aN` is the value the function was
    entered with in register N of x1, x2, x3, x5, x6, x7, counted from 0, so `a0` is the
    slot an instance method has `this` in and `a1` is always what arrived in x2. That is
    also its position in the list a direct call to the function prints, which is built
    from the same registers in the same order (Lifter._call_args). It is NOT a position
    in the Dart parameter list, which the snapshot does not state: a double is passed in
    a V register beside these, so in `f(double a, Object b)` it is `b` that arrives in
    x1. And it is no Dart name or type, neither of which survives for these.

    Whether a register STILL holds that value at a given use is the lifter's to decide,
    and it decides it the way it always has for `this`: `Lifter._leaf` prints the name
    only while the state map has never recorded the register, on any path."""

    def __init__(self, image, fr, epoch, arity):
        from .expr import LIFTABLE_ARCHS, TARGETS
        arch = getattr(getattr(image, "arch", None), "name", None)
        tgt = TARGETS.get(arch) if arch in LIFTABLE_ARCHS else None
        self._arity = arity
        self._instance = instance_function_refs(fr)
        self._owners, self._discarded = _function_code(image, fr, epoch)
        #: No registers where the target is not one tier 3 lifts or the release has no
        #: register convention, and then the resolver is never asked.
        has_code = bool(self._owners or self._discarded)
        self._regs = tgt.arg_regs if tgt is not None and has_code else ()

    def _read(self, cr) -> tuple:
        """(the resolver's count, the registers to name) for the code at `cr`: (None, ())
        where the resolver is not asked or declines, and no register where the code is
        not a function's."""
        args = getattr(self._arity, "args", None)
        if args is None or not self._regs:
            return None, ()
        k = self._arity(cr.pc_offset)
        if cr.owner_ref == -1:
            mine = cr.pc_offset in self._discarded
        else:
            mine = cr.owner_ref in self._owners
        return k, (args(cr.pc_offset) if mine and k is not None else ())

    def names(self, cr) -> dict:
        """{register: name} for the code range `cr`."""
        names = receiver_for(cr.owner_ref, instance_refs=self._instance)
        for reg in self._read(cr)[1]:
            names.setdefault(reg, f"a{self._regs.index(reg)}")
        return names

    def params(self, cr) -> str:
        """What a signature line puts between its brackets: the names the body reads its
        register arguments by, in call order and without the receiver; nothing where it
        reads none; and `...` where the list is not read, the spelling a call whose list
        is not read already has. A function that takes more on the stack ends in `...`.

        It lists what the BODY READS. A parameter the body never reads is not in it, so
        `f(a1, a3)` reads the registers either side of one it leaves alone, and nothing
        here says how many parameters the Dart function declares."""
        from .expr import StackArity
        k, regs = self._read(cr)
        if k is None or (k and not regs):
            return "..."
        names = self.names(cr)
        listed = [names[r] for r in regs if names[r] != "this"]
        if isinstance(k, StackArity):
            listed.append("...")
        return ", ".join(listed)


def _function_code(image, fr, epoch) -> tuple:
    """(owner refs, pcs): the code that is a Dart function's and may be entered with its
    fixed parameters in registers. Both empty where the release does not pass them so.

    A range is one in three ways, each read from the snapshot:

    * its Code is owned by a Function whose kind the VM does not always call through the
      stack (hooks.STACK_KINDS, which is `MaxNumberOfParametersInRegisters` in object.cc).
      Belt and braces: of the clean fixture's 1,075 ranges of those kinds the resolver
      counts a register for none, 249 read nothing and 826 decline;
    * its Code is owned by a Smi holding the Function class id. The precompiler leaves
      that behind when it drops a Function and keeps its Code: `owner =
      WeakSerializationReference::New(owner, Smi::New(owner.GetClassId()))`
      (precompiler.cc, drop_function, 3.12.2), and the serializer writes the
      replacement. 185 ranges of the obf fixture, none of the clean one;
    * it has no Code object at all, an instructions-table entry below
      `first_entry_with_code`. Only a function's Code is discarded: "Only discard Code
      objects corresponding to Dart functions", `if (!code.IsFunctionCode() ||
      code.IsUnknownDartCode()) return;` (precompiler.cc, DiscardCodeObjects, 3.12.2).
      6,421 ranges of the obf fixture, which is every range of it with no owner.

    Everything else is left out on purpose. An allocation stub is owned by its Class, a
    type-testing stub by its type, and the VM's own stubs by nothing, and each takes its
    operands in the registers of an ABI of its own (constants_arm64.h, TypeTestABI: the
    instance in x0, the type arguments in x2 and x1), so what x1 holds there is not an
    argument of the Dart calling convention. On the clean fixture 64 such ranges read an
    argument register on entry: 37 owned by a type, 26 VM stubs and 1 other.

    The facts this rests on were read at 3.12.2 and checked unchanged at 3.13.0: the
    argument registers, TypeTestABI's preserved registers, drop_function,
    DiscardCodeObjects and MaxNumberOfParametersInRegisters. `_register_cc` has no upper
    bound, so when a release newer than 3.13 is registered, repeat that check.
    """
    from .hooks import STACK_KINDS, _register_cc
    if epoch is None or not _register_cc(epoch.dart):
        return frozenset(), frozenset()
    owners = set()
    for ref, _n, _o, kt in fr.functions:
        kind = kt & 0x1F
        if kind < len(_FUNCTION_KINDS) and _FUNCTION_KINDS[kind] not in STACK_KINDS:
            owners.add(ref)
    cid = epoch.cid_table.get("FunctionCid")
    if cid >= 0:
        owners.update(ref for ref, v in fr.smi_values.items() if v == cid)
    discarded = frozenset(image.pcs[:max(image.first_code, 0)])
    return frozenset(owners), discarded


def build_program(fr, hdr, raw: bool = False) -> Program:
    """Resolve a completed fill-walk result into the Program model (names, owners,
    fields, superclasses). Shared by recover_program and the decompile view.

    Names and library urls are escaped and cut as names (fill.visible, #74, #94), since
    they come out of the binary and are printed; `raw` keeps them as written, for
    interop, which escapes and cuts them itself where it prints them."""
    from .fill import NAME_CUT, visible
    S = fr.strings if raw else fr.names

    def url(ref):
        u = fr.library_urls.get(fr.class_library.get(ref, -1), "")
        return u if raw else visible(u, limit=NAME_CUT)

    classes = []
    by_ref = {}
    by_cid = {}
    for ref, name_ref, cid, super_ref in fr.classes:
        k = Klass(ref=ref, name=S.get(name_ref, ""), class_id=cid, library=url(ref))
        classes.append(k)
        by_ref[ref] = k
        by_cid[cid & 0xFFFFFFFF] = k
        k._super_ref = super_ref   # temp, resolved below

    # superclass: class.super_type ref -> Type -> type_class_id -> class name
    for k in classes:
        tcid = fr.types.get(getattr(k, "_super_ref", -1))
        if tcid is not None:
            sup = by_cid.get(tcid & 0xFFFFFFFF)
            if sup and sup.name and not sup.name.startswith("<"):
                k.super_name = sup.name

    # methods (Function.owner) + fields (Field.owner) grouped into their class
    for ref, name_ref, owner_ref, kind_tag in fr.functions:
        owner = by_ref.get(owner_ref)
        nm = S.get(name_ref, "")
        if owner and nm:
            owner.members.append(Member(name=nm, kind=_decode_fn_kind(kind_tag)))
    # A surviving Field still says where it lives, so Tier 0 can print the layout and not
    # only the name list. See fields.py for why that is a fact rather than an inference.
    from .fields import recover_fields
    layout = recover_fields(fr, hdr.arch)
    for ref, name_ref, owner_ref in fr.fields:
        owner = by_ref.get(owner_ref) or by_ref.get(fr.patch_class.get(owner_ref, -1))
        nm = S.get(name_ref, "")
        if owner and nm:
            off = layout.offset_of.get(ref, -1)
            fi = layout.by_class.get(owner.ref, {}).get(off)
            owner.members.append(Member(name=nm, kind="field", offset=off,
                                        unboxed=bool(fi and fi.unboxed)))

    return Program(epoch_name=hdr.epoch.name, dart=hdr.epoch.dart, strings=fr.strings,
                   classes=classes, num_objects=hdr.num_objects,
                   num_predefined_cids=hdr.epoch.num_predefined_cids)


def recover_program(path) -> Program:
    """Full pipeline on the isolate snapshot: header -> alloc walk -> fill walk ->
    resolve names/owners/fields/superclasses. Fail-loud on unknown epoch or desync."""
    from .source import read_binary
    src = read_binary(path)
    container = open_container(src.data)
    blob = container.symbol_bytes(images(container, src.label).data)
    hdr = parse_blob(blob, "isolate", strict=True)
    if hdr.epoch is None:
        raise UnknownEpoch(f"unknown epoch for {src.label}")
    st = ReadStream(blob, 52)
    st.read_cstring()
    for _ in range(5):
        st.read_unsigned()
    clusters = walk_alloc(st, hdr.num_base_objects, hdr.num_objects, hdr.num_clusters,
                          epoch=hdr.epoch, is_root_unit=True, arch=hdr.arch)
    fr = walk_fill(st, clusters, hdr.epoch, arch=hdr.arch)
    return build_program(fr, hdr)


def decompile_class(path, class_name: str, max_methods: int = 40,
                    structured: bool = True, tier: int = 3,
                    sigs: str | None = None) -> str | None:
    """The unified JADX-for-Flutter view: the Tier 0 class header (extends + members)
    with each method's body, at the requested tier:
      tier 3 (default): expression reconstruction (pseudo-Dart statements)
      tier 2:           control-flow skeleton with annotated arm64 bodies
      tier 1:           block-labelled annotated arm64 (structured=False)
    structured=False forces tier 1."""
    from .branches import exits, row_kinds
    from .disasm import (load_instructions, disassemble_function, build_pool_map,
                         render_body, annotate, truncated_by, addr_label, rebaser,
                         cut_end)
    from .signatures import names_with_signatures
    from .cfg import render_function
    from .expr import lift_function, make_arity_resolver, make_return_resolver
    from .dispatch import recover_selectors
    from .fields import recover_allocations, recover_fields
    image, fr, hdr = load_instructions(path)
    prog = build_program(fr, hdr)
    S = fr.names                         # names, as printed (#74)

    targets = [k for k in prog.user_classes() if k.name == class_name]
    if not targets:
        return None                      # not found: caller decides how to report
    k = targets[0]

    # function name+ref by owner class ref
    cls_ref = {kk.name: kk.ref for kk in prog.classes}
    my_ref = cls_ref.get(class_name)
    method_refs = [(S.get(nr, ""), ref, kt) for ref, nr, ow, kt in fr.functions
                   if ow == my_ref and S.get(nr)]

    pc_to_name, signote = names_with_signatures(image, fr, sigs)
    pool_map = build_pool_map(fr, getattr(image, "arch", None))

    tname = {1: "Tier 1 annotated " + (getattr(getattr(image, "arch", None), "name", None) or "arm64"),
             2: "Tier 2 control-flow", 3: "Tier 3 expressions"}
    lvl = 1 if not structured else tier
    head = f"class {k.name}"
    if k.super_name and k.super_name != "Object":
        head += f" extends {k.super_name}"
    lines = [f"// jadart decompile ({tname.get(lvl, 'Tier 3 expressions')}, "
             f"epoch {prog.epoch_name}, dart {prog.dart})"]
    if signote:
        lines.append(f"// {signote}")
    lines.append(head + " {")
    # an instance method receives `this` in x1, the first argument (receiver_for)
    arity = make_arity_resolver(image) if lvl >= 3 else None
    entry = EntryNames(image, fr, hdr.epoch, arity) if lvl >= 3 else None
    returns = make_return_resolver(image) if lvl >= 3 else None
    selectors = recover_selectors(image, fr, hdr) if lvl >= 3 else None
    layout = recover_fields(fr, getattr(image, "arch", None)) if lvl >= 3 else None
    allocs = recover_allocations(image, fr, layout) if lvl >= 3 else None
    for nm, ref, kt in sorted(method_refs)[:max_methods]:
        disp = nm.split(":", 1)[1] if nm.startswith(("get:", "set:")) else nm.rstrip(".")
        dis = disassemble_function(image, ref)
        if not dis:
            lines.append(f"  {disp}();  // no code (inlined / abstract / no range)")
            continue
        cr = image.code_ranges[ref]
        cut = truncated_by(cr, dis)
        note = f", TRUNCATED: {len(dis)} of {len(dis) + cut} instructions" if cut else ""
        # The names the tier 3 body reads its arguments by. The other tiers print the
        # machine's registers, so their brackets stay empty, as they were.
        params = entry.params(cr) if entry is not None else ""
        lines.append(f"  {disp}({params}) {{  // {addr_label(image, cr.pc_offset)}, "
                     f"{cr.size} bytes{note}")
        if lvl >= 3:
            ann = annotate(dis, pc_to_name, pool_map, kinds=row_kinds(image, dis))
            lines.extend(lift_function(ann, pool_map,
                                       receiver=entry.names(cr),
                                       arity=arity, indent="  ", depth=2,
                                       selectors=selectors,
                                       arch=getattr(image, "arch", None),
                                       fields=layout.for_function(ref),
                                       allocs=allocs,
                                       show=rebaser(image), cut_end=cut_end(cr, dis),
                                       returns=returns))
        elif lvl == 2:
            ann = annotate(dis, pc_to_name, pool_map, kinds=row_kinds(image, dis))
            lines.extend(render_function(ann, exits=exits(image, dis),
                                         cut_end=cut_end(cr, dis), indent="  ", depth=2,
                                         show=rebaser(image)))
        else:
            lines.extend(render_body(dis, pc_to_name, pool_map, indent="      ",
                                     kinds=row_kinds(image, dis), show=rebaser(image)))
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines)


def emit_tier0(prog: Program, name_filter: str | None = None) -> str:
    """Render a Tier 0 skeleton: classes with superclass, fields, and methods."""
    def keep(k: Klass) -> bool:
        if name_filter is None:
            return True
        return name_filter in k.name or any(name_filter in m.name for m in k.members)

    order = {"field": 0, "ctor": 1, "getter": 2, "setter": 3, "method": 4}
    out = []
    for k in sorted(prog.user_classes(), key=lambda x: x.name):
        if not keep(k):
            continue
        head = f"class {k.name}"
        if k.super_name and k.super_name != "Object":
            head += f" extends {k.super_name}"
        out.append(head + " {")
        seen = set()
        for m in sorted(k.members, key=lambda m: (order.get(m.kind, 9), m.name)):
            # strip Dart's internal name decorations (get:/set: prefixes, ctor trailing dot)
            nm = m.name.split(":", 1)[1] if m.name.startswith(("get:", "set:")) else m.name
            if m.kind == "field":
                # The offset is where the reader goes when the receiver is a bare register
                # and the name cannot be substituted: `x2.field_0x18` is this slot.
                where = (f";   // @0x{m.offset:x}" + (" unboxed" if m.unboxed else "")
                         if m.offset >= 0 else ";")
                sig, suffix = nm, where
            elif m.kind == "getter":
                sig, suffix = f"get {nm}", ";"
            elif m.kind == "setter":
                sig, suffix = f"set {nm}(_)", " { ... }"
            elif m.kind == "ctor":
                sig, suffix = f"{nm.rstrip('.')}()", " { ... }"
            else:
                sig, suffix = f"{nm}()", " { ... }"
            if (m.kind, sig) in seen:
                continue
            seen.add((m.kind, sig))
            out.append(f"  {sig}{suffix}")
        out.append("}")
    return "\n".join(out)
