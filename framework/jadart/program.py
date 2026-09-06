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
from .snapshot import parse_blob, UnknownEpoch
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


# Dart FunctionLayout::Kind (low bits of kind_tag) for this epoch. Only the values we
# label are listed; anything else stays a plain method.
_FN_KIND = {5: "ctor", 3: "getter", 4: "setter"}


def _decode_fn_kind(kind_tag: int) -> str:
    return _FN_KIND.get(kind_tag & 0x1F, "method")


# Function::Kind indices, FOR_EACH_RAW_FUNCTION_KIND in raw_object.h. The SDK's own
# comments state the staticness of these by definition, which is what makes them usable as
# witnesses: ImplicitGetter/ImplicitSetter are "for instance fields", MethodExtractor
# returns "a closure on the receiver", the dispatchers and the dynamic forwarder all act on
# a receiver, and ImplicitStaticGetter is "for static fields".
_KIND_INSTANCE = frozenset({6, 7, 10, 11, 12, 14, 16})
_KIND_STATIC = frozenset({8})


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


def receiver_for(func_ref: int, static_refs: frozenset) -> dict:
    """The lifter's `receiver` argument: x1 holds `this` only for an instance method.

    Passing `{"x1": "this"}` unconditionally printed a receiver that does not exist in
    every static and top-level function, roughly 450 of them on the corpus binary,
    across about 1,900 output lines. x1 there is the first real parameter, so the rendered
    code attributed a field access to a `this` the function was never handed.
    """
    return {} if func_ref in static_refs else {"x1": "this"}


def build_program(fr, hdr) -> Program:
    """Resolve a completed fill-walk result into the Program model (names, owners,
    fields, superclasses). Shared by recover_program and the decompile view."""
    S = fr.strings

    classes = []
    by_ref = {}
    by_cid = {}
    for ref, name_ref, cid, super_ref in fr.classes:
        k = Klass(ref=ref, name=S.get(name_ref, ""), class_id=cid,
                  library=fr.library_urls.get(fr.class_library.get(ref, -1), ""))
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

    return Program(epoch_name=hdr.epoch.name, dart=hdr.epoch.dart, strings=S,
                   classes=classes, num_objects=hdr.num_objects,
                   num_predefined_cids=hdr.epoch.num_predefined_cids)


def recover_program(path: str) -> Program:
    """Full pipeline on the isolate snapshot: header -> alloc walk -> fill walk ->
    resolve names/owners/fields/superclasses. Fail-loud on unknown epoch or desync."""
    blob = open_container(open(path, "rb").read()).symbol_bytes(
        "_kDartIsolateSnapshotData")
    hdr = parse_blob(blob, "isolate", strict=True)
    if hdr.epoch is None:
        raise UnknownEpoch(f"unknown epoch for {path}")
    st = ReadStream(blob, 52)
    st.read_cstring()
    for _ in range(5):
        st.read_unsigned()
    clusters = walk_alloc(st, hdr.num_base_objects, hdr.num_objects, hdr.num_clusters,
                          epoch=hdr.epoch, is_root_unit=True, arch=hdr.arch)
    fr = walk_fill(st, clusters, hdr.epoch, arch=hdr.arch)
    return build_program(fr, hdr)


def decompile_class(path: str, class_name: str, max_methods: int = 40,
                    structured: bool = True, tier: int = 3,
                    sigs: str | None = None) -> str | None:
    """The unified JADX-for-Flutter view: the Tier 0 class header (extends + members)
    with each method's body, at the requested tier:
      tier 3 (default): expression reconstruction (pseudo-Dart statements)
      tier 2:           control-flow skeleton with annotated arm64 bodies
      tier 1:           block-labelled annotated arm64 (structured=False)
    structured=False forces tier 1."""
    from .disasm import (load_instructions, disassemble_function, build_pool_map,
                         render_body, annotate, truncated_by)
    from .signatures import names_with_signatures
    from .cfg import build_cfg, structure, render as render_cfg
    from .expr import lift_function, make_arity_resolver
    from .dispatch import recover_selectors
    from .fields import recover_fields
    image, fr, hdr = load_instructions(path)
    prog = build_program(fr, hdr)
    S = fr.strings

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
    # class members receive `this` in x1 (Dart AOT: the receiver is the first argument)
    static_refs = static_function_refs(fr)
    arity = make_arity_resolver(image) if lvl >= 3 else None
    selectors = recover_selectors(image, fr, hdr) if lvl >= 3 else None
    layout = recover_fields(fr, getattr(image, "arch", None)) if lvl >= 3 else None
    for nm, ref, kt in sorted(method_refs)[:max_methods]:
        disp = nm.split(":", 1)[1] if nm.startswith(("get:", "set:")) else nm.rstrip(".")
        dis = disassemble_function(image, ref)
        if not dis:
            lines.append(f"  {disp}();  // no code (inlined / abstract / no range)")
            continue
        cr = image.code_ranges[ref]
        cut = truncated_by(cr, dis)
        note = f", TRUNCATED: {len(dis)} of {len(dis) + cut} instructions" if cut else ""
        lines.append(f"  {disp}() {{  // .text+0x{cr.pc_offset:x}, {cr.size} bytes{note}")
        if lvl >= 3:
            ann = annotate(dis, pc_to_name, pool_map)
            lines.extend(lift_function(ann, pool_map,
                                       receiver=receiver_for(ref, static_refs),
                                       arity=arity, indent="  ", depth=2,
                                       selectors=selectors,
                                       arch=getattr(image, "arch", None),
                                       fields=layout.for_function(ref)))
        elif lvl == 2:
            ann = annotate(dis, pc_to_name, pool_map)
            blocks, entry = build_cfg(ann)
            lines.extend(render_cfg(blocks, structure(blocks, entry), indent="  ", depth=2))
        else:
            lines.extend(render_body(dis, pc_to_name, pool_map, indent="      "))
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
