"""What an ObjectPool slot holds, read from the snapshot.

One reader for the three places that ask: `xrefs pool` says what any slot holds (#443),
and the lifter prints a slot loaded as a double by its number (#362) and a slot holding
a const instance by its class and fields (#363), where before all three said
`pool_0x...`.

Everything here comes out of the binary and is printed, so it is bounded the way names
and literals already are: a string is cut and escaped by fill.quoted, a name comes
through fr.names, an instance is spelled to at most _CUT characters and _DEPTH levels
(an instance can name itself), and each answer is worked out once per object. Where the
snapshot does not say what a thing is, this says what it does know, a class id or a ref,
and no more: a field the class keeps unboxed is `?`, since its bits alone do not say
whether they are an int or a double, and an object of the vm snapshot is only a ref.
"""
from __future__ import annotations

import bisect
import re
import struct

_M64 = 0xFFFFFFFFFFFFFFFF
#: The quiet NaN `double.nan` is on every target Dart compiles for (0.0 / 0.0 on arm64
#: and x64 alike). Another NaN has bits no literal gives back, so it is not printed.
_NAN = 0x7FF8000000000000
#: The longest an instance is spelled, as printed, and how deep it opens the instances
#: it names. Past either it ends `...`, so a crafted instance that names itself, or a
#: long chain of them, costs this much and no more.
_CUT = 200
_DEPTH = 2
#: How long a string a field holds may print inside an instance, quoted.
_FIELD_STR = 40
#: How many of an instance's fields `xrefs -j` lists.
_JSON_FIELDS = 64
#: An enum value's name as printed after its class: an identifier of the length a
#: person writes. Anything else in `_name` prints as a field like any other.
_ENUM_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]{0,63}\Z")
#: dart:core's `_Enum` and its `_name` field, as a snapshot names them: a private name
#: carries its library's key after an `@`.
_PRIVATE_ENUM = re.compile(r"_Enum(?:@\d+)?\Z")
_PRIVATE_NAME = re.compile(r"_name(?:@\d+)?\Z")


def double_text(bits: int):
    """A double's 64 bits as a literal that reads back to the same bits, or None.

    `repr` is the shortest text Python reads back to the same double, and it always has
    a point or an exponent, so an integral value cannot read as an int (`255.0`, `1e+16`).
    -0.0 keeps its sign. The infinities and the one NaN that has a name print by it."""
    bits &= _M64
    if bits == _NAN:
        return "double.nan"
    x = struct.unpack("<d", struct.pack("<Q", bits))[0]
    if x != x:
        return None
    if x in (float("inf"), float("-inf")):
        return "double.infinity" if x > 0 else "-double.infinity"
    return repr(x)


class Holdings:
    """What each pool slot and each object it names holds, for one FillResult.

    Built with the pool map and asked lazily: a lift asks about the few slots its body
    loads, `xrefs pool` about one."""

    def __init__(self, fr, arch=None):
        self.fr = fr
        self.arch = arch
        spans = getattr(fr, "spans", None) or []
        self._spans = spans
        self._starts = [s[0] for s in spans]
        self._first = getattr(fr, "first_ref", 0)
        # Where the vm snapshot was read, the base objects from `base_first_ref` on are
        # its strings, Smis and Arrays (baseobjects.py); only those below it are made
        # by the VM and stated nowhere.
        self._vm_made = getattr(fr, "base_first_ref", 0) or self._first
        self._memo = {}
        self._texts = {}
        self._tables = None

    # -- the slot ---------------------------------------------------------------------

    def index(self, off: int):
        """The pool index a `[PP, #off]` load of `off` reads, or None where `off` is not
        the offset of a slot."""
        from .disasm import _pool_shape
        start, size, tag = _pool_shape(self.arch)
        q, r = divmod(off + tag - start, size)
        if r or not 0 <= q < len(self.fr.pool):
            return None
        return q

    def slot(self, off: int):
        """What the slot at `off` holds, as a dict for `xrefs -j`, or None where `off` is
        not a slot. `kind` is always there; `class`, `cid`, `value` and the rest only
        where the snapshot says them."""
        idx = self.index(off)
        if idx is None:
            return None
        kind, val = self.fr.pool[idx]
        if kind == "imm":
            out = {"kind": "immediate", "value": f"0x{val & _M64:x}"}
            d = double_text(val) if self._word() == 8 else None
            if d is not None:
                out["double"] = d
            return out
        if kind == "native":
            return {"kind": "native function"}
        if kind != "ref":
            # A call site's entry the VM writes when the program runs.
            return {"kind": "runtime entry"}
        return self.object(val)

    def text(self, off: int, label=None):
        """The slot as `xrefs pool` heads it: the pool map's label where it has one, so
        a string slot answers as it always has, else what `slot` says, in one line."""
        if label is not None:
            return label
        got = self.slot(off)
        if got is None:
            return None
        k, v = got["kind"], got.get("value")
        if k == "immediate":
            d = got.get("double")
            return f"immediate {v}" + (f" ({d} as a double)" if d else "")
        if k == "instance":
            return v if v is not None else f"instance of class id {got['cid']}"
        if k in ("int", "double", "string", "function", "list") and v is not None:
            return f"{k} {v}"
        if k == "null":
            return "null"
        if k == "vm object":
            return f"vm object ref {got['ref']}"
        if k == "object":
            return f"{got['class']} object"
        if k == "unknown":
            return f"unknown object ref {got['ref']}"
        return k if v is None else f"{k} {v}"

    def lift_double(self, off: int):
        """The text a load of slot `off` into a d register prints: the double whose bits
        the slot holds, or None where it holds no raw word, or bits no literal gives."""
        if self._word() != 8:
            return None
        idx = self.index(off)
        if idx is None:
            return None
        kind, val = self.fr.pool[idx]
        return double_text(val) if kind == "imm" else None

    def lift_object(self, off: int):
        """The text a load of slot `off` into a general register prints where the slot
        names a const instance whose class the snapshot holds, else None."""
        idx = self.index(off)
        if idx is None:
            return None
        kind, val = self.fr.pool[idx]
        if kind != "ref" or val not in self.fr.instances:
            return None
        return self._inst_text(val, 0)

    # -- objects ----------------------------------------------------------------------

    def object(self, ref: int) -> dict:
        got = self._memo.get(ref)
        if got is None:
            got = self._memo[ref] = self._object(ref)
        return got

    def _object(self, ref: int) -> dict:
        fr = self.fr
        if ref == 1:
            # The first base object every release adds is null (AddVMIsolateBaseObjects);
            # an arguments descriptor's terminator is read the same way (disasm).
            return {"kind": "null"}
        if 0 < ref < self._vm_made:
            return {"kind": "vm object", "ref": ref}
        s = fr.strings.get(ref)
        if s is not None:
            from .fill import quoted
            from .disasm import _LITERAL_CUT
            return {"kind": "string", "value": quoted(s, _LITERAL_CUT)}
        fn = self._tab()["fname"].get(ref)
        if fn is not None:
            out = {"kind": "function"}
            if fn:
                out["value"] = f"&{fn}"
            return out
        v = fr.smi_values.get(ref)
        if v is not None:
            return {"kind": "int", "value": _int_text(v)}
        b = getattr(fr, "doubles", {}).get(ref)
        if b is not None:
            out = {"kind": "double", "bits": f"0x{b:x}"}
            d = double_text(b)
            if d is not None:
                out["value"] = d
            return out
        inst = getattr(fr, "instances", {}).get(ref)
        if inst is not None:
            return self._instance(ref, inst)
        elems = (getattr(fr, "arrays", None) or {}).get(ref)
        if elems is not None:
            from .disasm import _list_label, _at
            out = {"kind": "list", "length": len(elems)}
            lab = _list_label(fr, ref, {})
            if lab is not None:
                out["value"] = _at(lab, 0) if isinstance(lab, str) else (
                    f"const[{lab[0]}]{{{lab[1]}, ...}}")
            return out
        span = self._span(ref)
        if span is None:
            if 0 < ref < self._first:
                return {"kind": "vm object", "ref": ref}
            return {"kind": "unknown", "ref": ref}
        name = span[3]
        return {"kind": "object", "class": name[:-3] if name.endswith("Cid") else name,
                "cid": span[2]}

    def _span(self, ref: int):
        i = bisect.bisect_right(self._starts, ref) - 1
        if i < 0:
            return None
        s = self._spans[i]
        return s if s[0] <= ref < s[1] else None

    def _instance(self, ref: int, inst) -> dict:
        cid, bitmap, fields = inst
        t = self._tab()
        cls = t["by_cid"].get(cid)
        out = {"kind": "instance", "cid": cid}
        if cls is None:
            return out
        out["class"] = t["cname"].get(cls, "")
        text = self._inst_text(ref, 0)
        if text is not None:
            out["value"] = text
        names = t["fields"](cls)
        listed, more = [], 0
        for off, raw, v in self._slots(bitmap, fields):
            if len(listed) == _JSON_FIELDS:
                more += 1
                continue
            f = {"offset": off}
            if off in names:
                f["name"] = names[off]
            if raw:
                f["raw"] = f"0x{v:x}"
            else:
                f["value"] = self._value_text(v, 1)
            listed.append(f)
        out["fields"] = listed
        if more:
            out["more_fields"] = more
        return out

    def _slots(self, bitmap: int, fields):
        """(offset, unboxed, value) for each field of an instance, in order.

        On a 64-bit target with compressed pointers a slot is four bytes, and an unboxed
        field fills the two slots of its word, each written as its own 32 bits: an int
        or a double is one field here, its word put back together low half first, and
        not two halves."""
        t = self._tab()
        hw, cws = t["hw"], t["cws"]
        per = max(1, self._word() // cws)
        j, n = 0, len(fields)
        while j < n:
            if not (bitmap >> (hw + j)) & 1:
                yield (hw + j) * cws, False, fields[j]
                j += 1
                continue
            w, k = fields[j], 1
            if per > 1:
                w &= 0xFFFFFFFF
                while k < per and j + k < n and (bitmap >> (hw + j + k)) & 1:
                    w |= (fields[j + k] & 0xFFFFFFFF) << (32 * k)
                    k += 1
            yield (hw + j) * cws, True, w
            j += k

    def _inst_text(self, ref: int, depth: int):
        key = (ref, depth)
        if key in self._texts:
            return self._texts[key]
        self._texts[key] = None                 # a cycle met while spelling it
        got = self._texts[key] = self._spell(ref, depth)
        return got

    def _spell(self, ref: int, depth: int):
        cid, bitmap, fields = self.fr.instances[ref]
        t = self._tab()
        cls = t["by_cid"].get(cid)
        if cls is None:
            return None
        cname = t["cname"].get(cls) or ""
        if not cname:
            return None
        en = self._enum_name(cls, fields)
        if en is not None:
            return f"{cname}.{en}"
        head = f"const {cname}"
        if depth >= _DEPTH:
            return head + "{...}"
        names = t["fields"](cls)
        parts, total = [], len(head) + 2
        for off, raw, v in self._slots(bitmap, fields):
            name = names.get(off) or f"field_0x{off:x}"
            val = "?" if raw else self._value_text(v, depth + 1)
            piece = f"{name}: {val}"
            if total + len(piece) + 5 > _CUT:
                parts.append("...")
                break
            parts.append(piece)
            total += len(piece) + 2
        return head + "{" + ", ".join(parts) + "}"

    def _value_text(self, ref: int, depth: int) -> str:
        """A field's value inside an instance: short, and `?` for what is not known."""
        fr = self.fr
        if ref in getattr(fr, "instances", {}):
            got = self._inst_text(ref, depth)
            return got if got is not None else "?"
        if ref in fr.strings:
            from .fill import quoted
            return quoted(fr.strings[ref], _FIELD_STR)
        got = self.object(ref)
        k = got["kind"]
        if k == "null":
            return "null"
        if k in ("int", "double", "function") and "value" in got:
            return got["value"]
        if k == "list" and "value" in got and len(got["value"]) <= _CUT // 2:
            return got["value"]
        if k == "object":
            return f"<{got['class']}>"
        return "?"

    # -- tables, built once and only when an object asks ---------------------------------

    def _word(self) -> int:
        return getattr(self.arch, "word_size", 8) if self.arch is not None else 8

    def _tab(self) -> dict:
        if self._tables is not None:
            return self._tables
        fr, arch = self.fr, self.arch
        names = fr.names
        by_cid, cname, sup = {}, {}, {}
        for ref, name_ref, cid, super_ref in fr.classes:
            by_cid.setdefault(cid & 0xFFFFFFFF, ref)
            cname[ref] = names.get(name_ref, "")
            sup[ref] = super_ref
        layout = None
        if arch is not None and getattr(fr, "field_meta", None):
            from .fields import recover_fields
            layout = recover_fields(fr, arch)
        cache = {}

        def fields_of(cls):
            got = cache.get(cls)
            if got is None:
                got = cache[cls] = layout.for_class(cls) if layout is not None else {}
            return got

        enum = None
        for ref, nm in cname.items():
            # A product snapshot keeps dart:core's name and drops its url.
            if _PRIVATE_ENUM.match(nm) and fr.library_urls.get(
                    fr.class_library.get(ref)) in ("dart:core", "dart.core"):
                enum = ref if enum is None else -1      # two of them: neither is it
        enum_off = None
        if enum not in (None, -1) and layout is not None:
            offs = [off for off, fi in layout.by_class.get(enum, {}).items()
                    if _PRIVATE_NAME.match(fi.name) and not fi.unboxed]
            enum_off = offs[0] if len(offs) == 1 else None
        self._tables = {
            "by_cid": by_cid, "cname": cname, "sup": sup, "fields": fields_of,
            "fname": {ref: names.get(nr, "") for ref, nr, _o, _k in fr.functions},
            "enum": enum if enum_off is not None else None, "enum_off": enum_off,
            "hw": arch.instance_header_words if arch is not None else 2,
            "cws": arch.compressed_word_size if arch is not None else 8,
            "is_enum": {},
        }
        return self._tables

    def _enum_name(self, cls: int, fields):
        """The name an instance of an enum holds, where `cls` extends dart:core's _Enum
        and the `_name` slot that class declares holds a String that is an identifier."""
        t = self._tab()
        enum, off = t["enum"], t["enum_off"]
        if enum is None or not self._extends(cls, enum):
            return None
        j = off // t["cws"] - t["hw"]
        if not 0 <= j < len(fields):
            return None
        s = self.fr.strings.get(fields[j])
        return s if s is not None and _ENUM_NAME.match(s) else None

    def _extends(self, cls: int, target: int) -> bool:
        t = self._tab()
        memo = t["is_enum"]
        if cls in memo:
            return memo[cls]
        seen, at, hit = [], cls, False
        types = self.fr.types
        for _ in range(64):
            if at is None or at in memo:
                hit = bool(at is not None and memo[at])
                break
            seen.append(at)
            if at == target:
                hit = True
                break
            st = types.get(t["sup"].get(at, -1))
            at = t["by_cid"].get(st & 0xFFFFFFFF) if st is not None else None
            if at in seen:
                break
        for c in seen:
            memo[c] = hit
        return hit


def _int_text(v: int) -> str:
    return hex(v) if abs(v) > 9 else str(v)
