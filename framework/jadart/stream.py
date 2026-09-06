"""Dart snapshot data-stream decoders.

Byte-exact port of runtime/vm/datastream.h (dart-lang/sdk). Constants verified
against source:
  kDataBitsPerByte = 7
  kMaxUnsignedDataPerByte = 127
  kMaxDataPerByte = 63
  kEndByteMarker         = 255 - 63  = 192   (signed reads, Read<T>)
  kEndUnsignedByteMarker = 255 - 127 = 128   (unsigned reads, ReadUnsigned)

Encoding: little-endian 7-bit groups; a byte with the high bit SET terminates
the value and carries (byte - marker) as its final group. For unsigned, that is
byte-128 (0..127). For signed, byte-192 (-64..63), which sign-extends.
"""
from __future__ import annotations

from .errors import JadartError

END_BYTE_MARKER = 192
END_UNSIGNED_BYTE_MARKER = 128
_MAX_UNSIGNED_PER_BYTE = 127
REF_ID_MAX_BYTES = 4      # datastream.h ReadRefId: four STAGE expansions, 28 bits
#: Reader::Read<T> is bounded by sizeof(T), and the widest value the format encodes is a
#: uint64: ten 7-bit groups. Without the bound a run of continuation bytes accumulates an
#: unbounded Python int, which is quadratic rather than merely wrong: 320 KB of 0x7f took
#: 3.7s and 1.28 MB took 56.6s, so a crafted file hangs a batch scan instead of failing.
VARINT_MAX_BYTES = 10
_MAX_VALUE_BITS = 7 * (VARINT_MAX_BYTES - 1)


class TruncatedSnapshot(JadartError):
    """Raised when a read runs past the end of the snapshot blob. The input is truncated
    or malformed, and that surfaces loudly instead of as a bare IndexError/ValueError."""


class ReadStream:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise TruncatedSnapshot(
                f"read past end of snapshot at offset {self.pos} (len {len(self.data)})")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise TruncatedSnapshot(
                f"read of {n} bytes at offset {self.pos} runs past end (len {len(self.data)})")
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    # The three decoders below read the stream a byte at a time, and between them that is
    # where a snapshot parse spends most of its time: 564,097 byte reads to answer
    # `jadart classes` on the corpus binary. So they index `self.data` directly instead of
    # going through byte(), and let a read past the end raise IndexError, which becomes
    # the same TruncatedSnapshot with the same offset in the same place. The bound is
    # still checked on every byte; CPython just checks it for us.

    def _varint(self, marker: int) -> int:
        # mirrors Reader::Read<T>(end_byte_marker) in datastream.h
        data = self.data
        pos = self.pos
        try:
            b = data[pos]
            pos += 1
            if b > _MAX_UNSIGNED_PER_BYTE:
                self.pos = pos
                return b - marker
            r = 0
            s = 0
            start = pos - 1
            while b <= _MAX_UNSIGNED_PER_BYTE:
                r |= b << s
                s += 7
                if s > _MAX_VALUE_BITS:
                    self.pos = pos
                    raise TruncatedSnapshot(
                        f"varint did not terminate within {VARINT_MAX_BYTES} bytes at "
                        f"offset {start}: the stream is desynced. The widest value the VM "
                        f"encodes is a uint64, which fits in {VARINT_MAX_BYTES} groups")
                b = data[pos]
                pos += 1
        except IndexError:
            self.pos = pos
            raise TruncatedSnapshot(
                f"read past end of snapshot at offset {pos} (len {len(data)})") from None
        self.pos = pos
        return r | ((b - marker) << s)

    def read_unsigned(self) -> int:
        # One byte covers most values, and skipping the call for that case is worth the
        # four lines: read_unsigned and read_int are called 127,328 times on one `classes`.
        data = self.data
        pos = self.pos
        if pos < len(data):
            b = data[pos]
            if b > _MAX_UNSIGNED_PER_BYTE:
                self.pos = pos + 1
                return b - END_UNSIGNED_BYTE_MARKER
        return self._varint(END_UNSIGNED_BYTE_MARKER)

    def read_int(self) -> int:
        data = self.data
        pos = self.pos
        if pos < len(data):
            b = data[pos]
            if b > _MAX_UNSIGNED_PER_BYTE:
                self.pos = pos + 1
                return b - END_BYTE_MARKER
        return self._varint(END_BYTE_MARKER)

    def read_uint32_tag(self) -> int:
        # Read<uint32_t>() uses the signed marker but the value is a 32-bit tag.
        return self._varint(END_BYTE_MARKER) & 0xFFFFFFFF

    def read_uint64_tag(self) -> int:
        # Read<uint64_t>(), the cluster tag before Dart 3.4. Same varint, but it must not be
        # truncated to 32 bits: the value is cid<<1|is_canonical, so masking at 32 would
        # clip the top bit of a large cid.
        return self._varint(END_BYTE_MARKER) & 0xFFFFFFFFFFFFFFFF

    def read_ref_id(self) -> int:
        # ReadRefId: big-endian 7-bit groups, high bit (byte<0 as int8) terminates.
        # Bounded at 4 bytes / 28 bits: datastream.h expands its STAGE macro exactly four
        # times (0-7, 8-14, 15-21, 22-28) and then asserts the value terminated ("256MB is
        # enough for anyone"). An unbounded loop turns a desynced stream into a silent scan
        # for the next high-bit byte instead of a fail-loud error.
        data = self.data
        pos = self.pos
        result = 0
        try:
            for _ in range(REF_ID_MAX_BYTES):
                b = data[pos]
                pos += 1
                result = (b & 0x7F) + (result << 7)
                if b & 0x80:
                    self.pos = pos
                    return result
        except IndexError:
            self.pos = pos
            raise TruncatedSnapshot(
                f"read past end of snapshot at offset {pos} (len {len(data)})") from None
        self.pos = pos
        raise TruncatedSnapshot(
            f"ref id did not terminate within {REF_ID_MAX_BYTES} bytes at offset "
            f"{self.pos - REF_ID_MAX_BYTES}: the stream is desynced. The VM encodes ref "
            f"ids in at most {REF_ID_MAX_BYTES} bytes / 28 bits)")

    def read_cstring(self) -> str:
        end = self.data.find(b"\x00", self.pos)
        if end < 0:
            raise TruncatedSnapshot(
                f"unterminated C-string at offset {self.pos} (len {len(self.data)})")
        s = self.data[self.pos:end].decode("utf-8", "replace")
        self.pos = end + 1
        return s
