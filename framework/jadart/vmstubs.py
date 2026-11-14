"""The stubs a program calls that its own roots do not name, found through the vm
snapshot beside it.

Through Dart 3.12 an AOT library has every runtime stub twice. The vm snapshot holds
the VM isolate's, one Code for each entry of VM_STUB_CODE_LIST, and its roots end with
one ref for each of them in that list's order (VMSerializationRoots::WriteRoots,
`StubCode::EntryAt(i)`). The isolate snapshot holds the copies generated code calls,
the ObjectStore's, and its roots name them only as far as `slow_tts_stub`, where the
AOT root run ends (objstore.py). The stubs an async or a sync* function calls come
after that in object_store.h: InitAsync, Await, ReturnAsync, the suspend stubs. So a
`bl` to one printed as `sub_0x15765c();`, and `benchFetchToken` read as three calls to
nothing (#462).

Both copies are made by one generator from one description, so they are the same
bytes, give or take the pool slot a `ldr xN, [x27, #off]` names where the two pools
number an object differently. A stub of the isolate snapshot that its roots do not
name is given the name of the vm snapshot's stub it is a copy of.

What has to hold on the binary in hand before anything is named, each of them a
refusal that leaves every such stub as `sub_0x...`:

  the release has a list here (VM_STUBS), and the vm snapshot has exactly as many
    Code objects as the list has names, each with instructions of its own.
  every stub the isolate roots DO name, and the list names too, is the same code as
    the vm snapshot's stub at that name's position in the list, and there are at
    least MIN_ANCHORS of them (69 to 76 on a real build). The roots and the list are
    written by different code from different files, so a list that is one entry out
    anywhere before the last of them fails here.
  the range is a Code object nothing owns, which is what a stub is (85 of the clean
    fixture's 8,194 Codes, 76 of them named by the roots), it is at least MIN_SIZE
    bytes, and its bytes are those of one stub of the list and of no other, and no
    other range's are.

Measured on 26 corpus builds that keep a symbol table (13 releases from 2.19.6 to
3.12.0, arm64 and arm32), against the symbols: the vm snapshot's stubs carry the
list's names at 159 to 172 positions a build and differ at none, and the names given
here to isolate stubs are right where there is a symbol to compare, none wrong. The
3.12.2 builds keep no symbol; they are held to the same list as 3.12.0, which
stub_code_list.h says it is, and pass the checks above.

arm32 compares whole bytes only, so a stub whose pool slot differs there (InitAsync,
AwaitWithTypeCheck and InitSyncStar before 3.9) stays unnamed. Dart 3.13 has one
snapshot and names every stub from its roots.
"""
from __future__ import annotations

import re
import struct
from bisect import bisect_right

from .errors import JadartError

#: null, the owner of a stub's Code: the first base object of every snapshot before
#: 3.13 (Serializer::AddBaseObject(Object::null()), and baseobjects._check_roots).
NULL_REF = 1
#: The shortest stub that is named by its bytes. Some of the list are one instruction
#: and two of those are the same bytes (FrameAwaitingMaterialization and
#: AsynchronousGapMarker); eight instructions is past every one of that kind and
#: under the stubs this is for, which are 40 to 404 bytes on every build read.
MIN_SIZE = 32
#: How many of the stubs the isolate roots name have to be found in the vm snapshot at
#: their list positions. A real build has 69 to 76; fewer than this is not a build.
MIN_ANCHORS = 32
#: The longest stub that is named by its bytes, ten times the longest named on any
#: build read. It bounds the words `_pool_blind` walks one by one, which a crafted
#: table could otherwise make as many as the file has.
MAX_SIZE = 4096

_ROOTED = re.compile(r"_iso_stub_(\w+)Stub")
VM_INSTRUCTIONS = "_kDartVmSnapshotInstructions"


def read_stub_code(container, blob: bytes, end: int, vm, codes, stub_refs) -> tuple:
    """The instructions of each stub of the vm snapshot, in the order its roots list
    them, or () where they are not what the release's list says.

    `blob` is the vm snapshot's data and `end` where its stream ends, `codes` its
    Code objects as the fill read them, (ref, owner, code index), and `stub_refs` the
    refs its roots end with. Nothing here is fatal: with no stub code the isolate's
    stubs keep the names the roots give them and no more."""
    from .disasm import parse_instructions_table
    from .snapshot import VM_DATA

    names = VM_STUBS.get(getattr(vm.epoch, "dart", None))
    if names is None or len(names) != len(stub_refs):
        return ()
    try:
        text = container.symbol_bytes(VM_INSTRUCTIONS)
        pcs, first = parse_instructions_table(blob, end, vm.instr_table_rodata_offset,
                                              vm.arch, symbol=VM_DATA)
    except JadartError:
        return ()
    index = {ref: ci for ref, _owner, ci in codes}
    starts = []
    for ref in stub_refs:
        slot = first + index.get(ref, -1 - first)
        if not 0 <= slot < len(pcs):
            return ()
        starts.append(pcs[slot])
    # Each stub its own instructions. It is what every build has, and it is what
    # bounds the copies below to the image's own size: the ranges are disjoint.
    if len(set(starts)) != len(starts):
        return ()
    bounds = sorted(set(pcs))
    out = []
    for pc in starts:
        i = bisect_right(bounds, pc)
        stop = bounds[i] if i < len(bounds) else len(text)
        if not 0 <= pc < stop <= len(text):
            return ()
        out.append(bytes(text[pc:stop]))
    return tuple(out)


def _pool_blind(code: bytes) -> bytes:
    """arm64 `code` with the offset of every `ldr Xt, [x27, #off]` cleared: the same
    stub generated against another object pool."""
    n = len(code) // 4
    words = list(struct.unpack_from(f"<{n}I", code))
    for i, w in enumerate(words):
        # 1111 1001 01 imm12 Rn Rt, Rn = x27 (PP)
        if w & 0xFFC003E0 == 0xF9400360:
            words[i] = w & ~0x003FFC00
    return struct.pack(f"<{n}I", *words) + code[n * 4:]


def vm_stub_names(image, rooted: dict) -> dict:
    """pc_offset -> `_iso_stub_<Name>Stub` for the isolate's stubs that `rooted`, the
    names its own roots give (objstore.stub_names), leaves out. Empty wherever the
    module docstring's conditions do not all hold."""
    code = getattr(image, "vm_stubs", None) or ()
    epoch = getattr(image, "epoch", None)
    names = VM_STUBS.get(getattr(epoch, "dart", None)) if code and rooted else None
    if names is None or len(names) != len(code):
        return {}
    text = image.text
    arm64 = getattr(getattr(image, "arch", None), "name", None) == "arm64"

    def same(a: bytes, b: bytes) -> bool:
        return a == b or (arm64 and len(a) == len(b) <= MAX_SIZE
                          and _pool_blind(a) == _pool_blind(b))

    size, free = {}, []
    for cr in image.all_ranges:
        if cr.pc_offset in rooted:
            size[cr.pc_offset] = cr.size
        elif cr.owner_ref == NULL_REF and MIN_SIZE <= cr.size <= MAX_SIZE:
            free.append(cr)
    at = {name: i for i, name in enumerate(names)}
    anchored = set()
    for pc, label in rooted.items():
        m = _ROOTED.fullmatch(label)
        i = at.get(m.group(1)) if m else None
        if i is None:
            continue                    # a stub the VM isolate has no copy of
        # The length first: what is copied is then no longer than the vm snapshot's
        # own stub, whatever size the table gives the range.
        n = size.get(pc, 0)
        if n != len(code[i]) or not same(bytes(text[pc:pc + n]), code[i]):
            return {}
        anchored.add(m.group(1))
    if len(anchored) < MIN_ANCHORS:
        return {}
    exact, blind = {}, {}
    for name, c in zip(names, code):
        if name in anchored or not MIN_SIZE <= len(c) <= MAX_SIZE:
            continue
        exact.setdefault(c, []).append(name)
        if arm64:
            blind.setdefault(_pool_blind(c), []).append(name)
    lengths = {len(c) for c in exact}
    found = {}
    for cr in free:
        if cr.size not in lengths:
            continue
        own = bytes(text[cr.pc_offset:cr.pc_offset + cr.size])
        hit = exact.get(own) or (blind.get(_pool_blind(own)) if arm64 else None)
        if hit and len(hit) == 1:
            found.setdefault(hit[0], []).append(cr.pc_offset)
    return {pcs[0]: f"_iso_stub_{name}Stub" for name, pcs in found.items()
            if len(pcs) == 1}


# --------------------------------------------------------------------------------------
# Generated by tools/gen_objstore.py --emit-vm-stubs. Do not hand-edit; regenerate.
#: Dart 3.12.2 and 3.12.0. 173 stubs.
_VM_3_12_2 = tuple("""
JumpToFrame RunExceptionHandler RunExceptionHandlerUnbox DeoptForRewind WriteBarrier
WriteBarrierWrappers ArrayWriteBarrier AllocationProbePoint AllocateArray AllocateMint
AllocateDouble AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4 AllocateInt8Array
AllocateUint8Array AllocateUint8ClampedArray AllocateInt16Array AllocateUint16Array
AllocateInt32Array AllocateUint32Array AllocateInt64Array AllocateUint64Array
AllocateFloat32Array AllocateFloat64Array AllocateFloat32x4Array AllocateInt32x4Array
AllocateFloat64x2Array AllocateMintSharedWithFPURegs AllocateMintSharedWithoutFPURegs
AllocateClosure AllocateClosureGeneric AllocateClosureTA AllocateClosureTAGeneric
AllocateContext AllocateGrowableArray AllocateObject AllocateObjectParameterized
AllocateObjectSlow AllocateRecord AllocateRecord2 AllocateRecord2Named AllocateRecord3
AllocateRecord3Named AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2
CloneContext CallToRuntime LazyCompile InterpretCall ResumeInterpreter
CallBootstrapNative CallNoScopeNative CallAutoScopeNative FixCallersTarget
CallStaticFunction OptimizeFunction InvokeDartCode InvokeDartCodeFromBytecode
DebugStepCheck SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall
ICCallThroughCode MegamorphicCall FixAllocationStubTarget
FixParameterizedAllocationStubTarget Deoptimize DeoptimizeLazyFromReturn
DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping NullIsAssignableToType Subtype1TestCache Subtype2TestCache
Subtype3TestCache Subtype4TestCache Subtype6TestCache Subtype7TestCache DefaultTypeTest
DefaultNullableTypeTest TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest
NullableTypeParameterTypeTest SlowTypeTest LazySpecializeTypeTest
LazySpecializeNullableTypeTest CallClosureNoSuchMethod FrameAwaitingMaterialization
AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs FieldAccessErrorSharedWithFPURegs
FieldAccessErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
CallNativeThroughSafepoint FfiCallTrampoline FfiCallbackTrampoline InitStaticField
InitLateStaticField InitLateFinalStaticField InitInstanceField InitLateInstanceField
InitLateFinalInstanceField InitSharedLateStaticField Throw ReThrow InstanceOf
InstantiateType InstantiateTypeNonNullableClassTypeParameter
InstantiateTypeNullableClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeArguments
InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
CheckIsolateFieldAccess CheckedStoreIntoShared EnsureDeeplyImmutable UnknownDartCode
""".split())

#: Dart 3.11.5. 173 stubs.
_VM_3_11_5 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler RunExceptionHandlerUnbox DeoptForRewind
WriteBarrier WriteBarrierWrappers ArrayWriteBarrier AllocationProbePoint AllocateArray
AllocateMint AllocateDouble AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4
AllocateInt8Array AllocateUint8Array AllocateUint8ClampedArray AllocateInt16Array
AllocateUint16Array AllocateInt32Array AllocateUint32Array AllocateInt64Array
AllocateUint64Array AllocateFloat32Array AllocateFloat64Array AllocateFloat32x4Array
AllocateInt32x4Array AllocateFloat64x2Array AllocateMintSharedWithFPURegs
AllocateMintSharedWithoutFPURegs AllocateClosure AllocateClosureGeneric
AllocateClosureTA AllocateClosureTAGeneric AllocateContext AllocateGrowableArray
AllocateObject AllocateObjectParameterized AllocateObjectSlow AllocateRecord
AllocateRecord2 AllocateRecord2Named AllocateRecord3 AllocateRecord3Named
AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2 CloneContext
CallToRuntime LazyCompile InterpretCall ResumeInterpreter CallBootstrapNative
CallNoScopeNative CallAutoScopeNative FixCallersTarget CallStaticFunction
OptimizeFunction InvokeDartCode InvokeDartCodeFromBytecode DebugStepCheck
SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall ICCallThroughCode
MegamorphicCall FixAllocationStubTarget FixParameterizedAllocationStubTarget Deoptimize
DeoptimizeLazyFromReturn DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping NullIsAssignableToType Subtype1TestCache Subtype2TestCache
Subtype3TestCache Subtype4TestCache Subtype6TestCache Subtype7TestCache DefaultTypeTest
DefaultNullableTypeTest TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest
NullableTypeParameterTypeTest SlowTypeTest LazySpecializeTypeTest
LazySpecializeNullableTypeTest CallClosureNoSuchMethod FrameAwaitingMaterialization
AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs FieldAccessErrorSharedWithFPURegs
FieldAccessErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
CallNativeThroughSafepoint FfiCallTrampoline FfiCallbackTrampoline InitStaticField
InitLateStaticField InitLateFinalStaticField InitInstanceField InitLateInstanceField
InitLateFinalInstanceField InitSharedLateStaticField Throw ReThrow InstanceOf
InstantiateType InstantiateTypeNonNullableClassTypeParameter
InstantiateTypeNullableClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeArguments
InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
CheckIsolateFieldAccess CheckedStoreIntoShared UnknownDartCode
""".split())

#: Dart 3.10.9. 172 stubs.
_VM_3_10_9 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler RunExceptionHandlerUnbox DeoptForRewind
WriteBarrier WriteBarrierWrappers ArrayWriteBarrier AllocationProbePoint AllocateArray
AllocateMint AllocateDouble AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4
AllocateInt8Array AllocateUint8Array AllocateUint8ClampedArray AllocateInt16Array
AllocateUint16Array AllocateInt32Array AllocateUint32Array AllocateInt64Array
AllocateUint64Array AllocateFloat32Array AllocateFloat64Array AllocateFloat32x4Array
AllocateInt32x4Array AllocateFloat64x2Array AllocateMintSharedWithFPURegs
AllocateMintSharedWithoutFPURegs AllocateClosure AllocateClosureGeneric
AllocateClosureTA AllocateClosureTAGeneric AllocateContext AllocateGrowableArray
AllocateObject AllocateObjectParameterized AllocateObjectSlow AllocateRecord
AllocateRecord2 AllocateRecord2Named AllocateRecord3 AllocateRecord3Named
AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2 CloneContext
CallToRuntime LazyCompile InterpretCall ResumeInterpreter CallBootstrapNative
CallNoScopeNative CallAutoScopeNative FixCallersTarget CallStaticFunction
OptimizeFunction InvokeDartCode InvokeDartCodeFromBytecode DebugStepCheck
SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall ICCallThroughCode
MegamorphicCall FixAllocationStubTarget FixParameterizedAllocationStubTarget Deoptimize
DeoptimizeLazyFromReturn DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping NullIsAssignableToType Subtype1TestCache Subtype2TestCache
Subtype3TestCache Subtype4TestCache Subtype6TestCache Subtype7TestCache DefaultTypeTest
DefaultNullableTypeTest TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest
NullableTypeParameterTypeTest SlowTypeTest LazySpecializeTypeTest
LazySpecializeNullableTypeTest CallClosureNoSuchMethod FrameAwaitingMaterialization
AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs FieldAccessErrorSharedWithFPURegs
FieldAccessErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
CallNativeThroughSafepoint FfiCallTrampoline FfiCallbackTrampoline InitStaticField
InitLateStaticField InitLateFinalStaticField InitInstanceField InitLateInstanceField
InitLateFinalInstanceField InitSharedLateStaticField Throw ReThrow InstanceOf
InstantiateType InstantiateTypeNonNullableClassTypeParameter
InstantiateTypeNullableClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeArguments
InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
CheckIsolateFieldAccess UnknownDartCode
""".split())

#: Dart 3.9.2. 171 stubs.
_VM_3_9_2 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler RunExceptionHandlerUnbox DeoptForRewind
WriteBarrier WriteBarrierWrappers ArrayWriteBarrier AllocationProbePoint AllocateArray
AllocateMint AllocateDouble AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4
AllocateInt8Array AllocateUint8Array AllocateUint8ClampedArray AllocateInt16Array
AllocateUint16Array AllocateInt32Array AllocateUint32Array AllocateInt64Array
AllocateUint64Array AllocateFloat32Array AllocateFloat64Array AllocateFloat32x4Array
AllocateInt32x4Array AllocateFloat64x2Array AllocateMintSharedWithFPURegs
AllocateMintSharedWithoutFPURegs AllocateClosure AllocateClosureGeneric
AllocateClosureTA AllocateClosureTAGeneric AllocateContext AllocateGrowableArray
AllocateObject AllocateObjectParameterized AllocateObjectSlow AllocateRecord
AllocateRecord2 AllocateRecord2Named AllocateRecord3 AllocateRecord3Named
AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2 CloneContext
CallToRuntime LazyCompile InterpretCall ResumeInterpreter CallBootstrapNative
CallNoScopeNative CallAutoScopeNative FixCallersTarget CallStaticFunction
OptimizeFunction InvokeDartCode InvokeDartCodeFromBytecode DebugStepCheck
SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall ICCallThroughCode
MegamorphicCall FixAllocationStubTarget FixParameterizedAllocationStubTarget Deoptimize
DeoptimizeLazyFromReturn DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping NullIsAssignableToType Subtype1TestCache Subtype2TestCache
Subtype3TestCache Subtype4TestCache Subtype6TestCache Subtype7TestCache DefaultTypeTest
DefaultNullableTypeTest TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest
NullableTypeParameterTypeTest SlowTypeTest LazySpecializeTypeTest
LazySpecializeNullableTypeTest CallClosureNoSuchMethod FrameAwaitingMaterialization
AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs FieldAccessErrorSharedWithFPURegs
FieldAccessErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
CallNativeThroughSafepoint FfiCallbackTrampoline InitStaticField InitLateStaticField
InitLateFinalStaticField InitInstanceField InitLateInstanceField
InitLateFinalInstanceField InitSharedLateStaticField Throw ReThrow InstanceOf
InstantiateType InstantiateTypeNonNullableClassTypeParameter
InstantiateTypeNullableClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeArguments
InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
CheckIsolateFieldAccess UnknownDartCode
""".split())

#: Dart 3.7.2. 169 stubs.
_VM_3_7_2 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler DeoptForRewind WriteBarrier
WriteBarrierWrappers ArrayWriteBarrier AllocationProbePoint AllocateArray AllocateMint
AllocateDouble AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4 AllocateInt8Array
AllocateUint8Array AllocateUint8ClampedArray AllocateInt16Array AllocateUint16Array
AllocateInt32Array AllocateUint32Array AllocateInt64Array AllocateUint64Array
AllocateFloat32Array AllocateFloat64Array AllocateFloat32x4Array AllocateInt32x4Array
AllocateFloat64x2Array AllocateMintSharedWithFPURegs AllocateMintSharedWithoutFPURegs
AllocateClosure AllocateClosureGeneric AllocateClosureTA AllocateClosureTAGeneric
AllocateContext AllocateGrowableArray AllocateObject AllocateObjectParameterized
AllocateObjectSlow AllocateRecord AllocateRecord2 AllocateRecord2Named AllocateRecord3
AllocateRecord3Named AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2
CloneContext CallToRuntime LazyCompile InterpretCall ResumeInterpreter
CallBootstrapNative CallNoScopeNative CallAutoScopeNative FixCallersTarget
CallStaticFunction OptimizeFunction InvokeDartCode InvokeDartCodeFromBytecode
DebugStepCheck SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall
ICCallThroughCode MegamorphicCall FixAllocationStubTarget
FixParameterizedAllocationStubTarget Deoptimize DeoptimizeLazyFromReturn
DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping NullIsAssignableToType Subtype1TestCache Subtype2TestCache
Subtype3TestCache Subtype4TestCache Subtype6TestCache Subtype7TestCache DefaultTypeTest
DefaultNullableTypeTest TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest
NullableTypeParameterTypeTest SlowTypeTest LazySpecializeTypeTest
LazySpecializeNullableTypeTest CallClosureNoSuchMethod FrameAwaitingMaterialization
AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
ExitSafepointIgnoreUnwindInProgress CallNativeThroughSafepoint FfiCallbackTrampoline
InitStaticField InitLateStaticField InitLateFinalStaticField InitInstanceField
InitLateInstanceField InitLateFinalInstanceField InitSharedLateStaticField
InitSharedLateFinalStaticField Throw ReThrow InstanceOf InstantiateType
InstantiateTypeNonNullableClassTypeParameter InstantiateTypeNullableClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeArguments
InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
UnknownDartCode
""".split())

#: Dart 3.6.2. 168 stubs.
_VM_3_6_2 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler DeoptForRewind WriteBarrier
WriteBarrierWrappers ArrayWriteBarrier AllocateArray AllocateMint AllocateDouble
AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4 AllocateInt8Array AllocateUint8Array
AllocateUint8ClampedArray AllocateInt16Array AllocateUint16Array AllocateInt32Array
AllocateUint32Array AllocateInt64Array AllocateUint64Array AllocateFloat32Array
AllocateFloat64Array AllocateFloat32x4Array AllocateInt32x4Array AllocateFloat64x2Array
AllocateMintSharedWithFPURegs AllocateMintSharedWithoutFPURegs AllocateClosure
AllocateClosureGeneric AllocateClosureTA AllocateClosureTAGeneric AllocateContext
AllocateGrowableArray AllocateObject AllocateObjectParameterized AllocateObjectSlow
AllocateRecord AllocateRecord2 AllocateRecord2Named AllocateRecord3 AllocateRecord3Named
AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2 CloneContext
CallToRuntime LazyCompile InterpretCall ResumeInterpreter CallBootstrapNative
CallNoScopeNative CallAutoScopeNative FixCallersTarget CallStaticFunction
OptimizeFunction InvokeDartCode InvokeDartCodeFromBytecode DebugStepCheck
SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall ICCallThroughCode
MegamorphicCall FixAllocationStubTarget FixParameterizedAllocationStubTarget Deoptimize
DeoptimizeLazyFromReturn DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping NullIsAssignableToType Subtype1TestCache Subtype2TestCache
Subtype3TestCache Subtype4TestCache Subtype6TestCache Subtype7TestCache DefaultTypeTest
DefaultNullableTypeTest TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest
NullableTypeParameterTypeTest SlowTypeTest LazySpecializeTypeTest
LazySpecializeNullableTypeTest CallClosureNoSuchMethod FrameAwaitingMaterialization
AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
ExitSafepointIgnoreUnwindInProgress CallNativeThroughSafepoint FfiCallbackTrampoline
InitStaticField InitLateStaticField InitLateFinalStaticField InitInstanceField
InitLateInstanceField InitLateFinalInstanceField InitSharedLateStaticField
InitSharedLateFinalStaticField Throw ReThrow InstanceOf InstantiateType
InstantiateTypeNonNullableClassTypeParameter InstantiateTypeNullableClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeArguments
InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
UnknownDartCode
""".split())

#: Dart 3.5.4. 166 stubs.
_VM_3_5_4 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler DeoptForRewind WriteBarrier
WriteBarrierWrappers ArrayWriteBarrier AllocateArray AllocateMint AllocateDouble
AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4 AllocateInt8Array AllocateUint8Array
AllocateUint8ClampedArray AllocateInt16Array AllocateUint16Array AllocateInt32Array
AllocateUint32Array AllocateInt64Array AllocateUint64Array AllocateFloat32Array
AllocateFloat64Array AllocateFloat32x4Array AllocateInt32x4Array AllocateFloat64x2Array
AllocateMintSharedWithFPURegs AllocateMintSharedWithoutFPURegs AllocateClosure
AllocateClosureGeneric AllocateClosureTA AllocateClosureTAGeneric AllocateContext
AllocateGrowableArray AllocateObject AllocateObjectParameterized AllocateObjectSlow
AllocateRecord AllocateRecord2 AllocateRecord2Named AllocateRecord3 AllocateRecord3Named
AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2 CloneContext
CallToRuntime LazyCompile CallBootstrapNative CallNoScopeNative CallAutoScopeNative
FixCallersTarget CallStaticFunction OptimizeFunction InvokeDartCode DebugStepCheck
SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall ICCallThroughCode
MegamorphicCall FixAllocationStubTarget FixParameterizedAllocationStubTarget Deoptimize
DeoptimizeLazyFromReturn DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping NullIsAssignableToType Subtype1TestCache Subtype2TestCache
Subtype3TestCache Subtype4TestCache Subtype6TestCache Subtype7TestCache DefaultTypeTest
DefaultNullableTypeTest TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest
NullableTypeParameterTypeTest SlowTypeTest LazySpecializeTypeTest
LazySpecializeNullableTypeTest CallClosureNoSuchMethod FrameAwaitingMaterialization
AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
ExitSafepointIgnoreUnwindInProgress CallNativeThroughSafepoint FfiCallbackTrampoline
InitStaticField InitLateStaticField InitLateFinalStaticField InitInstanceField
InitLateInstanceField InitLateFinalInstanceField InitSharedLateStaticField
InitSharedLateFinalStaticField Throw ReThrow AssertBoolean InstanceOf InstantiateType
InstantiateTypeNonNullableClassTypeParameter InstantiateTypeNullableClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeArguments
InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
UnknownDartCode
""".split())

#: Dart 3.4.4. 168 stubs.
_VM_3_4_4 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler DeoptForRewind WriteBarrier
WriteBarrierWrappers ArrayWriteBarrier AllocateArray AllocateMint AllocateDouble
AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4 AllocateInt8Array AllocateUint8Array
AllocateUint8ClampedArray AllocateInt16Array AllocateUint16Array AllocateInt32Array
AllocateUint32Array AllocateInt64Array AllocateUint64Array AllocateFloat32Array
AllocateFloat64Array AllocateFloat32x4Array AllocateInt32x4Array AllocateFloat64x2Array
AllocateMintSharedWithFPURegs AllocateMintSharedWithoutFPURegs AllocateClosure
AllocateClosureGeneric AllocateClosureTA AllocateClosureTAGeneric AllocateContext
AllocateGrowableArray AllocateObject AllocateObjectParameterized AllocateObjectSlow
AllocateRecord AllocateRecord2 AllocateRecord2Named AllocateRecord3 AllocateRecord3Named
AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2 CloneContext
CallToRuntime LazyCompile CallBootstrapNative CallNoScopeNative CallAutoScopeNative
FixCallersTarget CallStaticFunction OptimizeFunction InvokeDartCode DebugStepCheck
SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall ICCallThroughCode
MegamorphicCall FixAllocationStubTarget FixParameterizedAllocationStubTarget Deoptimize
DeoptimizeLazyFromReturn DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping TypeIsTopTypeForSubtypingNullSafe NullIsAssignableToType
NullIsAssignableToTypeNullSafe Subtype1TestCache Subtype2TestCache Subtype3TestCache
Subtype4TestCache Subtype6TestCache Subtype7TestCache DefaultTypeTest
DefaultNullableTypeTest TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest
NullableTypeParameterTypeTest SlowTypeTest LazySpecializeTypeTest
LazySpecializeNullableTypeTest CallClosureNoSuchMethod FrameAwaitingMaterialization
AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
ExitSafepointIgnoreUnwindInProgress CallNativeThroughSafepoint FfiCallbackTrampoline
InitStaticField InitLateStaticField InitLateFinalStaticField InitInstanceField
InitLateInstanceField InitLateFinalInstanceField Throw ReThrow AssertBoolean InstanceOf
InstantiateType InstantiateTypeNonNullableClassTypeParameter
InstantiateTypeNullableClassTypeParameter InstantiateTypeLegacyClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeLegacyFunctionTypeParameter
InstantiateTypeArguments InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
UnknownDartCode
""".split())

#: Dart 3.3.4 and 3.2.6. 165 stubs.
_VM_3_3_4 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler DeoptForRewind WriteBarrier
WriteBarrierWrappers ArrayWriteBarrier AllocateArray AllocateMint AllocateDouble
AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4 AllocateInt8Array AllocateUint8Array
AllocateUint8ClampedArray AllocateInt16Array AllocateUint16Array AllocateInt32Array
AllocateUint32Array AllocateInt64Array AllocateUint64Array AllocateFloat32Array
AllocateFloat64Array AllocateFloat32x4Array AllocateInt32x4Array AllocateFloat64x2Array
AllocateMintSharedWithFPURegs AllocateMintSharedWithoutFPURegs AllocateClosure
AllocateContext AllocateGrowableArray AllocateObject AllocateObjectParameterized
AllocateObjectSlow AllocateRecord AllocateRecord2 AllocateRecord2Named AllocateRecord3
AllocateRecord3Named AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2
CloneContext CallToRuntime LazyCompile CallBootstrapNative CallNoScopeNative
CallAutoScopeNative FixCallersTarget CallStaticFunction OptimizeFunction InvokeDartCode
DebugStepCheck SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall
ICCallThroughCode MegamorphicCall FixAllocationStubTarget
FixParameterizedAllocationStubTarget Deoptimize DeoptimizeLazyFromReturn
DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping TypeIsTopTypeForSubtypingNullSafe NullIsAssignableToType
NullIsAssignableToTypeNullSafe Subtype1TestCache Subtype2TestCache Subtype3TestCache
Subtype4TestCache Subtype6TestCache Subtype7TestCache DefaultTypeTest
DefaultNullableTypeTest TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest
NullableTypeParameterTypeTest SlowTypeTest LazySpecializeTypeTest
LazySpecializeNullableTypeTest CallClosureNoSuchMethod FrameAwaitingMaterialization
AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
ExitSafepointIgnoreUnwindInProgress CallNativeThroughSafepoint FfiCallbackTrampoline
InitStaticField InitLateStaticField InitLateFinalStaticField InitInstanceField
InitLateInstanceField InitLateFinalInstanceField Throw ReThrow AssertBoolean InstanceOf
InstantiateType InstantiateTypeNonNullableClassTypeParameter
InstantiateTypeNullableClassTypeParameter InstantiateTypeLegacyClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeLegacyFunctionTypeParameter
InstantiateTypeArguments InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
UnknownDartCode
""".split())

#: Dart 3.1.5. 164 stubs.
_VM_3_1_5 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler DeoptForRewind WriteBarrier
WriteBarrierWrappers ArrayWriteBarrier AllocateArray AllocateMint AllocateDouble
AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4 AllocateInt8Array AllocateUint8Array
AllocateUint8ClampedArray AllocateInt16Array AllocateUint16Array AllocateInt32Array
AllocateUint32Array AllocateInt64Array AllocateUint64Array AllocateFloat32Array
AllocateFloat64Array AllocateFloat32x4Array AllocateInt32x4Array AllocateFloat64x2Array
AllocateMintSharedWithFPURegs AllocateMintSharedWithoutFPURegs AllocateClosure
AllocateContext AllocateGrowableArray AllocateObject AllocateObjectParameterized
AllocateObjectSlow AllocateRecord AllocateRecord2 AllocateRecord2Named AllocateRecord3
AllocateRecord3Named AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2
CloneContext CallToRuntime LazyCompile CallBootstrapNative CallNoScopeNative
CallAutoScopeNative FixCallersTarget CallStaticFunction OptimizeFunction InvokeDartCode
DebugStepCheck SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall
ICCallThroughCode MegamorphicCall FixAllocationStubTarget
FixParameterizedAllocationStubTarget Deoptimize DeoptimizeLazyFromReturn
DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping TypeIsTopTypeForSubtypingNullSafe NullIsAssignableToType
NullIsAssignableToTypeNullSafe Subtype1TestCache Subtype2TestCache Subtype4TestCache
Subtype6TestCache Subtype7TestCache DefaultTypeTest DefaultNullableTypeTest
TopTypeTypeTest UnreachableTypeTest TypeParameterTypeTest NullableTypeParameterTypeTest
SlowTypeTest LazySpecializeTypeTest LazySpecializeNullableTypeTest
CallClosureNoSuchMethod FrameAwaitingMaterialization AsynchronousGapMarker NotLoaded
DispatchTableNullError LateInitializationErrorSharedWithFPURegs
LateInitializationErrorSharedWithoutFPURegs NullErrorSharedWithFPURegs
NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
ExitSafepointIgnoreUnwindInProgress CallNativeThroughSafepoint FfiCallbackTrampoline
InitStaticField InitLateStaticField InitLateFinalStaticField InitInstanceField
InitLateInstanceField InitLateFinalInstanceField Throw ReThrow AssertBoolean InstanceOf
InstantiateType InstantiateTypeNonNullableClassTypeParameter
InstantiateTypeNullableClassTypeParameter InstantiateTypeLegacyClassTypeParameter
InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeLegacyFunctionTypeParameter
InstantiateTypeArguments InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState FfiAsyncCallbackSend
UnknownDartCode
""".split())

#: Dart 3.0.6. 161 stubs.
_VM_3_0_6 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler DeoptForRewind WriteBarrier
WriteBarrierWrappers ArrayWriteBarrier AllocateArray AllocateMint AllocateDouble
AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4 AllocateInt8Array AllocateUint8Array
AllocateUint8ClampedArray AllocateInt16Array AllocateUint16Array AllocateInt32Array
AllocateUint32Array AllocateInt64Array AllocateUint64Array AllocateFloat32Array
AllocateFloat64Array AllocateFloat32x4Array AllocateInt32x4Array AllocateFloat64x2Array
AllocateMintSharedWithFPURegs AllocateMintSharedWithoutFPURegs AllocateClosure
AllocateContext AllocateGrowableArray AllocateObject AllocateObjectParameterized
AllocateObjectSlow AllocateRecord AllocateRecord2 AllocateRecord2Named AllocateRecord3
AllocateRecord3Named AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2
CloneContext CallToRuntime LazyCompile CallBootstrapNative CallNoScopeNative
CallAutoScopeNative FixCallersTarget CallStaticFunction OptimizeFunction InvokeDartCode
DebugStepCheck SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall
ICCallThroughCode MegamorphicCall FixAllocationStubTarget
FixParameterizedAllocationStubTarget Deoptimize DeoptimizeLazyFromReturn
DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping TypeIsTopTypeForSubtypingNullSafe NullIsAssignableToType
NullIsAssignableToTypeNullSafe Subtype1TestCache Subtype3TestCache Subtype5TestCache
Subtype7TestCache DefaultTypeTest DefaultNullableTypeTest TopTypeTypeTest
UnreachableTypeTest TypeParameterTypeTest NullableTypeParameterTypeTest SlowTypeTest
LazySpecializeTypeTest LazySpecializeNullableTypeTest CallClosureNoSuchMethod
FrameAwaitingMaterialization AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
ExitSafepointIgnoreUnwindInProgress CallNativeThroughSafepoint InitStaticField
InitLateStaticField InitLateFinalStaticField InitInstanceField InitLateInstanceField
InitLateFinalInstanceField Throw ReThrow AssertBoolean InstanceOf InstantiateType
InstantiateTypeNonNullableClassTypeParameter InstantiateTypeNullableClassTypeParameter
InstantiateTypeLegacyClassTypeParameter InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeLegacyFunctionTypeParameter
InstantiateTypeArguments InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await
AwaitWithTypeCheck InitAsync Resume ReturnAsync ReturnAsyncNotFuture InitAsyncStar
YieldAsyncStar ReturnAsyncStar InitSyncStar SuspendSyncStarAtStart
SuspendSyncStarAtYield AsyncExceptionHandler CloneSuspendState UnknownDartCode
""".split())

#: Dart 2.19.6. 160 stubs.
_VM_2_19_6 = tuple("""
GetCStackPointer JumpToFrame RunExceptionHandler DeoptForRewind WriteBarrier
WriteBarrierWrappers ArrayWriteBarrier AllocateArray AllocateMint AllocateDouble
AllocateFloat32x4 AllocateFloat64x2 AllocateInt32x4 AllocateInt8Array AllocateUint8Array
AllocateUint8ClampedArray AllocateInt16Array AllocateUint16Array AllocateInt32Array
AllocateUint32Array AllocateInt64Array AllocateUint64Array AllocateFloat32Array
AllocateFloat64Array AllocateFloat32x4Array AllocateInt32x4Array AllocateFloat64x2Array
AllocateMintSharedWithFPURegs AllocateMintSharedWithoutFPURegs AllocateClosure
AllocateContext AllocateGrowableArray AllocateObject AllocateObjectParameterized
AllocateObjectSlow AllocateRecord AllocateRecord2 AllocateRecord2Named AllocateRecord3
AllocateRecord3Named AllocateUnhandledException BoxDouble BoxFloat32x4 BoxFloat64x2
CloneContext CallToRuntime LazyCompile CallBootstrapNative CallNoScopeNative
CallAutoScopeNative FixCallersTarget CallStaticFunction OptimizeFunction InvokeDartCode
DebugStepCheck SwitchableCallMiss MonomorphicSmiableCheck SingleTargetCall
ICCallThroughCode MegamorphicCall FixAllocationStubTarget
FixParameterizedAllocationStubTarget Deoptimize DeoptimizeLazyFromReturn
DeoptimizeLazyFromThrow UnoptimizedIdenticalWithNumberCheck
OptimizedIdenticalWithNumberCheck ICCallBreakpoint UnoptStaticCallBreakpoint
RuntimeCallBreakpoint OneArgCheckInlineCache TwoArgsCheckInlineCache SmiAddInlineCache
SmiLessInlineCache SmiEqualInlineCache OneArgOptimizedCheckInlineCache
TwoArgsOptimizedCheckInlineCache ZeroArgsUnoptimizedStaticCall
OneArgUnoptimizedStaticCall TwoArgsUnoptimizedStaticCall AssertSubtype AssertAssignable
TypeIsTopTypeForSubtyping TypeIsTopTypeForSubtypingNullSafe NullIsAssignableToType
NullIsAssignableToTypeNullSafe Subtype1TestCache Subtype3TestCache Subtype5TestCache
Subtype7TestCache DefaultTypeTest DefaultNullableTypeTest TopTypeTypeTest
UnreachableTypeTest TypeParameterTypeTest NullableTypeParameterTypeTest SlowTypeTest
LazySpecializeTypeTest LazySpecializeNullableTypeTest CallClosureNoSuchMethod
FrameAwaitingMaterialization AsynchronousGapMarker NotLoaded DispatchTableNullError
LateInitializationErrorSharedWithFPURegs LateInitializationErrorSharedWithoutFPURegs
NullErrorSharedWithFPURegs NullErrorSharedWithoutFPURegs NullArgErrorSharedWithFPURegs
NullArgErrorSharedWithoutFPURegs NullCastErrorSharedWithFPURegs
NullCastErrorSharedWithoutFPURegs RangeErrorSharedWithFPURegs
RangeErrorSharedWithoutFPURegs WriteErrorSharedWithFPURegs
WriteErrorSharedWithoutFPURegs StackOverflowSharedWithFPURegs
StackOverflowSharedWithoutFPURegs DoubleToInteger
OneArgCheckInlineCacheWithExactnessCheck
OneArgOptimizedCheckInlineCacheWithExactnessCheck EnterSafepoint ExitSafepoint
ExitSafepointIgnoreUnwindInProgress CallNativeThroughSafepoint InitStaticField
InitLateStaticField InitLateFinalStaticField InitInstanceField InitLateInstanceField
InitLateFinalInstanceField Throw ReThrow AssertBoolean InstanceOf InstantiateType
InstantiateTypeNonNullableClassTypeParameter InstantiateTypeNullableClassTypeParameter
InstantiateTypeLegacyClassTypeParameter InstantiateTypeNonNullableFunctionTypeParameter
InstantiateTypeNullableFunctionTypeParameter InstantiateTypeLegacyFunctionTypeParameter
InstantiateTypeArguments InstantiateTypeArgumentsMayShareInstantiatorTA
InstantiateTypeArgumentsMayShareFunctionTA NoSuchMethodDispatcher Await InitAsync Resume
ReturnAsync ReturnAsyncNotFuture InitAsyncStar YieldAsyncStar ReturnAsyncStar
InitSyncStar SuspendSyncStarAtStart SuspendSyncStarAtYield AsyncExceptionHandler
CloneSuspendState UnknownDartCode
""".split())

#: SDK release -> its VM_STUB_CODE_LIST, in order.
VM_STUBS: dict[str, tuple] = {
    '2.19.6': _VM_2_19_6,
    '3.0.6': _VM_3_0_6,
    '3.1.5': _VM_3_1_5,
    '3.10.9': _VM_3_10_9,
    '3.11.5': _VM_3_11_5,
    '3.12.0': _VM_3_12_2,
    '3.12.2': _VM_3_12_2,
    '3.2.6': _VM_3_3_4,
    '3.3.4': _VM_3_3_4,
    '3.4.4': _VM_3_4_4,
    '3.5.4': _VM_3_5_4,
    '3.6.2': _VM_3_6_2,
    '3.7.2': _VM_3_7_2,
    '3.9.2': _VM_3_9_2,
}
