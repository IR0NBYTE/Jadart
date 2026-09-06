"""Dart cid -> class-name table, generated for SDK 3.12.2.

Written by tools/gen_cids.py, which runs the C preprocessor over the
runtime/vm/class_id.h CLASS_ID_LIST at tag 3.12.2. That's the same X-macro
the VM uses to build its ClassId enum.

Don't hand-edit this file, regenerate it per epoch. cid numbering shifts
whenever a predefined class is added or removed, and a shifted table
mislabels clusters.
"""
from __future__ import annotations

NUM_PREDEFINED_CIDS = 175

CID_NAMES: dict[int, str] = {
    0: 'IllegalCid',
    1: 'NativePointer',
    2: 'FreeListElement',
    3: 'ForwardingCorpse',
    4: 'ObjectCid',
    5: 'ClassCid',
    6: 'PatchClassCid',
    7: 'FunctionCid',
    8: 'TypeParametersCid',
    9: 'ClosureDataCid',
    10: 'FfiTrampolineDataCid',
    11: 'FieldCid',
    12: 'ScriptCid',
    13: 'LibraryCid',
    14: 'NamespaceCid',
    15: 'KernelProgramInfoCid',
    16: 'WeakSerializationReferenceCid',
    17: 'WeakArrayCid',
    18: 'CodeCid',
    19: 'BytecodeCid',
    20: 'InstructionsCid',
    21: 'InstructionsSectionCid',
    22: 'InstructionsTableCid',
    23: 'ObjectPoolCid',
    24: 'PcDescriptorsCid',
    25: 'CodeSourceMapCid',
    26: 'CompressedStackMapsCid',
    27: 'LocalVarDescriptorsCid',
    28: 'ExceptionHandlersCid',
    29: 'ContextCid',
    30: 'ContextScopeCid',
    31: 'SentinelCid',
    32: 'SingleTargetCacheCid',
    33: 'MonomorphicSmiableCallCid',
    34: 'CallSiteDataCid',
    35: 'UnlinkedCallCid',
    36: 'ICDataCid',
    37: 'MegamorphicCacheCid',
    38: 'SubtypeTestCacheCid',
    39: 'LoadingUnitCid',
    40: 'ErrorCid',
    41: 'ApiErrorCid',
    42: 'LanguageErrorCid',
    43: 'UnhandledExceptionCid',
    44: 'UnwindErrorCid',
    45: 'InstanceCid',
    46: 'LibraryPrefixCid',
    47: 'TypeArgumentsCid',
    48: 'AbstractTypeCid',
    49: 'TypeCid',
    50: 'FunctionTypeCid',
    51: 'RecordTypeCid',
    52: 'TypeParameterCid',
    53: 'FinalizerBaseCid',
    54: 'FinalizerCid',
    55: 'NativeFinalizerCid',
    56: 'FinalizerEntryCid',
    57: 'ClosureCid',
    58: 'NumberCid',
    59: 'IntegerCid',
    60: 'SmiCid',
    61: 'MintCid',
    62: 'DoubleCid',
    63: 'BoolCid',
    64: 'Float32x4Cid',
    65: 'Int32x4Cid',
    66: 'Float64x2Cid',
    67: 'RecordCid',
    68: 'TypedDataBaseCid',
    69: 'TypedDataCid',
    70: 'ExternalTypedDataCid',
    71: 'TypedDataViewCid',
    72: 'PointerCid',
    73: 'DynamicLibraryCid',
    74: 'CapabilityCid',
    75: 'ReceivePortCid',
    76: 'SendPortCid',
    77: 'StackTraceCid',
    78: 'SuspendStateCid',
    79: 'RegExpCid',
    80: 'WeakPropertyCid',
    81: 'WeakReferenceCid',
    82: 'MirrorReferenceCid',
    83: 'FutureOrCid',
    84: 'UserTagCid',
    85: 'TransferableTypedDataCid',
    86: 'MapCid',
    87: 'ConstMapCid',
    88: 'SetCid',
    89: 'ConstSetCid',
    90: 'ArrayCid',
    91: 'ImmutableArrayCid',
    92: 'GrowableObjectArrayCid',
    93: 'StringCid',
    94: 'OneByteStringCid',
    95: 'TwoByteStringCid',
    96: 'FfiNativeFunctionCid',
    97: 'FfiInt8Cid',
    98: 'FfiInt16Cid',
    99: 'FfiInt32Cid',
    100: 'FfiInt64Cid',
    101: 'FfiUint8Cid',
    102: 'FfiUint16Cid',
    103: 'FfiUint32Cid',
    104: 'FfiUint64Cid',
    105: 'FfiFloatCid',
    106: 'FfiDoubleCid',
    107: 'FfiVoidCid',
    108: 'FfiHandleCid',
    109: 'FfiBoolCid',
    110: 'FfiNativeTypeCid',
    111: 'FfiStructCid',
    112: 'TypedDataInt8ArrayCid',
    113: 'TypedDataInt8ArrayViewCid',
    114: 'ExternalTypedDataInt8ArrayCid',
    115: 'UnmodifiableTypedDataInt8ArrayViewCid',
    116: 'TypedDataUint8ArrayCid',
    117: 'TypedDataUint8ArrayViewCid',
    118: 'ExternalTypedDataUint8ArrayCid',
    119: 'UnmodifiableTypedDataUint8ArrayViewCid',
    120: 'TypedDataUint8ClampedArrayCid',
    121: 'TypedDataUint8ClampedArrayViewCid',
    122: 'ExternalTypedDataUint8ClampedArrayCid',
    123: 'UnmodifiableTypedDataUint8ClampedArrayViewCid',
    124: 'TypedDataInt16ArrayCid',
    125: 'TypedDataInt16ArrayViewCid',
    126: 'ExternalTypedDataInt16ArrayCid',
    127: 'UnmodifiableTypedDataInt16ArrayViewCid',
    128: 'TypedDataUint16ArrayCid',
    129: 'TypedDataUint16ArrayViewCid',
    130: 'ExternalTypedDataUint16ArrayCid',
    131: 'UnmodifiableTypedDataUint16ArrayViewCid',
    132: 'TypedDataInt32ArrayCid',
    133: 'TypedDataInt32ArrayViewCid',
    134: 'ExternalTypedDataInt32ArrayCid',
    135: 'UnmodifiableTypedDataInt32ArrayViewCid',
    136: 'TypedDataUint32ArrayCid',
    137: 'TypedDataUint32ArrayViewCid',
    138: 'ExternalTypedDataUint32ArrayCid',
    139: 'UnmodifiableTypedDataUint32ArrayViewCid',
    140: 'TypedDataInt64ArrayCid',
    141: 'TypedDataInt64ArrayViewCid',
    142: 'ExternalTypedDataInt64ArrayCid',
    143: 'UnmodifiableTypedDataInt64ArrayViewCid',
    144: 'TypedDataUint64ArrayCid',
    145: 'TypedDataUint64ArrayViewCid',
    146: 'ExternalTypedDataUint64ArrayCid',
    147: 'UnmodifiableTypedDataUint64ArrayViewCid',
    148: 'TypedDataFloat32ArrayCid',
    149: 'TypedDataFloat32ArrayViewCid',
    150: 'ExternalTypedDataFloat32ArrayCid',
    151: 'UnmodifiableTypedDataFloat32ArrayViewCid',
    152: 'TypedDataFloat64ArrayCid',
    153: 'TypedDataFloat64ArrayViewCid',
    154: 'ExternalTypedDataFloat64ArrayCid',
    155: 'UnmodifiableTypedDataFloat64ArrayViewCid',
    156: 'TypedDataFloat32x4ArrayCid',
    157: 'TypedDataFloat32x4ArrayViewCid',
    158: 'ExternalTypedDataFloat32x4ArrayCid',
    159: 'UnmodifiableTypedDataFloat32x4ArrayViewCid',
    160: 'TypedDataInt32x4ArrayCid',
    161: 'TypedDataInt32x4ArrayViewCid',
    162: 'ExternalTypedDataInt32x4ArrayCid',
    163: 'UnmodifiableTypedDataInt32x4ArrayViewCid',
    164: 'TypedDataFloat64x2ArrayCid',
    165: 'TypedDataFloat64x2ArrayViewCid',
    166: 'ExternalTypedDataFloat64x2ArrayCid',
    167: 'UnmodifiableTypedDataFloat64x2ArrayViewCid',
    168: 'ByteDataViewCid',
    169: 'UnmodifiableByteDataViewCid',
    170: 'ByteBufferCid',
    171: 'NullCid',
    172: 'DynamicCid',
    173: 'VoidCid',
    174: 'NeverCid',
}

NAME_TO_CID: dict[str, int] = {v: k for k, v in CID_NAMES.items()}

# Named cids the parser dispatches on, resolved through the table above so they
# can't drift from it. A name this epoch doesn't define is just absent.
kIllegalCid = NAME_TO_CID['IllegalCid']
kObjectCid = NAME_TO_CID['ObjectCid']
kClassCid = NAME_TO_CID['ClassCid']
kFunctionCid = NAME_TO_CID['FunctionCid']
kFieldCid = NAME_TO_CID['FieldCid']
kScriptCid = NAME_TO_CID['ScriptCid']
kLibraryCid = NAME_TO_CID['LibraryCid']
kCodeCid = NAME_TO_CID['CodeCid']
kObjectPoolCid = NAME_TO_CID['ObjectPoolCid']
kInstanceCid = NAME_TO_CID['InstanceCid']
kTypeArgumentsCid = NAME_TO_CID['TypeArgumentsCid']
kTypeCid = NAME_TO_CID['TypeCid']
kFunctionTypeCid = NAME_TO_CID['FunctionTypeCid']
kTypeParameterCid = NAME_TO_CID['TypeParameterCid']
kTypeParametersCid = NAME_TO_CID['TypeParametersCid']
kClosureCid = NAME_TO_CID['ClosureCid']
kClosureDataCid = NAME_TO_CID['ClosureDataCid']
kMintCid = NAME_TO_CID['MintCid']
kDoubleCid = NAME_TO_CID['DoubleCid']
kArrayCid = NAME_TO_CID['ArrayCid']
kImmutableArrayCid = NAME_TO_CID['ImmutableArrayCid']
kGrowableObjectArrayCid = NAME_TO_CID['GrowableObjectArrayCid']
kWeakArrayCid = NAME_TO_CID['WeakArrayCid']
kRecordCid = NAME_TO_CID['RecordCid']
kRecordTypeCid = NAME_TO_CID['RecordTypeCid']
kStringCid = NAME_TO_CID['StringCid']
kOneByteStringCid = NAME_TO_CID['OneByteStringCid']
kTwoByteStringCid = NAME_TO_CID['TwoByteStringCid']
kContextCid = NAME_TO_CID['ContextCid']
kContextScopeCid = NAME_TO_CID['ContextScopeCid']
kPcDescriptorsCid = NAME_TO_CID['PcDescriptorsCid']
kCodeSourceMapCid = NAME_TO_CID['CodeSourceMapCid']
kCompressedStackMapsCid = NAME_TO_CID['CompressedStackMapsCid']
kLocalVarDescriptorsCid = NAME_TO_CID['LocalVarDescriptorsCid']
kExceptionHandlersCid = NAME_TO_CID['ExceptionHandlersCid']
kConstMapCid = NAME_TO_CID['ConstMapCid']
kConstSetCid = NAME_TO_CID['ConstSetCid']
kFfiTrampolineDataCid = NAME_TO_CID['FfiTrampolineDataCid']
kPatchClassCid = NAME_TO_CID['PatchClassCid']
kLibraryPrefixCid = NAME_TO_CID['LibraryPrefixCid']
kTypedDataInt8ArrayCid = NAME_TO_CID['TypedDataInt8ArrayCid']

