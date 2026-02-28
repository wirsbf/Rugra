# Rudra Alignment Checklist: 01 Core Infrastructure

## File: `address.hh`
### Class: `Address`
- [x] `new` ✅
- [x] `as_u64` ✅
- [x] `offset` ✅
- [x] `is_null` ✅
- [x] `is_aligned` ✅
- [x] `next` ✅
- [x] `prev` ✅

### Class: `SeqNum`
- [x] `SeqNum` ✅
- [x] `decode` ✅
- [x] `encode` ✅
- [x] `getOrder` ✅
- [ ] `getTime`
- [x] `setOrder` ✅

### Class: `Range`
- [x] `Address` ✅
- [x] `Range` ✅
- [x] `contains` ✅
- [x] `decode` ✅
- [x] `decodeFromAttributes` ✅
- [x] `encode` ✅
- [x] `getFirst` ✅
- [x] `getFirstAddr` ✅
- [x] `getLast` ✅
- [x] `getLastAddr` ✅
- [x] `getLastAddrOpen` ✅
- [x] `printBounds` ✅

### Class: `RangeProperties`
- [x] `decode` ✅

### Class: `RangeList`
- [x] `RangeList` ✅
- [x] `begin` ✅
- [x] `clear` ✅
- [x] `decode` ✅
- [x] `empty` ✅
- [x] `encode` ✅
- [x] `end` ✅
- [x] `inRange` ✅
- [x] `insertRange` ✅
- [x] `longestFit` ✅
- [x] `merge` ✅
- [x] `numRanges` ✅
- [x] `printBounds` ✅
- [x] `removeRange` ✅

## File: `pcoderaw.hh`
### Class: `PcodeOpRaw`
- [x] `addInput` ✅
- [x] `clearInputs` ✅
- [x] `decode` ✅
- [x] `getOpcode` ✅
- [x] `numInput` ✅
- [x] `setBehavior` ✅
- [x] `setOutput` ✅
- [x] `setSeqNum` ✅

## File: `opcodes.hh`
### Enum: `OpCode`
- [x] `OpCode` (Definition of all 73 variants) ✅
- [x] `name` (String representation) ✅

## File: `sleigh.hh`
### Class: `PcodeCacher`
- [ ] `addLabel`
- [ ] `addLabelRef`
- [ ] `clear`
- [ ] `emit`
- [ ] `expandPool`
- [ ] `resolveRelatives`
- [ ] `~PcodeCacher`

### Class: `DisassemblyCache`
- [ ] `~DisassemblyCache`

### Class: `SleighBuilder`
- [ ] `appendBuild`
- [ ] `appendCrossBuild`
- [ ] `delaySlot`
- [ ] `setLabel`

### Class: `Sleigh`
- [ ] `allowContextSet`
- [ ] `initialize`
- [ ] `instructionLength`
- [ ] `oneInstruction`
- [ ] `printAssembly`
- [ ] `registerContext`
- [ ] `reset`
- [ ] `setContextDefault`
- [ ] `~Sleigh`

### Class: `AssemblyRaw`
- [ ] `dump`

### Class: `PcodeRawOut`
- [ ] `dump`

### Class: `MyLoadImage`
- [ ] `Loadimage`
- [ ] `adjustVma`
- [ ] `getArchType`
- [ ] `loadFill`

## File: `sleighbase.hh`
### Class: `SourceFileIndexer`
- [ ] `decode`
- [ ] `encode`
- [ ] `getFilename`
- [ ] `getIndex`
- [ ] `index`

### Class: `SleighBase`
- [ ] `encode`
- [ ] `encodeSlaSpace`
- [ ] `getAllRegisters`
- [ ] `getExactRegisterName`
- [ ] `getRegisterName`
- [ ] `getUserOpNames`
- [ ] `isInitialized`
- [ ] `~SleighBase`

## File: `space.hh`
### Class: `AddrSpace`
- [x] `space_id` ✅
- [x] `from_id` ✅
- [x] `is_register` ✅
- [x] `is_unique` ✅
- [x] `is_const` ✅
- [x] `is_ram` ✅
- [x] `is_stack` ✅
- [x] `word_size` ✅
- [x] `addr_size` ✅
- [x] `name` ✅

### Class: `ConstantSpace`
- [x] `decode` ✅
- [x] `overlapJoin` ✅
- [x] `printRaw` ✅

### Class: `OtherSpace`
- [x] `OtherSpace` ✅
- [x] `printRaw` ✅

### Class: `UniqueSpace`
- [x] `UniqueSpace` ✅
- [x] `allocate` ✅
- [x] `reset` ✅

### Class: `JoinSpace`
- [x] `decode` ✅
- [x] `decodeAttributes` ✅
- [x] `encodeAttributes` ✅
- [x] `overlapJoin` ✅
- [x] `printRaw` ✅
- [x] `read` ✅

### Class: `OverlaySpace`
- [x] `decode` ✅

## File: `translate.hh`
### Class: `TruncationTag`
- [ ] `decode`
- [ ] `getSize`

### Class: `PcodeEmit`
- [ ] `decodeOp`
- [ ] `dump`
- [ ] `~PcodeEmit`

### Class: `AssemblyEmit`
- [ ] `dump`
- [ ] `~AssemblyEmit`

### Class: `AddressResolver`
- [ ] `resolve`
- [ ] `~AddressResolver`

### Class: `SpacebaseSpace`
- [ ] `decode`
- [ ] `numSpacebase`
- [ ] `stackGrowsNegative`

### Class: `JoinRecord`
- [ ] `getEquivalentAddress`
- [ ] `isFloatExtension`
- [ ] `mergeSequence`
- [ ] `numPieces`

### Class: `AddrSpaceManager`
- [ ] `constructFloatExtensionAddress`
- [ ] `constructJoinAddress`
- [ ] `createConstFromSpace`
- [ ] `getConstant`
- [ ] `getDefaultSize`
- [ ] `numSpaces`
- [ ] `parseAddressSimple`
- [ ] `renormalizeJoinAddress`
- [ ] `resolveConstant`
- [ ] `setDeadcodeDelay`
- [ ] `truncateSpace`
- [ ] `~AddrSpaceManager`

### Class: `Translate`
- [ ] *No public functions*