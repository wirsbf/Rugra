# Rudra Alignment Checklist: 04 Control Flow

## File: `block.hh`
### Class: `FlowBlock`
- [x] `get_index` ✅
- [x] `set_index` ✅
- [x] `get_type` ✅
- [x] `get_flags` ✅
- [x] `set_flags` ✅
- [x] `size_in` ✅
- [x] `size_out` ✅
- [x] `get_in` ✅
- [x] `get_out` ✅
- [x] `get_parent` ✅

### Class: `BlockGraph`
- [x] `addEdge` ✅
- [x] `addLoopEdge` ✅
- [ ] `buildCopy`
- [x] `buildDomDepth` ✅
- [x] `buildDomSubTree` ✅
- [x] `buildDomTree` ✅
- [ ] `calcForwardDominator`
- [ ] `calcLoop`
- [x] `clear` ✅
- [ ] `clearVisitCount`
- [ ] `collectReachable`
- [ ] `decode`
- [ ] `decodeBody`
- [ ] `emit`
- [ ] `encodeBody`
- [ ] `finalTransform`
- [ ] `finalizePrinting`
- [x] `getSize` ✅
- [x] `getType` ✅
- [ ] `if`
- [ ] `isConsistent`
- [ ] `markLabelBumpUp`
- [ ] `markUnstructured`
- [ ] `moveOutEdge`
- [ ] `orderBlocks`
- [ ] `printRaw`
- [ ] `printRawImpliedGoto`
- [ ] `printTree`
- [ ] `removeBlock`
- [ ] `removeEdge`
- [ ] `removeFromFlow`
- [ ] `removeFromFlowSplit`
- [ ] `scopeBreak`
- [ ] `setStartBlock`
- [ ] `spliceBlock`
- [ ] `structureLoops`
- [ ] `switchEdge`
- [x] `calc_rpo` ✅
- [x] `calc_dom_frontier` ✅
- [ ] `~BlockGraph`

### Class: `BlockBasic`
- [x] `add_op` ✅
- [x] `last_op` ✅
- [x] `first_op` ✅
- [ ] `beginOp`
- [ ] `contains`
- [ ] `decodeBody`
- [ ] `emit`
- [ ] `emptyOp`
- [ ] `encodeBody`
- [ ] `endOp`
- [ ] `flipInPlaceExecute`
- [ ] `flipInPlaceTest`
- [ ] `getEntryAddr`
- [ ] `getStart`
- [ ] `getStop`
- [x] `getType` ✅
- [ ] `hasOnlyMarkers`
- [ ] `isComplex`
- [ ] `isDoNothing`
- [ ] `liftVerifyUnroll`
- [ ] `negateCondition`
- [ ] `noInterveningStatement`
- [ ] `printHeader`
- [ ] `printRaw`
- [ ] `printRawImpliedGoto`
- [ ] `unblockedMulti`

### Class: `BlockCopy`
- [ ] `emit`
- [ ] `encodeHeader`
- [x] `getType` ✅
- [ ] `isComplex`
- [ ] `negateCondition`
- [ ] `printHeader`
- [ ] `printRaw`
- [ ] `printRawImpliedGoto`
- [ ] `printTree`

### Class: `BlockGoto`
- [ ] `emit`
- [ ] `encodeBody`
- [ ] `getBlock`
- [ ] `getGotoType`
- [x] `getType` ✅
- [ ] `gotoPrints`
- [ ] `markUnstructured`
- [ ] `printHeader`
- [ ] `printRaw`
- [ ] `scopeBreak`

### Class: `BlockMultiGoto`
- [ ] `addEdge`
- [ ] `emit`
- [ ] `encodeBody`
- [ ] `getBlock`
- [ ] `getType`
- [ ] `hasDefaultGoto`
- [ ] `numGotos`
- [ ] `printHeader`
- [ ] `printRaw`
- [ ] `scopeBreak`
- [ ] `setDefaultGoto`

### Class: `BlockList`
- [ ] `emit`
- [x] `getType` ✅
- [ ] `negateCondition`
- [ ] `printHeader`

### Class: `BlockCondition`
- [ ] `emit`
- [ ] `encodeHeader`
- [ ] `flipInPlaceExecute`
- [ ] `flipInPlaceTest`
- [ ] `getBlock`
- [ ] `getOpcode`
- [x] `getType` ✅
- [ ] `isComplex`
- [ ] `negateCondition`
- [ ] `printHeader`
- [ ] `scopeBreak`


### Class: `BlockIf`
- [ ] `emit`
- [ ] `encodeBody`
- [ ] `getGotoType`
- [x] `getType` ✅
- [ ] `markUnstructured`
- [ ] `preferComplement`
- [ ] `printHeader`
- [ ] `scopeBreak`
- [ ] `setGotoTarget`

### Class: `BlockWhileDo`
- [ ] `emit`
- [ ] `finalTransform`
- [ ] `finalizePrinting`
- [x] `getType` ✅
- [ ] `hasOverflowSyntax`
- [ ] `markLabelBumpUp`
- [ ] `printHeader`
- [ ] `scopeBreak`
- [ ] `setOverflowSyntax`

### Class: `BlockDoWhile`
- [ ] `emit`
- [x] `getType` ✅
- [ ] `markLabelBumpUp`
- [ ] `printHeader`
- [ ] `scopeBreak`

### Class: `BlockInfLoop`
- [ ] `emit`
- [x] `getType` ✅
- [ ] `markLabelBumpUp`
- [ ] `printHeader`
- [ ] `scopeBreak`

### Class: `BlockMap`
- [ ] `findBlock`
- [ ] `sortList`

## File: `flow.hh`
### Class: `FlowInfo`
- [ ] *No public functions*

## File: `jumptable.hh`
### Class: `LoadTable`
- [ ] `LoadTable`
- [ ] `collapseTable`
- [ ] `decode`
- [ ] `encode`

### Class: `EmulateFunction`
- [ ] `emulatePath`
- [ ] `getVarnodeValue`
- [ ] `setExecuteAddress`
- [ ] `setLoadCollect`
- [ ] `setVarnodeValue`

### Class: `GuardRecord`
- [ ] `clear`
- [ ] `getPath`
- [ ] `isUnrolled`
- [ ] `oneOffMatch`
- [ ] `valueMatch`

### Class: `JumpValues`
- [ ] `contains`
- [ ] `getSize`
- [ ] `getValue`
- [ ] `initializeForReading`
- [ ] `isReversible`
- [ ] `next`
- [ ] `truncate`
- [ ] `~JumpValues`

### Class: `JumpValuesRange`
- [ ] `contains`
- [ ] `getSize`
- [ ] `getValue`
- [ ] `initializeForReading`
- [ ] `isReversible`
- [ ] `next`
- [ ] `setRange`
- [ ] `setStartOp`
- [ ] `setStartVn`
- [ ] `truncate`

### Class: `JumpValuesRangeDefault`
- [ ] `contains`
- [ ] `getSize`
- [ ] `initializeForReading`
- [ ] `isReversible`
- [ ] `next`
- [ ] `setDefaultOp`
- [ ] `setDefaultVn`
- [ ] `setExtraValue`

### Class: `JumpModel`
- [ ] `buildLabels`
- [ ] `clear`
- [ ] `decode`
- [ ] `encode`
- [ ] `findUnnormalized`
- [ ] `foldInGuards`
- [ ] `getTableSize`
- [ ] `isOverride`
- [ ] `recoverModel`
- [ ] `~JumpModel`

### Class: `JumpModelTrivial`
- [ ] `JumpModel`
- [ ] `buildLabels`
- [ ] `findUnnormalized`
- [ ] `foldInGuards`
- [ ] `getTableSize`
- [ ] `isOverride`
- [ ] `recoverModel`

### Class: `JumpBasic`
- [ ] `JumpModel`
- [ ] `buildLabels`
- [ ] `clear`
- [ ] `findUnnormalized`
- [ ] `foldInGuards`
- [ ] `getTableSize`
- [ ] `isOverride`
- [ ] `recoverModel`
- [ ] `~JumpBasic`

### Class: `JumpBasic2`
- [ ] `JumpBasic`
- [ ] `clear`
- [ ] `findUnnormalized`
- [ ] `initializeStart`
- [ ] `recoverModel`

### Class: `JumpBasicOverride`
- [ ] `buildLabels`
- [ ] `clear`
- [ ] `decode`
- [ ] `encode`
- [ ] `foldInGuards`
- [ ] `getTableSize`
- [ ] `isOverride`
- [ ] `recoverModel`
- [ ] `setAddresses`
- [ ] `setNorm`
- [ ] `setStartingValue`

### Class: `JumpAssisted`
- [ ] `JumpModel`
- [ ] `buildLabels`
- [ ] `clear`
- [ ] `findUnnormalized`
- [ ] `foldInGuards`
- [ ] `getTableSize`
- [ ] `isOverride`
- [ ] `recoverModel`
- [ ] `~JumpAssisted`

### Class: `JumpTable`
- [ ] *No public functions*

