# Rudra Alignment Checklist: 02 Syntax Tree

## File: `fspec.hh`
### Class: `ParamEntry`
- [ ] *No public functions*

### Class: `ParamEntryRange`
- [ ] *No public functions*

### Class: `SubsortPosition`
- [ ] `SubsortPosition`

### Class: `ParamTrial`
- [ ] *No public functions*

### Class: `ParamActive`
- [ ] `clear`
- [ ] `deleteUnusedTrials`
- [ ] `finishPass`
- [ ] `freePlaceholderSlot`
- [ ] `getMaxPass`
- [ ] `getNumPasses`
- [ ] `getNumTrials`
- [ ] `getNumUsed`
- [ ] `isFullyChecked`
- [ ] `isJoinReverse`
- [ ] `isRecoverSubcall`
- [ ] `joinTrial`
- [ ] `markFullyChecked`
- [ ] `markNeedsFinalCheck`
- [ ] `needsFinalCheck`
- [ ] `registerTrial`
- [ ] `setJoinReverse`
- [ ] `setMaxPass`
- [ ] `setPlaceholderSlot`
- [ ] `shrink`
- [ ] `sortFixedPosition`
- [ ] `sortTrials`
- [ ] `splitTrial`
- [ ] `testShrink`
- [ ] `whichTrial`

### Class: `FspecSpace`
- [ ] `decode`
- [ ] `encodeAttributes`
- [ ] `printRaw`

### Class: `EffectRecord`
- [ ] *No public functions*

### Class: `ParamList`
- [ ] *No public functions*

### Class: `ParamListStandard`
- [ ] `assignMap`
- [ ] `assumedExtension`
- [ ] `characterizeAsParam`
- [ ] `checkJoin`
- [ ] `checkSplit`
- [ ] `decode`
- [ ] `extractTiles`
- [ ] `fillinMap`
- [ ] `getBiggestContainedParam`
- [ ] `getMaxDelay`
- [ ] `getRangeList`
- [ ] `getType`
- [ ] `isAutoKilledByCall`
- [ ] `isBigEndian`
- [ ] `isThisBeforeRetPointer`
- [ ] `possibleParam`
- [ ] `possibleParamWithSlot`
- [ ] `unjustifiedContainer`
- [ ] `~ParamListStandard`

### Class: `ParamListStandardOut`
- [ ] `ParamListStandard`
- [ ] `assignMap`
- [ ] `decode`
- [ ] `fillinMap`
- [ ] `fillinMapFallback`
- [ ] `getType`
- [ ] `possibleParam`

### Class: `ParamListRegisterOut`
- [ ] `ParamListRegisterOut`
- [ ] `ParamListStandardOut`
- [ ] `assignMap`
- [ ] `getType`

### Class: `ParamListRegister`
- [ ] `ParamListStandard`
- [ ] `fillinMap`
- [ ] `getType`

### Class: `ParamListMerged`
- [ ] `LowlevelError`
- [ ] `ParamListMerged`
- [ ] `ParamListStandard`
- [ ] `assignMap`
- [ ] `fillinMap`
- [ ] `finalize`
- [ ] `foldIn`
- [ ] `getType`

### Class: `ProtoModel`
- [ ] *No public functions*

### Class: `UnknownProtoModel`
- [ ] `ProtoModel`
- [ ] `isUnknown`

### Class: `ScoreProtoModel`
- [ ] *No public functions*

### Class: `ProtoModelMerged`
- [ ] `ProtoModel`
- [ ] `decode`
- [ ] `foldIn`
- [ ] `isMerged`
- [ ] `numModels`
- [ ] `~ProtoModelMerged`

### Class: `ProtoParameter`
- [x] `new` ✅
- [x] `getAddress` ✅
- [x] `getSize` ✅
- [ ] `isHiddenReturn`
- [ ] `isIndirectStorage`
- [ ] `isNameLocked`
- [ ] `isNameUndefined`
- [ ] `isSizeTypeLocked`
- [x] `isThisPointer` ✅
- [x] `isTypeLocked` ✅
- [ ] `overrideSizeLockType`
- [ ] `resetSizeLockType`
- [ ] `setNameLock`
- [ ] `setThisPointer`
- [ ] `setTypeLock`
- [ ] `~ProtoParameter`

### Class: `ParameterBasic`
- [ ] `LowlevelError`
- [ ] `ParameterBasic`
- [ ] `getAddress`
- [ ] `getSize`
- [ ] `isHiddenReturn`
- [ ] `isIndirectStorage`
- [ ] `isNameLocked`
- [ ] `isNameUndefined`
- [ ] `isSizeTypeLocked`
- [ ] `isThisPointer`
- [ ] `isTypeLocked`
- [ ] `overrideSizeLockType`
- [ ] `resetSizeLockType`
- [ ] `setNameLock`
- [ ] `setThisPointer`
- [ ] `setTypeLock`

### Class: `ProtoStore`
- [ ] `clearAllInputs`
- [ ] `clearInput`
- [ ] `clearOutput`
- [ ] `decode`
- [ ] `encode`
- [ ] `getNumInputs`
- [ ] `~ProtoStore`

### Class: `ParameterSymbol`
- [ ] `getAddress`
- [ ] `getSize`
- [ ] `isHiddenReturn`
- [ ] `isIndirectStorage`
- [ ] `isNameLocked`
- [ ] `isNameUndefined`
- [ ] `isSizeTypeLocked`
- [ ] `isThisPointer`
- [ ] `isTypeLocked`
- [ ] `overrideSizeLockType`
- [ ] `resetSizeLockType`
- [ ] `setNameLock`
- [ ] `setThisPointer`
- [ ] `setTypeLock`

### Class: `ProtoStoreSymbol`
- [ ] `clearAllInputs`
- [ ] `clearInput`
- [ ] `clearOutput`
- [ ] `decode`
- [ ] `encode`
- [ ] `getNumInputs`
- [ ] `~ProtoStoreSymbol`

### Class: `ProtoStoreInternal`
- [ ] `clearAllInputs`
- [ ] `clearInput`
- [ ] `clearOutput`
- [ ] `decode`
- [ ] `encode`
- [ ] `getNumInputs`
- [ ] `~ProtoStoreInternal`

### Class: `FuncCallSpecs`
- [ ] *No public functions*

## File: `funcdata.hh`
### Class: `PcodeEmitFd`
- [ ] `setFuncdata`

### Class: `AncestorRealistic`
- [ ] *No public functions*

## File: `op.hh`
### Class: `IopSpace`
- [ ] `decode`
- [ ] `encodeAttributes`
- [ ] `printRaw`

### Class: `PcodeOp`
- [x] `new` ✅
- [x] `getOpcode` ✅
- [x] `getAddress` ✅
- [x] `getSeqNum` ✅
- [x] `numInput` ✅
- [x] `getIn` ✅
- [x] `getOut` ✅
- [x] `isDead` ✅
- [x] `isCall` ✅
- [x] `isBranch` ✅
- [x] `push` ✅

### Class: `PieceNode`
- [ ] `gatherPieces`
- [ ] `getSlot`
- [ ] `getTypeOffset`
- [ ] `isLeaf`

### Class: `PcodeOpBank`
- [x] `new` ✅
- [x] `create` ✅
- [ ] `begin`
- [ ] `beginAlive`
- [ ] `beginAll`
- [ ] `beginDead`
- [ ] `changeOpcode`
- [x] `clear` ✅
- [x] `destroy` ✅
- [ ] `destroyDead`
- [x] `empty` ✅
- [ ] `end`
- [ ] `endAlive`
- [ ] `endAll`
- [ ] `endDead`
- [x] `getUniqId` ✅
- [x] `findOp` ✅
- [ ] `insertAfterDead`
- [x] `markAlive` ✅
- [x] `markDead` ✅
- [ ] `markIncidentalCopy`
- [ ] `moveSequenceDead`
- [x] `setUniqId` ✅
- [ ] `~PcodeOpBank`

## File: `typeop.hh`
### Class: `TypeOp`
- [x] `getOpcode` ✅
- [x] `get_name` ✅
- [x] `get_flags` ✅
- [x] `printRaw` ✅
- [x] `push` ✅
- [x] `get_output_local` ✅
- [x] `get_input_local` ✅

### Class: `TypeOpBinary`
- [x] `TypeOp` ✅
- [x] `printRaw` ✅

### Class: `TypeOpUnary`
- [x] `TypeOp` ✅
- [x] `printRaw` ✅

### Class: `TypeOpFunc`
- [ ] `TypeOp`
- [ ] `printRaw`

### Class: `TypeOpCopy`
- [x] `printRaw` ✅
- [x] `push` ✅
- [x] `get_output_local` ✅
- [x] `get_input_local` ✅

### Class: `TypeOpLoad`
- [x] `printRaw` ✅
- [x] `push` ✅
- [x] `get_output_local` ✅

### Class: `TypeOpStore`
- [x] `printRaw` ✅
- [x] `push` ✅
- [x] `get_input_local` ✅

### Class: `TypeOpBranch`
- [x] `printRaw` ✅
- [x] `push` ✅

### Class: `TypeOpCbranch`
- [x] `printRaw` ✅
- [x] `push` ✅

### Class: `TypeOpBranchind`
- [x] `printRaw` ✅
- [ ] `push`

### Class: `TypeOpCall`
- [x] `printRaw` ✅
- [x] `push` ✅

### Class: `TypeOpCallind`
- [x] `printRaw` ✅
- [ ] `push`

### Class: `TypeOpCallother`
- [ ] `getOperatorName`
- [x] `printRaw` ✅
- [ ] `push`

### Class: `TypeOpReturn`
- [x] `printRaw` ✅
- [x] `push` ✅

### Class: `TypeOpEqual`
- [ ] `push`

### Class: `TypeOpNotEqual`
- [ ] `push`

### Class: `TypeOpIntSless`
- [ ] `push`

### Class: `TypeOpIntSlessEqual`
- [ ] `push`

### Class: `TypeOpIntLess`
- [ ] `push`

### Class: `TypeOpIntLessEqual`
- [ ] `push`

### Class: `TypeOpIntZext`
- [ ] `getOperatorName`
- [ ] `push`

### Class: `TypeOpIntSext`
- [ ] `getOperatorName`
- [ ] `push`

### Class: `TypeOpIntAdd`
- [ ] `propagateAddPointer`
- [x] `push` ✅
- [x] `printRaw` ✅
- [x] `get_output_local` ✅
- [x] `get_input_local` ✅

### Class: `TypeOpIntSub`
- [ ] `push`

### Class: `TypeOpIntCarry`
- [ ] `getOperatorName`
- [ ] `push`

### Class: `TypeOpIntScarry`
- [ ] `getOperatorName`
- [ ] `push`

### Class: `TypeOpIntSborrow`
- [ ] `getOperatorName`
- [ ] `push`

### Class: `TypeOpInt2Comp`
- [ ] `push`

### Class: `TypeOpIntNegate`
- [ ] `push`

### Class: `TypeOpIntXor`
- [ ] `push`

### Class: `TypeOpIntAnd`
- [ ] `push`

### Class: `TypeOpIntOr`
- [ ] `push`

### Class: `TypeOpIntLeft`
- [ ] `push`

### Class: `TypeOpIntRight`
- [ ] `push`

### Class: `TypeOpIntSright`
- [x] `printRaw` ✅
- [x] `push` ✅
- [x] `get_output_local` ✅
- [x] `get_input_local` ✅

### Class: `TypeOpIntMult`
- [ ] `push`

### Class: `TypeOpIntDiv`
- [ ] `push`

### Class: `TypeOpIntSdiv`
- [ ] `push`

### Class: `TypeOpIntRem`
- [ ] `push`

### Class: `TypeOpIntSrem`
- [ ] `push`

### Class: `TypeOpBoolNegate`
- [ ] `push`

### Class: `TypeOpBoolXor`
- [ ] `push`

### Class: `TypeOpBoolAnd`
- [ ] `push`

### Class: `TypeOpBoolOr`
- [ ] `push`

### Class: `TypeOpFloatEqual`
- [ ] `push`

### Class: `TypeOpFloatNotEqual`
- [ ] `push`

### Class: `TypeOpFloatLess`
- [ ] `push`

### Class: `TypeOpFloatLessEqual`
- [ ] `push`

### Class: `TypeOpFloatNan`
- [ ] `push`

### Class: `TypeOpFloatAdd`
- [ ] `push`

### Class: `TypeOpFloatDiv`
- [ ] `push`

### Class: `TypeOpFloatMult`
- [ ] `push`

### Class: `TypeOpFloatSub`
- [ ] `push`

### Class: `TypeOpFloatNeg`
- [ ] `push`

### Class: `TypeOpFloatAbs`
- [ ] `push`

### Class: `TypeOpFloatSqrt`
- [ ] `push`

### Class: `TypeOpFloatInt2Float`
- [ ] `preferredZextSize`
- [ ] `push`

### Class: `TypeOpFloatFloat2Float`
- [ ] `push`

### Class: `TypeOpFloatTrunc`
- [ ] `push`

### Class: `TypeOpFloatCeil`
- [ ] `push`

### Class: `TypeOpFloatFloor`
- [ ] `push`

### Class: `TypeOpFloatRound`
- [ ] `push`

### Class: `TypeOpMulti`
- [x] `printRaw` ✅
- [x] `push` ✅
- [x] `get_output_local` ✅
- [x] `get_input_local` ✅

### Class: `TypeOpIndirect`
- [x] `printRaw` ✅
- [x] `push` ✅
- [x] `get_output_local` ✅

### Class: `TypeOpPiece`
- [ ] `computeByteOffsetForComposite`
- [ ] `getOperatorName`
- [ ] `push`

### Class: `TypeOpSubpiece`
- [ ] `computeByteOffsetForComposite`
- [ ] `getOperatorName`
- [ ] `push`

### Class: `TypeOpCast`
- [ ] `printRaw`
- [ ] `push`

### Class: `TypeOpPtradd`
- [x] `printRaw` ✅
- [x] `push` ✅
- [x] `get_output_local` ✅
- [x] `get_input_local` ✅

### Class: `TypeOpPtrsub`
- [x] `printRaw` ✅
- [x] `push` ✅
- [x] `get_output_local` ✅

### Class: `TypeOpSegment`
- [x] `printRaw` ✅
- [ ] `push`

### Class: `TypeOpCpoolref`
- [x] `printRaw` ✅
- [ ] `push`

### Class: `TypeOpNew`
- [x] `printRaw` ✅
- [ ] `push`

### Class: `TypeOpInsert`
- [ ] `push`

### Class: `TypeOpExtract`
- [ ] `push`

### Class: `TypeOpPopcount`
- [ ] `push`

### Class: `TypeOpLzcount`
- [ ] `push`

## File: `variable.hh`
### Class: `VariablePiece`
- [ ] `getOffset`
- [ ] `getSize`
- [ ] `markExtendCoverDirty`
- [ ] `markIntersectionDirty`
- [ ] `mergeGroups`
- [ ] `numIntersection`
- [ ] `setHigh`
- [ ] `transferGroup`
- [ ] `updateCover`
- [ ] `updateIntersections`

### Class: `HighVariable`
- [ ] *No public functions*

### Class: `HighEdge`
- [ ] *No public functions*

### Class: `HighIntersectTest`
- [ ] `affectingOps`
- [ ] `clear`
- [ ] `intersection`
- [ ] `moveIntersectTests`
- [ ] `updateHigh`

## File: `varnode.hh`
### Class: `Varnode`
- [x] `new` ✅
- [x] `getAddress` ✅
- [x] `getSpace` ✅
- [x] `getOffset` ✅
- [x] `getSize` ✅
- [x] `getCreateIndex` ✅
- [x] `isConstant` ✅
- [x] `isInput` ✅
- [x] `isWritten` ✅
- [x] `isFree` ✅

### Class: `VarnodeBank`
- [x] `new` ✅
- [x] `create` ✅
- [x] `createUnique` ✅
- [x] `createConstant` ✅
- [x] `setInput` ✅
- [x] `setDef` ✅
- [ ] `beginDef`
- [ ] `beginLoc`
- [x] `clear` ✅
- [ ] `destroy`
- [ ] `endDef`
- [ ] `endLoc`
- [x] `getCreateIndex` ✅
- [x] `findFree` ✅
- [ ] `hasInputIntersection`
- [ ] `makeFree`
- [x] `numVarnodes` ✅
- [ ] `overlapLoc`
- [ ] `replace`
- [ ] `verifyIntegrity`
- [ ] `~VarnodeBank`

