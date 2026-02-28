# Rudra Alignment Checklist: 10 Other Modules

## File: `analyzesigs.hh`
### Class: `IfaceAnalyzeSigsCapability`
- [ ] `registerCommands`

### Class: `IfcSignatureSettings`
- [ ] `execute`

### Class: `IfcPrintSignatures`
- [ ] `execute`

### Class: `IfcSaveSignatures`
- [ ] `execute`

### Class: `IfcSaveAllSignatures`
- [ ] `execute`
- [ ] `iterationCallback`
- [ ] `~IfcSaveAllSignatures`

### Class: `IfcProduceSignatures`
- [ ] `iterationCallback`

## File: `bfd_arch.hh`
### Class: `BfdArchitectureCapability`
- [ ] `isFileMatch`
- [ ] `isXmlMatch`
- [ ] `~BfdArchitectureCapability`

### Class: `BfdArchitecture`
- [ ] `encode`
- [ ] `restoreXml`
- [ ] `~BfdArchitecture`

## File: `callgraph.hh`
### Class: `CallGraphEdge`
- [ ] *No public functions*

### Class: `CallGraphNode`
- [ ] *No public functions*

### Class: `CallGraph`
- [ ] `addEdge`
- [ ] `begin`
- [ ] `buildAllNodes`
- [ ] `buildEdges`
- [ ] `decoder`
- [ ] `deleteInEdge`
- [ ] `encode`
- [ ] `end`
- [ ] `initLeafWalk`

## File: `codedata.hh`
### Class: `IfaceCodeDataCapability`
- [ ] `registerCommands`

### Class: `CodeUnit`
- [ ] *No public functions*

### Class: `DisassemblyEngine`
- [ ] `addTarget`
- [ ] `disassemble`
- [ ] `dump`
- [ ] `init`

### Class: `TargetHit`
- [ ] `funcstart`

### Class: `CodeDataAnalysis`
- [ ] `addTarget`
- [ ] `addTargetHit`
- [ ] `checkErrantStart`
- [ ] `clearCodeUnits`
- [ ] `clearCrossRefs`
- [ ] `clearHitBy`
- [ ] `commitCodeVec`
- [ ] `disassembleBlock`
- [ ] `disassembleRange`
- [ ] `disassembleRangeList`
- [ ] `dumpCrossRefs`
- [ ] `dumpFunctionStarts`
- [ ] `dumpModelHits`
- [ ] `dumpTargetHits`
- [ ] `dumpUnlinked`
- [ ] `findFunctionStart`
- [ ] `findNotCodeUnits`
- [ ] `findOffCut`
- [ ] `findUnlinked`
- [ ] `getNumTargets`
- [ ] `init`
- [ ] `markCrossHits`
- [ ] `markFallthruHits`
- [ ] `processTaint`
- [ ] `pushTaintAddress`
- [ ] `repairJump`
- [ ] `resolveThunkHit`
- [ ] `runModel`
- [ ] `~CodeDataAnalysis`

### Class: `IfaceCodeDataCommand`
- [ ] `CodeDataAnalysis`
- [ ] `getModule`
- [ ] `setData`

### Class: `IfcCodeDataInit`
- [ ] `execute`

### Class: `IfcCodeDataTarget`
- [ ] `execute`

### Class: `IfcCodeDataRun`
- [ ] `execute`

### Class: `IfcCodeDataDumpModelHits`
- [ ] `execute`

### Class: `IfcCodeDataDumpCrossRefs`
- [ ] `execute`

### Class: `IfcCodeDataDumpStarts`
- [ ] `execute`

### Class: `IfcCodeDataDumpUnlinked`
- [ ] `execute`

### Class: `IfcCodeDataDumpTargetHits`
- [ ] `execute`

## File: `comment.hh`
### Class: `Comment`
- [ ] *No public functions*

### Class: `CommentDatabase`
- [ ] `addCommentNoDuplicate`
- [ ] `beginComment`
- [ ] `clear`
- [ ] `clearType`
- [ ] `decode`
- [ ] `deleteComment`
- [ ] `encode`
- [ ] `endComment`
- [ ] `~CommentDatabase`

### Class: `CommentDatabaseInternal`
- [ ] `addCommentNoDuplicate`
- [ ] `beginComment`
- [ ] `clear`
- [ ] `clearType`
- [ ] `decode`
- [ ] `deleteComment`
- [ ] `encode`
- [ ] `endComment`
- [ ] `~CommentDatabaseInternal`

### Class: `CommentSorter`
- [ ] *No public functions*

## File: `comment_ghidra.hh`
### Class: `CommentDatabaseGhidra`
- [ ] `LowlevelError`
- [ ] `addCommentNoDuplicate`
- [ ] `beginComment`
- [ ] `clear`
- [ ] `clearType`
- [ ] `decode`
- [ ] `deleteComment`
- [ ] `encode`
- [ ] `endComment`

## File: `compression.hh`
### Class: `Compress`
- [ ] `deflate`
- [ ] `input`
- [ ] `~Compress`

### Class: `Decompress`
- [ ] `inflate`
- [ ] `input`
- [ ] `isFinished`
- [ ] `~Decompress`

## File: `condexe.hh`
### Class: `ConditionalExecution`
- [ ] `execute`
- [ ] `trial`

### Class: `ActionConditionalExe`
- [ ] `Action`
- [ ] `ActionConditionalExe`
- [ ] `apply`

## File: `constseq.hh`
### Class: `ArraySequence`
- [ ] *No public functions*

### Class: `StringSequence`
- [ ] `transform`

### Class: `HeapSequence`
- [ ] `IndirectPair`
- [ ] `compareOutput`
- [ ] `isDuplicate`
- [ ] `markDuplicate`

### Class: `RuleStringCopy`
- [ ] `Rule`
- [ ] `RuleStringCopy`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleStringStore`
- [ ] `Rule`
- [ ] `RuleStringStore`
- [ ] `applyOp`
- [ ] `getOpList`

## File: `context.hh`
### Class: `Token`
- [ ] `getIndex`
- [ ] `getSize`
- [ ] `isBigEndian`
- [ ] `name`

### Class: `ParserContext`
- [ ] *No public functions*

### Class: `ParserWalker`
- [ ] `baseState`
- [ ] `getContextBits`
- [ ] `getContextBytes`
- [ ] `getInstructionBits`
- [ ] `getInstructionBytes`
- [ ] `getLength`
- [ ] `getOffset`
- [ ] `getOperand`
- [ ] `isState`
- [ ] `popOperand`
- [ ] `pushOperand`
- [ ] `setOutOfBandState`

### Class: `ParserWalkerChange`
- [ ] `ParserWalker`
- [ ] `calcCurrentLength`
- [ ] `setConstructor`
- [ ] `setCurrentLength`
- [ ] `setOffset`

## File: `cpool_ghidra.hh`
### Class: `ConstantPoolGhidra`
- [ ] `clear`
- [ ] `decode`
- [ ] `empty`
- [ ] `encode`

## File: `database_ghidra.hh`
### Class: `ScopeGhidra`
- [ ] `LowlevelError`
- [ ] `adjustCaches`
- [ ] `begin`
- [ ] `beginDynamic`
- [ ] `buildUndefinedName`
- [ ] `clear`
- [ ] `clearAttribute`
- [ ] `clearCategory`
- [ ] `clearUnlocked`
- [ ] `clearUnlockedCategory`
- [ ] `decode`
- [ ] `encode`
- [ ] `end`
- [ ] `endDynamic`
- [ ] `findByName`
- [ ] `getCategorySize`
- [ ] `isNameUsed`
- [ ] `lockDefaultProperties`
- [ ] `makeNameUnique`
- [ ] `printEntries`
- [ ] `removeSymbol`
- [ ] `removeSymbolMappings`
- [ ] `renameSymbol`
- [ ] `restrictScope`
- [ ] `retypeSymbol`
- [ ] `setAttribute`
- [ ] `setCategory`
- [ ] `setDisplayFormat`
- [ ] `~ScopeGhidra`

### Class: `ScopeGhidraNamespace`
- [ ] `ScopeInternal`
- [ ] `isNameUsed`

## File: `double.hh`
### Class: `SplitVarnode`
- [ ] `SplitVarnode`
- [ ] `adjacentOffsets`
- [ ] `applyRuleIn`
- [ ] `buildHiFromWhole`
- [ ] `buildLoFromWhole`
- [ ] `createJoinedWhole`
- [ ] `exceedsConstPrecision`
- [ ] `findCopies`
- [ ] `findCreateOutputWhole`
- [ ] `findCreateWhole`
- [ ] `getSize`
- [ ] `getTrueFalse`
- [ ] `getValue`
- [ ] `hasBothPieces`
- [ ] `inHandHi`
- [ ] `inHandHiOut`
- [ ] `inHandLo`
- [ ] `inHandLoNoHi`
- [ ] `inHandLoOut`
- [ ] `initAll`
- [ ] `initPartial`
- [ ] `isAddrTiedContiguous`
- [ ] `isConstant`
- [ ] `isWholeFeasible`
- [ ] `isWholePhiFeasible`
- [ ] `otherwiseEmpty`
- [ ] `prepareBoolOp`
- [ ] `prepareIndirectOp`
- [ ] `replaceCopyForce`
- [ ] `replaceIndirectOp`
- [ ] `testContiguousPointers`
- [ ] `verifyMultNegOne`
- [ ] `wholeList`

### Class: `AddForm`
- [ ] `applyRule`
- [ ] `verify`

### Class: `SubForm`
- [ ] `applyRule`
- [ ] `verify`

### Class: `LogicalForm`
- [ ] `applyRule`
- [ ] `verify`

### Class: `Equal1Form`
- [ ] `applyRule`

### Class: `Equal2Form`
- [ ] `applyRule`

### Class: `Equal3Form`
- [ ] `applyRule`
- [ ] `verify`

### Class: `LessThreeWay`
- [ ] `applyRule`

### Class: `LessConstForm`
- [ ] `applyRule`

### Class: `ShiftForm`
- [ ] `applyRuleLeft`
- [ ] `applyRuleRight`
- [ ] `verifyLeft`
- [ ] `verifyRight`

### Class: `MultForm`
- [ ] `applyRule`
- [ ] `verify`

### Class: `PhiForm`
- [ ] `applyRule`
- [ ] `verify`

### Class: `IndirectForm`
- [ ] `applyRule`
- [ ] `verify`

### Class: `CopyForceForm`
- [ ] `applyRule`
- [ ] `verify`

### Class: `RuleDoubleIn`
- [ ] `Rule`
- [ ] `RuleDoubleIn`
- [ ] `applyOp`
- [ ] `getOpList`
- [ ] `reset`

### Class: `RuleDoubleOut`
- [ ] `Rule`
- [ ] `RuleDoubleOut`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDoubleLoad`
- [ ] `Rule`
- [ ] `RuleDoubleLoad`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDoubleStore`
- [ ] `Rule`
- [ ] `RuleDoubleStore`
- [ ] `applyOp`
- [ ] `getOpList`
- [ ] `reassignIndirects`
- [ ] `testIndirectUse`

## File: `dynamic.hh`
### Class: `ToOpEdge`
- [ ] `getSlot`
- [ ] `hash`

### Class: `DynamicHash`
- [ ] `calcHash`
- [ ] `clear`
- [ ] `clearTotalPosition`
- [ ] `gatherFirstLevelVars`
- [ ] `gatherOpsAtAddress`
- [ ] `getComparable`
- [ ] `getHash`
- [ ] `getIsNotAttached`
- [ ] `getMethodFromHash`
- [ ] `getOpCodeFromHash`
- [ ] `getPositionFromHash`
- [ ] `getSlotFromHash`
- [ ] `getTotalFromHash`
- [ ] `uniqueHash`

## File: `expression.hh`
### Class: `BooleanMatch`
- [ ] *No public functions*

### Class: `BooleanExpressionMatch`
- [ ] `getFlip`
- [ ] `getMultiSlot`
- [ ] `verifyCondition`

### Class: `AdditiveEdge`
- [ ] `getSlot`

### Class: `TermOrder`
- [ ] `collect`
- [ ] `getSize`
- [ ] `sortTerms`

### Class: `AddExpression`
- [ ] `Term`
- [ ] `isEquivalent`

## File: `float.hh`
### Class: `FloatFormat`
- [ ] *No public functions*

## File: `ghidra_context.hh`
### Class: `ContextGhidra`
- [ ] `LowlevelError`
- [ ] `decode`
- [ ] `decodeFromSpec`
- [ ] `encode`
- [ ] `getContextSize`
- [ ] `registerVariable`
- [ ] `~ContextGhidra`

## File: `ghidra_translate.hh`
### Class: `GhidraTranslate`
- [ ] `LowlevelError`
- [ ] `getAllRegisters`
- [ ] `getExactRegisterName`
- [ ] `getRegisterName`
- [ ] `getUserOpNames`
- [ ] `initialize`
- [ ] `instructionLength`
- [ ] `oneInstruction`
- [ ] `printAssembly`

## File: `globalcontext.hh`
### Class: `ContextBitRange`
- [ ] `ContextBitRange`
- [ ] `getMask`
- [ ] `getShift`
- [ ] `getValue`
- [ ] `getWord`
- [ ] `setValue`

### Class: `ContextDatabase`
- [ ] `decode`
- [ ] `decodeFromSpec`
- [ ] `encode`
- [ ] `getContextSize`
- [ ] `getDefaultValue`
- [ ] `getTrackedValue`
- [ ] `getVariable`
- [ ] `registerVariable`
- [ ] `setContextChangePoint`
- [ ] `setContextRegion`
- [ ] `setVariable`
- [ ] `setVariableDefault`
- [ ] `~ContextDatabase`

### Class: `ContextCache`
- [ ] `allowSet`
- [ ] `getContext`
- [ ] `setContext`

## File: `grammar.hh`
### Class: `GrammarToken`
- [ ] *No public functions*

### Class: `TypeModifier`
- [ ] *No public functions*

### Class: `PointerModifier`
- [ ] `getType`
- [ ] `isValid`

### Class: `ArrayModifier`
- [ ] `getType`
- [ ] `isValid`

### Class: `FunctionModifier`
- [ ] `getInNames`
- [ ] `getInTypes`
- [ ] `getType`
- [ ] `isDotdotdot`
- [ ] `isValid`

### Class: `TypeDeclarator`
- [ ] `getPrototype`
- [ ] `hasProperty`
- [ ] `isValid`
- [ ] `numModifiers`

### Class: `CParse`
- [ ] *No public functions*

## File: `ifacedecomp.hh`
### Class: `IfaceDecompCapability`
- [ ] `registerCommands`

### Class: `IfaceDecompData`
- [ ] `IfaceDecompData`
- [ ] `abortFunction`
- [ ] `allocateCallGraph`
- [ ] `clearArchitecture`
- [ ] `followFlow`
- [ ] `readSymbol`
- [ ] `~IfaceDecompData`

### Class: `IfaceAssemblyEmit`
- [ ] `dump`

### Class: `IfaceDecompCommand`
- [ ] `IfaceDecompData`
- [ ] `getModule`
- [ ] `iterateFunctionsAddrOrder`
- [ ] `iterateFunctionsLeafOrder`
- [ ] `iterationCallback`
- [ ] `setData`

### Class: `IfcSource`
- [ ] `execute`

### Class: `IfcOption`
- [ ] `execute`

### Class: `IfcParseLine`
- [ ] `execute`

### Class: `IfcParseFile`
- [ ] `execute`

### Class: `IfcAdjustVma`
- [ ] `execute`

### Class: `IfcFuncload`
- [ ] `execute`

### Class: `IfcAddrrangeLoad`
- [ ] `execute`

### Class: `IfcCleararch`
- [ ] `execute`

### Class: `IfcReadSymbols`
- [ ] `execute`

### Class: `IfcMapaddress`
- [ ] `execute`

### Class: `IfcMaphash`
- [ ] `execute`

### Class: `IfcMapParam`
- [ ] `execute`

### Class: `IfcMapReturn`
- [ ] `execute`

### Class: `IfcMapfunction`
- [ ] `execute`

### Class: `IfcMapexternalref`
- [ ] `execute`

### Class: `IfcMaplabel`
- [ ] `execute`

### Class: `IfcMapconvert`
- [ ] `execute`

### Class: `IfcMapunionfacet`
- [ ] `execute`

### Class: `IfcPrintdisasm`
- [ ] `execute`

### Class: `IfcDump`
- [ ] `execute`

### Class: `IfcDumpbinary`
- [ ] `execute`

### Class: `IfcDecompile`
- [ ] `execute`

### Class: `IfcPrintLanguage`
- [ ] `execute`

### Class: `IfcPrintCXml`
- [ ] `execute`

### Class: `IfcPrintCFlat`
- [ ] `execute`

### Class: `IfcPrintCStruct`
- [ ] `execute`

### Class: `IfcPrintCGlobals`
- [ ] `execute`

### Class: `IfcPrintCTypes`
- [ ] `execute`

### Class: `IfcProduceC`
- [ ] `execute`
- [ ] `iterationCallback`

### Class: `IfcProducePrototypes`
- [ ] `execute`
- [ ] `iterationCallback`

### Class: `IfcListaction`
- [ ] `execute`

### Class: `IfcListOverride`
- [ ] `execute`

### Class: `IfcListprototypes`
- [ ] `execute`

### Class: `IfcSetcontextrange`
- [ ] `execute`

### Class: `IfcSettrackedrange`
- [ ] `execute`

### Class: `IfcBreakstart`
- [ ] `execute`

### Class: `IfcBreakaction`
- [ ] `execute`

### Class: `IfcPrintTree`
- [ ] `execute`

### Class: `IfcPrintBlocktree`
- [ ] `execute`

### Class: `IfcPrintSpaces`
- [ ] `execute`

### Class: `IfcPrintHigh`
- [ ] `execute`

### Class: `IfcPrintParamMeasures`
- [ ] `execute`

### Class: `IfcRename`
- [ ] `execute`

### Class: `IfcRetype`
- [ ] `execute`

### Class: `IfcRemove`
- [ ] `execute`

### Class: `IfcIsolate`
- [ ] `execute`

### Class: `IfcPrintVarnode`
- [ ] `execute`

### Class: `IfcPrintCover`
- [ ] `execute`

### Class: `IfcVarnodehighCover`
- [ ] `execute`

### Class: `IfcPrintExtrapop`
- [ ] `execute`

### Class: `IfcVarnodeCover`
- [ ] `execute`

### Class: `IfcNameVarnode`
- [ ] `execute`

### Class: `IfcTypeVarnode`
- [ ] `execute`

### Class: `IfcForceFormat`
- [ ] `execute`

### Class: `IfcForceDatatypeFormat`
- [ ] `execute`

### Class: `IfcForcegoto`
- [ ] `execute`

### Class: `IfcProtooverride`
- [ ] `execute`

### Class: `IfcJumpOverride`
- [ ] `execute`

### Class: `IfcFlowOverride`
- [ ] `execute`

### Class: `IfcDeadcodedelay`
- [ ] `execute`

### Class: `IfcGlobalAdd`
- [ ] `execute`

### Class: `IfcGlobalRemove`
- [ ] `execute`

### Class: `IfcGlobalify`
- [ ] `execute`

### Class: `IfcGlobalRegisters`
- [ ] `execute`

### Class: `IfcPrintInputs`
- [ ] `checkRestore`
- [ ] `execute`
- [ ] `findRestore`
- [ ] `nonTrivialUse`
- [ ] `print`

### Class: `IfcPrintInputsAll`
- [ ] `execute`
- [ ] `iterationCallback`

### Class: `IfcLockPrototype`
- [ ] `execute`

### Class: `IfcUnlockPrototype`
- [ ] `execute`

### Class: `IfcPrintLocalrange`
- [ ] `execute`

### Class: `IfcPrintMap`
- [ ] `execute`

### Class: `IfcContinue`
- [ ] `execute`

### Class: `IfcPrintRaw`
- [ ] `execute`

### Class: `IfcGraphDataflow`
- [ ] `execute`

### Class: `IfcGraphControlflow`
- [ ] `execute`

### Class: `IfcGraphDom`
- [ ] `execute`

### Class: `IfcCommentInstr`
- [ ] `execute`

### Class: `IfcDuplicateHash`
- [ ] `check`
- [ ] `execute`
- [ ] `iterationCallback`

### Class: `IfcCallGraphDump`
- [ ] `execute`

### Class: `IfcCallGraphBuild`
- [ ] `execute`
- [ ] `iterationCallback`

### Class: `IfcCallGraphLoad`
- [ ] `execute`

### Class: `IfcCallGraphList`
- [ ] `execute`
- [ ] `iterationCallback`

### Class: `IfcComment`
- [ ] `execute`

### Class: `IfcCallFixup`
- [ ] `execute`

### Class: `IfcCallOtherFixup`
- [ ] `execute`

### Class: `IfcFixupApply`
- [ ] `execute`

### Class: `IfcCountPcode`
- [ ] `execute`

### Class: `IfcPrintActionstats`
- [ ] `execute`

### Class: `IfcResetActionstats`
- [ ] `execute`

### Class: `IfcVolatile`
- [ ] `execute`

### Class: `IfcReadonly`
- [ ] `execute`

### Class: `IfcPointerSetting`
- [ ] `execute`

### Class: `IfcPreferSplit`
- [ ] `execute`

### Class: `IfcStructureBlocks`
- [ ] `execute`

### Class: `IfcAnalyzeRange`
- [ ] `execute`

### Class: `IfcLoadTestFile`
- [ ] `execute`

### Class: `IfcListTestCommands`
- [ ] `execute`

### Class: `IfcExecuteTestCommand`
- [ ] `execute`

### Class: `IfcParseRule`
- [ ] `execute`

### Class: `IfcExperimentalRules`
- [ ] `execute`

### Class: `IfcDebugAction`
- [ ] `execute`

### Class: `IfcTraceBreak`
- [ ] `execute`

### Class: `IfcTraceAddress`
- [ ] `execute`

### Class: `IfcTraceEnable`
- [ ] `execute`

### Class: `IfcTraceDisable`
- [ ] `execute`

### Class: `IfcTraceClear`
- [ ] `execute`

### Class: `IfcTraceList`
- [ ] `execute`

### Class: `IfcBreakjump`
- [ ] `execute`

### Class: `IfcTracePropagation`
- [ ] `execute`

## File: `ifaceterm.hh`
### Class: `IfaceTerm`
- [ ] `isStreamFinished`
- [ ] `popScript`
- [ ] `pushScript`
- [ ] `~IfaceTerm`

## File: `inject_ghidra.hh`
### Class: `InjectContextGhidra`
- [ ] `encode`

### Class: `InjectPayloadGhidra`
- [ ] `InjectPayload`
- [ ] `decode`
- [ ] `getSource`
- [ ] `inject`
- [ ] `printTemplate`

### Class: `InjectCallfixupGhidra`
- [ ] `decode`

### Class: `InjectCallotherGhidra`
- [ ] `decode`

### Class: `ExecutablePcodeGhidra`
- [ ] `decode`
- [ ] `inject`
- [ ] `printTemplate`

### Class: `PcodeInjectLibraryGhidra`
- [ ] `manualCallFixup`

## File: `inject_sleigh.hh`
### Class: `InjectContextSleigh`
- [ ] `InjectContextSleigh`
- [ ] `encode`
- [ ] `~InjectContextSleigh`

### Class: `InjectPayloadSleigh`
- [ ] `decode`
- [ ] `getSource`
- [ ] `inject`
- [ ] `printTemplate`
- [ ] `~InjectPayloadSleigh`

### Class: `InjectPayloadCallfixup`
- [ ] `decode`

### Class: `InjectPayloadCallother`
- [ ] `decode`

### Class: `ExecutablePcodeSleigh`
- [ ] `decode`
- [ ] `inject`
- [ ] `printTemplate`
- [ ] `~ExecutablePcodeSleigh`

### Class: `InjectPayloadDynamic`
- [ ] `LowlevelError`
- [ ] `decode`
- [ ] `decodeEntry`
- [ ] `getSource`
- [ ] `inject`
- [ ] `printTemplate`
- [ ] `~InjectPayloadDynamic`

### Class: `PcodeInjectLibrarySleigh`
- [ ] `decodeDebug`
- [ ] `manualCallFixup`

## File: `interface.hh`
### Class: `RemoteSocket`
- [ ] `close`
- [ ] `isSocketOpen`
- [ ] `open`
- [ ] `~RemoteSocket`

### Class: `IfaceData`
- [ ] `~IfaceData`

### Class: `IfaceCommand`
- [ ] `addWord`
- [ ] `addWords`
- [ ] `commandString`
- [ ] `compare`
- [ ] `execute`
- [ ] `getModule`
- [ ] `numWords`
- [ ] `removeWord`
- [ ] `setData`
- [ ] `~IfaceCommand`

### Class: `IfaceCommandDummy`
- [ ] `execute`
- [ ] `getModule`
- [ ] `setData`

### Class: `IfaceCapability`
- [ ] `initialize`
- [ ] `registerAllCommands`
- [ ] `registerCommands`

### Class: `IfaceStatus`
- [ ] `IfaceStatus`
- [ ] `evaluateError`
- [ ] `getHistory`
- [ ] `getHistorySize`
- [ ] `getNumInputStreamSize`
- [ ] `isInError`
- [ ] `isStreamFinished`
- [ ] `popScript`
- [ ] `pushScript`
- [ ] `reset`
- [ ] `runCommand`
- [ ] `setErrorIsDone`
- [ ] `wordsToString`
- [ ] `writePrompt`
- [ ] `~IfaceStatus`

### Class: `IfaceBaseCommand`
- [ ] `getModule`
- [ ] `setData`

### Class: `IfcQuit`
- [ ] `execute`

### Class: `IfcHistory`
- [ ] `execute`

### Class: `IfcOpenfile`
- [ ] `execute`

### Class: `IfcOpenfileAppend`
- [ ] `execute`

### Class: `IfcClosefile`
- [ ] `execute`

### Class: `IfcEcho`
- [ ] `execute`

## File: `loadimage.hh`
### Class: `LoadImage`
- [ ] `adjustVma`
- [ ] `closeSectionInfo`
- [ ] `closeSymbols`
- [ ] `getArchType`
- [ ] `getNextSection`
- [ ] `getNextSymbol`
- [ ] `getReadonly`
- [ ] `loadFill`
- [ ] `openSectionInfo`
- [ ] `openSymbols`
- [ ] `~LoadImage`

### Class: `RawLoadImage`
- [ ] `adjustVma`
- [ ] `attachToSpace`
- [ ] `getArchType`
- [ ] `loadFill`
- [ ] `open`
- [ ] `~RawLoadImage`

## File: `loadimage_bfd.hh`
### Class: `LoadImageBfd`
- [ ] `LowlevelError`
- [ ] `adjustVma`
- [ ] `attachToSpace`
- [ ] `close`
- [ ] `closeSectionInfo`
- [ ] `closeSymbols`
- [ ] `getArchType`
- [ ] `getImportTable`
- [ ] `getNextSection`
- [ ] `getNextSymbol`
- [ ] `getReadonly`
- [ ] `loadFill`
- [ ] `open`
- [ ] `openSectionInfo`
- [ ] `openSymbols`
- [ ] `~LoadImageBfd`

## File: `loadimage_ghidra.hh`
### Class: `LoadImageGhidra`
- [ ] `adjustVma`
- [ ] `close`
- [ ] `getArchType`
- [ ] `loadFill`
- [ ] `open`
- [ ] `~LoadImage`

## File: `loadimage_xml.hh`
### Class: `LoadImageXml`
- [ ] `adjustVma`
- [ ] `clear`
- [ ] `encode`
- [ ] `getArchType`
- [ ] `getNextSymbol`
- [ ] `getReadonly`
- [ ] `loadFill`
- [ ] `open`
- [ ] `openSymbols`
- [ ] `~LoadImageXml`

## File: `memstate.hh`
### Class: `MemoryBank`
- [ ] `constructValue`
- [ ] `deconstructValue`
- [ ] `getChunk`
- [ ] `getPageSize`
- [ ] `getValue`
- [ ] `getWordSize`
- [ ] `setChunk`
- [ ] `setValue`
- [ ] `~MemoryBank`

### Class: `MemoryImage`
- [ ] *No public functions*

### Class: `MemoryPageOverlay`
- [ ] `~MemoryPageOverlay`

### Class: `MemoryHashOverlay`
- [ ] *No public functions*

### Class: `MemoryState`
- [ ] `getChunk`
- [ ] `getValue`
- [ ] `setChunk`
- [ ] `setMemoryBank`
- [ ] `setValue`
- [ ] `~MemoryState`

## File: `modelrules.hh`
### Class: `Primitive`
- [ ] `Primitive`

### Class: `DatatypeFilter`
- [ ] `decode`
- [ ] `filter`
- [ ] `~DatatypeFilter`

### Class: `SizeRestrictedFilter`
- [ ] `SizeRestrictedFilter`
- [ ] `decode`
- [ ] `filter`
- [ ] `filterOnSize`

### Class: `MetaTypeFilter`
- [ ] `MetaTypeFilter`
- [ ] `filter`

### Class: `HomogeneousAggregate`
- [ ] `HomogeneousAggregate`
- [ ] `decode`
- [ ] `filter`

### Class: `QualifierFilter`
- [ ] `decode`
- [ ] `filter`
- [ ] `~QualifierFilter`

### Class: `AndFilter`
- [ ] `decode`
- [ ] `filter`
- [ ] `~AndFilter`

### Class: `VarargsFilter`
- [ ] `VarargsFilter`
- [ ] `decode`
- [ ] `filter`

### Class: `PositionMatchFilter`
- [ ] `PositionMatchFilter`
- [ ] `decode`
- [ ] `filter`

### Class: `DatatypeMatchFilter`
- [ ] `decode`
- [ ] `filter`
- [ ] `~DatatypeMatchFilter`

### Class: `AssignAction`
- [ ] *No public functions*

### Class: `GotoStack`
- [ ] `GotoStack`
- [ ] `decode`
- [ ] `fillinOutputMap`

### Class: `ConvertToPointer`
- [ ] `ConvertToPointer`
- [ ] `decode`

### Class: `MultiSlotAssign`
- [ ] `MultiSlotAssign`
- [ ] `decode`
- [ ] `fillinOutputMap`

### Class: `MultiMemberAssign`
- [ ] `MultiMemberAssign`
- [ ] `decode`
- [ ] `fillinOutputMap`

### Class: `MultiSlotDualAssign`
- [ ] `decode`
- [ ] `fillinOutputMap`

### Class: `ConsumeAs`
- [ ] `ConsumeAs`
- [ ] `decode`
- [ ] `fillinOutputMap`

### Class: `HiddenReturnAssign`
- [ ] `HiddenReturnAssign`
- [ ] `decode`

### Class: `ConsumeExtra`
- [ ] `ConsumeExtra`
- [ ] `decode`

### Class: `ExtraStack`
- [ ] `ExtraStack`
- [ ] `decode`

### Class: `ConsumeRemaining`
- [ ] `ConsumeRemaining`
- [ ] `decode`

### Class: `ModelRule`
- [ ] `ModelRule`
- [ ] `canAffectFillinOutput`
- [ ] `decode`
- [ ] `fillinOutputMap`
- [ ] `~ModelRule`

## File: `opbehavior.hh`
### Class: `OpBehavior`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`
- [ ] `evaluateTernary`
- [ ] `evaluateUnary`
- [ ] `getOpcode`
- [ ] `isSpecial`
- [ ] `isUnary`
- [ ] `recoverInputBinary`
- [ ] `recoverInputUnary`
- [ ] `registerInstructions`
- [ ] `~OpBehavior`

### Class: `OpBehaviorCopy`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`
- [ ] `recoverInputUnary`

### Class: `OpBehaviorEqual`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorNotEqual`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntSless`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntSlessEqual`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntLess`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntLessEqual`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntZext`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`
- [ ] `recoverInputUnary`

### Class: `OpBehaviorIntSext`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`
- [ ] `recoverInputUnary`

### Class: `OpBehaviorIntAdd`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`
- [ ] `recoverInputBinary`

### Class: `OpBehaviorIntSub`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`
- [ ] `recoverInputBinary`

### Class: `OpBehaviorIntCarry`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntScarry`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntSborrow`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorInt2Comp`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`
- [ ] `recoverInputUnary`

### Class: `OpBehaviorIntNegate`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`
- [ ] `recoverInputUnary`

### Class: `OpBehaviorIntXor`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntAnd`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntOr`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntLeft`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`
- [ ] `recoverInputBinary`

### Class: `OpBehaviorIntRight`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`
- [ ] `recoverInputBinary`

### Class: `OpBehaviorIntSright`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`
- [ ] `recoverInputBinary`

### Class: `OpBehaviorIntMult`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntDiv`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntSdiv`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntRem`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorIntSrem`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorBoolNegate`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorBoolXor`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorBoolAnd`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorBoolOr`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorFloatEqual`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorFloatNotEqual`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorFloatLess`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorFloatLessEqual`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorFloatNan`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorFloatAdd`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorFloatDiv`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorFloatMult`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorFloatSub`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorFloatNeg`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorFloatAbs`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorFloatSqrt`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorFloatInt2Float`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorFloatFloat2Float`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorFloatTrunc`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorFloatCeil`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorFloatFloor`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorFloatRound`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorPiece`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorSubpiece`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorPtradd`
- [ ] `OpBehavior`
- [ ] `evaluateTernary`

### Class: `OpBehaviorPtrsub`
- [ ] `OpBehavior`
- [ ] `evaluateBinary`

### Class: `OpBehaviorPopcount`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

### Class: `OpBehaviorLzcount`
- [ ] `OpBehavior`
- [ ] `evaluateUnary`

## File: `override.hh`
### Class: `Override`
- [ ] *No public functions*

## File: `paramid.hh`
### Class: `ParamMeasure`
- [ ] *No public functions*

### Class: `ParamIDAnalysis`
- [ ] `encode`
- [ ] `savePretty`

## File: `partmap.hh`
### Class: `partmap`
- [ ] *No public functions*

## File: `pcodecompile.hh`
### Class: `Location`
- [ ] `format`
- [ ] `getFilename`
- [ ] `getLineno`

### Class: `ExprTree`
- [ ] `setOutput`

### Class: `PcodeCompile`
- [ ] `appendOp`
- [ ] `fillinZero`
- [ ] `force_size`
- [ ] `matchSize`
- [ ] `newLocalDefinition`
- [ ] `propagateSize`
- [ ] `reportError`
- [ ] `reportWarning`
- [ ] `resetLabelCount`
- [ ] `setConstantSpace`
- [ ] `setDefaultSpace`
- [ ] `setEnforceLocalKey`
- [ ] `setUniqueSpace`
- [ ] `~PcodeCompile`

## File: `pcodeinject.hh`
### Class: `InjectParameter`
- [ ] `getIndex`
- [ ] `getSize`

### Class: `InjectContext`
- [ ] `clear`
- [ ] `encode`
- [ ] `~InjectContext`

### Class: `InjectPayload`
- [ ] *No public functions*

### Class: `ExecutablePcode`
- [ ] `evaluate`
- [ ] `getSource`
- [ ] `~ExecutablePcode`

### Class: `PcodeInjectLibrary`
- [ ] `decodeDebug`
- [ ] `decodeInject`
- [ ] `getCallFixupName`
- [ ] `getCallMechanismName`
- [ ] `getCallOtherTarget`
- [ ] `getPayloadId`
- [ ] `getUniqueBase`
- [ ] `manualCallFixup`
- [ ] `~PcodeInjectLibrary`

## File: `pcodeparse.hh`
### Class: `PcodeLexer`
- [ ] *No public functions*

### Class: `PcodeSnippet`
- [ ] `addOperand`
- [ ] `clear`
- [ ] `getErrorMessage`
- [ ] `getUniqueBase`
- [ ] `hasErrors`
- [ ] `lex`
- [ ] `parseStream`
- [ ] `reportError`
- [ ] `reportWarning`
- [ ] `setResult`
- [ ] `setUniqueBase`
- [ ] `~PcodeSnippet`

## File: `prefersplit.hh`
### Class: `PreferSplitManager`
- [ ] *No public functions*

## File: `rangemap.hh`
### Class: `rangemap`
- [ ] *No public functions*

### Class: `PartIterator`
- [ ] `PartIterator`
- [ ] `getValueIter`
- [ ] `orig`

## File: `rangeutil.hh`
### Class: `CircleRange`
- [ ] `CircleRange`
- [ ] `circleUnion`
- [ ] `contains`
- [ ] `getEnd`
- [ ] `getMask`
- [ ] `getMax`
- [ ] `getMaxInfo`
- [ ] `getMin`
- [ ] `getNext`
- [ ] `getSize`
- [ ] `getStep`
- [ ] `intersect`
- [ ] `invert`
- [ ] `isEmpty`
- [ ] `isFull`
- [ ] `isSingle`
- [ ] `minimalContainer`
- [ ] `printRaw`
- [ ] `pullBackBinary`
- [ ] `pullBackUnary`
- [ ] `pushForwardBinary`
- [ ] `pushForwardUnary`
- [ ] `setFull`
- [ ] `setNZMask`
- [ ] `setRange`
- [ ] `setStride`
- [ ] `translate2Op`
- [ ] `widen`

### Class: `ValueSet`
- [ ] `Equation`

### Class: `Partition`
- [ ] *No public functions*

### Class: `ValueSetRead`
- [ ] `compute`
- [ ] `getTypeCode`
- [ ] `isLeftStable`
- [ ] `isRightStable`
- [ ] `printRaw`

### Class: `Widener`
- [ ] `checkFreeze`
- [ ] `determineIterationReset`
- [ ] `doWidening`
- [ ] `~Widener`

### Class: `WidenerFull`
- [ ] `WidenerFull`
- [ ] `checkFreeze`
- [ ] `determineIterationReset`
- [ ] `doWidening`

### Class: `WidenerNone`
- [ ] `checkFreeze`
- [ ] `determineIterationReset`
- [ ] `doWidening`

### Class: `ValueSetSolver`
- [ ] *No public functions*

## File: `raw_arch.hh`
### Class: `RawBinaryArchitectureCapability`
- [ ] `isFileMatch`
- [ ] `isXmlMatch`
- [ ] `~RawBinaryArchitectureCapability`

### Class: `RawBinaryArchitecture`
- [ ] `encode`
- [ ] `restoreXml`
- [ ] `~RawBinaryArchitecture`

## File: `semantics.hh`
### Class: `ConstTpl`
- [ ] *No public functions*

### Class: `VarnodeTpl`
- [ ] `adjustTruncation`
- [ ] `changeHandleIndex`
- [ ] `decode`
- [ ] `encode`
- [ ] `isDynamic`
- [ ] `isLocalTemp`
- [ ] `isRelative`
- [ ] `isUnnamed`
- [ ] `isZeroSize`
- [ ] `setOffset`
- [ ] `setRelative`
- [ ] `setSize`
- [ ] `setUnnamed`
- [ ] `space`
- [ ] `transfer`

### Class: `HandleTpl`
- [ ] `changeHandleIndex`
- [ ] `decode`
- [ ] `encode`
- [ ] `fix`
- [ ] `setPtrOffset`
- [ ] `setPtrSize`
- [ ] `setSize`
- [ ] `setTempOffset`

### Class: `OpTpl`
- [ ] `addInput`
- [ ] `changeHandleIndex`
- [ ] `clearOutput`
- [ ] `decode`
- [ ] `encode`
- [ ] `getOpcode`
- [ ] `isZeroSize`
- [ ] `numInput`
- [ ] `removeInput`
- [ ] `setInput`
- [ ] `setOpcode`
- [ ] `setOutput`

### Class: `ConstructTpl`
- [ ] `addOp`
- [ ] `addOpList`
- [ ] `buildOnly`
- [ ] `changeHandleIndex`
- [ ] `decode`
- [ ] `delaySlot`
- [ ] `deleteOps`
- [ ] `encode`
- [ ] `fillinBuild`
- [ ] `numLabels`
- [ ] `setInput`
- [ ] `setOutput`
- [ ] `setResult`

### Class: `PcodeBuilder`
- [ ] `appendBuild`
- [ ] `appendCrossBuild`
- [ ] `build`
- [ ] `delaySlot`
- [ ] `getLabelBase`
- [ ] `setLabel`
- [ ] `~PcodeBuilder`

## File: `signature.hh`
### Class: `Signature`
- [ ] `compare`
- [ ] `comparePtr`
- [ ] `decode`
- [ ] `encode`
- [ ] `getHash`
- [ ] `print`
- [ ] `printOrigin`
- [ ] `~Signature`

### Class: `BlockSignatureEntry`
- [ ] `flip`
- [ ] `getHash`
- [ ] `hashIn`
- [ ] `localHash`

### Class: `VarnodeSignature`
- [ ] `Signature`
- [ ] `encode`
- [ ] `printOrigin`

### Class: `BlockSignature`
- [ ] `Signature`
- [ ] `encode`
- [ ] `printOrigin`

### Class: `CopySignature`
- [ ] `Signature`
- [ ] `encode`
- [ ] `printOrigin`

### Class: `SigManager`
- [ ] `clear`
- [ ] `encode`
- [ ] `generate`
- [ ] `getOverallHash`
- [ ] `getSettings`
- [ ] `getSignatureVector`
- [ ] `initializeFromStream`
- [ ] `numSignatures`
- [ ] `print`
- [ ] `setCurrentFunction`
- [ ] `setSettings`
- [ ] `sortByHash`
- [ ] `~SigManager`

### Class: `GraphSigManager`
- [ ] *No public functions*

## File: `signature_ghidra.hh`
### Class: `GhidraSignatureCapability`
- [ ] `initialize`

### Class: `SignaturesAt`
- [ ] `rawAction`

### Class: `GetSignatureSettings`
- [ ] `rawAction`

### Class: `SetSignatureSettings`
- [ ] `rawAction`

## File: `slaformat.hh`
### Class: `FormatEncode`
- [ ] `flush`

### Class: `FormatDecode`
- [ ] `ingestStream`
- [ ] `~FormatDecode`

## File: `sleigh_arch.hh`
### Class: `CompilerTag`
- [ ] `decode`

### Class: `LanguageDescription`
- [ ] `decode`
- [ ] `getSize`
- [ ] `isBigEndian`
- [ ] `isDeprecated`
- [ ] `numCompilers`
- [ ] `numTruncations`

### Class: `SleighArchitecture`
- [ ] `encodeHeader`
- [ ] `getDescription`
- [ ] `normalizeArchitecture`
- [ ] `normalizeEndian`
- [ ] `normalizeProcessor`
- [ ] `normalizeSize`
- [ ] `printMessage`
- [ ] `restoreXmlHeader`
- [ ] `scanForSleighDirectories`
- [ ] `shutdown`
- [ ] `~SleighArchitecture`

## File: `slgh_compile.hh`
### Class: `SectionVector`
- [ ] `append`
- [ ] `getMainPair`
- [ ] `getMaxId`
- [ ] `getNamedPair`
- [ ] `setNextIndex`

### Class: `WithBlock`
- [ ] `set`
- [ ] `~WithBlock`

### Class: `ConsistencyChecker`
- [ ] `OptimizeRecord`
- [ ] `copyFromExcludingSize`
- [ ] `update`
- [ ] `updateCombine`
- [ ] `updateExport`
- [ ] `updateRead`
- [ ] `updateWrite`

### Class: `UniqueState`
- [ ] `begin`
- [ ] `clear`
- [ ] `end`
- [ ] `getDefinitions`
- [ ] `set`

### Class: `MacroBuilder`
- [ ] `PcodeBuilder`
- [ ] `appendBuild`
- [ ] `appendCrossBuild`
- [ ] `delaySlot`
- [ ] `hasError`
- [ ] `setLabel`
- [ ] `setMacroOp`
- [ ] `~MacroBuilder`

### Class: `SleighPcode`
- [ ] `PcodeCompile`
- [ ] `setCompiler`

### Class: `SleighCompile`
- [ ] *No public functions*

## File: `slghpatexpress.hh`
### Class: `TokenPattern`
- [ ] `TokenPattern`
- [ ] `alwaysFalse`
- [ ] `alwaysInstructionTrue`
- [ ] `alwaysTrue`
- [ ] `commonSubPattern`
- [ ] `doAnd`
- [ ] `doCat`
- [ ] `doOr`
- [ ] `getLeftEllipsis`
- [ ] `getMinimumLength`
- [ ] `getRightEllipsis`
- [ ] `setLeftEllipsis`
- [ ] `setRightEllipsis`

### Class: `PatternExpression`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `getMinMax`
- [ ] `getSubValue`
- [ ] `getValue`
- [ ] `layClaim`
- [ ] `listValues`
- [ ] `release`

### Class: `PatternValue`
- [ ] `genPattern`
- [ ] `getMinMax`
- [ ] `getSubValue`
- [ ] `listValues`
- [ ] `maxValue`
- [ ] `minValue`

### Class: `TokenField`
- [ ] `TokenField`
- [ ] `TokenPattern`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `genPattern`
- [ ] `getValue`
- [ ] `maxValue`
- [ ] `minValue`
- [ ] `zero_extend`

### Class: `ContextField`
- [ ] `ContextField`
- [ ] `TokenPattern`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `genPattern`
- [ ] `getEndBit`
- [ ] `getSignBit`
- [ ] `getStartBit`
- [ ] `getValue`
- [ ] `maxValue`
- [ ] `minValue`
- [ ] `zero_extend`

### Class: `ConstantValue`
- [ ] `ConstantValue`
- [ ] `TokenPattern`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `genPattern`
- [ ] `getValue`
- [ ] `maxValue`
- [ ] `minValue`

### Class: `StartInstructionValue`
- [ ] `TokenPattern`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `genPattern`
- [ ] `getValue`
- [ ] `maxValue`
- [ ] `minValue`

### Class: `EndInstructionValue`
- [ ] `TokenPattern`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `genPattern`
- [ ] `getValue`
- [ ] `maxValue`
- [ ] `minValue`

### Class: `Next2InstructionValue`
- [ ] `TokenPattern`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `genPattern`
- [ ] `getValue`
- [ ] `maxValue`
- [ ] `minValue`

### Class: `OperandValue`
- [ ] `OperandValue`
- [ ] `changeIndex`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `genPattern`
- [ ] `getSubValue`
- [ ] `getValue`
- [ ] `isConstructorRelative`
- [ ] `maxValue`
- [ ] `minValue`

### Class: `BinaryExpression`
- [ ] `BinaryExpression`
- [ ] `TokenPattern`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `getMinMax`
- [ ] `listValues`

### Class: `UnaryExpression`
- [ ] `TokenPattern`
- [ ] `UnaryExpression`
- [ ] `decode`
- [ ] `encode`
- [ ] `genMinPattern`
- [ ] `getMinMax`
- [ ] `listValues`

### Class: `PlusExpression`
- [ ] `PlusExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `SubExpression`
- [ ] `SubExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `MultExpression`
- [ ] `MultExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `LeftShiftExpression`
- [ ] `BinaryExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `RightShiftExpression`
- [ ] `BinaryExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `AndExpression`
- [ ] `BinaryExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `OrExpression`
- [ ] `BinaryExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `XorExpression`
- [ ] `BinaryExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `DivExpression`
- [ ] `BinaryExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `MinusExpression`
- [ ] `UnaryExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `NotExpression`
- [ ] `UnaryExpression`
- [ ] `encode`
- [ ] `getSubValue`
- [ ] `getValue`

### Class: `PatternEquation`
- [ ] `genPattern`
- [ ] `layClaim`
- [ ] `operandOrder`
- [ ] `release`
- [ ] `resolveOperandLeft`

### Class: `OperandEquation`
- [ ] `genPattern`
- [ ] `operandOrder`
- [ ] `resolveOperandLeft`

### Class: `UnconstrainedEquation`
- [ ] `genPattern`
- [ ] `resolveOperandLeft`

### Class: `ValExpressEquation`
- [ ] `resolveOperandLeft`

### Class: `EqualEquation`
- [ ] `ValExpressEquation`
- [ ] `genPattern`

### Class: `NotEqualEquation`
- [ ] `ValExpressEquation`
- [ ] `genPattern`

### Class: `LessEquation`
- [ ] `ValExpressEquation`
- [ ] `genPattern`

### Class: `LessEqualEquation`
- [ ] `ValExpressEquation`
- [ ] `genPattern`

### Class: `GreaterEquation`
- [ ] `ValExpressEquation`
- [ ] `genPattern`

### Class: `GreaterEqualEquation`
- [ ] `ValExpressEquation`
- [ ] `genPattern`

### Class: `EquationAnd`
- [ ] `genPattern`
- [ ] `operandOrder`
- [ ] `resolveOperandLeft`

### Class: `EquationOr`
- [ ] `genPattern`
- [ ] `operandOrder`
- [ ] `resolveOperandLeft`

### Class: `EquationCat`
- [ ] `genPattern`
- [ ] `operandOrder`
- [ ] `resolveOperandLeft`

### Class: `EquationLeftEllipsis`
- [ ] `genPattern`
- [ ] `operandOrder`
- [ ] `resolveOperandLeft`

### Class: `EquationRightEllipsis`
- [ ] `genPattern`
- [ ] `operandOrder`
- [ ] `resolveOperandLeft`

## File: `slghpattern.hh`
### Class: `PatternBlock`
- [ ] `alwaysFalse`
- [ ] `alwaysTrue`
- [ ] `decode`
- [ ] `encode`
- [ ] `getLength`
- [ ] `getMask`
- [ ] `getValue`
- [ ] `identical`
- [ ] `isContextMatch`
- [ ] `isInstructionMatch`
- [ ] `shift`
- [ ] `specializes`

### Class: `Pattern`
- [ ] `alwaysFalse`
- [ ] `alwaysInstructionTrue`
- [ ] `alwaysTrue`
- [ ] `decode`
- [ ] `encode`
- [ ] `isMatch`
- [ ] `numDisjoint`
- [ ] `shiftInstruction`
- [ ] `~Pattern`

### Class: `DisjointPattern`
- [ ] `getLength`
- [ ] `getMask`
- [ ] `getValue`
- [ ] `identical`
- [ ] `numDisjoint`
- [ ] `resolvesIntersect`
- [ ] `specializes`

### Class: `InstructionPattern`
- [ ] `InstructionPattern`
- [ ] `PatternBlock`
- [ ] `alwaysFalse`
- [ ] `alwaysInstructionTrue`
- [ ] `alwaysTrue`
- [ ] `decode`
- [ ] `encode`
- [ ] `isMatch`
- [ ] `shiftInstruction`
- [ ] `~InstructionPattern`

### Class: `ContextPattern`
- [ ] `ContextPattern`
- [ ] `alwaysFalse`
- [ ] `alwaysInstructionTrue`
- [ ] `alwaysTrue`
- [ ] `decode`
- [ ] `encode`
- [ ] `isMatch`
- [ ] `shiftInstruction`
- [ ] `~ContextPattern`

### Class: `CombinePattern`
- [ ] `alwaysFalse`
- [ ] `alwaysInstructionTrue`
- [ ] `alwaysTrue`
- [ ] `decode`
- [ ] `encode`
- [ ] `isMatch`
- [ ] `shiftInstruction`
- [ ] `~CombinePattern`

### Class: `OrPattern`
- [ ] `OrPattern`
- [ ] `alwaysFalse`
- [ ] `alwaysInstructionTrue`
- [ ] `alwaysTrue`
- [ ] `decode`
- [ ] `encode`
- [ ] `isMatch`
- [ ] `numDisjoint`
- [ ] `shiftInstruction`
- [ ] `~OrPattern`

## File: `slghsymbol.hh`
### Class: `SleighSymbol`
- [ ] *No public functions*

### Class: `SymbolScope`
- [ ] `begin`
- [ ] `end`
- [ ] `getId`
- [ ] `removeSymbol`

### Class: `SymbolTable`
- [ ] `addGlobalSymbol`
- [ ] `addScope`
- [ ] `addSymbol`
- [ ] `decode`
- [ ] `decodeSymbolHeader`
- [ ] `encode`
- [ ] `findSymbolInternal`
- [ ] `popScope`
- [ ] `purge`
- [ ] `replaceSymbol`
- [ ] `setCurrentScope`

### Class: `SpaceSymbol`
- [ ] `SleighSymbol`
- [ ] `getType`

### Class: `TokenSymbol`
- [ ] `SleighSymbol`
- [ ] `getType`

### Class: `SectionSymbol`
- [ ] `SleighSymbol`
- [ ] `getDefineCount`
- [ ] `getRefCount`
- [ ] `getTemplateId`
- [ ] `getType`
- [ ] `incrementDefineCount`
- [ ] `incrementRefCount`

### Class: `UserOpSymbol`
- [ ] `UserOpSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getIndex`
- [ ] `getType`
- [ ] `setIndex`

### Class: `TripleSymbol`
- [ ] `SleighSymbol`
- [ ] `collectLocalValues`
- [ ] `getFixedHandle`
- [ ] `getSize`
- [ ] `print`

### Class: `FamilySymbol`
- [ ] `TripleSymbol`

### Class: `SpecificSymbol`
- [ ] `TripleSymbol`

### Class: `PatternlessSymbol`
- [ ] `PatternlessSymbol`
- [ ] `~PatternlessSymbol`

### Class: `EpsilonSymbol`
- [ ] `EpsilonSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFixedHandle`
- [ ] `getType`
- [ ] `print`

### Class: `ValueSymbol`
- [ ] `ValueSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFixedHandle`
- [ ] `getType`
- [ ] `print`
- [ ] `~ValueSymbol`

### Class: `ValueMapSymbol`
- [ ] `ValueMapSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFixedHandle`
- [ ] `getType`
- [ ] `print`

### Class: `NameSymbol`
- [ ] `NameSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getType`
- [ ] `print`

### Class: `VarnodeSymbol`
- [ ] `VarnodeSymbol`
- [ ] `collectLocalValues`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFixedHandle`
- [ ] `getName`
- [ ] `getSize`
- [ ] `getType`
- [ ] `markAsContext`
- [ ] `print`

### Class: `BitrangeSymbol`
- [ ] `SleighSymbol`
- [ ] `getBitOffset`
- [ ] `getType`
- [ ] `numBits`

### Class: `ContextSymbol`
- [ ] `ContextSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFlow`
- [ ] `getHigh`
- [ ] `getLow`
- [ ] `getType`

### Class: `VarnodeListSymbol`
- [ ] `VarnodeListSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFixedHandle`
- [ ] `getSize`
- [ ] `getType`
- [ ] `print`

### Class: `OperandSymbol`
- [ ] *No public functions*

### Class: `StartSymbol`
- [ ] `StartSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFixedHandle`
- [ ] `getType`
- [ ] `print`
- [ ] `~StartSymbol`

### Class: `EndSymbol`
- [ ] `EndSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFixedHandle`
- [ ] `getType`
- [ ] `print`
- [ ] `~EndSymbol`

### Class: `Next2Symbol`
- [ ] `Next2Symbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFixedHandle`
- [ ] `getType`
- [ ] `print`
- [ ] `~Next2Symbol`

### Class: `FlowDestSymbol`
- [ ] `FlowDestSymbol`
- [ ] `SleighError`
- [ ] `getFixedHandle`
- [ ] `getType`
- [ ] `print`

### Class: `FlowRefSymbol`
- [ ] `FlowRefSymbol`
- [ ] `SleighError`
- [ ] `getFixedHandle`
- [ ] `getType`
- [ ] `print`

### Class: `ContextChange`
- [ ] `apply`
- [ ] `decode`
- [ ] `encode`
- [ ] `validate`
- [ ] `~ContextChange`

### Class: `ContextOp`
- [ ] `apply`
- [ ] `decode`
- [ ] `encode`
- [ ] `validate`
- [ ] `~ContextOp`

### Class: `ContextCommit`
- [ ] `ContextCommit`
- [ ] `apply`
- [ ] `decode`
- [ ] `encode`
- [ ] `validate`

### Class: `Constructor`
- [ ] `Constructor`
- [ ] `addContext`
- [ ] `addEquation`
- [ ] `addInvisibleOperand`
- [ ] `addOperand`
- [ ] `addSyntax`
- [ ] `applyContext`
- [ ] `collectLocalExports`
- [ ] `decode`
- [ ] `encode`
- [ ] `getId`
- [ ] `getLineno`
- [ ] `getMinimumLength`
- [ ] `getNumOperands`
- [ ] `getNumSections`
- [ ] `getSrcIndex`
- [ ] `isError`
- [ ] `isRecursive`
- [ ] `markSubtableOperands`
- [ ] `print`
- [ ] `printBody`
- [ ] `printInfo`
- [ ] `printMnemonic`
- [ ] `removeTrailingSpace`
- [ ] `setError`
- [ ] `setId`
- [ ] `setLineno`
- [ ] `setMainSection`
- [ ] `setMinimumLength`
- [ ] `setNamedSection`
- [ ] `setSrcIndex`

### Class: `DecisionProperties`
- [ ] `conflictingPattern`
- [ ] `identicalPattern`

### Class: `DecisionNode`
- [ ] `DecisionNode`
- [ ] `addConstructorPair`
- [ ] `decode`
- [ ] `encode`
- [ ] `orderPatterns`
- [ ] `split`

### Class: `SubtableSymbol`
- [ ] `SleighError`
- [ ] `SubtableSymbol`
- [ ] `addConstructor`
- [ ] `buildDecisionTree`
- [ ] `collectLocalValues`
- [ ] `decode`
- [ ] `encode`
- [ ] `encodeHeader`
- [ ] `getFixedHandle`
- [ ] `getNumConstructors`
- [ ] `getSize`
- [ ] `getType`
- [ ] `isBeingBuilt`
- [ ] `isError`
- [ ] `print`
- [ ] `~SubtableSymbol`

### Class: `MacroSymbol`
- [ ] `SleighSymbol`
- [ ] `addOperand`
- [ ] `getIndex`
- [ ] `getNumOperands`
- [ ] `getType`
- [ ] `setConstruct`
- [ ] `~MacroSymbol`

### Class: `LabelSymbol`
- [ ] `SleighSymbol`
- [ ] `getIndex`
- [ ] `getRefCount`
- [ ] `getType`
- [ ] `incrementRefCount`
- [ ] `isPlaced`
- [ ] `setPlaced`

## File: `string_ghidra.hh`
### Class: `GhidraStringManager`
- [ ] `~GhidraStringManager`

## File: `stringmanage.hh`
### Class: `StringManager`
- [ ] *No public functions*

### Class: `StringManagerUnicode`
- [ ] `~StringManagerUnicode`

## File: `subflow.hh`
### Class: `RuleSubvarAnd`
- [ ] `Rule`
- [ ] `RuleSubvarAnd`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubvarSubpiece`
- [ ] `Rule`
- [ ] `RuleSubvarSubpiece`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubvarCompZero`
- [ ] `Rule`
- [ ] `RuleSubvarCompZero`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubvarShift`
- [ ] `Rule`
- [ ] `RuleSubvarShift`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubvarZext`
- [ ] `Rule`
- [ ] `RuleSubvarZext`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubvarSext`
- [ ] `Rule`
- [ ] `RuleSubvarSext`
- [ ] `applyOp`
- [ ] `getOpList`
- [ ] `reset`

### Class: `SplitFlow`
- [ ] `doTrace`

### Class: `RuleSplitFlow`
- [ ] `Rule`
- [ ] `RuleSplitFlow`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `SplitDatatype`
- [ ] *No public functions*

### Class: `RootPointer`
- [ ] `duplicateToTemp`
- [ ] `find`
- [ ] `freePointerChain`

### Class: `RuleSplitCopy`
- [ ] `Rule`
- [ ] `RuleSplitCopy`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSplitLoad`
- [ ] `Rule`
- [ ] `RuleSplitLoad`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSplitStore`
- [ ] `Rule`
- [ ] `RuleSplitStore`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDumptyHumpLate`
- [ ] `Rule`
- [ ] `RuleDumptyHumpLate`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `SubfloatFlow`
- [ ] `State`
- [ ] `incorporateInputSize`

### Class: `RuleSubfloatConvert`
- [ ] `Rule`
- [ ] `RuleSubfloatConvert`
- [ ] `applyOp`
- [ ] `getOpList`

## File: `testfunction.hh`
### Class: `FunctionTestProperty`
- [ ] `endTest`
- [ ] `getName`
- [ ] `processLine`
- [ ] `restoreXml`
- [ ] `startTest`

### Class: `ConsoleCommands`
- [ ] `isStreamFinished`
- [ ] `reset`

### Class: `FunctionTestCollection`
- [ ] `FunctionTestCollection`
- [ ] `getCommand`
- [ ] `getTestsApplied`
- [ ] `getTestsSucceeded`
- [ ] `loadTest`
- [ ] `numCommands`
- [ ] `restoreXml`
- [ ] `restoreXmlOldForm`
- [ ] `runTestFiles`
- [ ] `runTests`
- [ ] `~FunctionTestCollection`

## File: `transform.hh`
### Class: `TransformVar`
- [ ] *No public functions*

### Class: `TransformOp`
- [ ] *No public functions*

### Class: `LanedRegister`
- [ ] `LanedIterator`
- [ ] `normalize`

### Class: `LaneDescription`
- [ ] `LaneDescription`
- [ ] `extension`
- [ ] `getBoundary`
- [ ] `getNumLanes`
- [ ] `getPosition`
- [ ] `getSize`
- [ ] `getWholeSize`
- [ ] `restriction`
- [ ] `subset`

### Class: `TransformManager`
- [ ] `apply`
- [ ] `clearVarnodeMarks`
- [ ] `opSetInput`
- [ ] `opSetOutput`
- [ ] `preexistingGuard`
- [ ] `preserveAddress`
- [ ] `~TransformManager`

## File: `typegrp_ghidra.hh`
### Class: `TypeFactoryGhidra`
- [ ] `TypeFactory`
- [ ] `~TypeFactoryGhidra`

## File: `unify.hh`
### Class: `UnifyDatatype`
- [ ] *No public functions*

### Class: `RHSConstant`
- [ ] `getConstant`
- [ ] `writeExpression`
- [ ] `~RHSConstant`

### Class: `ConstantNamed`
- [ ] `ConstantNamed`
- [ ] `getConstant`
- [ ] `getId`
- [ ] `writeExpression`

### Class: `ConstantAbsolute`
- [ ] `ConstantAbsolute`
- [ ] `getConstant`
- [ ] `getVal`
- [ ] `writeExpression`

### Class: `ConstantNZMask`
- [ ] `ConstantNZMask`
- [ ] `getConstant`
- [ ] `writeExpression`

### Class: `ConstantConsumed`
- [ ] `ConstantConsumed`
- [ ] `getConstant`
- [ ] `writeExpression`

### Class: `ConstantOffset`
- [ ] `ConstantOffset`
- [ ] `getConstant`
- [ ] `writeExpression`

### Class: `ConstantIsConstant`
- [ ] `ConstantIsConstant`
- [ ] `getConstant`
- [ ] `writeExpression`

### Class: `ConstantHeritageKnown`
- [ ] `ConstantHeritageKnown`
- [ ] `getConstant`
- [ ] `writeExpression`

### Class: `ConstantVarnodeSize`
- [ ] `ConstantVarnodeSize`
- [ ] `getConstant`
- [ ] `writeExpression`

### Class: `ConstantExpression`
- [ ] `getConstant`
- [ ] `writeExpression`
- [ ] `~ConstantExpression`

### Class: `TraverseConstraint`
- [ ] `getId`
- [ ] `~TraverseConstraint`

### Class: `TraverseDescendState`
- [ ] `TraverseConstraint`
- [ ] `initialize`
- [ ] `step`

### Class: `TraverseCountState`
- [ ] `TraverseConstraint`
- [ ] `getState`
- [ ] `initialize`
- [ ] `step`

### Class: `TraverseGroupState`
- [ ] `TraverseConstraint`
- [ ] `addTraverse`
- [ ] `getCurrentIndex`
- [ ] `getState`
- [ ] `setCurrentIndex`
- [ ] `setState`

### Class: `UnifyConstraint`
- [ ] `buildTraverseState`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `getId`
- [ ] `getMaxNum`
- [ ] `initialize`
- [ ] `isDummy`
- [ ] `print`
- [ ] `removeDummy`
- [ ] `setId`
- [ ] `step`
- [ ] `~UnifyConstraint`

### Class: `DummyOpConstraint`
- [ ] `DummyOpConstraint`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `isDummy`
- [ ] `print`
- [ ] `step`

### Class: `DummyVarnodeConstraint`
- [ ] `DummyVarnodeConstraint`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `isDummy`
- [ ] `print`
- [ ] `step`

### Class: `DummyConstConstraint`
- [ ] `DummyConstConstraint`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `isDummy`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintBoolean`
- [ ] `ConstraintBoolean`
- [ ] `print`
- [ ] `step`
- [ ] `~ConstraintBoolean`

### Class: `ConstraintVarConst`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`
- [ ] `~ConstraintVarConst`

### Class: `ConstraintNamedExpression`
- [ ] `ConstraintNamedExpression`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`
- [ ] `~ConstraintNamedExpression`

### Class: `ConstraintOpCopy`
- [ ] `ConstraintOpCopy`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintOpcode`
- [ ] `ConstraintOpcode`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintOpCompare`
- [ ] `ConstraintOpCompare`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintOpInput`
- [ ] `ConstraintOpInput`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintOpInputAny`
- [ ] `ConstraintOpInputAny`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `initialize`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintOpOutput`
- [ ] `ConstraintOpOutput`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintParamConstVal`
- [ ] `ConstraintParamConstVal`
- [ ] `collectTypes`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintParamConst`
- [ ] `ConstraintParamConst`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintVarnodeCopy`
- [ ] `ConstraintVarnodeCopy`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintVarCompare`
- [ ] `ConstraintVarCompare`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintDef`
- [ ] `ConstraintDef`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintDescend`
- [ ] `ConstraintDescend`
- [ ] `buildTraverseState`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `initialize`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintLoneDescend`
- [ ] `ConstraintLoneDescend`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintOtherInput`
- [ ] `ConstraintOtherInput`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintConstCompare`
- [ ] `ConstraintConstCompare`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintGroup`
- [ ] `addConstraint`
- [ ] `buildTraverseState`
- [ ] `collectTypes`
- [ ] `deleteConstraint`
- [ ] `getBaseIndex`
- [ ] `initialize`
- [ ] `mergeIn`
- [ ] `numConstraints`
- [ ] `print`
- [ ] `removeDummy`
- [ ] `setId`
- [ ] `step`
- [ ] `~ConstraintGroup`

### Class: `ConstraintOr`
- [ ] `buildTraverseState`
- [ ] `getBaseIndex`
- [ ] `initialize`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintNewOp`
- [ ] `ConstraintNewOp`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintNewUniqueOut`
- [ ] `ConstraintNewUniqueOut`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `ConstraintSetInput`
- [ ] `ConstraintSetInput`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`
- [ ] `~ConstraintSetInput`

### Class: `ConstraintSetInputConstVal`
- [ ] `collectTypes`
- [ ] `print`
- [ ] `step`
- [ ] `~ConstraintSetInputConstVal`

### Class: `ConstraintRemoveInput`
- [ ] `ConstraintRemoveInput`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`
- [ ] `~ConstraintRemoveInput`

### Class: `ConstraintSetOpcode`
- [ ] `ConstraintSetOpcode`
- [ ] `collectTypes`
- [ ] `getBaseIndex`
- [ ] `print`
- [ ] `step`

### Class: `UnifyState`
- [ ] `initialize`
- [ ] `numTraverse`
- [ ] `registerTraverseConstraint`
- [ ] `setFunction`

### Class: `UnifyCPrinter`
- [ ] `addNames`
- [ ] `decDepth`
- [ ] `getDepth`
- [ ] `incDepth`
- [ ] `initializeBasic`
- [ ] `initializeRuleAction`
- [ ] `popDepth`
- [ ] `print`
- [ ] `printAbort`
- [ ] `printIndent`
- [ ] `printVarDecls`
- [ ] `setClassName`

## File: `unionresolve.hh`
### Class: `ResolvedUnion`
- [ ] `ResolvedUnion`
- [ ] `getFieldNum`
- [ ] `isLocked`
- [ ] `setLock`

### Class: `ResolveEdge`
- [ ] *No public functions*

### Class: `VisitMark`
- [ ] *No public functions*

## File: `userop.hh`
### Class: `UserPcodeOp`
- [ ] *No public functions*

### Class: `UnspecializedPcodeOp`
- [ ] `UserPcodeOp`
- [ ] `decode`

### Class: `DatatypeUserOp`
- [ ] `decode`

### Class: `InjectedUserOp`
- [ ] `UserPcodeOp`
- [ ] `decode`
- [ ] `getInjectId`

### Class: `VolatileOp`
- [ ] `UserPcodeOp`
- [ ] `decode`

### Class: `VolatileReadOp`
- [ ] `VolatileOp`
- [ ] `extractAnnotationSize`
- [ ] `getOperatorName`

### Class: `VolatileWriteOp`
- [ ] `VolatileOp`
- [ ] `extractAnnotationSize`
- [ ] `getOperatorName`

### Class: `TermPatternOp`
- [ ] `UserPcodeOp`
- [ ] `execute`
- [ ] `getNumVariableTerms`
- [ ] `unify`

### Class: `SegmentOp`
- [ ] `decode`
- [ ] `execute`
- [ ] `getBaseSize`
- [ ] `getInnerSize`
- [ ] `getNumVariableTerms`
- [ ] `hasFarPointerSupport`
- [ ] `unify`

### Class: `JumpAssistOp`
- [ ] `decode`
- [ ] `getCalcSize`
- [ ] `getDefaultAddr`
- [ ] `getIndex2Addr`
- [ ] `getIndex2Case`

### Class: `InternalStringOp`
- [ ] `decode`

### Class: `UserOpManage`
- [ ] `decodeCallOtherFixup`
- [ ] `decodeJumpAssist`
- [ ] `decodeSegmentOp`
- [ ] `decodeVolatile`
- [ ] `initialize`
- [ ] `numSegmentOps`
- [ ] `~UserOpManage`

## File: `xml_arch.hh`
### Class: `XmlArchitectureCapability`
- [ ] `isFileMatch`
- [ ] `isXmlMatch`
- [ ] `~XmlArchitectureCapability`

### Class: `XmlArchitecture`
- [ ] `encode`
- [ ] `restoreXml`
- [ ] `~XmlArchitecture`

