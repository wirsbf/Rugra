# Rudra Alignment Checklist: 05 Actions And Rules

## File: `action.hh`
### Class: `ActionGroupList`
- [ ] `contains`

### Class: `Action`
- [x] `apply` ✅
- [x] `get_name` ✅

### Class: `ActionGroup`
- [x] `new` ✅
- [x] `add_action` ✅
- [x] `apply` ✅
- [ ] `clearBreakPoints`
- [ ] `print`
- [ ] `printState`
- [ ] `printStatistics`
- [ ] `reset`
- [ ] `resetStats`
- [ ] `turnOffDebug`
- [ ] `turnOnDebug`
- [ ] `~ActionGroup`

### Class: `ActionRestartGroup`
- [ ] `ActionGroup`
- [ ] `apply`
- [ ] `reset`

### Class: `Rule`
- [x] `apply_op` ✅
- [x] `get_name` ✅
- [x] `get_opcodes` ✅

### Class: `ActionPool`
- [ ] `Action`
- [ ] `addRule`
- [ ] `apply`
- [ ] `clearBreakPoints`
- [ ] `print`
- [ ] `printState`
- [ ] `printStatistics`
- [ ] `reset`
- [ ] `resetStats`
- [ ] `turnOffDebug`
- [ ] `turnOnDebug`
- [ ] `~ActionPool`

### Class: `ActionDatabase`
- [x] `new` ✅
- [x] `register_action` ✅
- [x] `get_action` ✅
- [x] `set_default_actions` ✅

## File: `blockaction.hh`
### Class: `FloatingEdge`
- [ ] *No public functions*

### Class: `LoopBody`
- [ ] `addTail`
- [ ] `clearExitMarks`
- [ ] `clearMarks`
- [ ] `compare_ends`
- [ ] `compare_head`
- [ ] `emitLikelyEdges`
- [ ] `extend`
- [ ] `findBase`
- [ ] `findExit`
- [ ] `labelContainments`
- [ ] `labelExitEdges`
- [ ] `mergeIdenticalHeads`
- [ ] `orderTails`
- [ ] `setExitMarks`

### Class: `TraceDAG`
- [ ] `BranchPoint`
- [ ] `distance`
- [ ] `markPath`
- [ ] `~BranchPoint`

### Class: `CollapseStructure`
- [ ] `collapseAll`
- [ ] `getChangeCount`

### Class: `ActionStructureTransform`
- [ ] `Action`
- [ ] `ActionStructureTransform`
- [ ] `apply`

### Class: `ActionNormalizeBranches`
- [ ] `Action`
- [ ] `ActionNormalizeBranches`
- [ ] `apply`

### Class: `ActionPreferComplement`
- [ ] `Action`
- [ ] `ActionPreferComplement`
- [ ] `apply`

### Class: `ActionBlockStructure`
- [ ] `Action`
- [ ] `ActionBlockStructure`
- [ ] `apply`

### Class: `ActionFinalStructure`
- [ ] `Action`
- [ ] `ActionFinalStructure`
- [ ] `apply`

### Class: `ActionReturnSplit`
- [ ] `Action`
- [ ] `ActionReturnSplit`
- [ ] `apply`

### Class: `ActionNodeJoin`
- [ ] `Action`
- [ ] `ActionNodeJoin`
- [ ] `apply`

## File: `coreaction.hh`
### Class: `ActionStart`
- [ ] `Action`
- [ ] `ActionStart`
- [ ] `apply`

### Class: `ActionStop`
- [ ] `Action`
- [ ] `ActionStop`
- [ ] `apply`

### Class: `ActionStartCleanUp`
- [ ] `Action`
- [ ] `ActionStartCleanUp`
- [ ] `apply`

### Class: `ActionStartTypes`
- [ ] `Action`
- [ ] `ActionStartTypes`
- [ ] `apply`
- [ ] `reset`

### Class: `ActionStackPtrFlow`
- [ ] `Action`
- [ ] `ActionStackPtrFlow`
- [ ] `apply`
- [ ] `reset`

### Class: `ActionLaneDivide`
- [ ] `Action`
- [ ] `ActionLaneDivide`
- [ ] `apply`

### Class: `ActionSegmentize`
- [ ] `Action`
- [ ] `ActionSegmentize`
- [ ] `apply`
- [ ] `reset`

### Class: `ActionForceGoto`
- [ ] `Action`
- [ ] `ActionForceGoto`
- [ ] `apply`

### Class: `ActionCse`
- [ ] `Action`
- [ ] `ActionCse`
- [ ] `apply`

### Class: `ActionMultiCse`
- [ ] `Action`
- [ ] `ActionMultiCse`
- [ ] `apply`

### Class: `ActionShadowVar`
- [ ] `Action`
- [ ] `ActionShadowVar`
- [ ] `apply`

### Class: `ActionConstantPtr`
- [ ] `Action`
- [ ] `ActionConstantPtr`
- [ ] `apply`
- [ ] `reset`

### Class: `ActionDeindirect`
- [ ] `Action`
- [ ] `ActionDeindirect`
- [ ] `apply`

### Class: `ActionVarnodeProps`
- [ ] `Action`
- [ ] `ActionVarnodeProps`
- [ ] `apply`

### Class: `ActionDirectWrite`
- [ ] `Action`
- [ ] `ActionDirectWrite`
- [ ] `apply`

### Class: `ActionConstbase`
- [ ] `Action`
- [ ] `ActionConstbase`
- [ ] `apply`

### Class: `ActionSpacebase`
- [ ] `Action`
- [ ] `ActionSpacebase`
- [ ] `apply`

### Class: `ActionHeritage`
- [x] `new` ✅
- [x] `apply` ✅

### Class: `ActionNonzeroMask`
- [ ] `Action`
- [ ] `ActionNonzeroMask`
- [ ] `apply`

### Class: `ActionSetCasts`
- [ ] `Action`
- [ ] `ActionSetCasts`
- [ ] `apply`

### Class: `ActionAssignHigh`
- [ ] `Action`
- [ ] `ActionAssignHigh`
- [ ] `apply`

### Class: `ActionMarkIndirectOnly`
- [ ] `Action`
- [ ] `ActionMarkIndirectOnly`
- [ ] `apply`

### Class: `ActionMergeRequired`
- [ ] `Action`
- [ ] `ActionMergeRequired`
- [ ] `apply`

### Class: `ActionMergeAdjacent`
- [ ] `Action`
- [ ] `ActionMergeAdjacent`
- [ ] `apply`

### Class: `ActionMergeCopy`
- [ ] `Action`
- [ ] `ActionMergeCopy`
- [ ] `apply`

### Class: `ActionMergeMultiEntry`
- [ ] `Action`
- [ ] `ActionMergeMultiEntry`
- [ ] `apply`

### Class: `ActionMergeType`
- [ ] `Action`
- [ ] `ActionMergeType`
- [ ] `apply`

### Class: `ActionUnreachable`
- [ ] `Action`
- [ ] `ActionUnreachable`
- [ ] `apply`

### Class: `ActionDoNothing`
- [ ] `Action`
- [ ] `ActionDoNothing`
- [ ] `apply`

### Class: `ActionRedundBranch`
- [ ] `Action`
- [ ] `ActionRedundBranch`
- [ ] `apply`

### Class: `ActionDeterminedBranch`
- [ ] `Action`
- [ ] `ActionDeterminedBranch`
- [ ] `apply`

### Class: `ActionDeadCode`
- [x] `new` ✅
- [x] `apply` ✅

### Class: `ActionSwitchNorm`
- [ ] `Action`
- [ ] `ActionSwitchNorm`
- [ ] `apply`

### Class: `ActionNormalizeSetup`
- [ ] `Action`
- [ ] `ActionNormalizeSetup`
- [ ] `apply`

### Class: `ActionPrototypeTypes`
- [ ] `Action`
- [ ] `ActionPrototypeTypes`
- [ ] `apply`
- [ ] `extendInput`

### Class: `ActionDefaultParams`
- [ ] `Action`
- [ ] `ActionDefaultParams`
- [ ] `apply`

### Class: `ActionExtraPopSetup`
- [ ] `Action`
- [ ] `ActionExtraPopSetup`
- [ ] `apply`

### Class: `ActionFuncLink`
- [ ] `Action`
- [ ] `ActionFuncLink`
- [ ] `apply`

### Class: `ActionFuncLinkOutOnly`
- [ ] `Action`
- [ ] `ActionFuncLinkOutOnly`
- [ ] `apply`

### Class: `ActionParamDouble`
- [ ] `Action`
- [ ] `ActionParamDouble`
- [ ] `apply`

### Class: `ActionActiveParam`
- [ ] `Action`
- [ ] `ActionActiveParam`
- [ ] `apply`

### Class: `ActionActiveReturn`
- [ ] `Action`
- [ ] `ActionActiveReturn`
- [ ] `apply`

### Class: `ActionParamShiftStart`
- [ ] `Action`
- [ ] `ActionParamShiftStart`
- [ ] `apply`

### Class: `ActionParamShiftStop`
- [ ] `Action`
- [ ] `ActionParamShiftStop`
- [ ] `apply`
- [ ] `reset`

### Class: `ActionReturnRecovery`
- [ ] `Action`
- [ ] `ActionReturnRecovery`
- [ ] `apply`

### Class: `ActionRestrictLocal`
- [ ] `Action`
- [ ] `ActionRestrictLocal`
- [ ] `apply`

### Class: `ActionLikelyTrash`
- [ ] `Action`
- [ ] `ActionLikelyTrash`
- [ ] `apply`

### Class: `ActionRestructureVarnode`
- [ ] `Action`
- [ ] `ActionRestructureVarnode`
- [ ] `apply`
- [ ] `reset`

### Class: `ActionMappedLocalSync`
- [ ] `Action`
- [ ] `ActionMappedLocalSync`
- [ ] `apply`

### Class: `ActionMapGlobals`
- [ ] `Action`
- [ ] `ActionMapGlobals`
- [ ] `apply`

### Class: `ActionInputPrototype`
- [ ] `Action`
- [ ] `ActionInputPrototype`
- [ ] `apply`

### Class: `ActionOutputPrototype`
- [ ] `Action`
- [ ] `ActionOutputPrototype`
- [ ] `apply`

### Class: `ActionUnjustifiedParams`
- [ ] `Action`
- [ ] `ActionUnjustifiedParams`
- [ ] `apply`

### Class: `ActionInferTypes`
- [ ] `Action`
- [ ] `ActionInferTypes`
- [ ] `apply`
- [ ] `reset`

### Class: `ActionHideShadow`
- [ ] `Action`
- [ ] `ActionHideShadow`
- [ ] `apply`

### Class: `ActionDominantCopy`
- [ ] `Action`
- [ ] `ActionDominantCopy`
- [ ] `apply`

### Class: `ActionCopyMarker`
- [ ] `Action`
- [ ] `ActionCopyMarker`
- [ ] `apply`

### Class: `ActionDynamicMapping`
- [ ] `Action`
- [ ] `ActionDynamicMapping`
- [ ] `apply`

### Class: `ActionDynamicSymbols`
- [ ] `Action`
- [ ] `ActionDynamicSymbols`
- [ ] `apply`

### Class: `ActionPrototypeWarnings`
- [ ] `Action`
- [ ] `ActionPrototypeWarnings`
- [ ] `apply`

### Class: `ActionInternalStorage`
- [ ] `Action`
- [ ] `ActionInternalStorage`
- [ ] `apply`

### Class: `PropagationState`
- [ ] `PropagationState`
- [ ] `step`
- [ ] `valid`

## File: `options.hh`
### Class: `ArchOption`
- [ ] `apply`
- [ ] `getName`
- [ ] `onOrOff`
- [ ] `~ArchOption`

### Class: `OptionDatabase`
- [ ] `decode`
- [ ] `decodeOne`
- [ ] `set`
- [ ] `~OptionDatabase`

### Class: `OptionExtraPop`
- [ ] `apply`

### Class: `OptionReadOnly`
- [ ] `apply`

### Class: `OptionDefaultPrototype`
- [ ] `apply`

### Class: `OptionInferConstPtr`
- [ ] `apply`

### Class: `OptionForLoops`
- [ ] `apply`

### Class: `OptionInline`
- [ ] `apply`

### Class: `OptionNoReturn`
- [ ] `apply`

### Class: `OptionWarning`
- [ ] `apply`

### Class: `OptionNullPrinting`
- [ ] `apply`

### Class: `OptionInPlaceOps`
- [ ] `apply`

### Class: `OptionConventionPrinting`
- [ ] `apply`

### Class: `OptionNoCastPrinting`
- [ ] `apply`

### Class: `OptionHideExtensions`
- [ ] `apply`

### Class: `OptionMaxLineWidth`
- [ ] `apply`

### Class: `OptionIndentIncrement`
- [ ] `apply`

### Class: `OptionCommentIndent`
- [ ] `apply`

### Class: `OptionCommentStyle`
- [ ] `apply`

### Class: `OptionCommentHeader`
- [ ] `apply`

### Class: `OptionCommentInstruction`
- [ ] `apply`

### Class: `OptionIntegerFormat`
- [ ] `apply`

### Class: `OptionBraceFormat`
- [ ] `apply`

### Class: `OptionSetAction`
- [ ] `apply`

### Class: `OptionCurrentAction`
- [ ] `apply`

### Class: `OptionAllowContextSet`
- [ ] `apply`

### Class: `OptionIgnoreUnimplemented`
- [ ] `apply`

### Class: `OptionErrorUnimplemented`
- [ ] `apply`

### Class: `OptionErrorReinterpreted`
- [ ] `apply`

### Class: `OptionErrorTooManyInstructions`
- [ ] `apply`

### Class: `OptionProtoEval`
- [ ] `apply`

### Class: `OptionSetLanguage`
- [ ] `apply`

### Class: `OptionJumpTableMax`
- [ ] `apply`

### Class: `OptionJumpLoad`
- [ ] `apply`

### Class: `OptionToggleRule`
- [ ] `apply`

### Class: `OptionAliasBlock`
- [ ] `apply`

### Class: `OptionMaxInstruction`
- [ ] `apply`

### Class: `OptionNamespaceStrategy`
- [ ] `apply`

### Class: `OptionSplitDatatypes`
- [ ] *No public functions*

### Class: `OptionNanIgnore`
- [ ] `apply`

## File: `ruleaction.hh`
### Class: `AddTreeState`
- [ ] `apply`
- [ ] `initAlternateForm`

### Class: `RuleEarlyRemoval`
- [ ] `Rule`
- [ ] `RuleEarlyRemoval`
- [ ] `applyOp`

### Class: `RuleAddrForceRelease`
- [ ] `Rule`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleCollectTerms`
- [ ] `Rule`
- [ ] `RuleCollectTerms`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSelectCse`
- [ ] `Rule`
- [ ] `RuleSelectCse`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePiece2Zext`
- [ ] `Rule`
- [ ] `RulePiece2Zext`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePiece2Sext`
- [ ] `Rule`
- [ ] `RulePiece2Sext`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleBxor2NotEqual`
- [ ] `Rule`
- [ ] `RuleBxor2NotEqual`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleOrMask`
- [ ] `Rule`
- [ ] `RuleOrMask`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleAndMask`
- [ ] `Rule`
- [ ] `RuleAndMask`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleOrConsume`
- [ ] `Rule`
- [ ] `RuleOrConsume`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleOrCollapse`
- [ ] `Rule`
- [ ] `RuleOrCollapse`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleAndOrLump`
- [ ] `Rule`
- [ ] `RuleAndOrLump`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleNegateIdentity`
- [ ] `Rule`
- [ ] `RuleNegateIdentity`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleShiftBitops`
- [ ] `Rule`
- [ ] `RuleShiftBitops`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleRightShiftAnd`
- [ ] `Rule`
- [ ] `RuleRightShiftAnd`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleIntLessEqual`
- [ ] `Rule`
- [ ] `RuleIntLessEqual`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleEquality`
- [ ] `Rule`
- [ ] `RuleEquality`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleTermOrder`
- [ ] `Rule`
- [ ] `RuleTermOrder`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePullsubMulti`
- [ ] `Rule`
- [ ] `RulePullsubMulti`
- [ ] `acceptableSize`
- [ ] `applyOp`
- [ ] `getOpList`
- [ ] `minMaxUse`
- [ ] `replaceDescendants`

### Class: `RulePullsubIndirect`
- [ ] `Rule`
- [ ] `RulePullsubIndirect`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePushMulti`
- [ ] `Rule`
- [ ] `RulePushMulti`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleNotDistribute`
- [ ] `Rule`
- [ ] `RuleNotDistribute`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleHighOrderAnd`
- [ ] `Rule`
- [ ] `RuleHighOrderAnd`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleAndDistribute`
- [ ] `Rule`
- [ ] `RuleAndDistribute`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleLessOne`
- [ ] `Rule`
- [ ] `RuleLessOne`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleRangeMeld`
- [ ] `Rule`
- [ ] `RuleRangeMeld`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleFloatRange`
- [ ] `Rule`
- [ ] `RuleFloatRange`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleAndCommute`
- [ ] `Rule`
- [ ] `RuleAndCommute`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleAndPiece`
- [ ] `Rule`
- [ ] `RuleAndPiece`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleAndZext`
- [ ] `Rule`
- [ ] `RuleAndZext`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleAndCompare`
- [ ] `Rule`
- [ ] `RuleAndCompare`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDoubleSub`
- [ ] `Rule`
- [ ] `RuleDoubleSub`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDoubleShift`
- [ ] `Rule`
- [ ] `RuleDoubleShift`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDoubleArithShift`
- [ ] `Rule`
- [ ] `RuleDoubleArithShift`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleConcatShift`
- [ ] `Rule`
- [ ] `RuleConcatShift`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleLeftRight`
- [ ] `Rule`
- [ ] `RuleLeftRight`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleShiftCompare`
- [ ] `Rule`
- [ ] `RuleShiftCompare`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleShiftLess`
- [ ] `Rule`
- [ ] `RuleShiftLess`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleLessEqual`
- [ ] `Rule`
- [ ] `RuleLessEqual`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleLessNotEqual`
- [ ] `Rule`
- [ ] `RuleLessNotEqual`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleTrivialArith`
- [ ] `Rule`
- [ ] `RuleTrivialArith`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleTrivialBool`
- [x] `new` ✅
- [x] `apply_op` ✅
- [x] `get_name` ✅
- [x] `get_opcodes` ✅

### Class: `RuleZextEliminate`
- [x] `new` ✅
- [x] `apply_op` ✅
- [x] `get_name` ✅
- [x] `get_opcodes` ✅

### Class: `RuleSlessToLess`
- [ ] `Rule`
- [ ] `RuleSlessToLess`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleZextSless`
- [ ] `Rule`
- [ ] `RuleZextSless`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleBitUndistribute`
- [ ] `Rule`
- [ ] `RuleBitUndistribute`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleBooleanUndistribute`
- [ ] `Rule`
- [ ] `RuleBooleanUndistribute`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleBooleanDedup`
- [ ] `Rule`
- [ ] `RuleBooleanDedup`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleBooleanNegate`
- [ ] `Rule`
- [ ] `RuleBooleanNegate`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleBoolZext`
- [ ] `Rule`
- [ ] `RuleBoolZext`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleLogic2Bool`
- [ ] `Rule`
- [ ] `RuleLogic2Bool`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleIndirectCollapse`
- [ ] `Rule`
- [ ] `RuleIndirectCollapse`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleMultiCollapse`
- [ ] `Rule`
- [ ] `RuleMultiCollapse`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSborrow`
- [ ] `Rule`
- [ ] `RuleSborrow`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleScarry`
- [ ] `Rule`
- [ ] `RuleScarry`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleTrivialShift`
- [ ] `Rule`
- [ ] `RuleTrivialShift`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSignShift`
- [ ] `Rule`
- [ ] `RuleSignShift`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleTestSign`
- [ ] `Rule`
- [ ] `RuleTestSign`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleIdentityEl`
- [ ] `Rule`
- [ ] `RuleIdentityEl`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleShift2Mult`
- [ ] `Rule`
- [ ] `RuleShift2Mult`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleShiftPiece`
- [ ] `Rule`
- [ ] `RuleShiftPiece`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleCollapseConstants`
- [x] `new` ✅
- [x] `apply_op` ✅
- [x] `get_name` ✅
- [x] `get_opcodes` ✅

### Class: `RuleTransformCpool`
- [ ] `Rule`
- [ ] `RuleTransformCpool`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePropagateCopy`
- [x] `new` ✅
- [x] `apply_op` ✅
- [x] `get_name` ✅
- [x] `get_opcodes` ✅

### Class: `Rule2Comp2Mult`
- [ ] `Rule`
- [ ] `Rule2Comp2Mult`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleCarryElim`
- [ ] `Rule`
- [ ] `RuleCarryElim`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSub2Add`
- [ ] `Rule`
- [ ] `RuleSub2Add`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleXorCollapse`
- [ ] `Rule`
- [ ] `RuleXorCollapse`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleAddMultCollapse`
- [ ] `Rule`
- [ ] `RuleAddMultCollapse`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleUndistribute`
- [ ] `Rule`
- [ ] `RuleUndistribute`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleLoadVarnode`
- [ ] `Rule`
- [ ] `RuleLoadVarnode`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleStoreVarnode`
- [ ] `Rule`
- [ ] `RuleStoreVarnode`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleShadowVar`
- [ ] `Rule`
- [ ] `RuleShadowVar`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubExtComm`
- [ ] `Rule`
- [ ] `RuleSubExtComm`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubCommute`
- [ ] `Rule`
- [ ] `RuleSubCommute`
- [ ] `applyOp`
- [ ] `cancelExtensions`
- [ ] `getOpList`

### Class: `RuleConcatCommute`
- [ ] `Rule`
- [ ] `RuleConcatCommute`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleIndirectConcat`
- [ ] `Rule`
- [ ] `RuleIndirectConcat`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleConcatZext`
- [ ] `Rule`
- [ ] `RuleConcatZext`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleZextCommute`
- [ ] `Rule`
- [ ] `RuleZextCommute`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleZextShiftZext`
- [ ] `Rule`
- [ ] `RuleZextShiftZext`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleShiftAnd`
- [ ] `Rule`
- [ ] `RuleShiftAnd`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleConcatZero`
- [ ] `Rule`
- [ ] `RuleConcatZero`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleConcatLeftShift`
- [ ] `Rule`
- [ ] `RuleConcatLeftShift`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubZext`
- [ ] `Rule`
- [ ] `RuleSubZext`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubCancel`
- [ ] `Rule`
- [ ] `RuleSubCancel`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleShiftSub`
- [ ] `Rule`
- [ ] `RuleShiftSub`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleHumptyDumpty`
- [ ] `Rule`
- [ ] `RuleHumptyDumpty`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDumptyHump`
- [ ] `Rule`
- [ ] `RuleDumptyHump`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleHumptyOr`
- [ ] `Rule`
- [ ] `RuleHumptyOr`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSwitchSingle`
- [ ] `Rule`
- [ ] `RuleSwitchSingle`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleCondNegate`
- [ ] `Rule`
- [ ] `RuleCondNegate`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleBoolNegate`
- [ ] `Rule`
- [ ] `RuleBoolNegate`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleLess2Zero`
- [ ] `Rule`
- [ ] `RuleLess2Zero`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleLessEqual2Zero`
- [ ] `Rule`
- [ ] `RuleLessEqual2Zero`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSLess2Zero`
- [ ] `Rule`
- [ ] `RuleSLess2Zero`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleEqual2Zero`
- [ ] `Rule`
- [ ] `RuleEqual2Zero`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleEqual2Constant`
- [ ] `Rule`
- [ ] `RuleEqual2Constant`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePtrArith`
- [ ] `Rule`
- [ ] `RulePtrArith`
- [ ] `applyOp`
- [ ] `evaluatePointerExpression`
- [ ] `getOpList`

### Class: `RuleStructOffset0`
- [ ] `Rule`
- [ ] `RuleStructOffset0`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePushPtr`
- [ ] `Rule`
- [ ] `RulePushPtr`
- [ ] `applyOp`
- [ ] `duplicateNeed`
- [ ] `getOpList`

### Class: `RulePtraddUndo`
- [ ] `Rule`
- [ ] `RulePtraddUndo`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePtrsubUndo`
- [ ] `Rule`
- [ ] `RulePtrsubUndo`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleMultNegOne`
- [ ] `Rule`
- [ ] `RuleMultNegOne`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleAddUnsigned`
- [ ] `Rule`
- [ ] `RuleAddUnsigned`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `Rule2Comp2Sub`
- [ ] `Rule`
- [ ] `Rule2Comp2Sub`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubRight`
- [ ] `Rule`
- [ ] `RuleSubRight`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePtrsubCharConstant`
- [ ] `Rule`
- [ ] `RulePtrsubCharConstant`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleExtensionPush`
- [ ] `Rule`
- [ ] `RuleExtensionPush`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePieceStructure`
- [ ] `Rule`
- [ ] `RulePieceStructure`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSubNormal`
- [ ] `Rule`
- [ ] `RuleSubNormal`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleRightShiftSub`
- [ ] `Rule`
- [ ] `RuleRightShiftSub`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePositiveDiv`
- [ ] `Rule`
- [ ] `RulePositiveDiv`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDivTermAdd`
- [ ] `Rule`
- [ ] `RuleDivTermAdd`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDivTermAdd2`
- [ ] `Rule`
- [ ] `RuleDivTermAdd2`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDivOpt`
- [ ] `Rule`
- [ ] `RuleDivOpt`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSignDiv2`
- [ ] `Rule`
- [ ] `RuleSignDiv2`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleDivChain`
- [ ] `Rule`
- [ ] `RuleDivChain`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSignForm`
- [ ] `Rule`
- [ ] `RuleSignForm`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSignForm2`
- [ ] `Rule`
- [ ] `RuleSignForm2`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSignNearMult`
- [ ] `Rule`
- [ ] `RuleSignNearMult`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleModOpt`
- [ ] `Rule`
- [ ] `RuleModOpt`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSignMod2nOpt`
- [ ] `Rule`
- [ ] `RuleSignMod2nOpt`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSignMod2Opt`
- [ ] `Rule`
- [ ] `RuleSignMod2Opt`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSignMod2nOpt2`
- [ ] `Rule`
- [ ] `RuleSignMod2nOpt2`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleSegment`
- [ ] `Rule`
- [ ] `RuleSegment`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePtrFlow`
- [ ] `RulePtrFlow`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleNegateNegate`
- [ ] `Rule`
- [ ] `RuleNegateNegate`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleConditionalMove`
- [ ] `Rule`
- [ ] `RuleConditionalMove`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleFloatCast`
- [ ] `Rule`
- [ ] `RuleFloatCast`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleIgnoreNan`
- [ ] `Rule`
- [ ] `RuleIgnoreNan`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleUnsigned2Float`
- [ ] `Rule`
- [ ] `RuleUnsigned2Float`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleInt2FloatCollapse`
- [ ] `Rule`
- [ ] `RuleInt2FloatCollapse`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleFuncPtrEncoding`
- [ ] `Rule`
- [ ] `RuleFuncPtrEncoding`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleThreeWayCompare`
- [ ] `Rule`
- [ ] `RuleThreeWayCompare`
- [ ] `applyOp`
- [ ] `getOpList`
- [ ] `testCompareEquivalence`

### Class: `RulePopcountBoolXor`
- [ ] `Rule`
- [ ] `RulePopcountBoolXor`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RulePiecePathology`
- [ ] `Rule`
- [ ] `RulePiecePathology`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleXorSwap`
- [ ] `Rule`
- [ ] `RuleXorSwap`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleLzcountShiftBool`
- [ ] `Rule`
- [ ] `RuleLzcountShiftBool`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleFloatSign`
- [ ] `Rule`
- [ ] `RuleFloatSign`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleFloatSignCleanup`
- [ ] `Rule`
- [ ] `RuleFloatSignCleanup`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleOrCompare`
- [ ] `Rule`
- [ ] `RuleOrCompare`
- [ ] `applyOp`
- [ ] `getOpList`

### Class: `RuleExpandLoad`
- [ ] `Rule`
- [ ] `RuleExpandLoad`
- [ ] `applyOp`
- [ ] `getOpList`

## File: `rulecompile.hh`
### Class: `RuleLexer`
- [ ] `getLineNo`
- [ ] `initialize`
- [ ] `nextToken`

### Class: `DummyTranslate`
- [ ] `LowlevelError`
- [ ] `getAllRegisters`
- [ ] `getExactRegisterName`
- [ ] `getRegisterName`
- [ ] `getUserOpNames`
- [ ] `initialize`
- [ ] `instructionLength`
- [ ] `oneInstruction`
- [ ] `printAssembly`

### Class: `RuleCompile`
- [ ] `findIdentifier`
- [ ] `getLineNo`
- [ ] `nextToken`
- [ ] `numErrors`
- [ ] `postProcess`
- [ ] `postProcessRule`
- [ ] `ruleError`
- [ ] `run`
- [ ] `setErrorStream`
- [ ] `setFullRule`

### Class: `RuleGeneric`
- [ ] `RuleGeneric`
- [ ] `applyOp`
- [ ] `getOpList`
- [ ] `~RuleGeneric`

