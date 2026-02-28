# Rudra Alignment Checklist: 03 Ssa And Heritage

## File: `cover.hh`
### Class: `PcodeOpSet`
- [ ] `affectsTest`
- [ ] `clear`
- [ ] `compareByBlock`
- [ ] `isPopulated`
- [ ] `populate`
- [ ] `~PcodeOpSet`

### Class: `CoverBlock`
- [ ] `boundary`
- [ ] `clear`
- [ ] `contain`
- [ ] `empty`
- [ ] `getUIndex`
- [ ] `intersect`
- [ ] `merge`
- [ ] `print`
- [ ] `setAll`
- [ ] `setBegin`
- [ ] `setEnd`

### Class: `Cover`
- [ ] `addDefPoint`
- [ ] `addRefPoint`
- [ ] `begin`
- [ ] `clear`
- [ ] `compareTo`
- [ ] `contain`
- [ ] `containVarnodeDef`
- [ ] `end`
- [ ] `intersect`
- [ ] `intersectByBlock`
- [ ] `intersectList`
- [ ] `merge`
- [ ] `print`
- [ ] `rebuild`
- [ ] `remove_refpoint`

## File: `heritage.hh`
### Class: `Heritage`
- [x] `heritage` ✅
- [x] `place_multiequals` ✅
- [x] `rename` ✅

### Class: `LocationMap`
- [x] `add` ✅
- [x] `find_pass` ✅
- [x] `clear` ✅

### Class: `TaskList`
- [ ] *No public functions*

### Class: `PriorityQueue`
- [x] `empty` ✅
- [x] `insert` ✅
- [x] `reset` ✅
- [x] `extract` ✅

### Class: `HeritageInfo`
- [x] `new` ✅

### Class: `LoadGuard`
- [ ] `getMaximum`
- [ ] `getMinimum`
- [ ] `getStep`
- [ ] `isGuarded`
- [ ] `isRangeLocked`
- [ ] `isValid`

## File: `merge.hh`
### Class: `BlockVarnode`
- [ ] `findFront`
- [ ] `getIndex`
- [ ] `set`

### Class: `StackAffectingOps`
- [ ] `affectsTest`
- [ ] `data`
- [ ] `populate`

### Class: `Merge`
- [x] `clear` ✅
- [ ] `data`
- [ ] `groupPartials`
- [ ] `hideShadows`
- [ ] `inflateTest`
- [ ] `markImplied`
- [ ] `markInternalCopies`
- [x] `mergeAddrTied` ✅
- [x] `mergeAdjacent` ✅
- [x] `mergeByDatatype` ✅
- [x] `mergeMarker` ✅
- [ ] `mergeMultiEntry`
- [ ] `mergeOpcode`
- [x] `mergeTest` ✅
- [x] `merge_force` ✅
- [ ] `processCopyTrims`
- [ ] `registerProtoPartialRoot`
- [ ] `verifyHighCovers`

