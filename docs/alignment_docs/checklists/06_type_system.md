# Rudra Alignment Checklist: 06 Type System

## File: `cast.hh`
### Class: `CastStrategy`
- [ ] *No public functions*

### Class: `CastStrategyC`
- [x] `checkIntPromotionForCompare` ✅
- [x] `checkIntPromotionForExtension` ✅
- [ ] `intPromotionType`
- [x] `isExtensionCastImplied` ✅ (as `is_cast_implied`)
- [ ] `isSextCast`
- [ ] `isSubpieceCast`
- [ ] `isSubpieceCastEndian`
- [ ] `isZextCast`
- [ ] `localExtensionType`

### Class: `CastStrategyJava`
- [ ] `isZextCast`

## File: `cpool.hh`
### Class: `CPoolRecord`
- [ ] *No public functions*

### Class: `ConstantPool`
- [ ] `clear`
- [ ] `decode`
- [ ] `empty`
- [ ] `encode`
- [ ] `putRecord`
- [ ] `~ConstantPool`

### Class: `ConstantPoolInternal`
- [ ] `CheapSorter`
- [ ] `apply`
- [ ] `decode`
- [ ] `encode`

## File: `database.hh`
### Class: `SymbolEntry`
- [ ] `uselimit`

### Class: `EntrySubsort`
- [ ] `EntrySubsort`

### Class: `Symbol`
- [ ] *No public functions*

### Class: `FunctionSymbol`
- [ ] `FunctionSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `getBytesConsumed`

### Class: `EquateSymbol`
- [ ] `EquateSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `getValue`
- [ ] `isValueClose`

### Class: `UnionFacetSymbol`
- [ ] `UnionFacetSymbol`
- [ ] `decode`
- [ ] `encode`
- [ ] `getFieldNumber`

### Class: `LabSymbol`
- [ ] `LabSymbol`
- [ ] `decode`
- [ ] `encode`

### Class: `ExternRefSymbol`
- [ ] `ExternRefSymbol`
- [ ] `decode`
- [ ] `encode`

### Class: `SymbolCompareName`
- [ ] `operator`

### Class: `MapIterator`
- [ ] `MapIterator`

### Class: `Scope`
- [ ] `Scope`
- [ ] `adjustCaches`
- [ ] `begin`
- [ ] `beginDynamic`
- [ ] `buildDefaultName`
- [ ] `buildUndefinedName`
- [ ] `childrenBegin`
- [ ] `childrenEnd`
- [ ] `clear`
- [ ] `clearAttribute`
- [ ] `clearCategory`
- [ ] `clearUnlocked`
- [ ] `clearUnlockedCategory`
- [ ] `decode`
- [ ] `decodeWrappingAttributes`
- [ ] `encode`
- [ ] `encodeRecursive`
- [ ] `end`
- [ ] `endDynamic`
- [ ] `findByName`
- [ ] `getCategorySize`
- [ ] `getFullName`
- [ ] `getId`
- [ ] `getScopePath`
- [ ] `inScope`
- [ ] `isGlobal`
- [ ] `isNameUsed`
- [ ] `isReadOnly`
- [ ] `isSubScope`
- [ ] `makeNameUnique`
- [ ] `overrideSizeLockType`
- [ ] `printBounds`
- [ ] `printEntries`
- [ ] `queryByName`
- [ ] `removeSymbol`
- [ ] `removeSymbolMappings`
- [ ] `renameSymbol`
- [ ] `resetSizeLockType`
- [ ] `retypeSymbol`
- [ ] `setAttribute`
- [ ] `setCategory`
- [ ] `setDisplayFormat`
- [ ] `setThisPointer`
- [ ] `turnOffDebug`
- [ ] `turnOnDebug`
- [ ] `~Scope`

### Class: `ScopeInternal`
- [ ] `ScopeInternal`
- [ ] `adjustCaches`
- [ ] `assignDefaultNames`
- [ ] `begin`
- [ ] `beginDynamic`
- [ ] `beginMultiEntry`
- [ ] `buildUndefinedName`
- [ ] `categorySanity`
- [ ] `clear`
- [ ] `clearAttribute`
- [ ] `clearCategory`
- [ ] `clearUnlocked`
- [ ] `clearUnlockedCategory`
- [ ] `decode`
- [ ] `encode`
- [ ] `end`
- [ ] `endDynamic`
- [ ] `endMultiEntry`
- [ ] `findByName`
- [ ] `getCategorySize`
- [ ] `isNameUsed`
- [ ] `makeNameUnique`
- [ ] `printEntries`
- [ ] `removeSymbol`
- [ ] `removeSymbolMappings`
- [ ] `renameSymbol`
- [ ] `retypeSymbol`
- [ ] `setAttribute`
- [ ] `setCategory`
- [ ] `setDisplayFormat`
- [ ] `~ScopeInternal`

### Class: `ScopeMapper`
- [ ] `NullSubsort`

### Class: `Database`
- [ ] `addRange`
- [ ] `adjustCaches`
- [ ] `attachScope`
- [ ] `clearPropertyRange`
- [ ] `clearUnlocked`
- [ ] `decode`
- [ ] `decodeScope`
- [ ] `deleteScope`
- [ ] `deleteSubScopes`
- [ ] `encode`
- [ ] `getProperty`
- [ ] `removeRange`
- [ ] `setProperties`
- [ ] `setPropertyRange`
- [ ] `setRange`
- [ ] `~Database`

## File: `type.hh`
### Class: `TypeField`
- [x] `TypeField` ✅
- [ ] `encode`

### Class: `TypeBase`
- [x] `new` ✅

### Class: `TypeChar`
- [x] `TypeChar` ✅
- [ ] `encode`

### Class: `TypeUnicode`
- [x] `TypeBase` ✅
- [x] `TypeUnicode` ✅
- [ ] `encode`

### Class: `TypeVoid`
- [x] `TypeVoid` ✅
- [ ] `encode`

### Class: `TypePointer`
- [x] `TypePointer` ✅
- [ ] `compare`
- [ ] `compareDependency`
- [ ] `encode`
- [ ] `findResolve`
- [ ] `getWordSize`
- [ ] `isPtrsubMatching`
- [ ] `numDepend`
- [ ] `printNameBase`
- [ ] `printRaw`

### Class: `TypeArray`
- [x] `TypeArray` ✅
- [ ] `compare`
- [ ] `compareDependency`
- [ ] `encode`
- [ ] `findCompatibleResolve`
- [ ] `findResolve`
- [ ] `getHoleSize`
- [ ] `numDepend`
- [x] `num_elements` ✅
- [ ] `printNameBase`
- [ ] `printRaw`

### Class: `TypeEnum`
- [x] `TypeEnum` ✅

### Class: `TypeStruct`
- [x] `TypeStruct` ✅
- [ ] `assignFieldOffsets`
- [ ] `beginField`
- [ ] `compare`
- [ ] `compareDependency`
- [ ] `encode`
- [ ] `endField`
- [ ] `findCompatibleResolve`
- [ ] `findResolve`
- [ ] `getHoleSize`
- [ ] `numDepend`
- [ ] `scoreSingleComponent`

### Class: `TypeUnion`
- [x] `TypeUnion` ✅
- [ ] `assignFieldOffsets`
- [ ] `compare`
- [ ] `compareDependency`
- [ ] `encode`
- [ ] `findCompatibleResolve`
- [ ] `findResolve`
- [ ] `numDepend`

### Class: `TypePartialEnum`
- [ ] `TypePartialEnum`
- [ ] `compare`
- [ ] `compareDependency`
- [ ] `encode`
- [ ] `getMatches`
- [ ] `getOffset`
- [ ] `hasNamedValue`
- [ ] `printRaw`

### Class: `TypePartialStruct`
- [ ] `TypePartialStruct`
- [ ] `compare`
- [ ] `compareDependency`
- [ ] `getHoleSize`
- [ ] `getOffset`
- [ ] `printRaw`

### Class: `TypePartialUnion`
- [ ] `TypePartialUnion`
- [ ] `compare`
- [ ] `compareDependency`
- [ ] `encode`
- [ ] `findCompatibleResolve`
- [ ] `findResolve`
- [ ] `getOffset`
- [ ] `numDepend`
- [ ] `printRaw`

### Class: `TypePointerRel`
- [ ] `TypePointerRel`
- [ ] `compare`
- [ ] `compareDependency`
- [ ] `encode`
- [ ] `evaluateThruParent`
- [ ] `getAddressOffset`
- [ ] `getByteOffset`
- [ ] `isPtrsubMatching`
- [ ] `printRaw`

### Class: `TypeCode`
- [x] `TypeCode` ✅
- [ ] `compare`
- [ ] `compareBasic`
- [ ] `compareDependency`
- [ ] `encode`
- [ ] `printRaw`
- [ ] `~TypeCode`

### Class: `TypeSpacebase`
- [x] `Datatype` ✅
- [x] `TypeSpacebase` ✅
- [ ] `compare`
- [ ] `compareDependency`
- [ ] `encode`
- [ ] `getAddress`

### Class: `DatatypeWarning`
- [ ] *No public functions*

### Class: `TypeFactory`
- [x] `new` ✅
- [x] `find_by_name` ✅
- [x] `get_ptr` ✅
- [x] `get_array` ✅
- [x] `create_struct` ✅
- [x] `set_fields` ✅
- [x] `num_types` ✅
- [x] `clear_non_core` ✅
- [ ] `beginWarnings`
- [ ] `cacheCoreTypes`
- [x] `clear` ✅
- [x] `clearNoncore` ✅
- [ ] `decode`
- [ ] `decodeCoreTypes`
- [ ] `decodeDataOrganization`
- [ ] `dependentOrder`
- [ ] `destroyType`
- [ ] `encode`
- [ ] `encodeCoreTypes`
- [ ] `endWarnings`
- [ ] `getAlignment`
- [ ] `getPrimitiveAlignSize`
- [ ] `getSizeOfAltPointer`
- [ ] `getSizeOfChar`
- [ ] `getSizeOfInt`
- [ ] `getSizeOfLong`
- [ ] `getSizeOfPointer`
- [ ] `getSizeOfWChar`
- [ ] `parseEnumConfig`
- [ ] `setCoreType`
- [ ] `setDisplayFormat`
- [ ] `setEnumValues`
- [x] `setFields` ✅
- [ ] `setPrototype`
- [ ] `setupSizes`
- [ ] `~TypeFactory`

## File: `varmap.hh`
### Class: `NameRecommend`
- [ ] `addr`
- [ ] `getName`
- [ ] `getSize`
- [ ] `getSymbolId`

### Class: `DynamicRecommend`
- [ ] `getHash`
- [ ] `getName`
- [ ] `getSymbolId`
- [ ] `usePoint`

### Class: `TypeRecommend`
- [ ] `addr`

### Class: `RangeHint`
- [ ] *No public functions*

### Class: `AliasChecker`
- [ ] `AddBase`

### Class: `MapState`
- [ ] `MapState`
- [ ] `gatherOpen`
- [ ] `gatherSymbols`
- [ ] `gatherVarnodes`
- [ ] `getNext`
- [ ] `initialize`
- [ ] `sortAlias`
- [ ] `turnOffDebug`
- [ ] `turnOnDebug`
- [ ] `~MapState`

### Class: `ScopeLocal`
- [ ] `addTypeRecommendation`
- [ ] `applyTypeRecommendations`
- [ ] `decode`
- [ ] `decodeWrappingAttributes`
- [ ] `encode`
- [ ] `hasOverlapProbems`
- [ ] `hasTypeRecommendations`
- [ ] `isUnaffectedStorage`
- [ ] `isUnmappedUnaliased`
- [ ] `markNotMapped`
- [ ] `recoverNameRecommendationsForSymbols`
- [ ] `resetLocalWindow`
- [ ] `restructureVarnode`
- [ ] `~ScopeLocal`

