# Rudra Alignment Checklist: 07 Decompilation Process

## File: `architecture.hh`
### Class: `Statistics`
- [ ] `countCast`
- [ ] `printResults`
- [ ] `process`
- [ ] `~Statistics`

### Class: `ArchitectureCapability`
- [ ] `getMajorVersion`
- [ ] `getMinorVersion`
- [ ] `initialize`
- [ ] `isFileMatch`
- [ ] `isXmlMatch`
- [ ] `sortCapabilities`

### Class: `Architecture`
- [ ] `Architecture`
- [ ] `clearAnalysis`
- [ ] `collectBehaviors`
- [ ] `decodeFlowOverride`
- [ ] `encode`
- [ ] `getDescription`
- [ ] `getMinimumLanedRegisterSize`
- [ ] `globalify`
- [ ] `hasModel`
- [ ] `highPtrPossible`
- [ ] `init`
- [ ] `nameFunction`
- [ ] `printDebug`
- [ ] `printMessage`
- [ ] `readLoaderSymbols`
- [ ] `resetDefaults`
- [ ] `resetDefaultsInternal`
- [ ] `restoreXml`
- [ ] `setDebugStream`
- [ ] `setDefaultModel`
- [ ] `setPrintLanguage`
- [ ] `setPrototype`
- [ ] `~Architecture`

### Class: `SegmentedResolver`
- [ ] `SegmentedResolver`
- [ ] `resolve`

## File: `capability.hh`
### Class: `CapabilityPoint`
- [ ] `initialize`
- [ ] `initializeAll`
- [ ] `~CapabilityPoint`

## File: `ghidra_arch.hh`
### Class: `ArchitectureGhidra`
- [ ] `clearWarnings`
- [ ] `getBytes`
- [ ] `getCPoolRef`
- [ ] `getCodeLabel`
- [ ] `getComments`
- [ ] `getDataType`
- [ ] `getExternalRef`
- [ ] `getMappedSymbolsXML`
- [ ] `getNamespacePath`
- [ ] `getPcode`
- [ ] `getPcodeInject`
- [ ] `getRegister`
- [ ] `getRegisterName`
- [ ] `getSendCCode`
- [ ] `getSendParamMeasures`
- [ ] `getSendSyntaxTree`
- [ ] `getStringData`
- [ ] `getTrackedRegisters`
- [ ] `getUserOpName`
- [ ] `isDynamicSymbolName`
- [ ] `isNameUsed`
- [ ] `passJavaException`
- [ ] `printMessage`
- [ ] `readAll`
- [ ] `readBoolStream`
- [ ] `readResponseEnd`
- [ ] `readStringStream`
- [ ] `readToAnyBurst`
- [ ] `readToResponse`
- [ ] `segvHandler`
- [ ] `setSendCCode`
- [ ] `setSendParamMeasures`
- [ ] `setSendSyntaxTree`
- [ ] `writeStringStream`

## File: `ghidra_process.hh`
### Class: `GhidraCapability`
- [ ] `readCommand`
- [ ] `shutDown`

### Class: `GhidraDecompCapability`
- [ ] `initialize`

### Class: `GhidraCommand`
- [ ] `doit`
- [ ] `rawAction`
- [ ] `sin`
- [ ] `~GhidraCommand`

### Class: `RegisterProgram`
- [ ] `rawAction`

### Class: `DeregisterProgram`
- [ ] `rawAction`

### Class: `FlushNative`
- [ ] `rawAction`

### Class: `DecompileAt`
- [ ] `rawAction`

### Class: `StructureGraph`
- [ ] `rawAction`

### Class: `SetAction`
- [ ] `rawAction`

### Class: `SetOptions`
- [ ] `SetOptions`
- [ ] `rawAction`
- [ ] `~SetOptions`

## File: `funcdata.hh`
### Class: `Funcdata`
- [x] `new` ✅
- [x] `set_self_ref` ✅
- [x] `get_name` ✅
- [x] `get_address` ✅
- [x] `get_size` ✅
- [x] `clear` ✅
- [x] `num_heritage_passes` ✅

