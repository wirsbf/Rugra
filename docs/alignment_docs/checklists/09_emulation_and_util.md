# Rudra Alignment Checklist: 09 Emulation And Util

## File: `emulate.hh`
### Class: `BreakTable`
- [ ] `~BreakTable`

### Class: `BreakCallBack`
- [ ] `addressCallback`
- [ ] `pcodeCallback`
- [ ] `setEmulate`
- [ ] `~BreakCallBack`

### Class: `BreakTableCallBack`
- [ ] `doAddressBreak`
- [ ] `doPcodeOpBreak`
- [ ] `registerAddressCallback`
- [ ] `registerPcodeCallback`
- [ ] `setEmulate`

### Class: `Emulate`
- [ ] `executeCurrentOp`
- [ ] `getExecuteAddress`
- [ ] `getHalt`
- [ ] `setExecuteAddress`
- [ ] `setHalt`
- [ ] `~Emulate`

### Class: `EmulateMemory`
- [ ] `EmulateMemory`

### Class: `PcodeEmitCache`
- [ ] `dump`

### Class: `EmulatePcodeCache`
- [ ] `executeInstruction`
- [ ] `getCurrentOpIndex`
- [ ] `getExecuteAddress`
- [ ] `isInstructionStart`
- [ ] `numCurrentOps`
- [ ] `setExecuteAddress`
- [ ] `~EmulatePcodeCache`

### Class: `PutsCallBack`
- [ ] `addressCallback`

## File: `emulateutil.hh`
### Class: `EmulatePcodeOp`
- [ ] `getExecuteAddress`
- [ ] `getVarnodeValue`
- [ ] `setCurrentOp`
- [ ] `setVarnodeValue`

### Class: `EmulateSnippet`
- [ ] `checkForLegalCode`
- [ ] `getExecuteAddress`
- [ ] `getTempValue`
- [ ] `getVarnodeValue`
- [ ] `resetMemory`
- [ ] `setCurrentOp`
- [ ] `setExecuteAddress`
- [ ] `setVarnodeValue`
- [ ] `~EmulateSnippet`

## File: `filemanage.hh`
### Class: `FileManage`
- [ ] `addCurrentDir`
- [ ] `addDir2Path`
- [ ] `directoryList`
- [ ] `discoverGhidraRoot`
- [ ] `findFile`
- [ ] `isAbsolutePath`
- [ ] `isDirectory`
- [ ] `isSeparator`
- [ ] `matchList`
- [ ] `matchListDir`
- [ ] `scanDirectoryRecursive`
- [ ] `splitPath`

## File: `marshal.hh`
### Class: `AttributeId`
- [ ] `find`
- [ ] `getId`
- [ ] `initialize`

### Class: `ElementId`
- [ ] `find`
- [ ] `getId`
- [ ] `initialize`

### Class: `Decoder`
- [ ] `closeElement`
- [ ] `closeElementSkipping`
- [ ] `getIndexedAttributeId`
- [ ] `getNextAttributeId`
- [ ] `ingestStream`
- [ ] `openElement`
- [ ] `peekElement`
- [ ] `readBool`
- [ ] `readOpcode`
- [ ] `readSignedInteger`
- [ ] `readSignedIntegerExpectString`
- [ ] `readString`
- [ ] `readUnsignedInteger`
- [ ] `rewindAttributes`
- [ ] `skipElement`
- [ ] `~Decoder`

### Class: `Encoder`
- [ ] `closeElement`
- [ ] `openElement`
- [ ] `writeBool`
- [ ] `writeOpcode`
- [ ] `writeSignedInteger`
- [ ] `writeSpace`
- [ ] `writeString`
- [ ] `writeStringIndexed`
- [ ] `writeUnsignedInteger`
- [ ] `~Encoder`

### Class: `XmlDecode`
- [ ] `Decoder`
- [ ] `XmlDecode`
- [ ] `closeElement`
- [ ] `closeElementSkipping`
- [ ] `getIndexedAttributeId`
- [ ] `getNextAttributeId`
- [ ] `ingestStream`
- [ ] `openElement`
- [ ] `peekElement`
- [ ] `readBool`
- [ ] `readOpcode`
- [ ] `readSignedInteger`
- [ ] `readSignedIntegerExpectString`
- [ ] `readString`
- [ ] `readUnsignedInteger`
- [ ] `rewindAttributes`
- [ ] `~XmlDecode`

### Class: `PackedDecode`
- [ ] *No public functions*

### Class: `PackedEncode`
- [ ] `closeElement`
- [ ] `openElement`
- [ ] `outStream`
- [ ] `writeBool`
- [ ] `writeOpcode`
- [ ] `writeSignedInteger`
- [ ] `writeSpace`
- [ ] `writeString`
- [ ] `writeStringIndexed`
- [ ] `writeUnsignedInteger`

## File: `xml.hh`
### Class: `Attributes`
- [ ] `add_attribute`
- [ ] `getIndex`
- [ ] `getLength`
- [ ] `~Attributes`

### Class: `ContentHandler`
- [ ] `characters`
- [ ] `endDocument`
- [ ] `endPrefixMapping`
- [ ] `ignorableWhitespace`
- [ ] `processingInstruction`
- [ ] `setDocumentLocator`
- [ ] `setEncoding`
- [ ] `setError`
- [ ] `setVersion`
- [ ] `skippedEntity`
- [ ] `startDocument`
- [ ] `startPrefixMapping`
- [ ] `~ContentHandler`

### Class: `Element`
- [ ] `addAttribute`
- [ ] `addChild`
- [ ] `addContent`
- [ ] `getNumAttributes`
- [ ] `setName`
- [ ] `~Element`

### Class: `Document`
- [ ] `Element`

### Class: `TreeHandler`
- [ ] `characters`
- [ ] `endDocument`
- [ ] `endPrefixMapping`
- [ ] `ignorableWhitespace`
- [ ] `processingInstruction`
- [ ] `setDocumentLocator`
- [ ] `setEncoding`
- [ ] `setError`
- [ ] `setVersion`
- [ ] `skippedEntity`
- [ ] `startDocument`
- [ ] `startPrefixMapping`
- [ ] `~TreeHandler`

### Class: `DocumentStorage`
- [ ] `registerTag`

