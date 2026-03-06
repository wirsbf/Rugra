# `type_system/datatype.rs` API Reference

**源代码路径**: `src/type_system/datatype.rs`

## 模块说明 (Module Doc)

Datatype definitions for Rugra's type system

Corresponds to Ghidra's `type.hh`

## 导出的公共 API (Public API)

### `pub enum TypeMetatype`

Categories of types (type_metatype in Ghidra)

### `pub const CORETYPE: u32 = 1 << 0`

*暂无代码注释*

### `pub const CHARTYPE: u32 = 1 << 1`

*暂无代码注释*

### `pub const ENUMTYPE: u32 = 1 << 2`

*暂无代码注释*

### `pub const TYPEDEF: u32 = 1 << 3`

*暂无代码注释*

### `pub const VARLENGTH: u32 = 1 << 4`

*暂无代码注释*

### `pub const UTF16: u32 = 1 << 5`

*暂无代码注释*

### `pub const UTF32: u32 = 1 << 6`

*暂无代码注释*

### `pub const OPAQUE_STRUCT: u32 = 1 << 7`

*暂无代码注释*

### `pub struct TypeField`

A single field within a structure or union

Corresponds to Ghidra's `TypeField` class in `type.hh`

### `pub struct TypeBase`

Base structure for all data types containing common fields

### `pub fn new(name: String, size: usize, metatype: TypeMetatype) -> Self`

*暂无代码注释*

### `pub enum Datatype`

Represents a data type in the decompiler

Corresponds to Ghidra's `Datatype` class hierarchy in `type.hh`

### `pub fn get_name(&self) -> &str`

Get the name of the data type

### `pub fn get_size(&self) -> usize`

Get the size of the data type in bytes

### `pub fn get_metatype(&self) -> TypeMetatype`

Get the metatype of the data type

### `pub fn get_id(&self) -> u64`

Get the unique ID of the data type

### `pub fn is_coretype(&self) -> bool`

Returns true if this is a core type

### `pub fn is_variable_length(&self) -> bool`

Returns true if this type has a variable length

### `pub fn get_flags(&self) -> u32`

Get the internal flags of the data type

### `pub struct TypePointer`

Pointer data type

Corresponds to Ghidra's `TypePointer` class in `type.hh`

### `pub struct TypeArray`

Array data type

Corresponds to Ghidra's `TypeArray` class in `type.hh`

### `pub struct TypeStruct`

Structure data type

Corresponds to Ghidra's `TypeStruct` class in `type.hh`

### `pub struct TypeEnum`

Enumeration data type

Corresponds to Ghidra's `TypeEnum` class in `type.hh`

### `pub struct TypeUnion`

Union data type

Corresponds to Ghidra's `TypeUnion` class in `type.hh`

### `pub struct TypeCode`

Code/Function data type

Corresponds to Ghidra's `TypeCode` class in `type.hh`

### `pub struct TypeSpacebase`

Type representing a spacebase (e.g. stack frame, register bank)

Corresponds to Ghidra's `TypeSpacebase` class in `type.hh`

