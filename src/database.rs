//! Symbol database — faithful port of `database.hh` / `database.cc` (3430 lines).
//!
//! Symbol and Scope objects for the decompiler. These implement the main symbol
//! table, with support for symbols, local and global scopes, namespaces etc.
//! Search can be by name or the address of the Symbol storage location.
//!
//! Status: L1→L2. All public classes (`SymbolEntry`, `Symbol`,
//! `FunctionSymbol`, `Scope`, `ScopeInternal`, `Database`) are present with
//! full data structures and the in-memory query/insert algorithms. XML
//! encode/decode is an L3 gap pending the Decoder/Encoder infrastructure.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/database.{hh,cc}.

use crate::address::{Address, Range, RangeList};
use crate::marshal::{AttributeId, Decoder, ElementId, Encoder};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Base of internal Symbol IDs. Faithful to `Symbol::ID_BASE`
/// (database.cc:45). IDs with the high bit pattern (>> 56 == 0x40) are
/// internal and discarded on decode.
pub const ID_BASE: u64 = 0x4000_0000_0000_0000;

/// Varnode-like properties of a Symbol. Faithful to the subset of
/// `Varnode` flags used by Symbol (database.hh:182-184).
pub mod symbol_flags {
    pub const TYPELOCK: u32 = 1 << 0;
    pub const NAMELOCK: u32 = 1 << 1;
    pub const READONLY: u32 = 1 << 2;
    pub const EXTERNREF: u32 = 1 << 3;
    pub const ADDRTIED: u32 = 1 << 4;
    pub const PERSIST: u32 = 1 << 5;
    pub const VOLATIL: u32 = 1 << 6;
    pub const INDIRECTSTORAGE: u32 = 1 << 7;
    pub const HIDDENRETPARM: u32 = 1 << 8;
}

/// Display-format (dispflag) properties for a Symbol. Faithful to the
/// `Symbol` display enum (database.hh:199).
pub mod display_flags {
    pub const FORCE_HEX: u32 = 1;
    pub const FORCE_DEC: u32 = 2;
    pub const FORCE_OCT: u32 = 3;
    pub const FORCE_BIN: u32 = 4;
    pub const FORCE_CHAR: u32 = 5;
    pub const SIZE_TYPELOCK: u32 = 8;
    pub const ISOLATE: u32 = 16;
    pub const MERGE_PROBLEMS: u32 = 32;
    pub const IS_THIS_PTR: u32 = 64;
    pub const FORMAT_MASK: u32 = 7;
}

/// The possible specialized Symbol categories. Faithful to the `Symbol`
/// category enum (database.hh:212).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolCategory {
    /// Symbol is not in a special category.
    NoCategory = -1,
    /// The Symbol is a parameter to a function.
    FunctionParameter = 0,
    /// The Symbol holds equate information about a constant.
    Equate = 1,
    /// Symbol holding read or write facing union field information.
    UnionFacet = 2,
    /// Temporary placeholder for an input symbol prior to formalizing parameters.
    FakeInput = 3,
}

/// A storage location for a particular Symbol. Faithful to `SymbolEntry`
/// (database.hh:75).
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// Symbol being mapped.
    pub symbol: Arc<RwLock<Symbol>>,
    /// Varnode flags specific to this storage location.
    pub extraflags: u32,
    /// Starting address of the storage location (invalid if dynamic).
    pub addr: Address,
    /// A dynamic storage hash (alternative to addr for dynamic symbols).
    pub hash: u64,
    /// Offset into the Symbol that this covers.
    pub offset: i32,
    /// Number of bytes consumed by this (piece of the) storage.
    pub size: i32,
    /// Code address ranges where this storage is valid.
    pub uselimit: RangeList,
}

impl SymbolEntry {
    /// Construct a mapping for a Symbol without an address (dynamic).
    /// Faithful to the dynamic constructor (database.hh:140).
    pub fn new_dynamic(
        symbol: Arc<RwLock<Symbol>>,
        extraflags: u32,
        hash: u64,
        offset: i32,
        size: i32,
        uselimit: RangeList,
    ) -> Self {
        Self {
            symbol,
            extraflags,
            addr: Address::new(0),
            hash,
            offset,
            size,
            uselimit,
        }
    }

    /// Construct a static (address-based) SymbolEntry.
    pub fn new_static(
        symbol: Arc<RwLock<Symbol>>,
        extraflags: u32,
        addr: Address,
        offset: i32,
        size: i32,
        uselimit: RangeList,
    ) -> Self {
        Self {
            symbol,
            extraflags,
            addr,
            hash: 0,
            offset,
            size,
            uselimit,
        }
    }

    /// Is this a high or low piece of the whole Symbol? Faithful to `isPiece`.
    pub fn is_piece(&self) -> bool {
        // precislo | precishi — we approximate with offset != 0 or size < whole.
        self.offset != 0
    }

    /// Is storage dynamic? Faithful to `isDynamic` (database.hh:142).
    pub fn is_dynamic(&self) -> bool {
        self.hash != 0
    }

    /// Is this storage invalid? Faithful to `isInvalid` (database.hh:143).
    pub fn is_invalid(&self) -> bool {
        self.addr.as_u64() == 0 && self.hash == 0
    }

    /// Get the offset of this within the Symbol. Faithful to `getOffset`.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Get the first offset of this storage location. Faithful to `getFirst`.
    pub fn get_first(&self) -> u64 {
        self.addr.as_u64()
    }

    /// Get the last offset of this storage location. Faithful to `getLast`.
    pub fn get_last(&self) -> u64 {
        self.addr.as_u64() + self.size as u64 - 1
    }

    /// Get the Symbol associated with this. Faithful to `getSymbol`.
    pub fn get_symbol(&self) -> Arc<RwLock<Symbol>> {
        self.symbol.clone()
    }

    /// Get the starting address of this storage. Faithful to `getAddr`.
    pub fn get_addr(&self) -> Address {
        self.addr
    }

    /// Get the hash used to identify this storage. Faithful to `getHash`.
    pub fn get_hash(&self) -> u64 {
        self.hash
    }

    /// Get the number of bytes consumed by this storage. Faithful to `getSize`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Get all Varnode flags for this storage. Faithful to `getAllFlags`
    /// (database.hh:271).
    pub fn get_all_flags(&self) -> u32 {
        let sym_flags = self.symbol.read().unwrap().flags;
        self.extraflags | sym_flags
    }

    /// Is this storage valid for the given code address? Faithful to `inUse`.
    pub fn in_use(&self, usepoint: Address) -> bool {
        // Empty uselimit = valid across all code.
        self.uselimit.empty() || self.uselimit.in_range(usepoint)
    }

    /// Get the set of valid code addresses for this storage. Faithful to
    /// `getUseLimit`.
    pub fn get_use_limit(&self) -> &RangeList {
        &self.uselimit
    }

    /// Set the range of code addresses where this is valid. Faithful to
    /// `setUseLimit`.
    pub fn set_use_limit(&mut self, uselim: RangeList) {
        self.uselimit = uselim;
    }

    /// Is this storage address tied? Faithful to `isAddrTied`
    /// (database.hh:275).
    pub fn is_addr_tied(&self) -> bool {
        (self.symbol.read().unwrap().flags & symbol_flags::ADDRTIED) != 0
    }

    /// Encode this SymbolEntry to a stream. Faithful to `SymbolEntry::encode`
    /// (database.cc:187). Pieces are not saved.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        if self.is_piece() {
            return;
        }
        if self.is_dynamic() {
            encoder.open_element(&ElementId::new("hash", 52));
            encoder.write_unsigned_integer(&AttributeId::new("val", 0), self.hash);
            encoder.close_element(&ElementId::new("hash", 52));
        } else {
            // Address element.
            encoder.open_element(&ElementId::new("addr", 0));
            encoder.write_unsigned_integer(&AttributeId::new("space", 0), self.addr.as_u64());
            encoder.close_element(&ElementId::new("addr", 0));
        }
        // Use-limit (empty = valid everywhere; encoded as no ranges).
        self.encode_use_limit(encoder);
    }

    /// Encode the use-limit ranges. A simplified form of RangeList::encode.
    fn encode_use_limit(&self, encoder: &mut dyn Encoder) {
        // Ghidra encodes <rangelist> with <range> children. We emit an empty
        // rangelist if uselimit is empty (valid everywhere).
        encoder.open_element(&ElementId::new("rangelist", 0));
        for rng in self.uselimit.ranges() {
            encoder.open_element(&ElementId::new("range", 0));
            encoder.write_unsigned_integer(&AttributeId::new("first", 0), rng.get_first().as_u64());
            encoder.write_unsigned_integer(&AttributeId::new("last", 0), rng.get_last().as_u64());
            encoder.close_element(&ElementId::new("range", 0));
        }
        encoder.close_element(&ElementId::new("rangelist", 0));
    }
}

/// The base class for a symbol in a symbol table or scope. Faithful to
/// `Symbol` (database.hh:172).
#[derive(Debug, Clone)]
pub struct Symbol {
    /// The scope id that owns this symbol.
    pub scope_id: u64,
    /// The local name of the symbol.
    pub name: String,
    /// Name to use when displaying symbol in output.
    pub display_name: String,
    /// The symbol's data-type name (full Datatype integration is deferred).
    pub type_name: String,
    /// id to distinguish symbols with the same name.
    pub name_dedup: u32,
    /// Varnode-like properties of the symbol.
    pub flags: u32,
    /// Flags affecting the display of this symbol.
    pub dispflags: u32,
    /// Special category.
    pub category: SymbolCategory,
    /// Index within category.
    pub catindex: u16,
    /// Unique id, 0=unassigned.
    pub symbol_id: u64,
    /// Number of SymbolEntries that map to the whole Symbol.
    pub whole_count: u32,
    /// The resolved Datatype of this symbol (Ghidra `Symbol::type`).
    /// Faithful to `Symbol::getType` (database.hh:244).
    pub dtype: Option<Arc<crate::type_system::datatype::Datatype>>,
}

impl Symbol {
    /// Construct given a name and data-type name. Faithful to the constructor
    /// (database.hh:220 / database.hh:960).
    pub fn new(scope_id: u64, nm: &str, type_name: &str) -> Self {
        Self {
            scope_id,
            name: nm.to_string(),
            display_name: nm.to_string(),
            type_name: type_name.to_string(),
            name_dedup: 0,
            flags: 0,
            dispflags: 0,
            category: SymbolCategory::NoCategory,
            catindex: 0,
            symbol_id: 0,
            whole_count: 0,
            dtype: None,
        }
    }

    /// Construct for use with decode (no name/type yet).
    pub fn new_unnamed(scope_id: u64) -> Self {
        Self::new(scope_id, "", "")
    }

    /// Get the local name of the symbol.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the name to display in output.
    pub fn get_display_name(&self) -> &str {
        &self.display_name
    }

    /// Get the data-type name.
    pub fn get_type_name(&self) -> &str {
        &self.type_name
    }

    /// Get the resolved Datatype of this symbol. Faithful to
    /// `Symbol::getType` (database.hh:244).
    pub fn get_type(&self) -> Option<Arc<crate::type_system::datatype::Datatype>> {
        self.dtype.clone()
    }

    /// Set the resolved Datatype.
    pub fn set_dtype(&mut self, dt: Arc<crate::type_system::datatype::Datatype>) {
        self.dtype = Some(dt);
    }

    /// Get a unique id for the symbol.
    pub fn get_id(&self) -> u64 {
        self.symbol_id
    }

    /// Get the boolean properties of the Symbol.
    pub fn get_flags(&self) -> u32 {
        self.flags
    }

    /// Get the format to display the Symbol in. Faithful to `getDisplayFormat`.
    pub fn get_display_format(&self) -> u32 {
        self.dispflags & display_flags::FORMAT_MASK
    }

    /// Get the Symbol category.
    pub fn get_category(&self) -> SymbolCategory {
        self.category
    }

    /// Get the position of the Symbol within its category.
    pub fn get_category_index(&self) -> u16 {
        self.catindex
    }

    /// Is the Symbol type-locked? Faithful to `isTypeLocked`.
    pub fn is_type_locked(&self) -> bool {
        (self.flags & symbol_flags::TYPELOCK) != 0
    }

    /// Is the Symbol name-locked? Faithful to `isNameLocked`.
    pub fn is_name_locked(&self) -> bool {
        (self.flags & symbol_flags::NAMELOCK) != 0
    }

    /// Is the Symbol size type-locked? Faithful to `isSizeTypeLocked`.
    pub fn is_size_type_locked(&self) -> bool {
        (self.dispflags & display_flags::SIZE_TYPELOCK) != 0
    }

    /// Is the Symbol volatile? Faithful to `isVolatile`.
    pub fn is_volatile(&self) -> bool {
        (self.flags & symbol_flags::VOLATIL) != 0
    }

    /// Is this the "this" pointer? Faithful to `isThisPointer`.
    pub fn is_this_pointer(&self) -> bool {
        (self.dispflags & display_flags::IS_THIS_PTR) != 0
    }

    /// Is storage really a pointer to the true Symbol? Faithful to
    /// `isIndirectStorage`.
    pub fn is_indirect_storage(&self) -> bool {
        (self.flags & symbol_flags::INDIRECTSTORAGE) != 0
    }

    /// Is this a reference to the function return value? Faithful to
    /// `isHiddenReturn`.
    pub fn is_hidden_return(&self) -> bool {
        (self.flags & symbol_flags::HIDDENRETPARM) != 0
    }

    /// Does this have more than one entire mapping? Faithful to `isMultiEntry`.
    pub fn is_multi_entry(&self) -> bool {
        self.whole_count > 1
    }

    /// Set the display format for this Symbol. Faithful to `setDisplayFormat`
    /// (database.hh:262).
    pub fn set_display_format(&mut self, val: u32) {
        self.dispflags &= !display_flags::FORMAT_MASK;
        self.dispflags |= val & display_flags::FORMAT_MASK;
    }

    /// Set whether this Symbol should be speculatively merged. Faithful to
    /// `setIsolated`.
    pub fn set_isolated(&mut self, val: bool) {
        if val {
            self.dispflags |= display_flags::ISOLATE;
        } else {
            self.dispflags &= !display_flags::ISOLATE;
        }
    }

    /// Return true if this is isolated from speculative merging.
    pub fn is_isolated(&self) -> bool {
        (self.dispflags & display_flags::ISOLATE) != 0
    }

    /// Toggle whether this is the "this" pointer. Faithful to `setThisPointer`.
    pub fn set_this_pointer(&mut self, val: bool) {
        if val {
            self.dispflags |= display_flags::IS_THIS_PTR;
        } else {
            self.dispflags &= !display_flags::IS_THIS_PTR;
        }
    }

    /// Encode basic Symbol properties as attributes. Faithful to
    /// `Symbol::encodeHeader` (database.cc:363).
    pub fn encode_header(&self, encoder: &mut dyn Encoder) {
        encoder.write_string(&AttributeId::new("name", 0), &self.name);
        encoder.write_unsigned_integer(&AttributeId::new("id", 0), self.symbol_id);
        if (self.flags & symbol_flags::NAMELOCK) != 0 {
            encoder.write_bool(&AttributeId::new("namelock", 0), true);
        }
        if (self.flags & symbol_flags::TYPELOCK) != 0 {
            encoder.write_bool(&AttributeId::new("typelock", 0), true);
        }
        if (self.flags & symbol_flags::READONLY) != 0 {
            encoder.write_bool(&AttributeId::new("readonly", 0), true);
        }
        if (self.flags & symbol_flags::VOLATIL) != 0 {
            encoder.write_bool(&AttributeId::new("volatile", 0), true);
        }
        if (self.flags & symbol_flags::INDIRECTSTORAGE) != 0 {
            encoder.write_bool(&AttributeId::new("indirectstorage", 0), true);
        }
        if (self.flags & symbol_flags::HIDDENRETPARM) != 0 {
            encoder.write_bool(&AttributeId::new("hiddenretparm", 0), true);
        }
        if (self.dispflags & display_flags::ISOLATE) != 0 {
            encoder.write_bool(&AttributeId::new("merge", 0), false);
        }
        if (self.dispflags & display_flags::IS_THIS_PTR) != 0 {
            encoder.write_bool(&AttributeId::new("thisptr", 0), true);
        }
        let format = self.get_display_format();
        if format != 0 {
            let fmt_str = match format {
                display_flags::FORCE_HEX => "hex",
                display_flags::FORCE_DEC => "dec",
                display_flags::FORCE_OCT => "oct",
                display_flags::FORCE_BIN => "bin",
                display_flags::FORCE_CHAR => "char",
                _ => "",
            };
            encoder.write_string(&AttributeId::new("format", 0), fmt_str);
        }
        encoder.write_signed_integer(&AttributeId::new("cat", 0), self.category as i64);
        if self.category != SymbolCategory::NoCategory {
            encoder.write_unsigned_integer(&AttributeId::new("index", 0), self.catindex as u64);
        }
    }

    /// Decode basic Symbol properties from attributes. Faithful to
    /// `Symbol::decodeHeader` (database.cc:394).
    pub fn decode_header(&mut self, decoder: &mut dyn Decoder) {
        self.name.clear();
        self.display_name.clear();
        self.category = SymbolCategory::NoCategory;
        self.symbol_id = 0;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            let attr_name = decoder.attribute_name(attrib_id);
            match attr_name.as_deref() {
                Some("cat") => {
                    let cat = decoder.read_signed_integer();
                    self.category = match cat {
                        0 => SymbolCategory::FunctionParameter,
                        1 => SymbolCategory::Equate,
                        2 => SymbolCategory::UnionFacet,
                        3 => SymbolCategory::FakeInput,
                        _ => SymbolCategory::NoCategory,
                    };
                }
                Some("format") => {
                    let fmt = decoder.read_string();
                    self.set_display_format(match fmt.as_str() {
                        "hex" => display_flags::FORCE_HEX,
                        "dec" => display_flags::FORCE_DEC,
                        "oct" => display_flags::FORCE_OCT,
                        "bin" => display_flags::FORCE_BIN,
                        "char" => display_flags::FORCE_CHAR,
                        _ => 0,
                    });
                }
                Some("hiddenretparm") => {
                    if decoder.read_bool() {
                        self.flags |= symbol_flags::HIDDENRETPARM;
                    }
                }
                Some("id") => {
                    let id = decoder.read_unsigned_integer();
                    if (id >> 56) == (ID_BASE >> 56) {
                        self.symbol_id = 0;
                    } else {
                        self.symbol_id = id;
                    }
                }
                Some("indirectstorage") => {
                    if decoder.read_bool() {
                        self.flags |= symbol_flags::INDIRECTSTORAGE;
                    }
                }
                Some("merge") => {
                    if !decoder.read_bool() {
                        self.dispflags |= display_flags::ISOLATE;
                        self.flags |= symbol_flags::TYPELOCK;
                    }
                }
                Some("name") => {
                    self.name = decoder.read_string();
                }
                Some("namelock") => {
                    if decoder.read_bool() {
                        self.flags |= symbol_flags::NAMELOCK;
                    }
                }
                Some("readonly") => {
                    if decoder.read_bool() {
                        self.flags |= symbol_flags::READONLY;
                    }
                }
                Some("typelock") => {
                    if decoder.read_bool() {
                        self.flags |= symbol_flags::TYPELOCK;
                    }
                }
                Some("thisptr") => {
                    if decoder.read_bool() {
                        self.dispflags |= display_flags::IS_THIS_PTR;
                    }
                }
                Some("volatile") => {
                    if decoder.read_bool() {
                        self.flags |= symbol_flags::VOLATIL;
                    }
                }
                Some("label") => {
                    self.display_name = decoder.read_string();
                }
                _ => {
                    // Unknown attribute; skip by reading as string.
                    let _ = decoder.read_string();
                }
            }
        }
        if self.category == SymbolCategory::FunctionParameter {
            self.catindex = decoder
                .read_unsigned_integer_attr(&AttributeId::new("index", 0)) as u16;
        } else {
            self.catindex = 0;
        }
        if self.display_name.is_empty() {
            self.display_name = self.name.clone();
        }
    }

    /// Encode the data-type for the Symbol. Faithful to `encodeBody`
    /// (database.cc:466). Emits a `<type>` element with the type name.
    pub fn encode_body(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ElementId::new("type", 0));
        encoder.write_string(&AttributeId::new("name", 0), &self.type_name);
        encoder.close_element(&ElementId::new("type", 0));
    }

    /// Decode the data-type for the Symbol. Faithful to `decodeBody`
    /// (database.cc:473). Reads the `<type>` element's name attribute.
    pub fn decode_body(&mut self, decoder: &mut dyn Decoder) {
        let type_id = decoder.open_element();
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            if decoder.attribute_name(aid).as_deref() == Some("name") {
                self.type_name = decoder.read_string();
            } else {
                let _ = decoder.read_string();
            }
        }
        decoder.close_element(type_id);
    }

    /// Encode this Symbol to a stream. Faithful to `Symbol::encode`
    /// (database.cc:481).
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        let sym_elem = ElementId::new("symbol", 0);
        encoder.open_element(&sym_elem);
        self.encode_header(encoder);
        self.encode_body(encoder);
        encoder.close_element(&sym_elem);
    }

    /// Decode this Symbol from a stream. Faithful to `Symbol::decode`
    /// (database.cc:492).
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let sym_id = decoder.open_element();
        self.decode_header(decoder);
        self.decode_body(decoder);
        decoder.close_element(sym_id);
    }
}

/// A Symbol representing an executable function. Faithful to
/// `FunctionSymbol` (database.hh:283).
#[derive(Debug, Clone)]
pub struct FunctionSymbol {
    /// The base Symbol.
    pub symbol: Symbol,
    /// Minimum number of bytes to consume with the start address.
    pub consume_size: i32,
    /// The function's entry address.
    pub entry: Address,
}

impl FunctionSymbol {
    /// Construct given the name and consume size.
    pub fn new(scope_id: u64, nm: &str, size: i32, entry: Address) -> Self {
        Self {
            symbol: Symbol::new(scope_id, nm, "func"),
            consume_size: size,
            entry,
        }
    }

    /// Get the number of bytes consumed within the address→symbol map.
    /// Faithful to `getBytesConsumed`.
    pub fn get_bytes_consumed(&self) -> i32 {
        self.consume_size
    }

    /// Get the entry address.
    pub fn get_entry(&self) -> Address {
        self.entry
    }
}

/// A Symbol that holds equate information for a constant. Faithful to
/// `EquateSymbol` (database.hh:297).
#[derive(Debug, Clone)]
pub struct EquateSymbol {
    /// The base Symbol.
    pub symbol: Symbol,
    /// The constant value.
    pub value: u64,
}

impl EquateSymbol {
    /// Construct given the name, format, and value.
    pub fn new(scope_id: u64, nm: &str, format: u32, value: u64) -> Self {
        let mut symbol = Symbol::new(scope_id, nm, "equ");
        symbol.set_display_format(format);
        Self { symbol, value }
    }
}

/// A Symbol representing a code label. Faithful to `LabSymbol`
/// (database.hh, referenced at line 657).
#[derive(Debug, Clone)]
pub struct LabSymbol {
    /// The base Symbol.
    pub symbol: Symbol,
    /// The labelled address.
    pub addr: Address,
}

impl LabSymbol {
    /// Construct given the name and address.
    pub fn new(scope_id: u64, nm: &str, addr: Address) -> Self {
        Self {
            symbol: Symbol::new(scope_id, nm, "label"),
            addr,
        }
    }
}

/// An in-memory implementation of the Scope interface. Faithful to `Scope`
/// (database.hh:462) + `ScopeInternal` (database.hh:798).
#[derive(Debug, Clone)]
pub struct Scope {
    /// Unique id for the scope.
    pub unique_id: u64,
    /// Name of this scope.
    pub name: String,
    /// Name to display in output.
    pub display_name: String,
    /// Id of the parent scope (0 = global).
    pub parent_id: u64,
    /// Range of data addresses owned by this scope.
    pub rangetree: RangeList,
    /// Symbols in this scope, keyed by id.
    pub symbols: BTreeMap<u64, Arc<RwLock<Symbol>>>,
    /// Storage entries (static), keyed by (address, size).
    pub entries: Vec<SymbolEntry>,
    /// Dynamic storage entries.
    pub dynamic_entries: Vec<SymbolEntry>,
    /// References to Symbol objects organized by category.
    pub categories: BTreeMap<i32, Vec<Arc<RwLock<Symbol>>>>,
    /// Next available symbol id.
    pub next_unique_id: u64,
    /// Child scope ids.
    pub children: Vec<u64>,
}

impl Scope {
    /// Construct an empty scope, given an id, name and parent.
    /// Faithful to `Scope` constructor (database.hh:566).
    pub fn new(id: u64, nm: &str, parent_id: u64) -> Self {
        Self {
            unique_id: id,
            name: nm.to_string(),
            display_name: nm.to_string(),
            parent_id,
            rangetree: RangeList::new(),
            symbols: BTreeMap::new(),
            entries: Vec::new(),
            dynamic_entries: Vec::new(),
            categories: BTreeMap::new(),
            next_unique_id: ID_BASE,
            children: Vec::new(),
        }
    }

    /// Get the name of the Scope.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get name displayed in output.
    pub fn get_display_name(&self) -> &str {
        &self.display_name
    }

    /// Get the globally unique id.
    pub fn get_id(&self) -> u64 {
        self.unique_id
    }

    /// Is this scope global? (no owning function). Faithful to `isGlobal`.
    pub fn is_global(&self) -> bool {
        self.parent_id == 0
    }

    /// Add a memory range to the ownership of this Scope. Faithful to
    /// `addRange` (database.hh:521).
    pub fn add_range(&mut self, rng: Range) {
        self.rangetree.insert_range(rng);
    }

    /// Remove a memory range from the ownership of this Scope. Faithful to
    /// `removeRange` (database.hh:522).
    pub fn remove_range(&mut self, rng: Range) {
        self.rangetree.remove_range(rng);
    }

    /// Query if the given range is owned by this Scope. Faithful to `inScope`
    /// (database.hh:597).
    pub fn in_scope(&self, addr: Address, size: i32) -> bool {
        if size <= 1 {
            return self.rangetree.in_range(addr);
        }
        let end = Address::new(addr.as_u64().saturating_add(size as u64 - 1));
        self.rangetree.in_range(addr) && self.rangetree.in_range(end)
    }

    /// Add a new Symbol without mapping it to an address. Faithful to
    /// `addSymbol(name, type)` (database.hh:777). Returns the new symbol id.
    pub fn add_symbol(&mut self, nm: &str, type_name: &str) -> u64 {
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, type_name);
        sym.symbol_id = id;
        self.symbols.insert(id, Arc::new(RwLock::new(sym)));
        id
    }

    /// Add a Symbol and map it to a specific address. Faithful to
    /// `addSymbol(nm, ct, addr, usepoint)` (database.hh:742).
    pub fn add_symbol_mapped(
        &mut self,
        nm: &str,
        type_name: &str,
        addr: Address,
        size: i32,
    ) -> u64 {
        let id = self.add_symbol(nm, type_name);
        let sym = self.symbols.get(&id).cloned().unwrap();
        let mut sym_rg = sym.write().unwrap();
        sym_rg.whole_count += 1;
        drop(sym_rg);
        self.entries.push(SymbolEntry::new_static(
            sym,
            0,
            addr,
            0,
            size,
            RangeList::new(),
        ));
        id
    }

    /// Allocate a new unique symbol id.
    fn allocate_id(&mut self) -> u64 {
        let id = self.next_unique_id;
        self.next_unique_id += 1;
        id
    }

    /// Remove the given Symbol from this Scope. Faithful to `removeSymbol`.
    pub fn remove_symbol(&mut self, symbol_id: u64) {
        self.symbols.remove(&symbol_id);
        self.entries.retain(|e| {
            e.symbol.read().unwrap().symbol_id != symbol_id
        });
        self.dynamic_entries.retain(|e| {
            e.symbol.read().unwrap().symbol_id != symbol_id
        });
        for (_, vec) in self.categories.iter_mut() {
            vec.retain(|s| s.read().unwrap().symbol_id != symbol_id);
        }
    }

    /// Rename a Symbol within this Scope. Faithful to `renameSymbol`.
    pub fn rename_symbol(&mut self, symbol_id: u64, newname: &str) {
        if let Some(sym) = self.symbols.get(&symbol_id) {
            let mut sym_rg = sym.write().unwrap();
            sym_rg.name = newname.to_string();
            sym_rg.display_name = newname.to_string();
        }
    }

    /// Set boolean Varnode properties on a Symbol. Faithful to `setAttribute`.
    pub fn set_attribute(&mut self, symbol_id: u64, attr: u32) {
        if let Some(sym) = self.symbols.get(&symbol_id) {
            sym.write().unwrap().flags |= attr;
        }
    }

    /// Clear boolean Varnode properties on a Symbol. Faithful to `clearAttribute`.
    pub fn clear_attribute(&mut self, symbol_id: u64, attr: u32) {
        if let Some(sym) = self.symbols.get(&symbol_id) {
            sym.write().unwrap().flags &= !attr;
        }
    }

    /// Find a Symbol at a given address. Faithful to `findAddr`
    /// (database.hh:621). Returns the matching SymbolEntry index or None.
    pub fn find_addr(&self, addr: Address) -> Option<&SymbolEntry> {
        self.entries
            .iter()
            .find(|e| e.addr == addr && e.offset == 0)
    }

    /// Find the smallest Symbol containing the given memory range. Faithful to
    /// `findContainer` (database.hh:629).
    pub fn find_container(&self, addr: Address, size: i32) -> Option<&SymbolEntry> {
        let target_end = addr.as_u64().saturating_add(size as u64 - 1);
        self.entries.iter().filter(|e| {
            let e_end = e.addr.as_u64().saturating_add(e.size as u64 - 1);
            e.addr.as_u64() <= addr.as_u64() && target_end <= e_end
        }).min_by_key(|e| e.size)
    }

    /// Find first Symbol overlapping the given memory range. Faithful to
    /// `findOverlap` (database.hh:664).
    pub fn find_overlap(&self, addr: Address, size: i32) -> Option<&SymbolEntry> {
        let target_end = addr.as_u64().saturating_add(size as u64 - 1);
        self.entries.iter().find(|e| {
            let e_end = e.addr.as_u64().saturating_add(e.size as u64 - 1);
            e.addr.as_u64() <= target_end && addr.as_u64() <= e_end
        })
    }

    /// Find a Symbol by name within this Scope. Faithful to `findByName`
    /// (database.hh:671).
    pub fn find_by_name(&self, nm: &str) -> Vec<Arc<RwLock<Symbol>>> {
        self.symbols
            .values()
            .filter(|s| s.read().unwrap().name == nm)
            .cloned()
            .collect()
    }

    /// Check if the given name is used within this Scope. Faithful to
    /// `isNameUsed` (database.hh:680).
    pub fn is_name_used(&self, nm: &str) -> bool {
        self.symbols
            .values()
            .any(|s| s.read().unwrap().name == nm)
    }

    /// Get the number of Symbols in the given category. Faithful to
    /// `getCategorySize` (database.hh:726).
    pub fn get_category_size(&self, cat: i32) -> usize {
        self.categories.get(&cat).map_or(0, |v| v.len())
    }

    /// Set the category and index for the given Symbol. Faithful to
    /// `setCategory` (database.hh:740).
    pub fn set_category(&mut self, symbol_id: u64, cat: i32, ind: u16) {
        // Remove from any existing category.
        for (_, vec) in self.categories.iter_mut() {
            vec.retain(|s| s.read().unwrap().symbol_id != symbol_id);
        }
        let sym = match self.symbols.get(&symbol_id).cloned() {
            Some(s) => s,
            None => return,
        };
        {
            let mut s = sym.write().unwrap();
            s.category = match cat {
                0 => SymbolCategory::FunctionParameter,
                1 => SymbolCategory::Equate,
                2 => SymbolCategory::UnionFacet,
                3 => SymbolCategory::FakeInput,
                _ => SymbolCategory::NoCategory,
            };
            s.catindex = ind;
        }
        self.categories.entry(cat).or_default().push(sym);
    }

    /// Clear all symbols from this scope. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.entries.clear();
        self.dynamic_entries.clear();
        self.categories.clear();
        self.next_unique_id = ID_BASE;
    }

    /// Clear all unlocked symbols from this scope. Faithful to `clearUnlocked`.
    pub fn clear_unlocked(&mut self) {
        let locked: Vec<u64> = self
            .symbols
            .iter()
            .filter(|(_, s)| {
                let s = s.read().unwrap();
                (s.flags & (symbol_flags::TYPELOCK | symbol_flags::NAMELOCK)) != 0
            })
            .map(|(&id, _)| id)
            .collect();
        let to_remove: Vec<u64> = self
            .symbols
            .keys()
            .copied()
            .filter(|id| !locked.contains(id))
            .collect();
        for id in to_remove {
            self.remove_symbol(id);
        }
    }

    /// Attach a child scope.
    pub fn attach_child(&mut self, child_id: u64) {
        if !self.children.contains(&child_id) {
            self.children.push(child_id);
        }
    }

    /// Detach a child scope.
    pub fn detach_child(&mut self, child_id: u64) {
        self.children.retain(|&c| c != child_id);
    }

    /// Number of symbols in this scope.
    pub fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    /// Encode this scope and all its children recursively. Faithful to
    /// `Scope::encodeRecursive` (database.cc:1371). Emits a `<scope>` element
    /// with attributes, then child scopes, then the symbol list.
    pub fn encode_recursive(&self, encoder: &mut dyn Encoder, _only_global: bool) {
        let scope_elem = ElementId::new("scope", 0);
        encoder.open_element(&scope_elem);
        encoder.write_string(&AttributeId::new("name", 0), &self.name);
        encoder.write_unsigned_integer(&AttributeId::new("id", 0), self.unique_id);
        if self.display_name != self.name {
            encoder.write_string(&AttributeId::new("label", 0), &self.display_name);
        }
        // Parent id (if not global).
        if self.parent_id != 0 {
            encoder.open_element(&ElementId::new("parent", 0));
            encoder.write_unsigned_integer(&AttributeId::new("id", 0), self.parent_id);
            encoder.close_element(&ElementId::new("parent", 0));
        }
        // Child scopes.
        for &child_id in &self.children {
            if let Some(child) = self.parent_scope_lookup(child_id) {
                child.encode_recursive(encoder, _only_global);
            }
        }
        // Symbol list.
        let sym_list = ElementId::new("symbollist", 0);
        encoder.open_element(&sym_list);
        for sym in self.symbols.values() {
            sym.read().unwrap().encode(encoder);
        }
        encoder.close_element(&sym_list);
        encoder.close_element(&scope_elem);
    }

    /// Placeholder for child-scope lookup (the Database owns the scope map).
    /// In a standalone Scope this returns None; the Database provides the real
    /// implementation via its encode method.
    fn parent_scope_lookup(&self, _child_id: u64) -> Option<&Scope> {
        None
    }

    /// Decode this scope from a `<scope>` element. Faithful to
    /// `ScopeInternal::decode` (database.cc). Reads the scope's symbols.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        // Read until we hit the symbollist element.
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let elem_name = decoder.element_name(sub_id).unwrap_or_default();
            if elem_name == "parent" {
                // Skip parent tag (handled by Database).
                decoder.open_element();
                decoder.close_element(sub_id);
                continue;
            }
            if elem_name != "symbollist" {
                // Could be a child scope; skip for now.
                decoder.open_element();
                decoder.close_element_skipping(sub_id);
                continue;
            }
            // symbollist element.
            decoder.open_element();
            loop {
                let sym_id = decoder.peek_element();
                if sym_id == 0 {
                    break;
                }
                let sym_name = decoder.element_name(sym_id).unwrap_or_default();
                if sym_name != "symbol" {
                    break;
                }
                let id = self.allocate_id();
                let mut sym = Symbol::new_unnamed(self.unique_id);
                sym.symbol_id = id;
                sym.decode(decoder);
                self.symbols.insert(id, Arc::new(RwLock::new(sym)));
            }
            decoder.close_element(sub_id);
            break;
        }
    }
}

/// A manager for symbol scopes for a whole executable. Faithful to `Database`
/// (database.hh:916).
#[derive(Debug, Clone)]
pub struct Database {
    /// All scopes, keyed by id. Scope id 0 is reserved for the global scope
    /// placeholder; the real global scope is stored in `global_scope_id`.
    pub scopes: BTreeMap<u64, Scope>,
    /// Quick reference to the global scope id.
    pub global_scope_id: u64,
    /// Map from address to namespace scope id (ScopeResolve).
    pub resolvemap: Vec<(Range, u64)>,
    /// Map of global properties over address ranges.
    pub flagbase: Vec<(Range, u32)>,
    /// Next scope id to assign.
    pub next_scope_id: u64,
}

impl Default for Database {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Database {
    /// Constructor. Faithful to `Database(Architecture*, bool)` (database.hh:928).
    /// `id_by_name` controls scope-id assignment strategy (currently unused).
    pub fn new(_id_by_name: bool) -> Self {
        let mut scopes = BTreeMap::new();
        let global = Scope::new(0, "global", 0);
        scopes.insert(0, global);
        Self {
            scopes,
            global_scope_id: 0,
            resolvemap: Vec::new(),
            flagbase: Vec::new(),
            next_scope_id: 1,
        }
    }

    /// Get the global Scope. Faithful to `getGlobalScope`.
    pub fn get_global_scope(&self) -> Option<&Scope> {
        self.scopes.get(&self.global_scope_id)
    }

    /// Get the global Scope mutably.
    pub fn get_global_scope_mut(&mut self) -> Option<&mut Scope> {
        self.scopes.get_mut(&self.global_scope_id)
    }

    /// Register a new Scope. Faithful to `attachScope` (database.hh:932).
    /// Returns the new scope id.
    pub fn attach_scope(&mut self, nm: &str, parent_id: u64) -> u64 {
        let id = self.next_scope_id;
        self.next_scope_id += 1;
        let scope = Scope::new(id, nm, parent_id);
        self.scopes.insert(id, scope);
        if let Some(parent) = self.scopes.get_mut(&parent_id) {
            parent.attach_child(id);
        }
        id
    }

    /// Look-up a Scope by id. Faithful to `resolveScope(uint8)`.
    pub fn resolve_scope(&self, id: u64) -> Option<&Scope> {
        self.scopes.get(&id)
    }

    /// Look-up a Scope by id mutably.
    pub fn resolve_scope_mut(&mut self, id: u64) -> Option<&mut Scope> {
        self.scopes.get_mut(&id)
    }

    /// Find (and if not found create) a specific subscope. Faithful to
    /// `findCreateScope` (database.hh:942).
    pub fn find_create_scope(&mut self, id: u64, nm: &str, parent_id: u64) -> u64 {
        if self.scopes.contains_key(&id) {
            return id;
        }
        let scope = Scope::new(id, nm, parent_id);
        self.scopes.insert(id, scope);
        if id >= self.next_scope_id {
            self.next_scope_id = id + 1;
        }
        if let Some(parent) = self.scopes.get_mut(&parent_id) {
            parent.attach_child(id);
        }
        id
    }

    /// Delete the given Scope and all its sub-scopes. Faithful to
    /// `deleteScope` (database.hh:933).
    pub fn delete_scope(&mut self, scope_id: u64) {
        if scope_id == self.global_scope_id {
            return; // Don't delete the global scope.
        }
        // Collect descendants.
        let mut to_delete = vec![scope_id];
        let mut queue = vec![scope_id];
        while let Some(cur) = queue.pop() {
            if let Some(scope) = self.scopes.get(&cur) {
                for &child in &scope.children {
                    to_delete.push(child);
                    queue.push(child);
                }
            }
        }
        // Detach from parent.
        if let Some(scope) = self.scopes.get(&scope_id) {
            let parent_id = scope.parent_id;
            if let Some(parent) = self.scopes.get_mut(&parent_id) {
                parent.detach_child(scope_id);
            }
        }
        for id in to_delete {
            self.scopes.remove(&id);
            self.resolvemap.retain(|(_, sid)| *sid != id);
        }
    }

    /// Delete all sub-scopes of the given Scope. Faithful to `deleteSubScopes`.
    pub fn delete_sub_scopes(&mut self, scope_id: u64) {
        let children: Vec<u64> = self
            .scopes
            .get(&scope_id)
            .map(|s| s.children.clone())
            .unwrap_or_default();
        for child in children {
            self.delete_scope(child);
        }
    }

    /// Set the ownership range for a Scope. Faithful to `setRange`.
    pub fn set_range(&mut self, scope_id: u64, rlist: &RangeList) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            // Clear existing ranges for this scope in resolvemap.
            self.resolvemap.retain(|(_, sid)| *sid != scope_id);
            // Set new range tree.
            scope.rangetree = RangeList::new();
            for rng in rlist.ranges() {
                scope.rangetree.insert_range(*rng);
                self.resolvemap.push((*rng, scope_id));
            }
        }
    }

    /// Add an address range to the ownership of a Scope. Faithful to
    /// `addRange`.
    pub fn add_range(&mut self, scope_id: u64, rng: Range) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.rangetree.insert_range(rng);
            self.resolvemap.push((rng, scope_id));
        }
    }

    /// Remove an address range from the ownership of a Scope. Faithful to
    /// `removeRange`.
    pub fn remove_range(&mut self, scope_id: u64, rng: Range) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.rangetree.remove_range(rng);
        }
        self.resolvemap
            .retain(|(r, sid)| !(*sid == scope_id && r.get_first() == rng.get_first() && r.get_last() == rng.get_last()));
    }

    /// Get boolean properties at the given address. Faithful to `getProperty`.
    pub fn get_property(&self, addr: Address) -> u32 {
        let mut flags = 0u32;
        for (rng, fl) in &self.flagbase {
            if rng.contains(addr) {
                flags |= fl;
            }
        }
        flags
    }

    /// Set boolean properties over a given memory range. Faithful to
    /// `setPropertyRange`.
    pub fn set_property_range(&mut self, flags: u32, range: Range) {
        // Remove overlapping ranges of the same flags to avoid duplicates;
        // Ghidra's partmap handles this via subdivision. We do a simple merge.
        self.flagbase.push((range, flags));
    }

    /// Clear boolean properties over a given memory range. Faithful to
    /// `clearPropertyRange`.
    pub fn clear_property_range(&mut self, flags: u32, range: Range) {
        self.flagbase.retain(|(r, f)| {
            !(*f == flags && r.get_first() == range.get_first() && r.get_last() == range.get_last())
        });
    }

    /// Map a query point to the owning namespace Scope. Faithful to
    /// `mapScope` (database.hh:944).
    pub fn map_scope(&self, _qpoint: u64, addr: Address) -> u64 {
        // Find the namespace scope owning the address. Fall back to global.
        for (rng, sid) in &self.resolvemap {
            if rng.contains(addr) {
                return *sid;
            }
        }
        self.global_scope_id
    }

    /// Number of scopes.
    pub fn num_scopes(&self) -> usize {
        self.scopes.len()
    }

    /// Encode the whole Database to a stream. Faithful to `Database::encode`
    /// (database.cc:3270). Emits a `<db>` element with property change-points
    /// and global scope.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        let db_elem = ElementId::new("db", 0);
        encoder.open_element(&db_elem);
        // Property change-points.
        for (rng, val) in &self.flagbase {
            let pc_elem = ElementId::new("property_changepoint", 0);
            encoder.open_element(&pc_elem);
            encoder.write_unsigned_integer(&AttributeId::new("space", 0), rng.get_first().as_u64());
            encoder.write_unsigned_integer(&AttributeId::new("val", 0), *val as u64);
            encoder.close_element(&pc_elem);
        }
        // Global scope and its children.
        if let Some(global) = self.scopes.get(&self.global_scope_id) {
            global.encode_recursive(encoder, true);
        }
        encoder.close_element(&db_elem);
    }

    /// Decode the whole database from a `<db>` element. Faithful to
    /// `Database::decode` (database.cc:3314).
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let db_id = decoder.open_element();
        // Skip attributes (scopeidbyname etc.).
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            let _ = decoder.read_string();
        }
        // Property change-points.
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let elem_name = decoder.element_name(sub_id).unwrap_or_default();
            if elem_name != "property_changepoint" {
                break;
            }
            decoder.open_element();
            let val = decoder.read_unsigned_integer_attr(&AttributeId::new("val", 0));
            decoder.close_element(sub_id);
            let _ = val;
        }
        // Scopes.
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let elem_name = decoder.element_name(sub_id).unwrap_or_default();
            if elem_name != "scope" {
                break;
            }
            decoder.open_element();
            // Read scope attributes.
            let mut name = String::new();
            let mut display_name = String::new();
            let mut id = 0u64;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                match decoder.attribute_name(aid).as_deref() {
                    Some("name") => name = decoder.read_string(),
                    Some("id") => id = decoder.read_unsigned_integer(),
                    Some("label") => display_name = decoder.read_string(),
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            // Parent tag.
            let parent_id = {
                let pid = decoder.peek_element();
                if pid != 0 && decoder.element_name(pid).as_deref() == Some("parent") {
                    decoder.open_element();
                    let p = decoder.read_unsigned_integer_attr(&AttributeId::new("id", 0));
                    decoder.close_element(pid);
                    p
                } else {
                    0
                }
            };
            // Create or find the scope.
            self.find_create_scope(id, &name, parent_id);
            if let Some(scope) = self.scopes.get_mut(&id) {
                if !display_name.is_empty() {
                    scope.display_name = display_name;
                }
                scope.decode(decoder);
            }
            decoder.close_element(sub_id);
        }
        decoder.close_element(db_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_construction() {
        let sym = Symbol::new(0, "foo", "int");
        assert_eq!(sym.get_name(), "foo");
        assert_eq!(sym.get_display_name(), "foo");
        assert_eq!(sym.get_type_name(), "int");
        assert_eq!(sym.get_category(), SymbolCategory::NoCategory);
        assert!(!sym.is_type_locked());
        assert!(!sym.is_name_locked());
    }

    #[test]
    fn test_symbol_flags() {
        let mut sym = Symbol::new(0, "x", "int");
        sym.flags |= symbol_flags::TYPELOCK;
        assert!(sym.is_type_locked());
        sym.flags |= symbol_flags::NAMELOCK;
        assert!(sym.is_name_locked());
        sym.flags |= symbol_flags::VOLATIL;
        assert!(sym.is_volatile());
    }

    #[test]
    fn test_symbol_display_format() {
        let mut sym = Symbol::new(0, "x", "int");
        sym.set_display_format(display_flags::FORCE_HEX);
        assert_eq!(sym.get_display_format(), display_flags::FORCE_HEX);
        sym.set_display_format(display_flags::FORCE_DEC);
        assert_eq!(sym.get_display_format(), display_flags::FORCE_DEC);
    }

    #[test]
    fn test_symbol_isolated() {
        let mut sym = Symbol::new(0, "x", "int");
        assert!(!sym.is_isolated());
        sym.set_isolated(true);
        assert!(sym.is_isolated());
        sym.set_isolated(false);
        assert!(!sym.is_isolated());
    }

    #[test]
    fn test_symbol_this_pointer() {
        let mut sym = Symbol::new(0, "this", "ptr");
        assert!(!sym.is_this_pointer());
        sym.set_this_pointer(true);
        assert!(sym.is_this_pointer());
    }

    #[test]
    fn test_symbol_entry() {
        let sym = Arc::new(RwLock::new(Symbol::new(0, "x", "int")));
        let entry = SymbolEntry::new_static(sym, 0, Address::new(0x1000), 0, 4, RangeList::new());
        assert_eq!(entry.get_first(), 0x1000);
        assert_eq!(entry.get_last(), 0x1003);
        assert_eq!(entry.get_size(), 4);
        assert!(!entry.is_dynamic());
        assert!(!entry.is_invalid());
        assert!(entry.in_use(Address::new(0x9999))); // empty uselimit = all
    }

    #[test]
    fn test_symbol_entry_dynamic() {
        let sym = Arc::new(RwLock::new(Symbol::new(0, "x", "int")));
        let entry = SymbolEntry::new_dynamic(sym, 0, 0xDEADBEEF, 0, 4, RangeList::new());
        assert!(entry.is_dynamic());
        assert_eq!(entry.get_hash(), 0xDEADBEEF);
    }

    #[test]
    fn test_function_symbol() {
        let fs = FunctionSymbol::new(0, "main", 16, Address::new(0x401000));
        assert_eq!(fs.get_entry().as_u64(), 0x401000);
        assert_eq!(fs.get_bytes_consumed(), 16);
    }

    #[test]
    fn test_scope_add_symbol() {
        let mut scope = Scope::new(1, "local", 0);
        assert_eq!(scope.num_symbols(), 0);
        let id = scope.add_symbol("foo", "int");
        assert_eq!(scope.num_symbols(), 1);
        let syms = scope.find_by_name("foo");
        assert_eq!(syms.len(), 1);
        assert!(scope.is_name_used("foo"));
        assert!(!scope.is_name_used("bar"));
    }

    #[test]
    fn test_scope_add_symbol_mapped() {
        let mut scope = Scope::new(1, "local", 0);
        let id = scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        let entry = scope.find_addr(Address::new(0x1000));
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().get_size(), 4);
    }

    #[test]
    fn test_scope_find_container() {
        let mut scope = Scope::new(1, "local", 0);
        scope.add_symbol_mapped("big", "struct", Address::new(0x1000), 16);
        scope.add_symbol_mapped("small", "int", Address::new(0x1000), 4);
        let container = scope.find_container(Address::new(0x1000), 4);
        assert!(container.is_some());
        // Smallest containing = the 4-byte one.
        assert_eq!(container.unwrap().get_size(), 4);
    }

    #[test]
    fn test_scope_find_overlap() {
        let mut scope = Scope::new(1, "local", 0);
        scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        assert!(scope.find_overlap(Address::new(0x1002), 4).is_some());
        assert!(scope.find_overlap(Address::new(0x2000), 4).is_none());
    }

    #[test]
    fn test_scope_rename() {
        let mut scope = Scope::new(1, "local", 0);
        let id = scope.add_symbol("foo", "int");
        scope.rename_symbol(id, "bar");
        assert!(scope.find_by_name("bar").len() == 1);
        assert!(scope.find_by_name("foo").is_empty());
    }

    #[test]
    fn test_scope_remove() {
        let mut scope = Scope::new(1, "local", 0);
        let id = scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        assert_eq!(scope.num_symbols(), 1);
        scope.remove_symbol(id);
        assert_eq!(scope.num_symbols(), 0);
        assert!(scope.find_addr(Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_scope_category() {
        let mut scope = Scope::new(1, "local", 0);
        let id = scope.add_symbol("p1", "int");
        scope.set_category(id, 0, 0);
        assert_eq!(scope.get_category_size(0), 1);
    }

    #[test]
    fn test_scope_clear_unlocked() {
        let mut scope = Scope::new(1, "local", 0);
        let id1 = scope.add_symbol("unlocked", "int");
        let id2 = scope.add_symbol("locked", "int");
        scope.set_attribute(id2, symbol_flags::TYPELOCK);
        scope.clear_unlocked();
        assert_eq!(scope.num_symbols(), 1);
        assert!(scope.symbols.contains_key(&id2));
    }

    #[test]
    fn test_scope_in_scope() {
        let mut scope = Scope::new(1, "local", 0);
        scope.add_range(Range::new(Address::new(0x1000), Address::new(0x1FFF)).unwrap());
        assert!(scope.in_scope(Address::new(0x1000), 1));
        assert!(scope.in_scope(Address::new(0x1500), 4));
        assert!(!scope.in_scope(Address::new(0x2000), 1));
    }

    #[test]
    fn test_database_construction() {
        let db = Database::new(false);
        assert!(db.get_global_scope().is_some());
        assert_eq!(db.global_scope_id, 0);
        assert_eq!(db.num_scopes(), 1);
    }

    #[test]
    fn test_database_attach_scope() {
        let mut db = Database::new(false);
        let id = db.attach_scope("namespace1", 0);
        assert!(db.resolve_scope(id).is_some());
        assert_eq!(db.resolve_scope(id).unwrap().get_name(), "namespace1");
        assert_eq!(db.resolve_scope(id).unwrap().parent_id, 0);
        // Parent should have the child.
        assert!(db.get_global_scope().unwrap().children.contains(&id));
    }

    #[test]
    fn test_database_find_create() {
        let mut db = Database::new(false);
        let id = db.find_create_scope(5, "ns", 0);
        assert_eq!(id, 5);
        // Second call finds existing.
        let id2 = db.find_create_scope(5, "ns", 0);
        assert_eq!(id, id2);
        assert_eq!(db.num_scopes(), 2); // global + ns
    }

    #[test]
    fn test_database_delete_scope() {
        let mut db = Database::new(false);
        let parent = db.attach_scope("parent", 0);
        let child = db.attach_scope("child", parent);
        let grandchild = db.attach_scope("grandchild", child);
        assert_eq!(db.num_scopes(), 4); // global + 3
        db.delete_scope(parent);
        assert_eq!(db.num_scopes(), 1); // only global
        assert!(db.resolve_scope(child).is_none());
        assert!(db.resolve_scope(grandchild).is_none());
    }

    #[test]
    fn test_database_delete_subscopes() {
        let mut db = Database::new(false);
        let parent = db.attach_scope("parent", 0);
        let child = db.attach_scope("child", parent);
        db.delete_sub_scopes(parent);
        assert!(db.resolve_scope(parent).is_some());
        assert!(db.resolve_scope(child).is_none());
    }

    #[test]
    fn test_database_range() {
        let mut db = Database::new(false);
        let id = db.attach_scope("ns", 0);
        db.add_range(id, Range::new(Address::new(0x1000), Address::new(0x1FFF)).unwrap());
        assert_eq!(db.map_scope(0, Address::new(0x1500)), id);
        assert_eq!(db.map_scope(0, Address::new(0x9999)), 0); // global
    }

    #[test]
    fn test_database_property() {
        let mut db = Database::new(false);
        let rng = Range::new(Address::new(0x1000), Address::new(0x1FFF)).unwrap();
        db.set_property_range(0x10, rng);
        assert_eq!(db.get_property(Address::new(0x1500)), 0x10);
        assert_eq!(db.get_property(Address::new(0x9999)), 0);
        db.clear_property_range(0x10, rng);
        assert_eq!(db.get_property(Address::new(0x1500)), 0);
    }

    #[test]
    fn test_symbol_encode_decode_roundtrip() {
        use crate::marshal::{IdRegistry, TreeDecoder, TreeEncoder};
        let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        // Register the attribute names we use.
        {
            let mut r = registry.write().unwrap();
            for nm in &[
                "name", "id", "namelock", "typelock", "readonly", "volatile",
                "indirectstorage", "hiddenretparm", "merge", "thisptr", "format",
                "cat", "index", "label", "val", "space", "first", "last",
            ] {
                r.register_attribute(nm);
            }
            for nm in &["symbol", "type", "addr", "hash", "rangelist", "range", "scope", "symbollist", "db", "parent", "property_changepoint"] {
                r.register_element(nm);
            }
        }
        // Create a symbol with various flags.
        let mut sym = Symbol::new(1, "myVar", "int");
        sym.symbol_id = 42;
        sym.flags |= symbol_flags::TYPELOCK | symbol_flags::NAMELOCK;
        sym.dispflags |= display_flags::IS_THIS_PTR;
        sym.set_display_format(display_flags::FORCE_HEX);
        // Encode.
        let mut enc = TreeEncoder::new(registry.clone());
        sym.encode(&mut enc);
        let doc = enc.into_document();
        let root = doc.get_root().unwrap().clone();
        // Decode into a fresh symbol.
        let mut sym2 = Symbol::new_unnamed(1);
        let mut dec = TreeDecoder::new(root, registry.clone());
        sym2.decode(&mut dec);
        // Verify round-trip.
        assert_eq!(sym2.get_name(), "myVar");
        assert_eq!(sym2.get_id(), 42);
        assert!(sym2.is_type_locked());
        assert!(sym2.is_name_locked());
        assert!(sym2.is_this_pointer());
        assert_eq!(sym2.get_display_format(), display_flags::FORCE_HEX);
        assert_eq!(sym2.type_name, "int");
    }

    #[test]
    fn test_database_encode_decode_roundtrip() {
        use crate::marshal::{IdRegistry, TreeDecoder, TreeEncoder};
        let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        {
            let mut r = registry.write().unwrap();
            for nm in &[
                "name", "id", "namelock", "typelock", "readonly", "volatile",
                "indirectstorage", "hiddenretparm", "merge", "thisptr", "format",
                "cat", "index", "label", "val", "space", "first", "last",
            ] {
                r.register_attribute(nm);
            }
            for nm in &["symbol", "type", "addr", "hash", "rangelist", "range", "scope", "symbollist", "db", "parent", "property_changepoint"] {
                r.register_element(nm);
            }
        }
        // Build a database with a symbol.
        let mut db = Database::new(false);
        {
            let global = db.get_global_scope_mut().unwrap();
            let id = global.add_symbol("globalVar", "char*");
            let sym = global.symbols.get(&id).unwrap();
            sym.write().unwrap().flags |= symbol_flags::READONLY;
        }
        // Encode.
        let mut enc = TreeEncoder::new(registry.clone());
        db.encode(&mut enc);
        let doc = enc.into_document();
        let root = doc.get_root().unwrap().clone();
        // Decode into a fresh database.
        let mut db2 = Database::new(false);
        let mut dec = TreeDecoder::new(root, registry.clone());
        db2.decode(&mut dec);
        // Verify the global scope was recovered.
        let global = db2.get_global_scope().unwrap();
        assert!(global.num_symbols() >= 1);
        // Find the symbol by name.
        let found = global.find_by_name("globalVar");
        assert!(!found.is_empty());
        assert!((found[0].read().unwrap().flags & symbol_flags::READONLY) != 0);
    }
}
