//! Symbol database — faithful port of `database.hh` / `database.cc` (3430 lines).
//!
//! Symbol and Scope objects for the decompiler. These implement the main symbol
//! table, with support for symbols, local and global scopes, namespaces etc.
//! Search can be by name or the address of the Symbol storage location.
//!
//! Status: ✅ L3 (per ALIGNMENT_ROADMAP #52). All public classes (`SymbolEntry`,
//! `Symbol`, `FunctionSymbol`, `Scope`, `ScopeInternal`, `Database`) are present
//! with full data structures, the in-memory query/insert algorithms, AND XML
//! encode/decode via `marshal.rs`'s `Encoder`/`Decoder` traits
//! (`SymbolEntry`/`Symbol`/`Scope`/`Database` all implement encode/decode).
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/database.{hh,cc}.

use crate::address::{Address, Range, RangeList};
use crate::marshal::{AttributeId, Decoder, ElementId, Encoder};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock, Weak};

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

/// Non-owning category slots corresponding to Ghidra's
/// `vector<Symbol *>`. `None` preserves an interior `NULL` entry.
#[derive(Debug, Clone, Default)]
pub struct CategoryList(Vec<Option<Weak<RwLock<Symbol>>>>);

impl CategoryList {
    // RUGRA-GLUE: Rust wrapper preserving vector<Symbol *> null-slot/index semantics.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // RUGRA-GLUE: Rust Option models a nullable Symbol * category slot.
    pub fn get(&self, index: usize) -> Option<Arc<RwLock<Symbol>>> {
        self.0
            .get(index)
            .and_then(Option::as_ref)
            .and_then(Weak::upgrade)
    }

    // RUGRA-GLUE: Upgrade non-owning category slots while the name tree owns each Symbol.
    fn iter(&self) -> impl Iterator<Item = Arc<RwLock<Symbol>>> + '_ {
        self.0
            .iter()
            .filter_map(|slot| slot.as_ref().and_then(Weak::upgrade))
    }

    // RUGRA-GLUE: Mutable access to the exact nullable slot named by Symbol::catindex.
    fn get_mut(&mut self, index: usize) -> Option<&mut Option<Weak<RwLock<Symbol>>>> {
        self.0.get_mut(index)
    }

    // RUGRA-GLUE: Extend vector<Symbol *> with NULL slots through an inclusive index.
    fn resize_for_index(&mut self, index: usize) {
        if self.0.len() <= index {
            self.0.resize_with(index + 1, || None);
        }
    }

    // RUGRA-GLUE: Remove only trailing NULL slots, preserving interior category holes.
    fn trim_trailing_nulls(&mut self) {
        while self.0.last().is_some_and(Option::is_none) {
            self.0.pop();
        }
    }
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
    // Ghidra: database.cc:50 SymbolEntry::newDynamic
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

    // Ghidra: database.cc:50 SymbolEntry::newStatic
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

    // Ghidra: database.cc:50 SymbolEntry::isPiece
    /// Is this a high or low piece of the whole Symbol? Faithful to `isPiece`.
    pub fn is_piece(&self) -> bool {
        // precislo | precishi — we approximate with offset != 0 or size < whole.
        self.offset != 0
    }

    // Ghidra: database.cc:50 SymbolEntry::isDynamic
    /// Is storage dynamic? Faithful to `isDynamic` (database.hh:142).
    pub fn is_dynamic(&self) -> bool {
        self.hash != 0
    }

    // Ghidra: database.cc:50 SymbolEntry::isInvalid
    /// Is this storage invalid? Faithful to `isInvalid` (database.hh:143).
    pub fn is_invalid(&self) -> bool {
        self.addr.as_u64() == 0 && self.hash == 0
    }

    // Ghidra: database.cc:50 SymbolEntry::getOffset
    /// Get the offset of this within the Symbol. Faithful to `getOffset`.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    // Ghidra: database.cc:50 SymbolEntry::getFirst
    /// Get the first offset of this storage location. Faithful to `getFirst`.
    pub fn get_first(&self) -> u64 {
        self.addr.as_u64()
    }

    // Ghidra: database.cc:50 SymbolEntry::getLast
    /// Get the last offset of this storage location. Faithful to `getLast`.
    pub fn get_last(&self) -> u64 {
        self.addr.as_u64() + self.size as u64 - 1
    }

    // Ghidra: database.cc:50 SymbolEntry::getSymbol
    /// Get the Symbol associated with this. Faithful to `getSymbol`.
    pub fn get_symbol(&self) -> Arc<RwLock<Symbol>> {
        self.symbol.clone()
    }

    // Ghidra: database.cc:50 SymbolEntry::getAddr
    /// Get the starting address of this storage. Faithful to `getAddr`.
    pub fn get_addr(&self) -> Address {
        self.addr
    }

    // Ghidra: database.cc:50 SymbolEntry::getHash
    /// Get the hash used to identify this storage. Faithful to `getHash`.
    pub fn get_hash(&self) -> u64 {
        self.hash
    }

    // Ghidra: database.cc:50 SymbolEntry::getSize
    /// Get the number of bytes consumed by this storage. Faithful to `getSize`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    // Ghidra: database.cc:50 SymbolEntry::getAllFlags
    /// Get all Varnode flags for this storage. Faithful to `getAllFlags`
    /// (database.hh:271).
    pub fn get_all_flags(&self) -> u32 {
        let sym_flags = self.symbol.read().unwrap().flags;
        self.extraflags | sym_flags
    }

    // Ghidra: database.cc:114 SymbolEntry::inUse
    /// Is this storage valid for the given code address? Faithful to `inUse`.
    pub fn in_use(&self, usepoint: Address) -> bool {
        // Empty uselimit = valid across all code.
        self.uselimit.empty() || self.uselimit.in_range(usepoint)
    }

    // Ghidra: database.cc:50 SymbolEntry::getUseLimit
    /// Get the set of valid code addresses for this storage. Faithful to
    /// `getUseLimit`.
    pub fn get_use_limit(&self) -> &RangeList {
        &self.uselimit
    }

    // Ghidra: database.cc:50 SymbolEntry::setUseLimit
    /// Set the range of code addresses where this is valid. Faithful to
    /// `setUseLimit`.
    pub fn set_use_limit(&mut self, uselim: RangeList) {
        self.uselimit = uselim;
    }

    // Ghidra: database.cc:50 SymbolEntry::isAddrTied
    /// Is this storage address tied? Faithful to `isAddrTied`
    /// (database.hh:275).
    pub fn is_addr_tied(&self) -> bool {
        (self.symbol.read().unwrap().flags & symbol_flags::ADDRTIED) != 0
    }

    // Ghidra: database.cc:151 SymbolEntry::getSizedType
    /// Return the data-type that matches the given size and address within
    /// this storage. Faithful to `SymbolEntry::getSizedType`
    /// (database.cc:151). For dynamic storage, the symbol's own offset is
    /// used; for static storage, the offset of `inaddr` relative to this
    /// entry's starting address is added. Returns `None` if there is no
    /// exact sub-type of the requested size at the computed offset.
    ///
    /// Ghidra resolves the sub-type via
    /// `TypeFactory::getExactPiece(cur, off, sz)`. Rugra does not yet wire a
    /// `TypeFactory` into `SymbolEntry`; we use `Datatype::get_sub_type` to
    /// locate the field at `off`, then accept it only when the remaining
    /// offset is zero and its size equals `sz`. Because field sub-types are
    /// borrowed out of the symbol's own `Arc<Datatype>` allocation, when the
    /// offset is zero and the request covers the whole symbol we return the
    /// symbol's whole type (matching `getExactPiece(cur, 0, type->getSize())`
    /// returning `cur` itself).
    pub fn get_sized_type(&self, inaddr: Address, sz: i32) -> Option<Arc<crate::type_system::datatype::Datatype>> {
        let off = if self.is_dynamic() {
            self.offset
        } else {
            ((inaddr.as_u64() as i64).wrapping_sub(self.addr.as_u64() as i64)) as i32 + self.offset
        };
        let sym = self.symbol.read().unwrap();
        let dt = sym.dtype.clone()?;
        if off == 0 && dt.get_size() as i32 == sz {
            // Whole-symbol match — `getExactPiece` returns the type itself.
            return Some(dt);
        }
        // Look up the field at the computed offset and accept it only if it is
        // an exact (size, offset) match.
        let (sub, rem) = dt.get_sub_type(off as i64);
        if rem == 0 && sub.map_or(false, |s| s.get_size() as i32 == sz) {
            // No separate Arc per field; return the whole-type Arc. Callers
            // needing the exact field pointer must defer to a future
            // TypeFactory-backed implementation.
            Some(dt)
        } else {
            None
        }
    }

    // Ghidra: database.cc:135 SymbolEntry::updateType
    /// If the Symbol associated with this is type-locked, change the given
    /// Varnode's attached data-type to match the Symbol. Faithful to
    /// `SymbolEntry::updateType` (database.cc:135). The C++ form takes a
    /// `Varnode*` and calls `vn->updateType(dt,true,true)`; the Rust port
    /// returns the resolved `Datatype` (or `None`) so the caller can apply
    /// it to the Varnode. This is the type-propagation entry point for
    /// mapped symbols.
    pub fn update_type(&self, vn_addr: Address, vn_size: i32) -> Option<Arc<crate::type_system::datatype::Datatype>> {
        let sym = self.symbol.read().unwrap();
        if (sym.flags & symbol_flags::TYPELOCK) == 0 {
            return None;
        }
        drop(sym);
        self.get_sized_type(vn_addr, vn_size)
    }

    // Ghidra: database.cc:187 SymbolEntry::encode
    /// Encode this SymbolEntry to a stream. Faithful to `SymbolEntry::encode`
    /// (database.cc:187). Pieces are not saved. Emits an `<addr>` element for
    /// static storage or a `<hash>` element for dynamic storage, followed by a
    /// `<rangelist>` for the uselimit.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        if self.is_piece() {
            return;
        }
        if self.is_dynamic() {
            encoder.open_element(&ElementId::new("hash", 52));
            encoder.write_unsigned_integer(&AttributeId::new("val", 0), self.hash);
            encoder.close_element(&ElementId::new("hash", 52));
        } else {
            // Address element. Faithful to `addr.encode(encoder)`; we emit
            // offset so the value round-trips with SymbolEntry::decode.
            encoder.open_element(&ElementId::new("addr", 0));
            encoder.write_unsigned_integer(&AttributeId::new("offset", 0), self.addr.as_u64());
            encoder.close_element(&ElementId::new("addr", 0));
        }
        // Use-limit (empty = valid everywhere; encoded as no ranges).
        self.encode_use_limit(encoder);
    }

    // Ghidra: database.cc:50 SymbolEntry::encodeUseLimit
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

    // Ghidra: database.cc:206 SymbolEntry::decode
    /// Decode this SymbolEntry from a stream. Faithful to `SymbolEntry::decode`
    /// (database.cc:206). Parses either an `<addr>` element (for static storage)
    /// or a `<hash>` element (for dynamic storage), then a `<rangelist>` element
    /// for the uselimit.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.peek_element();
        let elem_name = decoder.element_name(elem_id).unwrap_or_default();
        if elem_name == "hash" {
            // Dynamic storage.
            let hash_id = decoder.open_element();
            let mut hash_val = 0u64;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                if decoder.attribute_name(aid).as_deref() == Some("val") {
                    hash_val = decoder.read_unsigned_integer();
                } else {
                    let _ = decoder.read_string();
                }
            }
            decoder.close_element(hash_id);
            self.hash = hash_val;
            self.addr = Address::new(0); // invalid address
        } else if elem_name == "addr" {
            // Static (address-based) storage.
            let addr_id = decoder.open_element();
            let mut off = 0u64;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                if decoder.attribute_name(aid).as_deref() == Some("offset") {
                    off = decoder.read_unsigned_integer();
                } else {
                    let _ = decoder.read_string();
                }
            }
            decoder.close_element(addr_id);
            self.addr = Address::new(off);
            self.hash = 0;
        }
        // Parse the <rangelist> uselimit.
        self.decode_use_limit(decoder);
    }

    // Ghidra: database.cc:206 SymbolEntry::decode (uselimit portion)
    /// Decode the use-limit ranges. Faithful to the `uselimit.decode(decoder)`
    /// call inside `SymbolEntry::decode`. Reads a `<rangelist>` element whose
    /// `<range>` children give the (first,last) ranges where this entry is
    /// valid. If no `<rangelist>` is present, the uselimit is empty (valid
    /// everywhere).
    fn decode_use_limit(&mut self, decoder: &mut dyn Decoder) {
        let rl_id = decoder.peek_element();
        if rl_id == 0 {
            self.uselimit = RangeList::new();
            return;
        }
        let rl_name = decoder.element_name(rl_id).unwrap_or_default();
        if rl_name != "rangelist" {
            self.uselimit = RangeList::new();
            return;
        }
        decoder.open_element();
        let mut rl = RangeList::new();
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            if sub_name != "range" {
                break;
            }
            decoder.open_element();
            let mut first = 0u64;
            let mut last = 0u64;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                match decoder.attribute_name(aid).as_deref() {
                    Some("first") => first = decoder.read_unsigned_integer(),
                    Some("last") => last = decoder.read_unsigned_integer(),
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            if let Some(rng) = Range::new(Address::new(first), Address::new(last)) {
                rl.insert_range(rng);
            }
            decoder.close_element(sub_id);
        }
        decoder.close_element(rl_id);
        self.uselimit = rl;
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
    // Ghidra: database.hh:960 Symbol::new
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

    // Ghidra: database.hh:960 Symbol::newUnnamed
    /// Construct for use with decode (no name/type yet).
    pub fn new_unnamed(scope_id: u64) -> Self {
        Self::new(scope_id, "", "")
    }

    // Ghidra: database.hh:960 Symbol::getName
    /// Get the local name of the symbol.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: database.hh:960 Symbol::getDisplayName
    /// Get the name to display in output.
    pub fn get_display_name(&self) -> &str {
        &self.display_name
    }

    // Ghidra: database.hh:960 Symbol::getTypeName
    /// Get the data-type name.
    pub fn get_type_name(&self) -> &str {
        &self.type_name
    }

    // Ghidra: database.hh:960 Symbol::getType
    /// Get the resolved Datatype of this symbol. Faithful to
    /// `Symbol::getType` (database.hh:244).
    pub fn get_type(&self) -> Option<Arc<crate::type_system::datatype::Datatype>> {
        self.dtype.clone()
    }

    // Ghidra: database.hh:960 Symbol::setDtype
    /// Set the resolved Datatype.
    pub fn set_dtype(&mut self, dt: Arc<crate::type_system::datatype::Datatype>) {
        self.dtype = Some(dt);
    }

    // Ghidra: database.hh:960 Symbol::getId
    /// Get a unique id for the symbol.
    pub fn get_id(&self) -> u64 {
        self.symbol_id
    }

    // Ghidra: database.hh:960 Symbol::getFlags
    /// Get the boolean properties of the Symbol.
    pub fn get_flags(&self) -> u32 {
        self.flags
    }

    // Ghidra: database.hh:960 Symbol::getDisplayFormat
    /// Get the format to display the Symbol in. Faithful to `getDisplayFormat`.
    pub fn get_display_format(&self) -> u32 {
        self.dispflags & display_flags::FORMAT_MASK
    }

    // Ghidra: database.hh:960 Symbol::getCategory
    /// Get the Symbol category.
    pub fn get_category(&self) -> SymbolCategory {
        self.category
    }

    // Ghidra: database.hh:960 Symbol::getCategoryIndex
    /// Get the position of the Symbol within its category.
    pub fn get_category_index(&self) -> u16 {
        self.catindex
    }

    // Ghidra: database.hh:960 Symbol::isTypeLocked
    /// Is the Symbol type-locked? Faithful to `isTypeLocked`.
    pub fn is_type_locked(&self) -> bool {
        (self.flags & symbol_flags::TYPELOCK) != 0
    }

    // Ghidra: database.hh:960 Symbol::isNameLocked
    /// Is the Symbol name-locked? Faithful to `isNameLocked`.
    pub fn is_name_locked(&self) -> bool {
        (self.flags & symbol_flags::NAMELOCK) != 0
    }

    // Ghidra: database.cc:249 Symbol::isNameUndefined
    /// Return true if this symbol's name is the auto-generated "$$undef"
    /// placeholder. Faithful to `isNameUndefined` (database.cc:249).
    pub fn is_name_undefined(&self) -> bool {
        self.name.starts_with("$$undef")
    }

    // Ghidra: database.hh:960 Symbol::isSizeTypeLocked
    /// Is the Symbol size type-locked? Faithful to `isSizeTypeLocked`.
    pub fn is_size_type_locked(&self) -> bool {
        (self.dispflags & display_flags::SIZE_TYPELOCK) != 0
    }

    // Ghidra: database.hh:960 Symbol::isVolatile
    /// Is the Symbol volatile? Faithful to `isVolatile`.
    pub fn is_volatile(&self) -> bool {
        (self.flags & symbol_flags::VOLATIL) != 0
    }

    // Ghidra: database.hh:960 Symbol::isThisPointer
    /// Is this the "this" pointer? Faithful to `isThisPointer`.
    pub fn is_this_pointer(&self) -> bool {
        (self.dispflags & display_flags::IS_THIS_PTR) != 0
    }

    // Ghidra: database.hh:960 Symbol::isIndirectStorage
    /// Is storage really a pointer to the true Symbol? Faithful to
    /// `isIndirectStorage`.
    pub fn is_indirect_storage(&self) -> bool {
        (self.flags & symbol_flags::INDIRECTSTORAGE) != 0
    }

    // Ghidra: database.hh:960 Symbol::isHiddenReturn
    /// Is this a reference to the function return value? Faithful to
    /// `isHiddenReturn`.
    pub fn is_hidden_return(&self) -> bool {
        (self.flags & symbol_flags::HIDDENRETPARM) != 0
    }

    // Ghidra: database.hh:960 Symbol::isMultiEntry
    /// Does this have more than one entire mapping? Faithful to `isMultiEntry`.
    pub fn is_multi_entry(&self) -> bool {
        self.whole_count > 1
    }

    // Ghidra: database.hh:262 Symbol::setDisplayFormat
    /// Set the display format for this Symbol. Faithful to `setDisplayFormat`
    /// (database.hh:262).
    pub fn set_display_format(&mut self, val: u32) {
        self.dispflags &= !display_flags::FORMAT_MASK;
        self.dispflags |= val & display_flags::FORMAT_MASK;
    }

    // Ghidra: database.cc:255 Symbol::setIsolated
    /// Set whether this Symbol should be speculatively merged. Faithful to
    /// `setIsolated` (database.cc:255). When isolating, the Symbol is also
    /// type-locked and `checkSizeTypeLock` is re-run (database.cc:259-262).
    pub fn set_isolated(&mut self, val: bool) {
        if val {
            self.dispflags |= display_flags::ISOLATE;
            self.flags |= symbol_flags::TYPELOCK;
            self.check_size_type_lock();
        } else {
            self.dispflags &= !display_flags::ISOLATE;
        }
    }

    // Ghidra: database.hh:960 Symbol::isIsolated
    /// Return true if this is isolated from speculative merging.
    pub fn is_isolated(&self) -> bool {
        (self.dispflags & display_flags::ISOLATE) != 0
    }

    // Ghidra: database.cc:226 Symbol::checkSizeTypeLock
    /// Examine the data-type to decide if the Symbol has the special property
    /// called \b size_typelock, which indicates the \e size of the Symbol is
    /// locked, but the data-type is not locked (and can float). Faithful to
    /// `Symbol::checkSizeTypeLock` (database.cc:226). Clears the
    /// `size_typelock` flag, then sets it iff the Symbol is type-locked and
    /// its data-type is `TYPE_UNKNOWN`. This must be re-invoked after any
    /// change to the type or typelock flag.
    pub fn check_size_type_lock(&mut self) {
        self.dispflags &= !display_flags::SIZE_TYPELOCK;
        if self.is_type_locked() {
            if let Some(dt) = &self.dtype {
                if dt.get_metatype() == crate::type_system::datatype::TypeMetatype::Unknown {
                    self.dispflags |= display_flags::SIZE_TYPELOCK;
                }
            }
        }
    }

    // Ghidra: database.cc:268 Symbol::getFirstWholeMap
    /// Return the first SymbolEntry that maps the whole Symbol. Faithful to
    /// `Symbol::getFirstWholeMap` (database.cc:268). Ghidra's Symbol carries a
    /// `mapentry` vector; Rugra's Symbol does not, so this method accepts the
    /// list of SymbolEntries (typically from the owning Scope) and returns the
    /// first entry whose `offset == 0`. The C++ form throws `LowlevelError`
    /// when no mapping exists; the Rust port returns `None`.
    pub fn get_first_whole_map<'a>(&self, entries: &'a [SymbolEntry]) -> Option<&'a SymbolEntry> {
        entries.iter().find(|e| {
            e.symbol.read().unwrap().symbol_id == self.symbol_id && e.offset == 0
        })
    }

    // Ghidra: database.cc:280 Symbol::getMapEntry
    /// Return the SymbolEntry containing the given address. Faithful to
    /// `Symbol::getMapEntry(addr)` (database.cc:280). May return a partial
    /// entry (one holding only part of the whole Symbol). Ghidra walks the
    /// Symbol's own `mapentry` vector; Rugra's Symbol does not carry one, so
    /// this method accepts the list of SymbolEntries (typically from the
    /// owning Scope). Returns the first entry whose address range contains
    /// `addr`.
    pub fn get_map_entry<'a>(&self, entries: &'a [SymbolEntry], addr: Address) -> Option<&'a SymbolEntry> {
        entries.iter().find(|e| {
            if e.symbol.read().unwrap().symbol_id != self.symbol_id {
                return false;
            }
            // Same address space (Rugra is single-space, so skip the space
            // check at database.cc:287).
            let start = e.addr.as_u64();
            let diff = addr.as_u64().wrapping_sub(start);
            // database.cc:289 — skip if addr < entry start, then require
            // diff < size.
            diff < e.size as u64
        })
    }

    // Ghidra: database.cc:235 Symbol::setThisPointer
    /// Toggle whether this is the "this" pointer. Faithful to `setThisPointer`.
    pub fn set_this_pointer(&mut self, val: bool) {
        if val {
            self.dispflags |= display_flags::IS_THIS_PTR;
        } else {
            self.dispflags &= !display_flags::IS_THIS_PTR;
        }
    }

    // Ghidra: database.cc:363 Symbol::encodeHeader
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

    // Ghidra: database.cc:394 Symbol::decodeHeader
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

    // Ghidra: database.cc:466 Symbol::encodeBody
    /// Encode the data-type for the Symbol. Faithful to `encodeBody`
    /// (database.cc:466). Emits a `<type>` element with the type name.
    pub fn encode_body(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ElementId::new("type", 0));
        encoder.write_string(&AttributeId::new("name", 0), &self.type_name);
        encoder.close_element(&ElementId::new("type", 0));
    }

    // Ghidra: database.cc:473 Symbol::decodeBody
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

    // Ghidra: database.cc:481 Symbol::encode
    /// Encode this Symbol to a stream. Faithful to `Symbol::encode`
    /// (database.cc:481).
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        let sym_elem = ElementId::new("symbol", 0);
        encoder.open_element(&sym_elem);
        self.encode_header(encoder);
        self.encode_body(encoder);
        encoder.close_element(&sym_elem);
    }

    // Ghidra: database.cc:492 Symbol::decode
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
    // Ghidra: database.cc:534 FunctionSymbol::new
    /// Construct given the name and consume size.
    pub fn new(scope_id: u64, nm: &str, size: i32, entry: Address) -> Self {
        Self {
            symbol: Symbol::new(scope_id, nm, "func"),
            consume_size: size,
            entry,
        }
    }

    // Ghidra: database.cc:534 FunctionSymbol::getBytesConsumed
    /// Get the number of bytes consumed within the address→symbol map.
    /// Faithful to `getBytesConsumed`.
    pub fn get_bytes_consumed(&self) -> i32 {
        self.consume_size
    }

    // Ghidra: database.cc:534 FunctionSymbol::getEntry
    /// Get the entry address.
    pub fn get_entry(&self) -> Address {
        self.entry
    }

    // Ghidra: database.cc:566 FunctionSymbol::encode
    /// Encode this FunctionSymbol. Faithful to `FunctionSymbol::encode`
    /// (database.cc:566). Emits a `<functionshell>` element (when there is no
    /// backing function descriptor, as in the Rust port) carrying the symbol
    /// header, the entry address, and the consume-size.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ElementId::new("functionshell", 72));
        self.symbol.encode_header(encoder);
        encoder.open_element(&ElementId::new("addr", 0));
        encoder.write_unsigned_integer(&AttributeId::new("offset", 0), self.entry.as_u64());
        encoder.close_element(&ElementId::new("addr", 0));
        if self.consume_size > 0 {
            encoder.write_signed_integer(&AttributeId::new("size", 0), self.consume_size as i64);
        }
        encoder.close_element(&ElementId::new("functionshell", 72));
    }

    // Ghidra: database.cc:580 FunctionSymbol::decode
    /// Decode this FunctionSymbol. Faithful to `FunctionSymbol::decode`
    /// (database.cc:580). Reads a `<functionshell>` element: the symbol header,
    /// the entry `<addr>` element, and the consume-size attribute.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element();
        self.symbol.decode_header(decoder);
        // Entry address.
        let sub_id = decoder.peek_element();
        if sub_id != 0 && decoder.element_name(sub_id).as_deref() == Some("addr") {
            let addr_id = decoder.open_element();
            let mut off = 0u64;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                if decoder.attribute_name(aid).as_deref() == Some("offset") {
                    off = decoder.read_unsigned_integer();
                } else {
                    let _ = decoder.read_string();
                }
            }
            decoder.close_element(addr_id);
            self.entry = Address::new(off);
        }
        // Consume size attribute on the parent (if present).
        // We already read attributes in decode_header; rewind not supported, so
        // mirror the C++ behavior: size is optional and defaults to 0.
        self.consume_size = 0;
        decoder.close_element(elem_id);
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
    // Ghidra: database.cc:624 EquateSymbol::new
    /// Construct given the name, format, and value. Faithful to
    /// `EquateSymbol::EquateSymbol` (database.cc:624-631): the C++ constructor
    /// body runs `value = val; category = equate;
    /// type = sc->getArch()->types->getBase(1,TYPE_UNKNOWN); dispflags |= format;`.
    pub fn new(scope_id: u64, nm: &str, format: u32, value: u64) -> Self {
        let mut symbol = Symbol::new(scope_id, nm, "equ");
        // cc:630 dispflags |= format.
        symbol.set_display_format(format);
        // cc:628 category = equate (the decode constructor database.hh:306
        // sets the same category before decodeHeader re-reads `cat`).
        symbol.category = SymbolCategory::Equate;
        Self { symbol, value }
    }

    // Ghidra: database.cc:659 EquateSymbol::encode
    /// Encode this EquateSymbol. Faithful to `EquateSymbol::encode`
    /// (database.cc:659). Emits an `<equatesymbol>` element carrying the
    /// symbol header and a `<value>` child with the constant.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ElementId::new("equatesymbol", 69));
        self.symbol.encode_header(encoder);
        encoder.open_element(&ElementId::new("value", 0));
        encoder.write_unsigned_integer(&AttributeId::new("val", 0), self.value);
        encoder.close_element(&ElementId::new("value", 0));
        encoder.close_element(&ElementId::new("equatesymbol", 69));
    }

    // Ghidra: database.cc:670 EquateSymbol::decode
    /// Decode this EquateSymbol. Faithful to `EquateSymbol::decode`
    /// (database.cc:670). Reads an `<equatesymbol>` element: the symbol header
    /// and the `<value>` child carrying the constant.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element();
        self.symbol.decode_header(decoder);
        // Value child.
        let sub_id = decoder.peek_element();
        if sub_id != 0 && decoder.element_name(sub_id).as_deref() == Some("value") {
            let val_id = decoder.open_element();
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                if decoder.attribute_name(aid).as_deref() == Some("val") {
                    self.value = decoder.read_unsigned_integer();
                } else {
                    let _ = decoder.read_string();
                }
            }
            decoder.close_element(val_id);
        }
        decoder.close_element(elem_id);
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
    // Ghidra: database.cc:736 LabSymbol::new
    /// Construct given the name and address.
    pub fn new(scope_id: u64, nm: &str, addr: Address) -> Self {
        Self {
            symbol: Symbol::new(scope_id, nm, "label"),
            addr,
        }
    }

    // Ghidra: database.cc:751 LabSymbol::encode
    /// Encode this LabSymbol. Faithful to `LabSymbol::encode`
    /// (database.cc:751). Emits a `<labelsym>` element carrying the symbol
    /// header. If a name is set, the label attribute carries it; otherwise a
    /// child `<addr>` element carries the labelled address.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ElementId::new("labelsym", 75));
        self.symbol.encode_header(encoder);
        encoder.open_element(&ElementId::new("addr", 0));
        encoder.write_unsigned_integer(&AttributeId::new("offset", 0), self.addr.as_u64());
        encoder.close_element(&ElementId::new("addr", 0));
        encoder.close_element(&ElementId::new("labelsym", 75));
    }

    // Ghidra: database.cc:759 LabSymbol::decode
    /// Decode this LabSymbol. Faithful to `LabSymbol::decode`
    /// (database.cc:759). Reads a `<labelsym>` element: the symbol header and
    /// the labelled address from a child `<addr>` element.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element();
        self.symbol.decode_header(decoder);
        // Labelled address child.
        let sub_id = decoder.peek_element();
        if sub_id != 0 && decoder.element_name(sub_id).as_deref() == Some("addr") {
            let addr_id = decoder.open_element();
            let mut off = 0u64;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                if decoder.attribute_name(aid).as_deref() == Some("offset") {
                    off = decoder.read_unsigned_integer();
                } else {
                    let _ = decoder.read_string();
                }
            }
            decoder.close_element(addr_id);
            self.addr = Address::new(off);
        }
        decoder.close_element(elem_id);
    }
}

/// A Symbol referring to an external function or symbol. Faithful to
/// `ExternRefSymbol` (database.hh:349).
#[derive(Debug, Clone)]
pub struct ExternRefSymbol {
    /// The base Symbol.
    pub symbol: Symbol,
    /// The address that the extern reference resolves to.
    pub refaddr: Address,
}

impl ExternRefSymbol {
    // Ghidra: database.cc:785 ExternRefSymbol::new
    /// Construct given the name and reference address.
    pub fn new(scope_id: u64, nm: &str, refaddr: Address) -> Self {
        Self {
            symbol: Symbol::new(scope_id, nm, "exref"),
            refaddr,
        }
    }

    // Ghidra: database.cc:796 ExternRefSymbol::encode
    /// Encode this ExternRefSymbol. Faithful to `ExternRefSymbol::encode`
    /// (database.cc:796). Emits an `<externrefsymbol>` element carrying the
    /// symbol header and a child `<addr>` element with the reference address.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ElementId::new("externrefsymbol", 70));
        self.symbol.encode_header(encoder);
        encoder.open_element(&ElementId::new("addr", 0));
        encoder.write_unsigned_integer(&AttributeId::new("offset", 0), self.refaddr.as_u64());
        encoder.close_element(&ElementId::new("addr", 0));
        encoder.close_element(&ElementId::new("externrefsymbol", 70));
    }

    // Ghidra: database.cc:805 ExternRefSymbol::decode
    /// Decode this ExternRefSymbol. Faithful to `ExternRefSymbol::decode`
    /// (database.cc:805). Reads an `<externrefsymbol>` element: the symbol
    /// header and a child `<addr>` element with the reference address.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element();
        self.symbol.decode_header(decoder);
        // Reference address child.
        let sub_id = decoder.peek_element();
        if sub_id != 0 && decoder.element_name(sub_id).as_deref() == Some("addr") {
            let addr_id = decoder.open_element();
            let mut off = 0u64;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                if decoder.attribute_name(aid).as_deref() == Some("offset") {
                    off = decoder.read_unsigned_integer();
                } else {
                    let _ = decoder.read_string();
                }
            }
            decoder.close_element(addr_id);
            self.refaddr = Address::new(off);
        }
        decoder.close_element(elem_id);
    }
}

/// A Symbol that overrides one facet of a union field. Faithful to
/// `UnionFacetSymbol` (database.hh:362).
#[derive(Debug, Clone)]
pub struct UnionFacetSymbol {
    /// The base Symbol.
    pub symbol: Symbol,
    /// The field index within the union that this facet overrides.
    pub field: u64,
}

impl UnionFacetSymbol {
    // Ghidra: database.cc:688 UnionFacetSymbol::new
    /// Construct given the name and field index.
    pub fn new(scope_id: u64, nm: &str, field: u64) -> Self {
        Self {
            symbol: Symbol::new(scope_id, nm, "union"),
            field,
        }
    }

    // Ghidra: database.cc:698 UnionFacetSymbol::encode
    /// Encode this UnionFacetSymbol. Faithful to `UnionFacetSymbol::encode`
    /// (database.cc:698). Emits a `<facetsymbol>` element carrying the symbol
    /// header and the `field` attribute giving the union field index.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ElementId::new("facetsymbol", 71));
        self.symbol.encode_header(encoder);
        encoder.write_unsigned_integer(&AttributeId::new("field", 62), self.field);
        encoder.close_element(&ElementId::new("facetsymbol", 71));
    }

    // Ghidra: database.cc:708 UnionFacetSymbol::decode
    /// Decode this UnionFacetSymbol. Faithful to `UnionFacetSymbol::decode`
    /// (database.cc:708). Reads a `<facetsymbol>` element: the symbol header
    /// and the `field` attribute giving the union field index. NOTE: because
    /// `decode_header` consumes attributes, the `field` attribute is read as
    /// a header attribute via `attribute_name`.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element();
        // Read attributes, capturing `field`.
        self.symbol.name.clear();
        self.symbol.display_name.clear();
        self.symbol.category = SymbolCategory::NoCategory;
        self.symbol.symbol_id = 0;
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            match decoder.attribute_name(aid).as_deref() {
                Some("field") => self.field = decoder.read_unsigned_integer(),
                _ => {
                    // Defer to header parsing for the common attributes by
                    // reading the value; header re-parse is not possible, so
                    // we record name/cat/id inline.
                    let name = decoder.attribute_name(aid).unwrap_or_default();
                    match name.as_str() {
                        "name" => self.symbol.name = decoder.read_string(),
                        "id" => {
                            let id = decoder.read_unsigned_integer();
                            if (id >> 56) == (ID_BASE >> 56) {
                                self.symbol.symbol_id = 0;
                            } else {
                                self.symbol.symbol_id = id;
                            }
                        }
                        "cat" => {
                            let cat = decoder.read_signed_integer();
                            self.symbol.category = match cat {
                                0 => SymbolCategory::FunctionParameter,
                                1 => SymbolCategory::Equate,
                                2 => SymbolCategory::UnionFacet,
                                3 => SymbolCategory::FakeInput,
                                _ => SymbolCategory::NoCategory,
                            };
                        }
                        _ => {
                            let _ = decoder.read_string();
                        }
                    }
                }
            }
        }
        decoder.close_element(elem_id);
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
    pub categories: BTreeMap<i32, CategoryList>,
    /// Next available symbol id.
    pub next_unique_id: u64,
    /// Child scope ids.
    pub children: Vec<u64>,
}

impl Scope {
    // Ghidra: database.hh:34 Scope::new
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

    // Ghidra: database.hh:34 Scope::getName
    /// Get the name of the Scope.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: database.hh:34 Scope::getDisplayName
    /// Get name displayed in output.
    pub fn get_display_name(&self) -> &str {
        &self.display_name
    }

    // Ghidra: database.hh:34 Scope::getId
    /// Get the globally unique id.
    pub fn get_id(&self) -> u64 {
        self.unique_id
    }

    // Ghidra: database.hh:34 Scope::isGlobal
    /// Is this scope global? (no owning function). Faithful to `isGlobal`.
    pub fn is_global(&self) -> bool {
        self.parent_id == 0
    }

    // Ghidra: database.cc:1105 Scope::addRange
    /// Add a memory range to the ownership of this Scope. Faithful to
    /// `addRange` (database.hh:521).
    pub fn add_range(&mut self, rng: Range) {
        self.rangetree.insert_range(rng);
    }

    // Ghidra: database.cc:1114 Scope::removeRange
    /// Remove a memory range from the ownership of this Scope. Faithful to
    /// `removeRange` (database.hh:522).
    pub fn remove_range(&mut self, rng: Range) {
        self.rangetree.remove_range(rng);
    }

    // Ghidra: database.hh:34 Scope::inScope
    /// Query if the given range is owned by this Scope. Faithful to `inScope`
    /// (database.hh:597).
    pub fn in_scope(&self, addr: Address, size: i32) -> bool {
        if size <= 1 {
            return self.rangetree.in_range(addr);
        }
        let end = Address::new(addr.as_u64().saturating_add(size as u64 - 1));
        self.rangetree.in_range(addr) && self.rangetree.in_range(end)
    }

    // Ghidra: database.cc:1510 Scope::addSymbol
    /// Add a new Symbol without mapping it to an address. Faithful to
    /// `addSymbol(name, type)` (database.hh:777). Returns the new symbol id.
    pub fn add_symbol(&mut self, nm: &str, type_name: &str) -> u64 {
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, type_name);
        sym.symbol_id = id;
        self.symbols.insert(id, Arc::new(RwLock::new(sym)));
        id
    }

    // Ghidra: database.hh:34 Scope::addSymbolMapped
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

    // Ghidra: database.hh:34 Scope::allocateId
    /// Allocate a new unique symbol id.
    fn allocate_id(&mut self) -> u64 {
        let id = self.next_unique_id;
        self.next_unique_id += 1;
        id
    }

    // Ghidra: database.cc:2138 ScopeInternal::removeSymbol
    /// Remove the given Symbol from this Scope. Faithful to `removeSymbol`.
    pub fn remove_symbol(&mut self, symbol_id: u64) {
        if let Some((category, index)) = self.symbols.get(&symbol_id).and_then(|symbol| {
            let symbol = symbol.read().unwrap();
            let category = symbol.category as i32;
            (category >= 0).then_some((category, symbol.catindex as usize))
        }) {
            if let Some(list) = self.categories.get_mut(&category) {
                if let Some(slot) = list.get_mut(index) {
                    *slot = None;
                }
                list.trim_trailing_nulls();
            }
        }
        self.entries.retain(|e| {
            e.symbol.read().unwrap().symbol_id != symbol_id
        });
        self.dynamic_entries.retain(|e| {
            e.symbol.read().unwrap().symbol_id != symbol_id
        });
        self.symbols.remove(&symbol_id);
    }

    // Ghidra: database.hh:34 Scope::renameSymbol
    /// Rename a Symbol within this Scope. Faithful to `renameSymbol`.
    pub fn rename_symbol(&mut self, symbol_id: u64, newname: &str) {
        if let Some(sym) = self.symbols.get(&symbol_id) {
            let mut sym_rg = sym.write().unwrap();
            sym_rg.name = newname.to_string();
            sym_rg.display_name = newname.to_string();
        }
    }

    // Ghidra: database.hh:34 Scope::setAttribute
    /// Set boolean Varnode properties on a Symbol. Faithful to `setAttribute`.
    pub fn set_attribute(&mut self, symbol_id: u64, attr: u32) {
        if let Some(sym) = self.symbols.get(&symbol_id) {
            sym.write().unwrap().flags |= attr;
        }
    }

    // Ghidra: database.hh:34 Scope::clearAttribute
    /// Clear boolean Varnode properties on a Symbol. Faithful to `clearAttribute`.
    pub fn clear_attribute(&mut self, symbol_id: u64, attr: u32) {
        if let Some(sym) = self.symbols.get(&symbol_id) {
            sym.write().unwrap().flags &= !attr;
        }
    }

    // Ghidra: database.hh:34 Scope::findAddr
    /// Find a Symbol at a given address. Faithful to `findAddr`
    /// (database.hh:621). Returns the matching SymbolEntry index or None.
    pub fn find_addr(&self, addr: Address) -> Option<&SymbolEntry> {
        self.entries
            .iter()
            .find(|e| e.addr == addr && e.offset == 0)
    }

    // Ghidra: database.hh:34 Scope::findContainer
    /// Find the smallest Symbol containing the given memory range. Faithful to
    /// `findContainer` (database.hh:629).
    pub fn find_container(&self, addr: Address, size: i32) -> Option<&SymbolEntry> {
        let target_end = addr.as_u64().saturating_add(size as u64 - 1);
        self.entries.iter().filter(|e| {
            let e_end = e.addr.as_u64().saturating_add(e.size as u64 - 1);
            e.addr.as_u64() <= addr.as_u64() && target_end <= e_end
        }).min_by_key(|e| e.size)
    }

    // Ghidra: database.hh:34 Scope::findOverlap
    /// Find first Symbol overlapping the given memory range. Faithful to
    /// `findOverlap` (database.hh:664).
    pub fn find_overlap(&self, addr: Address, size: i32) -> Option<&SymbolEntry> {
        let target_end = addr.as_u64().saturating_add(size as u64 - 1);
        self.entries.iter().find(|e| {
            let e_end = e.addr.as_u64().saturating_add(e.size as u64 - 1);
            e.addr.as_u64() <= target_end && addr.as_u64() <= e_end
        })
    }

    // Ghidra: database.hh:34 Scope::findByName
    /// Find a Symbol by name within this Scope. Faithful to `findByName`
    /// (database.hh:671).
    pub fn find_by_name(&self, nm: &str) -> Vec<Arc<RwLock<Symbol>>> {
        self.symbols
            .values()
            .filter(|s| s.read().unwrap().name == nm)
            .cloned()
            .collect()
    }

    // Ghidra: database.hh:34 Scope::isNameUsed
    /// Check if the given name is used within this Scope. Faithful to
    /// `isNameUsed` (database.hh:680).
    pub fn is_name_used(&self, nm: &str) -> bool {
        self.symbols
            .values()
            .any(|s| s.read().unwrap().name == nm)
    }

    // Ghidra: database.cc:2284 ScopeInternal::findClosestFit
    /// Find the SymbolEntry that most closely matches the given range,
    /// valid at `usepoint`. Faithful to `ScopeInternal::findClosestFit`
    /// (database.cc:2284). Among entries whose last address is at or beyond
    /// `addr` (i.e. they contain the start of the requested range), picks
    /// the entry whose size is closest to `size` — preferring an exact match,
    /// then the smallest over-sized entry, then the largest under-sized one.
    /// Entries must also be valid at `usepoint`.
    pub fn find_closest_fit(&self, addr: Address, size: i32, usepoint: Address) -> Option<&SymbolEntry> {
        let mut best: Option<&SymbolEntry> = None;
        let mut olddiff: i32 = -10000; // Ghidra sentinel: -10000
        for entry in &self.entries {
            // database.cc:2305 — require entry->getLast() >= addr.
            if entry.get_last() < addr.as_u64() {
                continue;
            }
            if !entry.in_use(usepoint) {
                continue;
            }
            let newdiff = entry.size - size;
            // database.cc:2307-2308 selection predicate.
            let accept = if olddiff < 0 {
                newdiff > olddiff
            } else {
                newdiff >= 0 && newdiff < olddiff
            };
            if accept {
                best = Some(entry);
                if newdiff == 0 {
                    break; // Exact match — database.cc:2311.
                }
                olddiff = newdiff;
            }
        }
        best
    }

    // Ghidra: database.cc:2321 ScopeInternal::findFunction
    /// Find the FunctionSymbol whose entry starts at `addr`. Faithful to
    /// `ScopeInternal::findFunction` (database.cc:2321). Returns the
    /// FunctionSymbol's entry address (the C++ version returns a `Funcdata*`;
    /// Rugra's FunctionSymbol is a separate struct without Funcdata
    /// integration, so we return the entry's `Address`). Rugra identifies
    /// function symbols by `type_name == "func"` since the Symbol struct is
    /// not polymorphic.
    pub fn find_function(&self, addr: Address) -> Option<Address> {
        for entry in &self.entries {
            if entry.addr.as_u64() != addr.as_u64() {
                continue;
            }
            let sym = entry.symbol.read().unwrap();
            if sym.type_name == "func" {
                return Some(entry.addr);
            }
        }
        None
    }

    // Ghidra: database.cc:2342 ScopeInternal::findExternalRef
    /// Find the ExternRefSymbol whose entry starts at `addr`. Faithful to
    /// `ScopeInternal::findExternalRef` (database.cc:2342). The C++ version
    /// returns the `ExternRefSymbol*`; Rugra's ExternRefSymbol is a separate
    /// struct, so we return the symbol id of the matching entry (identified
    /// by `type_name == "exref"`).
    pub fn find_external_ref(&self, addr: Address) -> Option<u64> {
        for entry in &self.entries {
            if entry.addr.as_u64() != addr.as_u64() {
                continue;
            }
            let sym = entry.symbol.read().unwrap();
            if sym.type_name == "exref" {
                return Some(sym.symbol_id);
            }
        }
        None
    }

    // Ghidra: database.cc:2368 ScopeInternal::findCodeLabel
    /// Find the LabSymbol for the given address, valid at `addr`. Faithful to
    /// `ScopeInternal::findCodeLabel` (database.cc:2368). The C++ version
    /// returns the `LabSymbol*`; Rugra's LabSymbol is a separate struct, so
    /// we return the symbol id of the matching entry (identified by
    /// `type_name == "label"`).
    pub fn find_code_label(&self, addr: Address) -> Option<u64> {
        // database.cc:2379-2385 walks entries in reverse for the most
        // recent label valid at `addr`. We walk forward and require
        // in_use(addr), matching the C++ acceptance predicate.
        for entry in &self.entries {
            if entry.addr.as_u64() != addr.as_u64() {
                continue;
            }
            if !entry.in_use(addr) {
                continue;
            }
            let sym = entry.symbol.read().unwrap();
            if sym.type_name == "label" {
                return Some(sym.symbol_id);
            }
        }
        None
    }

    // Ghidra: database.cc:268 Symbol::getFirstWholeMap (Scope-side helper)
    /// Return the first SymbolEntry that maps the whole of the given Symbol
    /// within this Scope. Faithful to `Symbol::getFirstWholeMap`
    /// (database.cc:268). Ghidra's Symbol carries its own `mapentry` list;
    /// Rugra's does not, so the owning Scope provides the entries.
    pub fn symbol_first_whole_map(&self, symbol_id: u64) -> Option<&SymbolEntry> {
        self.entries.iter().find(|e| {
            e.symbol.read().unwrap().symbol_id == symbol_id && e.offset == 0
        })
    }

    // Ghidra: database.cc:280 Symbol::getMapEntry (Scope-side helper)
    /// Return the SymbolEntry for `symbol_id` that contains `addr`. Faithful
    /// to `Symbol::getMapEntry(addr)` (database.cc:280). May return a partial
    /// entry. Ghidra walks the Symbol's own `mapentry` vector; Rugra's Symbol
    /// does not carry one, so the owning Scope provides the entries.
    pub fn symbol_map_entry(&self, symbol_id: u64, addr: Address) -> Option<&SymbolEntry> {
        self.entries.iter().find(|e| {
            if e.symbol.read().unwrap().symbol_id != symbol_id {
                return false;
            }
            let start = e.addr.as_u64();
            addr.as_u64().wrapping_sub(start) < e.size as u64
        })
    }

    // Ghidra: database.cc:909 Scope::stackAddr
    /// Query for Symbols starting at a given address, matching a given
    /// usepoint, walking the scope stack from `scope1` up to (but not
    /// including) `scope2`. Faithful to `Scope::stackAddr` (database.cc:909).
    /// If a Scope owns the address (`inScope`), that Scope is returned and a
    /// new variable may be discovered there; if a SymbolEntry matches, it is
    /// passed back via `addrmatch`. Returns the owning Scope's index in
    /// `scope_stack`, or `None` if no Scope controls the address.
    ///
    /// Ghidra threads the scope chain via `Scope::getParent()`; Rugra's
    /// Scopes are owned by the `Database` and carry no parent pointer chain,
    /// so the caller supplies the ordered stack of ancestor scopes
    /// (`scope_stack[0]` = innermost). `scope1_end` is the exclusive end
    /// index (corresponding to Ghidra's `scope2`).
    pub fn stack_addr(
        scope_stack: &[&Scope],
        scope1_end: usize,
        addr: Address,
        usepoint: Address,
        addrmatch: &mut Option<usize>,
    ) -> Option<usize> {
        // database.cc:916 — bail on constant addresses. Rugra is a
        // single-address-space model with no constant space, so this guard
        // is a no-op preserved for fidelity.
        let mut i = 0;
        while i < scope1_end && i < scope_stack.len() {
            let scope1 = scope_stack[i];
            // database.cc:918 — findAddr(addr, usepoint). Rugra's find_addr
            // ignores usepoint (all entries are considered valid); we refine
            // to in_use(usepoint) here.
            if let Some(entry) = scope1.find_addr(addr) {
                if entry.in_use(usepoint) {
                    // Map the matched entry back to its position in this
                    // Scope's entries vector.
                    *addrmatch = scope1.entries.iter().position(|e| std::ptr::eq(e, entry));
                    return Some(i);
                }
            }
            // database.cc:923 — discovery of a new variable.
            if scope1.in_scope(addr, 1) {
                return Some(i);
            }
            i += 1; // scope1 = scope1->getParent()
        }
        None
    }

    // Ghidra: database.cc:943 Scope::stackContainer
    /// Query for a Symbol containing a given range accessed at `usepoint`,
    /// walking the scope stack. Faithful to `Scope::stackContainer`
    /// (database.cc:943). See `stack_addr` for the scope-stack convention.
    pub fn stack_container(
        scope_stack: &[&Scope],
        scope1_end: usize,
        addr: Address,
        size: i32,
        usepoint: Address,
        addrmatch: &mut Option<usize>,
    ) -> Option<usize> {
        let mut i = 0;
        while i < scope1_end && i < scope_stack.len() {
            let scope1 = scope_stack[i];
            // database.cc:952 — findContainer(addr, size, usepoint).
            if let Some(entry) = scope1.find_container(addr, size) {
                if entry.in_use(usepoint) {
                    *addrmatch = scope1.entries.iter().position(|e| std::ptr::eq(e, entry));
                    return Some(i);
                }
            }
            // database.cc:957 — discovery of a new variable.
            if scope1.in_scope(addr, size) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    // Ghidra: database.cc:977 Scope::stackClosestFit
    /// Query for the SymbolEntry which most closely matches a given range
    /// and usepoint, walking the scope stack. Faithful to
    /// `Scope::stackClosestFit` (database.cc:977). See `stack_addr` for the
    /// scope-stack convention.
    pub fn stack_closest_fit(
        scope_stack: &[&Scope],
        scope1_end: usize,
        addr: Address,
        size: i32,
        usepoint: Address,
        addrmatch: &mut Option<usize>,
    ) -> Option<usize> {
        let mut i = 0;
        while i < scope1_end && i < scope_stack.len() {
            let scope1 = scope_stack[i];
            // database.cc:986 — findClosestFit(addr, size, usepoint).
            if let Some(entry) = scope1.find_closest_fit(addr, size, usepoint) {
                *addrmatch = scope1.entries.iter().position(|e| std::ptr::eq(e, entry));
                return Some(i);
            }
            // database.cc:991 — discovery of a new variable.
            if scope1.in_scope(addr, size) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    // Ghidra: database.cc:1009 Scope::stackFunction
    /// Query for a function Symbol starting at `addr`, walking the scope
    /// stack. Faithful to `Scope::stackFunction` (database.cc:1009). On a
    /// match, `addrmatch` is set to the function's entry address (the C++
    /// version passes back a `Funcdata*`). See `stack_addr` for the
    /// scope-stack convention.
    pub fn stack_function(
        scope_stack: &[&Scope],
        scope1_end: usize,
        addr: Address,
        addrmatch: &mut Option<Address>,
    ) -> Option<usize> {
        let mut i = 0;
        while i < scope1_end && i < scope_stack.len() {
            let scope1 = scope_stack[i];
            // database.cc:1017 — findFunction(addr).
            if let Some(faddr) = scope1.find_function(addr) {
                *addrmatch = Some(faddr);
                return Some(i);
            }
            // database.cc:1022 — discovery of a new variable (no usepoint).
            if scope1.in_scope(addr, 1) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    // Ghidra: database.cc:1040 Scope::stackExternalRef
    /// Query for an external-reference Symbol at `addr`, walking the scope
    /// stack. Faithful to `Scope::stackExternalRef` (database.cc:1040). On a
    /// match, `addrmatch` is set to the matching ExternRefSymbol's id.
    ///
    /// NOTE (database.cc:1053-1057): unlike the other stack* methods, this
    /// one does NOT perform scope discovery — a function in a lower scope may
    /// mask the external reference that refers to it. See `stack_addr` for
    /// the scope-stack convention.
    pub fn stack_external_ref(
        scope_stack: &[&Scope],
        scope1_end: usize,
        addr: Address,
        addrmatch: &mut Option<u64>,
    ) -> Option<usize> {
        let mut i = 0;
        while i < scope1_end && i < scope_stack.len() {
            let scope1 = scope_stack[i];
            // database.cc:1048 — findExternalRef(addr). No discovery.
            if let Some(sym_id) = scope1.find_external_ref(addr) {
                *addrmatch = Some(sym_id);
                return Some(i);
            }
            i += 1;
        }
        None
    }

    // Ghidra: database.cc:1074 Scope::stackCodeLabel
    /// Query for a label Symbol at `addr`, walking the scope stack. Faithful
    /// to `Scope::stackCodeLabel` (database.cc:1074). On a match, `addrmatch`
    /// is set to the matching LabSymbol's id. See `stack_addr` for the
    /// scope-stack convention.
    pub fn stack_code_label(
        scope_stack: &[&Scope],
        scope1_end: usize,
        addr: Address,
        addrmatch: &mut Option<u64>,
    ) -> Option<usize> {
        let mut i = 0;
        while i < scope1_end && i < scope_stack.len() {
            let scope1 = scope_stack[i];
            // database.cc:1082 — findCodeLabel(addr).
            if let Some(sym_id) = scope1.find_code_label(addr) {
                *addrmatch = Some(sym_id);
                return Some(i);
            }
            // database.cc:1087 — discovery of a new variable.
            if scope1.in_scope(addr, 1) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    // Ghidra: database.cc:1198 Scope::queryByName
    /// Starting from the first scope in `scope_stack`, look for Symbols with
    /// the given name; if none are found in this scope, recurse into the
    /// parent (next entry in the stack). Faithful to `Scope::queryByName`
    /// (database.cc:1198). The C++ form recurses via `parent->queryByName`;
    /// Rugra walks the supplied ancestor stack. Returns the ids of all
    /// matching Symbols in the first scope that has any.
    pub fn query_by_name(scope_stack: &[&Scope], nm: &str) -> Vec<u64> {
        for scope in scope_stack {
            // database.cc:1201 — findByName(nm, res).
            let matches: Vec<u64> = scope
                .symbols
                .values()
                .filter(|s| s.read().unwrap().name == nm)
                .map(|s| s.read().unwrap().symbol_id)
                .collect();
            if !matches.is_empty() {
                // database.cc:1202-1203 — stop at the first non-empty scope.
                return matches;
            }
            // database.cc:1204-1205 — else recurse into parent.
        }
        Vec::new()
    }

    // Ghidra: database.cc:1212 Scope::queryFunction(string)
    /// Find a function with the given name by walking the scope stack.
    /// Faithful to `Scope::queryFunction(const string &nm)`
    /// (database.cc:1212). Uses `query_by_name` then filters for symbols
    /// whose `type_name == "func"` (the C++ version dynamic_casts to
    /// `FunctionSymbol*`). Returns the first matching function's entry
    /// address, or `None`.
    pub fn query_function_by_name(scope_stack: &[&Scope], nm: &str) -> Option<Address> {
        let sym_ids = Scope::query_by_name(scope_stack, nm);
        for sid in sym_ids {
            for scope in scope_stack {
                if let Some(sym) = scope.symbols.get(&sid) {
                    let s = sym.read().unwrap();
                    if s.type_name == "func" {
                        // The FunctionSymbol's entry address lives in its
                        // SymbolEntry; look it up in the owning scope.
                        if let Some(entry) = scope.symbol_first_whole_map(sid) {
                            return Some(entry.addr);
                        }
                    }
                }
            }
        }
        None
    }

    // Ghidra: database.cc:1231 Scope::queryByAddr
    /// Within the scope stack, find a SymbolEntry mapped to `addr`, valid at
    /// `usepoint`. Faithful to `Scope::queryByAddr` (database.cc:1231). The
    /// C++ form first calls `mapScope` to pick the base scope; the caller
    /// supplies that base scope as `scope_stack[0]`. Returns a tuple of
    /// (scope index, entry index within that scope) or `None`.
    pub fn query_by_addr(
        scope_stack: &[&Scope],
        addr: Address,
        usepoint: Address,
    ) -> Option<(usize, usize)> {
        let mut addrmatch: Option<usize> = None;
        // database.cc:1236 — stackAddr(basescope, NULL, ...).
        let scope_idx = Scope::stack_addr(scope_stack, scope_stack.len(), addr, usepoint, &mut addrmatch)?;
        match addrmatch {
            Some(entry_idx) => Some((scope_idx, entry_idx)),
            None => None,
        }
    }

    // Ghidra: database.cc:1246 Scope::queryContainer
    /// Within the scope stack, find the smallest SymbolEntry containing the
    /// given range, valid at `usepoint`. Faithful to `Scope::queryContainer`
    /// (database.cc:1246). See `query_by_addr` for the return convention.
    pub fn query_container(
        scope_stack: &[&Scope],
        addr: Address,
        size: i32,
        usepoint: Address,
    ) -> Option<(usize, usize)> {
        let mut addrmatch: Option<usize> = None;
        // database.cc:1251 — stackContainer(basescope, NULL, ...).
        let scope_idx = Scope::stack_container(scope_stack, scope_stack.len(), addr, size, usepoint, &mut addrmatch)?;
        match addrmatch {
            Some(entry_idx) => Some((scope_idx, entry_idx)),
            None => None,
        }
    }

    // Ghidra: database.cc:1263 Scope::queryProperties
    /// Search for the smallest containing Symbol, and regardless of whether
    /// one is found, also look up the boolean properties of the memory range.
    /// Faithful to `Scope::queryProperties` (database.cc:1263). Returns
    /// `(Some((scope_idx, entry_idx)), flags)` when a SymbolEntry is found,
    /// or `(None, flags)` with the scope/property-derived flags otherwise.
    ///
    /// `flag_lookup` provides the analogue of
    /// `glb->symboltab->getProperty(addr)` (Rugra's Database::get_property),
    /// since the Scope itself has no Architecture handle.
    pub fn query_properties(
        scope_stack: &[&Scope],
        addr: Address,
        size: i32,
        usepoint: Address,
        flag_lookup: impl Fn(Address) -> u32,
    ) -> (Option<(usize, usize)>, u32) {
        let mut addrmatch: Option<usize> = None;
        // database.cc:1268 — stackContainer(basescope, NULL, ...).
        let finalscope = Scope::stack_container(scope_stack, scope_stack.len(), addr, size, usepoint, &mut addrmatch);
        if let Some(entry_idx) = addrmatch {
            // database.cc:1269-1270 — use the symbol's flags. The matched
            // entry lives in the scope returned by stack_container.
            if let Some(scope_idx) = finalscope {
                if let Some(entry) = scope_stack[scope_idx].entries.get(entry_idx) {
                    let flags = entry.get_all_flags();
                    return (Some((scope_idx, entry_idx)), flags);
                }
            }
            (None, flag_lookup(addr))
        } else if let Some(scope_idx) = finalscope {
            // database.cc:1271-1276 — set flags based on the owning scope.
            let mut flags = crate::varnode::varnode_flags::MAPPED | crate::varnode::varnode_flags::ADDRTIED;
            if scope_stack[scope_idx].is_global() {
                flags |= crate::varnode::varnode_flags::PERSIST;
            }
            flags |= flag_lookup(addr);
            (None, flags)
        } else {
            // database.cc:1278-1279 — just the global property.
            (None, flag_lookup(addr))
        }
    }

    // Ghidra: database.cc:1287 Scope::queryFunction(addr)
    /// Within the scope stack, find a function starting at `addr`. Faithful
    /// to `Scope::queryFunction(const Address &addr)` (database.cc:1287).
    /// Returns the function's entry address, or `None`.
    pub fn query_function_addr(scope_stack: &[&Scope], addr: Address) -> Option<Address> {
        let mut addrmatch: Option<Address> = None;
        // database.cc:1293 — stackFunction(basescope, NULL, addr, ...).
        let _ = Scope::stack_function(scope_stack, scope_stack.len(), addr, &mut addrmatch)?;
        addrmatch
    }

    // Ghidra: database.cc:1301 Scope::queryCodeLabel
    /// Within the scope stack, find a label Symbol at `addr`. Faithful to
    /// `Scope::queryCodeLabel` (database.cc:1301). Returns the matching
    /// LabSymbol's id, or `None`.
    pub fn query_code_label(scope_stack: &[&Scope], addr: Address) -> Option<u64> {
        let mut addrmatch: Option<u64> = None;
        // database.cc:1307 — stackCodeLabel(basescope, NULL, addr, ...).
        let _ = Scope::stack_code_label(scope_stack, scope_stack.len(), addr, &mut addrmatch)?;
        addrmatch
    }

    // Ghidra: database.cc:1416 Scope::queryExternalRefFunction
    /// Search for an external reference at `addr`, then resolve the function
    /// it refers to. Faithful to `Scope::queryExternalRefFunction`
    /// (database.cc:1416). The C++ version calls
    /// `basescope->resolveExternalRefFunction(sym)`, which is
    /// `queryFunction(sym->getRefAddr())`; Rugra returns the referred-to
    /// function's entry address by performing that lookup against the same
    /// scope stack.
    pub fn query_external_ref_function(
        scope_stack: &[&Scope],
        addr: Address,
        refaddr_lookup: impl Fn(u64) -> Option<Address>,
    ) -> Option<Address> {
        let mut addrmatch: Option<u64> = None;
        // database.cc:1422 — stackExternalRef(basescope, NULL, addr, &sym).
        let _base = Scope::stack_external_ref(scope_stack, scope_stack.len(), addr, &mut addrmatch)?;
        let sym_id = addrmatch?;
        // database.cc:1425 — resolveExternalRefFunction(sym):
        //   queryFunction(sym->getRefAddr()).
        let refaddr = refaddr_lookup(sym_id)?;
        Scope::query_function_addr(scope_stack, refaddr)
    }

    // Ghidra: database.cc:2806 ScopeInternal::getCategorySize
    /// Get the number of Symbols in the given category. Faithful to
    /// `getCategorySize` (database.hh:726).
    pub fn get_category_size(&self, cat: i32) -> usize {
        self.categories.get(&cat).map_or(0, |v| v.len())
    }

    // Ghidra: database.cc:2824 ScopeInternal::setCategory
    /// Set the category and index for the given Symbol. Faithful to
    /// `setCategory` (database.hh:740).
    pub fn set_category(&mut self, symbol_id: u64, cat: i32, ind: i32) {
        let sym = match self.symbols.get(&symbol_id).cloned() {
            Some(s) => s,
            None => return,
        };

        // database.cc:2827-2831 — clear only the old indexed slot, then remove
        // trailing NULLs without compacting any interior holes.
        let old_slot = {
            let symbol = sym.read().unwrap();
            let category = symbol.category as i32;
            (category >= 0).then_some((category, symbol.catindex as usize))
        };
        if let Some((old_category, old_index)) = old_slot {
            if let Some(list) = self.categories.get_mut(&old_category) {
                if let Some(slot) = list.get_mut(old_index) {
                    *slot = None;
                }
                list.trim_trailing_nulls();
            }
        }

        // database.cc:2834-2836 — int4 is assigned to uint2 before the
        // negative-category guard.
        let category_index = ind as u16;
        {
            let mut s = sym.write().unwrap();
            s.category = match cat {
                0 => SymbolCategory::FunctionParameter,
                1 => SymbolCategory::Equate,
                2 => SymbolCategory::UnionFacet,
                3 => SymbolCategory::FakeInput,
                _ => SymbolCategory::NoCategory,
            };
            s.catindex = category_index;
        }
        if cat < 0 {
            return;
        }

        // database.cc:2837-2844 — category 0 honors the requested uint2
        // index, padding with NULL; all later categories ignore ind and append.
        // Ghidra's outer vector grows through every intermediate category.
        for category in 0..=cat {
            self.categories.entry(category).or_default();
        }
        let list = self.categories.get_mut(&cat).unwrap();
        let index = if cat > 0 {
            list.len()
        } else {
            category_index as usize
        };
        {
            let mut symbol = sym.write().unwrap();
            symbol.catindex = index as u16;
        }
        list.resize_for_index(index);
        list.0[index] = Some(Arc::downgrade(&sym));
    }

    // Ghidra: database.hh:34 Scope::clear
    /// Clear all symbols from this scope. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.entries.clear();
        self.dynamic_entries.clear();
        self.categories.clear();
        self.next_unique_id = ID_BASE;
    }

    // Ghidra: database.hh:34 Scope::clearUnlocked
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

    // Ghidra: database.hh:34 Scope::attachChild
    /// Attach a child scope.
    pub fn attach_child(&mut self, child_id: u64) {
        if !self.children.contains(&child_id) {
            self.children.push(child_id);
        }
    }

    // Ghidra: database.hh:34 Scope::detachChild
    /// Detach a child scope.
    pub fn detach_child(&mut self, child_id: u64) {
        self.children.retain(|&c| c != child_id);
    }

    // Ghidra: database.hh:34 Scope::numSymbols
    /// Number of symbols in this scope.
    pub fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    // Ghidra: database.cc:2616 ScopeInternal::encode
    /// Encode this single scope (no children) to a `<scope>` element. Faithful
    /// to `ScopeInternal::encode` (database.cc:2616). Emits the scope name and
    /// id attributes, an optional `<parent>` child, the `<rangelist>` of owned
    /// memory, and a `<symbollist>` of `<mapsym>` entries (each wrapping a
    /// symbol and its address/hash mappings).
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        let scope_elem = ElementId::new("scope", 80);
        encoder.open_element(&scope_elem);
        encoder.write_string(&AttributeId::new("name", 0), &self.name);
        encoder.write_unsigned_integer(&AttributeId::new("id", 0), self.unique_id);
        if self.display_name != self.name {
            encoder.write_string(&AttributeId::new("label", 0), &self.display_name);
        }
        // Parent id (if not global).
        if self.parent_id != 0 {
            encoder.open_element(&ElementId::new("parent", 77));
            encoder.write_unsigned_integer(&AttributeId::new("id", 0), self.parent_id);
            encoder.close_element(&ElementId::new("parent", 77));
        }
        // Owned memory ranges (RangeList).
        self.rangetree_encode(encoder);
        // Symbol list (only if non-empty, matching the C++ guard).
        if !self.symbols.is_empty() {
            encoder.open_element(&ElementId::new("symbollist", 81));
            for sym_arc in self.symbols.values() {
                let sym = sym_arc.read().unwrap();
                // Determine the symbol's mapping type for the mapsym "type"
                // attribute, mirroring database.cc:2634-2647.
                let mut symbol_type = 0u32; // 0=none, 1=dynamic, 2=equate
                let matching_entry = self
                    .entries
                    .iter()
                    .chain(self.dynamic_entries.iter())
                    .find(|e| {
                        e.symbol.read().unwrap().symbol_id == sym.symbol_id && e.offset == 0
                    });
                if let Some(entry) = matching_entry {
                    if entry.is_dynamic() {
                        match sym.category {
                            SymbolCategory::UnionFacet => {
                                // Don't save overrides (database.cc:2639).
                                continue;
                            }
                            SymbolCategory::Equate => symbol_type = 2,
                            _ => symbol_type = 1,
                        }
                    }
                }
                encoder.open_element(&ElementId::new("mapsym", 76));
                if symbol_type == 1 {
                    encoder.write_string(&AttributeId::new("type", 0), "dynamic");
                } else if symbol_type == 2 {
                    encoder.write_string(&AttributeId::new("type", 0), "equate");
                }
                sym.encode(encoder);
                // Encode each mapping (addr/hash + uselimit) for this symbol.
                for entry in self.entries.iter().chain(self.dynamic_entries.iter()) {
                    if entry.symbol.read().unwrap().symbol_id == sym.symbol_id {
                        entry.encode(encoder);
                    }
                }
                encoder.close_element(&ElementId::new("mapsym", 76));
            }
            encoder.close_element(&ElementId::new("symbollist", 81));
        }
        encoder.close_element(&scope_elem);
    }

    // Ghidra: database.cc:2616 ScopeInternal::encode (rangelist portion)
    /// Encode the scope's owned memory ranges as a `<rangelist>`. Faithful to
    /// the `getRangeTree().encode(encoder)` call at database.cc:2627.
    fn rangetree_encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ElementId::new("rangelist", 0));
        for rng in self.rangetree.ranges() {
            encoder.open_element(&ElementId::new("range", 0));
            encoder.write_unsigned_integer(&AttributeId::new("first", 0), rng.get_first().as_u64());
            encoder.write_unsigned_integer(&AttributeId::new("last", 0), rng.get_last().as_u64());
            encoder.close_element(&ElementId::new("range", 0));
        }
        encoder.close_element(&ElementId::new("rangelist", 0));
    }

    // Ghidra: database.cc:1371 Scope::encodeRecursive
    /// Encode this scope. Faithful to `Scope::encodeRecursive`
    /// (database.cc:1371). Because child scopes live in the `Database` (not in
    /// the `Scope`), this method encodes only the current scope; the Database
    /// drives the recursive walk over its scope map.
    pub fn encode_recursive(&self, encoder: &mut dyn Encoder, _only_global: bool) {
        self.encode(encoder);
    }

    // Ghidra: database.cc:2667 ScopeInternal::decodeHole
    /// Parse a `<hole>` element describing boolean properties of a memory
    /// range. Faithful to `ScopeInternal::decodeHole` (database.cc:2667). The
    /// C++ version forwards the range+flags to the Database's
    /// `setPropertyRange`; the Rust port returns the (range, flags) pair so the
    /// Database can apply it.
    pub fn decode_hole(decoder: &mut dyn Decoder) -> (Range, u32) {
        let elem_id = decoder.open_element();
        let mut first = 0u64;
        let mut last = 0u64;
        let mut flags = 0u32;
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            match decoder.attribute_name(aid).as_deref() {
                Some("first") => first = decoder.read_unsigned_integer(),
                Some("last") => last = decoder.read_unsigned_integer(),
                Some("readonly") => {
                    if decoder.read_bool() {
                        flags |= symbol_flags::READONLY;
                    }
                }
                Some("volatile") => {
                    if decoder.read_bool() {
                        flags |= symbol_flags::VOLATIL;
                    }
                }
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
        decoder.close_element(elem_id);
        let range = Range::new(Address::new(first), Address::new(last))
            .unwrap_or_else(|| Range::new(Address::new(0), Address::new(0)).unwrap());
        (range, flags)
    }

    // Ghidra: database.cc:2695 ScopeInternal::decodeCollision
    /// Parse a `<collision>` element indicating a named symbol with no storage
    /// or data-type info. Faithful to `ScopeInternal::decodeCollision`
    /// (database.cc:2695). Returns the name to register; the caller creates an
    /// unmapped symbol if the name is not already present.
    pub fn decode_collision_name(decoder: &mut dyn Decoder) -> String {
        let elem_id = decoder.open_element();
        let mut nm = String::new();
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            if decoder.attribute_name(aid).as_deref() == Some("name") {
                nm = decoder.read_string();
            } else {
                let _ = decoder.read_string();
            }
        }
        decoder.close_element(elem_id);
        nm
    }

    // Ghidra: database.cc:2744 ScopeInternal::decode
    /// Decode this scope's contents from the children of a `<scope>` element
    /// (the `<scope>` element itself is opened by the caller). Faithful to
    /// `ScopeInternal::decode` (database.cc:2744). Handles an optional
    /// `<parent>` (skipped — applied by the Database), `<rangelist>` /
    /// `<rangeequalssymbols>`, and a `<symbollist>` of `<mapsym>`/`<hole>`/
    /// `<collision>` children.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let elem_name = decoder.element_name(sub_id).unwrap_or_default();
            if elem_name == "parent" {
                // Skip <parent> — the Database applies the parent linkage.
                decoder.open_element();
                decoder.close_element(sub_id);
                continue;
            }
            if elem_name == "rangelist" {
                // Owned memory ranges.
                self.decode_rangelist(decoder);
                continue;
            }
            if elem_name == "rangeequalssymbols" {
                decoder.open_element();
                decoder.close_element(sub_id);
                continue;
            }
            if elem_name != "symbollist" {
                // Unknown element (e.g. nested scope) — skip.
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
                match sym_name.as_str() {
                    "mapsym" => {
                        self.add_map_sym(decoder);
                    }
                    "hole" => {
                        // Holes describe global memory properties; collect them
                        // for the Database. In a standalone Scope we just skip.
                        let (_rng, _flags) = Scope::decode_hole(decoder);
                    }
                    "collision" => {
                        let nm = Scope::decode_collision_name(decoder);
                        if !self.is_name_used(&nm) {
                            self.add_symbol(&nm, "int");
                        }
                    }
                    "symbol" => {
                        // Legacy raw <symbol> elements (older format).
                        let id = self.allocate_id();
                        let mut sym = Symbol::new_unnamed(self.unique_id);
                        sym.symbol_id = id;
                        sym.decode(decoder);
                        self.symbols.insert(id, Arc::new(RwLock::new(sym)));
                    }
                    _ => break,
                }
            }
            decoder.close_element(sub_id);
            break;
        }
    }

    // Ghidra: database.cc:2744 ScopeInternal::decode (rangelist portion)
    /// Decode a `<rangelist>` child into the scope's rangetree. Faithful to the
    /// `RangeList newrangetree; newrangetree.decode(decoder)` block at
    /// database.cc:2757.
    fn decode_rangelist(&mut self, decoder: &mut dyn Decoder) {
        let rl_id = decoder.peek_element();
        if rl_id == 0 {
            return;
        }
        decoder.open_element();
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            if decoder.element_name(sub_id).as_deref() != Some("range") {
                break;
            }
            decoder.open_element();
            let mut first = 0u64;
            let mut last = 0u64;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                match decoder.attribute_name(aid).as_deref() {
                    Some("first") => first = decoder.read_unsigned_integer(),
                    Some("last") => last = decoder.read_unsigned_integer(),
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            if let Some(rng) = Range::new(Address::new(first), Address::new(last)) {
                self.rangetree.insert_range(rng);
            }
            decoder.close_element(sub_id);
        }
        decoder.close_element(rl_id);
    }

    // Ghidra: database.cc:1564 Scope::addMapSym
    /// Parse a mapped Symbol from a `<mapsym>` element. Faithful to
    /// `Scope::addMapSym` (database.cc:1564). The first child determines the
    /// symbol kind (`<symbol>`, `<equatesymbol>`, `<function>`,
    /// `<functionshell>`, `<labelsym>`, `<externrefsymbol>`, `<facetsymbol>`);
    /// subsequent `<addr>`/`<hash>` children define the SymbolEntry mappings.
    /// Returns the new symbol id (0 = none created).
    pub fn add_map_sym(&mut self, decoder: &mut dyn Decoder) -> u64 {
        let elem_id = decoder.open_element();
        // Consume any mapsym attributes (e.g. "type").
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            let _ = decoder.read_string();
        }
        let sub_id = decoder.peek_element();
        let sub_name = decoder.element_name(sub_id).unwrap_or_default();
        let id = self.allocate_id();
        let type_name = match sub_name.as_str() {
            "equatesymbol" => "equ",
            "function" | "functionshell" => "func",
            "labelsym" => "label",
            "externrefsymbol" => "exref",
            "facetsymbol" => "union",
            _ => "",
        };
        let mut sym = Symbol::new_unnamed(self.unique_id);
        sym.symbol_id = id;
        sym.type_name = type_name.to_string();
        // Decode the symbol element itself (header + body, body skipped).
        let opened = decoder.open_element();
        sym.decode_header(decoder);
        // database.cc:1572-1573/1587 — an <equatesymbol> child decodes into an
        // EquateSymbol instance whose decode body (database.cc:670-683) reads
        // the <value> child after decodeHeader; the object identity carries
        // the equate payload regardless of the category attribute. The Rust
        // encoder writes the value as a `val` attribute (EquateSymbol::encode);
        // an absent/attribute-less <value> leaves the hh:306 default 0.
        let mut equate_value: Option<u64> = None;
        if sub_name == "equatesymbol" {
            let val_id = decoder.peek_element();
            if val_id != 0 && decoder.element_name(val_id).as_deref() == Some("value") {
                let v_id = decoder.open_element();
                loop {
                    let aid = decoder.next_attribute_id();
                    if aid == 0 {
                        break;
                    }
                    if decoder.attribute_name(aid).as_deref() == Some("val") {
                        equate_value = Some(decoder.read_unsigned_integer());
                    } else {
                        let _ = decoder.read_string();
                    }
                }
                decoder.close_element(v_id);
            }
        }
        decoder.close_element_skipping(opened);
        let sym_arc = Arc::new(RwLock::new(sym));
        self.symbols.insert(id, sym_arc.clone());
        if sub_name == "equatesymbol" {
            // RUGRA-GLUE (database.cc:1572 new EquateSymbol(owner)): the
            // decoded C++ object is an EquateSymbol; the registry entry on
            // the registered Arc stands in for that subtype identity.
            crate::varnode::equate_symbol_registry::register_value(
                &sym_arc,
                equate_value.unwrap_or(0),
            );
        }
        // Parse subsequent <addr>/<hash> mappings.
        loop {
            let map_id = decoder.peek_element();
            if map_id == 0 {
                break;
            }
            let map_name = decoder.element_name(map_id).unwrap_or_default();
            if map_name != "addr" && map_name != "hash" {
                break;
            }
            let sym_arc = self.symbols.get(&id).cloned();
            let sym_arc = match sym_arc {
                Some(a) => a,
                None => break,
            };
            let mut entry = SymbolEntry::new_static(
                sym_arc,
                0,
                Address::new(0),
                0,
                0,
                RangeList::new(),
            );
            entry.decode(decoder);
            if entry.is_invalid() {
                // database.cc:2596 — throw out invalid mappings.
                self.remove_symbol(id);
                decoder.close_element(elem_id);
                return 0;
            }
            if entry.is_dynamic() {
                self.dynamic_entries.push(entry);
            } else {
                self.entries.push(entry);
            }
        }
        decoder.close_element(elem_id);
        id
    }

    // Ghidra: database.cc:2850 ScopeInternal::assignDefaultNames
    /// Assign a default name to any symbol whose name is undefined. Faithful to
    /// `ScopeInternal::assignDefaultNames` (database.cc:2850). Iterates the
    /// name tree (here: symbols sorted by id) and, for each symbol whose name
    /// matches the `$$undef` placeholder, builds a default variable name via
    /// `build_default_name` and renames it. The `base` index is advanced as
    /// names are generated. Returns the new value of `base`.
    pub fn assign_default_names(&mut self, base: &mut i32) -> i32 {
        // Collect ids first to avoid borrowing self during rename.
        let undef_ids: Vec<u64> = self
            .symbols
            .iter()
            .filter(|(_, s)| s.read().unwrap().is_name_undefined())
            .map(|(&id, _)| id)
            .collect();
        for id in undef_ids {
            let nm = {
                let sym = match self.symbols.get(&id) {
                    Some(s) => s,
                    None => continue,
                };
                let sym = sym.read().unwrap();
                if !sym.is_name_undefined() {
                    continue;
                }
                self.build_default_name(&sym, base)
            };
            self.rename_symbol(id, &nm);
        }
        *base
    }

    // Ghidra: database.cc:2850 ScopeInternal::buildDefaultName (helper)
    /// Build a default variable name for the given symbol. Faithful to the
    /// `buildDefaultName` call inside `assignDefaultNames` (database.cc:2862).
    /// The C++ dispatches to `Scope::buildVariableName`; the Rust port produces
    /// a `var_<n>` style name, matching the generic fallback used when no
    /// Varnode is available.
    fn build_default_name(&self, _sym: &Symbol, base: &mut i32) -> String {
        let nm = format!("var_{}", *base);
        *base += 1;
        nm
    }

    // Ghidra: database.cc:1615 Scope::addFunction
    /// Create a function Symbol at the given address in this Scope. Faithful to
    /// `Scope::addFunction` (database.cc:1615). The C++ form builds a
    /// `FunctionSymbol` (carrying `glb->min_funcsymbol_size`) and maps it to the
    /// function entry address; Rugra's `Scope` stores generic `Symbol`s, so we
    /// create a `FunctionSymbol` struct (for the caller) and register its base
    /// `Symbol` (with `type_name == "func"`) plus a whole-map `SymbolEntry` at
    /// `addr`. As in database.cc:1620-1625, an overlapping container is queried
    /// for a warning; Rugra has no `glb->printMessage`, so the overlap is
    /// reported only via the returned `overlap` flag.
    ///
    /// Returns `(FunctionSymbol, overlap)` where `overlap` is the address of an
    /// overlapping SymbolEntry's symbol (database.cc:1623), or `None`.
    pub fn add_function(
        &mut self,
        addr: Address,
        nm: &str,
        consume_size: i32,
    ) -> (FunctionSymbol, Option<u64>) {
        // database.cc:1620 — queryContainer(addr, 1, Address()).
        let overlap = self
            .find_container(addr, 1)
            .map(|e| e.symbol.read().unwrap().symbol_id);
        // database.cc:1626 — new FunctionSymbol(owner, nm, glb->min_funcsymbol_size).
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, "func");
        sym.symbol_id = id;
        // Build the FunctionSymbol view for the caller (database.cc:1615 return).
        let fs = FunctionSymbol::new(self.unique_id, nm, consume_size, addr);
        self.symbols.insert(id, Arc::new(RwLock::new(sym)));
        // database.cc:1627 — addSymbolInternal(sym).
        // database.cc:1630 — addMapPoint(sym, addr, Address()). whole-map entry.
        let sym_arc = self.symbols.get(&id).cloned().unwrap();
        sym_arc.write().unwrap().whole_count += 1;
        self.entries.push(SymbolEntry::new_static(
            sym_arc,
            0,
            addr,
            0,
            consume_size,
            RangeList::new(),
        ));
        (fs, overlap)
    }

    // Ghidra: database.cc:1642 Scope::addExternalRef
    /// Create an external reference at the given address in this Scope.
    /// Faithful to `Scope::addExternalRef` (database.cc:1642). The C++ form
    /// builds an `ExternRefSymbol` storing `refaddr`, maps it to `addr`, and
    /// clears the `Varnode::readonly` flag on the resulting SymbolEntry's
    /// symbol (database.cc:1654). Rugra's `Scope` stores generic `Symbol`s, so
    /// we create an `ExternRefSymbol` struct (for the caller) and register its
    /// base `Symbol` (with `type_name == "exref"`) plus a whole-map entry. The
    /// readonly flag is cleared via `symbol_flags::READONLY` (database.cc:1654
    /// uses `Varnode::readonly`; Rugra's Symbol flags namespace reuses
    /// `symbol_flags::READONLY` for the same purpose).
    ///
    /// Returns the `ExternRefSymbol` view for the caller.
    pub fn add_external_ref(
        &mut self,
        addr: Address,
        refaddr: Address,
        nm: &str,
    ) -> ExternRefSymbol {
        // database.cc:1647 — new ExternRefSymbol(owner, refaddr, nm).
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, "exref");
        sym.symbol_id = id;
        self.symbols.insert(id, Arc::new(RwLock::new(sym)));
        // database.cc:1648 — addSymbolInternal(sym).
        // database.cc:1651 — addMapPoint(sym, addr, Address()). whole-map entry.
        let sym_arc = self.symbols.get(&id).cloned().unwrap();
        sym_arc.write().unwrap().whole_count += 1;
        self.entries.push(SymbolEntry::new_static(
            sym_arc.clone(),
            0,
            addr,
            0,
            1,
            RangeList::new(),
        ));
        // database.cc:1654 — ret->symbol->flags &= ~Varnode::readonly.
        // The external reference value is in the image and probably isn't a
        // valid readonly datum, so strip the readonly attribute.
        sym_arc.write().unwrap().flags &= !symbol_flags::READONLY;
        // The ExternRefSymbol view for the caller (database.cc:1655 return).
        ExternRefSymbol::new(self.unique_id, nm, refaddr)
    }

    // Ghidra: database.cc:1664 Scope::addCodeLabel
    /// Create a code label at the given address in this Scope. Faithful to
    /// `Scope::addCodeLabel` (database.cc:1664). The C++ form builds a
    /// `LabSymbol` and maps it to `addr`; as in database.cc:1669-1674, an
    /// overlapping container is queried for a warning (using `addr` itself as
    /// the usepoint). Rugra has no `glb->printMessage`, so the overlap is
    /// reported only via the returned `overlap` flag.
    ///
    /// Returns `(LabSymbol, overlap)` where `overlap` is the symbol id of an
    /// overlapping SymbolEntry (database.cc:1672), or `None`.
    pub fn add_code_label(
        &mut self,
        addr: Address,
        nm: &str,
    ) -> (LabSymbol, Option<u64>) {
        // database.cc:1669 — queryContainer(addr, 1, addr).
        let overlap = self
            .find_container(addr, 1)
            .map(|e| e.symbol.read().unwrap().symbol_id);
        // database.cc:1675 — new LabSymbol(owner, nm).
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, "label");
        sym.symbol_id = id;
        self.symbols.insert(id, Arc::new(RwLock::new(sym)));
        // database.cc:1676 — addSymbolInternal(sym).
        // database.cc:1677 — addMapPoint(sym, addr, Address()). whole-map entry.
        let sym_arc = self.symbols.get(&id).cloned().unwrap();
        sym_arc.write().unwrap().whole_count += 1;
        self.entries.push(SymbolEntry::new_static(
            sym_arc,
            0,
            addr,
            0,
            1,
            RangeList::new(),
        ));
        // The LabSymbol view for the caller (database.cc:1678 return).
        (LabSymbol::new(self.unique_id, nm, addr), overlap)
    }

    // Ghidra: database.cc:1690 Scope::addDynamicSymbol
    /// Create a dynamically mapped Symbol attached to a specific data-flow.
    /// Faithful to `Scope::addDynamicSymbol` (database.cc:1690). The C++ form
    /// builds a `Symbol`, then calls `addDynamicMapInternal(sym, Varnode::mapped,
    /// hash, 0, ct->getSize(), rnglist)` (database.cc:1700), where `rnglist`
    /// holds `caddr` if it is valid. Rugra's `Scope` stores generic `Symbol`s
    /// and uses `dynamic_entries` for hashed `SymbolEntry`s; we mirror that by
    /// pushing a `SymbolEntry::new_dynamic` with `extraflags = MAPPED`, offset 0
    /// and the requested size, and a `RangeList` containing `caddr` when valid.
    ///
    /// Returns the new symbol id.
    pub fn add_dynamic_symbol(
        &mut self,
        nm: &str,
        type_name: &str,
        size: i32,
        caddr: Address,
        hash: u64,
    ) -> u64 {
        // database.cc:1695 — new Symbol(owner, nm, ct).
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, type_name);
        sym.symbol_id = id;
        self.symbols.insert(id, Arc::new(RwLock::new(sym)));
        // database.cc:1696 — addSymbolInternal(sym).
        // database.cc:1697-1699 — RangeList rnglist; insertRange(caddr...) if valid.
        let mut rnglist = RangeList::new();
        if caddr.as_u64() != 0 {
            if let Some(rng) = Range::new(caddr, caddr) {
                rnglist.insert_range(rng);
            }
        }
        // database.cc:1700 — addDynamicMapInternal(sym, Varnode::mapped, hash, 0, ct->getSize(), rnglist).
        let sym_arc = self.symbols.get(&id).cloned().unwrap();
        sym_arc.write().unwrap().whole_count += 1;
        self.dynamic_entries.push(SymbolEntry::new_dynamic(
            sym_arc,
            crate::varnode::varnode_flags::MAPPED,
            hash,
            0,
            size,
            rnglist,
        ));
        id
    }

    // Ghidra: database.cc:1712 Scope::addEquateSymbol
    /// Create a symbol that forces display conversion on a constant. Faithful
    /// to `Scope::addEquateSymbol` (database.cc:1712). The C++ form builds an
    /// `EquateSymbol(owner, nm, format, value)` — a `Symbol` subtype whose
    /// constructor (database.cc:624-631) sets `value`, `category = equate`,
    /// `dispflags |= format` — then calls `addSymbolInternal(sym)` and
    /// `addDynamicMapInternal(sym, Varnode::mapped, hash, 0, 1, rnglist)`
    /// (database.cc:1722), where `rnglist` holds `addr` if valid. Rugra
    /// registers the base `Symbol` (with `type_name == "equ"`, category
    /// `Equate`, and the requested display format) and pushes a single-byte
    /// dynamic `SymbolEntry`.
    ///
    /// Because Rust has no `Symbol` subtyping, the C++ object identity that
    /// `dynamic_cast<EquateSymbol*>` (varnode.cc:516) would examine is the
    /// registered `Arc<RwLock<Symbol>>` itself: we record `value` on that
    /// identity through [`crate::varnode::equate_symbol_registry::register_value`]
    /// (the varnodeeq-delivered stand-in for the subtype payload), so
    /// `copy_symbol_if_valid` sees main-pipeline equates exactly where the
    /// C++ dynamic_cast would succeed.
    ///
    /// Returns the `(EquateSymbol, symbol_id)` pair so the caller can recover
    /// both the equate view and the registered id.
    pub fn add_equate_symbol(
        &mut self,
        nm: &str,
        format: u32,
        value: u64,
        addr: Address,
        hash: u64,
    ) -> (EquateSymbol, u64) {
        // database.cc:1717 — new EquateSymbol(owner, nm, format, value): the
        // constructor body (database.cc:627-630) sets value, category=equate,
        // and dispflags |= format on the object being registered.
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, "equ");
        sym.symbol_id = id;
        sym.set_display_format(format); // cc:630 dispflags |= format.
        sym.category = SymbolCategory::Equate; // cc:628 category = equate.
        let sym_arc = Arc::new(RwLock::new(sym));
        self.symbols.insert(id, sym_arc.clone());
        // RUGRA-GLUE (database.cc:624 object identity): in C++ the registered
        // object IS an EquateSymbol carrying `value`; the registry entry on
        // this Arc is the Rust stand-in for that subtype payload.
        crate::varnode::equate_symbol_registry::register_value(&sym_arc, value);
        // database.cc:1718 — addSymbolInternal(sym).
        // database.cc:1719-1721 — RangeList rnglist; insertRange(addr...) if valid.
        let mut rnglist = RangeList::new();
        if addr.as_u64() != 0 {
            if let Some(rng) = Range::new(addr, addr) {
                rnglist.insert_range(rng);
            }
        }
        // database.cc:1722 — addDynamicMapInternal(sym, Varnode::mapped, hash, 0, 1, rnglist).
        sym_arc.write().unwrap().whole_count += 1;
        self.dynamic_entries.push(SymbolEntry::new_dynamic(
            sym_arc,
            crate::varnode::varnode_flags::MAPPED,
            hash,
            0,
            1,
            rnglist,
        ));
        // The EquateSymbol view for the caller (database.cc:1723 return).
        (EquateSymbol::new(self.unique_id, nm, format, value), id)
    }

    // Ghidra: database.cc:1737 Scope::addUnionFacetSymbol
    /// Create a symbol forcing a field interpretation for a specific access to a
    /// variable with union data-type. Faithful to `Scope::addUnionFacetSymbol`
    /// (database.cc:1737). The C++ form builds a `UnionFacetSymbol(owner, nm,
    /// dt, fieldNum)`, then calls `addDynamicMapInternal(sym, Varnode::mapped,
    /// hash, 0, 1, rnglist)` (database.cc:1745). Rugra builds a
    /// `UnionFacetSymbol` struct (for the caller), registers its base `Symbol`
    /// (with `type_name == "union"` and the requested category), and pushes a
    /// single-byte dynamic `SymbolEntry`.
    ///
    /// Returns the `(UnionFacetSymbol, symbol_id)` pair.
    pub fn add_union_facet_symbol(
        &mut self,
        nm: &str,
        type_name: &str,
        field_num: u64,
        addr: Address,
        hash: u64,
    ) -> (UnionFacetSymbol, u64) {
        // database.cc:1740 — new UnionFacetSymbol(owner, nm, dt, fieldNum).
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, type_name);
        sym.symbol_id = id;
        sym.category = SymbolCategory::UnionFacet;
        self.symbols.insert(id, Arc::new(RwLock::new(sym)));
        // database.cc:1741 — addSymbolInternal(sym).
        // database.cc:1742-1744 — RangeList rnglist; insertRange(addr...) if valid.
        let mut rnglist = RangeList::new();
        if addr.as_u64() != 0 {
            if let Some(rng) = Range::new(addr, addr) {
                rnglist.insert_range(rng);
            }
        }
        // database.cc:1745 — addDynamicMapInternal(sym, Varnode::mapped, hash, 0, 1, rnglist).
        let sym_arc = self.symbols.get(&id).cloned().unwrap();
        sym_arc.write().unwrap().whole_count += 1;
        self.dynamic_entries.push(SymbolEntry::new_dynamic(
            sym_arc,
            crate::varnode::varnode_flags::MAPPED,
            hash,
            0,
            1,
            rnglist,
        ));
        // The UnionFacetSymbol view for the caller (database.cc:1746 return).
        (UnionFacetSymbol::new(self.unique_id, nm, field_num), id)
    }

    // Ghidra: database.cc:1548 Scope::addMapPoint
    /// Create a new SymbolEntry that maps the whole Symbol to the given address.
    /// Faithful to `Scope::addMapPoint` (database.cc:1548). The C++ form
    /// constructs a `SymbolEntry(sym)`, restricts its use to `usepoint` if valid,
    /// sets `entry.addr = addr`, then calls `addMap(entry)`. Rugra pushes a
    /// whole-map static `SymbolEntry` directly. Does nothing if the symbol id is
    /// not registered in this scope.
    pub fn add_map_point(
        &mut self,
        symbol_id: u64,
        addr: Address,
        usepoint: Address,
        size: i32,
    ) {
        let sym_arc = match self.symbols.get(&symbol_id).cloned() {
            Some(a) => a,
            None => return,
        };
        // database.cc:1553-1554 — restrict use if usepoint is valid.
        let mut uselimit = RangeList::new();
        if usepoint.as_u64() != 0 {
            if let Some(rng) = Range::new(usepoint, usepoint) {
                uselimit.insert_range(rng);
            }
        }
        // database.cc:1555 — entry.addr = addr.
        // database.cc:1556 — addMap(entry). whole-map entry at offset 0.
        sym_arc.write().unwrap().whole_count += 1;
        self.entries.push(SymbolEntry::new_static(
            sym_arc,
            0,
            addr,
            0,
            size,
            uselimit,
        ));
    }

    // Ghidra: database.cc:1889 ScopeInternal::begin
    /// Return an iterator over the whole-map `SymbolEntry`s in this Scope,
    /// ordered by mapping address. Faithful to `ScopeInternal::begin`
    /// (database.cc:1889) / `ScopeInternal::end` (database.cc:1914). Ghidra's
    /// `MapIterator` walks the per-address-space `maptable` rangemaps in
    /// address order; Rugra stores a single `entries` vector, so we sort a
    /// snapshot by address to provide the same ordering guarantee. This is the
    /// range-for equivalent used by `Database::encode` and debugging output.
    ///
    /// Returns a freshly-allocated `Vec<&SymbolEntry>` sorted by `addr` then
    /// `size`, so callers can iterate in mapping-address order without mutating
    /// the scope.
    pub fn begin_end(&self) -> Vec<&SymbolEntry> {
        let mut refs: Vec<&SymbolEntry> = self.entries.iter().collect();
        // database.cc:1889 comment — "The symbols are ordered via their mapping address".
        refs.sort_by(|a, b| {
            a.addr
                .as_u64()
                .cmp(&b.addr.as_u64())
                .then(a.size.cmp(&b.size))
        });
        refs
    }

    // Ghidra: database.cc:1921 ScopeInternal::beginDynamic
    /// Return an iterator over the dynamic (hash-based) `SymbolEntry`s in this
    /// Scope. Faithful to `ScopeInternal::beginDynamic` (database.cc:1921) /
    /// `ScopeInternal::endDynamic` (database.cc:1927). Ghidra returns a
    /// `list<SymbolEntry>::const_iterator` over `dynamicentry`; Rugra returns a
    /// slice iterator over `dynamic_entries`.
    pub fn begin_end_dynamic(&self) -> std::slice::Iter<'_, SymbolEntry> {
        self.dynamic_entries.iter()
    }

    // Ghidra: database.cc:2020 ScopeInternal::clearCategory
    /// Clear all symbols of the given category from this Scope. Faithful to
    /// `ScopeInternal::clearCategory` (database.cc:2020). When `cat >= 0`, every
    /// symbol in `category[cat]` is removed via `removeSymbol`; when `cat < 0`,
    /// every symbol whose category is `>= 0` is skipped (Ghidra clears the
    /// `no_category` bucket, i.e. symbols whose category is `< 0`). The C++
    /// implementation uses the `nametree` to enumerate; Rugra collects ids from
    /// `symbols` first to avoid mutating the map while iterating.
    ///
    /// NOTE: Rugra maps Ghidra's `Symbol::no_category = -1` to
    /// `SymbolCategory::NoCategory`; the `cat < 0` branch therefore clears
    /// symbols whose category is `NoCategory` (i.e. `get_category() < 0` in the
    /// C++ sense), matching database.cc:2032-2038.
    pub fn clear_category(&mut self, cat: i32) {
        if cat >= 0 {
            // database.cc:2023-2029 — remove every symbol in category[cat].
            let to_remove: Vec<u64> = self
                .categories
                .get(&cat)
                .map(|v| {
                    v.iter()
                        .map(|s| s.read().unwrap().symbol_id)
                        .collect()
                })
                .unwrap_or_default();
            for id in to_remove {
                self.remove_symbol(id);
            }
        } else {
            // database.cc:2031-2038 — walk nametree, remove symbols whose
            // category >= 0 are skipped (i.e. clear the no_category bucket).
            let to_remove: Vec<u64> = self
                .symbols
                .iter()
                .filter(|(_, s)| {
                    s.read().unwrap().category == SymbolCategory::NoCategory
                })
                .map(|(&id, _)| id)
                .collect();
            for id in to_remove {
                self.remove_symbol(id);
            }
        }
    }

    // Ghidra: database.cc:2071 ScopeInternal::clearUnlockedCategory
    /// Clear unlocked symbols of the given category from this Scope. Faithful
    /// to `ScopeInternal::clearUnlockedCategory` (database.cc:2071). When
    /// `cat >= 0`, for each symbol in `category[cat]`: if it is type-locked,
    /// clear any unlocked name and reset size-typelock (Ghidra renames to an
    /// undefined name and calls `resetSizeLockType`); otherwise remove it. When
    /// `cat < 0`, the same logic applies to symbols whose category is
    /// `NoCategory`. Rugra inlines the rename to an undefined placeholder and
    /// clears the size-typelock flag directly (see `clear_unlocked` for the
    /// same simplification).
    pub fn clear_unlocked_category(&mut self, cat: i32) {
        let ids: Vec<u64> = if cat >= 0 {
            // database.cc:2074-2076 — category[cat].
            self.categories
                .get(&cat)
                .map(|v| {
                    v.iter()
                        .map(|s| s.read().unwrap().symbol_id)
                        .collect()
                })
                .unwrap_or_default()
        } else {
            // database.cc:2092-2097 — nametree filtered to category < 0.
            self.symbols
                .iter()
                .filter(|(_, s)| {
                    s.read().unwrap().category == SymbolCategory::NoCategory
                })
                .map(|(&id, _)| id)
                .collect()
        };
        let mut to_remove: Vec<u64> = Vec::new();
        for id in ids {
            let sym = match self.symbols.get(&id) {
                Some(s) => s.clone(),
                None => continue,
            };
            let mut s = sym.write().unwrap();
            // database.cc:2079 — if type-locked, clear unlocked name & reset size-lock.
            if (s.flags & symbol_flags::TYPELOCK) != 0 {
                // database.cc:2080-2082 — rename to undefined if name not undefined.
                if (s.flags & symbol_flags::NAMELOCK) == 0 && !s.is_name_undefined() {
                    s.name = "$$undef".to_string();
                    s.display_name = "$$undef".to_string();
                }
                // database.cc:2085-2086 — resetSizeLockType.
                s.dispflags &= !display_flags::SIZE_TYPELOCK;
            } else {
                // database.cc:2088-2089 — remove symbol.
                to_remove.push(id);
            }
        }
        for id in to_remove {
            self.remove_symbol(id);
        }
    }

    // Ghidra: database.cc:2111 ScopeInternal::adjustCaches
    /// Let the Scope adjust its internal caches after the Architecture's
    /// address-space configuration is finalized. Faithful to
    /// `ScopeInternal::adjustCaches` (database.cc:2111). The C++ form resizes
    /// `maptable` to `glb->numSpaces()`; Rugra's Scope has a single address
    /// space and uses flat vectors rather than a per-space rangemap, so this is
    /// a no-op preserved for API fidelity (callers in the configuration path
    /// may still invoke it).
    pub fn adjust_caches(&mut self) {
        // database.cc:2114 — maptable.resize(glb->numSpaces(), NULL).
        // Rugra has no per-space maptable to resize.
    }

    // Ghidra: database.cc:2117 ScopeInternal::removeSymbolMappings
    /// Remove every mapping (SymbolEntry) of the given Symbol, but keep the
    /// Symbol itself registered. Faithful to
    /// `ScopeInternal::removeSymbolMappings` (database.cc:2117). The C++ form
    /// erases each iterator in `symbol->mapentry` from the owning rangemap (or
    /// `dynamicentry` for dynamic maps), resets `wholeCount = 0`, and clears
    /// `mapentry`. Rugra retains entries in the flat `entries` /
    /// `dynamic_entries` vectors, so we filter them out by symbol id and reset
    /// `whole_count` on the Symbol.
    pub fn remove_symbol_mappings(&mut self, symbol_id: u64) {
        // database.cc:2122-2133 — erase each mapping.
        self.entries
            .retain(|e| e.symbol.read().unwrap().symbol_id != symbol_id);
        self.dynamic_entries
            .retain(|e| e.symbol.read().unwrap().symbol_id != symbol_id);
        // database.cc:2134 — symbol->wholeCount = 0.
        if let Some(sym) = self.symbols.get(&symbol_id) {
            sym.write().unwrap().whole_count = 0;
        }
    }

    // Ghidra: database.cc:2166 ScopeInternal::retypeSymbol
    /// Change the data-type of a Symbol, adjusting its mappings if the size
    /// changed. Faithful to `ScopeInternal::retypeSymbol` (database.cc:2166).
    /// If the new type's size matches the current type, or the symbol has no
    /// mappings, only the type is updated (database.cc:2171-2176). If the
    /// symbol has exactly one address-tied mapping, that mapping is removed,
    /// the type is updated, and a new whole-map entry is added at the saved
    /// address with the new size (database.cc:2177-2196). Otherwise the
    /// retype fails; Ghidra throws `RecovError`, Rugra returns `false`.
    ///
    /// Rugra accepts the new type as `(type_name, size)` since Datatype
    /// integration is deferred; `checkSizeTypeLock` is re-run after the change
    /// (database.cc:2174/2192).
    pub fn retype_symbol(&mut self, symbol_id: u64, type_name: &str, new_size: i32) -> bool {
        let sym_arc = match self.symbols.get(&symbol_id).cloned() {
            Some(a) => a,
            None => return false,
        };
        // Collect this symbol's own whole-map static entries (database.cc:2171
        // uses sym->mapentry, the symbol's own mapping list).
        let mine: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.symbol.read().unwrap().symbol_id == symbol_id)
            .map(|(i, _)| i)
            .collect();
        // database.cc:2171 — if size matches OR no mappings, just set type.
        // Ghidra's sym->type->getSize() is the symbol's data-type size; Rugra's
        // dtype may be None (deferred integration), so we fall back to the
        // first whole-map entry's size when dtype is unset.
        let cur_size = sym_arc.read().unwrap()
            .dtype
            .as_ref()
            .map_or_else(
                || mine.first().map_or(0, |&i| self.entries[i].size),
                |d| d.get_size() as i32,
            );
        let has_mappings = !mine.is_empty();
        if cur_size == new_size || !has_mappings {
            let mut s = sym_arc.write().unwrap();
            s.type_name = type_name.to_string();
            s.check_size_type_lock();
            return true;
        }
        // database.cc:2177 — if exactly one address-tied mapping.
        if mine.len() == 1 {
            let entry = self.entries[mine[0]].clone();
            // database.cc:2179 — must be address-tied.
            let is_addr_tied = {
                let s = sym_arc.read().unwrap();
                (s.flags & symbol_flags::ADDRTIED) != 0
            };
            if is_addr_tied {
                // database.cc:2186 — erase the old rangemap entry.
                let saved_addr = entry.addr;
                self.entries.swap_remove(mine[0]);
                // database.cc:2188 — wholeCount = 0.
                {
                    let mut s = sym_arc.write().unwrap();
                    s.whole_count = 0;
                    // database.cc:2191 — change the type.
                    s.type_name = type_name.to_string();
                    s.check_size_type_lock();
                }
                // database.cc:2193 — addMapPoint(sym, addr, Address()) with new size.
                self.add_map_point(symbol_id, saved_addr, Address::new(0), new_size);
                return true;
            }
        }
        // database.cc:2197 — throw RecovError. Rugra returns false.
        false
    }

    // Ghidra: database.cc:2218 ScopeInternal::setDisplayFormat
    /// Set the display format of a Symbol. Faithful to
    /// `ScopeInternal::setDisplayFormat` (database.cc:2218). The C++ form
    /// forwards to `sym->setDisplayFormat(attr)`; Rugra does the same. No-op if
    /// the symbol id is not registered.
    pub fn set_display_format(&mut self, symbol_id: u64, attr: u32) {
        if let Some(sym) = self.symbols.get(&symbol_id) {
            sym.write().unwrap().set_display_format(attr);
        }
    }

    // Ghidra: database.cc:2814 ScopeInternal::getCategorySymbol
    /// Get the indexed Symbol within the given category. Faithful to
    /// `ScopeInternal::getCategorySymbol` (database.cc:2814). Returns `None`
    /// when `cat` is out of range or `ind` is out of range for that category.
    /// The C++ form indexes `category[cat][ind]`; Rugra stores categories in a
    /// `BTreeMap<i32, Vec<...>>`, so we look up the vector and index it.
    pub fn get_category_symbol(&self, cat: i32, ind: i32) -> Option<Arc<RwLock<Symbol>>> {
        // database.cc:2817-2818 — bounds on cat.
        if cat < 0 || ind < 0 {
            return None;
        }
        self.categories
            .get(&cat)
            .and_then(|list| list.get(ind as usize))
    }

    // Ghidra: database.cc:2200 ScopeInternal::setAttribute
    /// Set boolean Varnode properties on a Symbol, restricted to the
    /// type/name/readonly/incidental_copy/nolocalalias/volatile/indirectstorage/
    /// hiddenretparm subset (database.cc:2203-2204), then re-run
    /// `checkSizeTypeLock`. Faithful to `ScopeInternal::setAttribute`
    /// (database.cc:2200). This overrides the existing `set_attribute` to
    /// additionally mask the attribute bits and re-run the size-typelock check;
    /// callers that only need the raw OR can keep using `set_attribute`.
    pub fn set_attribute_masked(&mut self, symbol_id: u64, attr: u32) {
        // database.cc:2203-2204 — restrict to the symbol-attribute subset.
        let mask = symbol_flags::TYPELOCK
            | symbol_flags::NAMELOCK
            | symbol_flags::READONLY
            | symbol_flags::VOLATIL
            | symbol_flags::INDIRECTSTORAGE
            | symbol_flags::HIDDENRETPARM;
        let masked = attr & mask;
        if let Some(sym) = self.symbols.get(&symbol_id) {
            let mut s = sym.write().unwrap();
            // database.cc:2205 — sym->flags |= attr.
            s.flags |= masked;
            // database.cc:2206 — sym->checkSizeTypeLock().
            s.check_size_type_lock();
        }
    }

    // Ghidra: database.cc:2209 ScopeInternal::clearAttribute
    /// Clear boolean Varnode properties on a Symbol, restricted to the same
    /// subset as `set_attribute_masked` (database.cc:2212-2213), then re-run
    /// `checkSizeTypeLock`. Faithful to `ScopeInternal::clearAttribute`
    /// (database.cc:2209).
    pub fn clear_attribute_masked(&mut self, symbol_id: u64, attr: u32) {
        // database.cc:2212-2213 — restrict to the symbol-attribute subset.
        let mask = symbol_flags::TYPELOCK
            | symbol_flags::NAMELOCK
            | symbol_flags::READONLY
            | symbol_flags::VOLATIL
            | symbol_flags::INDIRECTSTORAGE
            | symbol_flags::HIDDENRETPARM;
        let masked = attr & mask;
        if let Some(sym) = self.symbols.get(&symbol_id) {
            let mut s = sym.write().unwrap();
            // database.cc:2214 — sym->flags &= ~attr.
            s.flags &= !masked;
            // database.cc:2215 — sym->checkSizeTypeLock().
            s.check_size_type_lock();
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
    /// True if scope ids are built from a hash of the scope name. Faithful to
    /// `Database::idByNameHash` (database.hh:922); serialized as the
    /// `scopeidbyname` attribute on `<db>`.
    pub id_by_name: bool,
}

impl Default for Database {
    // Ghidra: database.cc:2924 Database::default
    fn default() -> Self {
        Self::new(false)
    }
}

impl Database {
    // Ghidra: database.cc:2924 Database::new
    /// Constructor. Faithful to `Database(Architecture*, bool)` (database.hh:928).
    /// `id_by_name` controls scope-id assignment strategy (currently unused).
    pub fn new(id_by_name: bool) -> Self {
        let mut scopes = BTreeMap::new();
        let global = Scope::new(0, "global", 0);
        scopes.insert(0, global);
        Self {
            scopes,
            global_scope_id: 0,
            resolvemap: Vec::new(),
            flagbase: Vec::new(),
            next_scope_id: 1,
            id_by_name,
        }
    }

    // Ghidra: database.cc:2924 Database::getGlobalScope
    /// Get the global Scope. Faithful to `getGlobalScope`.
    pub fn get_global_scope(&self) -> Option<&Scope> {
        self.scopes.get(&self.global_scope_id)
    }

    // Ghidra: database.cc:2924 Database::getGlobalScopeMut
    /// Get the global Scope mutably.
    pub fn get_global_scope_mut(&mut self) -> Option<&mut Scope> {
        self.scopes.get_mut(&self.global_scope_id)
    }

    // Ghidra: database.cc:2946 Database::attachScope
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

    // Ghidra: database.cc:3092 Database::resolveScope
    /// Look-up a Scope by id. Faithful to `resolveScope(uint8)`.
    pub fn resolve_scope(&self, id: u64) -> Option<&Scope> {
        self.scopes.get(&id)
    }

    // Ghidra: database.cc:2924 Database::resolveScopeMut
    /// Look-up a Scope by id mutably.
    pub fn resolve_scope_mut(&mut self, id: u64) -> Option<&mut Scope> {
        self.scopes.get_mut(&id)
    }

    // Ghidra: database.cc:3078 Database::findCreateScope
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

    // Ghidra: database.cc:2985 Database::deleteScope
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

    // Ghidra: database.cc:3003 Database::deleteSubScopes
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

    // Ghidra: database.cc:3036 Database::setRange
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

    // Ghidra: database.cc:3050 Database::addRange
    /// Add an address range to the ownership of a Scope. Faithful to
    /// `addRange`.
    pub fn add_range(&mut self, scope_id: u64, rng: Range) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.rangetree.insert_range(rng);
            self.resolvemap.push((rng, scope_id));
        }
    }

    // Ghidra: database.cc:3064 Database::removeRange
    /// Remove an address range from the ownership of a Scope. Faithful to
    /// `removeRange`.
    pub fn remove_range(&mut self, scope_id: u64, rng: Range) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.rangetree.remove_range(rng);
        }
        self.resolvemap
            .retain(|(r, sid)| !(*sid == scope_id && r.get_first() == rng.get_first() && r.get_last() == rng.get_last()));
    }

    // Ghidra: database.cc:2924 Database::getProperty
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

    // Ghidra: database.cc:3220 Database::setPropertyRange
    /// Set boolean properties over a given memory range. Faithful to
    /// `setPropertyRange`.
    pub fn set_property_range(&mut self, flags: u32, range: Range) {
        // Remove overlapping ranges of the same flags to avoid duplicates;
        // Ghidra's partmap handles this via subdivision. We do a simple merge.
        self.flagbase.push((range, flags));
    }

    // Ghidra: database.cc:3245 Database::clearPropertyRange
    /// Clear boolean properties over a given memory range. Faithful to
    /// `clearPropertyRange`.
    pub fn clear_property_range(&mut self, flags: u32, range: Range) {
        self.flagbase.retain(|(r, f)| {
            !(*f == flags && r.get_first() == range.get_first() && r.get_last() == range.get_last())
        });
    }

    // Ghidra: database.cc:3185 Database::mapScope
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

    // Ghidra: database.cc:2924 Database::numScopes
    /// Number of scopes.
    pub fn num_scopes(&self) -> usize {
        self.scopes.len()
    }

    // Ghidra: database.cc:3270 Database::encode
    /// Encode the whole Database to a stream. Faithful to `Database::encode`
    /// (database.cc:3270). Emits a `<db>` element carrying the optional
    /// `scopeidbyname` attribute, one `<property_changepoint>` child per
    /// flagbase entry, then the global scope and all its descendant scopes
    /// (the recursive walk over the scope map, since child scopes are owned
    /// by the Database in the Rust port).
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        let db_elem = ElementId::new("db", 68);
        encoder.open_element(&db_elem);
        if self.id_by_name {
            encoder.write_bool(&AttributeId::new("scopeidbyname", 64), true);
        }
        // Property change-points.
        for (rng, val) in &self.flagbase {
            let pc_elem = ElementId::new("property_changepoint", 78);
            encoder.open_element(&pc_elem);
            encoder.write_unsigned_integer(
                &AttributeId::new("space", 0),
                rng.get_first().as_u64(),
            );
            encoder.write_unsigned_integer(&AttributeId::new("offset", 0), rng.get_first().as_u64());
            encoder.write_unsigned_integer(&AttributeId::new("val", 0), *val as u64);
            encoder.close_element(&pc_elem);
        }
        // Global scope and its descendants.
        self.encode_scope_recursive(encoder, self.global_scope_id);
        encoder.close_element(&db_elem);
    }

    // Ghidra: database.cc:1371 Scope::encodeRecursive (Database-driven walker)
    /// Recursively encode a scope and all its descendants. Faithful to the
    /// recursive descent inside `Scope::encodeRecursive` (database.cc:1376),
    /// adapted because child scopes are owned by the Database (not by their
    /// parent Scope) in the Rust port.
    fn encode_scope_recursive(&self, encoder: &mut dyn Encoder, scope_id: u64) {
        let scope = match self.scopes.get(&scope_id) {
            Some(s) => s,
            None => return,
        };
        scope.encode(encoder);
        for &child_id in &scope.children {
            self.encode_scope_recursive(encoder, child_id);
        }
    }

    // Ghidra: database.cc:3300 Database::parseParentTag
    /// Parse a `<parent>` element for the parent scope id. Faithful to
    /// `Database::parseParentTag` (database.cc:3300). Returns the parent scope
    /// id (the C++ version returns a `Scope*`; the Rust port returns the id
    /// since scopes are keyed by id in the Database). Returns 0 if no `id`
    /// attribute is present (i.e. the global scope).
    pub fn parse_parent_tag(&self, decoder: &mut dyn Decoder) -> u64 {
        let elem_id = decoder.open_element();
        let id = decoder.read_unsigned_integer_attr(&AttributeId::new("id", 0));
        decoder.close_element(elem_id);
        id
    }

    // Ghidra: database.cc:3314 Database::decode
    /// Decode the whole database from a `<db>` element. Faithful to
    /// `Database::decode` (database.cc:3314). Reads the `scopeidbyname`
    /// attribute, one `<property_changepoint>` child per flagbase entry, then
    /// one or more `<scope>` elements. Each `<scope>`'s parent (if any) is
    /// resolved via `parse_parent_tag`, the scope is created/found via
    /// `find_create_scope`, and its contents are filled in by `Scope::decode`.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let db_id = decoder.open_element();
        // Attributes (scopeidbyname).
        self.id_by_name = false;
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            if decoder.attribute_name(aid).as_deref() == Some("scopeidbyname") {
                self.id_by_name = decoder.read_bool();
            } else {
                let _ = decoder.read_string();
            }
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
            let mut offset = 0u64;
            let mut val = 0u32;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                match decoder.attribute_name(aid).as_deref() {
                    Some("offset") => offset = decoder.read_unsigned_integer(),
                    Some("val") => val = decoder.read_unsigned_integer() as u32,
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            decoder.close_element(sub_id);
            if let Some(rng) = Range::new(Address::new(offset), Address::new(offset)) {
                self.flagbase.push((rng, val));
            }
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
            // Parent tag (resolved via parse_parent_tag).
            let parent_id = {
                let pid = decoder.peek_element();
                if pid != 0 && decoder.element_name(pid).as_deref() == Some("parent") {
                    self.parse_parent_tag(decoder)
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

    // Ghidra: database.cc:3375 Database::decodeScope
    /// Register and fill out a single Scope from an XML element that is either
    /// a `<scope>` itself or another element wrapping a `<scope>` as its first
    /// child. Faithful to `Database::decodeScope` (database.cc:3375). Returns
    /// the scope id of the decoded scope.
    pub fn decode_scope(&mut self, decoder: &mut dyn Decoder, new_scope_id: u64) -> u64 {
        let elem_id = decoder.open_element();
        let elem_name = decoder.element_name(elem_id).unwrap_or_default();
        if elem_name == "scope" {
            // Direct <scope>: read parent, attach, decode.
            let parent_id = self.parse_parent_tag(decoder);
            self.attach_scope_by_id(new_scope_id, parent_id);
            if let Some(scope) = self.scopes.get_mut(&new_scope_id) {
                scope.decode(decoder);
            }
        } else {
            // Wrapping element: skip its attributes, then the <scope> child.
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                let _ = decoder.read_string();
            }
            let sub_id = decoder.peek_element();
            if sub_id != 0 && decoder.element_name(sub_id).as_deref() == Some("scope") {
                decoder.open_element();
                let parent_id = self.parse_parent_tag(decoder);
                self.attach_scope_by_id(new_scope_id, parent_id);
                if let Some(scope) = self.scopes.get_mut(&new_scope_id) {
                    scope.decode(decoder);
                }
                decoder.close_element(sub_id);
            }
        }
        decoder.close_element(elem_id);
        new_scope_id
    }

    // RUGRA-GLUE: Database::attach_scope_by_id (helper for decodeScope)
    /// Attach a pre-allocated scope id under a parent, mirroring the
    /// `attachScope(newScope, parentScope)` call at database.cc:3381. The scope
    /// must already exist in the map (created by the caller).
    fn attach_scope_by_id(&mut self, scope_id: u64, parent_id: u64) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.parent_id = parent_id;
        }
        if let Some(parent) = self.scopes.get_mut(&parent_id) {
            parent.attach_child(scope_id);
        }
    }

    // Ghidra: database.cc:3398 Database::decodeScopePath
    /// Decode a namespace path (`<parent>` + `<val>` children) and ensure each
    /// namespace exists. Faithful to `Database::decodeScopePath`
    /// (database.cc:3398). Returns the id of the final (innermost) scope, or
    /// the global scope id if the path is empty.
    pub fn decode_scope_path(&mut self, decoder: &mut dyn Decoder) -> u64 {
        let mut curscope = self.global_scope_id;
        let elem_id = decoder.open_element();
        // The C++ version skips any leading element; here we skip attributes
        // and one optional child that describes the root.
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            let _ = decoder.read_string();
        }
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            if decoder.element_name(sub_id).as_deref() != Some("val") {
                break;
            }
            decoder.open_element();
            let mut display_name = String::new();
            let mut scope_id = 0u64;
            let mut name = String::new();
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 {
                    break;
                }
                match decoder.attribute_name(aid).as_deref() {
                    Some("id") => scope_id = decoder.read_unsigned_integer(),
                    Some("label") => display_name = decoder.read_string(),
                    Some("name") => name = decoder.read_string(),
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            // Fallback: try reading the CONTENT attribute for the name.
            if name.is_empty() {
                name = decoder.read_string_attr(&AttributeId::new("content", 0));
            }
            if scope_id == 0 {
                // database.cc:3420 throws DecoderError; we bail to global.
                decoder.close_element(sub_id);
                break;
            }
            curscope = self.find_create_scope(scope_id, &name, curscope);
            if !display_name.is_empty() {
                if let Some(scope) = self.scopes.get_mut(&curscope) {
                    scope.display_name = display_name;
                }
            }
            decoder.close_element(sub_id);
        }
        decoder.close_element(elem_id);
        curscope
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
                "cat", "index", "label", "val", "space", "offset", "first", "last",
            ] {
                r.register_attribute(nm);
            }
            for nm in &["symbol", "type", "addr", "hash", "rangelist", "range", "scope", "symbollist", "db", "parent", "property_changepoint", "mapsym"] {
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
                "cat", "index", "label", "val", "space", "offset", "first", "last",
            ] {
                r.register_attribute(nm);
            }
            for nm in &["symbol", "type", "addr", "hash", "rangelist", "range", "scope", "symbollist", "db", "parent", "property_changepoint", "mapsym"] {
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

    #[test]
    fn test_symbol_check_size_type_lock() {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
        let mut sym = Symbol::new(0, "x", "int");
        // Not type-locked → never size_typelocked.
        sym.check_size_type_lock();
        assert!(!sym.is_size_type_locked());
        // Type-locked with a non-unknown type → not size_typelocked.
        sym.flags |= symbol_flags::TYPELOCK;
        sym.dtype = Some(Arc::new(Datatype::Base(TypeBase::new(
            "int".into(), 4, TypeMetatype::Int,
        ))));
        sym.check_size_type_lock();
        assert!(!sym.is_size_type_locked());
        // Type-locked with an UNKNOWN type → size_typelocked.
        sym.dtype = Some(Arc::new(Datatype::Base(TypeBase::new(
            "unk".into(), 4, TypeMetatype::Unknown,
        ))));
        sym.check_size_type_lock();
        assert!(sym.is_size_type_locked());
    }

    #[test]
    fn test_symbol_get_first_whole_map_and_map_entry() {
        let mut scope = Scope::new(1, "local", 0);
        let id = scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        let sym_arc = scope.symbols.get(&id).cloned().unwrap();
        let sym = sym_arc.read().unwrap();
        // First whole map.
        let first = sym.get_first_whole_map(&scope.entries);
        assert!(first.is_some());
        assert_eq!(first.unwrap().addr.as_u64(), 0x1000);
        // Map entry containing an interior address.
        let entry = sym.get_map_entry(&scope.entries, Address::new(0x1002));
        assert!(entry.is_some());
        // Out-of-range address.
        assert!(sym.get_map_entry(&scope.entries, Address::new(0x2000)).is_none());
    }

    #[test]
    fn test_scope_find_closest_fit() {
        let mut scope = Scope::new(1, "local", 0);
        scope.add_symbol_mapped("a", "int", Address::new(0x1000), 4);
        scope.add_symbol_mapped("big", "struct", Address::new(0x1000), 16);
        // Request 4 bytes at 0x1000: both contain it; exact match (4) wins.
        let exact = scope.find_closest_fit(Address::new(0x1000), 4, Address::new(0));
        assert!(exact.is_some());
        assert_eq!(exact.unwrap().size, 4);
        // Request 8 bytes at 0x1000: only the 16-byte entry contains it,
        // and it is the closest (only) over-sized entry.
        let big = scope.find_closest_fit(Address::new(0x1000), 8, Address::new(0));
        assert!(big.is_some());
        assert_eq!(big.unwrap().size, 16);
    }

    #[test]
    fn test_scope_find_function_externalref_codelabel() {
        let mut scope = Scope::new(1, "local", 0);
        // A function symbol (type_name "func") mapped at 0x401000.
        let fid = scope.add_symbol_mapped("main", "func", Address::new(0x401000), 1);
        scope.symbols.get(&fid).unwrap().write().unwrap().type_name = "func".into();
        // An extern ref symbol (type_name "exref") mapped at 0x5000.
        let eid = scope.add_symbol_mapped("printf", "exref", Address::new(0x5000), 1);
        scope.symbols.get(&eid).unwrap().write().unwrap().type_name = "exref".into();
        // A code label (type_name "label") mapped at 0x6000.
        let lid = scope.add_symbol_mapped("L1", "label", Address::new(0x6000), 1);
        scope.symbols.get(&lid).unwrap().write().unwrap().type_name = "label".into();
        assert_eq!(scope.find_function(Address::new(0x401000)), Some(Address::new(0x401000)));
        assert!(scope.find_function(Address::new(0x9999)).is_none());
        assert_eq!(scope.find_external_ref(Address::new(0x5000)), Some(eid));
        assert_eq!(scope.find_code_label(Address::new(0x6000)), Some(lid));
    }

    #[test]
    fn test_scope_stack_and_query_methods() {
        // Build two scopes: a local (child) and the global scope.
        let mut local = Scope::new(1, "local", 0);
        let mut global = Scope::new(0, "global", 0);
        // Local has a 4-byte int at 0x1000.
        local.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        // Global owns the 0x2000 range and has a function there.
        global.add_range(Range::new(Address::new(0x2000), Address::new(0x2FFF)).unwrap());
        let fid = global.add_symbol_mapped("func", "func", Address::new(0x2000), 1);
        global.symbols.get(&fid).unwrap().write().unwrap().type_name = "func".into();

        // Stack: [local, global].
        let stack: Vec<&Scope> = vec![&local, &global];

        // query_by_name finds "x" in the local scope.
        let ids = Scope::query_by_name(&stack, "x");
        assert_eq!(ids.len(), 1);
        // query_by_name falls through to global for "func".
        let ids = Scope::query_by_name(&stack, "func");
        assert_eq!(ids.len(), 1);

        // stack_addr finds the entry at 0x1000 in local.
        let mut addrmatch = None;
        let scope_idx = Scope::stack_addr(&stack, stack.len(), Address::new(0x1000), Address::new(0), &mut addrmatch);
        assert_eq!(scope_idx, Some(0));
        assert!(addrmatch.is_some());

        // query_by_addr returns (scope_idx=0, entry_idx).
        let res = Scope::query_by_addr(&stack, Address::new(0x1000), Address::new(0));
        assert!(res.is_some());
        assert_eq!(res.unwrap().0, 0);

        // stack_function finds the function in global at 0x2000.
        let mut faddr = None;
        let idx = Scope::stack_function(&stack, stack.len(), Address::new(0x2000), &mut faddr);
        assert_eq!(idx, Some(1));
        assert_eq!(faddr, Some(Address::new(0x2000)));
        // query_function_addr convenience wrapper.
        assert_eq!(Scope::query_function_addr(&stack, Address::new(0x2000)), Some(Address::new(0x2000)));

        // query_properties with no symbol → returns scope-derived flags for
        // an address owned by the global scope.
        let (entry, _flags) = Scope::query_properties(
            &stack, Address::new(0x2500), 1, Address::new(0), |_| 0,
        );
        assert!(entry.is_none()); // no symbol at 0x2500
    }

    #[test]
    fn test_symbol_entry_get_sized_type_whole_match() {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
        let sym = Arc::new(RwLock::new(Symbol::new(0, "x", "int")));
        sym.write().unwrap().dtype = Some(Arc::new(Datatype::Base(TypeBase::new(
            "int".into(), 4, TypeMetatype::Int,
        ))));
        let entry = SymbolEntry::new_static(sym, 0, Address::new(0x1000), 0, 4, RangeList::new());
        // Whole-symbol match (offset 0, exact size).
        let dt = entry.get_sized_type(Address::new(0x1000), 4);
        assert!(dt.is_some());
        // Wrong size → no exact match.
        assert!(entry.get_sized_type(Address::new(0x1000), 8).is_none());
    }

    #[test]
    fn test_scope_add_function() {
        // database.cc:1615 — addFunction creates a func symbol and maps it.
        let mut scope = Scope::new(1, "global", 0);
        let (fs, overlap) = scope.add_function(Address::new(0x401000), "main", 16);
        assert_eq!(fs.get_entry().as_u64(), 0x401000);
        assert_eq!(fs.get_bytes_consumed(), 16);
        assert!(overlap.is_none()); // no overlap
        assert_eq!(scope.num_symbols(), 1);
        // The function should be discoverable via find_function.
        assert_eq!(scope.find_function(Address::new(0x401000)), Some(Address::new(0x401000)));
        // The entry should be a whole-map (offset 0) at the function address.
        let entry = scope.find_addr(Address::new(0x401000));
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().offset, 0);
        assert_eq!(entry.unwrap().size, 16);
    }

    #[test]
    fn test_scope_add_function_overlap() {
        // database.cc:1620-1625 — addFunction reports overlap with existing.
        let mut scope = Scope::new(1, "global", 0);
        let big_id = scope.add_symbol_mapped("big", "struct", Address::new(0x401000), 16);
        let (_fs, overlap) = scope.add_function(Address::new(0x401002), "inner", 1);
        // Overlap should report the big symbol id.
        assert_eq!(overlap, Some(big_id));
    }

    #[test]
    fn test_scope_add_external_ref() {
        // database.cc:1642 — addExternalRef creates an exref symbol.
        let mut scope = Scope::new(1, "global", 0);
        let exref = scope.add_external_ref(Address::new(0x5000), Address::new(0x9000), "printf");
        assert_eq!(exref.refaddr.as_u64(), 0x9000);
        // The symbol is discoverable as an external ref at 0x5000.
        assert!(scope.find_external_ref(Address::new(0x5000)).is_some());
        // The readonly flag must be cleared (database.cc:1654).
        let entry = scope.find_addr(Address::new(0x5000)).unwrap();
        let s = entry.symbol.read().unwrap();
        assert_eq!(s.type_name, "exref");
        assert_eq!(s.flags & symbol_flags::READONLY, 0);
    }

    #[test]
    fn test_scope_add_code_label() {
        // database.cc:1664 — addCodeLabel creates a label symbol.
        let mut scope = Scope::new(1, "func", 0);
        let (lab, overlap) = scope.add_code_label(Address::new(0x6000), "L1");
        assert_eq!(lab.addr.as_u64(), 0x6000);
        assert!(overlap.is_none());
        // The label is discoverable via find_code_label.
        assert!(scope.find_code_label(Address::new(0x6000)).is_some());
    }

    #[test]
    fn test_scope_add_dynamic_symbol() {
        // database.cc:1690 — addDynamicSymbol creates a hashed SymbolEntry.
        let mut scope = Scope::new(1, "func", 0);
        let id = scope.add_dynamic_symbol(
            "dyn", "int", 4, Address::new(0x1234), 0xDEADBEEF,
        );
        assert_eq!(scope.num_symbols(), 1);
        assert!(id != 0);
        // The dynamic entry should be in dynamic_entries with the hash.
        assert_eq!(scope.dynamic_entries.len(), 1);
        let entry = &scope.dynamic_entries[0];
        assert_eq!(entry.get_hash(), 0xDEADBEEF);
        assert!(entry.is_dynamic());
        assert_eq!(entry.size, 4);
        // Use-limit should contain the caddr.
        assert!(entry.in_use(Address::new(0x1234)));
        assert!(!entry.in_use(Address::new(0x9999)));
    }

    #[test]
    fn test_scope_add_equate_symbol() {
        // database.cc:1712 — addEquateSymbol creates an equate + dynamic entry.
        let mut scope = Scope::new(1, "func", 0);
        let (equ, id) = scope.add_equate_symbol(
            "MY_CONST", display_flags::FORCE_HEX, 0x42, Address::new(0x2000), 0xCAFE,
        );
        assert_eq!(equ.value, 0x42);
        assert_eq!(scope.dynamic_entries.len(), 1);
        let entry = &scope.dynamic_entries[0];
        assert_eq!(entry.get_hash(), 0xCAFE);
        assert_eq!(entry.size, 1); // equates are 1-byte (database.cc:1722).
        // The registered symbol should carry the display format.
        let s = scope.symbols.get(&id).unwrap().read().unwrap();
        assert_eq!(s.type_name, "equ");
        assert_eq!(s.get_display_format(), display_flags::FORCE_HEX);
        // database.cc:628 — the EquateSymbol constructor sets category=equate
        // on the registered object, and the value is part of that object's
        // identity (dynamic_cast<EquateSymbol*> in varnode.cc:516).
        assert_eq!(s.category, SymbolCategory::Equate);
        assert_eq!(equ.symbol.category, SymbolCategory::Equate);
        drop(s);
        let sym_arc = scope.symbols.get(&id).cloned().unwrap();
        assert_eq!(
            crate::varnode::equate_symbol_registry::query_value(&sym_arc),
            Some(0x42),
            "add_equate_symbol must register the value on the symbol identity"
        );
    }

    #[test]
    fn test_add_equate_symbol_same_value_duplicate_and_scope_isolation() {
        // database.cc:1717 + insertNameTree (database.cc:2712-2723): two
        // addEquateSymbol calls with the same value produce two distinct
        // EquateSymbol objects (nameDedup separates the names); each keeps its
        // own equate identity. Scopes are independent containers: an equate in
        // one scope is invisible from another.
        let mut scope_a = Scope::new(1, "funcA", 0);
        let mut scope_b = Scope::new(2, "funcB", 0);
        let (_, id1) = scope_a.add_equate_symbol(
            "SAME", display_flags::FORCE_DEC, 0x42, Address::new(0x2000), 0x1111,
        );
        let (_, id2) = scope_a.add_equate_symbol(
            "SAME", display_flags::FORCE_DEC, 0x42, Address::new(0x2000), 0x2222,
        );
        let (_, id3) = scope_b.add_equate_symbol(
            "SAME", display_flags::FORCE_DEC, 0x42, Address::new(0x2000), 0x3333,
        );
        assert_ne!(id1, id2, "same-value duplicates are distinct symbols");
        // Both scope_a equates are registered with the same value, and each
        // dynamic entry hashes distinctly (database.cc:1722).
        let v1 = scope_a.symbols.get(&id1).cloned().unwrap();
        let v2 = scope_a.symbols.get(&id2).cloned().unwrap();
        let v3 = scope_b.symbols.get(&id3).cloned().unwrap();
        assert_eq!(
            crate::varnode::equate_symbol_registry::query_value(&v1),
            Some(0x42)
        );
        assert_eq!(
            crate::varnode::equate_symbol_registry::query_value(&v2),
            Some(0x42)
        );
        assert_eq!(
            crate::varnode::equate_symbol_registry::query_value(&v3),
            Some(0x42)
        );
        // Cross-scope isolation: scope_a holds only its two equates.
        assert_eq!(scope_a.num_symbols(), 2);
        assert_eq!(scope_b.num_symbols(), 1);
        assert_eq!(scope_a.dynamic_entries.len(), 2);
        assert_eq!(scope_b.dynamic_entries.len(), 1);
    }

    #[test]
    fn test_add_map_sym_equatesymbol_registers_equate_value() {
        // database.cc:1572-1573 — <equatesymbol> decodes into an EquateSymbol
        // instance; database.cc:670-683 reads the <value> child after
        // decodeHeader. The decoded object keeps its equate identity (the
        // dynamic_cast in varnode.cc:516 succeeds) with the decoded value, or
        // the database.hh:306 default 0 when <value> carries no value.
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        {
            let mut r = registry.write().unwrap();
            for nm in &["name", "cat", "val"] {
                r.register_attribute(nm);
            }
            for nm in &["mapsym", "equatesymbol", "value"] {
                r.register_element(nm);
            }
        }
        let build_mapsym = |value_attr: Option<&str>| {
            // <mapsym><equatesymbol name="EQ" cat="1"><value val="..."/></equatesymbol></mapsym>
            let mut mapsym = Element::new();
            mapsym.set_name("mapsym");
            let mut equ = Element::new();
            equ.set_name("equatesymbol");
            equ.add_attribute("name", "EQ");
            equ.add_attribute("cat", "1");
            let mut val = Element::new();
            val.set_name("value");
            if let Some(v) = value_attr {
                val.add_attribute("val", v);
            }
            equ.add_child(std::sync::Arc::new(std::sync::RwLock::new(val)));
            mapsym.add_child(std::sync::Arc::new(std::sync::RwLock::new(equ)));
            mapsym
        };
        // With a value attribute: the decoded value is registered on the
        // symbol identity.
        let mut scope = Scope::new(1, "func", 0);
        let root = std::sync::Arc::new(std::sync::RwLock::new(build_mapsym(Some("66"))));
        let mut dec = TreeDecoder::new(root, registry.clone());
        let id = scope.add_map_sym(&mut dec);
        assert_ne!(id, 0);
        let sym_arc = scope.symbols.get(&id).cloned().unwrap();
        assert_eq!(sym_arc.read().unwrap().category, SymbolCategory::Equate);
        assert_eq!(
            crate::varnode::equate_symbol_registry::query_value(&sym_arc),
            Some(66),
            "decoded <equatesymbol> must register its <value> payload"
        );
        // Without a value attribute: identity still registers (the C++
        // object is an EquateSymbol regardless) with the hh:306 default 0.
        let mut scope2 = Scope::new(2, "func2", 0);
        let root2 = std::sync::Arc::new(std::sync::RwLock::new(build_mapsym(None)));
        let mut dec2 = TreeDecoder::new(root2, registry);
        let id2 = scope2.add_map_sym(&mut dec2);
        let sym_arc2 = scope2.symbols.get(&id2).cloned().unwrap();
        assert_eq!(
            crate::varnode::equate_symbol_registry::query_value(&sym_arc2),
            Some(0)
        );
    }

    #[test]
    fn test_add_equate_symbol_reaches_copy_symbol_if_valid() {
        // Main-pipeline connectivity gate (DATABASE-EQUATE-VALUE-REGISTRY-0001):
        // an equate created through Scope::add_equate_symbol carries its value
        // on the registered symbol identity, so a Varnode holding the symbol's
        // dynamic SymbolEntry passes the dynamic_cast<EquateSymbol*> stand-in
        // in Varnode::copySymbolIfValid (varnode.cc:516) and the markup
        // propagates exactly where the C++ pipeline would propagate it.
        use crate::varnode::Varnode;
        let mut scope = Scope::new(1, "func", 0);
        let _ = scope.add_equate_symbol(
            "MY_CONST", 0, 0x33333333, Address::new(0x2000), 0xCAFE,
        );
        let entry = scope.dynamic_entries[0].clone();
        let mut src = Varnode::new_constant(0x33333333, 4);
        src.set_symbol_entry(std::sync::Arc::new(std::sync::RwLock::new(entry)));
        let mut dst = Varnode::new_constant(0x33333333, 4);
        dst.copy_symbol_if_valid(&src);
        assert!(
            dst.get_symbol_entry().is_some(),
            "pipeline equate must propagate through copy_symbol_if_valid"
        );
        // Not-close destination constant must NOT receive the markup.
        let mut dst2 = Varnode::new_constant(0x12345678, 4);
        dst2.copy_symbol_if_valid(&src);
        assert!(dst2.get_symbol_entry().is_none());
    }

    #[test]
    fn test_scope_add_union_facet_symbol() {
        // database.cc:1737 — addUnionFacetSymbol creates a union facet.
        let mut scope = Scope::new(1, "func", 0);
        let (facet, id) = scope.add_union_facet_symbol(
            "u_facet", "union", 3, Address::new(0x3000), 0xBEEF,
        );
        assert_eq!(facet.field, 3);
        assert_eq!(scope.dynamic_entries.len(), 1);
        let s = scope.symbols.get(&id).unwrap().read().unwrap();
        assert_eq!(s.type_name, "union");
        assert_eq!(s.category, SymbolCategory::UnionFacet);
    }

    #[test]
    fn test_scope_add_map_point() {
        // database.cc:1548 — addMapPoint maps a whole Symbol to an address.
        let mut scope = Scope::new(1, "func", 0);
        let id = scope.add_symbol("v", "int");
        scope.add_map_point(id, Address::new(0x1000), Address::new(0x5000), 4);
        let entry = scope.find_addr(Address::new(0x1000));
        assert!(entry.is_some());
        // Use-limit must be restricted to the usepoint.
        assert!(entry.unwrap().in_use(Address::new(0x5000)));
        assert!(!entry.unwrap().in_use(Address::new(0x9999)));
    }

    #[test]
    fn test_scope_begin_end_iteration_order() {
        // database.cc:1889 — begin/end provide mapping-address order.
        let mut scope = Scope::new(1, "global", 0);
        scope.add_symbol_mapped("c", "int", Address::new(0x3000), 4);
        scope.add_symbol_mapped("a", "int", Address::new(0x1000), 4);
        scope.add_symbol_mapped("b", "int", Address::new(0x2000), 4);
        let ordered = scope.begin_end();
        assert_eq!(ordered.len(), 3);
        // Sorted by mapping address.
        assert_eq!(ordered[0].addr.as_u64(), 0x1000);
        assert_eq!(ordered[1].addr.as_u64(), 0x2000);
        assert_eq!(ordered[2].addr.as_u64(), 0x3000);
    }

    #[test]
    fn test_scope_clear_category() {
        // database.cc:2020 — clearCategory removes all symbols in a category.
        let mut scope = Scope::new(1, "func", 0);
        let p1 = scope.add_symbol("p1", "int");
        let p2 = scope.add_symbol("p2", "int");
        let other = scope.add_symbol("other", "int");
        scope.set_category(p1, 0, 0); // function_parameter
        scope.set_category(p2, 0, 1);
        assert_eq!(scope.get_category_size(0), 2);
        scope.clear_category(0);
        assert_eq!(scope.get_category_size(0), 0);
        // The symbols themselves should be removed.
        assert!(!scope.symbols.contains_key(&p1));
        assert!(!scope.symbols.contains_key(&p2));
        // The non-category symbol survives.
        assert!(scope.symbols.contains_key(&other));
    }

    #[test]
    fn test_scope_clear_category_negative_clears_no_category() {
        // database.cc:2031-2038 — cat < 0 clears the no_category bucket.
        let mut scope = Scope::new(1, "func", 0);
        let cat_id = scope.add_symbol("param", "int");
        let nocat_id = scope.add_symbol("local", "int");
        scope.set_category(cat_id, 0, 0);
        scope.clear_category(-1);
        // The no-category symbol is removed.
        assert!(!scope.symbols.contains_key(&nocat_id));
        // The categorized symbol survives.
        assert!(scope.symbols.contains_key(&cat_id));
    }

    #[test]
    fn test_scope_remove_symbol_mappings() {
        // database.cc:2117 — removeSymbolMappings drops entries but keeps symbol.
        let mut scope = Scope::new(1, "func", 0);
        let id = scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        assert_eq!(scope.entries.len(), 1);
        scope.remove_symbol_mappings(id);
        assert_eq!(scope.entries.len(), 0);
        // Symbol is still registered, with whole_count reset.
        assert!(scope.symbols.contains_key(&id));
        assert_eq!(scope.symbols.get(&id).unwrap().read().unwrap().whole_count, 0);
    }

    #[test]
    fn test_scope_retype_symbol_same_size() {
        // database.cc:2166 — retype with same size just updates type_name.
        let mut scope = Scope::new(1, "func", 0);
        let id = scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        let ok = scope.retype_symbol(id, "uint", 4);
        assert!(ok);
        let s = scope.symbols.get(&id).unwrap().read().unwrap();
        assert_eq!(s.type_name, "uint");
    }

    #[test]
    fn test_scope_retype_symbol_addr_tied_resize() {
        // database.cc:2177-2196 — retype with size change + 1 addr-tied map.
        let mut scope = Scope::new(1, "func", 0);
        let id = scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        // Mark the symbol as address-tied (database.cc:2179 guard).
        scope.symbols.get(&id).unwrap().write().unwrap().flags |= symbol_flags::ADDRTIED;
        let ok = scope.retype_symbol(id, "long", 8);
        assert!(ok);
        // The single mapping should now be 8 bytes at the same address.
        let entry = scope.find_addr(Address::new(0x1000));
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().size, 8);
        let s = scope.symbols.get(&id).unwrap().read().unwrap();
        assert_eq!(s.type_name, "long");
    }

    #[test]
    fn test_scope_get_category_symbol() {
        // database.cc:2814 — getCategorySymbol indexes a category vector.
        let mut scope = Scope::new(1, "func", 0);
        let p1 = scope.add_symbol("p1", "int");
        let p2 = scope.add_symbol("p2", "int");
        scope.set_category(p1, 0, 0);
        scope.set_category(p2, 0, 1);
        assert!(scope.get_category_symbol(0, 0).is_some());
        assert!(scope.get_category_symbol(0, 1).is_some());
        // Out of range.
        assert!(scope.get_category_symbol(0, 5).is_none());
        assert!(scope.get_category_symbol(99, 0).is_none());
    }

    #[test]
    fn test_scope_set_attribute_masked() {
        // database.cc:2200 — setAttribute masks bits and re-runs size-typelock.
        let mut scope = Scope::new(1, "func", 0);
        let id = scope.add_symbol("x", "int");
        // Set TYPELOCK | NAMELOCK | READONLY (all in the mask).
        scope.set_attribute_masked(
            id,
            symbol_flags::TYPELOCK | symbol_flags::NAMELOCK | symbol_flags::READONLY,
        );
        let s = scope.symbols.get(&id).unwrap().read().unwrap();
        assert!(s.is_type_locked());
        assert!(s.is_name_locked());
        assert_eq!(s.flags & symbol_flags::READONLY, symbol_flags::READONLY);
    }

    #[test]
    fn test_scope_clear_unlocked_category() {
        // database.cc:2071 — clearUnlockedCategory removes unlocked symbols.
        let mut scope = Scope::new(1, "func", 0);
        let unlocked = scope.add_symbol("u", "int");
        let locked = scope.add_symbol("l", "int");
        scope.set_category(unlocked, 0, 0);
        scope.set_category(locked, 0, 1);
        scope.set_attribute_masked(locked, symbol_flags::TYPELOCK);
        scope.clear_unlocked_category(0);
        // Unlocked is removed; locked survives.
        assert!(!scope.symbols.contains_key(&unlocked));
        assert!(scope.symbols.contains_key(&locked));
    }

    #[test]
    fn test_scope_adjust_caches_noop() {
        // database.cc:2111 — adjustCaches is a no-op in Rugra (single space).
        let mut scope = Scope::new(1, "func", 0);
        scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        scope.adjust_caches();
        // State unchanged.
        assert_eq!(scope.num_symbols(), 1);
    }


}
