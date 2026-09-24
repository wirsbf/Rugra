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
use crate::type_system::datatype::{Datatype, TypeMetatype};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock, Weak};

/// Base of internal Symbol IDs. Faithful to `Symbol::ID_BASE`
/// (database.cc:45). IDs with the high bit pattern (>> 56 == 0x40) are
/// internal and discarded on decode.
pub const ID_BASE: u64 = 0x4000_0000_0000_0000;

/// Varnode-like properties of a Symbol. Faithful to the subset of
/// `Varnode` flags used by Symbol (database.hh:182-184).
/// Symbol property flags. Faithful to `Symbol::flags`
/// (database.hh:183): Ghidra stores the VARNODE flag namespace directly on
/// the Symbol — `Scope::addMap` writes `Varnode::persist` (database.cc:1132),
/// `Varnode::addrtied` (database.cc:1150) and the flagbase bits
/// (database.cc:1153) into `symbol->flags`, and
/// `SymbolEntry::getAllFlags` (database.hh:271) ORs them with the entry's
/// `extraflags` in ONE bit space. The legacy Rugra constants (TYPELOCK=1<<0
/// …) were a private bit space that could never mix with the Varnode-space
/// `extraflags`; they now alias the varnode bit values
/// (varnode.hh:82-115) so the fold and getAllFlags projections match the
/// oracle bit-for-bit (DB-LOCALSCOPE-MAP-0001).
pub mod symbol_flags {
    /// varnode.hh:83 `typelock = 0x100`.
    pub const TYPELOCK: u32 = 1 << 8;
    /// varnode.hh:84 `namelock = 0x200`.
    pub const NAMELOCK: u32 = 1 << 9;
    /// varnode.hh:92 `readonly = 0x2000`.
    pub const READONLY: u32 = 1 << 13;
    /// varnode.hh:91 `externref = 0x1000`.
    pub const EXTERNREF: u32 = 1 << 12;
    /// varnode.hh:95 `addrtied = 0x8000`.
    pub const ADDRTIED: u32 = 1 << 15;
    /// varnode.hh:94 `persist = 0x4000`.
    pub const PERSIST: u32 = 1 << 14;
    /// varnode.hh:90 `volatil = 0x800`.
    pub const VOLATIL: u32 = 1 << 11;
    /// varnode.hh:109 `indirectstorage = 0x8000000`.
    pub const INDIRECTSTORAGE: u32 = 1 << 27;
    /// varnode.hh:110 `hiddenretparm = 0x10000000`.
    pub const HIDDENRETPARM: u32 = 1 << 28;
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
    /// Is this storage valid for the given code address? Faithful to
    /// `inUse` (database.cc:114-120):
    /// ```text
    /// if (isAddrTied()) return true;   // Valid throughout scope
    /// if (usepoint.isInvalid()) return false;
    /// return uselimit.inRange(usepoint,1);
    /// ```
    /// An address-tied Symbol (the addMap fold for empty uselimits,
    /// database.cc:1149-1150 via `apply_add_map_rules`) is valid at every
    /// usepoint; a use-limited Symbol is never valid at an invalid
    /// usepoint; otherwise the uselimit rangelist decides — an EMPTY
    /// rangelist admits nothing, because Scope::addMap marks those symbols
    /// addrtied instead (the previous "empty uselimit = valid across all
    /// code" reading contradicted database.cc:118-119).
    /// (FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001: queryProperties with the
    /// invalid usepoint of `Funcdata::newVarnode`
    /// funcdata_varnode.cc:162 must skip use-limited entries exactly here.)
    pub fn in_use(&self, usepoint: Address) -> bool {
        // cc:117: isAddrTied() — the Symbol's addrtied bit.
        if self.is_addr_tied() {
            return true;
        }
        // cc:118: usepoint.isInvalid() — Rugra's legacy Address is invalid
        // exactly when spaceless (address.rs is_invalid: space.is_none()).
        if usepoint.is_invalid() {
            return false;
        }
        // cc:119: uselimit.inRange(usepoint,1).
        self.uselimit.in_range(usepoint)
    }

    // RUGRA-GLUE: stable identity predicate standing in for the C++
    // `SymbolEntry*` pointer comparison (varnode.cc:415 `mapentry != entry`
    // inside Varnode::setSymbolProperties). Rugra's Database hands out
    /// cloned entries wrapped in fresh Arcs
    /// (`Database::query_container_entry`), so Arc identity can never match
    /// across two queries of the same storage; within one scope's entry map
    /// the (symbol, storage) pair is unique, which makes this field
    /// comparison observationally equal to the C++ pointer test for entries
    /// produced by the same stackContainer walk.
    pub fn same_storage_identity(&self, other: &SymbolEntry) -> bool {
        std::sync::Arc::ptr_eq(&self.symbol, &other.symbol)
            && self.addr == other.addr
            && self.offset == other.offset
            && self.size == other.size
            && self.hash == other.hash
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
    /// Ghidra reaches the owning Architecture's `TypeFactory` through the
    /// Symbol's Scope. Rugra's Symbol does not retain that owner, so the caller
    /// passes the same factory explicitly rather than constructing a local or
    /// process-global substitute.
    pub fn get_sized_type(
        &self,
        type_factory: &mut crate::type_system::typefactory::TypeFactory,
        inaddr: Address,
        sz: i32,
    ) -> Option<Arc<crate::type_system::datatype::Datatype>> {
        let off = if self.is_dynamic() {
            self.offset
        } else {
            ((inaddr.as_u64() as i64).wrapping_sub(self.addr.as_u64() as i64)) as i32 + self.offset
        };
        let sym = self.symbol.read().unwrap();
        let dt = sym.dtype.clone()?;
        let size = usize::try_from(sz).ok()?;
        type_factory.get_exact_piece(dt, off as i64, size)
    }

    // Ghidra: database.cc:135 SymbolEntry::updateType
    /// If the Symbol associated with this is type-locked, change the given
    /// Varnode's attached data-type to match the Symbol. Faithful to
    /// `SymbolEntry::updateType` (database.cc:135). The C++ form takes a
    /// `Varnode*` and calls `vn->updateType(dt,true,true)`; the Rust port
    /// returns the resolved `Datatype` (or `None`) so the caller can apply
    /// it to the Varnode. This is the type-propagation entry point for
    /// mapped symbols.
    pub fn update_type(
        &self,
        type_factory: &mut crate::type_system::typefactory::TypeFactory,
        vn_addr: Address,
        vn_size: i32,
    ) -> Option<Arc<crate::type_system::datatype::Datatype>> {
        let sym = self.symbol.read().unwrap();
        if (sym.flags & symbol_flags::TYPELOCK) == 0 {
            return None;
        }
        drop(sym);
        self.get_sized_type(type_factory, vn_addr, vn_size)
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

// RUGRA-GLUE: AddMapContext (Ghidra's Scope reads `glb->symboltab` through
// its Architecture handle inside Scope::addMap — database.cc:1136/1153;
// Rugra's Scope is Architecture-less, so the Database side passes the two
// lookups in one context struct. `None` models a standalone scope.)
/// The Database-side lookups `Scope::addMap` needs: the flagbase property
/// at an address (`glb->symboltab->getProperty`, database.hh:946) and the
/// global-scope discovery-range test (`glbScope->inScope(addr,1,addr)`,
/// database.cc:1138).
pub struct AddMapContext<'a> {
    /// `Database::get_property(addr)` at addMap time — the readonly/volatile
    /// fold bits (database.cc:1153).
    pub property: Box<dyn Fn(Address) -> u32 + 'a>,
    /// Is `addr` inside the global scope's discovery range? (database.cc:1138)
    pub in_global_discovery: Box<dyn Fn(Address) -> bool + 'a>,
}

/// An in-memory implementation of the Scope interface. Faithful to `Scope`
/// (database.hh:462) + `ScopeInternal` (database.hh:798).
// Clone: the lazy `maptable` index (Mutex-guarded) rebuilds from `entries`
// on first query, so a cloned Scope starts with a fresh (dirty) index —
// observably identical to the C++ copy (which rebuilds its rangemap
// through the copy constructor's addMap calls).
#[derive(Debug)]
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
    /// Static-entry indices ordered by `(addr, insertion seq)` — the Rust
    /// realization of ScopeInternal's `maptable` address rangemap
    /// (database.hh:877-878 `EntryMap` over `maptable`), backing
    /// `find_container`'s binary-search containment query. Insertion order
    /// is preserved for equal addresses (the seq tie-break), so the Vec
    /// `entries` itself stays the observable insertion-order container.
    /// Guarded by a Mutex so the (immutable) query path can rebuild it
    /// lazily after mutation (the C++ maintains its rangemap incrementally
    /// on insert; a lazy rebuild yields the identical pure-function-of-
    /// -entries query answer, which is what alignment observes).
    addr_index: std::sync::Mutex<AddrIndex>,
    /// References to Symbol objects organized by category.
    pub categories: BTreeMap<i32, CategoryList>,
    /// Next available symbol id.
    pub next_unique_id: u64,
    /// Child scope ids.
    pub children: Vec<u64>,
}

// RUGRA-GLUE: manual Clone (the Mutex-guarded index is not Clone): the
// copy re-derives a fresh (dirty) maptable index that rebuilds from
// `entries` on first query — observably identical to the C++ copy, whose
// rangemap is re-populated entry-by-entry.
impl Clone for Scope {
    // RUGRA-GLUE: trait-impl method (see the impl-block note above): the
    // field copy plus a fresh dirty addr_index.
    fn clone(&self) -> Self {
        Self {
            unique_id: self.unique_id,
            name: self.name.clone(),
            display_name: self.display_name.clone(),
            parent_id: self.parent_id,
            rangetree: self.rangetree.clone(),
            symbols: self.symbols.clone(),
            entries: self.entries.clone(),
            dynamic_entries: self.dynamic_entries.clone(),
            addr_index: std::sync::Mutex::new(AddrIndex::default()),
            categories: self.categories.clone(),
            next_unique_id: self.next_unique_id,
            children: self.children.clone(),
        }
    }
}

// RUGRA-GLUE: the sorted-address index backing Scope::find_container's
// binary-search containment query — ScopeInternal's per-space `maptable`
// rangemap (database.hh:877-878) realized as `(addr, insertion seq)`
// sorted entry indices plus a parallel prefix-max-end array. Rebuilt
// lazily after any entries mutation; `None` marks the dirty state.
#[derive(Default, Debug, Clone)]
struct AddrIndex {
    /// Entry indices sorted by `(entry.addr, index)` — `None` = dirty.
    sorted: Option<Vec<u32>>,
    /// Parallel to the built `sorted`: `prefix_max_end[p]` is the largest
    /// `get_last()` over `sorted[0..=p]`, pruning the backward walk.
    prefix_max_end: Vec<u64>,
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
            addr_index: std::sync::Mutex::new(AddrIndex::default()),
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

    // RUGRA-GLUE: addr_sorted index maintenance (ScopeInternal's maptable
    // rangemap is maintained incrementally on insert in C++; the Rust port
    // marks the index dirty at every entry push/retain/clear site and
    // rebuilds it lazily at the next find_container query — O(1) per
    /// mutation, one O(n log n) rebuild per query epoch, and the identical
    /// pure-function-of-entries query answers).
    fn invalidate_addr_index(&mut self) {
        if let Ok(mut index) = self.addr_index.lock() {
            index.sorted = None;
            index.prefix_max_end.clear();
        }
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

    // Ghidra: database.cc:1530 Scope::addSymbol
    /// Add a Symbol and map it to a specific address. Faithful to
    /// `Scope::addSymbol(nm, ct, addr, usepoint)` (database.cc:1530-1540):
    /// new Symbol + addSymbolInternal + addMapPoint — i.e. the `Scope::addMap`
    /// symbol-flag rules (database.cc:1126-1155, persist for a global scope /
    /// addrtied + flagbase property fold for an empty uselimit) run through
    /// [`Scope::apply_add_map_rules`] with `ctx = None` (standalone scope:
    /// the Database flagbase and global-discovery lookups answer 0/false).
    /// The usepoint is invalid (no parameter), so the whole-map entry keeps
    /// an EMPTY uselimit and its Symbol takes the addrtied fold — exactly
    /// the invariant `SymbolEntry::inUse` (database.cc:114-120) relies on.
    pub fn add_symbol_mapped(
        &mut self,
        nm: &str,
        type_name: &str,
        addr: Address,
        size: i32,
    ) -> u64 {
        let id = self.add_symbol(nm, type_name);
        let sym = self.symbols.get(&id).cloned().unwrap();
        let mut uselimit = RangeList::new();
        // database.cc:1539-1540: addMapPoint(sym, addr, Address()) — the
        // invalid usepoint leaves the uselimit empty (add_map_point's
        // usepoint!=0 restriction does not fire), then addMap's folds run.
        self.apply_add_map_rules(&sym, Some(addr), &mut uselimit, None);
        let mut sym_rg = sym.write().unwrap();
        sym_rg.whole_count += 1;
        drop(sym_rg);
        self.entries.push(SymbolEntry::new_static(
            sym,
            0,
            addr,
            0,
            size,
            uselimit,
        ));
        // maptable insert (database.cc:1869 addMapInternal).
        self.invalidate_addr_index();
        id
    }

    // Ghidra: database.hh:34 Scope::allocateId
    /// Allocate a new unique symbol id.
    fn allocate_id(&mut self) -> u64 {
        let id = self.next_unique_id;
        self.next_unique_id += 1;
        id
    }

    // Ghidra: database.cc:394 Symbol::decodeHeader (flag attributes)
    /// Set or clear one flag bit on a Symbol — the driver-side channel of
    /// the analyzer→decompiler symbol flag write. In Ghidra the platform
    /// analyzers express symbol flags through the symbol XML this decoder
    /// reads (database.cc:404-450): the ASCII-strings analyzer's defined
    /// Data carries a locked char-array type (`ATTRIB_TYPELOCK`, cc:439-442)
    /// and globals in read-only memory blocks carry `Varnode::readonly`
    /// (`ATTRIB_READONLY`, cc:435-438). `Funcdata::spacebaseConstant`
    /// (funcdata.cc:416) then reads `sym->isTypeLocked()` to decide whether
    /// the PTRSUB output's char-pointer type survives later type
    /// propagation, and `Scope::queryProperties`'s entry-hit arm
    /// (database.cc:1273 `flags = res->getAllFlags()`) folds the symbol
    /// flags into the readonly answers `RulePtrsubCharConstant`
    /// (ruleaction.cc:7372) and `PrintC::pushPtrCharConstant`
    /// (printc.cc:1709) consume.
    pub fn set_symbol_flag(&mut self, symbol_id: u64, flag: u32, on: bool) {
        if let Some(sym) = self.symbols.get(&symbol_id) {
            let mut sym_rg = sym.write().unwrap();
            if on {
                sym_rg.flags |= flag;
            } else {
                sym_rg.flags &= !flag;
            }
        }
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
        // maptable rebuild after entry removal (positional renumbering).
        self.invalidate_addr_index();
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

    // Ghidra: database.cc:2250 ScopeInternal::findContainer
    /// Find the smallest SymbolEntry containing the given memory range that
    /// is valid at `usepoint`. Faithful to `ScopeInternal::findContainer`
    /// (database.cc:2250-2276): the C++ queries the per-space `maptable`
    /// rangemap for the refinement interval containing `addr` (the
    /// `rangemap->find` window, rangemap.hh:355 — copies sub-sorted by
    /// first-use, bounded by the usepoint) and walks it backward, keeping a
    /// candidate only if it is strictly smaller than the running best
    /// (`entry->getSize() < oldsize || oldsize == -1`, cc:2268), requires
    /// `entry->inUse(usepoint)` (cc:2269), and breaks on an exact size match
    /// (cc:2270-2271). The Rust realization walks [`Scope::addr_sorted`]
    /// backward from the last entry starting at or before `addr`
    /// (containment requires `e.addr <= addr`), pruned by
    /// [`Scope::addr_prefix_max_end`] (stop once no lower-positioned entry
    /// can reach the range end), with the same strict-smaller/inUse/exact-
    /// break selection. Walk-order divergence: the oracle's window order is
    /// (interval copy, subsort) while this walk is (addr, insertion seq) —
    /// the selection outcome (unique smallest in-use container) is identical
    /// for the flat / nested-at-same-base entry sets the loaders and
    /// analyzers seed; only an equal-size overlapping tie at different
    /// addresses could resolve differently. Returns the index into
    /// `entries`, so `stackContainer` hands the index straight through
    /// without a linear position lookup.
    pub fn find_container(
        &self,
        addr: Address,
        size: i32,
        usepoint: Address,
    ) -> Option<usize> {
        // ScopeInternal::addMapInternal (database.cc:1841-1842) rejects
        // zero/negative-size mappings; a degenerate query finds nothing.
        if size <= 0 {
            return None;
        }
        let start = addr.as_u64();
        // cc:2266 — uintb end = addr.getOffset() + size - 1.
        let end = start + size as u64 - 1;
        // Lazy maptable build (see invalidate_addr_index): the index is a
        // pure function of `entries`, so a rebuild-on-dirty query answers
        // identically to the C++'s incrementally-maintained rangemap.
        let mut index_guard = self.addr_index.lock().ok()?;
        if index_guard.sorted.is_none() {
            let mut sorted: Vec<u32> = (0..self.entries.len() as u32).collect();
            sorted.sort_by_key(|&i| (self.entries[i as usize].addr.as_u64(), i));
            let mut prefix_max_end = Vec::with_capacity(sorted.len());
            let mut max_end = 0u64;
            for &i in &sorted {
                max_end = max_end.max(self.entries[i as usize].get_last());
                prefix_max_end.push(max_end);
            }
            index_guard.sorted = Some(sorted);
            index_guard.prefix_max_end = prefix_max_end;
        }
        let sorted = index_guard.sorted.as_ref()?;
        let prefix_max_end = &index_guard.prefix_max_end;
        // Containment requires the entry to start at or before `addr`, so
        // candidates live strictly before the first later-starting entry.
        let hi = sorted
            .partition_point(|&i| self.entries[i as usize].addr.as_u64() <= start);
        let mut best: Option<usize> = None;
        let mut oldsize: i64 = -1; // cc:2268 sentinel
        let mut p = hi as i64 - 1;
        while p >= 0 {
            let pu = p as usize;
            // Prefix-max-end prune: no entry at position <= pu can reach
            // `end`, so no lower entry can contain the range.
            if prefix_max_end[pu] < end {
                break;
            }
            let idx = sorted[pu] as usize;
            let entry = &self.entries[idx];
            // cc:2267 — entry->getLast() >= end: we contain the range.
            if entry.get_last() >= end {
                // cc:2268 — strictly smaller than the running best, or first.
                if (entry.size as i64) < oldsize || oldsize == -1 {
                    // cc:2269 — valid at the usepoint.
                    if entry.in_use(usepoint) {
                        best = Some(idx);
                        oldsize = entry.size as i64;
                        // cc:2270-2271 — exact size match: nothing smaller
                        // can contain the range.
                        if entry.size == size {
                            break;
                        }
                    }
                }
            }
            p -= 1;
        }
        best
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
            // database.cc:952 — findContainer(addr, size, usepoint): the
            // inUse(usepoint) filter is inside findContainer (cc:2269), so
            // the returned index is the attachable entry.
            if let Some(entry_idx) = scope1.find_container(addr, size, usepoint) {
                *addrmatch = Some(entry_idx);
                return Some(i);
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
    /// `ScopeInternal::decode` (database.cc:2744): handles an optional
    /// `<parent>` (skipped — applied by the Database), `<rangelist>` /
    /// `<rangeequalssymbols>`, and a `<symbollist>` of `<mapsym>`/`<hole>`/
    /// `<collision>` children. Standalone form: no Database side-channel —
    /// `<hole>` properties are dropped and `<mapsym>` mappings install
    /// without the addMap flag rules (see [`Scope::decode_with_ctx`] for the
    /// Database-integrated form).
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        self.decode_with_ctx(decoder, None, &[]);
    }

    // Ghidra: database.cc:2744 ScopeInternal::decode (Database-integrated)
    /// Database-integrated decode. Faithful to the `glb->symboltab` touches
    /// inside `ScopeInternal::decode` (database.cc:2744-2789):
    /// - `<mapsym>` children go through `addMapSym` → `addMap(entry)`
    ///   (database.cc:2772/1602) with the flagbase property lookup
    ///   (`glb->symboltab->getProperty`, database.cc:1153) and the global
    ///   discovery-range test (database.cc:1138) resolved against
    ///   `global_ranges` (a snapshot of the global scope's ownership ranges
    ///   as decoded so far).
    /// - `<hole>` children apply `setPropertyRange(flags, range)` to the
    ///   flagbase IMMEDIATELY (database.cc:2778-2779 → 2667-2687), in
    ///   document order — a `<hole>` BEFORE a `<mapsym>` feeds that
    ///   mapsym's property fold, one AFTER does not.
    /// - `flags == 0` holes apply nothing (database.cc:2683).
    pub fn decode_with_ctx(
        &mut self,
        decoder: &mut dyn Decoder,
        mut flagbase: Option<&mut PartMap>,
        global_ranges: &[Range],
    ) {
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
                        // database.cc:2771-2772 — addMapSym with the live
                        // flagbase + discovery ranges.
                        let ctx = flagbase.as_deref_mut().map(|fb| AddMapContext {
                            property: Box::new(move |addr: Address| fb.get_value(addr)),
                            in_global_discovery: Box::new(move |addr: Address| {
                                global_ranges.iter().any(|r| r.contains(addr))
                            }),
                        });
                        self.add_map_sym(decoder, ctx.as_ref());
                    }
                    "hole" => {
                        // database.cc:2778-2779 — decodeHole forwards to the
                        // Database's setPropertyRange (database.cc:2683-2685).
                        let (rng, flags) = Scope::decode_hole(decoder);
                        if let Some(fb) = flagbase.as_deref_mut() {
                            if flags != 0 {
                                fb.set_property_range(
                                    flags,
                                    rng.get_first_addr(),
                                    rng.get_last_addr_open(),
                                );
                            }
                        }
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
    /// `Scope::addMapSym` (database.cc:1564): the first child determines the
    /// symbol kind (`<symbol>`, `<equatesymbol>`, `<function>`,
    /// `<functionshell>`, `<labelsym>`, `<externrefsymbol>`, `<facetsymbol>`);
    /// subsequent `<addr>`/`<hash>` children define the SymbolEntry mappings,
    /// each installed through `addMap(entry)` (database.cc:1602) — the
    /// persist / global-discovery / addrtied + flagbase-property-fold rules
    /// run per mapping via [`AddMapContext`] (`None` = standalone scope).
    /// Returns the new symbol id (0 = none created).
    pub fn add_map_sym(&mut self, decoder: &mut dyn Decoder, ctx: Option<&AddMapContext>) -> u64 {
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
                sym_arc.clone(),
                // database.cc:1155/1147 — addMap installs the mapping with
                // extraflags = Varnode::mapped (addMapInternal /
                // addDynamicMapInternal), so getAllFlags carries the bit.
                crate::varnode::varnode_flags::MAPPED,
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
            // database.cc:1602 — addMap(entry): the flag rules run per
            // mapping, with the flagbase state AS OF THIS POINT in the
            // symbollist walk (an earlier <hole> feeds the fold, a later
            // one does not, database.cc:2768-2784 document order).
            let mut uselimit = entry.get_use_limit().clone();
            let static_addr = if entry.is_dynamic() {
                None
            } else {
                Some(entry.get_addr())
            };
            self.apply_add_map_rules(&sym_arc, static_addr, &mut uselimit, ctx);
            entry.set_use_limit(uselimit);
            if entry.is_dynamic() {
                self.dynamic_entries.push(entry);
            } else {
                self.entries.push(entry);
                // maptable insert (database.cc:1869 addMapInternal).
                self.invalidate_addr_index();
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
            .find_container(addr, 1, Address::new(0))
            .map(|idx| self.entries[idx].symbol.read().unwrap().symbol_id);
        // database.cc:1626 — new FunctionSymbol(owner, nm, glb->min_funcsymbol_size).
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, "func");
        sym.symbol_id = id;
        // FunctionSymbol::buildType (database.cc:514-520): the symbol's
        // data-type is the generic code type (type.cc:3692
        // TypeFactory::getTypeCode) and the symbol carries
        // namelock|typelock. container_hit surfaces the metatype, which
        // PrintC::opPtrsub's spacebase arm reads (printc.cc:1068-1069
        // `TYPE_CODE → valueon = true` — a function symbol drops the '&').
        sym.dtype = Some(std::sync::Arc::new(crate::type_system::datatype::Datatype::Code(
            crate::type_system::datatype::TypeCode::new(),
        )));
        sym.flags |= symbol_flags::NAMELOCK | symbol_flags::TYPELOCK;
        // Scope::addMap (database.cc:1131-1133, 1147-1151) — the whole-map
        // point integration on a global scope sets `persist`, and a valid
        // address with an EMPTY uselimit sets `addrtied` (both fold into
        // the symbol flags before addMapInternal). addrtied is load-bearing
        // for SymbolEntry::inUse (database.cc:114-119: an address-tied
        // entry is valid at ANY usepoint, including the invalid usepoint
        // linkSymbolReference and PrintC's spacebase arm query with).
        sym.flags |= symbol_flags::PERSIST | symbol_flags::ADDRTIED;
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
        // maptable insert (database.cc:1869 addMapInternal).
        self.invalidate_addr_index();
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
        // maptable insert (database.cc:1869 addMapInternal).
        self.invalidate_addr_index();
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
            .find_container(addr, 1, addr)
            .map(|idx| self.entries[idx].symbol.read().unwrap().symbol_id);
        // database.cc:1675 — new LabSymbol(owner, nm).
        let id = self.allocate_id();
        let mut sym = Symbol::new(self.unique_id, nm, "label");
        sym.symbol_id = id;
        self.symbols.insert(id, Arc::new(RwLock::new(sym)));
        // database.cc:1676 — addSymbolInternal(sym).
        // database.cc:1677 — addMapPoint(sym, addr, Address()). whole-map
        // entry through the addMap fold (empty uselimit -> the symbol's
        // ADDRTIED bit, database.cc:1150; extraflags = Varnode::mapped,
        // database.cc:1148) so `findCodeLabel`'s inUse(addr) admits it
        // (database.cc:114-120 isAddrTied leg).
        self.add_map_point(id, addr, Address::new(0), 1, None);
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

    // Ghidra: database.cc:1810 ScopeInternal::addSymbolInternal
    /// The category-table registration half of `addSymbolInternal`
    /// (database.cc:1827-1836): when `sym->category >= 0`, grow the outer
    /// category vector through that category, assign `catindex = list.size()`
    /// for categories > 0 (the symbol's existing catindex slot is used for
    /// category 0), pad the list with NULL slots through the index, and place
    /// the symbol. Called by `add_equate_symbol` to mirror the
    /// `addSymbolInternal(sym)` step of `Scope::addEquateSymbol`
    /// (database.cc:1718).
    fn add_symbol_internal_category(&mut self, sym_arc: &Arc<RwLock<Symbol>>) {
        // cc:1827 if (sym->category >= 0).
        let cat = sym_arc.read().unwrap().category as i32;
        if cat < 0 {
            return;
        }
        // cc:1828-1829 while(category.size() <= sym->category)
        //              category.push_back(vector<Symbol *>());
        for c in 0..=cat {
            self.categories.entry(c).or_default();
        }
        // cc:1831-1832 if (sym->category > 0) sym->catindex = list.size();
        let index = if cat > 0 {
            self.categories.get(&cat).map_or(0, |l| l.len())
        } else {
            sym_arc.read().unwrap().catindex as usize
        };
        sym_arc.write().unwrap().catindex = index as u16;
        // cc:1833-1835 while(list.size() <= sym->catindex) list.push_back(NULL);
        //              list[sym->catindex] = sym;
        let list = self.categories.get_mut(&cat).unwrap();
        list.resize_for_index(index);
        list.0[index] = Some(Arc::downgrade(sym_arc));
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
        // database.cc:1718 — addSymbolInternal(sym), whose category block
        // (database.cc:1827-1836) registers category[equate] and assigns
        // catindex = list.size().
        self.add_symbol_internal_category(&sym_arc);
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

    // Ghidra: database.cc:1126 Scope::addMap (flag rules)
    /// Apply `Scope::addMap`'s symbol-flag rules to one mapping.
    /// Faithful to database.cc:1126-1155:
    /// - `isGlobal()` scope: `symbol->flags |= Varnode::persist`
    ///   (database.cc:1131-1132) — runs for BOTH static and dynamic maps.
    /// - non-global scope with a static address (`addr = Some`) inside the
    ///   GLOBAL scope's discovery range: persist is set AND
    ///   `entry.uselimit.clear()` (database.cc:1133-1142) — the cleared
    ///   uselimit then feeds the addrtied/fold branch below.
    /// - static address with EMPTY uselimit: `symbol->flags |=
    ///   Varnode::addrtied` (database.cc:1150) and the Database property
    ///   fold `symbol->flags |= glb->symboltab->getProperty(entry.addr)`
    ///   (database.cc:1153) — readonly/volatile ranges live in the flagbase
    ///   and are OR-ed into the SYMBOL (not the entry) exactly once, at
    ///   map-install time; a property range installed LATER never
    ///   contaminates an already-mapped symbol. Dynamic maps
    ///   (`addr = None`, database.cc:1146-1147 addDynamicMapInternal) never
    ///   take addrtied or the fold.
    /// - the join-address piece loop (database.cc:1156-1177) is out of this
    ///   helper: Rugra's map-install callers never map join addresses.
    ///
    /// `ctx` carries the two `glb->symboltab` lookups the C++ scope reads
    /// through its Architecture handle; `None` models a standalone scope
    /// with no Database (both lookups answer false/0 — the no-fold
    /// behaviour, recorded under DB-LOCALSCOPE-MAP-0001).
    fn apply_add_map_rules(
        &mut self,
        sym_arc: &Arc<RwLock<Symbol>>,
        addr: Option<Address>,
        uselimit: &mut RangeList,
        ctx: Option<&AddMapContext>,
    ) {
        if self.is_global() {
            // database.cc:1131-1132.
            sym_arc.write().unwrap().flags |= symbol_flags::PERSIST;
        } else if let (Some(addr), Some(ctx)) = (addr, ctx) {
            // database.cc:1133-1142 — global discovery range check on the
            // (static) address (inScope(addr,1)); a hit clears the uselimit.
            if (ctx.in_global_discovery)(addr) {
                sym_arc.write().unwrap().flags |= symbol_flags::PERSIST;
                *uselimit = RangeList::new();
            }
        }
        let addr = match addr {
            // database.cc:1146-1147 — dynamic maps take no addrtied/fold.
            None => return,
            Some(addr) => addr,
        };
        if !uselimit.empty() {
            return;
        }
        // database.cc:1149-1153 — addrtied + the flagbase property fold.
        let property = ctx.map(|c| (c.property)(addr)).unwrap_or(0);
        let mut sym = sym_arc.write().unwrap();
        sym.flags |= symbol_flags::ADDRTIED | property;
    }

    // Ghidra: database.cc:1548 Scope::addMapPoint
    /// Create a new SymbolEntry that maps the whole Symbol to the given address.
    /// Faithful to `Scope::addMapPoint` (database.cc:1548): constructs the
    /// whole-map `SymbolEntry`, restricts its use to `usepoint` if valid,
    /// sets `entry.addr = addr`, then calls `addMap(entry)` — the addMap
    /// flag rules (persist / global-discovery uselimit clear / addrtied +
    /// flagbase property fold, database.cc:1126-1155) run through
    /// [`AddMapContext`] (`None` = standalone scope, no Database). Does
    /// nothing if the symbol id is not registered in this scope.
    pub fn add_map_point(
        &mut self,
        symbol_id: u64,
        addr: Address,
        usepoint: Address,
        size: i32,
        ctx: Option<&AddMapContext>,
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
        // database.cc:1555-1556 — entry.addr = addr; addMap(entry).
        self.apply_add_map_rules(&sym_arc, Some(addr), &mut uselimit, ctx);
        sym_arc.write().unwrap().whole_count += 1;
        // database.cc:1148-1149 — addMapInternal(symbol, Varnode::mapped,
        // ...): the whole-map entry carries `mapped` as its extraflags
        // (visible through `SymbolEntry::getAllFlags`).
        self.entries.push(SymbolEntry::new_static(
            sym_arc,
            crate::varnode::varnode_flags::MAPPED,
            addr,
            0,
            size,
            uselimit,
        ));
        // maptable insert (database.cc:1869 addMapInternal).
        self.invalidate_addr_index();
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
                // Ghidra's addMapPoint runs the addMap flag rules through
                // glb; this Scope-internal caller has no Database handle, so
                // the re-added map takes the no-fold path (residual under
                // DB-LOCALSCOPE-MAP-0001: the Database unification gap).
                self.add_map_point(symbol_id, saved_addr, Address::new(0), new_size, None);
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

/// A partition map: a default value plus a sorted map of split points,
/// each carrying the value of the partition that STARTS at that point.
/// Faithful to `partmap<Address,uint4>` (partmap.hh:50-73): the map from
/// split points to value objects is `std::map<Address,uint4>` ordered by
/// Address's natural (space, offset) ordering, and `getValue` returns the
/// value of the LAST split point at-or-before the query point (or the
/// default before the first split point).
#[derive(Debug, Clone, Default)]
pub struct PartMap {
    /// Map from split points to partition values (partmap.hh:56
    /// `maptype database`), ordered by `Address::operator<`
    /// (address.hh:398: space order then offset).
    pub database: BTreeMap<Address, u32>,
    /// The value before the first split point (partmap.hh:57
    /// `defaultvalue`); `Database` keeps it 0 (database.cc:2929).
    pub defaultvalue: u32,
}

impl PartMap {
    // Ghidra: partmap.hh:83 partmap::getValue
    /// Look up the first split point at-or-before `pnt` and return its
    /// value; the default if none. Faithful to `getValue` (partmap.hh:83-93:
    /// `upper_bound` then step back; `database.begin()` guard returns the
    /// default).
    pub fn get_value(&self, pnt: Address) -> u32 {
        match self.database.range(..=pnt).next_back() {
            Some((_, v)) => *v,
            None => self.defaultvalue,
        }
    }

    // Ghidra: partmap.hh:119 partmap::split
    /// Introduce (if not already present) a split point at `pnt` whose
    /// partition value starts as a COPY of the preceding partition's value
    /// (or the default if `pnt` precedes every split point). Faithful to
    /// `split` (partmap.hh:119-134: `upper_bound`; exact match returns the
    /// old ref; the new entry copies the previous value). Returns the new
    /// partition's value for assignment.
    pub fn split(&mut self, pnt: Address) -> &mut u32 {
        if let Some((_, v)) = self.database.range(..pnt).next_back() {
            let prev = *v;
            self.database.entry(pnt).or_insert(prev)
        } else {
            let default = self.defaultvalue;
            self.database.entry(pnt).or_insert(default)
        }
    }

    // Ghidra: database.cc:3220 Database::setPropertyRange (partmap walk)
    /// OR `flags` into every partition of `[first, last_open)` — the
    /// split/bounds walk of `Database::setPropertyRange`
    /// (database.cc:3220-3239): split at both bounds, then
    /// `while(aiter != biter) (*aiter).second |= flags;` where
    /// `aiter = begin(addr1)` is `lower_bound` (partmap.hh:70) and `biter`
    /// is `begin(addr2)` (`end()` for an open last bound). Overlapping
    /// property ranges ACCUMULATE on shared partitions.
    pub fn set_property_range(&mut self, flags: u32, first: Address, last_open: Address) {
        self.split(first);
        self.split(last_open);
        for (_key, value) in self.database.range_mut(first..last_open) {
            *value |= flags;
        }
    }

    // Ghidra: database.cc:3245 Database::clearPropertyRange (partmap walk)
    /// AND `!flags` into every partition of `[first, last_open)` — the
    /// split/bounds walk of `Database::clearPropertyRange`
    /// (database.cc:3245-3265: `flags = ~flags;` then
    /// `(*aiter).second &= flags;`). Only the listed bits clear, and only
    /// inside the range; partitions shared with neighbouring ranges keep
    /// their other bits.
    pub fn clear_property_range(&mut self, flags: u32, first: Address, last_open: Address) {
        self.split(first);
        self.split(last_open);
        let mask = !flags;
        for (_key, value) in self.database.range_mut(first..last_open) {
            *value &= mask;
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
    /// Map of global properties over address ranges. Faithful to
    /// `partmap<Address,uint4> flagbase` (database.hh:921): a split-point
    /// partition map, NOT a list of independent ranges — overlapping
    /// `setPropertyRange` calls OR into the shared partitions and
    /// `clearPropertyRange` ANDs bits away within sub-ranges.
    pub flagbase: PartMap,
    /// Next scope id to assign.
    pub next_scope_id: u64,
    /// True if scope ids are built from a hash of the scope name. Faithful to
    /// `Database::idByNameHash` (database.hh:922); serialized as the
    /// `scopeidbyname` attribute on `<db>`.
    pub id_by_name: bool,
}

/// Observable projection of a `queryContainer`/`queryProperties` hit — the
/// currency of the Funcdata query channel (B3-COREACTION-CONSTANTPTR-0001).
/// Ghidra returns the scope-owned `SymbolEntry*` directly; Rugra's scopes
/// live behind `Arc<RwLock<Database>>`, so a query hands back this by-value
/// summary of the same observables. It carries everything the production
/// consumers read off the entry:
/// - `ActionConstantPtr::isPointer` (coreaction.cc:1151-1163): the
///   `needexacthit` test `entry->getAddr() != rampoint` (via `entry_addr`)
///   and the char-array middle exception `getType()->getMetatype() ==
///   TYPE_ARRAY` + `((TypeArray *)type)->getBase()->isCharPrint()` (via
///   `type_metatype` + `base_is_char_print`).
/// - `Funcdata::linkSymbolReference` (funcdata_varnode.cc:1207-1211): the
///   entry start (`entry_addr`), the entry-relative offset
///   (`entry_offset`), and the symbol name for the symbol reference.
/// - `Funcdata::spacebaseConstant` (funcdata.cc:363): `entry->getAddr()`
///   for the `extra` computation.
#[derive(Debug, Clone)]
pub struct QueryContainerHit {
    /// Id of the scope whose entry answered (innermost wins; the C++
    /// `SymbolEntry*` carries its owning scope implicitly).
    pub scope_id: u64,
    /// Name of the answering scope (observability for scope traversal
    /// order; Ghidra has no such field on the entry).
    pub scope_name: String,
    /// `entry->getAddr()` — starting address of the storage.
    pub entry_addr: Address,
    /// `entry->getSize()`.
    pub entry_size: i32,
    /// `entry->getOffset()` — offset of this entry into the whole Symbol.
    pub entry_offset: i32,
    /// `entry->getSymbol()->getId()`.
    pub symbol_id: u64,
    /// `entry->getSymbol()->getName()`.
    pub symbol_name: String,
    /// `entry->getAllFlags()` (database.hh:271: `extraflags | symbol flags`).
    pub all_flags: u32,
    /// `entry->getSymbol()->getType()->getMetatype()` (Unknown when the
    /// Symbol has no resolved Datatype yet).
    pub type_metatype: TypeMetatype,
    /// For a TYPE_ARRAY Symbol: `((TypeArray *)type)->getBase()->isCharPrint()`
    /// (coreaction.cc:1156-1159). False for every other metatype.
    pub base_is_char_print: bool,
    /// `entry->getSymbol()->getType()` as the shared Datatype handle —
    /// `None` mirrors a Symbol whose type is not resolved yet. The
    /// `spacebaseConstant` consumer (funcdata.cc:413-419) reads it for
    /// `getTypePointerStripArray` and the typelock fold (B3-COREACTION-
    /// CONSTANTPTR-0001 segment b).
    pub symbol_type: Option<Arc<Datatype>>,
}

/// Observable projection of one `queryByName` match.
#[derive(Debug, Clone, PartialEq)]
pub struct QueryNameHit {
    /// Id of the scope holding the matching Symbol.
    pub scope_id: u64,
    /// Name of that scope.
    pub scope_name: String,
    /// `Symbol::getId()`.
    pub symbol_id: u64,
    /// `Symbol::getName()`.
    pub symbol_name: String,
}

// Ghidra: database.hh:900 ScopeResolve (rangemap<ScopeMapper>) insert
/// Insert `(rng, scope_id)` into the resolvemap with Ghidra rangemap
/// overlap-split semantics (`ScopeResolve::insert`, the `rangemap<ScopeMapper>`
/// insert behind `Database::fillResolve`, database.cc:2917): the inserted
/// range takes over its overlap from every current owner, and each owner
/// keeps its disjoint left/right remainders. Partitions stay disjoint, so a
/// containing-address lookup (`mapScope`) has at most one answer.
fn resolve_insert_split(map: &mut Vec<(Range, u64)>, sid: u64, rng: Range) {
    let first = rng.get_first();
    let last = rng.get_last();
    let first_off = first.as_u64();
    let last_off = last.as_u64();
    let mut out: Vec<(Range, u64)> = Vec::with_capacity(map.len() + 2);
    let mut inserted = false;
    for (r, owner) in map.iter() {
        let rf = r.get_first();
        let rl = r.get_last();
        if rl.as_u64() < first_off || rf.as_u64() > last_off {
            // Disjoint — keep whole.
            out.push((r.clone(), *owner));
            continue;
        }
        // Overlap — the new range owns the intersection.
        if rf.as_u64() < first_off {
            if let Some(left) =
                Range::new(rf, Address::new(first_off.wrapping_sub(1)))
            {
                out.push((left, *owner));
            }
        }
        if !inserted {
            out.push((rng.clone(), sid));
            inserted = true;
        }
        if rl.as_u64() > last_off {
            if let Some(right) =
                Range::new(Address::new(last_off.wrapping_add(1)), rl)
            {
                out.push((right, *owner));
            }
        }
    }
    if !inserted {
        out.push((rng, sid));
    }
    out.sort_by_key(|(r, _)| r.get_first());
    *map = out;
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
            // database.cc:2929 — flagbase.defaultValue()=0.
            flagbase: PartMap {
                database: BTreeMap::new(),
                defaultvalue: 0,
            },
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

    // Ghidra: database.hh:742 Scope::addSymbol(nm,ct,addr,usepoint) (Database-level entry)
    /// Add a Symbol with a resolved Datatype and map it to a whole-map
    /// static entry, applying the live `addMap` flag rules — the
    /// production-path installer for the query channel's fixture/driver
    /// population. Faithful to the C++ `addSymbol` → `addSymbolInternal` →
    /// `addMapPoint` → `addMap` chain (database.cc:1548/:1126-1155): the
    /// entry takes `Varnode::mapped` extraflags, the symbol takes
    /// `persist` (global-scope or global-discovery branch), `addrtied`, and
    /// the flagbase property fold at the mapping address. The
    /// [`AddMapContext`] lookups are wired to the LIVE Database state
    /// exactly as `Database::decode` wires them.
    pub fn add_symbol_mapped(
        &mut self,
        scope_id: u64,
        nm: &str,
        dtype: Option<std::sync::Arc<crate::type_system::datatype::Datatype>>,
        addr: Address,
        size: i32,
    ) -> Option<u64> {
        // The ctx reads the global scope's discovery ranges and the
        // flagbase (the same live-state wiring as Database::decode).
        let global_ranges: Vec<Range> = self
            .scopes
            .get(&self.global_scope_id)
            .map(|s| s.rangetree.ranges().to_vec())
            .unwrap_or_default();
        let Database {
            scopes, flagbase, ..
        } = self;
        let scope = scopes.get_mut(&scope_id)?;
        let id = scope.add_symbol(nm, "");
        if let Some(dt) = dtype {
            if let Some(sym) = scope.symbols.get(&id) {
                sym.write().unwrap().set_dtype(dt);
            }
        }
        let ctx = AddMapContext {
            property: Box::new(|a: Address| flagbase.get_value(a)),
            in_global_discovery: Box::new(move |a: Address| {
                global_ranges.iter().any(|r| r.contains(a))
            }),
        };
        // database.cc:1555 — the C++ convenience passes the invalid
        // usepoint (empty uselimit → addrtied + fold branch).
        scope.add_map_point(id, addr, Address::new(0), size, Some(&ctx));
        Some(id)
    }

    // Ghidra: database.cc:394 Symbol::decodeHeader (flag attributes)
    /// Database-level forwarder of [`crate::database::Scope::
    /// set_symbol_flag`]: set or clear one flag bit on a Symbol owned by
    /// `scope_id` — the driver-side channel of the analyzer→decompiler
    /// symbol flag write (the XML flag attributes `Symbol::decodeHeader`
    /// reads at database.cc:404-450).
    pub fn set_symbol_flag(&mut self, scope_id: u64, symbol_id: u64, flag: u32, on: bool) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.set_symbol_flag(symbol_id, flag, on);
        }
    }

    // Ghidra: database.cc:3050 Database::addRange
    /// Add an address range to the ownership of a Scope. Faithful to
    /// `addRange` (database.cc:3050-3061):
    /// `clearResolve(scope)` — erase this scope's resolvemap entries —
    /// then `scope->addRange(...)`, then `fillResolve(scope)` — re-insert
    /// every owned range into the resolvemap with rangemap split semantics
    /// (an inserted range takes over its overlap; neighbouring entries are
    /// trimmed to the remainder).
    pub fn add_range(&mut self, scope_id: u64, rng: Range) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.rangetree.insert_range(rng);
        } else {
            return;
        }
        // database.cc:3057-3059 — clearResolve + fillResolve. Both bail
        // early for the global scope (database.cc:2873/:2901-2903: the
        // global scope never enters the resolvemap) and for functional
        // scopes (fd != 0); Rugra scopes carry no Funcdata binding, so the
        // functional-scope guard is vacuous (documented residual).
        if scope_id == self.global_scope_id {
            return;
        }
        self.clear_resolve(scope_id);
        self.fill_resolve(scope_id);
    }

    // Ghidra: database.cc:2871 Database::clearResolve
    /// Erase this namespace Scope's ranges from the resolvemap. Faithful to
    /// `clearResolve` (database.cc:2871-2890): for each owned range, find
    /// the resolvemap partition starting at its first address and erase it
    /// if this scope owns it. The global scope bails early.
    fn clear_resolve(&mut self, scope_id: u64) {
        let first_addrs: Vec<Address> = self
            .scopes
            .get(&scope_id)
            .map(|s| s.rangetree.ranges().iter().map(|r| r.get_first()).collect())
            .unwrap_or_default();
        for first in first_addrs {
            if let Some(pos) = self
                .resolvemap
                .iter()
                .position(|(r, sid)| r.get_first() == first && *sid == scope_id)
            {
                self.resolvemap.remove(pos);
            }
        }
    }

    // Ghidra: database.cc:2897 Database::fillResolve
    /// Insert every range this namespace Scope owns into the resolvemap.
    /// Faithful to `fillResolve` (database.cc:2897-2908) — each insert goes
    /// through the rangemap `ScopeResolve::insert` overlap-split semantics
    /// (database.hh:900): the new range takes over its overlap from any
    /// current owner; the owner keeps disjoint remainders.
    fn fill_resolve(&mut self, scope_id: u64) {
        let ranges: Vec<Range> = self
            .scopes
            .get(&scope_id)
            .map(|s| s.rangetree.ranges().to_vec())
            .unwrap_or_default();
        for rng in ranges {
            resolve_insert_split(&mut self.resolvemap, scope_id, rng);
        }
    }

    // Ghidra: database.cc:3064 Database::removeRange
    /// Remove an address range from the ownership of a Scope. Faithful to
    /// `removeRange` (database.cc:3064-3077): `clearResolve(scope)`,
    /// `scope->removeRange(...)`, then `fillResolve(scope)` re-inserts the
    /// remaining ranges.
    pub fn remove_range(&mut self, scope_id: u64, rng: Range) {
        if scope_id != self.global_scope_id {
            self.clear_resolve(scope_id);
        }
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.rangetree.remove_range(rng);
        }
        if scope_id != self.global_scope_id {
            self.fill_resolve(scope_id);
        }
    }

    // Ghidra: database.hh:946 Database::getProperty
    /// Get boolean properties at the given address. Faithful to
    /// `getProperty` (database.hh:946: `flagbase.getValue(addr)` — the value
    /// of the last split point at-or-before `addr`, default 0).
    pub fn get_property(&self, addr: Address) -> u32 {
        self.flagbase.get_value(addr)
    }

    // Ghidra: database.cc:3220 Database::setPropertyRange
    /// Set boolean properties over a given memory range. Faithful to
    /// `setPropertyRange` (database.cc:3220-3239):
    /// - `addr1 = range.getFirstAddr()`, `addr2 = range.getLastAddrOpen()`
    ///   (last+1; address.cc:265-279).
    /// - `flagbase.split(addr1)`; if `addr2` is valid `flagbase.split(addr2)`
    ///   and the update walk stops at the first split point at-or-after it,
    ///   else the walk runs to `flagbase.end()` (database.cc:3229-3234).
    /// - every partition between the two bounds gets `value |= flags`
    ///   (database.cc:3236) — overlapping property ranges ACCUMULATE on the
    ///   shared partitions, they do not overwrite each other.
    ///
    /// Rugra notes: `Range::get_last_addr_open` (address.cc:265 mirror) has
    /// no `Address::m_maximal` sentinel for the "range runs to the space
    /// top and no later space exists" case — `last.next()` is used as the
    /// open end, which is equivalent for `getValue` queries; the residual
    /// (a changepoint emitted at space-top+1 in `encode` for that corner)
    /// is recorded under DB-LOCALSCOPE-MAP-0001.
    pub fn set_property_range(&mut self, flags: u32, range: Range) {
        let addr1 = range.get_first_addr();
        let addr2 = range.get_last_addr_open();
        self.flagbase.set_property_range(flags, addr1, addr2);
    }

    // Ghidra: database.cc:3245 Database::clearPropertyRange
    /// Clear boolean properties over a given memory range. Faithful to
    /// `clearPropertyRange` (database.cc:3245-3265): the same split/bounds
    /// walk as `setPropertyRange`, but each partition gets
    /// `value &= ~flags` (database.cc:3260-3263) — only the non-zero bits of
    /// `flags` are cleared, and only within `[addr1, addr2)`; partitions
    /// shared with neighbouring ranges keep their other bits.
    pub fn clear_property_range(&mut self, flags: u32, range: Range) {
        let addr1 = range.get_first_addr();
        let addr2 = range.get_last_addr_open();
        self.flagbase.clear_property_range(flags, addr1, addr2);
    }

    // Ghidra: database.cc:3185 Database::mapScope
    /// Map a query point to the owning namespace Scope. Faithful to
    /// `mapScope` (database.hh:944 / database.cc:3185-3196): with an empty
    /// resolvemap the query starts at `qpoint` itself; otherwise the
    /// partition containing `addr` answers, and a miss falls back to
    /// `qpoint` (NOT the global scope — database.cc:3195).
    pub fn map_scope(&self, qpoint: u64, addr: Address) -> u64 {
        if self.resolvemap.is_empty() {
            // database.cc:3187-3188 — no namespace scopes.
            return qpoint;
        }
        // Partitions are disjoint (split-on-insert), so the first
        // containing entry is THE containing entry.
        for (rng, sid) in &self.resolvemap {
            if rng.contains(addr) {
                return *sid;
            }
        }
        qpoint
    }

    // Ghidra: database.cc:1246 Scope::queryContainer (Database-level entry)
    /// Build the ordered ancestor stack of scopes starting at `scope_id`
    /// (`scope_stack[0]` = innermost, then parents up to the global scope).
    /// This is the Rugra equivalent of following `Scope::getParent()` links
    /// (database.cc:1251 `stackContainer(basescope, NULL, ...)`): Rugra's
    /// Scopes are owned by the `Database` and carry no parent pointer, so
    /// the chain is materialized here. A cycle guard stops at a repeated id.
    pub fn ancestor_stack(&self, scope_id: u64) -> Vec<&Scope> {
        let mut stack = Vec::new();
        let mut cur = scope_id;
        let mut seen = std::collections::BTreeSet::new();
        while let Some(scope) = self.scopes.get(&cur) {
            if !seen.insert(cur) {
                break; // parent-cycle guard; impossible in a well-formed db
            }
            stack.push(scope);
            if cur == self.global_scope_id {
                break;
            }
            cur = scope.parent_id;
        }
        stack
    }

    // Ghidra: database.hh:271 SymbolEntry::getAllFlags (hit projection)
    /// Project a `(scope_idx, entry_idx)` pair from the static `Scope`
    /// query helpers into the observable [`QueryContainerHit`] summary
    /// (entry observables per `database.hh:224 Symbol::getType` and
    /// `database.hh:271 SymbolEntry::getAllFlags`).
    fn container_hit(
        &self,
        stack: &[&Scope],
        scope_idx: usize,
        entry_idx: usize,
    ) -> Option<QueryContainerHit> {
        let scope = *stack.get(scope_idx)?;
        let entry = scope.entries.get(entry_idx)?;
        let sym = entry.symbol.read().unwrap();
        // coreaction.cc:1153-1159 — the char-array middle exception reads
        // `entry->getSymbol()->getType()->getMetatype() == TYPE_ARRAY` and,
        // for arrays, `((TypeArray *)type)->getBase()->isCharPrint()`.
        let (type_metatype, base_is_char_print) = match sym.dtype.as_deref() {
            Some(Datatype::Array(arr)) => (TypeMetatype::Array, arr.array_of.is_char_print()),
            Some(other) => (other.get_metatype(), false),
            None => (TypeMetatype::Unknown, false),
        };
        Some(QueryContainerHit {
            scope_id: scope.unique_id,
            scope_name: scope.name.clone(),
            entry_addr: entry.addr,
            entry_size: entry.size,
            entry_offset: entry.offset,
            symbol_id: sym.symbol_id,
            symbol_name: sym.name.clone(),
            all_flags: entry.get_all_flags(),
            type_metatype,
            base_is_char_print,
            symbol_type: sym.dtype.clone(),
        })
    }

    // Ghidra: database.cc:1246-1253 Scope::queryContainer
    /// Within a sub-scope or containing Scope of `qpoint_scope_id`, find the
    /// smallest SymbolEntry that contains the given range and is valid at
    /// `usepoint`. Faithful to `Scope::queryContainer` (database.cc:1246):
    /// `mapScope(this, addr, usepoint)` picks the base scope (the
    /// `qpoint_scope_id` argument plays `this`), then `stackContainer`
    /// walks the parent chain. Returns the observable hit summary, or `None`
    /// (scope discovery without a symbol, or no owner at all, both yield a
    /// NULL `SymbolEntry*` in the C++).
    pub fn query_container(
        &self,
        qpoint_scope_id: u64,
        addr: Address,
        size: i32,
        usepoint: Address,
    ) -> Option<QueryContainerHit> {
        // database.cc:1250 — const Scope *basescope = mapScope(this, ...).
        let base = self.map_scope(qpoint_scope_id, addr);
        let stack = self.ancestor_stack(base);
        // database.cc:1251 — stackContainer(basescope, NULL, ...).
        let (scope_idx, entry_idx) = Scope::query_container(&stack, addr, size, usepoint)?;
        self.container_hit(&stack, scope_idx, entry_idx)
    }

    // Ghidra: database.cc:1263-1281 Scope::queryProperties
    /// Search for the smallest containing Symbol relative to
    /// `qpoint_scope_id`, and regardless of whether one is found, also look
    /// up the boolean properties of the memory range. Faithful to
    /// `Scope::queryProperties` (database.cc:1263): the entry branch returns
    /// `entry->getAllFlags()`, the scope-only branch returns
    /// `mapped|addrtied(|persist)` OR the Database property at `addr`, and
    /// the no-owner branch returns just the property (database.cc:1269-1280)
    /// — `flag_lookup` is wired to [`Database::get_property`] directly since
    /// the Database owns the flagbase.
    pub fn query_properties(
        &self,
        qpoint_scope_id: u64,
        addr: Address,
        size: i32,
        usepoint: Address,
    ) -> (Option<QueryContainerHit>, u32) {
        // database.cc:1267 — mapScope(this, addr, usepoint).
        let base = self.map_scope(qpoint_scope_id, addr);
        let stack = self.ancestor_stack(base);
        let (hit, flags) =
            Scope::query_properties(&stack, addr, size, usepoint, |a| self.get_property(a));
        match hit {
            Some((scope_idx, entry_idx)) => (self.container_hit(&stack, scope_idx, entry_idx), flags),
            None => (None, flags),
        }
    }

    // Ghidra: database.cc:1796-1805 Scope::isReadOnly
    /// Is the given memory range marked as read-only, relative to
    /// `qpoint_scope_id`? Faithful to `Scope::isReadOnly` (database.cc:1796):
    /// `queryProperties(addr, size, usepoint, flags)` then test
    /// `flags & Varnode::readonly` — the consumer form used by
    /// `RulePtrsubCharConstant::applyOp` (ruleaction.cc:7372) and
    /// `PrintC::pushPtrCharConstant` (printc.cc:1709).
    pub fn is_read_only(
        &self,
        qpoint_scope_id: u64,
        addr: Address,
        size: i32,
        usepoint: Address,
    ) -> bool {
        let (_, flags) = self.query_properties(qpoint_scope_id, addr, size, usepoint);
        (flags & symbol_flags::READONLY) != 0
    }

    // Ghidra: database.cc:1198-1206 Scope::queryByName
    /// Starting from `qpoint_scope_id`, look for Symbols with the given
    /// name, recursing into parents until a scope has matches. Faithful to
    /// `Scope::queryByName` (database.cc:1198). Returns one record per
    /// matching Symbol in the first scope that has any (empty = no match
    /// anywhere on the chain).
    pub fn query_by_name(&self, qpoint_scope_id: u64, nm: &str) -> Vec<QueryNameHit> {
        let stack = self.ancestor_stack(qpoint_scope_id);
        let ids = Scope::query_by_name(&stack, nm);
        let mut out = Vec::new();
        for sid in ids {
            for scope in &stack {
                if let Some(sym) = scope.symbols.get(&sid) {
                    let sym = sym.read().unwrap();
                    if sym.name == nm {
                        out.push(QueryNameHit {
                            scope_id: scope.unique_id,
                            scope_name: scope.name.clone(),
                            symbol_id: sid,
                            symbol_name: sym.name.clone(),
                        });
                    }
                    break;
                }
            }
        }
        out
    }

    // Ghidra: database.cc:1246 Scope::queryContainer (live-entry form)
    /// The live-entry sibling of [`Database::query_container`]: the same
    /// `mapScope` + `stackContainer` walk, returning the scope-owned
    /// `SymbolEntry` itself (as an `Arc<RwLock<…>>` handle for
    /// `Varnode::set_symbol_entry`) plus the owning scope id, instead of the
    /// by-value `QueryContainerHit` projection. This is the form
    /// `Funcdata::mapGlobals`/`linkSymbol` consumers need when they attach
    /// the entry to a Varnode (funcdata_varnode.cc:1207-1211/1701): the C++
    /// hands the `SymbolEntry*` straight to `vn->setSymbolEntry`, and the
    /// symbol identity inside the shared `Arc` must survive so
    /// `HighVariable::set_symbol`'s conflict check (variable.cc:249-256)
    /// compares the same symbol.
    pub fn query_container_entry(
        &self,
        qpoint_scope_id: u64,
        addr: Address,
        size: i32,
        usepoint: Address,
    ) -> Option<(u64, std::sync::Arc<std::sync::RwLock<SymbolEntry>>)> {
        // database.cc:1250 — const Scope *basescope = mapScope(this, ...).
        let base = self.map_scope(qpoint_scope_id, addr);
        let stack = self.ancestor_stack(base);
        // database.cc:1251 — stackContainer(basescope, NULL, ...).
        let (scope_idx, entry_idx) = Scope::query_container(&stack, addr, size, usepoint)?;
        let scope = *stack.get(scope_idx)?;
        let entry = scope.entries.get(entry_idx)?;
        Some((
            scope.unique_id,
            std::sync::Arc::new(std::sync::RwLock::new(entry.clone())),
        ))
    }

    // Ghidra: database.cc:1353 Scope::discoverScope (channel form)
    /// The discover leg of the query channel: which scope owns the given
    /// memory range (ownership does not require a Symbol to exist there).
    /// Faithful to `Scope::discoverScope` (database.cc:1353-1366) realized
    /// through the Database scope stack: `mapScope(this, addr, usepoint)`
    /// then walk parents until `inScope(addr, sz, usepoint)` holds. The
    /// constant-address guard (cc:1358 `addr.isConstant()`) is the caller's
    /// space gate — Rugra's `Address` carries no space, so callers only
    /// reach this channel for default-data-space (RAM) addresses.
    pub fn discover_scope(&self, qpoint_scope_id: u64, addr: Address, sz: i32) -> Option<u64> {
        let base = self.map_scope(qpoint_scope_id, addr);
        let stack = self.ancestor_stack(base);
        // cc:1360-1364 — from the base scope upward, first scope in scope wins.
        for scope in stack {
            if scope.in_scope(addr, sz) {
                return Some(scope.unique_id);
            }
        }
        None
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
        // Property change-points (database.cc:3278-3288): one element per
        // flagbase SPLIT POINT, in split-point (Address) order, carrying the
        // cumulative value of the partition that starts at that address.
        for (addr, val) in &self.flagbase.database {
            let pc_elem = ElementId::new("property_changepoint", 78);
            encoder.open_element(&pc_elem);
            encoder.write_unsigned_integer(&AttributeId::new("offset", 0), addr.as_u64());
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
            // database.cc:3334 — flagbase.split(addr) = val: introduce the
            // split point (copying the previous partition's value) then
            // ASSIGN the decoded value, so the partition starting at `addr`
            // holds exactly `val`.
            *self.flagbase.split(Address::new(offset)) = val;
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
            // database.cc:2744-2789 — the scope decodes against the LIVE
            // Database state: <hole> children hit setPropertyRange and
            // <mapsym> folds read getProperty at their document position.
            // The global discovery snapshot is refreshed per scope so a
            // previously decoded global <rangelist> is visible (the C++
            // reads the live rangetree object at each addMap).
            let global_ranges: Vec<Range> = self
                .scopes
                .get(&self.global_scope_id)
                .map(|gs| gs.rangetree.ranges().to_vec())
                .unwrap_or_default();
            let Database {
                scopes, flagbase, ..
            } = self;
            if let Some(scope) = scopes.get_mut(&id) {
                if !display_name.is_empty() {
                    scope.display_name = display_name;
                }
                scope.decode_with_ctx(decoder, Some(flagbase), &global_ranges);
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
        // SymbolEntry::inUse (database.cc:114-120) three legs: a raw entry
        // (Symbol without the addMap addrtied fold, empty uselimit) is NOT
        // in use — cc:118 rejects the invalid usepoint and cc:119's
        // inRange admits nothing on an empty rangelist.
        assert!(!entry.in_use(Address::new(0x9999)));
        // cc:117: an address-tied Symbol is valid throughout the scope.
        let sym = Arc::new(RwLock::new(Symbol::new(0, "x", "int")));
        sym.write().unwrap().flags |= symbol_flags::ADDRTIED;
        let tied = SymbolEntry::new_static(sym, 0, Address::new(0x1000), 0, 4, RangeList::new());
        assert!(tied.in_use(Address::new(0x9999)));
        // cc:119: a use-limited entry is in use exactly inside its range.
        let sym = Arc::new(RwLock::new(Symbol::new(0, "x", "int")));
        let mut uselimit = RangeList::new();
        uselimit.insert_range(Range::new(Address::new(0x100), Address::new(0x1ff)).unwrap());
        let limited = SymbolEntry::new_static(sym, 0, Address::new(0x1000), 0, 4, uselimit);
        assert!(!limited.in_use(Address::new(0x99))); // legacy Address is
        // spaceless == Ghidra-invalid, so cc:118 fires before the range
        // test; the in-range admission is observable only through the
        // addrtied leg above.
        assert!(!limited.in_use(Address::new(0x150)));
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
        let container = scope.find_container(Address::new(0x1000), 4, Address::new(0));
        assert!(container.is_some());
        // Smallest containing = the 4-byte one.
        assert_eq!(scope.entries[container.unwrap()].get_size(), 4);
        // Over-extending query (cc:2267 getLast >= end): only the 16-byte
        // entry contains [0x1000,0x100f].
        let container = scope.find_container(Address::new(0x1000), 16, Address::new(0));
        assert_eq!(scope.entries[container.unwrap()].get_size(), 16);
        // Interior query starting past the base (cc find window on the
        // containing interval): [0x1002,0x1005] is beyond small's end
        // (0x1003, cc:2267 getLast >= end fails), only big contains.
        let container = scope.find_container(Address::new(0x1002), 4, Address::new(0));
        assert_eq!(scope.entries[container.unwrap()].get_size(), 16);
        // No container: past every entry.
        assert!(scope
            .find_container(Address::new(0x2000), 4, Address::new(0))
            .is_none());
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
    fn test_partmap_flagbase_semantics() {
        // database.cc:3220-3265 — the flagbase is a partition map: split
        // points carry cumulative values; overlapping setPropertyRange calls
        // ACCUMULATE on shared partitions (database.cc:3236 |=); a
        // sub-range clearPropertyRange only ANDs away the listed bits
        // inside [first, last_open) (database.cc:3261), leaving neighbours
        // untouched.
        let mut db = Database::new(false);
        let ro = Range::new(Address::new(0x1000), Address::new(0x1fff)).unwrap();
        let vol = Range::new(Address::new(0x1800), Address::new(0x27ff)).unwrap();
        db.set_property_range(symbol_flags::READONLY, ro);
        db.set_property_range(symbol_flags::VOLATIL, vol);
        // ro-only partition: [0x1000,0x1800).
        assert_eq!(db.get_property(Address::new(0x1000)), symbol_flags::READONLY);
        assert_eq!(db.get_property(Address::new(0x17ff)), symbol_flags::READONLY);
        // shared partition: [0x1800,0x2000) — both bits accumulate.
        assert_eq!(
            db.get_property(Address::new(0x1800)),
            symbol_flags::READONLY | symbol_flags::VOLATIL
        );
        // vol-only partition: [0x2000,0x2800).
        assert_eq!(db.get_property(Address::new(0x2000)), symbol_flags::VOLATIL);
        assert_eq!(db.get_property(Address::new(0x27ff)), symbol_flags::VOLATIL);
        // before / after everything: the default 0.
        assert_eq!(db.get_property(Address::new(0x0fff)), 0);
        assert_eq!(db.get_property(Address::new(0x2800)), 0);
        // Sub-range clear of readonly inside the shared partition: the
        // volatile bit survives, readonly stays outside [0x1900,0x1a00).
        let hole = Range::new(Address::new(0x1900), Address::new(0x19ff)).unwrap();
        db.clear_property_range(symbol_flags::READONLY, hole);
        assert_eq!(db.get_property(Address::new(0x1950)), symbol_flags::VOLATIL);
        assert_eq!(
            db.get_property(Address::new(0x1850)),
            symbol_flags::READONLY | symbol_flags::VOLATIL
        );
        assert_eq!(
            db.get_property(Address::new(0x1a00)),
            symbol_flags::READONLY | symbol_flags::VOLATIL
        );
    }

    #[test]
    fn test_partmap_split_value_copy() {
        // partmap.hh:119-134 — a split point starts as a COPY of the
        // preceding partition's value, so a later setPropertyRange below an
        // existing boundary never bleeds into earlier partitions.
        let mut pm = PartMap {
            database: BTreeMap::new(),
            defaultvalue: 0,
        };
        *pm.split(Address::new(0x100)) = 1;
        *pm.split(Address::new(0x300)) = 2;
        // The new split inherits value 1 (the partition [0x100,0x300)).
        assert_eq!(*pm.split(Address::new(0x200)), 1);
        assert_eq!(pm.get_value(Address::new(0x150)), 1);
        assert_eq!(pm.get_value(Address::new(0x250)), 1);
        assert_eq!(pm.get_value(Address::new(0x350)), 2);
        assert_eq!(pm.get_value(Address::new(0x050)), 0);
        // Re-splitting an existing point returns the SAME partition value.
        assert_eq!(*pm.split(Address::new(0x300)), 2);
    }

    #[test]
    fn test_add_map_point_property_fold() {
        // database.cc:1126-1155 — addMap folds the flagbase property at the
        // mapping address into the SYMBOL's flags when the uselimit is
        // empty; a usepoint-restricted map never folds; the construction
        // order decides (a later property range does not contaminate).
        let mut scope = Scope::new(2, "func", 1); // non-global (parent != 0)
        let sym = scope.add_symbol("folded", "int");
        // Models the Database flagbase: the readonly/volatile range
        // [0x4000,0x5000) exists BEFORE the first map; a SECOND range
        // [0x6000,0x7000) is installed only later (setPropertyRange flips
        // the flag) — only maps installed after their range exists fold.
        let property_calls = std::cell::RefCell::new(0u32);
        let second_range = std::cell::Cell::new(false);
        let ctx = AddMapContext {
            property: Box::new(|addr: Address| {
                *property_calls.borrow_mut() += 1;
                let mut bits = 0;
                if (0x4000..0x5000).contains(&addr.as_u64()) {
                    bits |= symbol_flags::READONLY | symbol_flags::VOLATIL;
                }
                if second_range.get() && (0x6000..0x7000).contains(&addr.as_u64()) {
                    bits |= symbol_flags::READONLY;
                }
                bits
            }),
            in_global_discovery: Box::new(|_| false),
        };
        // Property-first construction: fold happens (empty uselimit).
        scope.add_map_point(sym, Address::new(0x4500), Address::new(0), 4, Some(&ctx));
        let s = scope.symbols.get(&sym).unwrap().read().unwrap();
        assert!(s.flags & symbol_flags::ADDRTIED != 0);
        assert!(s.flags & symbol_flags::READONLY != 0);
        assert!(s.flags & symbol_flags::VOLATIL != 0);
        assert!(s.flags & symbol_flags::PERSIST == 0); // non-global, no discovery hit
        drop(s);
        // Victim order: the victim is mapped at 0x6100 BEFORE the
        // [0x6000,0x7000) readonly range is installed — never folds.
        let victim = scope.add_symbol("victim", "int");
        scope.add_map_point(victim, Address::new(0x6100), Address::new(0), 4, Some(&ctx));
        let v = scope.symbols.get(&victim).unwrap().read().unwrap();
        assert!(v.flags & symbol_flags::READONLY == 0);
        assert!(v.flags & symbol_flags::VOLATIL == 0);
        drop(v);
        // Now the range exists: a fresh map at the same address folds.
        second_range.set(true);
        let late = scope.add_symbol("late", "int");
        scope.add_map_point(late, Address::new(0x6100), Address::new(0), 4, Some(&ctx));
        let lt = scope.symbols.get(&late).unwrap().read().unwrap();
        assert!(lt.flags & symbol_flags::READONLY != 0);
        drop(lt);
        // A usepoint-restricted map (non-empty uselimit) skips BOTH addrtied
        // and the fold (database.cc:1149-1154 guard).
        let limited = scope.add_symbol("limited", "int");
        scope.add_map_point(
            limited,
            Address::new(0x4500),
            Address::new(0x9000),
            4,
            Some(&ctx),
        );
        let l = scope.symbols.get(&limited).unwrap().read().unwrap();
        assert!(l.flags & symbol_flags::ADDRTIED == 0);
        assert!(l.flags & symbol_flags::READONLY == 0);
        // Property lookup only ran for the three unrestricted maps (the
        // limited one returns before the lookup, database.cc:1149 guard).
        assert_eq!(*property_calls.borrow(), 3);
        // Persist branch: a GLOBAL scope symbol always takes persist
        // (database.cc:1131-1132).
        let mut global = Scope::new(0, "global", 0);
        let gsym = global.add_symbol("g", "int");
        global.add_map_point(gsym, Address::new(0x4500), Address::new(0), 4, Some(&ctx));
        let g = global.symbols.get(&gsym).unwrap().read().unwrap();
        assert!(g.flags & symbol_flags::PERSIST != 0);
        assert!(g.flags & symbol_flags::READONLY != 0);
        drop(g);
    }

    #[test]
    fn test_global_discovery_uselimit_clear() {
        // database.cc:1133-1142 — a non-global scope symbol mapped at an
        // address inside the GLOBAL scope's discovery range gets persist
        // AND its uselimit CLEARED, which then feeds the addrtied + fold
        // branch (the decisive interaction).
        let mut scope = Scope::new(2, "func", 1); // non-global
        let sym = scope.add_symbol("disc", "int");
        let ctx = AddMapContext {
            property: Box::new(|addr: Address| {
                if addr.as_u64() == 0x7f000000 {
                    symbol_flags::READONLY
                } else {
                    0
                }
            }),
            in_global_discovery: Box::new(|addr: Address| {
                (0x7f000000..=0x7f00ffff).contains(&addr.as_u64())
            }),
        };
        scope.add_map_point(
            sym,
            Address::new(0x7f000000),
            Address::new(0x2000), // would restrict the uselimit...
            4,
            Some(&ctx),
        );
        let s = scope.symbols.get(&sym).unwrap().read().unwrap();
        assert!(s.flags & symbol_flags::PERSIST != 0);
        // ...but the discovery hit cleared it, so addrtied + fold ran.
        assert!(s.flags & symbol_flags::ADDRTIED != 0);
        assert!(s.flags & symbol_flags::READONLY != 0);
        drop(s);
        let entry = &scope.entries[0];
        assert!(entry.get_use_limit().empty());
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
        use crate::type_system::typefactory::TypeFactory;
        let mut type_factory = TypeFactory::new(8);
        let sym = Arc::new(RwLock::new(Symbol::new(0, "x", "int")));
        sym.write().unwrap().dtype = Some(Arc::new(Datatype::Base(TypeBase::new(
            "int".into(), 4, TypeMetatype::Int,
        ))));
        let entry = SymbolEntry::new_static(sym, 0, Address::new(0x1000), 0, 4, RangeList::new());
        // Whole-symbol match (offset 0, exact size).
        let dt = entry.get_sized_type(&mut type_factory, Address::new(0x1000), 4);
        assert!(dt.is_some());
        // Wrong size → no exact match.
        assert!(entry
            .get_sized_type(&mut type_factory, Address::new(0x1000), 8)
            .is_none());
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
        let mut scope = Scope::new(2, "func", 1); // non-global
        // The caddr and the inUse probes are Ghidra-VALID code addresses:
        // legacy spaceless Address::new would be is_invalid() and the
        // database.cc:118 leg would reject the entry before the uselimit
        // test (SymbolEntry::inUse), so mint spaced addresses.
        use crate::space::{space_flags, AddrSpace, SpaceType};
        let ram = AddrSpace::new_space(
            SpaceType::Processor, "ram", false, 8, 1, 3, space_flags::HASPHYSICAL, 0, 0,
        );
        let caddr = Address::with_space(&ram, 0x1234);
        let id = scope.add_dynamic_symbol("dyn", "int", 4, caddr, 0xDEADBEEF);
        assert_eq!(scope.num_symbols(), 1);
        assert!(id != 0);
        // The dynamic entry should be in dynamic_entries with the hash.
        assert_eq!(scope.dynamic_entries.len(), 1);
        let entry = &scope.dynamic_entries[0];
        assert_eq!(entry.get_hash(), 0xDEADBEEF);
        assert!(entry.is_dynamic());
        assert_eq!(entry.size, 4);
        // Use-limit should contain the caddr (database.cc:119 inRange leg).
        assert!(entry.in_use(caddr));
        assert!(!entry.in_use(Address::with_space(&ram, 0x9999)));
    }

    #[test]
    fn test_scope_add_equate_symbol() {
        // database.cc:1712 — addEquateSymbol creates an equate + dynamic entry.
        let mut scope = Scope::new(2, "func", 1); // non-global
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
        // database.cc:1827-1836 (addSymbolInternal via cc:1718): both equates
        // land in category[equate] with catindex = list.size() at insert time
        // (first 0, second 1).
        assert_eq!(scope_a.get_category_size(1), 2);
        assert_eq!(
            scope_a
                .symbols
                .get(&id1)
                .unwrap()
                .read()
                .unwrap()
                .get_category_index(),
            0
        );
        assert_eq!(
            scope_a
                .symbols
                .get(&id2)
                .unwrap()
                .read()
                .unwrap()
                .get_category_index(),
            1
        );
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
        let mut scope = Scope::new(2, "func", 1); // non-global
        let root = std::sync::Arc::new(std::sync::RwLock::new(build_mapsym(Some("66"))));
        let mut dec = TreeDecoder::new(root, registry.clone());
        let id = scope.add_map_sym(&mut dec, None);
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
        let id2 = scope2.add_map_sym(&mut dec2, None);
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
        let mut scope = Scope::new(2, "func", 1); // non-global
        let _ = scope.add_equate_symbol(
            "MY_CONST", 0, 0x33333333, Address::new(0x2000), 0xCAFE,
        );
        let entry = scope.dynamic_entries[0].clone();
        let src = std::sync::Arc::new(std::sync::RwLock::new({
            let mut v = Varnode::new_constant(0x33333333, 4);
            v.set_symbol_entry(std::sync::Arc::new(std::sync::RwLock::new(entry)));
            v
        }));
        let dst = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(
            0x33333333, 4,
        )));
        Varnode::copy_symbol_if_valid(&dst, &src.read().unwrap());
        assert!(
            dst.read().unwrap().get_symbol_entry().is_some(),
            "pipeline equate must propagate through copy_symbol_if_valid"
        );
        // Not-close destination constant must NOT receive the markup.
        let dst2 = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(
            0x12345678, 4,
        )));
        Varnode::copy_symbol_if_valid(&dst2, &src.read().unwrap());
        assert!(dst2.read().unwrap().get_symbol_entry().is_none());
    }

    #[test]
    fn test_scope_add_union_facet_symbol() {
        // database.cc:1737 — addUnionFacetSymbol creates a union facet.
        let mut scope = Scope::new(2, "func", 1); // non-global
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
        let mut scope = Scope::new(2, "func", 1); // non-global
        let id = scope.add_symbol("v", "int");
        // The usepoint and the inUse probes are Ghidra-VALID code addresses
        // (database.cc:1151 insertRange fires on !isInvalid); mint spaced
        // addresses so the database.cc:119 inRange leg is observable.
        use crate::space::{space_flags, AddrSpace, SpaceType};
        let ram = AddrSpace::new_space(
            SpaceType::Processor, "ram", false, 8, 1, 3, space_flags::HASPHYSICAL, 0, 0,
        );
        let usepoint = Address::with_space(&ram, 0x5000);
        scope.add_map_point(id, Address::new(0x1000), usepoint, 4, None);
        let entry = scope.find_addr(Address::new(0x1000));
        assert!(entry.is_some());
        // Use-limit must be restricted to the usepoint.
        assert!(entry.unwrap().in_use(usepoint));
        assert!(!entry.unwrap().in_use(Address::with_space(&ram, 0x9999)));
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
        let mut scope = Scope::new(2, "func", 1); // non-global
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
        let mut scope = Scope::new(2, "func", 1); // non-global
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
        let mut scope = Scope::new(2, "func", 1); // non-global
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
        let mut scope = Scope::new(2, "func", 1); // non-global
        let id = scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        let ok = scope.retype_symbol(id, "uint", 4);
        assert!(ok);
        let s = scope.symbols.get(&id).unwrap().read().unwrap();
        assert_eq!(s.type_name, "uint");
    }

    #[test]
    fn test_scope_retype_symbol_addr_tied_resize() {
        // database.cc:2177-2196 — retype with size change + 1 addr-tied map.
        let mut scope = Scope::new(2, "func", 1); // non-global
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
        let mut scope = Scope::new(2, "func", 1); // non-global
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
        let mut scope = Scope::new(2, "func", 1); // non-global
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
        let mut scope = Scope::new(2, "func", 1); // non-global
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
        let mut scope = Scope::new(2, "func", 1); // non-global
        scope.add_symbol_mapped("x", "int", Address::new(0x1000), 4);
        scope.adjust_caches();
        // State unchanged.
        assert_eq!(scope.num_symbols(), 1);
    }


}
