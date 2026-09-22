//! Import function prototypes from native debug metadata.
//!
//! Ghidra imports DWARF into its Program database before the decompiler runs.
//! The decompiler then receives a locked [`crate::fspec::FuncProto`].  This
//! module provides the same front-end boundary for Rugra: it reads concrete
//! subprogram definitions (following `DW_AT_abstract_origin` and
//! `DW_AT_specification`), materializes the declared prototype, assigns
//! parameter storage from the active compiler-spec resource order, and locks
//! the result before any Action executes.
//!
//! It also imports DWARF global variables (`DW_TAG_variable` with a static
//! `DW_OP_addr` location) so their declared types reach the global
//! symbol/type boundary the same way Ghidra's DWARF analyzer attaches them
//! to the Program's symbol table.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianRcSlice, Reader, RunTimeEndian,
    SectionId, Unit, UnitOffset,
};
use object::{Object, ObjectSection};

use crate::fspec::FuncProto;
use crate::funcdata::Funcdata;
use crate::type_system::datatype::{
    Datatype, TypeArray, TypeBase, TypeEnum, TypeField, TypeMetatype, TypePointer, TypeStruct,
    TypeUnion,
};

type DwarfReader = EndianRcSlice<RunTimeEndian>;

/// One declared function parameter, in source declaration order.
#[derive(Debug, Clone)]
pub struct DebugParameter {
    pub name: String,
    /// True only when the source record carried an explicit parameter name.
    pub name_locked: bool,
    pub data_type: Arc<Datatype>,
}

/// A concrete DWARF subprogram definition and its canonical declaration.
#[derive(Debug, Clone)]
pub struct DebugPrototype {
    pub address: u64,
    pub name: String,
    pub return_type: Arc<Datatype>,
    pub parameters: Vec<DebugParameter>,
    pub is_varargs: bool,
}

/// Function-entry address to imported prototype.
#[derive(Debug, Clone, Default)]
pub struct DebugPrototypeDatabase {
    prototypes: BTreeMap<u64, DebugPrototype>,
}

/// A DWARF global-variable definition with a static address.
///
/// Mirrors the symbol-table entry Ghidra's DWARF analyzer creates for a
/// `DW_TAG_variable` carrying `DW_AT_location = DW_OP_addr <addr>`: the
/// variable's name, storage address, and declared data type.
#[derive(Debug, Clone)]
pub struct DebugGlobalVariable {
    pub address: u64,
    pub name: String,
    pub data_type: Arc<Datatype>,
    /// Name of the nearest enclosing `DW_TAG_subprogram` when the variable
    /// DIE is nested inside a function (a C function-static). Ghidra's DWARF
    /// analyzer imports those into the function's namespace, so the symbol
    /// display name is `<parent_function>::<name>` (locked-oracle witnesses:
    /// `my_get_token::save` at 0x17510, `next_url::beenhere` at 0x17518);
    /// CU-level variables keep `None` and stay in the global scope.
    pub parent_function: Option<String>,
}

/// Static-address global variables keyed by storage address.
#[derive(Debug, Clone, Default)]
pub struct DebugGlobalDatabase {
    globals: BTreeMap<u64, DebugGlobalVariable>,
    address_size: usize,
}

impl DebugGlobalDatabase {
    // RUGRA-GLUE: reads the same DW_TAG_variable + DW_OP_addr records Ghidra's Java DWARF analyzer turns into Program symbols; native front-end adapter for that boundary
    pub fn parse_elf(bytes: &[u8]) -> Result<Self> {
        let dwarf = load_dwarf(bytes).context("parsing object for DWARF globals")?;
        let mut globals = BTreeMap::new();
        let mut address_size = 8usize;
        let mut headers = dwarf.units();
        while let Some(header) = headers.next().context("iterating DWARF units")? {
            let unit = dwarf.unit(header).context("loading DWARF unit")?;
            address_size = unit.encoding().address_size as usize;
            let mut entries = unit.entries();
            // (depth, name, is_subprogram) stack for parent-function
            // tracking: next_dfs yields (depth, entry) in document order, so
            // popping the stack down to depth-1 leaves the direct parent.
            let mut scope_stack: Vec<(usize, Option<String>, bool)> = Vec::new();
            while let Some((depth, entry)) = entries.next_dfs().context("walking DWARF DIEs")? {
                let depth = usize::try_from(depth).unwrap_or(0);
                while scope_stack.len() > depth {
                    scope_stack.pop();
                }
                let parent_function = scope_stack
                    .iter()
                    .rev()
                    .find(|(_, _, is_subprogram)| *is_subprogram)
                    .and_then(|(_, name, _)| name.clone());
                let entry_name =
                    entry_string(&dwarf, &unit, entry, gimli::DW_AT_name)?;
                if entry.tag() != gimli::DW_TAG_variable {
                    scope_stack.push((depth, entry_name, entry.tag() == gimli::DW_TAG_subprogram));
                    continue;
                }
                let Some(address) = static_location_address(&unit, entry)? else {
                    scope_stack.push((depth, entry_name, false));
                    continue;
                };
                let Some(name) = entry_name.clone() else {
                    scope_stack.push((depth, entry_name, false));
                    continue;
                };
                let data_type = match entry_reference(&unit, entry, gimli::DW_AT_type)? {
                    Some(offset) => resolve_type(&dwarf, &unit, offset, 0, &mut Vec::new())?,
                    None => unknown_type(address_size),
                };
                globals.insert(
                    address,
                    DebugGlobalVariable {
                        address,
                        name,
                        data_type,
                        parent_function,
                    },
                );
                scope_stack.push((depth, entry_name, false));
            }
        }
        Ok(Self {
            globals,
            address_size,
        })
    }

    // RUGRA-GLUE: address-keyed lookup mirroring the Program database query Rugra's driver performs when seeding global types
    pub fn get(&self, address: u64) -> Option<&DebugGlobalVariable> {
        self.globals.get(&address)
    }

    // RUGRA-GLUE: deterministic address order for diagnostics around the Program-to-Funcdata import boundary
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &DebugGlobalVariable)> {
        self.globals.iter()
    }

    // RUGRA-GLUE: count accessor for diagnostics around the Program-to-Funcdata import boundary
    pub fn len(&self) -> usize {
        self.globals.len()
    }

    // RUGRA-GLUE: builds Funcdata::global_struct_ptrs entries; each address constant referencing a global gets the C "&global" type (pointer to the variable's declared type, with array decay), which Ghidra derives from its symbol-table Datatype linkage
    pub fn address_pointer_map(&self) -> HashMap<u64, Arc<Datatype>> {
        self.globals
            .values()
            .map(|global| {
                (
                    global.address, global_address_type(global, self.address_size),
                )
            })
            .collect()
    }

    // RUGRA-GLUE: the DWARF front-end's committed-data-type semantic.
    /// Ghidra's DWARF analyzer creates Data whose imported data type is
    /// committed (locked memory); the decompiler interface exports that as
    /// ATTRIB_TYPELOCK on the symbol XML, which `Symbol::decodeHeader`
    /// folds into the Symbol's typelock flag (database.cc:439-442). Both
    /// typelock-gated consumers — `SymbolEntry::updateType`
    /// (database.cc:135-141, reached via `Varnode::setSymbolProperties`
    /// varnode.cc:413) and `ActionInferTypes::buildLocaltypes`' exact-piece
    /// branch (coreaction.cc:5021-5027) — depend on it to attach a global
    /// Symbol's DWARF type onto the address varnode RuleLoadVarnode
    /// materializes (ruleaction.cc:4293 `newVarnode` → `queryProperties` →
    /// `setSymbolProperties`). Rugra's driver seeds the query-channel
    /// Database directly, so the typelock fold lives here as the single
    /// front-end semantic.
    pub fn seed_global_locked(
        db: &mut crate::database::Database,
        scope_id: u64,
        address: u64,
        name: &str,
        dtype: Arc<Datatype>,
        size: i32,
    ) -> Option<u64> {
        let symbol_id =
            db.add_symbol_mapped(scope_id, name, Some(dtype), crate::address::Address::new(address), size);
        if let Some(symbol_id) = symbol_id {
            db.set_symbol_flag(scope_id, symbol_id, crate::database::symbol_flags::TYPELOCK, true);
        }
        symbol_id
    }
}

/// PLT thunk entries keyed by thunk entry address.
///
/// Mirrors the function symbols Ghidra's ELF front-end creates for every PLT
/// thunk: a `.plt.sec`/`.plt` slot (an `endbr64; bnd jmp *disp32(%rip)`
/// sequence jumping through a GOT slot owned by an
/// `R_X86_64_JUMP_SLOT`/`.rela.plt` relocation) or a `.plt.got` slot (whose
/// GOT slot is owned by an `R_X86_64_GLOB_DAT` relocation in `.rela.dyn`)
/// becomes a thunk Function named after the dynamic import it resolves. The
/// decompiler side then reads that name through the call-spec chain
/// (`FlowInfo::queryCall` flow.cc:656-672 → `FuncCallSpecs::setFuncdata`
/// fspec.cc:4949-4960 → `PrintC::opCall` printc.cc:601-609 `fc->getName()`),
/// which is why an undefined dynamic import (`apr_app_initialize`,
/// st_value==0, lives in libapr) still prints its name at every direct call
/// site of the thunk in the locked httpd oracle
/// (tests/golden/ghidra_httpd_1204.c: `apr_app_initialize(auStack_9c,...)`
/// for the 0x12a6d0 thunk). Without this import a call target address has no
/// symbol anywhere, `Funcdata::map_globals`'s no-symbol arm builds a
/// `uRam<offset>` data-global name for it (varmap.rs build_variable_name
/// mirroring database.cc:2455-2468), and the printer shows `uRam...()` as
/// the callee.
#[derive(Debug, Clone, Default)]
pub struct ElfPltImports {
    thunks: BTreeMap<u64, String>,
}

impl ElfPltImports {
    /// Import every PLT thunk name from the ELF image.
    ///
    /// `.plt.sec`/`.plt` slots are matched to `.rela.plt` JUMP_SLOT
    /// relocations by slot index (`i`-th relocation ↔ `base + 16*i`, with
    /// `.plt` slots starting at index 1 to skip the resolver header);
    /// `.plt.got` slots are decoded individually (the `f2 ff 25 <disp32>`
    /// tail) and matched against the R_X86_64_GLOB_DAT relocation that owns
    /// the jumped-through GOT address. Slot geometry and matching follow the
    /// locked-oracle witnesses documented with the original driver-side
    /// implementation (examples/curl_decompile.rs PLT resolution block;
    /// httpd witnesses: slot 43 = 0x2a6d0 = `apr_app_initialize`,
    /// `.plt` @0x29020, `.plt.got` @0x2a400, `.plt.sec` @0x2a420).
    // RUGRA-GLUE: reads the same .plt/.plt.sec/.plt.got + relocation records Ghidra's Java ELF/PLT analyzer turns into thunk Function symbols; native front-end adapter for that boundary
    pub fn parse_elf(bytes: &[u8]) -> Self {
        let obj = match goblin::Object::parse(bytes) {
            Ok(obj) => obj,
            Err(_) => return Self::default(),
        };
        let goblin::Object::Elf(elf) = obj else {
            return Self::default();
        };
        let mut thunks = BTreeMap::new();

        let mut plt_sec_base = 0u64;
        let mut plt_base = 0u64;
        let mut plt_got: Option<(u64, u64, u64)> = None; // (sh_addr, sh_offset, sh_size)
        for header in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                match name {
                    ".plt" => plt_base = header.sh_addr,
                    ".plt.sec" => plt_sec_base = header.sh_addr,
                    ".plt.got" => {
                        plt_got =
                            Some((header.sh_addr, header.sh_offset, header.sh_size))
                    }
                    _ => {}
                }
            }
        }

        // .plt.sec (or .plt) via .rela.plt JUMP_SLOT relocations.
        let (base, offset_start) = if plt_sec_base != 0 {
            (plt_sec_base, 0u64)
        } else if plt_base != 0 {
            (plt_base, 1u64)
        } else {
            (0, 0)
        };
        if base != 0 {
            for (i, reloc) in elf.pltrelocs.iter().enumerate() {
                let plt_addr = base + 16 * (i as u64 + offset_start);
                if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if !name.is_empty() {
                            thunks
                                .entry(plt_addr)
                                .or_insert_with(|| name.to_string());
                        }
                    }
                }
            }
        }

        // .plt.got slots: GOT owners are R_X86_64_GLOB_DAT relocations in
        // .rela.dyn (not .rela.plt), so the slot-index loop above misses
        // them; decode each slot's `f2 ff 25 <disp32>` tail directly.
        if let Some((slot_vaddr, file_off, sh_size)) = plt_got {
            for slot in 0..(sh_size as usize / 8) {
                let start = file_off as usize + slot * 8;
                let Some(insn) = bytes.get(start..start + 11) else {
                    continue;
                };
                if insn[4] != 0xf2 || insn[5] != 0xff || insn[6] != 0x25 {
                    continue;
                }
                let disp =
                    i32::from_le_bytes([insn[7], insn[8], insn[9], insn[10]]) as i64;
                let got_addr = (slot_vaddr + slot as u64 + 11) as i64 + disp;
                let name = elf
                    .dynrelas
                    .iter()
                    .chain(elf.dynrels.iter())
                    .find_map(|reloc| {
                        if reloc.r_offset != got_addr as u64 {
                            return None;
                        }
                        elf.dynsyms
                            .get(reloc.r_sym)
                            .and_then(|sym| elf.dynstrtab.get_at(sym.st_name))
                            .filter(|name| !name.is_empty())
                    });
                if let Some(name) = name {
                    thunks
                        .entry(slot_vaddr + slot as u64)
                        .or_insert_with(|| name.to_string());
                }
            }
        }

        Self { thunks }
    }

    // RUGRA-GLUE: address-keyed lookup mirroring the Program database query the driver performs when seeding call-target symbols
    pub fn get(&self, address: u64) -> Option<&String> {
        self.thunks.get(&address)
    }

    // RUGRA-GLUE: deterministic address order for the driver-side seeding loop
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &String)> {
        self.thunks.iter()
    }

    // RUGRA-GLUE: count accessor for import-boundary diagnostics
    pub fn len(&self) -> usize {
        self.thunks.len()
    }

    // RUGRA-GLUE: emptiness accessor for the clippy len-without-is_empty pair
    pub fn is_empty(&self) -> bool {
        self.thunks.is_empty()
    }

    // RUGRA-GLUE: thunk-membership test used to gate the default FUN_ naming pass (a thunk already carries its import name)
    pub fn contains(&self, address: u64) -> bool {
        self.thunks.contains_key(&address)
    }
}

/// Default name for an analysis-discovered function symbol, mirroring the
/// locked-oracle convention: Ghidra's front-end names every function the
/// analysis creates (and no ELF symbol covers) `FUN_` + the entry address in
/// 8-digit zero-padded hex — on the analyzeHeadless **image base** address,
/// not the raw ELF virtual address (the httpd oracle loads the ET_DYN image
/// at 0x100000, so the golden's shared tail chunks read `FUN_0012c520` for
/// ELF vaddr 0x2c520). The decompiler prints such names verbatim at call
/// sites through the same fspec chain as named functions
/// (`PrintC::opCall` printc.cc:601-609); Rugra's driver seeds the name into
/// its callpoint-symbol stand-in for that table.
// RUGRA-GLUE: Ghidra's Java SymbolManager owns this default-name policy (outside decompile/cpp); native front-end adapter for the boundary
pub fn analyze_headless_function_symbol_name(vaddr: u64, image_base: u64) -> String {
    format!("FUN_{:08x}", image_base.wrapping_add(vaddr))
}

// RUGRA-GLUE: index of DWARF named types (struct/union/enum/typedef spellings)
// built at the Program-import boundary. Ghidra's DWARF analyzer populates the
// program type manager with these names, and the platform signature loader
// resolves signature base spellings (e.g. `FILE`) against that manager; this
// index is the driver-side equivalent handed to `LibcSignatureTable::locked_proto`.
// First definition wins on duplicate names (Ghidra suffixes conflicts; the
// locked curl corpus has none).
pub fn parse_type_names(bytes: &[u8]) -> Result<HashMap<String, Arc<Datatype>>> {
    let dwarf = load_dwarf(bytes).context("parsing object for DWARF named types")?;
    let mut names: HashMap<String, Arc<Datatype>> = HashMap::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next().context("iterating DWARF units")? {
        let unit = dwarf.unit(header).context("loading DWARF unit")?;
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs().context("walking DWARF DIEs")? {
            let named = matches!(
                entry.tag(),
                gimli::DW_TAG_structure_type
                    | gimli::DW_TAG_union_type
                    | gimli::DW_TAG_enumeration_type
                    | gimli::DW_TAG_typedef
                    | gimli::DW_TAG_base_type
            );
            if !named {
                continue;
            }
            let Some(name) = entry_string(&dwarf, &unit, entry, gimli::DW_AT_name)? else {
                continue;
            };
            if names.contains_key(&name) {
                continue;
            }
            let data_type = match entry_reference(&unit, entry, gimli::DW_AT_type)? {
                Some(offset) => resolve_type(&dwarf, &unit, offset, 0, &mut Vec::new())?,
                None => resolve_type(&dwarf, &unit, entry.offset(), 0, &mut Vec::new())?,
            };
            names.insert(name, data_type);
        }
    }
    Ok(names)
}

// RUGRA-GLUE: shared DWARF section loader for the prototype and global importers
fn load_dwarf(bytes: &[u8]) -> Result<Dwarf<DwarfReader>> {    let object = object::File::parse(bytes).context("parsing object for DWARF sections")?;
    let endian = if object.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    Dwarf::load(|id: SectionId| {
        let data = match object.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?,
            None => Cow::Borrowed(&[][..]),
        };
        let owned: Rc<[u8]> = Rc::from(data.as_ref());
        Ok::<DwarfReader, object::Error>(EndianRcSlice::new(owned, endian))
    })
    .context("loading DWARF sections")
}

// RUGRA-GLUE: extracts a variable's static storage address from DW_AT_location; accepts exactly DW_OP_addr (the form Ghidra's analyzer requires for a global symbol), skipping register/complex expressions deterministically
fn static_location_address(
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
) -> Result<Option<u64>> {
    let Some(AttributeValue::Exprloc(expression)) = entry.attr_value(gimli::DW_AT_location)?
    else {
        return Ok(None);
    };
    let mut operations = expression.operations(unit.encoding());
    let Some(first) = operations.next()? else {
        return Ok(None);
    };
    let gimli::Operation::Address { address } = first else {
        return Ok(None);
    };
    if operations.next()?.is_some() {
        return Ok(None);
    }
    Ok(Some(address))
}

// RUGRA-GLUE: the type of an address constant that references a DWARF global; "&global" is a pointer to the variable's declared type, and arrays decay to element pointers per C address-of semantics on the IR
fn global_address_type(global: &DebugGlobalVariable, ptr_size: usize) -> Arc<Datatype> {
    if let Datatype::Array(array) = global.data_type.as_ref() {
        return pointer_type(array.array_of.clone(), ptr_size);
    }
    pointer_type(global.data_type.clone(), ptr_size)
}

impl DebugPrototypeDatabase {
    // RUGRA-GLUE: Ghidra's Java DWARF analyzer populates the Program database before the C++ decompiler; this is Rugra's native front-end adapter for that boundary
    pub fn parse_elf(bytes: &[u8]) -> Result<Self> {
        let dwarf = load_dwarf(bytes).context("parsing object for DWARF prototypes")?;

        let mut prototypes = BTreeMap::new();
        let mut headers = dwarf.units();
        while let Some(header) = headers.next().context("iterating DWARF units")? {
            let unit = dwarf.unit(header).context("loading DWARF unit")?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs().context("walking DWARF DIEs")? {
                if entry.tag() != gimli::DW_TAG_subprogram {
                    continue;
                }
                let Some(address) = subprogram_address(&dwarf, &unit, entry)? else {
                    continue;
                };
                let canonical = canonical_subprogram_offset(&unit, entry.offset())?;
                let canonical_entry = unit
                    .entry(canonical)
                    .context("reading canonical subprogram DIE")?;
                let name = entry_string(&dwarf, &unit, &canonical_entry, gimli::DW_AT_name)?
                    .or(entry_string(&dwarf, &unit, entry, gimli::DW_AT_name)?)
                    .unwrap_or_else(|| format!("FUN_{address:08x}"));
                let return_type = match entry_reference(&unit, &canonical_entry, gimli::DW_AT_type)?
                {
                    Some(offset) => resolve_type(&dwarf, &unit, offset, 0, &mut Vec::new())?,
                    None => void_type(),
                };
                let (parameters, is_varargs) = read_prototype_children(&dwarf, &unit, canonical)?;
                prototypes.insert(
                    address,
                    DebugPrototype {
                        address,
                        name,
                        return_type,
                        parameters,
                        is_varargs,
                    },
                );
            }
        }
        Ok(Self { prototypes })
    }

    // RUGRA-GLUE: address-keyed lookup mirrors the Program database query performed before Ghidra constructs Funcdata
    pub fn get(&self, address: u64) -> Option<&DebugPrototype> {
        self.prototypes.get(&address)
    }

    // RUGRA-GLUE: exposes deterministic address order for front-end prototype seeding; Ghidra's Program database iterator is outside decompile/cpp
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &DebugPrototype)> {
        self.prototypes.iter()
    }

    // RUGRA-GLUE: count accessor for diagnostics around the Program-to-Funcdata import boundary
    pub fn len(&self) -> usize {
        self.prototypes.len()
    }

    // RUGRA-GLUE: applies a Program-database prototype to Rugra Funcdata before Actions, matching Ghidra's externally locked prototype boundary
    pub fn apply(&self, fd: &mut Funcdata) -> Result<bool> {
        let Some(debug_proto) = self.get(fd.baseaddr.as_u64()) else {
            return Ok(false);
        };
        let model_carrier = fd.funcp.clone();
        fd.funcp = self.locked_proto(debug_proto, &model_carrier)?;
        Ok(true)
    }

    /// Materialize the locked call-site `FuncProto` for a callee entry
    /// address, mirroring the other half of the same Program-database
    /// boundary: `FlowInfo::queryCall` (flow.cc:656-672) resolves the callee
    /// `Funcdata` whose DWARF signature the analyzer locked, and
    /// `ActionDefaultParams` (coreaction.cc:2322-2330) copies that whole
    /// callee prototype onto the call site with
    /// `fc->copy(otherfunc->getFuncProto())` — `FuncProto::copy`
    /// (fspec.cc:3789-3804) transfers the model pointer, the flag word
    /// (every lock bit), and a clone of the parameter store, so the call
    /// site ends up with the callee's locked parameter list verbatim.
    ///
    /// `model_carrier` supplies the model exactly as the callee's own
    /// `Funcdata` would have bound it: the Architecture default model both
    /// the decompiled function and every DWARF-analyzed callee carry (the
    /// same carrier `apply` clones from `fd.funcp` after
    /// `Funcdata::set_arch`'s named-ctor binding, FUNCPROTO-MODEL-BIND-0001).
    ///
    /// Returns `Ok(None)` when the address has no DWARF definition (import
    /// thunk / non-debug function: the boundary contributes nothing and the
    /// generic_clib import table or active recovery owns the call site).
    // RUGRA-GLUE: the queryCall -> ActionDefaultParams copy boundary for DWARF-locked callees; Ghidra reaches it via the Program database, Rugra's driver hands it directly
    pub fn locked_callsite_proto(
        &self,
        entry: u64,
        model_carrier: &FuncProto,
    ) -> Result<Option<FuncProto>> {
        let Some(debug_proto) = self.get(entry) else {
            return Ok(None);
        };
        // [DBG] probe: match_url DWARF proto pieces
        if debug_proto.name == "match_url" {
            eprintln!(
                "[DBG] MATCH_URL_PROTO ret={} params={}",
                debug_proto.return_type.get_name(),
                debug_proto.parameters.len()
            );
            for (i, p) in debug_proto.parameters.iter().enumerate() {
                let dt = &p.data_type;
                let mut layout = String::new();
                if let crate::type_system::datatype::Datatype::Struct(ts) = &**dt {
                    layout = ts
                        .fields
                        .iter()
                        .map(|f| format!("{}@{}", f.name, f.offset))
                        .collect::<Vec<_>>()
                        .join(",");
                }
                eprintln!(
                    "[DBG]   param{} name={} type={} size={} struct[{}]",
                    i, p.name, dt.get_name(), dt.get_size(), layout
                );
            }
        }
        self.locked_proto(debug_proto, model_carrier).map(Some)
    }

    // RUGRA-GLUE: shared locked-signature builder behind both halves of the
    // DWARF Program-database boundary (own-function apply + call-site copy);
    // the lock recipe mirrors FuncProto::setPieces (fspec.cc:3843-3852):
    // assigned storage, DW_AT_name-gated NAME_LOCKED bits, input/output/model
    // locks, and the void-signature unknown-model pin below.
    fn locked_proto(
        &self,
        debug_proto: &DebugPrototype,
        model_carrier: &FuncProto,
    ) -> Result<FuncProto> {
        if !model_carrier.has_model() {
            bail!(
                "DWARF prototype {} has no bound ProtoModel", debug_proto.name
            );
        }
        let mut proto = FuncProto::from_model_carrier(
            model_carrier,
            debug_proto.name.clone(),
            debug_proto.return_type.clone(),
        );
        let pieces = crate::grammar::PrototypePieces {
            model: None,
            name: debug_proto.name.clone(),
            out_type: Some(debug_proto.return_type.clone()),
            in_types: debug_proto
                .parameters
                .iter()
                .map(|parameter| parameter.data_type.clone())
                .collect(),
            in_names: debug_proto
                .parameters
                .iter()
                .map(|parameter| parameter.name.clone())
                .collect(),
            first_var_arg_slot: if debug_proto.is_varargs {
                debug_proto.parameters.len() as i32
            } else {
                -1
            },
        };
        proto.name = debug_proto.name.clone();
        proto.set_pieces(&pieces);
        if proto.has_input_errors() {
            bail!(
                "compiler model cannot assign parameter storage for DWARF prototype {}",
                debug_proto.name
            );
        }
        let mut source_index = 0usize;
        for param in &mut proto.parameters {
            if param.is_hidden_return() {
                continue;
            }
            let Some(parameter) = debug_proto.parameters.get(source_index) else {
                break;
            };
            // Ghidra's DWARF import locks only real DW_AT_name parameter
            // names (ProtoStoreSymbol::setInput mirrors
            // ParameterPieces::namelock onto the symbol, fspec.cc:3158/:3180);
            // a nameless DIE stays unnamed and the decompiler's default
            // naming (buildDefaultName) owns it — so the synthesized
            // param_N stand-in is NOT name-locked (lookForFuncParamNames
            // additionally filters the param_ prefix, coreaction.cc:2831).
            if parameter.name_locked {
                param.flags |= crate::fspec::protoparam_flags::NAME_LOCKED;
            }
            source_index += 1;
        }
        Ok(proto)
    }
}

/// One locked public-libc ABI declaration for an imported symbol, kept in the
/// exact C-declaration spelling Ghidra's shipped generic_clib signature data
/// carries (glibc reserved `__`-prefixed parameter names included).
///
/// Ghidra's decompile/cpp never parses this table: the platform side loads the
/// signature data into the Program database and the locked `FuncProto` reaches
/// the decompiler already materialized (queried by `FlowInfo::queryCall`
/// flow.cc:660 and copied to call sites by `ActionDefaultParams`
/// coreaction.cc:2327). This table is Rugra's native front-end adapter for
/// that same boundary.
#[derive(Debug, Clone)]
pub struct LibcSignature {
    pub return_type: &'static str,
    pub parameters: &'static str,
}

/// Locked libc ABI signatures keyed by imported symbol name. Rugra's minimal
/// equivalent of Ghidra's generic_clib signature data: the same public glibc
/// ABI declarations verbatim. Anything not in the table keeps the unlocked
/// `void F(void)` form (matching the external-stub rendering).
#[derive(Debug, Clone)]
pub struct LibcSignatureTable {
    entries: HashMap<&'static str, LibcSignature>,
}

impl Default for LibcSignatureTable {
    // RUGRA-GLUE: Ghidra draws these from its shipped generic_clib signature
    // data on the platform side; Rugra encodes the same public glibc ABI
    // declarations verbatim (the 24 imports the locked curl input references)
    fn default() -> Self {
        let entries: Vec<(&'static str, &'static str, &'static str)> = vec![
            ("free", "void", "void *__ptr"),
            ("malloc", "void *", "size_t __size"),
            ("realloc", "void *", "void *__ptr,size_t __size"),
            ("memcpy", "void *", "void *__dest,void *__src,size_t __n"),
            ("strlen", "size_t", "char *__s"),
            ("strcpy", "char *", "char *__dest,char *__src"),
            ("strcat", "char *", "char *__dest,char *__src"),
            ("strdup", "char *", "char *__s"),
            ("strchr", "char *", "char *__s,int __c"),
            ("strrchr", "char *", "char *__s,int __c"),
            ("strstr", "char *", "char *__haystack,char *__needle"),
            ("strtol", "long", "char *__nptr,char **__endptr,int __base"),
            ("puts", "int", "char *__s"),
            ("isatty", "int", "int __fd"),
            ("fileno", "int", "FILE *__stream"),
            ("fclose", "int", "FILE *__stream"),
            ("fopen", "FILE *", "char *__filename,char *__modes"),
            ("fgets", "char *", "char *__s,int __n,FILE *__stream"),
            ("fputc", "int", "int __c,FILE *__stream"),
            (
                "fwrite", "size_t", "void *__ptr,size_t __size,size_t __n,FILE *__s",
            ),
            ("exit", "void", "int __status"),
            ("time", "time_t", "time_t *__timer"),
            (
                "__xstat", "int", "int __ver,char *__filename,stat *__stat_buf",
            ),
            ("__ctype_b_loc", "ushort **", ""),
        ];
        Self {
            entries: entries
                .into_iter()
                .map(|(name, return_type, parameters)| {
                    (
                        name,
                        LibcSignature {
                            return_type,
                            parameters,
                        },
                    )
                })
                .collect(),
        }
    }
}

impl LibcSignatureTable {
    // RUGRA-GLUE: bare-load constructor (RUGRA-FLOW-MIRROR-0001 M3). The
    // oracle single-function harness loads via BfdArchitecture +
    // readLoaderSymbols only — no Java analyzer, no generic_clib signature
    // data reaches the decompiler — so every lookup misses and call sites
    // keep their unlocked prototypes. Default construction stays the full
    // locked ledger.
    pub fn empty() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
        }
    }

    // RUGRA-GLUE: address of the Program-database signature lookup the decompiler performs via queryFunction
    pub fn lookup(&self, name: &str) -> Option<&LibcSignature> {
        self.entries.get(name)
    }

    /// Materialize the locked call-site `FuncProto` for an imported symbol,
    /// mirroring the decoded Program-database state handed to the decompiler:
    /// missing addresses are assigned through the UnknownProtoModel's cloned
    /// default resources (`ProtoStoreInternal::decode`, fspec.cc:3533-3541),
    /// source markup is restored, and input/output type locks are retained.
    /// The call site receives a copy through `ActionDefaultParams`
    /// (coreaction.cc:2327).
    ///
    /// Returns `Ok(None)` when the symbol has no locked signature (unknown
    /// import: stays unlocked, active recovery decides) and `Err` when the
    /// bound compiler model cannot assign the requested prototype. Scalar
    /// stack spill is represented by that model; aggregate/ModelRule paths
    /// remain outside the current bilateral fixture.
    // RUGRA-GLUE: generic-clib Program-database adapter; storage/markup state follows ProtoStoreInternal::decode (fspec.cc:3464-3567)
    /// Resolve the platform-side locked signature for an imported callee.
    /// `type_names` is the DWARF named-type index (`parse_type_names`): a
    /// signature base spelling that names a DWARF-known type resolves to that
    /// concrete type — the same name resolution Ghidra's signature loader
    /// performs against the program's type manager, where `FILE *` is a
    /// pointer to the real glibc `FILE` struct rather than an opaque unknown.
    /// Without it, an unknown-based `FILE *` loses the typeOrder competition
    /// against `char *` (SUB_PTR vs SUB_PTR, then pointee char vs unknown)
    /// and the decompiler's inferred `char *` overwrites the locked libc
    /// return type.
    pub fn locked_proto(
        &self,
        name: &str,
        model_carrier: &FuncProto,
        type_names: Option<&HashMap<String, Arc<Datatype>>>,
    ) -> Result<Option<FuncProto>> {
        let Some(signature) = self.lookup(name) else {
            return Ok(None);
        };
        let address_size = 8usize;
        let return_type = parse_c_type(signature.return_type, address_size, type_names)?;
        let mut parameters = Vec::new();
        for declaration in split_parameter_list(signature.parameters) {
            let (type_text, parameter_name) = split_declaration(declaration)?;
            parameters.push(DebugParameter {
                name: parameter_name.to_string(),
                name_locked: true,
                data_type: parse_c_type(type_text, address_size, type_names)?,
            });
        }
        if !model_carrier.has_model() {
            bail!("libc prototype {name} has no bound ProtoModel");
        }
        let pieces = crate::grammar::PrototypePieces {
            model: None,
            name: name.to_string(),
            out_type: Some(return_type),
            in_types: parameters
                .iter()
                .map(|parameter| parameter.data_type.clone())
                .collect(),
            in_names: parameters
                .iter()
                .map(|parameter| parameter.name.clone())
                .collect(),
            first_var_arg_slot: -1,
        };
        let mut proto = FuncProto::from_model_carrier(
            model_carrier,
            name.to_string(),
            pieces
                .out_type
                .clone()
                .expect("libc prototype always has output type"),
        );
        proto.name = name.to_string();
        proto.update_all_types_from_pieces(&pieces);
        if proto.has_input_errors() {
            bail!("compiler model cannot assign parameter storage for libc prototype {name}");
        }
        for param in &mut proto.parameters {
            // fspec.cc:3503-3506: the platform-side signature decode reads
            // ATTRIB_NAMELOCK into ParameterPieces::namelock, and
            // fspec.cc:3564 propagates it via curparam->setNameLock(). Every
            // parameter of a locked generic_clib signature carries a real
            // glibc reserved name (split_declaration rejects nameless
            // declarations), so each is name-locked here — the bit
            // ActionNameVars::lookForFuncParamNames gates on
            // (coreaction.cc:2818 param->isNameLocked()).
            param.flags |= crate::fspec::protoparam_flags::NAME_LOCKED;
        }
        proto.set_input_lock(true);
        proto.set_output_lock(true);
        proto.set_model_lock(true);
        Ok(Some(proto))
    }
}

// RUGRA-GLUE: splits the comma-separated parameter declaration list the signature data carries; an empty list is a void parameter list
fn split_parameter_list(parameters: &str) -> impl Iterator<Item = &str> {
    parameters
        .split(',')
        .map(str::trim)
        .filter(|declaration| !declaration.is_empty())
}

// RUGRA-GLUE: splits one "TYPE NAME" parameter declaration; the trailing
// identifier run is the name, everything before it (spaces and pointer stars
// included, e.g. "void *__ptr") is the type text
fn split_declaration(declaration: &str) -> Result<(&str, &str)> {
    let trimmed = declaration.trim();
    let name_start = trimmed
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map(|pos| pos + 1)
        .unwrap_or(0);
    let (type_text, name) = trimmed.split_at(name_start);
    if name.is_empty() {
        bail!("signature parameter declaration has no name: {declaration:?}");
    }
    let type_text = type_text.trim();
    if type_text.is_empty() {
        bail!("signature parameter declaration has no type: {declaration:?}");
    }
    Ok((type_text, name))
}

// RUGRA-GLUE: parses the signature data's C type spellings into Datatypes; only the metatype/size-bearing forms the 24-entry public libc ABI uses (void, char, int, long, size_t, time_t, ushort and pointer layers). A base spelling that names a DWARF-known type (FILE, stat) resolves to that concrete type through `type_names` — the same type-manager name resolution Ghidra's signature loader performs — and only falls back to an address-sized unknown base when the name is unknown
fn parse_c_type(
    type_text: &str,
    address_size: usize,
    type_names: Option<&HashMap<String, Arc<Datatype>>>,
) -> Result<Arc<Datatype>> {
    let (base_text, pointer_depth) = split_pointer_depth(type_text);
    let mut datatype = match base_text {
        "void" => Arc::new(Datatype::Void(TypeBase::new(
            "void".to_string(),
            0,
            TypeMetatype::Void,
        ))),
        // The generic_clib Program-database type named `char` is Ghidra's
        // character datatype, not a same-sized plain integer.  The C++
        // decompiler receives it as TypeChar (type.hh:348-357), whose
        // `chartype` flag drives PrintC::pushConstant.
        "char" => Arc::new(Datatype::Base(TypeBase::new_char(
            "char".to_string(),
            TypeMetatype::Int,
        ))),
        "int" => Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(),
            4,
            TypeMetatype::Int,
        ))),
        "long" => Arc::new(Datatype::Base(TypeBase::new(
            "long".to_string(),
            address_size,
            TypeMetatype::Int,
        ))),
        "size_t" | "time_t" => Arc::new(Datatype::Base(TypeBase::new(
            base_text.to_string(),
            address_size,
            TypeMetatype::Uint,
        ))),
        "ushort" => Arc::new(Datatype::Base(TypeBase::new(
            "ushort".to_string(),
            2,
            TypeMetatype::Uint,
        ))),
        other => type_names
            .and_then(|index| index.get(other))
            .cloned()
            .unwrap_or_else(|| {
                Arc::new(Datatype::Base(TypeBase::new(
                    other.to_string(),
                    address_size,
                    TypeMetatype::Unknown,
                )))
            }),
    };
    for _ in 0..pointer_depth {
        // Ghidra builds parsed declarator pointers through
        // PointerModifier::modType -> glb->types->getTypePointer(addrsize,
        // base, wordsize) (grammar.cc:2403-2411), whose 3-arg overload
        // leaves the name EMPTY (type.cc:3867-3875) — the "char *" spelling
        // is syntax, not type identity, so the signature-parsed pointers
        // stay anonymous and PrintC renders them through the drilled
        // multi-layer form (`char *pcVar1`), matching the golden output.
        // The former composed display names ("char *"/"char **") made these
        // NAMED single-layer pointers and printed `char * pcVar1` (oracle
        // printc_anonymous_pointer_decl_1204 named_ptr_contrast).
        datatype = Arc::new(Datatype::Pointer(TypePointer::new(
            address_size,
            datatype,
            1,
        )));
    }
    Ok(datatype)
}

// RUGRA-GLUE: separates trailing pointer stars from the base type name in a C type spelling
fn split_pointer_depth(type_text: &str) -> (&str, usize) {
    let trimmed = type_text.trim();
    // Strip one trailing '*' at a time, along with any spaces before it, so
    // every spacing form ("char **", "char**", "char * *") reduces to the
    // same base + depth. The old `trim_end_matches(" *")` could not strip a
    // second star ("char **" does not END with the two-char pattern " *"),
    // so double pointers fell through to the unknown-name base arm and
    // produced Base("char **", TYPE_UNKNOWN) instead of a structural
    // Pointer-to-Pointer.
    let bytes = trimmed.as_bytes();
    let mut end = bytes.len();
    let mut depth = 0usize;
    while end > 0 && bytes[end - 1] == b'*' {
        depth += 1;
        end -= 1;
        while end > 0 && bytes[end - 1] == b' ' {
            end -= 1;
        }
    }
    (trimmed[..end].trim(), depth)
}


// RUGRA-GLUE: resolves a concrete function entry address from a DWARF DIE before handing the prototype to Funcdata
fn subprogram_address(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
) -> Result<Option<u64>> {
    if let Some(value) = entry.attr_value(gimli::DW_AT_low_pc)? {
        if let Some(address) = dwarf.attr_address(unit, value)? {
            return Ok(Some(address));
        }
    }
    let mut ranges = dwarf.die_ranges(unit, entry)?;
    Ok(ranges.next()?.map(|range| range.begin))
}

// RUGRA-GLUE: follows DWARF declaration inheritance so optimized definitions consume the same source prototype Ghidra imports into its Program database
fn canonical_subprogram_offset(
    unit: &Unit<DwarfReader>,
    mut offset: UnitOffset<usize>,
) -> Result<UnitOffset<usize>> {
    for _ in 0..32 {
        let entry = unit.entry(offset)?;
        let next = entry_reference(unit, &entry, gimli::DW_AT_abstract_origin)?
            .or(entry_reference(unit, &entry, gimli::DW_AT_specification)?);
        let Some(next) = next else {
            return Ok(offset);
        };
        offset = next;
    }
    bail!("DWARF abstract-origin/specification chain exceeds 32 entries")
}

// RUGRA-GLUE: extracts canonical direct formal-parameter children in DIE order, which is the declaration order preserved by Ghidra's imported prototype
fn read_prototype_children(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
) -> Result<(Vec<DebugParameter>, bool)> {
    let mut cursor = unit.entries_at_offset(offset)?;
    let mut first = true;
    let mut depth = 0isize;
    let mut parameters = Vec::new();
    let mut is_varargs = false;
    while let Some((delta, entry)) = cursor.next_dfs()? {
        if first {
            first = false;
            continue;
        }
        depth += delta;
        if depth <= 0 {
            break;
        }
        if depth != 1 {
            continue;
        }
        if entry.tag() == gimli::DW_TAG_unspecified_parameters {
            is_varargs = true;
            continue;
        }
        if entry.tag() != gimli::DW_TAG_formal_parameter {
            continue;
        }
        let canonical = canonical_parameter_offset(unit, entry.offset())?;
        let canonical_entry = unit.entry(canonical)?;
        let source_name = entry_string(dwarf, unit, &canonical_entry, gimli::DW_AT_name)?;
        let name_locked = source_name.is_some();
        let name = source_name
            .unwrap_or_else(|| format!("param_{}", parameters.len() + 1));
        let data_type = match entry_reference(unit, &canonical_entry, gimli::DW_AT_type)? {
            Some(type_offset) => resolve_type(dwarf, unit, type_offset, 0, &mut Vec::new())?,
            None => unknown_type(unit.encoding().address_size as usize),
        };
        parameters.push(DebugParameter { name, name_locked, data_type ,
        });
    }
    Ok((parameters, is_varargs))
}

// RUGRA-GLUE: follows optimized formal-parameter abstract origins to recover declaration name/type before FuncProto construction
fn canonical_parameter_offset(
    unit: &Unit<DwarfReader>,
    mut offset: UnitOffset<usize>,
) -> Result<UnitOffset<usize>> {
    for _ in 0..32 {
        let entry = unit.entry(offset)?;
        let Some(next) = entry_reference(unit, &entry, gimli::DW_AT_abstract_origin)? else {
            return Ok(offset);
        };
        offset = next;
    }
    bail!("DWARF formal-parameter abstract-origin chain exceeds 32 entries")
}

// RUGRA-GLUE: converts a DWARF string attribute into owned front-end state; Ghidra's Program database similarly outlives the DIE reader
fn entry_string(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
    name: gimli::DwAt,
) -> Result<Option<String>> {
    let Some(value) = entry.attr_value(name)? else {
        return Ok(None);
    };
    let reader = dwarf.attr_string(unit, value)?;
    Ok(Some(reader.to_string_lossy()?.into_owned()))
}

// RUGRA-GLUE: normalizes unit-relative and same-unit debug-info references for the native DWARF importer
fn entry_reference(
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
    name: gimli::DwAt,
) -> Result<Option<UnitOffset<usize>>> {
    let Some(value) = entry.attr_value(name)? else {
        return Ok(None);
    };
    Ok(match value {
        AttributeValue::UnitRef(offset) => Some(offset),
        AttributeValue::DebugInfoRef(offset) => offset.to_unit_offset(&unit.header),
        _ => None,
    })
}

// RUGRA-GLUE: materializes the DWARF type graph into Rugra Datatype objects at the Program-import boundary; Ghidra performs this in its DWARF/type-manager front end. `visiting` holds the DIE offsets currently being resolved so recursive types (FILE -> struct _IO_FILE -> _chain FILE *) break at the back edge with a shallow named projection, the same way Ghidra's two-phase type manager exposes an already-created type before its members are filled in
fn resolve_type(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
    depth: usize,
    visiting: &mut Vec<UnitOffset<usize>>,
) -> Result<Arc<Datatype>> {
    if depth >= 64 {
        bail!("DWARF type chain exceeds 64 entries")
    }
    if visiting.contains(&offset) {
        let entry = unit.entry(offset)?;
        return shallow_type(dwarf, unit, &entry, offset);
    }
    visiting.push(offset);
    let resolved = resolve_type_inner(dwarf, unit, offset, depth, visiting);
    visiting.pop();
    resolved
}

// RUGRA-GLUE: the field/chain-resolving half of resolve_type, entered with the DIE already pushed on the visiting stack
fn resolve_type_inner(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
    depth: usize,
    visiting: &mut Vec<UnitOffset<usize>>,
) -> Result<Arc<Datatype>> {
    let entry = unit.entry(offset)?;
    let size = entry
        .attr_value(gimli::DW_AT_byte_size)?
        .and_then(|value| value.udata_value())
        .map(|value| value as usize);
    let name = entry_string(dwarf, unit, &entry, gimli::DW_AT_name)?;
    let referenced = entry_reference(unit, &entry, gimli::DW_AT_type)?;
    match entry.tag() {
        gimli::DW_TAG_base_type => dwarf_base_type(
                name.unwrap_or_else(|| "int".to_string()),
                size.unwrap_or(4),
                &entry,
        ),
        gimli::DW_TAG_pointer_type
        | gimli::DW_TAG_reference_type
        | gimli::DW_TAG_rvalue_reference_type => {
            let pointee = match referenced {
                Some(inner) => resolve_type(dwarf, unit, inner, depth + 1, visiting)?,
                None => void_type(),
            };
            Ok(pointer_type(
                pointee,
                size.unwrap_or(unit.encoding().address_size as usize),
            ))
        }
        gimli::DW_TAG_typedef => {
            let inner = match referenced {
                Some(inner) => resolve_type(dwarf, unit, inner, depth + 1, visiting)?,
                None => unknown_type(size.unwrap_or(unit.encoding().address_size as usize)),
            };
            match name {
                // A typedef over a composite/enum keeps its fields and named
                // values under the typedef spelling (this is how the type
                // renders in decompiled C). Rugra's Datatype enum has no
                // TypeTypedef variant yet, so the typedef is materialized as
                // the renamed underlying type.
                Some(name) => materialized_alias(name, &inner),
                None => Ok(inner),
            }
        }
        gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type => {
            let inner = match referenced {
                Some(inner) => resolve_type(dwarf, unit, inner, depth + 1, visiting)?,
                None => unknown_type(size.unwrap_or(1)),
            };
            let qualifier = if entry.tag() == gimli::DW_TAG_const_type {
                "const"
            } else if entry.tag() == gimli::DW_TAG_volatile_type {
                "volatile"
            } else {
                "restrict"
            };
            Ok(alias_type(
                format!("{qualifier} {}", inner.get_name()),
                inner.as_ref(),
            ))
        }
        gimli::DW_TAG_structure_type => {
            let fields = read_composite_fields(dwarf, unit, offset, depth, visiting)?;
            let type_name = name.unwrap_or_else(|| format!("struct_{:x}", offset.0));
            Ok(struct_type(type_name, size.unwrap_or(0), fields))
        }
        gimli::DW_TAG_union_type => {
            let fields = read_composite_fields(dwarf, unit, offset, depth, visiting)?;
            let type_name = name.unwrap_or_else(|| format!("union_{:x}", offset.0));
            Ok(union_type(type_name, size.unwrap_or(0), fields))
        }
        gimli::DW_TAG_enumeration_type => {
            let values = read_enumerators(dwarf, unit, offset)?;
            let type_name = name.unwrap_or_else(|| format!("enum_{:x}", offset.0));
            Ok(enum_type(type_name, size.unwrap_or(4), values))
        }
        gimli::DW_TAG_array_type => {
            let element = match referenced {
                Some(inner) => resolve_type(dwarf, unit, inner, depth + 1, visiting)?,
                None => unknown_type(1),
            };
            let count = read_array_count(unit, offset)?;
            let array_size = element.get_size().saturating_mul(count);
            // Ghidra's DWARF array import runs through
            // TypeFactory::getTypeArray (type.cc:3902), whose inline
            // `TypeArray` ctor leaves the name EMPTY — array identity is
            // structural (element type + count), the composed spelling was
            // diagnostic-only.
            Ok(Arc::new(Datatype::Array(TypeArray {
                base: TypeBase::new(String::new(), array_size, TypeMetatype::Array),
                array_of: element,
                num_elements: count,
            })))
        }
        gimli::DW_TAG_unspecified_type => Ok(void_type()),
        _ => {
            if let Some(inner) = referenced {
                resolve_type(dwarf, unit, inner, depth + 1, visiting)
            } else {
                Ok(unknown_type(
                    size.unwrap_or(unit.encoding().address_size as usize),
                ))
            }
        }
    }
}

// RUGRA-GLUE: shallow projection of a type DIE that is already being resolved higher in the chain: the type's name/size/metatype without fields or nested chains, breaking recursive type graphs the way Ghidra's two-phase type creation does
fn shallow_type(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
    offset: UnitOffset<usize>,
) -> Result<Arc<Datatype>> {
    let address_size = unit.encoding().address_size as usize;
    let size = entry
        .attr_value(gimli::DW_AT_byte_size)?
        .and_then(|value| value.udata_value())
        .map(|value| value as usize);
    match entry.tag() {
        gimli::DW_TAG_base_type => dwarf_base_type(
            entry_string(dwarf, unit, entry, gimli::DW_AT_name)?
                .unwrap_or_else(|| "int".to_string()),
            size.unwrap_or(4),
            entry,
        ),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => Ok(base_type(
            format!("struct_{:x}", offset.0),
            size.unwrap_or(0),
            TypeMetatype::Struct,
        )),
        gimli::DW_TAG_union_type => Ok(base_type(
            format!("union_{:x}", offset.0),
            size.unwrap_or(0),
            TypeMetatype::Union,
        )),
        gimli::DW_TAG_enumeration_type => Ok(base_type(
            format!("enum_{:x}", offset.0),
            size.unwrap_or(4),
            TypeMetatype::Enum,
        )),
        gimli::DW_TAG_pointer_type
        | gimli::DW_TAG_reference_type
        | gimli::DW_TAG_rvalue_reference_type => {
            Ok(pointer_type(void_type(), size.unwrap_or(address_size)))
        }
        _ => {
            // Typedefs and qualifiers keep their own spelling over the
            // target's shallow size/metatype (attributes only, no chain
            // recursion), matching the flattened alias this importer
            // produced before field materialization existed (a recursive
            // `FILE` still renders as `FILE *`).
            let qualifier = match entry.tag() {
                gimli::DW_TAG_const_type => Some("const"),
                gimli::DW_TAG_volatile_type => Some("volatile"),
                gimli::DW_TAG_restrict_type => Some("restrict"),
                _ => None,
            };
            let target = entry_reference(unit, entry, gimli::DW_AT_type)?
                .map(|target| unit.entry(target))
                .transpose()?;
            let (target_name, target_size, metatype) = match &target {
                Some(target_entry) => {
                    let target_size = target_entry
                        .attr_value(gimli::DW_AT_byte_size)?
                        .and_then(|value| value.udata_value())
                        .map(|value| value as usize);
                    let metatype = match target_entry.tag() {
                        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
                            TypeMetatype::Struct
                        }
                        gimli::DW_TAG_union_type => TypeMetatype::Union,
                        gimli::DW_TAG_enumeration_type => TypeMetatype::Enum,
                        _ => TypeMetatype::Unknown,
                    };
                    (
                        entry_string(dwarf, unit, target_entry, gimli::DW_AT_name)?,
                        target_size,
                        metatype,
                    )
                }
                None => (None, None, TypeMetatype::Unknown),
            };
            let own_name = entry_string(dwarf, unit, entry, gimli::DW_AT_name)?;
            let base_name = own_name
                .or(target_name)
                .unwrap_or_else(|| format!("_{:x}", offset.0));
            let display = match qualifier {
                Some(qualifier) => format!("{qualifier} {base_name}"),
                None => base_name,
            };
            Ok(base_type(
                display,
                target_size
                    .or(size)
                    .unwrap_or(address_size),
                metatype,
            ))
        }
    }
}

// RUGRA-GLUE: maps DW_AT_encoding to the Rugra metatype the base-type importer assigns
fn base_metatype(entry: &DebuggingInformationEntry<DwarfReader>) -> Result<TypeMetatype> {
    let encoding = entry.attr_value(gimli::DW_AT_encoding)?;
    Ok(match encoding {
        Some(AttributeValue::Encoding(value))
            if value == gimli::DW_ATE_float || value == gimli::DW_ATE_complex_float =>
        {
            TypeMetatype::Float
        }
        Some(AttributeValue::Encoding(value))
            if value == gimli::DW_ATE_unsigned
                || value == gimli::DW_ATE_unsigned_char
                || value == gimli::DW_ATE_address =>
        {
            TypeMetatype::Uint
        }
        Some(AttributeValue::Encoding(value)) if value == gimli::DW_ATE_boolean => {
            TypeMetatype::Bool
        }
        _ => TypeMetatype::Int,
    })
}

// RUGRA-GLUE: materializes the Program database base type selected by the
// locked Ghidra DWARF analyzer before the C++ decompiler receives it.
fn dwarf_base_type(
    name: String,
    size: usize,
    entry: &DebuggingInformationEntry<DwarfReader>,
) -> Result<Arc<Datatype>> {
    let encoding = entry.attr_value(gimli::DW_AT_encoding)?;
    let metatype = base_metatype(entry)?;
    let is_signed_character_encoding = matches!(
        encoding,
        Some(AttributeValue::Encoding(value))
            if value == gimli::DW_ATE_signed_char
    );
    // DWARFDataTypeManager::getBaseType resolves the core names `char` and
    // `signed char` to CharDataType before its encoding fallback.  Its
    // DW_ATE_signed_char fallback is also CharDataType, whereas
    // DW_ATE_unsigned_char resolves to the ordinary unsigned `uchar` type.
    let is_direct_character_name = size == 1 && matches!(name.as_str(), "char" | "signed char");
    if is_direct_character_name || is_signed_character_encoding {
        let resolved_name = if is_direct_character_name {
            "char".to_string()
        } else {
            name
        };
        return Ok(Arc::new(Datatype::Base(TypeBase::new_char(
            resolved_name,
            TypeMetatype::Int,
        ))));
    }
    Ok(base_type(name, size, metatype))
}

// RUGRA-GLUE: reads direct DW_TAG_member children (DIE order = declaration order), resolving each member's DW_AT_type and DW_AT_data_member_location exactly as Ghidra's DWARF analyzer builds composite fields
fn read_composite_fields(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
    depth: usize,
    visiting: &mut Vec<UnitOffset<usize>>,
) -> Result<Vec<TypeField>> {
    let mut cursor = unit.entries_at_offset(offset)?;
    let mut first = true;
    let mut walk_depth = 0isize;
    let mut fields = Vec::new();
    while let Some((delta, entry)) = cursor.next_dfs()? {
        if first {
            first = false;
            continue;
        }
        walk_depth += delta;
        if walk_depth <= 0 {
            break;
        }
        if walk_depth != 1 {
            continue;
        }
        if entry.tag() != gimli::DW_TAG_member {
            continue;
        }
        let Some(name) = entry_string(dwarf, unit, entry, gimli::DW_AT_name)? else {
            continue;
        };
        let member_offset = member_location(unit, entry)?;
        let Some(type_reference) = entry_reference(unit, entry, gimli::DW_AT_type)? else {
            continue;
        };
        let data_type = resolve_type(dwarf, unit, type_reference, depth + 1, visiting)?;
        fields.push(TypeField {
            name,
            offset: member_offset,
            type_ptr: data_type,
        });
    }
    Ok(fields)
}

// RUGRA-GLUE: decodes DW_AT_data_member_location in the two forms producers emit for composites — a plain constant and DW_OP_plus_uconst — rejecting anything else fail-visibly
fn member_location(
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
) -> Result<usize> {
    let Some(value) = entry.attr_value(gimli::DW_AT_data_member_location)? else {
        return Ok(0);
    };
    match value {
        AttributeValue::Udata(value) => Ok(value as usize),
        AttributeValue::Exprloc(ref expression) => {
            let mut operations = expression.clone().operations(unit.encoding());
            let resolved = match operations.next()? {
                Some(gimli::Operation::PlusConstant { value }) => usize::try_from(value).ok(),
                _ => None,
            };
            let complete = resolved.is_some() && operations.next()?.is_none();
            match (resolved, complete) {
                (Some(offset), true) => Ok(offset),
                _ => bail!("unsupported DW_AT_data_member_location expression"),
            }
        }
        _ => bail!("unsupported DW_AT_data_member_location form"),
    }
}

// RUGRA-GLUE: reads direct DW_TAG_enumerator children into the value→name table Ghidra keeps on its enum data types for constant-name rendering
fn read_enumerators(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
) -> Result<BTreeMap<u64, String>> {
    let mut cursor = unit.entries_at_offset(offset)?;
    let mut first = true;
    let mut walk_depth = 0isize;
    let mut values = BTreeMap::new();
    while let Some((delta, entry)) = cursor.next_dfs()? {
        if first {
            first = false;
            continue;
        }
        walk_depth += delta;
        if walk_depth <= 0 {
            break;
        }
        if walk_depth != 1 {
            continue;
        }
        if entry.tag() != gimli::DW_TAG_enumerator {
            continue;
        }
        let Some(name) = entry_string(dwarf, unit, entry, gimli::DW_AT_name)? else {
            continue;
        };
        let Some(value) = entry
            .attr_value(gimli::DW_AT_const_value)?
            .and_then(|value| value.udata_value())
        else {
            continue;
        };
        values.insert(value, name);
    }
    Ok(values)
}

// RUGRA-GLUE: reads the first DW_TAG_subrange child's element count (DW_AT_count, or DW_AT_upper_bound+1) which is the array length Ghidra's DWARF analyzer assigns
fn read_array_count(unit: &Unit<DwarfReader>, offset: UnitOffset<usize>) -> Result<usize> {
    let mut cursor = unit.entries_at_offset(offset)?;
    let mut first = true;
    let mut walk_depth = 0isize;
    for _ in 0..64 {
        let Some((delta, entry)) = cursor.next_dfs()? else {
            break;
        };
        if first {
            first = false;
            continue;
        }
        walk_depth += delta;
        if walk_depth <= 0 {
            break;
        }
        if walk_depth != 1 {
            continue;
        }
        if entry.tag() == gimli::DW_TAG_subrange_type {
            if let Some(value) = entry.attr_value(gimli::DW_AT_count)? {
                if let Some(count) = value.udata_value() {
                    return Ok(count as usize);
                }
            }
            if let Some(value) = entry.attr_value(gimli::DW_AT_upper_bound)? {
                if let Some(upper) = value.udata_value() {
                    return Ok(upper as usize + 1);
                }
            }
            return Ok(0);
        }
    }
    Ok(0)
}

// RUGRA-GLUE: constructs a leaf Datatype from front-end debug metadata before it enters Ghidra-aligned type analysis
fn base_type(name: String, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    intern_named(Arc::new(Datatype::Base(TypeBase::new(name, size, metatype))))
}

// RUGRA-GLUE: constructs a fielded struct Datatype from DWARF DW_TAG_member children; Ghidra builds the equivalent Structure dataType in its DWARF/type-manager front end
fn struct_type(name: String, size: usize, fields: Vec<TypeField>) -> Arc<Datatype> {
    intern_named(Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new(name, size, TypeMetatype::Struct),
        fields,
    })))
}

// RUGRA-GLUE: constructs a fielded union Datatype from DWARF union members (all at offset 0)
fn union_type(name: String, size: usize, fields: Vec<TypeField>) -> Arc<Datatype> {
    intern_named(Arc::new(Datatype::Union(TypeUnion {
        base: TypeBase::new(name, size, TypeMetatype::Union),
        fields,
    })))
}

// RUGRA-GLUE: constructs an enum Datatype with its DWARF enumerator value table for constant-name rendering
fn enum_type(name: String, size: usize, values: BTreeMap<u64, String>) -> Arc<Datatype> {
    intern_named(Arc::new(Datatype::Enum(TypeEnum {
        base: TypeBase::new(name, size, TypeMetatype::Enum),
        values,
    })))
}

// RUGRA-GLUE: DWARF-import type-manager canonicalization. Ghidra's DWARF
// analyzer resolves every DIE type through the Architecture's ONE
// TypeFactory (type.cc findByName/setName interning), so the same-named
// structure reached from two variables — or from both the globals pass
// (DebugGlobalDatabase) and the prototype pass (DebugPrototypeDatabase) —
// is ONE interned Datatype object, and pointer-identity comparisons
// (CastStrategyC::castStandard's `curtype == reqtype`, cast.cc:299;
// ActionSetCasts' store-value cast, coreaction.cc:553-554) see equal types
// and emit no cast. Rugra's two independent DWARF passes each built fresh
// Arcs, so `*glob = glob_expand;` (URLGlob** param vs typelocked URLGlob*
// global read) gained a spurious `(URLGlob *)` cast. This soft intern
// reuses the shared factory's existing name entry when the shape (enum
// variant), size, and metatype match — the shape guard keeps a cycle-break
// shallow projection (base_type with a composite metatype) from shadowing
// the full fielded definition of the same DWARF name — and registers the
// new type otherwise. This is the cross-parse identity half of the importer
// boundary noted as untracked on alias_type.
fn intern_named(candidate: Arc<Datatype>) -> Arc<Datatype> {
    let name = candidate.get_name().to_string();
    if name.is_empty() {
        return candidate;
    }
    let factory = crate::type_system::typefactory::TypeFactory::shared_default();
    let mut guard = factory.write().unwrap();
    if let Some(existing) = guard.find_by_name(&name) {
        let same_shape = std::mem::discriminant(existing.as_ref())
            == std::mem::discriminant(candidate.as_ref());
        if same_shape
            && existing.get_size() == candidate.get_size()
            && existing.get_metatype() == candidate.get_metatype()
        {
            return existing;
        }
        // Same name, different shape/size (shallow cycle-break projection
        // vs the full definition, or a genuine DWARF redefinition): keep the
        // fresh candidate without touching the registered slot.
        return candidate;
    }
    match guard.intern_imported((*candidate).clone()) {
        Ok(interned) => interned,
        Err(_) => candidate,
    }
}

// RUGRA-GLUE: materializes a DWARF typedef as the underlying composite/enum renamed to the typedef spelling; Rugra's Datatype enum has no TypeTypedef variant yet (Ghidra type.hh has one), so fields and enumerator names are carried on the renamed type
fn materialized_alias(name: String, inner: &Datatype) -> Result<Arc<Datatype>> {
    Ok(alias_type(name, inner ))
}

// RUGRA-GLUE: preserves a DWARF typedef/qualifier spelling by cloning the
// resolved concrete datatype and changing only its name/id/core flag, matching
// the shape/flag-preserving clone portion of TypeFactory::getTypedef
// (type.cc:3818-3840). This retains TypeChar's chartype/submeta state and the
// full pointer/array/composite shape. Architecture-owned canonical insertion
// remains a separately tracked importer boundary.
fn alias_type(name: String, inner: &Datatype) -> Arc<Datatype> {
    let mut alias = inner.clone();
    let base = alias.base_record_mut();
    base.name = name.clone();
    base.display_name = name.clone();
    base.id = Datatype::hash_name(&name);
    base.flags &= !crate::type_system::datatype::type_flags::CORETYPE;
    intern_named(Arc::new(alias))
}

// RUGRA-GLUE: constructs a pointer Datatype from a resolved DWARF pointee at the native debug-import boundary
fn pointer_type(pointee: Arc<Datatype>, size: usize) -> Arc<Datatype> {
    // Ghidra builds DWARF pointer types anonymously (the TypeFactory 3-arg
    // getTypePointer path, type.cc:3867-3875 — DW_AT_name on a pointer
    // typedef attaches via alias_type, not here); see parse_c_type's note
    // for why the former composed display name diverged from the oracle.
    // The factory pass below canonicalizes pointer identity the way the
    // oracle's single TypeFactory does for every DWARF type.
    crate::type_system::typefactory::TypeFactory::shared_default()
        .write()
        .unwrap()
        .get_type_pointer(size, pointee, 1)
}

// RUGRA-GLUE: canonical locked-void type used when DW_AT_type is absent on a subprogram or pointer target
fn void_type() -> Arc<Datatype> {
    Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )))
}

// RUGRA-GLUE: fail-visible unknown DWARF type used only when a DIE omits a resolvable type reference
fn unknown_type(size: usize) -> Arc<Datatype> {
    base_type(format!("undefined{size}"), size, TypeMetatype::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;

    // Test-only drill: the spelling of the base type a (possibly nested)
    // anonymous pointer chain points at — the identity the composed name
    // used to carry before the anonymous-pointer alignment.
    trait PtrDrillBaseName {
        fn ptr_drill_base_name(&self) -> String;
    }
    impl PtrDrillBaseName for Arc<Datatype> {
        fn ptr_drill_base_name(&self) -> String {
            let mut cur = self.as_ref();
            while let Datatype::Pointer(p) = cur {
                cur = p.ptr_to.as_ref();
            }
            cur.get_name().to_string()
        }
    }

    struct TestSpecHost {
        registers: BTreeMap<String, crate::fspec::VarnodeData>,
    }

    impl crate::arch::SpecQuery for TestSpecHost {
        fn get_register(&self, name: &str) -> Option<crate::fspec::VarnodeData> {
            self.registers.get(name).copied()
        }

        fn space_by_name(&self, name: &str) -> Option<crate::space::AddressSpace> {
            use crate::space::AddressSpace;
            match name {
                "ram" => Some(AddressSpace::Ram),
                "stack" => Some(AddressSpace::Stack),
                "register" => Some(AddressSpace::Register),
                "OTHER" | "other" => Some(AddressSpace::Other(1)),
                "unique" => Some(AddressSpace::Unique),
                "const" => Some(AddressSpace::Const),
                _ => None,
            }
        }

        fn space_highest(&self, space: crate::space::AddressSpace) -> u64 {
            match space {
                crate::space::AddressSpace::Unique
                | crate::space::AddressSpace::Register
                | crate::space::AddressSpace::Join => 0xffff_ffff,
                _ => u64::MAX,
            }
        }

        fn unique_inject_base(&self) -> u64 {
            0x364_400
        }
    }

    impl crate::pcodeparse::SleighSymbolLookup for TestSpecHost {
        fn find_symbol(&self, name: &str) -> Option<crate::pcodeparse::SleighSymbol> {
            self.registers
                .get(name)
                .map(|data| crate::pcodeparse::SleighSymbol {
                name: name.to_string(),
                kind: crate::pcodeparse::SleightSymbolKind::Varnode(
                    crate::varnode::VarnodeData {
                        space: data.space,
                        offset: data.offset,
                        size: data.size.max(0) as usize,
                    },
                ),
            })
        }
    }

    fn model_carrier() -> FuncProto {
        let cspec = std::fs::read("sleigh_specs/x86-64-gcc.cspec")
            .expect("locked x86-64 gcc compiler spec");
        let mut store = crate::marshal::DocumentStorage::new();
        let document = store.parse_document(&cspec).expect("parse compiler spec");
        let root = document.root.clone().expect("compiler spec root");
        store.register_tag(&root);

        let sleigh = crate::sleigh_ffi::SleighCtx::new().expect("SLEIGH register catalog");
        let mut registers = BTreeMap::new();
        for index in 0..sleigh.num_registers() {
            let Some((name, space, offset, size)) = sleigh.register_info(index) else {
                continue;
            };
            let Ok(space_id) = u8::try_from(space) else {
                continue;
            };
            registers.insert(
                name,
                crate::fspec::VarnodeData {
                    space: crate::space::AddressSpace::from_id(space_id),
                    offset,
                    size,
                },
            );
        }
        let host = Arc::new(TestSpecHost { registers });
        let mut arch = crate::arch::Architecture::new();
        arch.archid = "x86:LE:64:default".to_string();
        let mut inject = crate::pcodeinject::PcodeInjectLibrary::new(0x364_400);
        inject.set_sleigh_lookup(host.clone());
        arch.pcodeinjectlib = Some(Arc::new(std::sync::RwLock::new(inject)));
        let mut userops = crate::userop::UserOpManage::new();
        userops.register_op(
            "segment".to_string(),
            crate::userop::UserOpType::Unspecialized,
        );
        arch.userops = Some(Arc::new(std::sync::RwLock::new(userops)));
        arch.parse_compiler_config(&mut store, host.as_ref(), 8)
            .expect("decode default ProtoModel");
        let mut carrier = FuncProto::new("carrier".to_string(), void_type());
        carrier.set_model(Some(
            arch.defaultfp
                .clone()
                .expect("default x86-64 gcc ProtoModel"),
        ));
        carrier
    }

    #[test]
    fn libc_signature_table_covers_the_24_locked_imports() {
        let table = LibcSignatureTable::default();
        for name in [
            "free", "malloc", "realloc", "memcpy", "strlen", "strcpy", "strcat", "strdup",
            "strchr", "strrchr", "strstr", "strtol", "puts", "isatty", "fileno", "fclose",
            "fopen", "fgets", "fputc", "fwrite", "exit", "time", "__xstat", "__ctype_b_loc",
        ] {
            assert!(table.lookup(name).is_some(), "missing signature for {name}");
        }
        assert!(table.lookup("not_an_import").is_none());
        // The stub-section spellings ride the same table (glibc reserved
        // parameter names included).
        assert_eq!(table.lookup("free").unwrap().parameters, "void *__ptr");
        assert_eq!(table.lookup("fwrite").unwrap().return_type, "size_t");
        assert_eq!(table.lookup("__ctype_b_loc").unwrap().parameters, "");
    }

    #[test]
    fn libc_locked_proto_assigns_sysv_storage_and_locks() {
        let carrier = model_carrier();
        let table = LibcSignatureTable::default();

        // free: void return, one void* parameter at RDI (0x38), fully locked.
        let free = table
            .locked_proto("free", &carrier, None)
            .expect("free signature represents")
            .expect("free is in the table");
        assert_eq!(free.return_type.get_metatype(), TypeMetatype::Void);
        assert_eq!(free.num_params(), 1);
        assert_eq!(free.get_param(0).unwrap().name, "__ptr");
        assert_eq!(free.get_param(0).unwrap().address.as_u64(), 0x38);
        assert!(free.is_output_locked());
        assert!(free.get_param(0).unwrap().is_type_locked());

        // strdup: char * return (8-byte pointer), one char* parameter.
        let strdup = table
            .locked_proto("strdup", &carrier, None)
            .expect("strdup signature represents")
            .expect("strdup is in the table");
        assert_eq!(strdup.return_type.get_metatype(), TypeMetatype::Pointer);
        assert_eq!(strdup.return_type.get_size(), 8);
        assert_eq!(strdup.get_param(0).unwrap().address.as_u64(), 0x38);

        match strdup.get_param(0).unwrap().data_type.as_ref() {
            Datatype::Pointer(pointer) => {
                assert!(pointer.ptr_to.is_char_print());
                assert_eq!(pointer.ptr_to.get_name(), "char");
            }
            other => panic!("strdup parameter is not a pointer: {other:?}"),
        }

        // strtol: long return, (char*, char**, int) at RDI/RSI/RDX.
        let strtol = table
            .locked_proto("strtol", &carrier, None)
            .expect("strtol signature represents")
            .expect("strtol is in the table");
        assert_eq!(strtol.num_params(), 3);
        // Signature-parsed pointers are ANONYMOUS (Ghidra's
        // PointerModifier::modType -> getTypePointer 3-arg, grammar.cc:2403
        // / type.cc:3867-3875); "char **" is the spelling, not the identity.
        let strtol_p1 = strtol.get_param(1).unwrap();
        assert_eq!(strtol_p1.data_type.get_name(), "");
        assert!(matches!(strtol_p1.data_type.as_ref(), Datatype::Pointer(_)));
        assert_eq!(strtol.get_param(2).unwrap().address.as_u64(), 0x10);

        // __ctype_b_loc: zero parameters, ushort ** return; the empty
        // parameter list is a locked void input.
        let ctype = table
            .locked_proto("__ctype_b_loc", &carrier, None)
            .expect("__ctype_b_loc signature represents")
            .expect("__ctype_b_loc is in the table");
        assert_eq!(ctype.num_params(), 0);
        // Anonymous pointer (see parse_c_type's Ghidra note).
        assert_eq!(ctype.return_type.get_name(), "");
        assert!(matches!(ctype.return_type.as_ref(), Datatype::Pointer(_)));
        assert!(ctype.void_input_locked);

        // Unknown imports stay unlocked (Ok(None) — active recovery decides).
        assert!(table
            .locked_proto("not_an_import", &carrier, None)
            .expect("unknown import does not error")
            .is_none());
    }

    #[test]
    fn compiler_model_spills_seventh_scalar_to_stack() {
        let mut proto = model_carrier();
        let scalar = base_type("long".to_string(), 8, TypeMetatype::Int);
        let pieces = crate::grammar::PrototypePieces {
            model: None,
            name: "eight_scalars".to_string(),
            out_type: Some(void_type()),
            in_types: vec![scalar; 8],
            in_names: (1..=8).map(|index| format!("p{index}")).collect(),
            first_var_arg_slot: -1,
        };
        proto.set_pieces(&pieces);
        assert!(!proto.has_input_errors());
        assert_eq!(proto.num_params(), 8);
        for (index, expected_offset) in [0x38, 0x30, 0x10, 0x08, 0x80, 0x88]
            .into_iter()
            .enumerate()
        {
            let param = proto.get_param(index).expect("register parameter");
            assert_eq!(param.address_space, crate::space::AddressSpace::Register);
            assert_eq!(param.address.as_u64(), expected_offset);
        }
        for (index, expected_offset) in [(6usize, 8u64), (7, 16)] {
            let param = proto.get_param(index).expect("stack parameter");
            assert_eq!(param.address_space, crate::space::AddressSpace::Stack);
            assert_eq!(param.address.as_u64(), expected_offset);
        }
    }

    #[test]
    fn curl_dwarf_prototypes_preserve_declared_shape() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");

        let getstr = db.get(0x36d0).expect("GetStr prototype");
        assert_eq!(getstr.name, "GetStr");
        assert_eq!(getstr.parameters.len(), 2);
        assert_eq!(getstr.parameters[0].name, "string");
        assert_eq!(getstr.parameters[1].name, "value");

        match getstr.parameters[1].data_type.as_ref() {
            Datatype::Pointer(pointer) => {
                assert_eq!(pointer.ptr_to.get_name(), "char");
                assert!(pointer.ptr_to.is_char_print());
            }
            other => panic!("GetStr value parameter is not a pointer: {other:?}"),
        }

        let progress = db.get(0x34d0).expect("myprogress prototype");
        assert_eq!(progress.parameters.len(), 5);
        assert_eq!(progress.parameters[0].name, "clientp");
        assert_eq!(progress.parameters[4].name, "ulnow");

        let helpf = db.get(0x3980).expect("helpf prototype");
        assert_eq!(helpf.parameters.len(), 1);
        assert!(helpf.is_varargs);

        let constant_propagated = db.get(0x3f00).expect("getparameter definition");
        assert_eq!(constant_propagated.name, "getparameter");
        assert_eq!(constant_propagated.parameters.len(), 4);
        assert_eq!(constant_propagated.parameters[3].name, "config");
    }

    #[test]
    fn curl_dwarf_globals_import_urlglob_pointer_chain() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugGlobalDatabase::parse_elf(&bytes).expect("DWARF globals");
        assert_eq!(db.len(), 5);

        let glob_expand = db.get(0x17660).expect("glob_expand global");
        assert_eq!(glob_expand.name, "glob_expand");
        // Anonymous pointer (see parse_c_type's Ghidra note); the pointee
        // structure check below carries the identity.
        assert_eq!(glob_expand.data_type.get_name(), "");
        match glob_expand.data_type.as_ref() {
            Datatype::Pointer(pointer) => match pointer.ptr_to.as_ref() {
                Datatype::Struct(composite) => {
                    assert_eq!(composite.base.size, 304);
                    let literal = composite
                        .fields
                        .iter()
                        .find(|field| field.name == "literal")
                        .expect("URLGlob.literal field");
                    assert_eq!(literal.offset, 0);
                    // Anonymous array of anonymous char* (getTypeArray /
                    // getTypePointer both leave names empty).
                    assert_eq!(literal.type_ptr.get_name(), "");
                    match literal.type_ptr.as_ref() {
                        Datatype::Array(arr) => {
                            assert_eq!(arr.num_elements, 10);
                            assert!(matches!(
                                arr.array_of.as_ref(),
                                Datatype::Pointer(_)
                            ));
                        }
                        _ => panic!("literal field must be an array"),
                    }
                    let pattern = composite
                        .fields
                        .iter()
                        .find(|field| field.name == "pattern")
                        .expect("URLGlob.pattern field");
                    assert_eq!(pattern.offset, 80);
                    // DW_AT_upper_bound 8 is inclusive: 9 elements of the
                    // 24-byte URLPattern occupy [80, 296) where `size` sits.
                    assert_eq!(pattern.type_ptr.get_name(), "");
                    match pattern.type_ptr.as_ref() {
                        Datatype::Array(arr) => {
                            assert_eq!(arr.num_elements, 9);
                            assert_eq!(arr.array_of.get_name(), "URLPattern");
                        }
                        _ => panic!("pattern field must be an array"),
                    }
                    let size = composite
                        .fields
                        .iter()
                        .find(|field| field.name == "size")
                        .expect("URLGlob.size field");
                    assert_eq!(size.offset, 296);
                    assert_eq!(size.type_ptr.get_name(), "int");
                }
                other => panic!("URLGlob pointee is not a struct: {other:?}"),
            },
            other => panic!("glob_expand is not a pointer: {other:?}"),
        }

        let glob_url = db.get(0x17520).expect("config global");
        assert_eq!(glob_url.name, "config");
        assert_eq!(glob_url.data_type.get_name(), "Configurable");
        assert_eq!(glob_url.data_type.get_size(), 304);

        let map = db.address_pointer_map();
        assert_eq!(map.len(), 5);
        // Address-pointer map types are anonymous pointers (see
        // pointer_type's Ghidra note); assert the pointee spelling through
        // the drill instead of the composed name.
        assert_eq!(
            map.get(&0x17660)
                .expect("glob_expand address type")
                .get_name(),
            ""
        );
        assert_eq!(
            map.get(&0x17660)
                .expect("glob_expand address type")
                .ptr_drill_base_name(),
            "URLGlob"
        );
        assert_eq!(
            map.get(&0x17520).expect("config address type").get_name(),
            ""
        );
        assert_eq!(
            map.get(&0x17520)
                .expect("config address type")
                .ptr_drill_base_name(),
            "Configurable"
        );
        assert_eq!(
            map.get(&0x17680)
                .expect("glob_buffer address type")
                .get_name(),
            ""
        );
        assert_eq!(
            map.get(&0x17680)
                .expect("glob_buffer address type")
                .ptr_drill_base_name(),
            "char"
        );
        assert_eq!(
            map.get(&0x17518)
                .expect("beenhere address type")
                .get_name(),
            ""
        );
        assert_eq!(
            map.get(&0x17518)
                .expect("beenhere address type")
                .ptr_drill_base_name(),
            "int"
        );
    }

    // GLOBWORD-C5: the DWARF front-end typelock semantic. In Ghidra, the
    // DWARF analyzer's committed Data types reach the decompiler symbol
    // table as ATTRIB_TYPELOCK (Symbol::decodeHeader database.cc:439-442);
    // without the flag, both typelock-gated consumers
    // (SymbolEntry::updateType database.cc:135-141 and buildLocaltypes'
    // exact-piece branch coreaction.cc:5021-5027) skip the global Symbol's
    // DWARF type, and glob_expand's value degrades to raw offsets in the
    // output. seed_global_locked is the single driver-side projection of
    // that semantic onto Rugra's query-channel Database.
    #[test]
    fn seed_global_locked_marks_dwarf_globals_typelocked_and_findable() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugGlobalDatabase::parse_elf(&bytes).expect("DWARF globals");
        let glob_expand = db.get(0x17660).expect("glob_expand global");

        let mut channel = crate::database::Database::new(false);
        let scope = channel.global_scope_id;
        let symbol_id = DebugGlobalDatabase::seed_global_locked(
            &mut channel,
            scope,
            glob_expand.address,
            &glob_expand.name,
            glob_expand.data_type.clone(),
            glob_expand.data_type.get_size().max(1) as i32,
        )
        .expect("seeded symbol id");

        // The typelock gate SymbolEntry::updateType checks.
        let locked = channel
            .get_global_scope()
            .and_then(|s| s.symbols.get(&symbol_id))
            .map(|sym| sym.read().unwrap().is_type_locked());
        assert_eq!(locked, Some(true));

        // The channel the pipeline queries (queryProperties/
        // queryContainer) resolves the seeded entry, and the entry carries
        // the URLGlob-pointer symbol type updateType hands to the Varnode.
        let hit = channel
            .query_container(
                scope,
                Address::new(0x17660),
                1,
                Address::new(0),
            )
            .expect("container hit at glob_expand");
        assert_eq!(hit.symbol_name, "glob_expand");
        let entry_type = channel
            .get_global_scope()
            .and_then(|s| s.symbols.get(&symbol_id))
            .map(|sym| sym.read().unwrap().get_type());
        assert!(matches!(
            entry_type,
            Some(Some(ref dt)) if matches!(dt.as_ref(), Datatype::Pointer(_))
        ));
    }

    #[test]
    fn typedef_and_qualifier_aliases_preserve_character_semantics_and_shape() {
        let character = Datatype::Base(TypeBase::new_char("char".to_string(), TypeMetatype::Int));
        let qualified = alias_type("const char".to_string(), &character);
        assert!(qualified.is_char_print());
        assert_eq!(qualified.get_name(), "const char");

        let pointer = Datatype::Pointer(TypePointer {
            base: TypeBase::new("char *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: Arc::new(character),
            wordsize: 1,
        });
        let alias = alias_type("char_ptr".to_string(), &pointer);
        match alias.as_ref() {
            Datatype::Pointer(pointer) => {
                assert_eq!(pointer.ptr_to.get_name(), "char");
                assert!(pointer.ptr_to.is_char_print());
            }
            other => panic!("pointer typedef lost its concrete shape: {other:?}"),
        }
    }

    // CALLSPEC-ENV-SCOPE-0001: the call-site half of the DWARF boundary —
    // queryCall resolves the DWARF-locked callee and ActionDefaultParams
    // copies its whole FuncProto to the call site (coreaction.cc:2322-2330),
    // so a caller decompiling with debug info sees the callee's locked
    // parameter list (golden main: `glob_url(&urls,pcVar12,&urlnum)` 3-arg
    // from the DWARF definition, not an experimental guess).
    #[test]
    fn locked_callsite_proto_copies_dwarf_signature() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");
        // glob_url @ 0x4f70: (URLGlob **glob, char *url, int *urlnum).
        let carrier = model_carrier();
        let proto = db
            .locked_callsite_proto(0x4f70, &carrier)
            .expect("glob_url callsite prototype represents")
            .expect("glob_url has a DWARF definition");
        assert_eq!(proto.num_params(), 3);
        assert!(proto.is_input_locked());
        assert!(proto.is_output_locked());
        assert!(proto.is_model_locked());
        assert!(!proto.is_model_unknown());
        assert_eq!(proto.get_param(0).unwrap().name, "glob");
        assert_eq!(proto.get_param(0).unwrap().address.as_u64(), 0x38);
        assert_eq!(proto.get_param(2).unwrap().address.as_u64(), 0x10);
        // Anonymous pointer chain (see parse_c_type's Ghidra note): the
        // "URLGlob **" spelling is not the imported type's name.
        assert_eq!(proto.get_param(0).unwrap().data_type.get_name(), "");
        assert!(matches!(
            proto.get_param(0).unwrap().data_type.as_ref(),
            Datatype::Pointer(_)
        ));

        // A thunk/import address has no DWARF definition: the boundary
        // contributes nothing (Ok(None)) and the import table owns it.
        assert!(db
            .locked_callsite_proto(0x2490, &carrier)
            .expect("thunk lookup does not error")
            .is_none());
    }

    #[test]
    fn applying_known_void_prototype_locks_shape_and_storage() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0x4a);
        fd.funcp = model_carrier();
        assert!(db
            .apply(&mut fd)
            .expect("apply prototype"));
        assert!(fd.funcp.is_input_locked());
        assert!(fd.funcp.is_output_locked());
        assert_eq!(fd.funcp.parameters.len(), 2);
        assert_eq!(fd.funcp.parameters[0].address.as_u64(), 0x38);
        assert_eq!(fd.funcp.parameters[1].address.as_u64(), 0x30);

        let mut no_args = Funcdata::new("hugehelp", Address::new(0x4a00), 0x54);
        no_args.funcp = model_carrier();
        assert!(db
            .apply(&mut no_args)
            .expect("apply void input"));
        assert!(no_args.funcp.parameters.is_empty());
        assert!(no_args.funcp.is_input_locked());
    }

    // A void input list locks the model, but does not replace a model already
    // bound by the caller. FuncProto::decode only constructs an unknown model
    // for an explicit, unresolved ATTRIB_MODEL value; voidinputlock merely
    // contributes to modellock (fspec.cc:4681-4698, 4737-4738, 4776-4777).
    #[test]
    fn void_signature_dwarf_prototype_keeps_bound_model() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");
        for (name, address) in
            [
            ("main_init", 0x4960u64), ("main_free", 0x4970), ("hugehelp", 0x4a00),
        ]
        {
            let mut fd = Funcdata::new(name, Address::new(address), 8);
            // Simulate the post-set_arch default-model binding the worker
            // performs before the DWARF overlay.
            fd.funcp = model_carrier();
            assert!(db
                .apply(&mut fd)
                .expect("apply void-signature prototype"));
            assert!(!fd.funcp.is_model_unknown(), "{name} keeps the bound model");
            assert!(
                fd.funcp.is_model_locked(),
                "{name} void parameter list locks the bound model"
            );
            assert!(fd.funcp.void_input_locked);
        }
    }

    // UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ⑤ counterpart: parameterized DWARF
    // signatures keep the resolved model binding — in the locked golden none
    // of the 18 parameterized DWARF functions warn, so the overlay must not
    // pin the unknown sentinel for them.
    // HTTPD-URAM-SYMBOLIZE-0001: the PLT thunk import boundary against the
    // locked-oracle httpd image (the binary the 12.0.4 headless golden was
    // produced from; thunk names cross-checked against the golden's function
    // headers `/* ---- 0x12aXXX: <name> (10 bytes) ---- */`).
    fn httpd_bytes() -> Vec<u8> {
        std::fs::read("examples/httpd").expect("httpd fixture")
    }

    #[test]
    fn plt_imports_resolve_sec_slots_from_jump_slot_relocs() {
        let imports = ElfPltImports::parse_elf(&httpd_bytes());
        // .plt.sec @0x2a420, slot i at +16*i ↔ .rela.plt[i].
        // Witness set = the 82 thunk call sites of the uRam family; every
        // name below matches the locked golden's callee spelling.
        for (addr, name) in [
            (0x2a6d0u64, "apr_app_initialize"),
            (0x2a7c0, "apr_pool_create_ex"),
            (0x2a6a0, "apr_pool_tag"),
            (0x2abc0, "apr_palloc"),
            (0x2a8e0, "apr_filepath_name_get"),
            (0x2a4d0, "apr_array_make"),
            (0x2a450, "apr_getopt_init"),
            (0x2b6e0, "apr_getopt"),
            (0x2b190, "apr_array_push"),
            (0x2aa50, "apr_hook_sort_all"),
            (0x2b070, "apr_dynamic_fn_retrieve"),
            (0x2a820, "apr_pool_clear"),
            (0x2b1a0, "apr_pool_destroy"),
            (0x2ab70, "apr_hook_deregister_all"),
            (0x2a540, "strcasecmp"),
            (0x2afd0, "strncasecmp"),
            (0x2acb0, "memcmp"),
            (0x2a800, "apr_table_get"),
            (0x2b790, "__ctype_b_loc"),
            (0x2b140, "apr_parse_addr_port"),
            (0x2a8d0, "apr_itoa"),
            (0x2b770, "__ctype_tolower_loc"),
            (0x2a600, "strncmp"),
            (0x2b430, "apr_sockaddr_equal"),
            (0x2a9e0, "strchr"),
            (0x2aee0, "apr_pstrdup"),
            (0x2b500, "apr_pstrndup"),
            (0x2aa30, "apr_time_exp_lt"),
            (0x2a4e0, "apr_time_exp_gmt"),
            (0x2aa90, "apr_strftime"),
            (0x2a980, "__stack_chk_fail"),
            (0x2a830, "apr_filepath_root"),
            (0x2a910, "strlen"),
            (0x2ab20, "apr_pool_cleanup_register"),
            (0x2a970, "apr_pool_cleanup_kill"),
            (0x2ab40, "memset"),
            (0x2ae60, "memcpy"),
            (0x2aa80, "strrchr"),
        ] {
            assert_eq!(
                imports.get(addr).map(String::as_str),
                Some(name),
                "PLT thunk at 0x{addr:x} must import as {name}"
            );
        }
        // JUMP_SLOT count == .plt.sec slot count: all 317 imports resolved.
        assert_eq!(imports.len(), 317, "one thunk name per .rela.plt entry");
        // Non-thunk addresses (the 5 shared tail chunks in .text) must stay
        // unnamed here — they are analysis functions, not imports.
        for addr in [0x2c520u64, 0x2c550, 0x2c8e0, 0x2c960, 0x2ce20] {
            assert!(
                imports.get(addr).is_none(),
                "0x{addr:x} is not a PLT thunk"
            );
        }
    }

    #[test]
    fn analyze_headless_function_symbol_name_uses_image_base_padding() {
        // Locked-oracle witnesses (golden headers):
        // 0x2c520 → FUN_0012c520, 0x2c960 → FUN_0012c960.
        assert_eq!(
            analyze_headless_function_symbol_name(0x2c520, 0x100000),
            "FUN_0012c520"
        );
        assert_eq!(
            analyze_headless_function_symbol_name(0x2c960, 0x100000),
            "FUN_0012c960"
        );
        assert_eq!(
            analyze_headless_function_symbol_name(0x2ce20, 0x100000),
            "FUN_0012ce20"
        );
    }

    #[test]
    fn plt_imports_reject_non_elf_payloads() {
        assert!(ElfPltImports::parse_elf(b"not an elf image at all").is_empty());
    }

}
