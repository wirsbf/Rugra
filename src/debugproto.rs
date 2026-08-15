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

use crate::address::Address;
use crate::fspec::{FuncProto, ProtoParameter};
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
            while let Some((_, entry)) = entries.next_dfs().context("walking DWARF DIEs")? {
                if entry.tag() != gimli::DW_TAG_variable {
                    continue;
                }
                let Some(address) = static_location_address(&unit, entry)? else {
                    continue;
                };
                let Some(name) = entry_string(&dwarf, &unit, entry, gimli::DW_AT_name)? else {
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
                    },
                );
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
            .map(|global| (global.address, global_address_type(global, self.address_size)))
            .collect()
    }
}

// RUGRA-GLUE: shared DWARF section loader for the prototype and global importers
fn load_dwarf(bytes: &[u8]) -> Result<Dwarf<DwarfReader>> {
    let object = object::File::parse(bytes).context("parsing object for DWARF sections")?;
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
    pub fn apply(&self, fd: &mut Funcdata, storage: &X86_64GccStorage) -> Result<bool> {
        let Some(debug_proto) = self.get(fd.baseaddr.as_u64()) else {
            return Ok(false);
        };
        let addresses = storage.assign(&debug_proto.parameters)?;
        let mut proto: FuncProto = fd.funcp.clone();
        proto.return_type = debug_proto.return_type.clone();
        proto.parameters.clear();
        for (index, (parameter, address)) in debug_proto
            .parameters
            .iter()
            .zip(addresses.into_iter())
            .enumerate()
        {
            let name = if parameter.name.is_empty() {
                format!("param_{}", index + 1)
            } else {
                parameter.name.clone()
            };
            proto.add_parameter(ProtoParameter::new(
                name,
                parameter.data_type.clone(),
                address,
            ));
        }
        proto.set_dotdotdot(debug_proto.is_varargs);
        proto.set_input_lock(true);
        proto.set_output_lock(true);
        proto.set_model_lock(true);
        fd.funcp = proto;
        Ok(true)
    }
}

/// Storage resources from the locked `x86-64-gcc.cspec` default prototype.
#[derive(Debug, Clone)]
pub struct X86_64GccStorage {
    registers: HashMap<String, (u64, usize)>,
}

impl X86_64GccStorage {
    // RUGRA-GLUE: converts the active SLEIGH register catalog into the ParamEntry resources declared by locked x86-64-gcc.cspec
    pub fn from_sleigh(ctx: &crate::sleigh_ffi::SleighCtx) -> Result<Self> {
        let mut registers = HashMap::new();
        for index in 0..ctx.num_registers() {
            let Some((name, _space, offset, size)) = ctx.register_info(index) else {
                continue;
            };
            let size = usize::try_from(size).context("negative SLEIGH register size")?;
            registers.insert(name.to_ascii_uppercase(), (offset, size));
        }
        Ok(Self { registers })
    }

    // RUGRA-GLUE: deterministic constructor used by fixtures to supply the same compiler-spec resource catalog without a live translator
    pub fn from_registers(registers: impl IntoIterator<Item = (String, u64, usize)>) -> Self {
        Self {
            registers: registers
                .into_iter()
                .map(|(name, offset, size)| (name.to_ascii_uppercase(), (offset, size)))
                .collect(),
        }
    }

    // RUGRA-GLUE: invokes the locked x86-64 gcc ParamList resource order at the Program-to-Funcdata boundary; the underlying order is x86-64-gcc.cspec, not a guessed live-in list
    fn assign(&self, parameters: &[DebugParameter]) -> Result<Vec<Address>> {
        const GENERAL: [&str; 6] = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"];
        const FLOAT: [&str; 8] = [
            "XMM0_QA", "XMM1_QA", "XMM2_QA", "XMM3_QA", "XMM4_QA", "XMM5_QA", "XMM6_QA", "XMM7_QA",
        ];
        let mut general_index = 0usize;
        let mut float_index = 0usize;
        let mut result = Vec::with_capacity(parameters.len());
        for parameter in parameters {
            let ty = parameter.data_type.as_ref();
            if matches!(
                ty.get_metatype(),
                TypeMetatype::Struct | TypeMetatype::Union | TypeMetatype::Array
            ) || ty.get_size() > 8
            {
                bail!(
                    "compiler-spec aggregate/stack assignment is not yet representable for {}",
                    parameter.name
                );
            }
            let resource = if ty.get_metatype() == TypeMetatype::Float {
                let name = FLOAT
                    .get(float_index)
                    .context("x86-64 gcc floating parameter spilled to unmodelled stack space")?;
                float_index += 1;
                *name
            } else {
                let name = GENERAL
                    .get(general_index)
                    .context("x86-64 gcc general parameter spilled to unmodelled stack space")?;
                general_index += 1;
                *name
            };
            let &(offset, resource_size) = self
                .registers
                .get(resource)
                .with_context(|| format!("SLEIGH register catalog is missing {resource}"))?;
            if ty.get_size() > resource_size {
                bail!(
                    "{}-byte parameter {} does not fit {}-byte resource {}",
                    ty.get_size(),
                    parameter.name,
                    resource_size,
                    resource
                );
            }
            result.push(Address::new(offset));
        }
        Ok(result)
    }
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
        let name = entry_string(dwarf, unit, &canonical_entry, gimli::DW_AT_name)?
            .unwrap_or_else(|| format!("param_{}", parameters.len() + 1));
        let data_type = match entry_reference(unit, &canonical_entry, gimli::DW_AT_type)? {
            Some(type_offset) => resolve_type(dwarf, unit, type_offset, 0, &mut Vec::new())?,
            None => unknown_type(unit.encoding().address_size as usize),
        };
        parameters.push(DebugParameter { name, data_type });
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
        gimli::DW_TAG_base_type => {
            let metatype = base_metatype(&entry)?;
            Ok(base_type(
                name.unwrap_or_else(|| "int".to_string()),
                size.unwrap_or(4),
                metatype,
            ))
        }
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
            let type_name = format!("{}[{}]", element.get_name(), count);
            Ok(Arc::new(Datatype::Array(TypeArray {
                base: TypeBase::new(type_name, array_size, TypeMetatype::Array),
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
        gimli::DW_TAG_base_type => Ok(base_type(
            "int".to_string(),
            size.unwrap_or(4),
            base_metatype(entry)?,
        )),
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
    Arc::new(Datatype::Base(TypeBase::new(name, size, metatype)))
}

// RUGRA-GLUE: constructs a fielded struct Datatype from DWARF DW_TAG_member children; Ghidra builds the equivalent Structure dataType in its DWARF/type-manager front end
fn struct_type(name: String, size: usize, fields: Vec<TypeField>) -> Arc<Datatype> {
    Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new(name, size, TypeMetatype::Struct),
        fields,
    }))
}

// RUGRA-GLUE: constructs a fielded union Datatype from DWARF union members (all at offset 0)
fn union_type(name: String, size: usize, fields: Vec<TypeField>) -> Arc<Datatype> {
    Arc::new(Datatype::Union(TypeUnion {
        base: TypeBase::new(name, size, TypeMetatype::Union),
        fields,
    }))
}

// RUGRA-GLUE: constructs an enum Datatype with its DWARF enumerator value table for constant-name rendering
fn enum_type(name: String, size: usize, values: BTreeMap<u64, String>) -> Arc<Datatype> {
    Arc::new(Datatype::Enum(TypeEnum {
        base: TypeBase::new(name, size, TypeMetatype::Enum),
        values,
    }))
}

// RUGRA-GLUE: materializes a DWARF typedef as the underlying composite/enum renamed to the typedef spelling; Rugra's Datatype enum has no TypeTypedef variant yet (Ghidra type.hh has one), so fields and enumerator names are carried on the renamed type
fn materialized_alias(name: String, inner: &Datatype) -> Result<Arc<Datatype>> {
    match inner {
        Datatype::Struct(composite) => Ok(struct_type(
            name,
            composite.base.size,
            composite.fields.clone(),
        )),
        Datatype::Union(composite) => Ok(union_type(
            name,
            composite.base.size,
            composite.fields.clone(),
        )),
        Datatype::Enum(enumeration) => Ok(enum_type(
            name,
            enumeration.base.size,
            enumeration.values.clone(),
        )),
        _ => Ok(alias_type(name, inner)),
    }
}

// RUGRA-GLUE: preserves a DWARF typedef/qualifier spelling while carrying its resolved size and metatype into FuncProto
fn alias_type(name: String, inner: &Datatype) -> Arc<Datatype> {
    base_type(name, inner.get_size(), inner.get_metatype())
}

// RUGRA-GLUE: constructs a pointer Datatype from a resolved DWARF pointee at the native debug-import boundary
fn pointer_type(pointee: Arc<Datatype>, size: usize) -> Arc<Datatype> {
    let name = if pointee.get_name().trim_end().ends_with('*') {
        format!("{}*", pointee.get_name().trim_end())
    } else {
        format!("{} *", pointee.get_name())
    };
    Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(name, size, TypeMetatype::Pointer),
        ptr_to: pointee,
        wordsize: 1,
    }))
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

    fn register_resources() -> X86_64GccStorage {
        let general = [
            ("RDI", 0x38),
            ("RSI", 0x30),
            ("RDX", 0x10),
            ("RCX", 0x08),
            ("R8", 0x80),
            ("R9", 0x88),
        ];
        let floats = (0..8).map(|index| (format!("XMM{index}_QA"), 0x100 + index * 8, 8));
        X86_64GccStorage::from_registers(
            general
                .into_iter()
                .map(|(name, offset)| (name.to_string(), offset, 8))
                .chain(floats),
        )
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
        assert_eq!(glob_expand.data_type.get_name(), "URLGlob *");
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
                    assert_eq!(literal.type_ptr.get_name(), "char *[10]");
                    let pattern = composite
                        .fields
                        .iter()
                        .find(|field| field.name == "pattern")
                        .expect("URLGlob.pattern field");
                    assert_eq!(pattern.offset, 80);
                    // DW_AT_upper_bound 8 is inclusive: 9 elements of the
                    // 24-byte URLPattern occupy [80, 296) where `size` sits.
                    assert_eq!(pattern.type_ptr.get_name(), "URLPattern[9]");
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
        assert_eq!(
            map.get(&0x17660).expect("glob_expand address type").get_name(),
            "URLGlob **"
        );
        assert_eq!(
            map.get(&0x17520).expect("config address type").get_name(),
            "Configurable *"
        );
        assert_eq!(
            map.get(&0x17680)
                .expect("glob_buffer address type")
                .get_name(),
            "char *"
        );
        assert_eq!(
            map.get(&0x17518)
                .expect("beenhere address type")
                .get_name(),
            "int *"
        );
    }

    #[test]
    fn applying_known_void_prototype_locks_shape_and_storage() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0x4a);
        assert!(db
            .apply(&mut fd, &register_resources())
            .expect("apply prototype"));
        assert!(fd.funcp.is_input_locked());
        assert!(fd.funcp.is_output_locked());
        assert_eq!(fd.funcp.parameters.len(), 2);
        assert_eq!(fd.funcp.parameters[0].address.as_u64(), 0x38);
        assert_eq!(fd.funcp.parameters[1].address.as_u64(), 0x30);

        let mut no_args = Funcdata::new("hugehelp", Address::new(0x4a00), 0x54);
        assert!(db
            .apply(&mut no_args, &register_resources())
            .expect("apply void input"));
        assert!(no_args.funcp.parameters.is_empty());
        assert!(no_args.funcp.is_input_locked());
    }
}
