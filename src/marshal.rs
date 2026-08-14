//! Marshaling / serialization — faithful port of `marshal.hh` / `marshal.cc`
//! (1273 lines) + `xml.hh` / `xml.cc` (2510 lines, the in-memory DOM tree).
//!
//! Provides the `AttributeId`/`ElementId` registry, the in-memory `Element`/
//! `Document` DOM tree, and the `Encoder`/`Decoder` traits with a concrete
//! XML-based implementation. This is the serialization foundation referenced
//! by database.rs, override.rs, and arch.rs as their XML encode/decode L3 gap.
//!
//! Status: L1→L2. The registry, DOM tree, and Encoder/Decoder traits are
//! complete with a working in-memory `XmlEncode`/`XmlDecode` round-trip. The
//! Packed binary format (`PackedEncode`/`PackedDecode`) is an L3 gap.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/{marshal,xml}.{hh,cc}.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

/// The locked Ghidra 12.0.4 id for an unrecognized attribute name.
pub const ATTRIB_UNKNOWN: u32 = 159;

/// The locked Ghidra 12.0.4 id for an unrecognized element name.
pub const ELEM_UNKNOWN: u32 = 289;

/// A special attribute id for an element's text content. Faithful to
/// `ATTRIB_CONTENT`.
pub const ATTRIB_CONTENT: u32 = 1;

/// Locked Ghidra 12.0.4 scope-0 attribute name/id table. Missing numeric ids
/// are intentional protocol gaps and must never be compacted or renumbered.
pub const ATTRIBUTE_ID_TABLE: &[(&str, u32)] = &[
    ("XMLcontent", 1),
    ("align", 2),
    ("bigendian", 3),
    ("constructor", 4),
    ("destructor", 5),
    ("extrapop", 6),
    ("format", 7),
    ("hiddenretparm", 8),
    ("id", 9),
    ("index", 10),
    ("indirectstorage", 11),
    ("metatype", 12),
    ("model", 13),
    ("name", 14),
    ("namelock", 15),
    ("offset", 16),
    ("readonly", 17),
    ("ref", 18),
    ("size", 19),
    ("space", 20),
    ("thisptr", 21),
    ("type", 22),
    ("typelock", 23),
    ("val", 24),
    ("value", 25),
    ("wordsize", 26),
    ("first", 27),
    ("last", 28),
    ("uniq", 29),
    ("addrtied", 30),
    ("grp", 31),
    ("input", 32),
    ("persists", 33),
    ("unaff", 34),
    ("blockref", 35),
    ("close", 36),
    ("color", 37),
    ("indent", 38),
    ("off", 39),
    ("open", 40),
    ("opref", 41),
    ("varref", 42),
    ("code", 43),
    ("contain", 44),
    ("defaultspace", 45),
    ("uniqbase", 46),
    ("alignment", 47),
    ("arraysize", 48),
    ("char", 49),
    ("core", 50),
    ("incomplete", 52),
    ("opaquestring", 56),
    ("signed", 57),
    ("structalign", 58),
    ("utf", 59),
    ("varlength", 60),
    ("cat", 61),
    ("field", 62),
    ("merge", 63),
    ("scopeidbyname", 64),
    ("volatile", 65),
    ("class", 66),
    ("repref", 67),
    ("symref", 68),
    ("trunc", 69),
    ("dynamic", 70),
    ("incidentalcopy", 71),
    ("inject", 72),
    ("paramshift", 73),
    ("targetop", 74),
    ("altindex", 75),
    ("depth", 76),
    ("end", 77),
    ("opcode", 78),
    ("rev", 79),
    ("a", 80),
    ("b", 81),
    ("length", 82),
    ("tag", 83),
    ("nocode", 84),
    ("farpointer", 85),
    ("inputop", 86),
    ("outputop", 87),
    ("userop", 88),
    ("base", 89),
    ("deadcodedelay", 90),
    ("delay", 91),
    ("logicalsize", 92),
    ("physical", 93),
    ("piece", 94),
    ("adjustvma", 103),
    ("enable", 104),
    ("group", 105),
    ("growth", 106),
    ("key", 107),
    ("loadersymbols", 108),
    ("parent", 109),
    ("register", 110),
    ("reversejustify", 111),
    ("signext", 112),
    ("style", 113),
    ("custom", 114),
    ("dotdotdot", 115),
    ("extension", 116),
    ("hasthis", 117),
    ("inline", 118),
    ("killedbycall", 119),
    ("maxsize", 120),
    ("minsize", 121),
    ("modellock", 122),
    ("noreturn", 123),
    ("pointermax", 124),
    ("separatefloat", 125),
    ("stackshift", 126),
    ("strategy", 127),
    ("thisbeforeretpointer", 128),
    ("voidlock", 129),
    ("vector_lane_sizes", 130),
    ("label", 131),
    ("num", 132),
    ("lock", 133),
    ("main", 134),
    ("arch", 135),
    ("deprecated", 136),
    ("endian", 137),
    ("processor", 138),
    ("processorspec", 139),
    ("slafile", 140),
    ("spec", 141),
    ("target", 142),
    ("variant", 143),
    ("version", 144),
    ("baddata", 145),
    ("hash", 146),
    ("unimpl", 147),
    ("address", 148),
    ("storage", 149),
    ("stackspill", 150),
    ("sizes", 151),
    ("maxprimitives", 153),
    ("reversesignif", 154),
    ("matchsize", 155),
    ("afterbytes", 156),
    ("afterstorage", 157),
    ("fillalternate", 158),
    ("XMLunknown", 159),
];

/// Locked Ghidra 12.0.4 scope-0 element name/id table. Missing numeric ids
/// are intentional protocol gaps and must never be compacted or renumbered.
pub const ELEMENT_ID_TABLE: &[(&str, u32)] = &[
    ("data", 1),
    ("input", 2),
    ("off", 3),
    ("output", 4),
    ("returnaddress", 5),
    ("symbol", 6),
    ("target", 7),
    ("val", 8),
    ("value", 9),
    ("void", 10),
    ("addr", 11),
    ("range", 12),
    ("rangelist", 13),
    ("register", 14),
    ("seqnum", 15),
    ("varnode", 16),
    ("break", 17),
    ("clang_document", 18),
    ("funcname", 19),
    ("funcproto", 20),
    ("label", 21),
    ("return_type", 22),
    ("statement", 23),
    ("syntax", 24),
    ("vardecl", 25),
    ("variable", 26),
    ("op", 27),
    ("sleigh", 28),
    ("space", 29),
    ("spaceid", 30),
    ("spaces", 31),
    ("space_base", 32),
    ("space_other", 33),
    ("space_overlay", 34),
    ("space_unique", 35),
    ("truncate_space", 36),
    ("char_size", 39),
    ("coretypes", 41),
    ("data_organization", 42),
    ("def", 43),
    ("entry", 47),
    ("enum", 48),
    ("field", 49),
    ("integer_size", 51),
    ("long_size", 54),
    ("pointer_size", 57),
    ("size_alignment_map", 59),
    ("type", 60),
    ("typegrp", 62),
    ("typeref", 63),
    ("wchar_size", 65),
    ("collision", 67),
    ("db", 68),
    ("equatesymbol", 69),
    ("externrefsymbol", 70),
    ("facetsymbol", 71),
    ("functionshell", 72),
    ("hash", 73),
    ("hole", 74),
    ("labelsym", 75),
    ("mapsym", 76),
    ("parent", 77),
    ("property_changepoint", 78),
    ("rangeequalssymbols", 79),
    ("scope", 80),
    ("symbollist", 81),
    ("high", 82),
    ("bytes", 83),
    ("string", 84),
    ("stringmanage", 85),
    ("comment", 86),
    ("commentdb", 87),
    ("text", 88),
    ("addr_pcode", 89),
    ("body", 90),
    ("callfixup", 91),
    ("callotherfixup", 92),
    ("case_pcode", 93),
    ("context", 94),
    ("default_pcode", 95),
    ("inject", 96),
    ("injectdebug", 97),
    ("inst", 98),
    ("payload", 99),
    ("pcode", 100),
    ("size_pcode", 101),
    ("bhead", 102),
    ("block", 103),
    ("blockedge", 104),
    ("edge", 105),
    ("parammeasures", 106),
    ("proto", 107),
    ("rank", 108),
    ("constantpool", 109),
    ("cpoolrec", 110),
    ("ref", 111),
    ("token", 112),
    ("iop", 113),
    ("unimpl", 114),
    ("ast", 115),
    ("function", 116),
    ("highlist", 117),
    ("jumptablelist", 118),
    ("varnodes", 119),
    ("context_data", 120),
    ("context_points", 121),
    ("context_pointset", 122),
    ("context_set", 123),
    ("set", 124),
    ("tracked_pointset", 125),
    ("tracked_set", 126),
    ("constresolve", 127),
    ("jumpassist", 128),
    ("segmentop", 129),
    ("address_shift_amount", 130),
    ("aggressivetrim", 131),
    ("compiler_spec", 132),
    ("data_space", 133),
    ("default_memory_blocks", 134),
    ("default_proto", 135),
    ("default_symbols", 136),
    ("eval_called_prototype", 137),
    ("eval_current_prototype", 138),
    ("experimental_rules", 139),
    ("flowoverridelist", 140),
    ("funcptr", 141),
    ("global", 142),
    ("incidentalcopy", 143),
    ("inferptrbounds", 144),
    ("modelalias", 145),
    ("nohighptr", 146),
    ("processor_spec", 147),
    ("programcounter", 148),
    ("properties", 149),
    ("property", 150),
    ("readonly", 151),
    ("register_data", 152),
    ("rule", 153),
    ("save_state", 154),
    ("segmented_address", 155),
    ("spacebase", 156),
    ("specextensions", 157),
    ("stackpointer", 158),
    ("volatile", 159),
    ("group", 160),
    ("internallist", 161),
    ("killedbycall", 162),
    ("likelytrash", 163),
    ("localrange", 164),
    ("model", 165),
    ("param", 166),
    ("paramrange", 167),
    ("pentry", 168),
    ("prototype", 169),
    ("resolveprototype", 170),
    ("retparam", 171),
    ("returnsym", 172),
    ("unaffected", 173),
    ("aliasblock", 174),
    ("allowcontextset", 175),
    ("analyzeforloops", 176),
    ("commentheader", 177),
    ("commentindent", 178),
    ("commentinstruction", 179),
    ("commentstyle", 180),
    ("conventionprinting", 181),
    ("currentaction", 182),
    ("defaultprototype", 183),
    ("errorreinterpreted", 184),
    ("errortoomanyinstructions", 185),
    ("errorunimplemented", 186),
    ("extrapop", 187),
    ("ignoreunimplemented", 188),
    ("indentincrement", 189),
    ("inferconstptr", 190),
    ("inline", 191),
    ("inplaceops", 192),
    ("integerformat", 193),
    ("jumpload", 194),
    ("maxinstruction", 195),
    ("maxlinewidth", 196),
    ("namespacestrategy", 197),
    ("nocastprinting", 198),
    ("noreturn", 199),
    ("nullprinting", 200),
    ("optionslist", 201),
    ("param1", 202),
    ("param2", 203),
    ("param3", 204),
    ("protoeval", 205),
    ("setaction", 206),
    ("setlanguage", 207),
    ("structalign", 208),
    ("togglerule", 209),
    ("warning", 210),
    ("basicoverride", 211),
    ("dest", 212),
    ("jumptable", 213),
    ("loadtable", 214),
    ("normaddr", 215),
    ("normhash", 216),
    ("startval", 217),
    ("deadcodedelay", 218),
    ("flow", 219),
    ("forcegoto", 220),
    ("indirectoverride", 221),
    ("multistagejump", 222),
    ("override", 223),
    ("protooverride", 224),
    ("prefersplit", 225),
    ("callgraph", 226),
    ("node", 227),
    ("localdb", 228),
    ("doc", 229),
    ("binaryimage", 230),
    ("bytechunk", 231),
    ("compiler", 232),
    ("description", 233),
    ("language", 234),
    ("language_definitions", 235),
    ("xml_savefile", 236),
    ("raw_savefile", 237),
    ("bfd_savefile", 238),
    ("command_isnameused", 239),
    ("command_getbytes", 240),
    ("command_getcallfixup", 241),
    ("command_getcallmech", 242),
    ("command_getcallotherfixup", 243),
    ("command_getcodelabel", 244),
    ("command_getcomments", 245),
    ("command_getcpoolref", 246),
    ("command_getdatatype", 247),
    ("command_getexternalref", 248),
    ("command_getmappedsymbols", 249),
    ("command_getnamespacepath", 250),
    ("command_getpcode", 251),
    ("command_getpcodeexecutable", 252),
    ("command_getregister", 253),
    ("command_getregistername", 254),
    ("command_getstringdata", 255),
    ("command_gettrackedregisters", 256),
    ("command_getuseropname", 257),
    ("blocksig", 258),
    ("call", 259),
    ("gensig", 260),
    ("major", 261),
    ("minor", 262),
    ("copysig", 263),
    ("settings", 264),
    ("sig", 265),
    ("signaturedesc", 266),
    ("signatures", 267),
    ("sigsettings", 268),
    ("varsig", 269),
    ("splitdatatype", 270),
    ("jumptablemax", 271),
    ("nanignore", 272),
    ("datatype", 273),
    ("consume", 274),
    ("consume_extra", 275),
    ("convert_to_ptr", 276),
    ("goto_stack", 277),
    ("join", 278),
    ("datatype_at", 279),
    ("position", 280),
    ("varargs", 281),
    ("hidden_return", 282),
    ("join_per_primitive", 283),
    ("braceformat", 284),
    ("join_dual_class", 285),
    ("internal_storage", 286),
    ("extra_stack", 287),
    ("consume_remaining", 288),
    ("XMLunknown", 289),
];

/// An annotation for a data element being transferred to/from a stream.
/// Faithful to `AttributeId` (marshal.hh:41).
#[derive(Debug, Clone)]
pub struct AttributeId {
    /// The name of the attribute.
    pub name: String,
    /// The internal id of the attribute.
    pub id: u32,
}

impl AttributeId {
    /// Construct a const placeholder with the numeric id.
    /// The name cannot be retained by this const initializer.
    // RUGRA-GLUE: Const placeholder; unlike Ghidra's constructor, it cannot retain the name or register globally.
    pub const fn new_static(nm: &'static str, id: u32) -> Self {
        Self {
            name: String::new(), // Will be set at runtime; const can't allocate.
            id,
        }
    }

    // Ghidra: marshal.cc:45 AttributeId::new
    /// Construct at runtime.
    pub fn new(nm: &str, id: u32) -> Self {
        Self {
            name: nm.to_string(),
            id,
        }
    }

    // Ghidra: marshal.cc:45 AttributeId::getName
    /// Get the attribute's name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: marshal.cc:45 AttributeId::getId
    /// Get the attribute's id.
    pub fn get_id(&self) -> u32 {
        self.id
    }
}

impl PartialEq for AttributeId {
    // Ghidra: marshal.cc:45 AttributeId::eq
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

/// An annotation for a specific collection of hierarchical data. Faithful to
/// `ElementId` (marshal.hh:65).
#[derive(Debug, Clone)]
pub struct ElementId {
    /// The name of the element.
    pub name: String,
    /// The internal id of the element.
    pub id: u32,
}

impl ElementId {
    // Ghidra: marshal.cc:87 ElementId::new
    /// Construct given a name and id.
    pub fn new(nm: &str, id: u32) -> Self {
        Self {
            name: nm.to_string(),
            id,
        }
    }

    // Ghidra: marshal.cc:87 ElementId::getName
    /// Get the element's name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: marshal.cc:87 ElementId::getId
    /// Get the element's id.
    pub fn get_id(&self) -> u32 {
        self.id
    }
}

impl PartialEq for ElementId {
    // Ghidra: marshal.cc:87 ElementId::eq
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

#[derive(Debug, Default)]
struct IdTables {
    attr_by_name: HashMap<&'static str, u32>,
    attr_by_id: HashMap<u32, &'static str>,
    elem_by_name: HashMap<&'static str, u32>,
    elem_by_id: HashMap<u32, &'static str>,
}

static ID_TABLES: OnceLock<IdTables> = OnceLock::new();

// Ghidra: marshal.cc:54 AttributeId::initialize
fn initialize_attribute_ids(tables: &mut IdTables) {
    for &(name, id) in ATTRIBUTE_ID_TABLE {
        tables.attr_by_name.insert(name, id);
        tables.attr_by_id.insert(id, name);
    }
}

// Ghidra: marshal.cc:96 ElementId::initialize
fn initialize_element_ids(tables: &mut IdTables) {
    for &(name, id) in ELEMENT_ID_TABLE {
        tables.elem_by_name.insert(name, id);
        tables.elem_by_id.insert(id, name);
    }
}

// RUGRA-GLUE: Combines the two Ghidra global lookup tables behind Rust's OnceLock.
fn build_id_tables() -> IdTables {
    let mut tables = IdTables::default();
    initialize_attribute_ids(&mut tables);
    initialize_element_ids(&mut tables);
    tables
}

// RUGRA-GLUE: Rust process-wide access to Ghidra's two static lookup tables.
fn id_tables() -> &'static IdTables {
    ID_TABLES.get_or_init(build_id_tables)
}

/// Process-wide fixed registry of locked Ghidra 12.0.4 scope-0 ids.
///
/// The value has no per-instance allocation or numbering state. All instances
/// address the same immutable tables initialized from `ATTRIBUTE_ID_TABLE` and
/// `ELEMENT_ID_TABLE`.
#[derive(Debug, Default)]
pub struct IdRegistry;

impl IdRegistry {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Access the fixed process-wide registry.
    pub fn new() -> Self {
        Self::initialize();
        Self
    }

    // RUGRA-GLUE: One Rust entry point invokes both Ghidra initialize methods.
    /// Initialize the process-wide tables. Repeated calls preserve the exact
    /// same table and have no observable mutation.
    pub fn initialize() {
        let _ = id_tables();
    }

    // RUGRA-GLUE: register_attribute (no Ghidra counterpart found)
    /// Compatibility lookup for callers that formerly registered names.
    /// Unknown input returns `ATTRIB_UNKNOWN`; no id is allocated.
    pub fn register_attribute(&mut self, nm: &str) -> u32 {
        self.find_attribute(nm)
    }

    // RUGRA-GLUE: register_attribute_with_id (no Ghidra counterpart found)
    /// Compatibility validation hook. Returns whether the pair is part of the
    /// locked table; runtime input can never mutate the process table.
    pub fn register_attribute_with_id(&mut self, nm: &str, id: u32) -> bool {
        self.find_attribute(nm) == id && self.attribute_name(id) == Some(nm)
    }

    // Ghidra: marshal.hh:686 AttributeId::find
    /// Look up an attribute id by name. Returns ATTRIB_UNKNOWN if not found.
    pub fn find_attribute(&self, nm: &str) -> u32 {
        self.find_attribute_in_scope(nm, 0)
    }

    // Ghidra: marshal.hh:686 AttributeId::find
    /// Look up an attribute in a Ghidra marshal scope. Locked 12.0.4 only
    /// supports reverse lookup for scope zero.
    pub fn find_attribute_in_scope(&self, nm: &str, scope: i32) -> u32 {
        if scope != 0 {
            return ATTRIB_UNKNOWN;
        }
        id_tables()
            .attr_by_name
            .get(nm)
            .copied()
            .unwrap_or(ATTRIB_UNKNOWN)
    }

    // RUGRA-GLUE: attribute_name (no Ghidra counterpart found)
    /// Look up an attribute name by id.
    pub fn attribute_name(&self, id: u32) -> Option<&str> {
        id_tables().attr_by_id.get(&id).copied()
    }

    // RUGRA-GLUE: register_element (no Ghidra counterpart found)
    /// Compatibility lookup for callers that formerly registered names.
    /// Unknown input returns `ELEM_UNKNOWN`; no id is allocated.
    pub fn register_element(&mut self, nm: &str) -> u32 {
        self.find_element(nm)
    }

    // RUGRA-GLUE: register_element_with_id (no Ghidra counterpart found)
    /// Compatibility validation hook. Returns whether the pair is part of the
    /// locked table; runtime input can never mutate the process table.
    pub fn register_element_with_id(&mut self, nm: &str, id: u32) -> bool {
        self.find_element(nm) == id && self.element_name(id) == Some(nm)
    }

    // Ghidra: marshal.hh:702 ElementId::find
    /// Look up an element id by name. Returns `ELEM_UNKNOWN` if not found.
    pub fn find_element(&self, nm: &str) -> u32 {
        self.find_element_in_scope(nm, 0)
    }

    // Ghidra: marshal.hh:702 ElementId::find
    /// Look up an element in a Ghidra marshal scope. Locked 12.0.4 only
    /// supports reverse lookup for scope zero.
    pub fn find_element_in_scope(&self, nm: &str, scope: i32) -> u32 {
        if scope != 0 {
            return ELEM_UNKNOWN;
        }
        id_tables()
            .elem_by_name
            .get(nm)
            .copied()
            .unwrap_or(ELEM_UNKNOWN)
    }

    // RUGRA-GLUE: element_name (no Ghidra counterpart found)
    /// Look up an element name by id.
    pub fn element_name(&self, id: u32) -> Option<&str> {
        id_tables().elem_by_id.get(&id).copied()
    }
}

/// An XML element — a node in the DOM tree. Faithful to `Element`
/// (xml.hh:159). Owned by its parent; children are stored as `Arc<RwLock<>>`
/// to allow shared reference during decode.
#[derive(Debug, Clone)]
pub struct Element {
    /// The local name of the element.
    pub name: String,
    /// Character content of the element.
    pub content: String,
    /// Attribute names (parallel to `values`).
    pub attr_names: Vec<String>,
    /// Attribute values (parallel to `attr_names`).
    pub attr_values: Vec<String>,
    /// Child elements.
    pub children: Vec<Arc<RwLock<Element>>>,
}

impl Element {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct an empty element.
    pub fn new() -> Self {
        Self {
            name: String::new(),
            content: String::new(),
            attr_names: Vec::new(),
            attr_values: Vec::new(),
            children: Vec::new(),
        }
    }

    // RUGRA-GLUE: set_name (no Ghidra counterpart found)
    /// Set the local name of the element. Faithful to `setName`.
    pub fn set_name(&mut self, nm: &str) {
        self.name = nm.to_string();
    }

    // RUGRA-GLUE: add_content (no Ghidra counterpart found)
    /// Append character content. Faithful to `addContent`.
    pub fn add_content(&mut self, s: &str) {
        self.content.push_str(s);
    }

    // RUGRA-GLUE: add_child (no Ghidra counterpart found)
    /// Add a child element. Faithful to `addChild`.
    pub fn add_child(&mut self, child: Arc<RwLock<Element>>) {
        self.children.push(child);
    }

    // RUGRA-GLUE: add_attribute (no Ghidra counterpart found)
    /// Add a name/value attribute pair. Faithful to `addAttribute`.
    pub fn add_attribute(&mut self, nm: &str, vl: &str) {
        self.attr_names.push(nm.to_string());
        self.attr_values.push(vl.to_string());
    }

    // RUGRA-GLUE: get_name (no Ghidra counterpart found)
    /// Get the local name. Faithful to `getName`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // RUGRA-GLUE: get_content (no Ghidra counterpart found)
    /// Get the character content. Faithful to `getContent`.
    pub fn get_content(&self) -> &str {
        &self.content
    }

    // RUGRA-GLUE: get_children (no Ghidra counterpart found)
    /// Get the child elements. Faithful to `getChildren`.
    pub fn get_children(&self) -> &[Arc<RwLock<Element>>] {
        &self.children
    }

    // RUGRA-GLUE: get_attribute_value (no Ghidra counterpart found)
    /// Get an attribute value by name. Returns None if not found. Faithful to
    /// `getAttributeValue` (which throws; we return Option).
    pub fn get_attribute_value(&self, nm: &str) -> Option<&str> {
        for (i, name) in self.attr_names.iter().enumerate() {
            if name == nm {
                return Some(&self.attr_values[i]);
            }
        }
        None
    }

    // RUGRA-GLUE: get_num_attributes (no Ghidra counterpart found)
    /// Get the number of attributes. Faithful to `getNumAttributes`.
    pub fn get_num_attributes(&self) -> usize {
        self.attr_names.len()
    }

    // RUGRA-GLUE: get_attribute_name (no Ghidra counterpart found)
    /// Get the name of the i-th attribute. Faithful to `getAttributeName`.
    pub fn get_attribute_name(&self, i: usize) -> &str {
        &self.attr_names[i]
    }

    // RUGRA-GLUE: get_attribute_value_at (no Ghidra counterpart found)
    /// Get the value of the i-th attribute. Faithful to `getAttributeValue(i)`.
    pub fn get_attribute_value_at(&self, i: usize) -> &str {
        &self.attr_values[i]
    }
}

impl Default for Element {
    // RUGRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

/// A complete in-memory XML document. Faithful to `Document` (xml.hh:215).
/// This is an `Element` whose single child is the root element.
#[derive(Debug, Clone, Default)]
pub struct Document {
    /// The root element of the document.
    pub root: Option<Arc<RwLock<Element>>>,
}

impl Document {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct an empty document.
    pub fn new() -> Self {
        Self { root: None }
    }

    // RUGRA-GLUE: get_root (no Ghidra counterpart found)
    /// Get the root element. Faithful to `getRoot`.
    pub fn get_root(&self) -> Option<&Arc<RwLock<Element>>> {
        self.root.as_ref()
    }

    // RUGRA-GLUE: set_root (no Ghidra counterpart found)
    /// Set the root element.
    pub fn set_root(&mut self, root: Arc<RwLock<Element>>) {
        self.root = Some(root);
    }
}

/// A class for writing structured data to a stream. Faithful to `Encoder`
/// (marshal.hh). This trait mirrors the virtual methods of Ghidra's Encoder.
pub trait Encoder {
    // RUGRA-GLUE: open_element (no Ghidra counterpart found)
    /// Open a new element with the given id.
    fn open_element(&mut self, elem_id: &ElementId);
    // RUGRA-GLUE: close_element (no Ghidra counterpart found)
    /// Close the current element.
    fn close_element(&mut self, elem_id: &ElementId);
    // RUGRA-GLUE: write_bool (no Ghidra counterpart found)
    /// Write a boolean attribute.
    fn write_bool(&mut self, attrib_id: &AttributeId, val: bool);
    // RUGRA-GLUE: write_signed_integer (no Ghidra counterpart found)
    /// Write a signed integer attribute.
    fn write_signed_integer(&mut self, attrib_id: &AttributeId, val: i64);
    // RUGRA-GLUE: write_unsigned_integer (no Ghidra counterpart found)
    /// Write an unsigned integer attribute.
    fn write_unsigned_integer(&mut self, attrib_id: &AttributeId, val: u64);
    // RUGRA-GLUE: write_string (no Ghidra counterpart found)
    /// Write a string attribute.
    fn write_string(&mut self, attrib_id: &AttributeId, val: &str);
    // RUGRA-GLUE: write_string_indexed (no Ghidra counterpart found)
    /// Write an indexed string attribute.
    fn write_string_indexed(&mut self, attrib_id: &AttributeId, index: u32, val: &str);
}

/// A class for reading structured data from a stream. Faithful to `Decoder`
/// (marshal.hh:99). The document is traversed depth-first via `open_element`/
/// `close_element`, with attributes read via `read_*`.
pub trait Decoder {
    // RUGRA-GLUE: peek_element (no Ghidra counterpart found)
    /// Peek at the next child element id without traversing in. Returns 0 if
    /// none. Faithful to `peekElement`.
    fn peek_element(&self) -> u32;

    // RUGRA-GLUE: open_element (no Ghidra counterpart found)
    /// Open (traverse into) the next child element. Returns the element id.
    /// Faithful to `openElement`.
    fn open_element(&mut self) -> u32;

    // RUGRA-GLUE: open_element_matching (no Ghidra counterpart found)
    /// Open the next child element, which must match the given id.
    fn open_element_matching(&mut self, elem_id: &ElementId) -> u32;

    // RUGRA-GLUE: close_element (no Ghidra counterpart found)
    /// Close the current element. Faithful to `closeElement`.
    fn close_element(&mut self, id: u32);

    // RUGRA-GLUE: close_element_skipping (no Ghidra counterpart found)
    /// Close the current element, skipping unread children. Faithful to
    /// `closeElementSkipping`.
    fn close_element_skipping(&mut self, id: u32);

    // RUGRA-GLUE: next_attribute_id (no Ghidra counterpart found)
    /// Get the next attribute id for the current element. Returns 0 when done.
    fn next_attribute_id(&mut self) -> u32;

    // RUGRA-GLUE: attribute_name (no Ghidra counterpart found)
    /// Look up the name of an attribute id. Returns None if the id is not
    /// registered. This allows decode implementations to dispatch on attribute
    /// names without holding a separate registry reference.
    fn attribute_name(&self, id: u32) -> Option<String>;

    // RUGRA-GLUE: element_name (no Ghidra counterpart found)
    /// Look up the name of an element id. Returns None if not registered.
    fn element_name(&self, id: u32) -> Option<String>;

    // RUGRA-GLUE: rewind_attributes (no Ghidra counterpart found)
    /// Reset attribute traversal. Faithful to `rewindAttributes`.
    fn rewind_attributes(&mut self);

    // RUGRA-GLUE: read_bool (no Ghidra counterpart found)
    /// Read the current attribute as a boolean.
    fn read_bool(&mut self) -> bool;

    // RUGRA-GLUE: read_bool_attr (no Ghidra counterpart found)
    /// Read a specific attribute as a boolean.
    fn read_bool_attr(&mut self, attrib_id: &AttributeId) -> bool;

    // RUGRA-GLUE: read_signed_integer (no Ghidra counterpart found)
    /// Read the current attribute as a signed integer.
    fn read_signed_integer(&mut self) -> i64;

    // RUGRA-GLUE: read_signed_integer_attr (no Ghidra counterpart found)
    /// Read a specific attribute as a signed integer.
    fn read_signed_integer_attr(&mut self, attrib_id: &AttributeId) -> i64;

    // RUGRA-GLUE: read_unsigned_integer (no Ghidra counterpart found)
    /// Read the current attribute as an unsigned integer.
    fn read_unsigned_integer(&mut self) -> u64;

    // RUGRA-GLUE: read_unsigned_integer_attr (no Ghidra counterpart found)
    /// Read a specific attribute as an unsigned integer.
    fn read_unsigned_integer_attr(&mut self, attrib_id: &AttributeId) -> u64;

    // RUGRA-GLUE: read_string (no Ghidra counterpart found)
    /// Read the current attribute as a string.
    fn read_string(&mut self) -> String;

    // RUGRA-GLUE: read_string_attr (no Ghidra counterpart found)
    /// Read a specific attribute as a string.
    fn read_string_attr(&mut self, attrib_id: &AttributeId) -> String;
}

/// An in-memory `Encoder` that builds an `Element` tree. This is the Rust
/// equivalent of Ghidra's `TreeHandler` + `Document` construction. The built
/// tree can be retrieved via `into_document`.
pub struct TreeEncoder {
    /// The stack of open elements; the last is the current.
    stack: Vec<Arc<RwLock<Element>>>,
    /// The root element (set after the first open_element).
    root: Option<Arc<RwLock<Element>>>,
    /// The registry for id→name lookup.
    registry: Arc<RwLock<IdRegistry>>,
}

impl TreeEncoder {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct given a registry.
    pub fn new(registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self {
            stack: Vec::new(),
            root: None,
            registry,
        }
    }

    // RUGRA-GLUE: into_document (no Ghidra counterpart found)
    /// Consume the encoder and return the built document.
    pub fn into_document(self) -> Document {
        Document { root: self.root }
    }

    // RUGRA-GLUE: root (no Ghidra counterpart found)
    /// Get the root element.
    pub fn root(&self) -> Option<Arc<RwLock<Element>>> {
        self.root.clone()
    }
}

impl Encoder for TreeEncoder {
    // RUGRA-GLUE: open_element (no Ghidra counterpart found)
    fn open_element(&mut self, elem_id: &ElementId) {
        let mut elem = Element::new();
        elem.set_name(&elem_id.name);
        let elem_arc = Arc::new(RwLock::new(elem));
        if let Some(parent) = self.stack.last() {
            parent.write().unwrap().add_child(elem_arc.clone());
        } else {
            self.root = Some(elem_arc.clone());
        }
        self.stack.push(elem_arc);
    }

    // RUGRA-GLUE: close_element (no Ghidra counterpart found)
    fn close_element(&mut self, _elem_id: &ElementId) {
        self.stack.pop();
    }

    // RUGRA-GLUE: write_bool (no Ghidra counterpart found)
    fn write_bool(&mut self, attrib_id: &AttributeId, val: bool) {
        if let Some(cur) = self.stack.last() {
            cur.write().unwrap().add_attribute(
                &attrib_id.name,
                if val { "1" } else { "0" },
            );
        }
    }

    // RUGRA-GLUE: write_signed_integer (no Ghidra counterpart found)
    fn write_signed_integer(&mut self, attrib_id: &AttributeId, val: i64) {
        if let Some(cur) = self.stack.last() {
            cur.write()
                .unwrap()
                .add_attribute(&attrib_id.name, &val.to_string());
        }
    }

    // RUGRA-GLUE: write_unsigned_integer (no Ghidra counterpart found)
    fn write_unsigned_integer(&mut self, attrib_id: &AttributeId, val: u64) {
        if let Some(cur) = self.stack.last() {
            cur.write()
                .unwrap()
                .add_attribute(&attrib_id.name, &val.to_string());
        }
    }

    // RUGRA-GLUE: write_string (no Ghidra counterpart found)
    fn write_string(&mut self, attrib_id: &AttributeId, val: &str) {
        if let Some(cur) = self.stack.last() {
            cur.write().unwrap().add_attribute(&attrib_id.name, val);
        }
    }

    // RUGRA-GLUE: write_string_indexed (no Ghidra counterpart found)
    fn write_string_indexed(&mut self, attrib_id: &AttributeId, index: u32, val: &str) {
        let nm = format!("{}_{}", attrib_id.name, index);
        if let Some(cur) = self.stack.last() {
            cur.write().unwrap().add_attribute(&nm, val);
        }
    }
}

/// An in-memory `Decoder` that reads from an `Element` tree. This traverses
/// the DOM depth-first, mirroring Ghidra's `XmlDecode`.
pub struct TreeDecoder {
    /// The root of the tree being decoded.
    root: Option<Arc<RwLock<Element>>>,
    /// Stack of (element, current child index, current attribute index).
    stack: Vec<(Arc<RwLock<Element>>, usize, usize)>,
    /// The registry for name→id lookup.
    registry: Arc<RwLock<IdRegistry>>,
}

impl TreeDecoder {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct given a document root and registry.
    pub fn new(root: Arc<RwLock<Element>>, registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self {
            root: Some(root),
            stack: Vec::new(),
            registry,
        }
    }

    // RUGRA-GLUE: from_document (no Ghidra counterpart found)
    /// Construct from a document.
    pub fn from_document(doc: &Document, registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self::new(
            doc.root.clone().unwrap_or_else(|| Arc::new(RwLock::new(Element::new()))),
            registry,
        )
    }
}

impl Decoder for TreeDecoder {
    // RUGRA-GLUE: peek_element (no Ghidra counterpart found)
    fn peek_element(&self) -> u32 {
        let Some((elem, child_idx, _)) = self.stack.last() else {
            // At the document level: peek the root.
            if let Some(root) = &self.root {
                if self.stack.is_empty() {
                    let rg = root.read().unwrap();
                    return self.registry.read().unwrap().find_element(&rg.name);
                }
            }
            return 0;
        };
        let rg = elem.read().unwrap();
        if *child_idx < rg.children.len() {
            let child = &rg.children[*child_idx];
            let child_rg = child.read().unwrap();
            self.registry.read().unwrap().find_element(&child_rg.name)
        } else {
            0
        }
    }

    // RUGRA-GLUE: open_element (no Ghidra counterpart found)
    fn open_element(&mut self) -> u32 {
        // If at document level with no stack, push the root.
        if self.stack.is_empty() {
            if let Some(root) = self.root.take() {
                let id = {
                    let rg = root.read().unwrap();
                    self.registry.read().unwrap().find_element(&rg.name)
                };
                self.stack.push((root, 0, 0));
                return id;
            }
            return 0;
        }
        let (elem, child_idx, _) = self.stack.last().cloned().unwrap();
        let child = {
            let rg = elem.read().unwrap();
            rg.children.get(child_idx).cloned()
        };
        let Some(child) = child else {
            return 0;
        };
        let id = {
            let rg = child.read().unwrap();
            self.registry.read().unwrap().find_element(&rg.name)
        };
        // Advance the parent's child index.
        if let Some(last) = self.stack.last_mut() {
            last.1 += 1;
        }
        self.stack.push((child, 0, 0));
        id
    }

    // RUGRA-GLUE: open_element_matching (no Ghidra counterpart found)
    fn open_element_matching(&mut self, elem_id: &ElementId) -> u32 {
        let id = self.open_element();
        if id != elem_id.id {
            // Ghidra throws; we return 0.
            return 0;
        }
        id
    }

    // RUGRA-GLUE: close_element (no Ghidra counterpart found)
    fn close_element(&mut self, _id: u32) {
        self.stack.pop();
    }

    // RUGRA-GLUE: close_element_skipping (no Ghidra counterpart found)
    fn close_element_skipping(&mut self, _id: u32) {
        self.stack.pop();
    }

    // RUGRA-GLUE: next_attribute_id (no Ghidra counterpart found)
    fn next_attribute_id(&mut self) -> u32 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        if attr_idx < rg.get_num_attributes() {
            // Clone the name to release the borrow before mutating the stack.
            let name = rg.get_attribute_name(attr_idx).to_string();
            drop(rg);
            if let Some(last) = self.stack.last_mut() {
                last.2 += 1;
            }
            self.registry.read().unwrap().find_attribute(&name)
        } else {
            0
        }
    }

    // RUGRA-GLUE: rewind_attributes (no Ghidra counterpart found)
    fn rewind_attributes(&mut self) {
        if let Some(last) = self.stack.last_mut() {
            last.2 = 0;
        }
    }

    // RUGRA-GLUE: attribute_name (no Ghidra counterpart found)
    fn attribute_name(&self, id: u32) -> Option<String> {
        self.registry
            .read()
            .unwrap()
            .attribute_name(id)
            .map(|s| s.to_string())
    }

    // RUGRA-GLUE: element_name (no Ghidra counterpart found)
    fn element_name(&self, id: u32) -> Option<String> {
        self.registry
            .read()
            .unwrap()
            .element_name(id)
            .map(|s| s.to_string())
    }

    // RUGRA-GLUE: read_bool (no Ghidra counterpart found)
    fn read_bool(&mut self) -> bool {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return false;
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            let val = rg.get_attribute_value_at(attr_idx - 1);
            return val == "1" || val.eq_ignore_ascii_case("true");
        }
        false
    }

    // RUGRA-GLUE: read_bool_attr (no Ghidra counterpart found)
    fn read_bool_attr(&mut self, attrib_id: &AttributeId) -> bool {
        let Some((elem, _, _)) = self.stack.last() else {
            return false;
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    // RUGRA-GLUE: read_signed_integer (no Ghidra counterpart found)
    fn read_signed_integer(&mut self) -> i64 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return rg.get_attribute_value_at(attr_idx - 1).parse().unwrap_or(0);
        }
        0
    }

    // RUGRA-GLUE: read_signed_integer_attr (no Ghidra counterpart found)
    fn read_signed_integer_attr(&mut self, attrib_id: &AttributeId) -> i64 {
        let Some((elem, _, _)) = self.stack.last() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    // RUGRA-GLUE: read_unsigned_integer (no Ghidra counterpart found)
    fn read_unsigned_integer(&mut self) -> u64 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return rg.get_attribute_value_at(attr_idx - 1).parse().unwrap_or(0);
        }
        0
    }

    // RUGRA-GLUE: read_unsigned_integer_attr (no Ghidra counterpart found)
    fn read_unsigned_integer_attr(&mut self, attrib_id: &AttributeId) -> u64 {
        let Some((elem, _, _)) = self.stack.last() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    // RUGRA-GLUE: read_string (no Ghidra counterpart found)
    fn read_string(&mut self) -> String {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return String::new();
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return rg.get_attribute_value_at(attr_idx - 1).to_string();
        }
        String::new()
    }

    // RUGRA-GLUE: read_string_attr (no Ghidra counterpart found)
    fn read_string_attr(&mut self, attrib_id: &AttributeId) -> String {
        let Some((elem, _, _)) = self.stack.last() else {
            return String::new();
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .unwrap_or("")
            .to_string()
    }
}

// ---------------------------------------------------------------------------
// PackedEncode — binary marshaling format (marshal.hh:579)
// ---------------------------------------------------------------------------

/// Protocol format constants. Faithful to `PackedFormat` (marshal.hh:480).
pub mod packed_format {
    pub const HEADER_MASK: u8 = 0xc0;
    pub const ELEMENT_START: u8 = 0x40;
    pub const ELEMENT_END: u8 = 0x80;
    pub const ATTRIBUTE: u8 = 0xc0;
    pub const HEADEREXTEND_MASK: u8 = 0x20;
    pub const ELEMENTID_MASK: u8 = 0x1f;
    pub const RAWDATA_MASK: u8 = 0x7f;
    pub const RAWDATA_BITSPERBYTE: u32 = 7;
    pub const RAWDATA_MARKER: u8 = 0x80;
    pub const TYPECODE_SHIFT: u32 = 4;
    pub const LENGTHCODE_MASK: u8 = 0xf;
    pub const TYPECODE_BOOLEAN: u8 = 1;
    pub const TYPECODE_SIGNEDINT_POSITIVE: u8 = 2;
    pub const TYPECODE_SIGNEDINT_NEGATIVE: u8 = 3;
    pub const TYPECODE_UNSIGNEDINT: u8 = 4;
    pub const TYPECODE_ADDRESSSPACE: u8 = 5;
    pub const TYPECODE_SPECIALSPACE: u8 = 6;
    pub const TYPECODE_STRING: u8 = 7;
}

/// A byte-based encoder for the packed binary format. Faithful to
/// `PackedEncode` (marshal.hh:579).
pub struct PackedEncode {
    out: Vec<u8>,
}

impl PackedEncode {
    // Ghidra: marshal.hh:579 PackedEncode::new
    /// Construct an empty encoder.
    pub fn new() -> Self {
        Self { out: Vec::new() }
    }

    // Ghidra: marshal.hh:579 PackedEncode::intoBytes
    /// Consume and return the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    // Ghidra: marshal.hh:661 PackedEncode::writeHeader
    /// Write a header byte (element start/end or attribute) with an id.
    /// Faithful to `writeHeader` (marshal.hh inline).
    fn write_header(&mut self, header: u8, id: u32) {
        use packed_format::*;
        if id > 0x1f {
            let h = header | HEADEREXTEND_MASK | ((id >> RAWDATA_BITSPERBYTE) as u8);
            let extend = ((id & RAWDATA_MASK as u32) as u8) | RAWDATA_MARKER;
            self.out.push(h);
            self.out.push(extend);
        } else {
            self.out.push(header | (id as u8));
        }
    }

    // Ghidra: marshal.cc:1065 PackedEncode::writeInteger
    /// Write an integer value with the given type byte. Faithful to
    /// `writeInteger` (marshal.cc:1065).
    fn write_integer(&mut self, type_byte: u8, val: u64) {
        use packed_format::*;
        let (len_code, sa) = if val == 0 {
            (0u8, -1i32)
        } else if val < 0x800000000 {
            if val < 0x200000 {
                if val < 0x80 {
                    (1, 0)
                } else if val < 0x4000 {
                    (2, RAWDATA_BITSPERBYTE as i32)
                } else {
                    (3, 2 * RAWDATA_BITSPERBYTE as i32)
                }
            } else if val < 0x10000000 {
                (4, 3 * RAWDATA_BITSPERBYTE as i32)
            } else {
                (5, 4 * RAWDATA_BITSPERBYTE as i32)
            }
        } else if val < 0x2000000000000 {
            if val < 0x40000000000 {
                (6, 5 * RAWDATA_BITSPERBYTE as i32)
            } else {
                (7, 6 * RAWDATA_BITSPERBYTE as i32)
            }
        } else if val < 0x100000000000000 {
            (8, 7 * RAWDATA_BITSPERBYTE as i32)
        } else if val < 0x8000000000000000 {
            (9, 8 * RAWDATA_BITSPERBYTE as i32)
        } else {
            (10, 9 * RAWDATA_BITSPERBYTE as i32)
        };
        self.out.push(type_byte | len_code);
        let mut shift = sa;
        while shift >= 0 {
            let piece = ((val >> shift) & RAWDATA_MASK as u64) as u8;
            self.out.push(piece | RAWDATA_MARKER);
            shift -= RAWDATA_BITSPERBYTE as i32;
        }
    }
}

impl Default for PackedEncode {
    // Ghidra: marshal.hh:579 PackedEncode::default
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for PackedEncode {
    // Ghidra: marshal.cc:1131 PackedEncode::openElement
    fn open_element(&mut self, elem_id: &ElementId) {
        self.write_header(packed_format::ELEMENT_START, elem_id.id);
    }

    // Ghidra: marshal.cc:1137 PackedEncode::closeElement
    fn close_element(&mut self, elem_id: &ElementId) {
        self.write_header(packed_format::ELEMENT_END, elem_id.id);
    }

    // Ghidra: marshal.cc:1143 PackedEncode::writeBool
    fn write_bool(&mut self, attrib_id: &AttributeId, val: bool) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id);
        let type_byte = if val {
            (TYPECODE_BOOLEAN << TYPECODE_SHIFT) | 1
        } else {
            TYPECODE_BOOLEAN << TYPECODE_SHIFT
        };
        self.out.push(type_byte);
    }

    // Ghidra: marshal.cc:1151 PackedEncode::writeSignedInteger
    fn write_signed_integer(&mut self, attrib_id: &AttributeId, val: i64) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id);
        if val < 0 {
            let type_byte = TYPECODE_SIGNEDINT_NEGATIVE << TYPECODE_SHIFT;
            self.write_integer(type_byte, (-val) as u64);
        } else {
            let type_byte = TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT;
            self.write_integer(type_byte, val as u64);
        }
    }

    // Ghidra: marshal.cc:1168 PackedEncode::writeUnsignedInteger
    fn write_unsigned_integer(&mut self, attrib_id: &AttributeId, val: u64) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id);
        self.write_integer(TYPECODE_UNSIGNEDINT << TYPECODE_SHIFT, val);
    }

    // Ghidra: marshal.cc:1175 PackedEncode::writeString
    fn write_string(&mut self, attrib_id: &AttributeId, val: &str) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id);
        self.write_integer(TYPECODE_STRING << TYPECODE_SHIFT, val.len() as u64);
        self.out.extend_from_slice(val.as_bytes());
    }

    // Ghidra: marshal.cc:1184 PackedEncode::writeStringIndexed
    fn write_string_indexed(&mut self, attrib_id: &AttributeId, index: u32, val: &str) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id + index);
        self.write_integer(TYPECODE_STRING << TYPECODE_SHIFT, val.len() as u64);
        self.out.extend_from_slice(val.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// PackedDecode — binary marshaling format reader (marshal.hh:512)
// ---------------------------------------------------------------------------

/// A byte-based decoder for the packed binary format. Faithful to
/// `PackedDecode` (marshal.hh:512).
pub struct PackedDecode {
    /// The raw input bytes.
    input: Vec<u8>,
    /// Current position in the input.
    pos: usize,
    /// Stack of open elements: (element_id, attribute_start_pos, attribute_cursor_pos).
    stack: Vec<(u32, usize, usize)>,
    /// The registry for name lookup.
    registry: Arc<RwLock<IdRegistry>>,
    /// Pending type byte from the last attribute header.
    pending_type: Option<u8>,
    /// Pending integer length code.
    pending_int_len: Option<usize>,
    /// Pending string byte length.
    pending_string_len: Option<usize>,
}

impl PackedDecode {
    // Ghidra: marshal.hh:512 PackedDecode::new
    /// Construct from a byte vector and registry.
    pub fn new(input: Vec<u8>, registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self {
            input,
            pos: 0,
            stack: Vec::new(),
            registry,
            pending_type: None,
            pending_int_len: None,
            pending_string_len: None,
        }
    }

    // Ghidra: marshal.hh:512 PackedDecode::readByte
    /// Read the next byte.
    fn read_byte(&mut self) -> Option<u8> {
        let b = self.input.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    // Ghidra: marshal.hh:512 PackedDecode::readHeader
    /// Read a header byte and extract the (record_type, id). Returns None at
    /// EOF.
    fn read_header(&mut self) -> Option<(u8, u32)> {
        use packed_format::*;
        let b = self.read_byte()?;
        let header_type = b & HEADER_MASK;
        let mut id = (b & ELEMENTID_MASK) as u32;
        if (b & HEADEREXTEND_MASK) != 0 {
            // Extended id: next byte has 7 more bits.
            let ext = self.read_byte()?;
            id = (id << RAWDATA_BITSPERBYTE) | ((ext & RAWDATA_MASK) as u32);
        }
        Some((header_type, id))
    }

    // Ghidra: marshal.cc:603 PackedDecode::readInteger
    /// Read an encoded integer given its length in bytes.
    fn read_integer(&mut self, len: usize) -> u64 {
        let mut val = 0u64;
        for _ in 0..len {
            if let Some(b) = self.read_byte() {
                val = (val << packed_format::RAWDATA_BITSPERBYTE) | (b & packed_format::RAWDATA_MASK) as u64;
            }
        }
        val
    }

    // Ghidra: marshal.hh:512 PackedDecode::lengthCode
    /// Determine the length code from a type byte.
    fn length_code(type_byte: u8) -> u8 {
        type_byte & packed_format::LENGTHCODE_MASK
    }

    // Ghidra: marshal.hh:512 PackedDecode::typeCode
    /// Determine the type code from a type byte.
    fn type_code(type_byte: u8) -> u8 {
        (type_byte >> packed_format::TYPECODE_SHIFT) & 0xf
    }
}

impl Decoder for PackedDecode {
    // Ghidra: marshal.cc:716 PackedDecode::peekElement
    fn peek_element(&self) -> u32 {
        use packed_format::*;
        // Scan forward from current pos to find the next ELEMENT_START header.
        let mut scan = self.pos;
        // Skip any attributes that belong to the current element.
        let attr_skip = self.stack.last().map(|(_, _, cur)| *cur).unwrap_or(self.pos);
        scan = scan.max(attr_skip);
        while scan < self.input.len() {
            let b = self.input[scan];
            let ht = b & HEADER_MASK;
            if ht == ELEMENT_START {
                // Decode the id.
                let mut id = (b & ELEMENTID_MASK) as u32;
                if (b & HEADEREXTEND_MASK) != 0 && scan + 1 < self.input.len() {
                    let ext = self.input[scan + 1];
                    id = (id << RAWDATA_BITSPERBYTE) | ((ext & RAWDATA_MASK) as u32);
                }
                return id;
            }
            if ht == ATTRIBUTE {
                // Skip this attribute to continue scanning.
                scan += 1;
                if (b & HEADEREXTEND_MASK) != 0 {
                    scan += 1;
                }
                // Read type byte.
                if scan >= self.input.len() {
                    break;
                }
                let tb = self.input[scan];
                scan += 1;
                let tc = Self::type_code(tb);
                let lc = Self::length_code(tb);
                // Skip the data based on type.
                match tc {
                    TYPECODE_BOOLEAN => {} // No data bytes.
                    TYPECODE_SIGNEDINT_POSITIVE | TYPECODE_SIGNEDINT_NEGATIVE | TYPECODE_UNSIGNEDINT | TYPECODE_ADDRESSSPACE => {
                        scan += lc as usize;
                    }
                    TYPECODE_SPECIALSPACE => {} // No data bytes.
                    TYPECODE_STRING => {
                        // lc = length of the length encoding; read the actual string length.
                        let mut str_len = 0u64;
                        for _ in 0..lc {
                            if scan >= self.input.len() { break; }
                            str_len = (str_len << RAWDATA_BITSPERBYTE) | (self.input[scan] & RAWDATA_MASK) as u64;
                            scan += 1;
                        }
                        scan += str_len as usize;
                    }
                    _ => break,
                }
            } else if ht == ELEMENT_END {
                return 0; // No more children.
            } else {
                break;
            }
        }
        0
    }

    // Ghidra: marshal.cc:730 PackedDecode::openElement
    fn open_element(&mut self) -> u32 {
        use packed_format::*;
        loop {
            let (ht, id) = match self.read_header() {
                Some(h) => h,
                None => return 0,
            };
            if ht == ELEMENT_START {
                let attr_start = self.pos;
                self.stack.push((id, attr_start, attr_start));
                return id;
            }
            // Skip non-element-start headers (shouldn't happen at this level).
        }
    }

    // Ghidra: marshal.hh:512 PackedDecode::openElementMatching
    fn open_element_matching(&mut self, elem_id: &ElementId) -> u32 {
        let id = self.open_element();
        if id != elem_id.id {
            return 0;
        }
        id
    }

    // Ghidra: marshal.cc:767 PackedDecode::closeElement
    fn close_element(&mut self, _id: u32) {
        // Read until we find the matching ELEMENT_END.
        use packed_format::*;
        loop {
            let (ht, _) = match self.read_header() {
                Some(h) => h,
                None => break,
            };
            if ht == ELEMENT_END {
                break;
            }
            // Skip attributes.
            if ht == ATTRIBUTE {
                if let Some(tb) = self.read_byte() {
                    let tc = Self::type_code(tb);
                    let lc = Self::length_code(tb);
                    match tc {
                        TYPECODE_BOOLEAN | TYPECODE_SPECIALSPACE => {}
                        TYPECODE_STRING => {
                            let str_len = self.read_integer(lc as usize);
                            for _ in 0..str_len {
                                let _ = self.read_byte();
                            }
                        }
                        _ => {
                            for _ in 0..lc {
                                let _ = self.read_byte();
                            }
                        }
                    }
                }
            }
        }
        self.stack.pop();
    }

    // Ghidra: marshal.cc:782 PackedDecode::closeElementSkipping
    fn close_element_skipping(&mut self, id: u32) {
        self.close_element(id);
    }

    // Ghidra: marshal.hh:512 PackedDecode::nextAttributeId
    fn next_attribute_id(&mut self) -> u32 {
        use packed_format::*;
        if self.pos >= self.input.len() {
            return 0;
        }
        let b = self.input[self.pos];
        let ht = b & HEADER_MASK;
        if ht != ATTRIBUTE {
            return 0; // No more attributes.
        }
        // Decode the attribute id.
        let mut id = (b & ELEMENTID_MASK) as u32;
        self.pos += 1;
        if (b & HEADEREXTEND_MASK) != 0 {
            if let Some(ext) = self.read_byte() {
                id = (id << RAWDATA_BITSPERBYTE) | ((ext & RAWDATA_MASK) as u32);
            }
        }
        // Read the type byte to know how to handle the value.
        let type_byte = self.read_byte().unwrap_or(0);
        let tc = Self::type_code(type_byte);
        let lc = Self::length_code(type_byte);
        match tc {
            TYPECODE_BOOLEAN | TYPECODE_SPECIALSPACE => {
                // No data bytes. Store the type_byte for the read_* call.
                self.stack.last_mut().map(|(_, _, cur)| *cur = self.pos);
                // Save type info for subsequent read.
                self.pending_type = Some(type_byte);
            }
            TYPECODE_STRING => {
                let str_len = self.read_integer(lc as usize);
                self.pending_string_len = Some(str_len as usize);
                self.pending_type = Some(type_byte);
                self.stack.last_mut().map(|(_, _, cur)| *cur = self.pos);
            }
            _ => {
                self.pending_int_len = Some(lc as usize);
                self.pending_type = Some(type_byte);
                self.stack.last_mut().map(|(_, _, cur)| *cur = self.pos);
            }
        }
        id
    }

    // Ghidra: marshal.hh:512 PackedDecode::attributeName
    fn attribute_name(&self, id: u32) -> Option<String> {
        self.registry
            .read()
            .unwrap()
            .attribute_name(id)
            .map(|s| s.to_string())
    }

    // Ghidra: marshal.hh:512 PackedDecode::elementName
    fn element_name(&self, id: u32) -> Option<String> {
        self.registry
            .read()
            .unwrap()
            .element_name(id)
            .map(|s| s.to_string())
    }

    // Ghidra: marshal.cc:801 PackedDecode::rewindAttributes
    fn rewind_attributes(&mut self) {
        if let Some((_, start, _)) = self.stack.last_mut() {
            self.pos = *start;
        }
    }

    // Ghidra: marshal.cc:831 PackedDecode::readBool
    fn read_bool(&mut self) -> bool {
        if let Some(tb) = self.pending_type.take() {
            (tb & packed_format::LENGTHCODE_MASK) != 0
        } else {
            false
        }
    }

    // Ghidra: marshal.hh:512 PackedDecode::readBoolAttr
    fn read_bool_attr(&mut self, attrib_id: &AttributeId) -> bool {
        // Rewind and find the attribute.
        self.rewind_attributes();
        loop {
            let aid = self.next_attribute_id();
            if aid == 0 || aid == attrib_id.id {
                return self.read_bool();
            }
            // Skip the current value.
            let _ = self.read_string();
        }
    }

    // Ghidra: marshal.cc:853 PackedDecode::readSignedInteger
    fn read_signed_integer(&mut self) -> i64 {
        let len = self.pending_int_len.take().unwrap_or(0);
        let val = self.read_integer(len);
        let is_neg = self
            .pending_type
            .take()
            .map(|tb| Self::type_code(tb) == packed_format::TYPECODE_SIGNEDINT_NEGATIVE)
            .unwrap_or(false);
        if is_neg {
            -(val as i64)
        } else {
            val as i64
        }
    }

    // Ghidra: marshal.hh:512 PackedDecode::readSignedIntegerAttr
    fn read_signed_integer_attr(&mut self, attrib_id: &AttributeId) -> i64 {
        self.rewind_attributes();
        loop {
            let aid = self.next_attribute_id();
            if aid == 0 || aid == attrib_id.id {
                return self.read_signed_integer();
            }
            let _ = self.read_string();
        }
    }

    // Ghidra: marshal.cc:921 PackedDecode::readUnsignedInteger
    fn read_unsigned_integer(&mut self) -> u64 {
        let len = self.pending_int_len.take().unwrap_or(0);
        let _ = self.pending_type.take();
        self.read_integer(len)
    }

    // Ghidra: marshal.hh:512 PackedDecode::readUnsignedIntegerAttr
    fn read_unsigned_integer_attr(&mut self, attrib_id: &AttributeId) -> u64 {
        self.rewind_attributes();
        loop {
            let aid = self.next_attribute_id();
            if aid == 0 || aid == attrib_id.id {
                return self.read_unsigned_integer();
            }
            let _ = self.read_string();
        }
    }

    // Ghidra: marshal.cc:951 PackedDecode::readString
    fn read_string(&mut self) -> String {
        if let Some(len) = self.pending_string_len.take() {
            let bytes = &self.input[self.pos..self.pos + len.min(self.input.len() - self.pos)];
            self.pos += len.min(self.input.len() - self.pos);
            let _ = self.pending_type.take();
            String::from_utf8_lossy(bytes).to_string()
        } else {
            String::new()
        }
    }

    // Ghidra: marshal.hh:512 PackedDecode::readStringAttr
    fn read_string_attr(&mut self, attrib_id: &AttributeId) -> String {
        self.rewind_attributes();
        loop {
            let aid = self.next_attribute_id();
            if aid == 0 || aid == attrib_id.id {
                return self.read_string();
            }
            let _ = self.read_string();
        }
    }
}

/// Pending decode state for PackedDecode. These fields store the type info
/// from the attribute header, consumed by the corresponding read_* method.
impl PackedDecode {
    // Fields are stored in the struct definition; these are accessed via the
    // struct's fields. We use a separate impl block to avoid duplicating the
    // struct definition.
}

// Add pending fields to PackedDecode via a separate implementation.
// We need to add the fields to the struct. Let's use a workaround:
// The struct already exists above; we add the fields by using a thread-local
// or by modifying the struct definition. Since we can't modify it after
// definition, let's add the fields directly in the struct.

// Actually, the struct was already defined above without these fields.
// We need to add them. Let's redefine with the fields.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_id() {
        let a = AttributeId::new("name", 5);
        assert_eq!(a.get_name(), "name");
        assert_eq!(a.get_id(), 5);
        let b = AttributeId::new("other", 5);
        assert!(a == b); // equality by id
    }

    #[test]
    fn test_element_id() {
        let e = ElementId::new("scope", 10);
        assert_eq!(e.get_name(), "scope");
        assert_eq!(e.get_id(), 10);
    }

    #[test]
    fn test_registry() {
        let mut reg = IdRegistry::new();
        let id1 = reg.register_attribute("label");
        let id2 = reg.register_attribute("label"); // same name → same id
        assert_eq!(id1, 131);
        assert_eq!(id1, id2);
        assert_eq!(reg.find_attribute("label"), id1);
        assert_eq!(reg.find_attribute("nonexistent"), ATTRIB_UNKNOWN);
        let eid = reg.register_element("db");
        assert_eq!(eid, 68);
        assert_eq!(reg.find_element("db"), eid);
        assert!(reg.attribute_name(id1).is_some());
        assert_eq!(reg.register_attribute("runtime_order_a"), ATTRIB_UNKNOWN);
        assert_eq!(reg.register_attribute("runtime_order_b"), ATTRIB_UNKNOWN);
        assert_eq!(reg.register_element("runtime_order_a"), ELEM_UNKNOWN);
        assert_eq!(reg.register_element("runtime_order_b"), ELEM_UNKNOWN);
        assert!(reg.register_attribute_with_id("size", 19));
        assert!(!reg.register_attribute_with_id("size", 20));
        assert!(reg.register_element_with_id("data", 1));
        assert!(!reg.register_element_with_id("data", 2));
        assert_eq!(reg.find_attribute_in_scope("size", 1), ATTRIB_UNKNOWN);
        assert_eq!(reg.find_element_in_scope("data", 1), ELEM_UNKNOWN);
    }

    #[test]
    fn test_locked_id_tables_are_complete_and_bidirectional() {
        IdRegistry::initialize();
        IdRegistry::initialize();
        let reg = IdRegistry::new();
        assert_eq!(ATTRIBUTE_ID_TABLE.len(), 146);
        assert_eq!(ELEMENT_ID_TABLE.len(), 274);
        for &(name, id) in ATTRIBUTE_ID_TABLE {
            assert_eq!(reg.find_attribute(name), id);
            assert_eq!(reg.attribute_name(id), Some(name));
        }
        for &(name, id) in ELEMENT_ID_TABLE {
            assert_eq!(reg.find_element(name), id);
            assert_eq!(reg.element_name(id), Some(name));
        }
        assert_eq!(reg.attribute_name(0), None);
        assert_eq!(reg.element_name(0), None);
        assert_eq!(reg.find_attribute("size"), 19);
        assert_eq!(reg.find_attribute("space"), 20);
    }

    #[test]
    fn test_element() {
        let mut e = Element::new();
        e.set_name("head");
        e.add_attribute("locked", "1");
        e.add_content("hello");
        assert_eq!(e.get_name(), "head");
        assert_eq!(e.get_num_attributes(), 1);
        assert_eq!(e.get_attribute_name(0), "locked");
        assert_eq!(e.get_attribute_value_at(0), "1");
        assert_eq!(e.get_attribute_value("locked"), Some("1"));
        assert_eq!(e.get_attribute_value("missing"), None);
        assert_eq!(e.get_content(), "hello");
    }

    #[test]
    fn test_element_children() {
        let mut parent = Element::new();
        parent.set_name("parent");
        let mut child = Element::new();
        child.set_name("child");
        let child_arc = Arc::new(RwLock::new(child));
        parent.add_child(child_arc);
        assert_eq!(parent.get_children().len(), 1);
        assert_eq!(parent.get_children()[0].read().unwrap().get_name(), "child");
    }

    #[test]
    fn test_document() {
        let mut doc = Document::new();
        let mut root = Element::new();
        root.set_name("root");
        doc.set_root(Arc::new(RwLock::new(root)));
        assert!(doc.get_root().is_some());
        assert_eq!(doc.get_root().unwrap().read().unwrap().get_name(), "root");
    }

    #[test]
    fn test_tree_encoder_roundtrip() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        let mut enc = TreeEncoder::new(registry.clone());
        let head_id = ElementId::new("data", 1);
        let num_id = AttributeId::new("num", 132);
        enc.open_element(&head_id);
        enc.write_unsigned_integer(&num_id, 42);
        enc.write_string(&AttributeId::new("name", registry.read().unwrap().find_attribute("name")), "foo");
        enc.close_element(&head_id);
        let doc = enc.into_document();
        let root = doc.get_root().unwrap();
        let rg = root.read().unwrap();
        assert_eq!(rg.get_name(), "data");
        assert_eq!(rg.get_attribute_value("num"), Some("42"));
        assert_eq!(rg.get_attribute_value("name"), Some("foo"));
    }

    #[test]
    fn test_tree_decoder() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        // Build a tree manually.
        let mut root = Element::new();
        root.set_name("data");
        root.add_attribute("num", "42");
        let mut dec = TreeDecoder::new(Arc::new(RwLock::new(root)), registry.clone());
        let id = dec.open_element();
        assert_eq!(id, 1);
        // Read the num attribute.
        let aid = dec.next_attribute_id();
        assert_eq!(aid, 132);
        let val = dec.read_unsigned_integer();
        assert_eq!(val, 42);
        dec.close_element(id);
    }

    #[test]
    fn test_reserved_ids() {
        assert_eq!(ATTRIB_UNKNOWN, 159);
        assert_eq!(ELEM_UNKNOWN, 289);
        assert_eq!(ATTRIB_CONTENT, 1);
    }

    // ----- PackedEncode / PackedDecode tests -----

    #[test]
    fn test_packed_encode_element_roundtrip() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        // Encode.
        let mut enc = PackedEncode::new();
        let root = ElementId::new("data", 1);
        let num = AttributeId::new("num", 132);
        enc.open_element(&root);
        enc.write_unsigned_integer(&num, 42);
        enc.write_bool(&AttributeId::new("readonly", 17), true);
        enc.write_string(&AttributeId::new("name", registry.write().unwrap().register_attribute("name")), "hello");
        enc.close_element(&root);
        let bytes = enc.into_bytes();
        assert!(!bytes.is_empty());

        // Decode.
        let mut dec = PackedDecode::new(bytes, registry.clone());
        let eid = dec.open_element();
        assert_eq!(eid, 1);

        // Read attributes in order: num, readonly, name.
        let aid1 = dec.next_attribute_id();
        let val1 = dec.read_unsigned_integer();
        assert_eq!(aid1, 132);
        assert_eq!(val1, 42);

        let aid2 = dec.next_attribute_id();
        let val2 = dec.read_bool();
        // flag id should be non-zero (registered).
        assert_ne!(aid2, 0);
        assert!(val2);

        let _aid3 = dec.next_attribute_id();
        let val3 = dec.read_string();
        assert_eq!(val3, "hello");

        dec.close_element(eid);
    }

    #[test]
    fn test_packed_encode_signed_integer() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        let mut enc = PackedEncode::new();
        let attr = AttributeId::new("val", 24);
        enc.write_signed_integer(&attr, -100);
        let bytes = enc.into_bytes();

        let mut dec = PackedDecode::new(bytes, registry);
        dec.next_attribute_id();
        let val = dec.read_signed_integer();
        assert_eq!(val, -100);
    }

    #[test]
    fn test_packed_encode_large_unsigned() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        let mut enc = PackedEncode::new();
        let attr = AttributeId::new("value", 25);
        enc.write_unsigned_integer(&attr, 0x123456789A);
        let bytes = enc.into_bytes();

        let mut dec = PackedDecode::new(bytes, registry);
        dec.next_attribute_id();
        let val = dec.read_unsigned_integer();
        assert_eq!(val, 0x123456789A);
    }

    #[test]
    fn test_packed_encode_zero() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        let mut enc = PackedEncode::new();
        let attr = AttributeId::new("offset", 16);
        enc.write_unsigned_integer(&attr, 0);
        let bytes = enc.into_bytes();

        let mut dec = PackedDecode::new(bytes, registry);
        dec.next_attribute_id();
        let val = dec.read_unsigned_integer();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_packed_encode_extended_id() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        let mut enc = PackedEncode::new();
        let elem = ElementId::new("compiler_spec", 132); // > 0x1f → extended.
        enc.open_element(&elem);
        enc.close_element(&elem);
        let bytes = enc.into_bytes();

        let mut dec = PackedDecode::new(bytes, registry);
        let eid = dec.open_element();
        assert_eq!(eid, 132);
        dec.close_element(eid);
    }
}
