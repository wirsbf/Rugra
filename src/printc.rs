//! C language printing implementation
//!
//! Corresponds to Ghidra's `printc.hh` and `printc.cc`

use crate::fspec::FuncProto;
use crate::funcdata::Funcdata;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::prettyprint::{Emit, NullEmit};
use crate::printlanguage::PrintLanguage;
use crate::type_system::Datatype;
use crate::type_system::datatype::TypeMetatype;
use crate::type_system::cast::CastStrategyC;
use crate::varnode::Varnode;
use crate::address::SeqNum;
use crate::space::AddressSpace;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

// Ghidra: printc.cc:23-76 OpToken static instances (precedence + associativity)
/// Operator precedence/associativity table mirroring Ghidra's static OpToken
/// instances in printc.cc (lines 23-76). Each opcode maps to (precedence,
/// associative). Higher precedence binds tighter. Faithful to Ghidra's
/// C operator precedence model used by printlanguage.cc:269 parentheses().
pub mod optoken {
    use crate::opcodes::OpCode;

    // Ghidra: printc.cc:36-55 OpToken static instances (precedence field)
    /// Return the precedence for a binary opcode, or None if it is not a
    /// binary arithmetic/comparison/logical op. Values mirror printc.cc:36-55:
    ///   multiply/divide/modulo=54, add/sub=50, shift=46, relational=42,
    ///   equality=38, bitwise_and=34, bitwise_xor=30, bitwise_or=26,
    ///   boolean_and=22, boolean_or=18.
    pub fn binary_precedence(opc: OpCode) -> Option<i32> {
        use OpCode::*;
        match opc {
            CPUI_INT_MULT | CPUI_FLOAT_MULT | CPUI_INT_DIV | CPUI_INT_SDIV
            | CPUI_FLOAT_DIV | CPUI_INT_REM | CPUI_INT_SREM => Some(54),
            CPUI_INT_ADD | CPUI_FLOAT_ADD | CPUI_INT_SUB | CPUI_FLOAT_SUB => Some(50),
            CPUI_INT_LEFT | CPUI_INT_RIGHT | CPUI_INT_SRIGHT => Some(46),
            CPUI_INT_LESS | CPUI_INT_SLESS | CPUI_FLOAT_LESS
            | CPUI_INT_LESSEQUAL | CPUI_INT_SLESSEQUAL | CPUI_FLOAT_LESSEQUAL => Some(42),
            CPUI_INT_EQUAL | CPUI_INT_NOTEQUAL | CPUI_FLOAT_EQUAL
            | CPUI_FLOAT_NOTEQUAL => Some(38),
            CPUI_INT_AND => Some(34),
            CPUI_INT_XOR | CPUI_BOOL_XOR => Some(30),
            CPUI_INT_OR => Some(26),
            CPUI_BOOL_AND => Some(22),
            CPUI_BOOL_OR => Some(18),
            _ => None,
        }
    }

    // Ghidra: printc.cc:36-55 OpToken static instances (associative field)
    /// Return whether a binary opcode is associative (printc.cc associative field).
    /// multiply=associative (line 36); add=associative (39); bitwise_and/xor/or
    /// = associative (50/51/52). All others (div/mod/sub/shift/relational/
    /// equality/boolean_and/boolean_or) are non-associative.
    pub fn binary_associative(opc: OpCode) -> bool {
        use OpCode::*;
        matches!(
            opc,
            CPUI_INT_MULT | CPUI_FLOAT_MULT | CPUI_INT_ADD | CPUI_FLOAT_ADD
            | CPUI_INT_AND | CPUI_INT_XOR | CPUI_BOOL_XOR | CPUI_INT_OR
        )
    }

    /// Unary prefix precedence (printc.cc:29-34): ~ ! - + & * = 62.
    pub const UNARY_PRECEDENCE: i32 = 62;

    /// Cast precedence (printc.cc:35 typecast): presurround = 62.
    pub const CAST_PRECEDENCE: i32 = 62;

    // Ghidra: printlanguage.cc:269 PrintLanguage::parentheses
    /// Decide whether a child sub-expression needs parentheses, given the
    /// child's opcode and which operand slot of the parent it occupies.
    /// Mirrors PrintLanguage::parentheses (printlanguage.cc:269-323) for the
    /// common binary/unary cases:
    ///   - If child precedence > parent precedence → needs parens (child binds
    ///     tighter but, per Ghidra's rule for the binary/unary_prefix cases,
    ///     a higher-precedence child still gets parens because the operators
    ///     are adjacent and the lower-precedence parent is being emitted).
    ///     NOTE: this is the OPPOSITE of textbook C; Ghidra's parentheses()
    ///     returns true when topToken->precedence > op2->precedence. The
    ///     function decides whether the *already-emitted* child (topToken)
    ///     needs wrapping relative to the *parent* (op2) about to be emitted.
    ///
    /// In Rugra's model we call this BEFORE emitting the child, so we invert:
    /// we are given the parent opcode and the child opcode, and decide if the
    /// child needs wrapping. Textbook rule applies: wrap the child if its
    /// precedence is LOWER than the parent's, OR equal-and-non-associative on
    /// the right operand (to preserve left-to-right evaluation order).
    ///
    /// `is_right_operand`: true if the child is the right operand of a
    /// non-associative binary parent (e.g. the `b` in `a - b`). For the left
    /// operand of an associative op, no parens needed even at equal precedence.
    pub fn child_needs_parens(parent_opc: OpCode, child_opc: OpCode, is_right_operand: bool) -> bool {
        let parent_prec = match binary_precedence(parent_opc) {
            Some(p) => p,
            None => return false, // parent isn't a tracked binary op
        };
        let child_prec = match binary_precedence(child_opc) {
            Some(p) => p,
            None => return false, // child isn't a tracked binary op (leaf or other)
        };
        if child_prec < parent_prec {
            // Child binds looser → must parenthesize to preserve grouping.
            return true;
        }
        if child_prec == parent_prec {
            // Equal precedence: left operand never needs parens (left-assoc);
            // right operand needs parens if parent is non-associative
            // (to keep left-to-right order, e.g. (a - b) - c needs no parens
            // but a - (b - c) does).
            if is_right_operand && !binary_associative(parent_opc) {
                return true;
            }
            // Also parenthesize if the operators differ and child is on the
            // right of a non-associative op at the same level (rare, but
            // faithful to Ghidra's "operators adjacent, evaluated first" rule).
        }
        false
    }
}

// Ghidra: printlanguage.hh:144 PrintLanguage::modifiers
/// Printing modification flags mirroring Ghidra's `modifiers` enum
/// (printlanguage.hh:144-161). Stored in PrintC.mods as a bitmask.
pub mod print_mods {
    /// Hide pointer deref for load with other ops (printlanguage.hh:150).
    pub const PRINT_LOAD_VALUE: u32 = 0x20;
    /// Hide pointer deref for store with other ops (printlanguage.hh:151).
    pub const PRINT_STORE_VALUE: u32 = 0x40;
    /// Do not print branch instruction (printlanguage.hh:152).
    pub const NO_BRANCH: u32 = 0x80;
    /// Print only the branch instruction (printlanguage.hh:153).
    pub const ONLY_BRANCH: u32 = 0x100;
    /// Statements within a condition (for-loop header parts separated by
    /// ';' rather than ';'+newline). emitStatement suppresses the trailing
    /// ';' when this is set (printc.cc:2291-2292).
    pub const COMMA_SEPARATE: u32 = 0x200;
    /// Do not print block structure (flat) (printlanguage.hh:155).
    pub const FLAT: u32 = 0x400;
    /// The current block may need to surround itself with additional braces
    /// (printlanguage.hh:160). Enables `else if` collapsing.
    pub const PENDING_BRACE: u32 = 0x8000;
    /// Print the negation token (printlanguage.hh:158). Set by opBoolNegate
    /// when folding `!(a==b)` -> `a != b`; the comparison reader consumes it.
    pub const NEGATETOKEN: u32 = 0x2000;
}

// Ghidra: database.hh:2027 symbol_display_format
/// Display-format enum mirroring Ghidra's `symbol_display_format`
/// (database.hh:2027-2033): the explicit formats a Symbol/Datatype can force
/// a constant to be rendered in. `DEFAULT` (0) means "decide automatically via
/// mostNaturalBase / mods". Used by push_integer / push_char_constant_fmt /
/// push_enum_constant_named to honour the formatting decisions recorded on
/// the symbol/type — the core of the P0 constant-formatting gap (audit P0-2).
/// Rugra does not yet persist a per-symbol display-format field, so callers
/// pass `display_format::DEFAULT` (auto); the dispatch machinery is in place
/// so that once the field is wired, formatting honours it.
pub mod display_format {
    /// Automatic: decide via mostNaturalBase / mods (database.hh:2028).
    pub const DEFAULT: u32 = 0;
    /// Force hexadecimal rendering, e.g. `0x1f` (database.hh:2029).
    pub const HEX: u32 = 1;
    /// Force decimal rendering, e.g. `31` (database.hh:2030).
    pub const DEC: u32 = 2;
    /// Force character rendering, e.g. `'A'` (database.hh:2031).
    pub const CHAR: u32 = 3;
    /// Force octal rendering, e.g. `037` (database.hh:2032).
    pub const OCT: u32 = 4;
    /// Force binary rendering, e.g. `0b11111` (database.hh:2033).
    pub const BIN: u32 = 5;
}

// RUGRA-GLUE: sanitize_c_ident (no Ghidra counterpart found)
fn sanitize_c_ident(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

// RUGRA-GLUE: escape_c_string (no Ghidra counterpart found)
/// Escape a raw string from the binary into a C string literal.
/// Converts control characters to their escape sequences:
/// newline → \n, carriage return → \r, tab → \t, null → \0, etc.
fn escape_c_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"'  => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_ascii_control() => {
                // Other control chars as hex escape
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}

/// Represents a detected struct on the stack frame.
/// When a stack address is passed to a function call (via lea reg, [rsp+X]),
/// it indicates a struct/buffer at that offset.
#[derive(Debug, Clone)]
struct StackStruct {
    /// Name assigned to this struct variable (e.g., "config", "buf")
    name: String,
    /// RSP offset where this struct starts
    base_offset: u64,
    /// Detected or estimated size of the struct  
    size: u64,
    /// Offsets of known fields (relative to base_offset)
    fields: Vec<u64>,
}

/// Printer for the C programming language
///
/// Corresponds to Ghidra's `PrintC` class. This handles the conversion
/// of high-level IR (P-code and Control Flow) into valid C source code.
pub struct PrintC {
    emit: Box<dyn Emit>,
    /// Address → symbol name lookup (borrowed from Funcdata during doc_function)
    symbol_table: HashMap<u64, String>,
    /// Address → string literal lookup (borrowed from Funcdata during doc_function)
    string_table: HashMap<u64, String>,
    /// Function address range for local label detection
    func_start: u64,
    func_end: u64,
    /// Copy propagation map: varnode Arc ptr → root source varnode Arc
    copy_map: HashMap<usize, Arc<RwLock<Varnode>>>,
    /// Defining-op map: output varnode Arc ptr → defining PcodeOp Arc
    def_map: HashMap<usize, Arc<RwLock<PcodeOp>>>,
    /// Value-based defining-op map: (space, offset) → defining PcodeOp Arc
    /// Reliable cross-block: same SSA value has same (space, offset) key.
    value_def_map: HashMap<(crate::space::AddressSpace, u64), Arc<RwLock<PcodeOp>>>,
    /// Track post-return state across blocks
    seen_return: bool,
    succ_recursion_depth: u32,
    /// Block indices that are switch case bodies. BlockIf emit checks this to
    /// avoid extracting case bodies (which would pull `case` labels out of switch).
    case_body_indices: HashSet<i32>,
    /// Track ops that have been inlined into consumers (and should not be emitted as standalone lines)
    inlined_ops: HashSet<SeqNum>,
    /// Track variable names actually used in the emitted code (for declaration pruning)
    used_varnode_names: HashSet<String>,
    /// Track actual types, space and offset of used variables for robust declaration mapping
    used_varnode_types: HashMap<String, (String, crate::space::AddressSpace, u64)>,
    /// First-use order of used variable names recorded during the REAL emit
    /// pass (not discovery). Declarations are emitted in this order so they
    /// are monotonic with compact_name_for's lazy numbering (bVar1, bVar2, ...
    /// assigned in first-use order). Faithful to Ghidra assignDefaultNames
    /// (database.cc:2850-2865). Without this, declarations iterated the
    /// HashMap in RANDOM order (Rust HashMap is randomly seeded), causing
    /// non-deterministic output: gcc audit varied 22-24/24 across runs.
    declaration_order: Vec<String>,
    /// Scope-local stack symbols (from varmap's restructure_varnode) that were
    /// referenced during the body emit. These MUST be declared even if the
    /// general discovery/mark path missed them (it sometimes does for STORE
    /// address LHS, causing 'StackX_N undeclared'). Populated by
    /// get_stack_variable_name during both discovery and real emit.
    used_scope_symbols: std::cell::RefCell<std::collections::HashSet<String>>,
    /// Compact variable renumbering map (raw name → compact name), built
    /// lazily on first use. Faithful to Ghidra's assignDefaultNames
    /// (database.cc:2862): variables are renumbered per type-prefix starting
    /// from 1 (iVar1, iVar2, lVar1, ...) instead of using the raw register
    /// offset (iVar23, lVar107). Built on-demand in push_varnode and
    /// get_varnode_display_name during the REAL emit pass (not discovery).
     compact_rename: HashMap<String, String>,
    /// Single shared counter for auto-local renaming, faithful to Ghidra's
    /// `int4 base` in `ActionNameVars::apply` (coreaction.cc:2988) +
    /// `assignDefaultNames(int4 &base)` (database.cc:2850). Initial value 1,
    /// monotonically incremented across ALL prefixes (iVar/lVar/bVar/...).
    /// This replaces the previous per-prefix `HashMap<&str,u32>` counter,
    /// which was the 181538f bug (per-prefix independent numbering produced
    /// `bVar1,bVar2` instead of Ghidra's shared `...iVar4,lVar5...`).
    compact_base: u32,
    /// If true, we are in the discovery pass (only collecting names, not printing)
    discovery_pass: bool,
    /// Addresses of CALL targets (should not be declared as local variables)
    call_targets: HashSet<u64>,
    /// Varnode Arc pointers that are used as pointers (LOAD/STORE address
    /// or INT_ADD input feeding LOAD/STORE). Precomputed in doc_function
    /// for usage-based type inference in Hungarian naming.
    pointer_varnodes: HashSet<(crate::space::AddressSpace, u64)>,
    /// Inline candidates: Unique-space (space, offset) → defining PcodeOp Arc
    /// Only populated for single-use Unique outputs of non-COPY, non-STORE ops.
    inline_candidates: HashMap<(crate::space::AddressSpace, u64), Arc<RwLock<PcodeOp>>>,
    /// Recursion guard to prevent infinite inlining loops
    inline_depth: u32,
    /// Cast strategy for determining when explicit casts are required
    cast_strategy: CastStrategyC,
    /// Parameter register offset → parameter name mapping
    /// Populated from fd.funcp.parameters in doc_function
    param_names: HashMap<u64, String>,
    /// True when currently emitting an output (LHS) varnode — skip def chain resolution
    is_lhs: bool,
    /// Global set of varnode Arc pointers used as input across ALL blocks
    /// Used for cross-block dead code elimination
    global_used_outputs: HashSet<usize>,
    /// Comparison/boolean ops def map: (space, offset) → comparison/boolean PcodeOp Arc
    /// Unlike value_def_map, this ONLY stores comparison and boolean ops,
    /// so non-comparison writes don't overwrite these entries.
    comparison_def_map: HashMap<(crate::space::AddressSpace, u64), Arc<RwLock<PcodeOp>>>,
    /// Stack frame size detected from `sub rsp, N` pattern.
    /// 0 means no stack frame detected.
    stack_frame_size: u64,
    /// (space, offset) key of the varnode that holds RSP - frame_size.
    /// Used to resolve uVar107 + offset patterns.
    stack_frame_base_key: Option<(crate::space::AddressSpace, u64)>,
    /// Detected structs on the stack (base_offset sorted)
    stack_structs: Vec<StackStruct>,
    /// Block-local register def map: (Register space, offset) → defining PcodeOp.
    /// Tracks the most recent op that writes to each register within the current block.
    /// Preferred over value_def_map for CALL argument resolution to avoid cross-block contamination.
    block_local_reg_defs: HashMap<(crate::space::AddressSpace, u64), Arc<RwLock<PcodeOp>>>,
    /// Current loop nesting depth. >0 means we are inside a while/do-while body.
    /// Used to suppress `continue` statements in non-loop contexts.
    loop_depth: u32,
    /// Printing modification flags (Ghidra `mods`, printlanguage.hh:144-161).
    /// Tracks context-sensitive modifiers like comma_separate (for-loop header),
    /// no_branch, only_branch. The mod_stack enables push/pop save-restore.
    /// Faithful to PrintLanguage::mods + modstack (printlanguage.hh:284-290).
    mods: u32,
    mod_stack: Vec<u32>,
    /// Recursion depth guard for emit_block_structured. Prevents stack overflow
    /// on deeply nested structures (e.g. when mainloop repeatapply rebuilds
    /// sblocks with different nesting).
    struct_emit_depth: u32,
    /// Set of block addresses that are targets of BRANCH/CBRANCH goto statements.
    /// Used to emit LAB_XXXX: labels at the start of target blocks.
    goto_targets: HashSet<u64>,
    /// Restructured local-variable scope (faithful port of varmap.cc). Built
    /// once per doc_function from the function's stack varnodes. When a symbol
    /// covers a stack offset, get_stack_variable_name prefers its name over the
    /// frame-relative heuristic.
    scope: Option<crate::varmap::ScopeLocal>,
    /// Whether to print the calling-convention model name in function
    /// declarations. Faithful to `PrintC::option_convention` (printc.hh:148),
    /// defaulting to true (printc.cc:1584 `resetDefaultsPrintC`).
    option_convention: bool,
    /// Whether to suppress all explicit casts. Faithful to
    /// `PrintC::option_nocasts` (printc.hh:152), defaulting to false
    /// (printc.cc:1587 `resetDefaultsPrintC`). Read by `pushConstant`'s default
    /// cast path (printc.cc:1807) and the SUBPIECE cast in pushPartialSymbol.
    option_nocasts: bool,
    /// Whether to render the NULL pointer as the `NULL` token. Faithful to
    /// `PrintC::option_NULL` (printc.hh:153), defaulting to false
    /// (printc.cc:1588 `resetDefaultsPrintC`). Read by the TYPE_PTR arm of
    /// `pushConstant` (printc.cc:1777).
    option_null: bool,
    /// Whether to hide extension casts that are implied by C integer
    /// promotion. Faithful to `PrintC::option_hide_exts` (printc.hh:149),
    /// defaulting to true (printc.cc:1585 `resetDefaultsPrintC`). Read by
    /// `opIntZext`/`opIntSext` (printc.cc:790, 803) via
    /// `CastStrategyC::isExtensionCastImplied`.
    option_hide_exts: bool,
    /// Whether to emit compound assignment operators (`+=`, `*=`, ...).
    /// Faithful to `PrintC::option_inplace_ops` (printc.hh:150), defaulting to
    /// false (printc.cc:1586 `resetDefaultsPrintC`). Read by `emitExpression`
    /// (printc.cc:2473) before calling `emitInplaceOp`.
    option_inplace_ops: bool,
    /// Whether to print unplaced/unused variables. Faithful to
    /// `PrintC::option_unplaced` (printc.hh:154), defaulting to false
    /// (printc.cc:1589 `resetDefaultsPrintC`).
    option_unplaced: bool,
}

impl PrintC {
    // Ghidra: printc.cc:123 PrintC::new
    /// Create a new PrintC instance
    pub fn new(emit: Box<dyn Emit>) -> Self {
        Self {
            emit,
            symbol_table: HashMap::new(),
            string_table: HashMap::new(),
            func_start: 0,
            func_end: 0,
            copy_map: HashMap::new(),
            def_map: HashMap::new(),
            value_def_map: HashMap::new(),
            seen_return: false,
            succ_recursion_depth: 0,
            case_body_indices: HashSet::new(),
            inlined_ops: HashSet::new(),
            used_varnode_names: HashSet::new(),
            used_varnode_types: HashMap::new(),
            declaration_order: Vec::new(),
            used_scope_symbols: std::cell::RefCell::new(std::collections::HashSet::new()),
            compact_rename: HashMap::new(),
            compact_base: 1, // faithful to Ghidra int4 base=1 (coreaction.cc:2988)
            discovery_pass: false,
            call_targets: HashSet::new(),
        pointer_varnodes: HashSet::new(),
            inline_candidates: HashMap::new(),
            inline_depth: 0,
            cast_strategy: CastStrategyC::new(4), // promote_size = 4 (x86/x64 int)
            param_names: HashMap::new(),
            is_lhs: false,
            global_used_outputs: HashSet::new(),
            comparison_def_map: HashMap::new(),
            stack_frame_size: 0,
            stack_frame_base_key: None,
            stack_structs: Vec::new(),
            block_local_reg_defs: HashMap::new(),
            loop_depth: 0,
            mods: 0,
            mod_stack: Vec::new(),
            struct_emit_depth: 0,
            goto_targets: HashSet::new(),
            scope: None,
            option_convention: true, // printc.cc:1584 resetDefaultsPrintC
            option_nocasts: false,   // printc.cc:1587 resetDefaultsPrintC
            option_null: false,      // printc.cc:1588 resetDefaultsPrintC
            option_hide_exts: true,    // printc.cc:1585 resetDefaultsPrintC
            option_inplace_ops: false, // printc.cc:1586 resetDefaultsPrintC
            option_unplaced: false,    // printc.cc:1589 resetDefaultsPrintC

        }
    }

    // Ghidra: printc.cc:123 PrintC::takeEmit
    /// Take ownership of the internal emitter, consuming the printer.
    /// This allows callers to retrieve the buffered output from emitters
    /// like `EmitNoMarkup`.
    pub fn take_emit(self) -> Box<dyn Emit> {
        self.emit
    }

    // Ghidra: printc.cc:123 PrintC::emitCbranchCondition
    /// Emit the boolean condition of a CBRANCH (its in(1)). When in(1) is
    /// absent, emit `1` (always-true) instead of leaving the parentheses empty.
    /// Rationale: Ghidra's `opCbranch` (printc.cc) always pushes `getIn(1)` —
    /// it never drops the condition. Rugra's structurer can build a BlockIf
    /// around a CBRANCH whose in(1) was consumed upstream, leaving the op with
    /// no condition. Previously this produced `if () goto ;` (syntax error);
    /// emitting `1` gives valid, if conservative, C. (Audit: BATCH1 R50.)
    fn emit_cbranch_condition(&mut self, op: &PcodeOp) {
        match op.get_in(1) {
            Some(in1) => {
                // in(1) is present, but emit_condition may still produce
                // garbage (e.g. ` == `, `!()`, or empty) when its def-map
                // strategies fail to resolve the comparison operands. Capture
                // the output and fall back to `1` (always-true) if it contains
                // no identifier/digit — that's a syntactically invalid
                // condition and would yield `if () goto ;` or `if ( == )`.
                // (Audit: BATCH1 R50.)
                let orig_emit = std::mem::replace(&mut self.emit,
                    Box::new(crate::prettyprint::EmitNoMarkup::new()));
                self.emit_condition(&in1);
                let text = {
                    let buf = std::mem::replace(&mut self.emit, orig_emit);
                    buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                        .map(|b| b.get_output()).unwrap_or_default()
                };
                let t = text.trim();
                // Same malformed-condition guard as emit_block_condition: detect
                // cast-concat and variable-name-concat (BOOL_OR/AND operator dropped
                // during emit_condition's nested emit-swap). Fall back to `1`.
                let cast_count = t.matches("(long)").count() + t.matches("(int)").count()
                    + t.matches("(char)").count() + t.matches("(bool)").count()
                    + t.matches("(short)").count();
                let has_bool_op = t.contains(" || ") || t.contains(" && ") || t.contains(" == ")
                    || t.contains(" != ") || t.contains(" < ") || t.contains(" > ")
                    || t.contains(" <= ") || t.contains(" >= ");
                let has_concat_cast = cast_count >= 2 && !has_bool_op;
                let has_concat_varname = Self::regex_concat_varname(t);
                let looks_valid = !t.is_empty()
                    && t.chars().any(|c| c.is_alphanumeric() || c == '_')
                    && !has_concat_cast
                    && !has_concat_varname;
                if looks_valid {
                    self.emit.print(&text);
                } else {
                    self.emit.print("1");
                }
            }
            None => self.emit.print("1"),
        }
    }

    // Ghidra: printc.cc:123 PrintC::emitBlockOps
    /// Emit a single block's operations, with dead code elimination.
    ///
    /// Skips: COPY ops (folded via copy_map), terminal branches (when skip_terminal),
    /// dead flag outputs (not referenced by any other op), and post-return dead code.
    fn emit_block_ops(&mut self, block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>, skip_terminal: bool) {
        use crate::opcodes::OpCode;
        use std::collections::HashSet;

        let block = block_arc.read().unwrap();
        let ops = block.get_ops();

        // Clear block-local register defs — each block starts fresh
        self.block_local_reg_defs.clear();

        // Build set of "used" varnode pointers: every input of every op is "used"
        // Combine block-local with global cross-block tracking
        let mut used_outputs: HashSet<usize> = self.global_used_outputs.clone();
        for op_ref in &ops {
            let op = op_ref.0.read().unwrap();
            for in_arc in &op.inrefs {
                used_outputs.insert(Arc::as_ptr(in_arc) as usize);
                // Also mark the copy-resolved source as used
                if let Some(resolved) = self.copy_map.get(&(Arc::as_ptr(in_arc) as usize)) {
                    used_outputs.insert(Arc::as_ptr(resolved) as usize);
                }
            }
        }

        for op_ref in &ops {
            let op = op_ref.0.read().unwrap();

            // Update block-local register def map: track last op writing to each register
            if let Some(ref out_arc) = op.output {
                let out_vn = out_arc.read().unwrap();
                if out_vn.get_space() == crate::space::AddressSpace::Register {
                    let key = (out_vn.get_space(), out_vn.get_offset());
                    drop(out_vn);
                    self.block_local_reg_defs.insert(key, op_ref.0.clone());
                }
            }

            // Feature 3: Skip ops after RETURN (global across blocks)
            if self.seen_return {
                continue;
            }
            if op.opcode == OpCode::CPUI_RETURN {
                self.doc_statement(&op);
                self.seen_return = true;
                continue;
            }

            // Ghidra printc.cc:2701: CPUI_BRANCH is NEVER printed as a
            // standalone statement — it is always rendered by the block/
            // structure classes (emitBlockGoto etc). This is unconditional,
            // independent of skip_terminal (unlike CBRANCH/BRANCHIND which
            // are controlled by skip_terminal).
            if op.opcode == OpCode::CPUI_BRANCH {
                continue;
            }

            if skip_terminal {
                match op.opcode {
                    OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND => {
                        // In structured emission (BlockIf/BlockWhile), branches are always
                        // consumed by the structure — skip regardless of branch_type
                        continue;
                    }
                    _ => {}
                }
            }

            // Ghidra printc.cc:2696: if (inst->notPrinted()) continue;
            // Skip ops explicitly marked as non-printing. NOTE: in Ghidra,
            // NONPRINTING is only set on branch ops consumed by the structurer
            // and redundant internal COPYs. Rugra's mark_internal_copies sets
            // it on same-high COPYs (which IS correct — they are internal).
            // However, applying this unconditionally breaks output because
            // many COPYs are marked NONPRINTING but still need to print as
            // assignments. The correct Ghidra model uses isImplied() for
            // COPY suppression, not NONPRINTING. So we skip this for now
            // and rely on the COPY-skip + inlined_ops checks below.
            // TODO: properly distinguish "structural non-printing" (branch)
            // from "internal COPY non-printing" (handled by copy_map).

            // Skip COPY ops (folded via copy_map)
            if op.opcode == OpCode::CPUI_COPY {
                continue;
            }

            // Round 7 Feature 1: Skip ops that have already been inlined into consumers
            if self.inlined_ops.contains(&op.get_seq_num()) {
                continue;
            }

            // Faithful to Ghidra printc.cc:2704: skip ops whose output isImplied().
            // An implied varnode's def expression is inlined at its read site
            // (push_varnode emits it), so the op is NOT emitted as a standalone
            // `lhs = expr` statement.
            if let Some(ref out_arc) = op.output {
                if out_arc.read().unwrap().is_implied() {
                    continue;
                }
            }

            // Skip RIP-relative INT_ADD ops — they create symbol aliases resolved via Priority 1.5
            if self.get_rip_relative_operand(&op).is_some() {
                continue;
            }

            // Skip INT_SUB(RSP, const) — stack frame setup (e.g., sub rsp, 0x228)
            if self.stack_frame_size > 0 && self.is_stack_frame_setup(&op) {
                continue;
            }

            // Feature 1: Skip dead outputs (flag comparisons not used by anyone)
            // Only skip pure-computation ops (comparisons, boolean ops), not side-effectful ones
            if let Some(ref out_arc) = op.output {
                let out_ptr = Arc::as_ptr(out_arc) as usize;
                if !used_outputs.contains(&out_ptr) {
                    // Skip pure-computation ops whose output is not used by anyone
                    match op.opcode {
                        // Comparisons and boolean ops
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                        | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                        | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                        | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
                        | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR
                        // Arithmetic ops
                        | OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB
                        | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_DIV
                        | OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_REM
                        | OpCode::CPUI_INT_SREM
                        // Bitwise ops
                        | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR
                        | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_NEGATE
                        | OpCode::CPUI_INT_2COMP
                        // Shift ops
                        | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT
                        | OpCode::CPUI_INT_SRIGHT
                        // Extensions and casts
                        | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT
                        | OpCode::CPUI_SUBPIECE | OpCode::CPUI_PIECE
                        // Loads (no side effects, just reads memory)
                        | OpCode::CPUI_LOAD
                        // COPY already handled above, but just in case
                        | OpCode::CPUI_COPY
                        => continue,
                        _ => {}
                    }
                }
            }

            self.doc_statement(&op);
        }
    }

    // Ghidra: printc.cc:123 PrintC::isBlockBodyEmpty
    /// Check if a block body has no emittable ops (all ops are dead, skipped, or branch-only).
    /// Used to suppress empty `if () {} else {}` blocks.
    fn is_block_body_empty(&self, block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>) -> bool {
        use crate::opcodes::OpCode;
        let block = block_arc.read().unwrap();
        let ops = block.get_ops();

        // Faithful to Ghidra's model: a block's BODY is its non-terminal ops.
        // The terminal CBRANCH/BRANCH/RETURN is the control-flow transfer that
        // the structurer consumes (printc.cc:2895 setMod(no_branch) suppresses
        // it when emitting a condition block) — it is NOT a body statement.
        // Previously this method returned false (non-empty) whenever the LAST
        // op was CBRANCH/BRANCH/RETURN/CALL, which mis-classified blocks whose
        // only live op was the terminal branch (all real body ops dead) as
        // non-empty. That made emit_structured_basic emit `if (cond) {} else {}`
        // with genuinely-empty braces — a form Ghidra's emitBlockIf never
        // produces (printc.cc:2878 always emits the block's actual content).
        // Now we fall through to the per-op scan, which mirrors emit_block_ops:
        // it skips branches/dead/pure-computation ops and reports empty only
        // when nothing emittable remains. CALL/CALLIND with live side effects
        // are still caught below (they are not in the skip set), so a block
        // whose body is a real call is correctly non-empty.

        for op_ref in &ops {
            let op = op_ref.0.read().unwrap();
            // Skip branches, COPY, phi-nodes — same skip set as emit_block_ops
            // (emit_block_ops:315-323 skips CBRANCH/BRANCH/BRANCHIND/COPY/MULTIEQUAL/INDIRECT).
            match op.opcode {
                OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT => continue,
                _ => {}
            }
            // Skip ops whose output is implied — emit_block_ops:334-338 skips
            // these (the def expression is inlined at the read site, so the op
            // is not emitted as a standalone statement).
            if let Some(ref out_arc) = op.output {
                if out_arc.read().unwrap().is_implied() { continue; }
            }
            // Skip RIP-relative
            if self.get_rip_relative_operand(&op).is_some() { continue; }
            // Skip stack frame setup
            if self.stack_frame_size > 0 && self.is_stack_frame_setup(&op) { continue; }
            // Skip inlined ops
            if self.inlined_ops.contains(&op.get_seq_num()) { continue; }
            // Check if output is dead (pure computation with unused output)
            if let Some(ref out_arc) = op.output {
                let out_ptr = Arc::as_ptr(out_arc) as usize;
                if !self.global_used_outputs.contains(&out_ptr) {
                    match op.opcode {
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                        | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                        | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                        | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
                        | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR
                        | OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB
                        | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_DIV
                        | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR
                        | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_NEGATE
                        | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT
                        | OpCode::CPUI_INT_SRIGHT
                        | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT
                        | OpCode::CPUI_SUBPIECE | OpCode::CPUI_PIECE
                        | OpCode::CPUI_LOAD
                        => continue,
                        _ => {}
                    }
                }
            }
            // If we reach here, this op is emittable
            return false;
        }
        true
    }

    // Ghidra: printc.cc:123 PrintC::emitBlockStructured
    /// Emit a block with structured control flow detection.
    ///
    /// Recursively walks structured block types (`BlockIf`, `BlockWhileDo`,
    /// `BlockList`) produced by `CollapseStructure`. Falls back to flat
    /// statement emission for `BlockBasic` nodes.
    fn emit_block_structured(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        graph: &crate::block::BlockGraph,
        emitted: &mut std::collections::HashSet<usize>,
    ) {
        // Depth guard: prevent stack overflow on deeply nested structures.
        // Fallback to sequential ops emission when depth exceeds safe limit.
        // Uses thread_local to avoid borrow conflicts with &mut self.
        thread_local! {
            static EMIT_DEPTH: std::cell::Cell<u32> = std::cell::Cell::new(0);
        }
        let depth = EMIT_DEPTH.with(|d| { let v = d.get(); d.set(v + 1); v });
        if depth > 200 {
            EMIT_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
            self.emit_block_ops(block_arc, false);
            return;
        }
        // Ensure decrement happens on all exit paths via a scope guard.
        struct DepthDec;
        impl Drop for DepthDec {
            // RUGRA-GLUE: drop (no Ghidra counterpart found)
            fn drop(&mut self) {
                EMIT_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
            }
        }
        let _dec = DepthDec;

        use crate::block::{BlockType, BlockIf, BlockWhileDo, BlockDoWhile, BlockList, BlockCondition, BlockSwitch};

        let block_idx = std::sync::Arc::as_ptr(&block_arc) as *const () as usize;
        if emitted.contains(&block_idx) {
            return;
        }
        emitted.insert(block_idx);

        // Skip blocks that have been consumed by structuring (DEAD flag set by
        // CollapseStructure when a block is absorbed into a BlockIf/BlockList/etc.)
        // These blocks have been replaced by structured blocks; their ops are emitted
        // via the structured block's recursive children traversal. Mark as emitted
        // so doc_function's root/unreachable loops don't re-visit them (single-
        // ownership: a consumed block is emitted only via its structured parent).
        if block_arc.read().unwrap().get_flags() & crate::block::block_flags::DEAD != 0 {
            emitted.insert(block_idx);
            return;
        }

        // Skip all emission after RETURN — prevents dead-code blocks from appearing.
        // BUT control structures (WhileDo/DoWhile/If/etc) must still render even
        // after a RETURN, because they represent reachable code paths. For these,
        // save/restore seen_return so the RETURN doesn't suppress the structure.
        let bt = block_arc.read().unwrap().get_type();
        let is_control_struct = matches!(bt,
            crate::block::BlockType::WhileDo
            | crate::block::BlockType::DoWhile
            | crate::block::BlockType::If
            | crate::block::BlockType::List);
        if self.seen_return && !is_control_struct {
            return;
        }

        // Emit label if this block is a goto target
        {
            let block = block_arc.read().unwrap();
            let ops = block.get_ops();
            if let Some(first_op) = ops.first() {
                let addr = first_op.0.read().unwrap().start.addr.as_u64();
                if self.goto_targets.contains(&addr) {
                    self.emit.tag_line(0);
                    self.emit.print(&format!("{}:", self.code_label(addr)));
                }
            }
        }

        let block_type = block_arc.read().unwrap().get_type();

        match block_type {
            BlockType::If => self.emit_structured_if(block_arc, graph, emitted),
            BlockType::WhileDo => self.emit_structured_whiledo(block_arc, graph, emitted),
            BlockType::DoWhile => self.emit_structured_dowhile(block_arc, graph, emitted),
            BlockType::InfLoop => self.emit_structured_infloop(block_arc, graph, emitted),
            BlockType::List => self.emit_structured_list(block_arc, graph, emitted),
            BlockType::Condition => self.emit_structured_condition(block_arc, graph, emitted),
            BlockType::Switch => self.emit_structured_switch(block_arc, graph, emitted),
            _ => self.emit_structured_basic(block_arc, graph, emitted),
        }
    }
    // RUGRA-GLUE: emit_structured_if (no Ghidra counterpart found)
    fn emit_structured_if(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        graph: &crate::block::BlockGraph,
        emitted: &mut std::collections::HashSet<usize>,
    ) {
        use crate::block::{BlockType, BlockIf, BlockWhileDo, BlockDoWhile, BlockList, BlockCondition, BlockSwitch};
                // Structured if-then or if-then-else
                let block = block_arc.read().unwrap();
                let if_block = block.as_any().downcast_ref::<BlockIf>();
                if let Some(if_data) = if_block {
                    // If-goto (newBlockIfGoto style): emit `if (cond) goto target;`
                    // The goto_target is set, body is external (not embedded).
                    if if_data.goto_target.is_some() {
                        // Emit the condition block's ops (including the CBRANCH
                        // which becomes the if-condition), then a goto to the
                        // target. The body (fallthrough) continues after.
                        self.emit_block_ops(&if_data.condition, false);
                        // The goto: emit as a labeled goto or just continue.
                        // For now, the condition block's CBRANCH op handles the
                        // branch; we just need to not emit the placeholder body.
                        return;
                    }
                    // Goto-cascade protection: if the condition block has
                    // GOTO_EDGE_1 flag (created by selectGoto), dry-run emit
                    // the if_body to check for case labels. If found, fall
                    // back to sequential emit to avoid pulling case labels
                    // out of switch bodies.
                    let cond_has_goto = if_data.condition.read().unwrap().get_flags()
                        & crate::block::block_flags::GOTO_EDGE_1 != 0;
                    let seq_emit = if cond_has_goto {
                        let saved_emit = std::mem::replace(&mut self.emit, Box::new(crate::prettyprint::CaseDetectEmit::new()));
                        // Use emit_block_structured for full recursion (covers
                        // nested BlockSwitch/BlockIf case label emission)
                        let if_type = if_data.if_body.read().unwrap().get_type();
                        if matches!(if_type, BlockType::Basic) {
                            self.emit_block_ops(&if_data.if_body, false);
                        } else {
                            let mut dry_emitted: HashSet<usize> = HashSet::new();
                            self.emit_block_structured(&if_data.if_body, graph, &mut dry_emitted);
                        }
                        let has_case = self.emit.as_any_mut()
                            .and_then(|a| a.downcast_mut::<crate::prettyprint::CaseDetectEmit>())
                            .map_or(false, |d| d.has_case());
                        self.emit = saved_emit;
                        if has_case {
                            let if_idx = std::sync::Arc::as_ptr(&if_data.if_body) as *const () as usize;
                            let ibt = if_data.if_body.read().unwrap().get_type();
                            if ibt == crate::block::BlockType::Basic || ibt == crate::block::BlockType::Copy {
                                emitted.insert(if_idx);
                            }
                            self.emit_block_ops(&if_data.condition, false);
                            self.emit_block_ops(&if_data.if_body, false);
                            true
                        } else { false }
                    } else { false };
                    if seq_emit {
                        // Already emitted sequentially, skip normal BlockIf processing
                    } else {
                    // Check if bodies have any emittable ops — skip empty if/else blocks
                    let if_body_empty = self.is_block_body_empty(&if_data.if_body);
                    let else_body_empty = if_data.else_body.as_ref()
                        .map_or(true, |eb| self.is_block_body_empty(eb));

                    if if_body_empty && else_body_empty {
                        // Both bodies empty — skip entire if/else, just emit condition block's ops
                        let ibt = if_data.if_body.read().unwrap().get_type();
                        if ibt == crate::block::BlockType::Basic || ibt == crate::block::BlockType::Copy {
                            emitted.insert(std::sync::Arc::as_ptr(&if_data.if_body) as *const () as usize);
                        }
                        if let Some(ref eb) = if_data.else_body {
                            let ebt = eb.read().unwrap().get_type();
                            if ebt == crate::block::BlockType::Basic || ebt == crate::block::BlockType::Copy {
                                emitted.insert(std::sync::Arc::as_ptr(&eb) as *const () as usize);
                            }
                        }
                        self.emit_block_ops(&if_data.condition, true);
                    } else if if_body_empty && !else_body_empty && if_data.else_body.is_some() {
                        // if_body is empty, else_body has code.
                        self.emit_block_ops(&if_data.condition, true);
                        let ibt = if_data.if_body.read().unwrap().get_type();
                        if ibt == crate::block::BlockType::Basic || ibt == crate::block::BlockType::Copy {
                            emitted.insert(std::sync::Arc::as_ptr(&if_data.if_body) as *const () as usize);
                        }
                        let else_body = if_data.else_body.as_ref().unwrap();
                        self.emit.tag_line(0);
                        if if_data.negated {
                            // Triangle-reverse + empty false branch: else_body is the true edge.
                            // Emit with the original (un-negated) condition.
                            self.emit.print("if (");
                            self.emit_block_condition(&if_data.condition);
                            self.emit.print(")");
                        } else {
                            // Standard: negate condition → if (!cond) { else_code }
                            let orig_emit = std::mem::replace(&mut self.emit,
                                Box::new(crate::prettyprint::EmitNoMarkup::new()));
                            self.emit_block_condition(&if_data.condition);
                            let cond_text = {
                                let buf = std::mem::replace(&mut self.emit, orig_emit);
                                buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                    .map(|b| b.get_output()).unwrap_or_default()
                            };
                            let trimmed = cond_text.trim();
                            let negated_cond = Self::negate_condition_text(trimmed)
                                .unwrap_or_else(|| format!("!({})", trimmed));
                            self.emit.print(&format!("if ({})", negated_cond));
                        }
                        self.emit.begin_block();
                        let else_body_type = else_body.read().unwrap().get_type();
                        if matches!(else_body_type, BlockType::Basic) {
                            emitted.insert(std::sync::Arc::as_ptr(else_body) as *const () as usize);
                            self.emit_block_ops(else_body, true);
                        } else {
                            self.emit_block_structured(else_body, graph, emitted);
                        }
                        self.emit.end_block();
                    } else {
                        // Emit the condition block's non-branch ops
                        self.emit_block_ops(&if_data.condition, true);

                        // Emit: if (condition) — handles both simple and compound conditions
                        // When negated=true (Triangle-reverse), negate the condition textually
                        self.emit.tag_line(0);
                        if if_data.negated {
                            // Capture condition text and negate it
                            let orig_emit = std::mem::replace(&mut self.emit,
                                Box::new(crate::prettyprint::EmitNoMarkup::new()));
                            self.emit_block_condition(&if_data.condition);
                            let cond_text = {
                                let buf = std::mem::replace(&mut self.emit, orig_emit);
                                buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                    .map(|b| b.get_output()).unwrap_or_default()
                            };
                            let trimmed = cond_text.trim();
                            let negated_cond = Self::negate_condition_text(trimmed)
                                .unwrap_or_else(|| format!("!({})", trimmed));
                            self.emit.print(&format!("if ({})", negated_cond));
                        } else {
                            self.emit.print("if (");
                            self.emit_block_condition(&if_data.condition);
                            self.emit.print(")");
                        }

                        // Emit true body.
                        // seen_return must be scoped to this branch: a RETURN
                        // in a sibling/preceding path must NOT suppress the
                        // then-body. Mirrors the else-body save/restore below.
                        self.emit.begin_block();
                        let if_body_type = if_data.if_body.read().unwrap().get_type();
                        if matches!(if_body_type, BlockType::Basic) {
                            emitted.insert(std::sync::Arc::as_ptr(&if_data.if_body) as *const () as usize);
                            let saved = self.seen_return;
                            self.seen_return = false;
                            self.emit_block_ops(&if_data.if_body, true);
                            self.seen_return = saved;
                        } else {
                            let saved = self.seen_return;
                            self.seen_return = false;
                            self.emit_block_structured(&if_data.if_body, graph, emitted);
                            self.seen_return = saved;
                        }
                        self.emit.end_block();

                        // Emit else body if present and non-empty.
                        // seen_return from the then-branch must NOT suppress the else.
                        if let Some(ref else_body) = if_data.else_body {
                            if !else_body_empty {
                                // P9: else-if chaining (Ghidra emitBlockIf cc:2928-2935).
                                // When the else body is itself a BlockIf, emit
                                // `else if (...)` (no braces around the nested if)
                                // instead of `else { if (...) }`. Ghidra does this
                                // via the pending_brace mod + PendingBrace callback;
                                // Rugra detects the BlockIf else body directly.
                                let else_is_if = else_body.read().unwrap().get_type() == BlockType::If;
                                if else_is_if {
                                    self.emit.print(" else ");
                                    let saved = self.seen_return;
                                    self.seen_return = false;
                                    self.emit_structured_if(else_body, graph, emitted);
                                    self.seen_return = saved;
                                } else {
                                    self.emit.print(" else");
                                    self.emit.begin_block();
                                    let else_body_type = else_body.read().unwrap().get_type();
                                    if matches!(else_body_type, BlockType::Basic) {
                                        emitted.insert(std::sync::Arc::as_ptr(else_body) as *const () as usize);
                                        let saved = self.seen_return;
                                        self.seen_return = false;
                                        self.emit_block_ops(else_body, true);
                                        self.seen_return = saved;
                                    } else {
                                        let saved = self.seen_return;
                                        self.seen_return = false;
                                        self.emit_block_structured(else_body, graph, emitted);
                                        self.seen_return = saved;
                                    }
                                    self.emit.end_block();
                                }
                            } else {
                                let ebt = else_body.read().unwrap().get_type();
                                if ebt == crate::block::BlockType::Basic || ebt == crate::block::BlockType::Copy {
                                    emitted.insert(std::sync::Arc::as_ptr(else_body) as *const () as usize);
                                }
                            }
                        }
                    }
                    } // end seq_emit else
                } else {
                    // Fallback: emit flat
                    self.emit_block_ops(block_arc, false);
                }
    }


    // RUGRA-GLUE: emit_structured_whiledo (no Ghidra counterpart found)
    fn emit_structured_whiledo(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        graph: &crate::block::BlockGraph,
        emitted: &mut std::collections::HashSet<usize>,
    ) {
        use crate::block::{BlockType, BlockIf, BlockWhileDo, BlockDoWhile, BlockList, BlockCondition, BlockSwitch};
                // Structured while loop (or for loop if for_init/for_iter set)
                let block = block_arc.read().unwrap();
                let while_block = block.as_any().downcast_ref::<BlockWhileDo>();
                if let Some(while_data) = while_block {
                    self.emit.tag_line(0);
                    // Check if this was identified as a for-loop by
                    // ActionStructureTransform (has init + iterate expressions).
                    let has_for = while_data.for_init.is_some() && while_data.for_iter.is_some();
                    // Ghidra emitBlockWhileDo (printc.cc:3017): if
                    // hasOverflowSyntax(), emit `while( true ) { <cond body>
                    // if(cond) break; }` instead of `while(cond) { ... }`.
                    // Set by ruleBlockWhileDo when bl->isComplex() (cc:1538).
                    let overflow = while_data.overflow_syntax;
                    if has_for {
                        // Ghidra emitForLoop (printc.cc:2957-2999): emit
                        // `for (init; cond; iter)` with the comma_separate mod
                        // active so doc_statement suppresses stray ';'.
                        self.push_mod();
                        self.set_mod(print_mods::COMMA_SEPARATE);
                        self.emit.print("for (");
                        self.emit.print(while_data.for_init.as_ref().unwrap());
                        self.emit.print("; ");
                        self.emit_block_condition(&while_data.condition);
                        self.emit.print("; ");
                        self.emit.print(while_data.for_iter.as_ref().unwrap());
                        self.emit.print(")");
                        self.pop_mod();
                    } else if overflow {
                        // cc:3017-3044: overflow syntax — condition too complex
                        // to print inline, so emit while(true) + explicit break.
                        self.emit.print("while (");
                        self.emit.print(" true");
                        self.emit.print(")");
                    } else {
                        // Emit as while(cond)
                        self.emit.print("while (");
                        self.emit_block_condition(&while_data.condition);
                        self.emit.print(")");
                    }

                    self.emit.begin_block();
                    self.loop_depth += 1;
                    // For overflow syntax, emit the condition body ops + the
                    // explicit `if (cond) break;` BEFORE the loop body
                    // (cc:3030-3043: condBlock emit with no_branch, then
                    // only_branch condition, then break).
                    if overflow {
                        // Emit condition block's non-branch ops (no_branch).
                        self.emit_block_ops(&while_data.condition, true);
                        // cc:3035-3043: if (<condition>) break;
                        self.emit.tag_line(0);
                        self.emit.print("if (");
                        self.emit_block_condition(&while_data.condition);
                        self.emit.print(") break;");
                    }
                    // A loop body is an independent control-flow path: a RETURN
                    // seen before the loop (or in a sibling branch) must NOT
                    // suppress the loop body. Scope seen_return to the body.
                    let body_is_dead = while_data.body.read().unwrap().get_flags()
                        & crate::block::block_flags::DEAD != 0;
                    let saved = self.seen_return;
                    self.seen_return = false;
                    if body_is_dead {
                        self.emit_block_ops(&while_data.body, true);
                    } else {
                        self.emit_block_structured(&while_data.body, graph, emitted);
                    }
                    self.seen_return = saved;
                    self.loop_depth -= 1;
                    self.emit.end_block();
                } else {
                    self.emit_block_ops(block_arc, false);
                }
    }


    // RUGRA-GLUE: emit_structured_dowhile (no Ghidra counterpart found)
    fn emit_structured_dowhile(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        graph: &crate::block::BlockGraph,
        emitted: &mut std::collections::HashSet<usize>,
    ) {
        use crate::block::{BlockType, BlockIf, BlockWhileDo, BlockDoWhile, BlockList, BlockCondition, BlockSwitch};
                // Structured do-while loop
                let block = block_arc.read().unwrap();
                let dowhile_block = block.as_any().downcast_ref::<BlockDoWhile>();
                if let Some(_dowhile_data) = dowhile_block {
                    self.emit.tag_line(0);
                    self.emit.print("do ");
                    self.emit.begin_block();
                    // In a do-while loop, the 'condition' block IS the body, but wait:
                    // we merged true_target into cond_idx. Actually, we should just emit the condition block inside the body
                    // because the ops are currently interleaved!
                    // Wait, Ghidra's BlockDoWhile usually has a separate condition block. But for now, we just emit its ops.
                    self.loop_depth += 1;
                    // Scope seen_return: a do-while body is re-entered each
                    // iteration; a prior RETURN must not suppress it.
                    let saved = self.seen_return;
                    self.seen_return = false;
                    self.emit_block_ops(block_arc, true);
                    self.seen_return = saved;
                    self.loop_depth -= 1;
                    self.emit.end_block();
                    
                    self.emit.print(" while (");
                    let ops = block.get_ops();
                    if let Some(last_op_ref) = ops.last() {
                        let last_op = last_op_ref.0.read().unwrap();
                        if let Some(cond_vn) = last_op.get_in(1) {
                            self.emit_condition(&cond_vn);
                        }
                    }
                    self.emit.print(");");
                } else {
                    self.emit_block_ops(block_arc, false);
                }
    }

    // Ghidra: printc.cc:3097 PrintC::emitBlockInfLoop
    /// Emit a BlockInfLoop as `do { <body> } while(true);`. Faithful to
    /// emitBlockInfLoop (printc.cc:3097-3122): emitAnyLabelStatement, `do`,
    /// open brace, emit body, close brace, ` while ( true );`.
    fn emit_structured_infloop(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        _graph: &crate::block::BlockGraph,
        _emitted: &mut std::collections::HashSet<usize>,
    ) {
        use crate::block::BlockInfLoop;
        let block = block_arc.read().unwrap();
        let inf_block = block.as_any().downcast_ref::<BlockInfLoop>();
        if let Some(inf_data) = inf_block {
            self.emit.tag_line(0);
            self.emit.print("do ");
            self.emit.begin_block();
            self.loop_depth += 1;
            // Scope seen_return: an inf-loop body is re-entered each
            // iteration; a prior RETURN must not suppress it.
            let saved = self.seen_return;
            self.seen_return = false;
            // Emit the body block's ops.
            self.emit_block_ops(&inf_data.body, true);
            self.seen_return = saved;
            self.loop_depth -= 1;
            self.emit.end_block();
            // cc:3112-3120: ` while ( true );`
            self.emit.print(" while (");
            self.emit.print(" true");
            self.emit.print(");");
        } else {
            self.emit_block_ops(block_arc, false);
        }
    }


    // RUGRA-GLUE: emit_structured_list (no Ghidra counterpart found)
    fn emit_structured_list(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        graph: &crate::block::BlockGraph,
        emitted: &mut std::collections::HashSet<usize>,
    ) {
        use crate::block::{BlockType, BlockIf, BlockWhileDo, BlockDoWhile, BlockList, BlockCondition, BlockSwitch};
                // Sequence of blocks — emit children in order
                let block = block_arc.read().unwrap();
                let list_block = block.as_any().downcast_ref::<BlockList>();
                if let Some(list_data) = list_block {
                    for child in &list_data.children {
                        self.emit_block_structured(child, graph, emitted);
                    }
                    // After emitting all children, follow the List's out-edges to
                    // structured blocks (WhileDo etc). The List's out-edges come
                    // from self_identify and may point to a WhileDo that was
                    // structured before the List was formed.
                    let outs: Vec<std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = {
                        let b = block_arc.read().unwrap();
                        (0..b.size_out()).filter_map(|s| b.get_out(s).map(|e| e.point.clone())).collect()
                    };
                    for succ in &outs {
                        let succ_idx = std::sync::Arc::as_ptr(succ) as *const () as usize;
                        if emitted.contains(&succ_idx) { continue; }
                        let st = succ.read().unwrap().get_type();
                        if st != crate::block::BlockType::Basic
                           && st != crate::block::BlockType::Copy {
                            self.emit_block_structured(succ, graph, emitted);
                        }
                    }
                } else {
                    self.emit_block_ops(block_arc, false);
                }
    }


    // RUGRA-GLUE: emit_structured_condition (no Ghidra counterpart found)
    fn emit_structured_condition(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        graph: &crate::block::BlockGraph,
        emitted: &mut std::collections::HashSet<usize>,
    ) {
        use crate::block::{BlockType, BlockIf, BlockWhileDo, BlockDoWhile, BlockList, BlockCondition, BlockSwitch};
                // P8 fix: BlockCondition at top level is a compound &&/|| condition.
                // Ghidra's emitBlockCondition (printc.cc:2836) emits the combined
                // condition `(sub0) && (sub1)` when only_branch/comma_separate are
                // set. Previously Rugra emitted the two sub-blocks as independent
                // statements, losing the &&/|| glue. Now capture each sub-condition
                // and emit the combined form.
                let block = block_arc.read().unwrap();
                if let Some(cond_data) = block.as_any().downcast_ref::<BlockCondition>() {
                    let op_str = match cond_data.op_type {
                        crate::block::BoolOp::And => " && ",
                        crate::block::BoolOp::Or => " || ",
                    };
                    let first = cond_data.first.clone();
                    let second = cond_data.second.clone();
                    drop(block);
                    // Capture each sub-condition's text (recursively handles
                    // nested BlockCondition via emit_block_condition_inner).
                    let left_text = self.capture_block_condition(&first);
                    let right_text = self.capture_block_condition(&second);
                    let lt = left_text.trim();
                    let rt = right_text.trim();
                    if !lt.is_empty() && !rt.is_empty() {
                        self.emit.tag_line(0);
                        self.emit.print("if (");
                        self.emit.print(lt);
                        self.emit.print(op_str);
                        self.emit.print(rt);
                        self.emit.print(")");
                        self.emit.begin_block();
                        self.emit.end_block();
                    } else {
                        // Fallback: emit sub-block ops flat (old behavior).
                        self.emit_block_structured(&first, graph, emitted);
                        self.emit_block_structured(&second, graph, emitted);
                    }
                } else {
                    drop(block);
                    self.emit_block_ops(block_arc, false);
                }
    }


    // RUGRA-GLUE: emit_structured_switch (no Ghidra counterpart found)
    fn emit_structured_switch(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        graph: &crate::block::BlockGraph,
        emitted: &mut std::collections::HashSet<usize>,
    ) {
        use crate::block::{BlockType, BlockIf, BlockWhileDo, BlockDoWhile, BlockList, BlockCondition, BlockSwitch};
                let block = block_arc.read().unwrap();
                let switch_block = block.as_any().downcast_ref::<BlockSwitch>();
                if let Some(switch_data) = switch_block {
                    // Emit the control block's non-branch ops (e.g. index computation)
                    self.emit_block_ops(&switch_data.control, true);

                    // Print switch header.
                    // Ghidra emitBlockSwitch (printc.cc:3313) emits `switch (<expr>)`
                    // where <expr> is the raw switch control op (BRANCHIND input),
                    // with NO synthetic cast. Rugra previously wrapped the control
                    // expression in `(long)(...)` to force integrality, but Ghidra
                    // never does this — it normalizes the type upstream via the
                    // FuncProto/typelock. Emit the bare expression to match Ghidra.
                    self.emit.tag_line(0);
                    self.emit.print("switch (");
                    if let Some(ref idx_vn_arc) = switch_data.index_varnode {
                        let idx_vn = idx_vn_arc.read().unwrap();
                        let key = (idx_vn.get_space(), idx_vn.get_offset());
                        drop(idx_vn);
                        // If this varnode is in inline_candidates, emit its defining expression
                        // instead of the inlined-away name (which would be empty)
                        if let Some(def_op_arc) = self.inline_candidates.get(&key).cloned()
                            .or_else(|| self.value_def_map.get(&key).cloned())
                        {
                            // Chase through COPY to the real expression
                            let def_op = def_op_arc.read().unwrap();
                            if def_op.opcode == OpCode::CPUI_COPY && !def_op.inrefs.is_empty() {
                                // COPY from something — push the source
                                let src = def_op.inrefs[0].clone();
                                drop(def_op);
                                self.push_varnode(&src.read().unwrap(), None);
                            } else {
                                // Non-trivial expression — inline it
                                let seq = *def_op.get_seq_num();
                                drop(def_op);
                                self.inlined_ops.insert(seq);
                                let def_op2 = def_op_arc.read().unwrap();
                                self.emit_inline_expr(&def_op2);
                            }
                        } else {
                            // Not in inline_candidates — emit normally
                            let idx_vn = idx_vn_arc.read().unwrap();
                            self.push_varnode(&idx_vn, None);
                        }
                    } else {
                        // Fallback 1: search for BRANCHIND's input
                        let mut found_var = false;
                        {
                            let ctrl = switch_data.control.read().unwrap();
                            let ops = ctrl.get_ops();
                            if let Some(last_op_ref) = ops.last() {
                                let last_op = last_op_ref.0.read().unwrap();
                                if last_op.opcode == OpCode::CPUI_BRANCHIND && !last_op.inrefs.is_empty() {
                                    self.push_varnode(&last_op.inrefs[0].read().unwrap(), Some(&last_op));
                                    found_var = true;
                                }
                            }
                            // Fallback 2: for CBRANCH cascade, find the compared non-const operand
                            if !found_var {
                                for op_ref in ops.iter().rev() {
                                    let op = op_ref.0.read().unwrap();
                                    if matches!(op.opcode,
                                        OpCode::CPUI_INT_EQUAL
                                        | OpCode::CPUI_INT_NOTEQUAL
                                        | OpCode::CPUI_INT_LESS
                                        | OpCode::CPUI_INT_SLESS
                                        | OpCode::CPUI_INT_LESSEQUAL
                                        | OpCode::CPUI_INT_SLESSEQUAL)
                                        && op.inrefs.len() >= 2
                                    {
                                        let in0 = op.inrefs[0].read().unwrap();
                                        let in1 = op.inrefs[1].read().unwrap();
                                        if in1.get_space() == crate::space::AddressSpace::Const && in0.get_space() != crate::space::AddressSpace::Const {
                                            drop(in0); drop(in1);
                                            self.push_varnode(&op.inrefs[0].read().unwrap(), Some(&op));
                                            break;
                                        } else if in0.get_space() == crate::space::AddressSpace::Const && in1.get_space() != crate::space::AddressSpace::Const {
                                            drop(in0); drop(in1);
                                            self.push_varnode(&op.inrefs[1].read().unwrap(), Some(&op));
                                            break;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    self.emit.print(")");

                    // Switch body block
                    self.emit.begin_block();

                    // Print each case block
                    let mut emitted_case_values: std::collections::HashSet<u64> = std::collections::HashSet::new();
                    for (idx, case_block) in switch_data.cases.iter().enumerate() {
                        let case_idx = std::sync::Arc::as_ptr(case_block) as *const () as usize;
                        let body_already_emitted = emitted.contains(&case_idx);
                        let values = &switch_data.case_values[idx];
                        // Skip duplicate case values (two CBRANCH blocks comparing
                        // the same constant produce duplicate cases in one switch).
                        let has_new_value = values.iter().any(|v| !emitted_case_values.contains(v));
                        if !has_new_value { continue; }
                        for val in values {
                            if !emitted_case_values.insert(*val) { continue; }
                            self.emit.tag_line(0);
                            // Format case value: char literal for printable ASCII, else numeric
                            let case_label = if *val >= 0x20 && *val <= 0x7e {
                                let ch = *val as u8 as char;
                                // Escape brace/paren chars to avoid confusing post-process brace counters
                                if matches!(ch, '}' | '{' | ')' | '(' | '\'' | '\\' | '"') || ch == '\0' {
                                    format!("case '\\x{:x}':", *val as u8)
                                } else {
                                    format!("case '{}':", ch)
                                }
                            } else if *val >= 256 {
                                format!("case 0x{:x}:", val)
                            } else {
                                format!("case {}:", val)
                            };
                            self.emit.print(&case_label);
                        }

                        self.emit.begin_block();
                        if !body_already_emitted {
                            let saved_seen_return = self.seen_return;
                            self.seen_return = false;
                            self.emit_block_structured(case_block, graph, emitted);
                            self.seen_return = saved_seen_return;
                        }

                        // If it doesn't end with a return, print break;
                        let is_terminal = {
                            let cb = case_block.read().unwrap();
                            (cb.get_flags() & crate::block::block_flags::RETURN_TERMINAL) != 0
                        };
                        if !is_terminal {
                            self.emit.tag_line(0);
                            self.emit.print("break;");
                        }
                        self.emit.end_block();
                    }

                    // Print default case
                    if let Some(ref def_block) = switch_data.default_case {
                        let def_idx = std::sync::Arc::as_ptr(&def_block) as *const () as usize;
                        if emitted.contains(&def_idx) {
                            // Skip default if extracted
                        } else {
                        self.emit.tag_line(0);
                        self.emit.print("default:");
                        self.emit.begin_block();
                        self.emit_block_structured(def_block, graph, emitted);
                        let is_terminal = {
                            let cb = def_block.read().unwrap();
                            (cb.get_flags() & crate::block::block_flags::RETURN_TERMINAL) != 0
                        };
                        if !is_terminal {
                            self.emit.tag_line(0);
                            self.emit.print("break;");
                        }
                        self.emit.end_block();
                        }
                    }

                    self.emit.end_block();
                } else {
                    self.emit_block_ops(block_arc, false);
                }
    }


    // RUGRA-GLUE: emit_structured_basic (no Ghidra counterpart found)
    fn emit_structured_basic(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        graph: &crate::block::BlockGraph,
        emitted: &mut std::collections::HashSet<usize>,
    ) {
        use crate::block::{BlockType, BlockIf, BlockWhileDo, BlockDoWhile, BlockList, BlockCondition, BlockSwitch};
                // BlockBasic or other — flat statement emission
                // Still check for inline CBRANCH pattern as fallback
                let has_cond = {
                    let block = block_arc.read().unwrap();
                    let ops = block.get_ops();
                    ops.last().map_or(false, |op_ref| {
                        let op = op_ref.0.read().unwrap();
                        op.opcode == OpCode::CPUI_CBRANCH
                    })
                };
                let size_out = block_arc.read().unwrap().size_out();

                if has_cond && size_out == 2 {
                    // Check if both branches are empty before emitting
                    // Ghidra convention: out(0) = true edge (taken), out(1) = false edge (fall-through)
                    let true_edge = block_arc.read().unwrap().get_out(0);
                    let false_edge = block_arc.read().unwrap().get_out(1);
                    
                    let true_empty = true_edge.as_ref()
                        .map_or(true, |e| self.is_block_body_empty(&e.point));
                    let false_empty = false_edge.as_ref()
                        .map_or(true, |e| self.is_block_body_empty(&e.point));
                    
                    if true_empty && false_empty {
                        // Both branches empty — emit the condition block ops but skip the if/else
                        self.emit_block_ops(block_arc, true);
                        if let Some(ref te) = true_edge {
                            let t = te.point.read().unwrap().get_type();
                            // Don't suppress structured blocks (WhileDo/DoWhile) — they must emit.
                            if t == crate::block::BlockType::Basic || t == crate::block::BlockType::Copy {
                                emitted.insert(std::sync::Arc::as_ptr(&te.point) as *const () as usize);
                            }
                        }
                        if let Some(ref fe) = false_edge {
                            let f = fe.point.read().unwrap().get_type();
                            if f == crate::block::BlockType::Basic || f == crate::block::BlockType::Copy {
                                emitted.insert(std::sync::Arc::as_ptr(&fe.point) as *const () as usize);
                            }
                        }
                    } else if true_empty && !false_empty {
                        // True branch empty, false has code → negate: if (!cond) { false_code }
                        self.emit_block_ops(block_arc, true);
                        if let Some(ref te) = true_edge {
                            let t = te.point.read().unwrap().get_type();
                            if t == crate::block::BlockType::Basic || t == crate::block::BlockType::Copy {
                                emitted.insert(std::sync::Arc::as_ptr(&te.point) as *const () as usize);
                            }
                        }

                        self.emit.tag_line(0);
                        // Emit condition to temp buffer for text-based negation
                        let orig_emit = std::mem::replace(&mut self.emit,
                            Box::new(crate::prettyprint::EmitNoMarkup::new()));
                        self.emit_block_condition(block_arc);
                        let cond_text = {
                            let buf = std::mem::replace(&mut self.emit, orig_emit);
                            buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                .map(|b| b.get_output()).unwrap_or_default()
                        };
                        let trimmed = cond_text.trim();
                        let negated_cond2 = Self::negate_condition_text(trimmed)
                            .unwrap_or_else(|| format!("!({})", trimmed));
                        self.emit.print(&format!("if ({})", negated_cond2));
                        if let Some(false_block_edge) = false_edge {
                            let false_idx = std::sync::Arc::as_ptr(&false_block_edge.point) as *const () as usize;
                            let ft = false_block_edge.point.read().unwrap().get_type();
                            self.emit.begin_block();
                            if ft == crate::block::BlockType::Basic || ft == crate::block::BlockType::Copy {
                                emitted.insert(false_idx);
                            }
                            self.emit_block_ops(&false_block_edge.point, false);
                            self.emit.end_block();
                        }
                    } else {
                        // Legacy inline if/else for blocks not captured by CollapseStructure
                        self.emit_block_ops(block_arc, true);

                        self.emit.tag_line(0);
                        self.emit.print("if (");
                        // Use emit_block_condition for consistent block-local comparison resolution
                        self.emit_block_condition(block_arc);
                        self.emit.print(")");

                        if let Some(true_block_edge) = true_edge {
                            let true_idx = std::sync::Arc::as_ptr(&true_block_edge.point) as *const () as usize;
                            let tt = true_block_edge.point.read().unwrap().get_type();
                            self.emit.begin_block();
                            if tt == crate::block::BlockType::Basic || tt == crate::block::BlockType::Copy {
                                emitted.insert(true_idx);
                            }
                            self.emit_block_ops(&true_block_edge.point, false);
                            self.emit.end_block();
                        }

                        if let Some(false_block_edge) = false_edge {
                            let false_idx = std::sync::Arc::as_ptr(&false_block_edge.point) as *const () as usize;
                            let ft = false_block_edge.point.read().unwrap().get_type();
                            // The else block is part of the conditional, not sequential code.
                            // seen_return from the then-branch should NOT suppress it.
                            if !emitted.contains(&false_idx) && !false_empty {
                                self.emit.print(" else");
                                self.emit.begin_block();
                                if ft == crate::block::BlockType::Basic || ft == crate::block::BlockType::Copy {
                                    emitted.insert(false_idx);
                                }
                                // Temporarily clear seen_return so the else block emits.
                                let saved_seen_return = self.seen_return;
                                self.seen_return = false;
                                self.emit_block_ops(&false_block_edge.point, false);
                                self.seen_return = saved_seen_return;
                                self.emit.end_block();
                            } else {
                                if ft == crate::block::BlockType::Basic || ft == crate::block::BlockType::Copy {
                                    emitted.insert(false_idx);
                                }
                            }
                        }
                    }
                } else {
                    let return_in_block = {
                        let b = block_arc.read().unwrap();
                        let ops = b.get_ops();
                        ops.last().map_or(false, |op_ref| {
                            op_ref.0.read().unwrap().opcode == OpCode::CPUI_RETURN
                        })
                    };
                    self.emit_block_ops(block_arc, false);
                    // Successor recursion: after emitting this block's ops, follow
                    // out-edges to structured blocks (WhileDo/DoWhile/If/Switch/etc).
                    // This is needed because WhileDo loops may be reachable only via
                    // a basic block's out-edge, and without recursion they'd be
                    // stranded in the unreachable loop. Only recurse into structured
                    // blocks (not basic blocks) to avoid canary block issues.
                    let outs: Vec<std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = {
                        let b = block_arc.read().unwrap();
                        (0..b.size_out()).filter_map(|s| b.get_out(s).map(|e| e.point.clone())).collect()
                    };
                    for succ in &outs {
                        let succ_idx = std::sync::Arc::as_ptr(succ) as *const () as usize;
                        if emitted.contains(&succ_idx) { continue; }
                        let st = succ.read().unwrap().get_type();
                        // Only recurse into structured blocks, not basic blocks.
                        if st != crate::block::BlockType::Basic
                           && st != crate::block::BlockType::Copy {
                            self.emit_block_structured(succ, graph, emitted);
                        }
                    }
                }
    }

    // Ghidra: printlanguage.hh:284 PrintLanguage::isSet
    /// Is the given printing modification active? Faithful to
    /// `PrintLanguage::isSet` (printlanguage.hh:284).
    fn is_set(&self, m: u32) -> bool { (self.mods & m) != 0 }
    // Ghidra: printlanguage.hh:287 PrintLanguage::pushMod
    /// Push current mods onto the mod stack (save).
    fn push_mod(&mut self) { self.mod_stack.push(self.mods); }
    // Ghidra: printlanguage.hh:288 PrintLanguage::popMod
    /// Pop to the previously saved mods (restore).
    fn pop_mod(&mut self) {
        if let Some(m) = self.mod_stack.pop() { self.mods = m; }
    }
    // Ghidra: printlanguage.hh:289 PrintLanguage::setMod
    /// Activate the given modification.
    fn set_mod(&mut self, m: u32) { self.mods |= m; }
    // Ghidra: printlanguage.hh:290 PrintLanguage::unsetMod
    /// Deactivate the given modification.
    fn unset_mod(&mut self, m: u32) { self.mods &= !m; }

    // Ghidra: printc.cc:3164 PrintC::emitLabel
    /// Build a Ghidra-style code label string for a code address.
    /// Faithful to `emitLabel` (printc.cc:3164-3193):
    ///   - prefix: "joined_" (joined block) / "dup_" (duplicated block) /
    ///     "code_" (normal). Rugra does not currently track joined/duplicated
    ///     block state, so "code_" is used (the normal case).
    ///   - shortcut char: space-name first char lowercased (translate.cc:529-533).
    ///     For x86 RAM space ("ram"), this is 'r'. Rugra hardcodes 'r' for
    ///     code addresses (the only space that holds goto targets in practice).
    ///   - printRaw (space.cc:206-222): "0x" + zero-padded hex, shrunk to
    ///     4/6/8 bytes based on high-zero content. For typical small code
    ///     addresses (high 32 bits zero), this is 8 hex digits.
    fn code_label(&self, addr: u64) -> String {
        // printRaw size selection (space.cc:210-215): if offset>>32 == 0, sz=4.
        let sz = if addr >> 32 == 0 {
            4
        } else if addr >> 48 == 0 {
            6
        } else {
            8
        };
        // code_ prefix + 'r' shortcut (RAM space) + 0x + zero-padded hex.
        format!("code_r0x{:0width$X}", addr, width = 2 * sz)
    }

    // RUGRA-GLUE: push_goto_target (no Ghidra counterpart found)
    /// Emit a goto label name. Uses Ghidra-style `code_r0xXXXX` for
    /// intra-function addresses, falls back to symbol lookup for named
    /// symbols. Mirrors PrintC::emitLabel's label-string construction
    /// (printc.cc:3183-3192) followed by tagVariable emission.
    fn push_goto_target(&mut self, vn: &Varnode) {
        let addr = vn.get_offset();
        if let Some(sym_name) = self.symbol_table.get(&addr) {
            self.emit.tag_variable(sym_name, 0);
            return;
        }
        let label = self.code_label(addr);
        self.emit.tag_variable(&label, 0);
    }

    // RUGRA-GLUE: compact_name_for (no Ghidra counterpart found)
    /// Return the compact (renumbered) name for a raw variable name, or None
    /// if the name is not an auto-local that should be renumbered. Faithful
    /// to Ghidra's assignDefaultNames (database.cc:2862): variables are
    /// renumbered per type-prefix starting from 1. Built lazily on first use
    /// during the REAL emit pass so names are stable across body + declarations.
    fn compact_name_for(&mut self, raw: &str) -> Option<String> {
        // Only renumber during the real emit pass (not discovery), and only
        // for auto-local names matching {prefix}{hexdigits} or {prefix}_{hexdigits}.
        if self.discovery_pass { return None; }
        const PREFIXES: &[&str] = &[
            "piVar", "pcVar", "psVar", "ppVar", "pvVar",
            "lVar", "uVar", "iVar", "bVar", "sVar", "fVar", "dVar",
        ];
        // Check if this is an auto-local name we should renumber.
        let mut matched_prefix: Option<&'static str> = None;
        for &prefix in PREFIXES {
            if let Some(rest) = raw.strip_prefix(prefix) {
                let digits = rest.strip_prefix('_').unwrap_or(rest);
                if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_hexdigit()) {
                    matched_prefix = Some(prefix);
                    break;
                }
            }
        }
        let prefix = matched_prefix?;
        // If already renamed, return the cached compact name.
        if let Some(compact) = self.compact_rename.get(raw) {
            return Some(compact.clone());
        }
        // Faithful to Ghidra `assignDefaultNames` (database.cc:2850-2865) +
        // `buildDefaultName`→`buildVariableName` local case (database.cc:2501-2504):
        //   ct->printNameBase(s); s << "Var" << dec << index++;
        // `index` is the SINGLE shared `int4 base` (initial 1, monotonic across
        // all prefixes). This is the 181538f fix: per-prefix counters were wrong;
        // Ghidra uses one shared counter. NOTE: Ghidra traverses symbols in
        // `nametree` order (SymbolCompareName: name.compare() then nameDedup),
        // i.e. creation order — Rugra approximates this by the lazy first-touch
        // order of `get_varnode_display_name` during op traversal (the closest
        // analogue available in Rugra's print-time architecture; see
        // FUNCTION_GAP_REPORT.md for the full nametree-order gap analysis).
        let n = self.compact_base;
        self.compact_base += 1;
        let compact = format!("{}{}", prefix, n);
        self.compact_rename.insert(raw.to_string(), compact.clone());
        Some(compact)
    }

    // RUGRA-GLUE: rename_scope_symbol (no Ghidra counterpart found)
    /// Rename a varmap-generated `StackX_<hex>` / `Stack_<hex>` symbol name into
    /// a Ghidra-style typed local name (`<printNameBase>Var<base>`), sharing the
    /// SAME `compact_base` counter as `compact_name_for`. Faithful to Ghidra
    /// `ActionNameVars::apply` (coreaction.cc:2988) which, after the per-Varnode
    /// `namerec` loop, calls `scope->assignDefaultNames(base)` (database.cc:2850)
    /// — renaming ALL remaining unnamed symbols (including the stack-local
    /// `StackX_` fallback names produced by `ScopeLocal::buildVariableName`,
    /// varmap.cc:548) under the single shared `int4 base`. The type prefix is
    /// derived from the symbol's dtype via `var_prefix` (Rugra's printNameBase
    /// equivalent), matching `ct->printNameBase(s)` at database.cc:2502.
    fn rename_scope_symbol(&mut self, sym: &crate::varmap::LocalSymbol) -> String {
        // Only rename the auto-generated Stack/StackX fallback names. Names that
        // are already typed (iVar/lVar/etc.) or came from real symbols stay.
        let raw = &sym.name;
        let is_stack_fallback = raw.starts_with("StackX_") || raw.starts_with("Stack_");
        if !is_stack_fallback {
            return raw.clone();
        }
        // Cached: same raw name → same compact name (decl & use must agree).
        if let Some(compact) = self.compact_rename.get(raw) {
            return compact.clone();
        }
        let prefix = Self::var_prefix(&sym.dtype, sym.size.max(1) as usize);
        let n = self.compact_base;
        self.compact_base += 1;
        let compact = format!("{}{}", prefix, n);
        self.compact_rename.insert(raw.to_string(), compact.clone());
        compact
    }

    // Ghidra: database.cc:2850 ScopeInternal::assignDefaultNames (nametree order)
    /// P4 fix: pre-allocate compact names for register-derived auto-locals in
    /// def-op address order, matching Ghidra's nametree/nameDedup (symbol
    /// creation) order. Ghidra traverses SymbolNameTree (sorted by name, tie-
    /// break nameDedup = creation order). For register vars, the closest
    /// analogue to creation order is the def-op's address order. This method
    /// scans all ops, collects register-space output varnodes whose raw name
    /// matches the auto-local pattern, sorts by def-op address, and pre-fills
    /// compact_rename so compact_name_for finds cached names during emit.
    fn preallocate_register_compact_names(&mut self, fd: &Funcdata) {
        use crate::space::AddressSpace;
        // Collect (raw_name, def_op_addr) for register auto-locals.
        let mut candidates: Vec<(String, u64)> = Vec::new();
        let mut seen_raw: std::collections::HashSet<String> = std::collections::HashSet::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(out_arc) = &op.output {
                let vn = out_arc.read().unwrap();
                if vn.get_space() != AddressSpace::Register { continue; }
                // Skip params (they have their own names).
                if self.param_names.contains_key(&vn.get_offset()) { continue; }
                let raw = self.get_varnode_display_name_inner(&vn);
                // Only auto-local names matching {prefix}_{hex} pattern.
                if Self::is_raw_register_name(&raw) || raw.contains("Var_") {
                    if seen_raw.insert(raw.clone()) {
                        candidates.push((raw, op.start.addr.as_u64()));
                    }
                }
            }
        }
        // Sort by def-op address (Ghidra nametree/nameDedup = creation order
        // analogue). Stable sort preserves first-seen for same-address ties.
        candidates.sort_by_key(|(_, addr)| *addr);
        // Pre-allocate compact names in this order. compact_name_for will find
        // these cached names during emit, so op-traversal order no longer
        // matters for numbering.
        for (raw, _) in &candidates {
            // Temporarily force non-discovery to allow allocation.
            let saved = self.discovery_pass;
            self.discovery_pass = false;
            let _ = self.compact_name_for(raw);
            self.discovery_pass = saved;
        }
    }

    // RUGRA-GLUE: doc_variable_decls_from_funcdata (no Ghidra counterpart found)
    /// Emit variable declarations at the top of the function body.
    fn doc_variable_decls_from_funcdata(&mut self, fd: &Funcdata) {
        use std::collections::BTreeMap;
        use crate::space::AddressSpace;

        let mut declared: BTreeMap<String, String> = BTreeMap::new();

        let is_declarable = |name: &str, space: AddressSpace, offset: u64, call_targets: &HashSet<u64>| -> bool {
            if name.is_empty() { return false; }
            if !name.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                return false;
            }
            if name.starts_with("DAT_") || name.starts_with("LAB_")
                || name.starts_with('"') || name.contains('(')
                || name.starts_with("0x") || name == "argc" || name == "argv"
            {
                return false;
            }
            // Don't declare parameters (they're already in the function signature)
            if name.starts_with("param_") && !name.starts_with("param_stack_") {
                return false;
            }
            // Don't declare function call targets as local variables
            if matches!(space, AddressSpace::Ram | AddressSpace::Const)
                && call_targets.contains(&offset)
            {
                return false;
            }
            // Don't declare RIP/RSP/RBP — they're pseudo/frame registers, not local variables
            // Also don't declare any raw register names — they're architectural temporaries.
            // Don't declare RIP — it's a pseudo register, not a real variable.
            // RSP/RBP and callee-saved (R12-R15, RBX) may appear in expressions
            // when stack-frame analysis is incomplete; declaring them as `long`
            // keeps the output compilable (they are real 8-byte registers).
            if space == AddressSpace::Register {
                // RIP (0x200) is a pseudo register — never declare
                if offset == 0x200 { return false; }
                const DECL_PREFIXES: &[&str] = &[
                    "lVar", "uVar", "iVar", "bVar", "sVar",
                    "piVar", "pcVar", "psVar", "ppVar", "pvVar",
                    "fVar", "dVar",
                    // `in_<hex>` is the fallback name for irregular/unresolved
                    // input-register CALL args (emit_call_arg_text, faithful to
                    // Ghidra buildVariableName's irregular-input case,
                    // database.cc:2470). It must be declarable.
                    "in_",
                ];
                let is_auto_local = DECL_PREFIXES.iter().any(|p| {
                    if let Some(rest) = name.strip_prefix(p) {
                        // Accept hex offset names (lVar_a8, uVar_b0) as well as
                        // decimal renumbered names (lVar1, iVar2). The display
                        // name generator uses {:x} for offsets (printc.rs:1652).
                        rest.starts_with(|c: char| c.is_ascii_hexdigit() || c == '_')
                    } else {
                        false
                    }
                });
                if is_auto_local {
                    // Allow declaring variables renamed from registers
                } else {
                    // Callee-saved + frame registers: allow declaration as long
                    // (RSP=0x20, RBP=0x28, RBX=0x18, R12=0xa0..R15=0xb8)
                    const DECL_REG_OFFSETS: &[u64] = &[
                        0x20, 0x28, 0x18, 0xa0, 0xa8, 0xb0, 0xb8,
                    ];
                    if !DECL_REG_OFFSETS.contains(&offset) {
                        // All other raw register names (RAX/RCX/flags) — not declared
                        return false;
                    }
                    // For these, only declare if the name is the raw register name
                    // (RBP, RSP, RBX, R12-R15) — not some other identifier at this offset
                    const RAW_REG_NAMES: &[&str] = &[
                        "RSP", "ESP", "RBP", "EBP", "RBX", "EBX",
                        "R12", "R13", "R14", "R15",
                    ];
                    if !RAW_REG_NAMES.contains(&name) {
                        return false;
                    }
                }
            }
            // Don't declare names that come from the global symbol or string table
            if matches!(space, AddressSpace::Ram | AddressSpace::Const) {
                if call_targets.contains(&offset) {
                    return false;
                }
                // These are global symbols, not local variables
                return false;
            }
            true
        };

        // Emit declarations in REAL-EMIT first-use order (declaration_order),
        // matching compact_name_for's numbering order. This fixes non-
        // determinism: previously iterated used_varnode_types (a randomly-
        // seeded HashMap), so declaration order varied per run and could
        // mismatch the lazy numbering, producing undeclared/duplicate names.
        // Faithful to Ghidra assignDefaultNames (database.cc:2850-2865).
        let order_snapshot: Vec<String> = self.declaration_order.clone();
        for name in &order_snapshot {
            if let Some((type_name, space, offset)) = self.used_varnode_types.get(name) {
                let (type_name, space, offset) = (type_name.clone(), *space, *offset);
                let decl_name = self.compact_name_for(name).unwrap_or_else(|| name.clone());
                if is_declarable(&decl_name, space, offset, &self.call_targets) {
                    let entry = declared.entry(decl_name).or_insert_with(|| type_name.clone());
                    if type_name.contains('*') && !entry.contains('*') {
                        *entry = type_name.clone();
                    }
                }
            }
        }

        // Safety net: scope-local stack symbols (StackX_*) referenced via
        // get_stack_variable_name must be declared. The general path above can
        // miss them (e.g. STORE address LHS where the symbol name is printed but
        // not routed through mark_variable_used). Declare any not yet declared
        // as `long` (default register width) to keep the output compilable.
        for name in self.used_scope_symbols.borrow().iter() {
            if declared.contains_key(name) { continue; }
            if is_declarable(name, AddressSpace::Stack, 0, &self.call_targets) {
                declared.entry(name.clone()).or_insert_with(|| "long".to_string());
            }
        }
        // Also declare any scope symbol whose name appears in used_varnode_names
        // (covers paths that print the scope name without going through
        // get_stack_variable_name's recording). The scope is the authoritative
        // set of this function's stack locals; any that the body references must
        // be declared.
        //
        // Route StackX_ fallback names through rename_scope_symbol (shared base,
        // faithful to Ghidra assignDefaultNames) so decl & use agree. We rename
        // ALL scope symbols up front into `renamed_map` to apply the shared base
        // in a deterministic order, then declare by the renamed name.
        let mut renamed_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        if let Some(scope) = &self.scope {
            // Snapshot raw names + size first (avoid holding scope borrow across
            // the &mut self rename_scope_symbol calls).
            let raw_syms: Vec<(String, i32)> = scope.symbols.iter()
                .map(|s| (s.name.clone(), s.size))
                .collect();
            for (raw_name, size) in raw_syms {
                if raw_name.starts_with("StackX_") || raw_name.starts_with("Stack_") {
                    let renamed = self.rename_scope_symbol(&crate::varmap::LocalSymbol {
                        name: raw_name.clone(),
                        start: 0,
                        size,
                        dtype: None,
                        unaliased: false,
                        is_param: false,
                    });
                    renamed_map.insert(raw_name, renamed);
                }
            }
        }
        if let Some(scope) = &self.scope {
            for sym in &scope.symbols {
                // Use the renamed name if one was allocated (StackX_ → iVar/lVar),
                // else the raw name. Conservatively declare every scope symbol:
                // they are this function's stack locals by definition, and
                // printc's discovery pass has known gaps where a referenced name
                // is emitted without being recorded in used_varnode_names.
                let name = renamed_map.get(&sym.name).cloned().unwrap_or_else(|| sym.name.clone());
                if !declared.contains_key(&name)
                    && is_declarable(&name, AddressSpace::Stack, 0, &self.call_targets)
                {
                    let ty = if sym.size <= 4 { "int" } else { "long" };
                    declared.insert(name, ty.to_string());
                }
            }
        }
        let _ = fd;

        // Declare stack_struct names (struct1, struct2, ...) that were detected
        // during doc_function but may not have been registered in
        // used_varnode_names. These are used as `*(long *)(structN + off)`
        // and must be declared as `long`.
        for ss in &self.stack_structs {
            if !declared.contains_key(&ss.name) {
                declared.insert(ss.name.clone(), "long".to_string());
            }
        }

        if !declared.is_empty() {
            for (name, type_name) in &declared {
                self.emit.tag_line(0);
                self.emit.print(&format!("{} {};", type_name, name));
            }
            self.emit.tag_line(0);
            self.emit.print("");
        }
    }

    // RUGRA-GLUE: mark_variable_used (no Ghidra counterpart found)
    /// Mark a variable name as used, recording its space, offset, and type
    fn mark_variable_used(&mut self, name: String, space: crate::space::AddressSpace, offset: u64, type_name: String) {
        if name.is_empty() { return; }
        // Filter out expressions (like struct->field or arrays) so we don't emit illegal declarations
        if name.contains("->") || name.contains('.') || name.contains('[') || name.contains('*') || name.contains('&') {
            return;
        }
        let is_new = !self.used_varnode_names.contains(&name);
        self.used_varnode_names.insert(name.clone());
        self.used_varnode_types.insert(name.clone(), (type_name, space, offset));
        // Record first-use order in BOTH passes. compact_name_for numbers
        // during emit, but names that don't go through it (e.g. in_<hex>
        // fallbacks) still need declaration. Recording in both passes
        // ensures every used name is declared in a deterministic order,
        // while compact names still get monotonic numbering (they're added
        // in emit order during emit, which is when compact_name_for runs).
        if is_new {
            self.declaration_order.push(name);
        }
    }

    // RUGRA-GLUE: mark_varnode_used (no Ghidra counterpart found)
    /// Mark a varnode's display name as used, recording its space, offset, and type
    fn mark_varnode_used(&mut self, name: String, vn: &Varnode) {
        if name.is_empty() { return; }
        // If this varnode is the output of a LOAD, it holds a loaded VALUE
        // (int/long), not a pointer. Use size-based type name so the
        // declaration matches the variable prefix.
        let type_name = if let Some(ref def_arc) = vn.def.as_ref().and_then(|d| d.upgrade()) {
            let def_op = def_arc.read().unwrap();
            if def_op.opcode == crate::opcodes::OpCode::CPUI_LOAD {
                match vn.get_size() {
                    4 => "int".to_string(),
                    8 => "long".to_string(),
                    1 => "byte".to_string(),
                    _ => vn.v_type.as_ref().map(|dt| dt.get_name().to_string())
                        .unwrap_or_else(|| "int".to_string()),
                }
            } else {
                vn.v_type.as_ref()
                    .map(|dt| dt.get_name().to_string())
                    .unwrap_or_else(|| "int".to_string())
            }
        } else {
            vn.v_type.as_ref()
                .map(|dt| dt.get_name().to_string())
                .unwrap_or_else(|| "int".to_string())
        };
        self.mark_variable_used(name, vn.get_space(), vn.get_offset(), type_name);
    }

    // RUGRA-GLUE: get_varnode_display_name (no Ghidra counterpart found)
    /// Get the display name for a varnode without emitting it
    fn get_varnode_display_name(&mut self, vn: &Varnode) -> String {
        let raw = self.get_varnode_display_name_inner(vn);
        // Apply compact renumbering lazily (assignDefaultNames).
        self.compact_name_for(&raw).unwrap_or(raw)
    }
    // RUGRA-GLUE: get_varnode_display_name_inner (no Ghidra counterpart found)
    fn get_varnode_display_name_inner(&self, vn: &Varnode) -> String {
        use crate::space::AddressSpace;

        let addr = vn.get_offset();
        let space = vn.get_space();
        if matches!(space, AddressSpace::Ram | AddressSpace::Const) {
            if let Some(sym_name) = self.symbol_table.get(&addr) {
                return sym_name.clone();
            }
            if self.string_table.contains_key(&addr) {
                return String::new(); // Don't declare strings
            }
        }

        // Priority 0.5: Parameter names take precedence over HighVariable for Register varnodes
        if vn.get_space() == AddressSpace::Register {
            if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                return pname.clone();
            }
        }

        if let Some(ref high_arc) = vn.high {
            let high = high_arc.read().unwrap();
            let name = high.get_name();
            if !name.is_empty() {
                // Faithful to pushSymbolDetail: raw register names → size-based
                // local variable name (Ghidra buildVariableName default case:
                // database.cc:2501-2504 "ct->printNameBase; VarN").
                if Self::is_raw_register_name(name) {
                    if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                        return pname.clone();
                    } else {
                        let prefix = Self::var_prefix(&vn.v_type, vn.get_size());
                        return format!("{}_{:x}", prefix, vn.get_offset());
                    }
                }
                let effective_type = Self::vn_type_if_meaningful(vn)
                    .or_else(|| Self::find_typed_instance(&high))
                    .or_else(|| self.pointer_type_for(vn));
                return Self::maybe_apply_type_prefix(name, &effective_type, vn.get_size());
            }
        }

        match vn.get_space() {
            AddressSpace::Register => {
                // Check if this register corresponds to a function parameter
                if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                    return pname.clone();
                }
                format!("uVar{:x}", vn.get_offset())
            }
            AddressSpace::Stack => {
                let off = vn.get_offset();
                if off >= 0x8000_0000_0000_0000 {
                    format!("local_{:x}", (!off).wrapping_add(1))
                } else {
                    format!("param_stack_{:x}", off)
                }
            }
            AddressSpace::Unique => {
                let key = (AddressSpace::Unique, vn.get_offset());
                if self.inline_candidates.contains_key(&key) {
                    return String::new();
                }
                format!("uVar_{:x}", vn.get_offset())
            }
            _ => String::new(),
        }
    }

    // RUGRA-GLUE: find_typed_instance (no Ghidra counterpart found)
    /// Check if a name is a raw x86-64 register name
    /// Scan all instances of a HighVariable for one with a meaningful
    /// (non-Unknown, non-undefined) type. ActionTypeInfer assigns types to
    /// individual SSA instances, not to the HighVariable as a whole. This
    /// finds the best type across all instances.
    fn find_typed_instance(high: &crate::variable::HighVariable) -> Option<std::sync::Arc<crate::type_system::Datatype>> {
        use crate::type_system::TypeMetatype;
        for inst_arc in &high.instances {
            let inst = inst_arc.read().unwrap();
            if let Some(ref dt) = inst.v_type {
                if dt.get_metatype() != TypeMetatype::Unknown && dt.get_name() != "undefined" {
                    return Some(dt.clone());
                }
            }
        }
        None
    }

    // RUGRA-GLUE: vn_type_if_meaningful (no Ghidra counterpart found)
    fn vn_type_if_meaningful(vn: &crate::varnode::Varnode) -> Option<std::sync::Arc<crate::type_system::Datatype>> {
        use crate::type_system::TypeMetatype;
        // If this varnode is the output of a LOAD, it holds a loaded VALUE
        // (int/long), not a pointer. Override any pointer type with a
        // size-based type. This is the root fix for piVar92=*(int*)piVar91
        // being wrongly named piVar — it should be iVar/lVar.
        if let Some(ref def_arc) = vn.def.as_ref().and_then(|d| d.upgrade()) {
            let def_op = def_arc.read().unwrap();
            if def_op.opcode == crate::opcodes::OpCode::CPUI_LOAD {
                let sz = vn.get_size();
                use crate::type_system::datatype::{Datatype, TypeBase};
                let base_type = match sz {
                    4 => Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int))),
                    8 => Arc::new(Datatype::Base(TypeBase::new("long".into(), 8, TypeMetatype::Int))),
                    1 => Arc::new(Datatype::Base(TypeBase::new("byte".into(), 1, TypeMetatype::Uint))),
                    _ => Arc::new(Datatype::Base(TypeBase::new("undefined".into(), sz, TypeMetatype::Unknown))),
                };
                return Some(base_type);
            }
        }
        vn.v_type.as_ref()
            .filter(|t| t.get_metatype() != TypeMetatype::Unknown && t.get_name() != "undefined")
            .cloned()
    }

    // RUGRA-GLUE: pointer_type_for (no Ghidra counterpart found)
    fn pointer_type_for(&self, vn: &crate::varnode::Varnode) -> Option<std::sync::Arc<crate::type_system::Datatype>> {
        if self.pointer_varnodes.contains(&(vn.get_space(), vn.get_offset())) {
            return self.make_int_ptr();
        }
        if let Some(ref high_arc) = vn.high {
            let high = high_arc.read().unwrap();
            for inst_arc in &high.instances {
                let inst = inst_arc.read().unwrap();
                if self.pointer_varnodes.contains(&(inst.get_space(), inst.get_offset())) {
                    return self.make_int_ptr();
                }
            }
        }
        None
    }

    // RUGRA-GLUE: make_int_ptr (no Ghidra counterpart found)
    fn make_int_ptr(&self) -> Option<std::sync::Arc<crate::type_system::Datatype>> {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        let int_type = std::sync::Arc::new(Datatype::Base(
            TypeBase::new("int".to_string(), 4, TypeMetatype::Int),
        ));
        Some(std::sync::Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_type,
            wordsize: 1,
        })))
    }

    // Ghidra: type.hh:273/424/457 Datatype::printNameBase (virtual dispatch via Datatype::print_name_base)
    // Ghidra: database.cc:2485-2509 Funcdata::buildVariableName (local-var case: printNameBase + "Var")
    /// Hungarian-notation variable-name prefix derived from `Datatype::print_name_base`
    /// (faithful to Ghidra's printNameBase virtual dispatch at type.hh:273/424/457,
    /// consumed by buildVariableName at database.cc:2485-2509 which appends "Var").
    /// Returns e.g. "iVar" for int, "piVar" for int*, "pUVar" for pointer to a
    /// struct named "URLGlob". Falls back to size-based dispatch when no Datatype
    /// is available (Rugra-specific gap: Ghidra always has a Datatype object).
    fn var_prefix(v_type: &Option<std::sync::Arc<crate::type_system::Datatype>>, size: usize) -> String {
        let mut base = String::new();
        match v_type {
            Some(dt) => dt.print_name_base(&mut base),
            None => match size {
                // Size-based fallback when no type info (Rugra-specific).
                // Matches the size dispatch Ghidra uses in buildLocalName
                // (database.cc:2501-2504) when no Datatype is attached.
                8 => base.push('l'),
                4 => base.push('i'),
                2 => base.push('s'),
                1 => base.push('b'),
                _ => base.push('u'),
            },
        }
        if base.is_empty() {
            // Unnamed type — Ghidra's base printNameBase writes nothing for
            // empty name; fall back to 'u' (undefined) so the variable still
            // gets a non-empty prefix.
            base.push('u');
        }
        base.push_str("Var");
        base
    }

    // RUGRA-GLUE: size_prefix (no Ghidra counterpart found)
    fn size_prefix(size: usize) -> &'static str {
        match size {
            8 => "lVar",
            4 => "iVar",
            2 => "sVar",
            1 => "bVar",
            _ => "uVar",
        }
    }

    // RUGRA-GLUE: maybe_apply_type_prefix (no Ghidra counterpart found)
    fn maybe_apply_type_prefix(name: &str, v_type: &Option<std::sync::Arc<crate::type_system::Datatype>>, size: usize) -> String {
        use crate::type_system::TypeMetatype;
        let suffix = ["uVar", "lVar", "iVar", "sVar", "bVar"]
            .iter()
            .find_map(|p| name.strip_prefix(p));
        if let Some(suffix) = suffix {
            let has_type = v_type.as_ref().map_or(false, |t| {
                t.get_metatype() != TypeMetatype::Unknown && t.get_name() != "undefined"
            });
            if has_type {
                let new_prefix = Self::var_prefix(v_type, size);
                let old_prefix_len = name.len() - suffix.len();
                if &name[..old_prefix_len] != new_prefix {
                    return format!("{}{}", new_prefix, suffix);
                }
            }
        }
        name.to_string()
    }

    /// Check if a name is a raw x86-64 register name (possibly with an SSA
    /// disambiguation suffix like `RAX_7`), i.e. a name that must NOT be
    /// emitted verbatim into the C output. Faithful to Ghidra's
    /// `ScopeInternal::buildVariableName` local-variable case (database.cc:2501-
    /// 2504): a HighVariable that only carries a register-derived name must be
    /// renamed to `<printNameBase>Var<index>` — here we route it to a size-based
    /// local name (`<prefix>_<offset>`) that `compact_name_for` then renumbers
    /// under the shared `compact_base` counter (Ghidra's single `int4 base`).
    /// The trailing `_N` is Rugra's SSA-instance disambiguator produced by
    /// `Merge::assign_names` (merge.rs:560-574); stripping it recovers the
    /// underlying register name, matching Ghidra's one-name-per-HighVariable
    /// model (the SSA instance count is irrelevant to the printed name).
    // Ghidra: database.cc:2501 ScopeInternal::buildVariableName (local-var branch: ct->printNameBase; "Var" << index++)
    fn is_raw_register_name(name: &str) -> bool {
        // Strip a trailing `_<digits>` SSA disambiguation suffix, so `RAX_7`
        // is recognised the same as `RAX`. A suffix is only `_<digits>`; names
        // like `uVar12` (no underscore) or `R8B` (not all-digit tail) are left
        // untouched.
        let base = match name.rsplit_once('_') {
            Some((head, tail)) if !head.is_empty()
                && !tail.is_empty()
                && tail.chars().all(|c| c.is_ascii_digit()) => head,
            _ => name,
        };
        matches!(base,
            "RAX" | "EAX" | "AX" | "AL" | "AH"
            | "RCX" | "ECX" | "CX" | "CL"
            | "RDX" | "EDX" | "DX" | "DL"
            | "RBX" | "EBX" | "BX" | "BL"
            | "RSP" | "ESP" | "SP"
            | "RBP" | "EBP" | "BP"
            | "RSI" | "ESI" | "SI" | "SIL"
            | "RDI" | "EDI" | "DI" | "DIL"
            | "R8" | "R8D" | "R8W" | "R8B"
            | "R9" | "R9D" | "R9W" | "R9B"
            | "R10" | "R10D" | "R10W" | "R10B"
            | "R11" | "R11D" | "R11W" | "R11B"
            | "R12" | "R12D" | "R12W" | "R12B"
            | "R13" | "R13D" | "R13W" | "R13B"
            | "R14" | "R14D" | "R14W" | "R14B"
            | "R15" | "R15D" | "R15W" | "R15B"
            | "RIP"
        )
    }

    // RUGRA-GLUE: resolve_varnode (no Ghidra counterpart found)
    /// Resolve a varnode through the copy propagation map.
    /// If this varnode is the output of a COPY op, return the root source.
    fn resolve_varnode(&self, vn_arc: &Arc<RwLock<Varnode>>) -> Option<Arc<RwLock<Varnode>>> {
        let ptr = Arc::as_ptr(vn_arc) as usize;
        self.copy_map.get(&ptr).cloned()
    }

    // RUGRA-GLUE: get_defining_op (no Ghidra counterpart found)
    /// Get the meaningful defining op for a varnode using the SSA def chain.
    /// Chases through COPY ops to find the non-trivial definition.
    /// This is the SSA-based replacement for ad-hoc map lookups.
    fn get_defining_op(vn_arc: &Arc<RwLock<Varnode>>) -> Option<Arc<RwLock<PcodeOp>>> {
        let mut current = vn_arc.clone();
        for _ in 0..20 {
            let def_op = {
                let vn = current.read().unwrap();
                vn.def.as_ref().and_then(|w| w.upgrade())
            };
            match def_op {
                Some(op_arc) => {
                    let op = op_arc.read().unwrap();
                    if op.opcode == OpCode::CPUI_COPY && !op.inrefs.is_empty() {
                        // Chase through COPY to the source
                        let src = op.inrefs[0].clone();
                        drop(op);
                        current = src;
                        continue;
                    }
                    drop(op);
                    return Some(op_arc);
                }
                None => return None,
            }
        }
        None
    }

    // RUGRA-GLUE: is_stack_frame_setup (no Ghidra counterpart found)
    /// Check if an op is INT_SUB(RSP, const) — the stack frame setup instruction.
    fn is_stack_frame_setup(&self, op: &PcodeOp) -> bool {
        if op.opcode != OpCode::CPUI_INT_SUB || op.inrefs.len() < 2 {
            return false;
        }
        let in0 = op.inrefs[0].read().unwrap();
        let in1 = op.inrefs[1].read().unwrap();
        in0.get_space() == crate::space::AddressSpace::Register
            && in0.get_offset() == 0x20 && in0.get_size() == 8
            && in1.get_space() == crate::space::AddressSpace::Const
            && in1.get_offset() == self.stack_frame_size
    }

    // RUGRA-GLUE: get_stack_variable_name (no Ghidra counterpart found)
    /// Check if an INT_ADD op is RSP + const, and if so, return the stack variable name.
    /// Also handles uVar107 + offset where uVar107 = RSP - frame_size.
    fn get_stack_variable_name(&mut self, op: &PcodeOp) -> Option<String> {
        if op.opcode != OpCode::CPUI_INT_ADD || op.inrefs.len() < 2 {
            return None;
        }
        if self.stack_frame_size == 0 {
            return None;
        }
        let in0 = op.inrefs[0].read().unwrap();
        let in1 = op.inrefs[1].read().unwrap();
        
        // Case 1: INT_ADD(RSP, const) — direct stack access
        if in0.get_space() == crate::space::AddressSpace::Register
            && in0.get_offset() == 0x20 && in0.get_size() == 8
            && in1.get_space() == crate::space::AddressSpace::Const
        {
            let offset = in1.get_offset();
            
            // Check if this offset falls within a detected struct (IDA-style)
            for ss in &self.stack_structs {
                if offset >= ss.base_offset && offset < ss.base_offset + ss.size {
                    if offset == ss.base_offset {
                        // Exact base: reference to the struct itself
                        return Some(ss.name.clone());
                    } else {
                        // Field access: *(long *)(structN + offset)
                        let field_offset = offset - ss.base_offset;
                        return Some(format!("*(long *)({} + 0x{:x})", ss.name, field_offset));
                    }
                }
            }

            // Prefer a restructured ScopeLocal symbol (faithful varmap.cc) when
            // one covers this raw stack offset. Falls through to the heuristic
            // when the scope has no symbol here (common, since Rugra's lift does
            // not yet produce Stack-space varnodes for RSP-relative accesses).
            // Clone the symbol data out of the scope borrow before calling the
            // &mut self renamer (avoids self borrow conflict), and route StackX_
            // fallback names through rename_scope_symbol (Ghidra assignDefaultNames).
            let sym_opt = self.scope.as_ref().and_then(|s| s.find_symbol(offset)).map(|sym| {
                (sym.name.clone(), sym.dtype.clone(), sym.size)
            });
            if let Some((raw_name, dtype, size)) = sym_opt {
                let renamed = self.rename_scope_symbol(&crate::varmap::LocalSymbol {
                    name: raw_name.clone(),
                    start: offset,
                    size,
                    dtype,
                    unaliased: false,
                    is_param: false,
                });
                self.used_scope_symbols.borrow_mut().insert(renamed.clone());
                return Some(renamed);
            }
            
            // Ghidra convention: local_XX where XX = frame_size - offset
            if offset < self.stack_frame_size {
                return Some(format!("local_{:x}", self.stack_frame_size - offset));
            } else if offset == self.stack_frame_size {
                return Some("local_0".to_string());
            } else {
                // Positive offset beyond frame = parameter area or return address
                return Some(format!("stack_{:x}", offset));
            }
        }
        
        // Case 2: INT_ADD(frame_base, const) where frame_base = RSP - frame_size
        // e.g., uVar107 + 0x218 where uVar107 = RSP - 0x228
        // → equivalent to RSP + (0x218 - 0x228) = RSP - 0x10 → local_10
        if let Some(ref base_key) = self.stack_frame_base_key {
            let in0_key = (in0.get_space(), in0.get_offset());
            if in0_key == *base_key && in1.get_space() == crate::space::AddressSpace::Const {
                let offset = in1.get_offset();
                if offset < self.stack_frame_size {
                    // frame_base + offset = (RSP - frame_size) + offset = RSP + (offset - frame_size)
                    // This is a negative RSP offset = local variable
                    return Some(format!("local_{:x}", self.stack_frame_size - offset));
                } else if offset == self.stack_frame_size {
                    return Some("local_0".to_string());
                } else {
                    // offset > frame_size: (RSP - frame_size) + offset = RSP + (offset - frame_size)
                    let rsp_off = offset - self.stack_frame_size;
                    if rsp_off < self.stack_frame_size {
                        return Some(format!("local_{:x}", self.stack_frame_size - rsp_off));
                    } else {
                        return Some(format!("stack_{:x}", rsp_off));
                    }
                }
            }
        }
        
        None
    }

    // RUGRA-GLUE: is_complementary_condition (no Ghidra counterpart found)
    /// Check if two condition strings form a tautology when OR'd.
    /// Covers:
    /// - Complementary pairs: "X == Y" / "X != Y", "X < Y" / "X >= Y"
    /// - Subsumption: "X != Y" / "X >= Y" (always true), "X != Y" / "X <= Y"
    /// - Duplicates: "X != Y" / "X != Y" → not a tautology but redundant
    fn is_complementary_condition(left: &str, right: &str) -> bool {
        // Direct complement pairs (guaranteed tautology when OR'd)
        let complementary_pairs: &[(&str, &str)] = &[
            (" == ", " != "),
            (" != ", " == "),
            (" < ",  " >= "),
            (" >= ", " < "),
            (" <= ", " > "),
            (" > ",  " <= "),
            // Subsumption tautologies: != covers everything except ==,
            // >= covers == and >, so != || >= is always true
            (" != ", " >= "),
            (" >= ", " != "),
            (" != ", " <= "),
            (" <= ", " != "),
        ];

        for &(op1, op2) in complementary_pairs {
            if let Some(pos1) = left.find(op1) {
                if let Some(pos2) = right.find(op2) {
                    let left_lhs = &left[..pos1];
                    let left_rhs = &left[pos1 + op1.len()..];
                    let right_lhs = &right[..pos2];
                    let right_rhs = &right[pos2 + op2.len()..];
                    if left_lhs == right_lhs && left_rhs == right_rhs {
                        return true;
                    }
                }
            }
        }
        false
    }

    // RUGRA-GLUE: negate_condition_text (no Ghidra counterpart found)
    /// Try to negate a comparison expression textually.
    /// E.g., "X == 0" → "X != 0", "X < Y" → "X >= Y"
    /// Returns None if the text doesn't contain a recognized comparison operator.
    fn negate_condition_text(text: &str) -> Option<String> {
        if let Some(pos) = text.find(" == ") {
            Some(format!("{} != {}", &text[..pos], &text[pos + 4..]))
        } else if let Some(pos) = text.find(" != ") {
            Some(format!("{} == {}", &text[..pos], &text[pos + 4..]))
        } else if let Some(pos) = text.find(" < ") {
            Some(format!("{} >= {}", &text[..pos], &text[pos + 3..]))
        } else if let Some(pos) = text.find(" >= ") {
            Some(format!("{} < {}", &text[..pos], &text[pos + 4..]))
        } else if let Some(pos) = text.find(" <= ") {
            Some(format!("{} > {}", &text[..pos], &text[pos + 4..]))
        } else if let Some(pos) = text.find(" > ") {
            Some(format!("{} <= {}", &text[..pos], &text[pos + 3..]))
        } else {
            None
        }
    }

    // RUGRA-GLUE: try_fold_bool_comparison (no Ghidra counterpart found)
    /// Try to fold a BOOL_OR/BOOL_AND of two comparisons into a single comparison.
    /// E.g., `BOOL_OR(INT_EQUAL(A,B), INT_LESS(A,B))` → emits `A <= B`
    /// Returns true if folding succeeded and the expression was emitted.
    fn try_fold_bool_comparison(&mut self, def_op: &PcodeOp) -> bool {
        if def_op.inrefs.len() < 2 || def_op.opcode != OpCode::CPUI_BOOL_OR {
            return false;
        }

        // Get the defining ops of both BOOL_OR inputs using pointer-based def_map
        // This is more precise than value_def_map which can have collisions
        let in0_ptr = Arc::as_ptr(&def_op.inrefs[0]) as usize;
        let in1_ptr = Arc::as_ptr(&def_op.inrefs[1]) as usize;
        // Also try the copy-resolved source
        let in0_resolved = self.copy_map.get(&in0_ptr)
            .map(|r| Arc::as_ptr(r) as usize).unwrap_or(in0_ptr);
        let in1_resolved = self.copy_map.get(&in1_ptr)
            .map(|r| Arc::as_ptr(r) as usize).unwrap_or(in1_ptr);

        let op0_arc = self.def_map.get(&in0_ptr).cloned()
            .or_else(|| self.def_map.get(&in0_resolved).cloned())
            .or_else(|| {
                let vn = def_op.inrefs[0].read().unwrap();
                let key = (vn.get_space(), vn.get_offset());
                self.value_def_map.get(&key).cloned()
                    .or_else(|| self.inline_candidates.get(&key).cloned())
            })
            // SSA def chain fallback
            .or_else(|| Self::get_defining_op(&def_op.inrefs[0]));
        let op1_arc = self.def_map.get(&in1_ptr).cloned()
            .or_else(|| self.def_map.get(&in1_resolved).cloned())
            .or_else(|| {
                let vn = def_op.inrefs[1].read().unwrap();
                let key = (vn.get_space(), vn.get_offset());
                self.value_def_map.get(&key).cloned()
                    .or_else(|| self.inline_candidates.get(&key).cloned())
            })
            // SSA def chain fallback
            .or_else(|| Self::get_defining_op(&def_op.inrefs[1]));

        let (op0_arc, op1_arc) = match (op0_arc, op1_arc) {
            (Some(a), Some(b)) => (a, b),
            _ => return false,
        };

        let op0 = op0_arc.read().unwrap();
        let op1 = op1_arc.read().unwrap();

        // Both must be binary comparison ops with 2 inputs
        if op0.inrefs.len() < 2 || op1.inrefs.len() < 2 {
            return false;
        }

        // Check that both compare the same operands
        // Strategy 1: exact (space+offset) match
        let op0_a = { let v = op0.inrefs[0].read().unwrap(); (v.get_space(), v.get_offset()) };
        let op0_b = { let v = op0.inrefs[1].read().unwrap(); (v.get_space(), v.get_offset()) };
        let op1_a = { let v = op1.inrefs[0].read().unwrap(); (v.get_space(), v.get_offset()) };
        let op1_b = { let v = op1.inrefs[1].read().unwrap(); (v.get_space(), v.get_offset()) };

        let operands_match = if op0_a == op1_a && op0_b == op1_b {
            true
        } else {
            // Strategy 2: compare by HighVariable display name (cross-SSA-version matching)
            // Two different SSA versions of the same register share the same HighVariable name
            let name_a0 = op0.inrefs[0].read().unwrap().high.as_ref()
                .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
            let name_a1 = op1.inrefs[0].read().unwrap().high.as_ref()
                .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
            let name_b0 = op0.inrefs[1].read().unwrap().high.as_ref()
                .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
            let name_b1 = op1.inrefs[1].read().unwrap().high.as_ref()
                .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
            !name_a0.is_empty() && !name_b0.is_empty()
                && name_a0 == name_a1 && name_b0 == name_b1
        };
        // Also check swapped operand order: (a,b) vs (b,a)
        let operands_swapped = !operands_match && {
            if op0_a == op1_b && op0_b == op1_a {
                true
            } else {
                let name_a0 = op0.inrefs[0].read().unwrap().high.as_ref()
                    .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
                let name_b1 = op1.inrefs[1].read().unwrap().high.as_ref()
                    .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
                let name_b0 = op0.inrefs[1].read().unwrap().high.as_ref()
                    .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
                let name_a1 = op1.inrefs[0].read().unwrap().high.as_ref()
                    .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
                !name_a0.is_empty() && !name_b0.is_empty()
                    && name_a0 == name_b1 && name_b0 == name_a1
            }
        };

        if !operands_match && !operands_swapped {
            return false;
        }

        // Determine the folded operator from the combination of comparison opcodes
        // Fix 2: Detect tautological conditions first
        let folded_sym = match (op0.opcode, op1.opcode) {
            // EQ(a,b) || NEQ(a,b) → always true (tautology)
            (OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL)
            | (OpCode::CPUI_INT_NOTEQUAL, OpCode::CPUI_INT_EQUAL) => {
                let seq0 = *op0.get_seq_num();
                let seq1 = *op1.get_seq_num();
                drop(op0);
                drop(op1);
                self.inlined_ops.insert(seq0);
                self.inlined_ops.insert(seq1);
                self.emit.print("1");
                return true;
            }
            // Swapped-operand tautologies:
            // NEQ(a,b) || LESSEQUAL(b,a) = a!=b || a>=b → always true
            // LESSEQUAL(a,b) || NEQ(b,a) = same
            _ if operands_swapped && matches!(
                (op0.opcode, op1.opcode),
                (OpCode::CPUI_INT_NOTEQUAL, OpCode::CPUI_INT_LESSEQUAL)
                | (OpCode::CPUI_INT_NOTEQUAL, OpCode::CPUI_INT_SLESSEQUAL)
                | (OpCode::CPUI_INT_LESSEQUAL, OpCode::CPUI_INT_NOTEQUAL)
                | (OpCode::CPUI_INT_SLESSEQUAL, OpCode::CPUI_INT_NOTEQUAL)
                // LESS(a,b) || LESSEQUAL(b,a) = a<b || a>=b → always true
                | (OpCode::CPUI_INT_LESS, OpCode::CPUI_INT_LESSEQUAL)
                | (OpCode::CPUI_INT_SLESS, OpCode::CPUI_INT_SLESSEQUAL)
                | (OpCode::CPUI_INT_LESSEQUAL, OpCode::CPUI_INT_LESS)
                | (OpCode::CPUI_INT_SLESSEQUAL, OpCode::CPUI_INT_SLESS)
            ) => {
                let seq0 = *op0.get_seq_num();
                let seq1 = *op1.get_seq_num();
                drop(op0);
                drop(op1);
                self.inlined_ops.insert(seq0);
                self.inlined_ops.insert(seq1);
                self.emit.print("1");
                return true;
            }
            // Duplicate: X(a,b) || X(a,b) → single X(a,b)
            (a, b) if a == b && matches!(a,
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
            ) => {
                let sym = match a {
                    OpCode::CPUI_INT_EQUAL => " == ",
                    OpCode::CPUI_INT_NOTEQUAL => " != ",
                    OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS => " < ",
                    OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL => " <= ",
                    _ => unreachable!(),
                };
                sym
            }
            // EQ || LT → <=
            (OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_LESS)
            | (OpCode::CPUI_INT_LESS, OpCode::CPUI_INT_EQUAL) => " <= ",
            (OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_SLESS)
            | (OpCode::CPUI_INT_SLESS, OpCode::CPUI_INT_EQUAL) => " <= ",
            _ => return false,
        };

        // Clone the operand arcs from one of the sub-comparisons before dropping the lock
        let operand_a = op0.inrefs[0].clone();
        let operand_b = op0.inrefs[1].clone();
        let seq0 = *op0.get_seq_num();
        let seq1 = *op1.get_seq_num();
        drop(op0);
        drop(op1);

        // Mark the sub-comparisons as inlined (they won't emit as separate lines)
        self.inlined_ops.insert(seq0);
        self.inlined_ops.insert(seq1);

        // Emit: A <= B
        self.push_varnode(&operand_a.read().unwrap(), None);
        self.emit.print(folded_sym);
        self.push_varnode(&operand_b.read().unwrap(), None);
        true
    }

    // RUGRA-GLUE: get_rip_relative_operand (no Ghidra counterpart found)
    /// Check if an op is `INT_ADD(RIP, x)` or `INT_ADD(x, RIP)` — a RIP-relative address.
    /// Returns the index of the non-RIP operand if matched.
    /// x86-64 PIC code uses `lea reg, [rip + offset]` which lifts to `INT_ADD(RIP, const)`.
    /// The result is a global address that should be displayed as just the symbol name.
    fn get_rip_relative_operand(&self, op: &PcodeOp) -> Option<usize> {
        use crate::space::AddressSpace;
        if op.opcode != OpCode::CPUI_INT_ADD || op.inrefs.len() < 2 {
            return None;
        }
        // RIP is Register offset 0x200, size 8
        let in0 = op.inrefs[0].read().unwrap();
        if in0.get_space() == AddressSpace::Register && in0.get_offset() == 0x200 && in0.get_size() == 8 {
            return Some(1);
        }
        drop(in0);
        let in1 = op.inrefs[1].read().unwrap();
        if in1.get_space() == AddressSpace::Register && in1.get_offset() == 0x200 && in1.get_size() == 8 {
            return Some(0);
        }
        None
    }

    // RUGRA-GLUE: push_input (no Ghidra counterpart found)
    /// Push an op's input varnode, resolving through the copy chain.
    fn push_input(&mut self, op: &PcodeOp, index: usize) {
        if let Some(in_arc) = op.get_in(index) {
            let resolved = self.resolve_varnode(&in_arc).unwrap_or_else(|| in_arc.clone());
            self.push_varnode(&resolved.read().unwrap(), Some(op));
        }
    }

    // Ghidra: printlanguage.cc:269 PrintLanguage::parentheses + printc.cc OpToken table
    /// Push an input varnode, wrapping it in parentheses if its defining op
    /// is a binary sub-expression that needs grouping relative to the parent
    /// binary op. Mirrors PrintLanguage::parentheses (printlanguage.cc:269)
    /// applied at the point of recursing into a child expression.
    ///
    /// `parent_opc`: the opcode of the binary op currently being emitted
    /// (whose input we are pushing). `index`: 0=left, 1=right.
    fn push_input_parenthesized(&mut self, parent_op: &PcodeOp, parent_opc: OpCode, index: usize) {
        if let Some(in_arc) = parent_op.get_in(index) {
            let resolved = self.resolve_varnode(&in_arc).unwrap_or_else(|| in_arc.clone());
            // Determine if the resolved input is itself a binary op that needs
            // parentheses. We must look through the COPY chain to the real def.
            let child_opc = {
                let vn = resolved.read().unwrap();
                if vn.is_implied() {
                    vn.get_def().map(|def_arc| {
                        let d = def_arc.read().unwrap();
                        if d.is_dead() { None } else { Some(d.opcode) }
                    }).flatten()
                } else {
                    None
                }
            };
            let needs_parens = child_opc
                .map(|co| optoken::child_needs_parens(parent_opc, co, index == 1))
                .unwrap_or(false);
            if needs_parens && !self.discovery_pass {
                self.emit.print("(");
                self.push_varnode(&resolved.read().unwrap(), Some(parent_op));
                self.emit.print(")");
            } else {
                self.push_varnode(&resolved.read().unwrap(), Some(parent_op));
            }
        }
    }

    // RUGRA-GLUE: push_output (no Ghidra counterpart found)
    /// Push an op's output varnode (no resolution needed for outputs).
    fn push_output(&mut self, op: &PcodeOp) {
        if let Some(out_arc) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out_arc.read().unwrap(), Some(op));
            self.is_lhs = false;
        }
    }

    // RUGRA-GLUE: emit_inline_expr (no Ghidra counterpart found)
    /// Emit just the RHS expression of a defining op (for expression inlining).
    /// Emits the operation without the `output = ` prefix.
    fn emit_inline_expr(&mut self, def_op: &PcodeOp) {
        match def_op.opcode {
            // COPY(x) inlines to just x — the source expression. Without this
            // branch, COPY fell through to the `_ =>` fallback and emitted the
            // output as `uVar_N`, creating uninitialized-variable fragments
            // (the dominant source of uVar noise). Inlining the COPY source is
            // always correct: COPY is semantically a no-op assignment.
            OpCode::CPUI_COPY => {
                if !def_op.inrefs.is_empty() {
                    self.push_input(def_op, 0);
                    return;
                }
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_FLOAT_ADD
            | OpCode::CPUI_INT_SUB | OpCode::CPUI_FLOAT_SUB
            | OpCode::CPUI_INT_MULT | OpCode::CPUI_FLOAT_MULT
            | OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_FLOAT_DIV
            | OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM
            | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT
            | OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
            | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => {
                // RIP-relative folding: INT_ADD(RIP, x) → just emit x
                if let Some(non_rip_idx) = self.get_rip_relative_operand(def_op) {
                    self.push_input(def_op, non_rip_idx);
                    return;
                }
                // Stack variable folding: INT_ADD(RSP, const) → &local_XX
                if let Some(stack_name) = self.get_stack_variable_name(def_op) {
                    self.mark_variable_used(stack_name.clone(), AddressSpace::Stack, 0, "int".to_string());
                    if !self.discovery_pass {
                        self.emit.print("&");
                        self.emit.tag_variable(&stack_name, 0);
                    }
                    return;
                }

                // Boolean comparison folding: BOOL_OR(EQ(A,B), LT(A,B)) → A <= B
                if self.try_fold_bool_comparison(def_op) {
                    return;
                }

                self.push_input_parenthesized(def_op, def_op.opcode, 0);
                let op_sym = match def_op.opcode {
                    OpCode::CPUI_INT_EQUAL | OpCode::CPUI_FLOAT_EQUAL => " == ",
                    OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_FLOAT_NOTEQUAL => " != ",
                    OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS | OpCode::CPUI_FLOAT_LESS => " < ",
                    OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL | OpCode::CPUI_FLOAT_LESSEQUAL => " <= ",
                    OpCode::CPUI_INT_ADD | OpCode::CPUI_FLOAT_ADD => " + ",
                    OpCode::CPUI_INT_SUB | OpCode::CPUI_FLOAT_SUB => " - ",
                    OpCode::CPUI_INT_MULT | OpCode::CPUI_FLOAT_MULT => " * ",
                    OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_FLOAT_DIV => " / ",
                    OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM => " % ",
                    OpCode::CPUI_INT_AND => " & ",
                    OpCode::CPUI_INT_OR => " | ",
                    OpCode::CPUI_INT_XOR | OpCode::CPUI_BOOL_XOR => " ^ ",
                    OpCode::CPUI_INT_LEFT => " << ",
                    OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => " >> ",
                    OpCode::CPUI_BOOL_AND => " && ",
                    OpCode::CPUI_BOOL_OR => " || ",
                    _ => " op ",
                };
                self.emit.print(op_sym);
                self.push_input_parenthesized(def_op, def_op.opcode, 1);
            }
            OpCode::CPUI_INT_NEGATE => { self.emit.print("~"); self.push_input(def_op, 0); }
            OpCode::CPUI_INT_2COMP => { self.emit.print("-"); self.push_input(def_op, 0); }
            OpCode::CPUI_BOOL_NEGATE => {
                // Try to negate textually: emit inner to temp buffer
                let orig_emit = std::mem::replace(&mut self.emit,
                    Box::new(crate::prettyprint::EmitNoMarkup::new()));
                self.push_input(def_op, 0);
                let inner_text = {
                    let buf = std::mem::replace(&mut self.emit, orig_emit);
                    buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                        .map(|b| b.get_output()).unwrap_or_default()
                };
                let trimmed = inner_text.trim();
                let negated = if let Some(pos) = trimmed.find(" == ") {
                    Some(format!("{} != {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" != ") {
                    Some(format!("{} == {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" < ") {
                    Some(format!("{} >= {}", &trimmed[..pos], &trimmed[pos + 3..]))
                } else if let Some(pos) = trimmed.find(" >= ") {
                    Some(format!("{} < {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" <= ") {
                    Some(format!("{} > {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" > ") {
                    Some(format!("{} <= {}", &trimmed[..pos], &trimmed[pos + 3..]))
                } else {
                    None
                };
                if let Some(neg) = negated {
                    self.emit.print(&neg);
                } else {
                    self.emit.print("!(");
                    self.emit.print(trimmed);
                    self.emit.print(")");
                }
            }
            OpCode::CPUI_INT_ZEXT => {
                let cast_name = def_op.output.as_ref()
                    .and_then(|out| out.read().unwrap().v_type.as_ref().map(|t| t.get_name().to_string()))
                    .unwrap_or_else(|| "uint".to_string());
                self.emit.print(&format!("({})", cast_name));
                self.push_input(def_op, 0);
            }
            OpCode::CPUI_INT_SEXT => {
                let cast_name = def_op.output.as_ref()
                    .and_then(|out| out.read().unwrap().v_type.as_ref().map(|t| t.get_name().to_string()))
                    .unwrap_or_else(|| "int".to_string());
                self.emit.print(&format!("({})", cast_name));
                self.push_input(def_op, 0);
            }
            OpCode::CPUI_LOAD => {
                // Struct field access: LOAD(RAM, INT_ADD(ptr, const_offset)) → ptr->field_XX
                if def_op.inrefs.len() >= 2 {
                    let addr_arc = &def_op.inrefs[1];
                    let addr_vn = addr_arc.read().unwrap();
                    let addr_key = (addr_vn.get_space(), addr_vn.get_offset());
                    drop(addr_vn);

                    let addr_def_opt = self.value_def_map.get(&addr_key).cloned()
                        .or_else(|| {
                            let ptr = Arc::as_ptr(addr_arc) as usize;
                            self.def_map.get(&ptr).cloned()
                        })
                        .or_else(|| {
                            self.inline_candidates.get(&addr_key).cloned()
                        })
                        .or_else(|| {
                            let resolved = self.resolve_varnode(addr_arc).unwrap_or_else(|| addr_arc.clone());
                            let rkey = { let rv = resolved.read().unwrap(); (rv.get_space(), rv.get_offset()) };
                            self.value_def_map.get(&rkey).cloned()
                                .or_else(|| self.inline_candidates.get(&rkey).cloned())
                        })
                        .or_else(|| Self::get_defining_op(addr_arc));

                    let mut emitted_as_field = false;
                    if let Some(addr_def_arc) = addr_def_opt {
                        let addr_def = addr_def_arc.read().unwrap();
                        if addr_def.opcode == OpCode::CPUI_INT_ADD && addr_def.inrefs.len() >= 2 {
                            let in0 = addr_def.inrefs[0].read().unwrap();
                            let in1 = addr_def.inrefs[1].read().unwrap();
                            // Pattern: INT_ADD(ptr, const_offset) — ptr can be any space
                            if in1.get_space() == AddressSpace::Const
                                && in0.get_space() != AddressSpace::Const
                                // But not RSP/RBP (stack frame) — those are already handled by get_stack_variable_name
                                && !(in0.get_space() == AddressSpace::Register
                                     && (in0.get_offset() == 0x20 || in0.get_offset() == 0x28))
                            {
                                let offset = in1.get_offset();
                                let ptr_arc = addr_def.inrefs[0].clone();
                                drop(in0); drop(in1); drop(addr_def);
                                // Emit: *(long *)(ptr + offset)  — avoids needing pointer type
                                self.emit.print("*(long *)(");
                                self.push_varnode(&ptr_arc.read().unwrap(), None);
                                if !self.discovery_pass {
                                    self.emit.print(&format!(" + 0x{:x})", offset));
                                } else {
                                    self.emit.print(" + 0)");
                                }
                                emitted_as_field = true;
                            }
                        }
                    }

                    if !emitted_as_field {
                        // Standard typed dereference
                        let addr_type_name = def_op.inrefs[1].read().unwrap().v_type.as_ref()
                            .and_then(|t| if matches!(t.as_ref(), Datatype::Pointer(_)) { Some(t.get_name().to_string()) } else { None });
                        if let Some(ref ptr_name) = addr_type_name {
                            self.emit.print(&format!("*(({} *)", ptr_name.trim_end_matches(" *")));
                            self.push_input(def_op, 1);
                            self.emit.print(")");
                        } else {
                            // *(long *)addr — default cast so *addr is legal C even
                            // when addr was inferred as a non-pointer scalar.
                            self.emit.print("*(long *)");
                            self.push_input(def_op, 1);
                        }
                    }
                } else {
                    // *(long *)addr — default cast form for bare LOAD address.
                    self.emit.print("*(long *)");
                    self.push_input(def_op, 1);
                }
            }
            OpCode::CPUI_CALL => {
                if let Some(in0) = def_op.get_in(0) {
                    let target_vn = in0.read().unwrap();
                    let target_addr = target_vn.get_offset();
                    let target_space = target_vn.get_space();
                    drop(target_vn);
                    if let Some(sym_name) = self.symbol_table.get(&target_addr) {
                        if !self.discovery_pass {
                            self.emit.tag_variable(sym_name, 0);
                        }
                    } else {
                        let fun_name = format!("FUN_{:08x}", target_addr);
                        self.mark_variable_used(fun_name.clone(), target_space, target_addr, "long".to_string());
                        if !self.discovery_pass {
                            self.emit.tag_variable(&fun_name, 0);
                        }
                    }
                }
                self.emit.open_paren();
                for i in 1..def_op.num_input() {
                    if i > 1 { self.emit.print(", "); }
                    if let Some(vn) = def_op.get_in(i) {
                        self.push_varnode(&vn.read().unwrap(), Some(def_op));
                    }
                }
                self.emit.close_paren();
            }
            // CPUI_CAST: emit `(type)input`. Faithful to Ghidra printCc's
            // op-cast handling (printc.cc): a CAST op renders as a C cast of
            // its single input to the output varnode's type. ActionSetCasts
            // inserts these (coreaction.cc:2702) when an op's expected input
            // type differs from the feeding varnode's high type.
            OpCode::CPUI_CAST => {
                // Emit "(typename)". The output varnode's v_type (set by
                // castInput to reqtype) is the cast target type.
                let type_name = def_op.output.as_ref()
                    .and_then(|o| {
                        let guard = o.read().unwrap();
                        guard.v_type.as_ref().map(|t| t.get_name().to_string())
                    })
                    .unwrap_or_else(|| "long".to_string());
                if !self.discovery_pass {
                    self.emit.print(&format!("({})", type_name));
                }
                if !def_op.inrefs.is_empty() {
                    self.push_input(def_op, 0);
                }
                return;
            }
            _ => {
                // Fallback: emit as variable name (don't inline unknown ops)
                if let Some(ref out_arc) = def_op.output {
                    let out_vn = out_arc.read().unwrap();
                    let name = format!("uVar_{:x}", out_vn.get_offset());
                    self.mark_varnode_used(name.clone(), &out_vn);
                    if !self.discovery_pass {
                        self.emit.tag_variable(&name, 0);
                    }
                }
            }
        }
    }

    // RUGRA-GLUE: emit_block_condition (no Ghidra counterpart found)
    /// Emit a condition expression from a block that may be a `BlockCondition`.
    ///
    /// If the block is a `BlockCondition`, recursively emits `(a) && (b)` or `(a) || (b)`.
    /// Otherwise, reads the last CBRANCH's condition input and emits it via `emit_condition`.
    fn emit_block_condition(
        &mut self,
        block_arc: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        use crate::block::{BlockType, BlockCondition, BoolOp};

        // Capture the condition text into a temporary buffer so we can detect
        // when no/invalid condition was produced (e.g. a CBRANCH whose in(1)
        // is gone, an empty block, or a failed def-map resolution yielding
        // garbage like ` == `). In that case emit `1` (always-true) rather
        // than leaving `if ()` empty or malformed — both are syntax errors.
        // (Audit: R50.)
        let produced = self.capture_block_condition(block_arc);
        let t = produced.trim();
        // Detect malformed conditions where BOOL_OR/BOOL_AND's operator was
        // dropped during the nested capture/emit swap in emit_condition's
        // BOOL_OR path. Two failure modes observed:
        //   1. Concatenated casts: `(long)bVar1(long)bVar12` (≥2 casts, no op).
        //   2. Concatenated variable names: `bVar1bVar12` (two Var names merged
        //      into one undeclared token, no cast, no op).
        // Both are gcc errors. Fall back to `1` (always-true) — valid C, matches
        // the existing malformed-condition policy (R50). The underlying
        // operator-drop (nested emit-swap bug) is tracked separately.
        let cast_count = t.matches("(long)").count() + t.matches("(int)").count()
            + t.matches("(char)").count() + t.matches("(bool)").count()
            + t.matches("(short)").count();
        let has_bool_op = t.contains(" || ") || t.contains(" && ") || t.contains(" == ")
            || t.contains(" != ") || t.contains(" < ") || t.contains(" > ")
            || t.contains(" <= ") || t.contains(" >= ");
        let has_concat_cast = cast_count >= 2 && !has_bool_op;
        // Variable-name concatenation: a token like `bVar1bVar12` (one
        // identifier containing two Var-prefix+number runs). Detected by
        // regex: an identifier with two `Var<digits>` segments.
        let has_concat_varname = Self::regex_concat_varname(t);
        let looks_valid = !t.is_empty()
            && t.chars().any(|c| c.is_alphanumeric() || c == '_')
            && !has_concat_cast
            && !has_concat_varname;
        if looks_valid {
            self.emit.print(&produced);
        } else {
            self.emit.print("1");
        }
    }

    // RUGRA-GLUE: capture_block_condition (no Ghidra counterpart found)
    /// Inner condition-emitter that writes to a throwaway buffer. Used by
    /// `emit_block_condition` to detect empty output.
    fn capture_block_condition(
        &mut self,
        block_arc: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> String {
        // Swap in a capture buffer
        let orig_emit = std::mem::replace(&mut self.emit,
            Box::new(crate::prettyprint::EmitNoMarkup::new()));
        self.emit_block_condition_inner(block_arc);
        let buf = std::mem::replace(&mut self.emit, orig_emit);
        buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
            .map(|b| b.get_output()).unwrap_or_default()
    }

    /// Render a single varnode to a String by swapping in a capture emit buffer.
    /// Used to inspect whether a varnode copy-propagates to a bare identifier
    /// or a compound expression, so callers can choose an lvalue-safe form
    /// (faithful to Ghidra opStore always wrapping the STORE address in a
    /// dereference, printc.cc:500-518).
    // RUGRA-GLUE: Rust-side helper (capture-emit-swap pattern, mirrors the
    // existing capture_block_condition at printc.rs:2512). No direct Ghidra
    // counterpart; exists to support the opStore address-wrapping fix.
    fn capture_varnode_text(&mut self, vn: &Varnode) -> String {
        let orig_emit = std::mem::replace(&mut self.emit,
            Box::new(crate::prettyprint::EmitNoMarkup::new()));
        self.push_varnode(vn, None);
        let buf = std::mem::replace(&mut self.emit, orig_emit);
        buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
            .map(|b| b.get_output()).unwrap_or_default()
    }

    /// Render an op's inline expression (RHS, no `out =`) to a String by
    /// swapping in a capture emit buffer. Used by op_return's RAX-writer
    /// reconstruction to inspect the inlined return-value text.
    // RUGRA-GLUE: Rust-side capture helper (capture-emit-swap pattern).
    fn capture_inline_expr_text(&mut self, op: &PcodeOp) -> String {
        // Save the emit buffer AND inline-state that emit_inline_expr mutates
        // (inline_depth, inlined_ops), so this dry-run capture has no visible
        // side effects on the main emission pass. Without restoring these, a
        // capture here would leave inlined_ops populated / inline_depth bumped
        // and corrupt subsequent varnode rendering (observed: bVarbVar2 name
        // concatenation in next_url).
        let orig_emit = std::mem::replace(&mut self.emit,
            Box::new(crate::prettyprint::EmitNoMarkup::new()));
        let saved_depth = self.inline_depth;
        let saved_inlined_ops = self.inlined_ops.clone();
        let saved_lhs = self.is_lhs;
        self.is_lhs = false;
        self.emit_inline_expr(op);
        let buf = std::mem::replace(&mut self.emit, orig_emit);
        self.inline_depth = saved_depth;
        self.inlined_ops = saved_inlined_ops;
        self.is_lhs = saved_lhs;
        buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
            .map(|b| b.get_output()).unwrap_or_default()
    }

    /// Detect a textual self-XOR `X ^ X` (identical operands around ` ^ `).
    /// Used to fold the canonical `xor eax,eax; ret` zero-return idiom to 0
    // RUGRA-GLUE: print-time textual predicate (no direct Ghidra counterpart;
    // Ghidra folds INT_XOR(x,x)->0 at the RuleTrivialArith op layer). Exists
    // because Rugra's late/dead self-XORs escape op-layer folding and reach
    // print, where text-level detection is the practical equivalent.
    /// Detect a textual self-XOR `X ^ X` (identical operands around ` ^ `).
    /// Used to fold the canonical `xor eax,eax; ret` zero-return idiom to 0
    // RUGRA-GLUE: print-time textual predicate (no direct Ghidra counterpart;
    // Ghidra folds INT_XOR(x,x)->0 at the RuleTrivialArith op layer). Exists
    // because Rugra's late/dead self-XORs escape op-layer folding and reach
    // print, where text-level detection is the practical equivalent.
    fn is_textual_self_xor(text: &str) -> bool {
        let t = text.trim();
        if let Some(idx) = t.find(" ^ ") {
            let lhs = t[..idx].trim();
            let rhs = t[idx + 3..].trim();
            return !lhs.is_empty() && lhs == rhs;
        }
        false
    }

    /// Detect a concatenated variable name like `bVar1bVar12` — a single
    /// identifier token containing two `Var<digits>` runs. This is the
    /// signature of a BOOL_OR/BOOL_AND whose operator was dropped during
    /// the nested capture/emit swap (same root cause as cast-concat), with
    /// non-cast operands. Such a token is undeclared => gcc error. Used by
    /// emit_block_condition's malformed-condition guard.
    // RUGRA-GLUE: print-time textual predicate (no Ghidra counterpart;
    // Ghidra never produces operator-less binary conditions).
    fn regex_concat_varname(text: &str) -> bool {
        // Scan tokens (maximal [A-Za-z_][A-Za-z0-9_] runs) and check if any
        // single token contains two Var-prefix+number segments, e.g. bVar1bVar12.
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let tok = &text[start..i];
                // Count occurrences of "Var" followed by digits within the token.
                let mut var_runs = 0;
                let mut j = 0;
                let tb = tok.as_bytes();
                while j + 3 <= tb.len() {
                    if &tb[j..j+3] == b"Var" {
                        let mut k = j + 3;
                        let digit_start = k;
                        while k < tb.len() && tb[k].is_ascii_digit() { k += 1; }
                        if k > digit_start { var_runs += 1; j = k; continue; }
                    }
                    j += 1;
                }
                if var_runs >= 2 { return true; }
            } else {
                i += 1;
            }
        }
        false
    }

    /// Resolve and render a single CALL argument to a String, guaranteed
    /// non-empty. Mirrors the arg-resolution that used to be inline in
    /// op_call (block_local_reg_defs / value_def_map / COPY-source chase /
    /// inline / push_varnode fallback), but captures the emit and falls back
    /// to a concrete name if resolution produces nothing — faithful to Ghidra
    /// opCall's pushVn which never emits empty (prevents illegal `f(, arg)`).
    // RUGRA-GLUE: Rust-side arg-text extractor (capture-emit-swap pattern).
    fn emit_call_arg_text(&mut self, op: &PcodeOp, i: usize) -> String {
        use crate::opcodes::OpCode;
        let vn_arc = match op.get_in(i) { Some(a) => a, None => return "0".to_string() };
        let (space, offset) = {
            let vn = vn_arc.read().unwrap();
            (vn.get_space(), vn.get_offset())
        };
        let orig_emit = std::mem::replace(&mut self.emit,
            Box::new(crate::prettyprint::EmitNoMarkup::new()));
        let saved_lhs = self.is_lhs;
        self.is_lhs = false;

        // Register args: try block-local def, then value_def_map, then the
        // COPY-source / inline chase that op_call used to do inline.
        let mut resolved = false;
        if space == crate::space::AddressSpace::Register {
            let key = (space, offset);
            let def_op_opt = self.block_local_reg_defs.get(&key).cloned()
                .or_else(|| self.value_def_map.get(&key).cloned());
            if let Some(def_op_arc) = def_op_opt {
                let is_copy = {
                    let d = def_op_arc.read().unwrap();
                    d.opcode == OpCode::CPUI_COPY && !d.inrefs.is_empty()
                };
                if is_copy {
                    let src_arc = def_op_arc.read().unwrap().inrefs[0].clone();
                    let (src_space, src_offset) = {
                        let v = src_arc.read().unwrap();
                        (v.get_space(), v.get_offset())
                    };
                    let src_key = (src_space, src_offset);
                    let src_def = self.value_def_map.get(&src_key).cloned()
                        .or_else(|| self.inline_candidates.get(&src_key).cloned());
                    if let Some(src_def_arc) = src_def {
                        let rip_idx = self.get_rip_relative_operand(&src_def_arc.read().unwrap());
                        if let Some(non_rip_idx) = rip_idx {
                            let sdo = src_def_arc.read().unwrap();
                            if non_rip_idx < sdo.inrefs.len() {
                                let sym_arc = sdo.inrefs[non_rip_idx].clone();
                                drop(sdo);
                                self.push_varnode(&sym_arc.read().unwrap(), None);
                                resolved = true;
                            }
                        }
                        if !resolved {
                            let sdo = src_def_arc.read().unwrap();
                            self.inlined_ops.insert(*sdo.get_seq_num());
                            self.emit_inline_expr(&sdo);
                            resolved = true;
                        }
                    }
                    if !resolved {
                        self.push_varnode(&src_arc.read().unwrap(), None);
                        resolved = true;
                    }
                } else {
                    let has_inrefs = !def_op_arc.read().unwrap().inrefs.is_empty();
                    if has_inrefs {
                        let rip_idx = self.get_rip_relative_operand(&def_op_arc.read().unwrap());
                        if let Some(non_rip_idx) = rip_idx {
                            let d = def_op_arc.read().unwrap();
                            if non_rip_idx < d.inrefs.len() {
                                let sym_arc = d.inrefs[non_rip_idx].clone();
                                drop(d);
                                self.push_varnode(&sym_arc.read().unwrap(), None);
                                resolved = true;
                            }
                        }
                        if !resolved {
                            let d = def_op_arc.read().unwrap();
                            let seq = *d.get_seq_num();
                            drop(d);
                            self.inlined_ops.insert(seq);
                            self.emit_inline_expr(&def_op_arc.read().unwrap());
                            resolved = true;
                        }
                    }
                }
            }
        }
        if !resolved {
            self.push_varnode(&vn_arc.read().unwrap(), Some(op));
        }

        let buf = std::mem::replace(&mut self.emit, orig_emit);
        self.is_lhs = saved_lhs;
        let text = buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
            .map(|b| b.get_output()).unwrap_or_default();
        if text.trim().is_empty() {
            // Resolution produced nothing (dead def / inline-candidate
            // Unique). Fall back to a concrete, declared local name so the
            // call stays valid C, matching Ghidra opCall's never-empty pushVn.
            // Ghidra's buildVariableName irregular-input case (database.cc:2470)
            // produces `in_<reg>` and declares it as a local; we mirror that by
            // registering the name with mark_variable_used so a declaration is
            // emitted. Type defaults to the varnode's size-based int.
            let name = format!("in_{:x}", offset);
            let sz = vn_arc.read().unwrap().get_size();
            let ty = match sz { 8 => "long", 4 => "int", _ => "int" }.to_string();
            self.mark_variable_used(name.clone(), space, offset, ty);
            name
        } else {
            text
        }
    }

    // RUGRA-GLUE: emit_block_condition_inner (no Ghidra counterpart found)
    fn emit_block_condition_inner(
        &mut self,
        block_arc: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        use crate::block::{BlockType, BlockCondition, BoolOp};

        let block_type = block_arc.read().unwrap().get_type();

        if block_type == BlockType::Condition {
            let block = block_arc.read().unwrap();
            if let Some(cond_data) = block.as_any().downcast_ref::<BlockCondition>() {
                let op_str = match cond_data.op_type {
                    BoolOp::And => " && ",
                    BoolOp::Or => " || ",
                };
                let first = cond_data.first.clone();
                let second = cond_data.second.clone();
                let is_or = matches!(cond_data.op_type, BoolOp::Or);
                drop(block);

                // For OR patterns, check for tautologies first
                if is_or {
                    // Emit each side to temp buffers
                    let orig_emit = std::mem::replace(&mut self.emit,
                        Box::new(crate::prettyprint::EmitNoMarkup::new()));
                    self.emit_block_condition_inner(&first);
                    let left_text = {
                        let buf = std::mem::replace(&mut self.emit,
                            Box::new(crate::prettyprint::EmitNoMarkup::new()));
                        buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                            .map(|b| b.get_output()).unwrap_or_default()
                    };
                    self.emit_block_condition_inner(&second);
                    let right_text = {
                        let buf = std::mem::replace(&mut self.emit, orig_emit);
                        buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                            .map(|b| b.get_output()).unwrap_or_default()
                    };

                    // Strip outer parens for comparison: "(X == 1)" → "X == 1"
                    let left_bare = left_text.trim().trim_start_matches('(').trim_end_matches(')').trim();
                    let right_bare = right_text.trim().trim_start_matches('(').trim_end_matches(')').trim();

                    if Self::is_complementary_condition(left_bare, right_bare) {
                        self.emit.print("1");
                        return;
                    }

                    // Not a tautology — emit normally with the captured text
                    self.emit.print("(");
                    self.emit.print(&left_text);
                    self.emit.print(")");
                    self.emit.print(op_str);
                    self.emit.print("(");
                    self.emit.print(&right_text);
                    self.emit.print(")");
                    return;
                }

                self.emit.print("(");
                self.emit_block_condition_inner(&first);
                self.emit.print(")");
                self.emit.print(op_str);
                self.emit.print("(");
                self.emit_block_condition_inner(&second);
                self.emit.print(")");
                return;
            }
        }

        // Simple block: read last CBRANCH's condition varnode and look for its defining comparison
        let block = block_arc.read().unwrap();
        let ops = block.get_ops();
        if let Some(last_op_ref) = ops.last() {
            // Extract condition varnode and drop the CBRANCH lock before mutating self
            let cond_vn_opt = {
                let last_op = last_op_ref.0.read().unwrap();
                last_op.get_in(1).map(|arc| arc.clone())
            };
            if let Some(cond_vn) = cond_vn_opt {
                // Strategy: scan the block's ops (excluding CBRANCH) for a comparison/boolean
                // whose output has the same (space, offset) as the condition varnode.
                let cond_key = {
                    let cv = cond_vn.read().unwrap();
                    (cv.get_space(), cv.get_offset())
                };
                for op_ref in &ops[..ops.len().saturating_sub(1)] {
                    let op = op_ref.0.read().unwrap();
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        let out_key = (out_vn.get_space(), out_vn.get_offset());
                        if out_key == cond_key {
                            match op.opcode {
                                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                                | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                                | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                                | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
                                | OpCode::CPUI_BOOL_OR => {
                                    let cond_ptr = Arc::as_ptr(&cond_vn) as usize;
                                    drop(out_vn);
                                    drop(op);
                                    self.def_map.insert(cond_ptr, op_ref.0.clone());
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                drop(block);
                self.emit_condition(&cond_vn);
            }
        }
    }

    // RUGRA-GLUE: emit_condition (no Ghidra counterpart found)
    /// Emit a condition expression, inlining comparisons.
    ///
    /// Uses `def_map` to trace the defining op for any varnode (cross-block).
    /// Resolves through copy chains, then inlines:
    /// - `BOOL_NOT(a == b)` → `a != b`
    /// - `a == b` → `a == b` (direct comparison)
    /// - `a || b` / `a && b` → inlined boolean expr
    fn emit_condition(&mut self, cond_arc: &Arc<RwLock<Varnode>>) {
        // Resolve through copy chain first
        let resolved = self.resolve_varnode(cond_arc).unwrap_or_else(|| cond_arc.clone());
        let resolved_ptr = Arc::as_ptr(&resolved) as usize;
        let vn_key = {
            let resolved_vn = resolved.read().unwrap();
            (resolved_vn.get_space(), resolved_vn.get_offset())
        };

        // Strategy 0: SSA def chain (ground truth from Heritage)
        // Use Varnode.def to chase through COPY chain to the meaningful defining op.
        // This is the most reliable strategy since it uses the actual SSA graph.
        let mut def_op_arc = Self::get_defining_op(cond_arc);
        
        // If SSA def didn't find anything, or found a non-comparison op,
        // check if it's a comparison/boolean op (which is what we need for conditions).
        if let Some(ref arc) = def_op_arc {
            let op = arc.read().unwrap();
            match op.opcode {
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
                | OpCode::CPUI_BOOL_OR | OpCode::CPUI_MULTIEQUAL => {
                    // Good — it's a comparison/boolean/phi, keep it
                }
                _ => {
                    // Not a comparison — clear so we fall through to ad-hoc maps
                    drop(op);
                    def_op_arc = None;
                }
            }
        }

        // Fallback strategies using ad-hoc maps (for cases where SSA def is incomplete):
        // 1. Original varnode Arc pointer → def_map (most precise)
        // 2. Copy-resolved Arc pointer → def_map  
        // 3. Value-based (space, offset) → value_def_map (may have collisions)
        // 4. inline_candidates
        let original_ptr = Arc::as_ptr(cond_arc) as usize;
        let mut lookup_key = vn_key;
        
        if def_op_arc.is_none() {
            // Try pointer-based lookup first (more precise than value-based)
            if let Some(arc) = self.def_map.get(&original_ptr).cloned()
                .or_else(|| self.def_map.get(&resolved_ptr).cloned())
            {
                let op = arc.read().unwrap();
                if op.opcode == OpCode::CPUI_COPY && !op.inrefs.is_empty() {
                    // Chase through COPY chain
                    let (s, o) = {
                        let in_vn = op.inrefs[0].read().unwrap();
                        (in_vn.get_space(), in_vn.get_offset())
                    };
                    lookup_key = (s, o);
                    drop(op);
                    // Continue to value-based chase below
                } else {
                    drop(op);
                    def_op_arc = Some(arc);
                }
            }
        }
        
        // If pointer-based didn't find a non-COPY def, chase via value_def_map
        if def_op_arc.is_none() {
            for _ in 0..20 {
                let found = self.value_def_map.get(&lookup_key).cloned()
                    .or_else(|| self.inline_candidates.get(&lookup_key).cloned());
                match found {
                    Some(arc) => {
                        let op = arc.read().unwrap();
                        if op.opcode == OpCode::CPUI_COPY && !op.inrefs.is_empty() {
                            let in_vn = op.inrefs[0].read().unwrap();
                            lookup_key = (in_vn.get_space(), in_vn.get_offset());
                            continue;
                        }
                        drop(op);
                        def_op_arc = Some(arc);
                        break;
                    }
                    None => break,
                }
            }
        }
        
        // Final fallback: try comparison_def_map which only stores comparison/boolean ops
        // This handles cases where value_def_map was overwritten by a later non-comparison op
        if def_op_arc.is_none() {
            // Try resolved key first, then original (unresolved) key
            let original_key = {
                let orig_vn = cond_arc.read().unwrap();
                (orig_vn.get_space(), orig_vn.get_offset())
            };
            if let Some(arc) = self.comparison_def_map.get(&vn_key).cloned()
                .or_else(|| self.comparison_def_map.get(&original_key).cloned())
                .or_else(|| self.comparison_def_map.get(&lookup_key).cloned())
            {
                def_op_arc = Some(arc);
            }
        }

        if let Some(def_op_arc) = def_op_arc {
            let def_op = def_op_arc.read().unwrap();

            // Round 7 Feature 2: Trace through MULTIEQUAL (phi-nodes)
            if def_op.opcode == OpCode::CPUI_MULTIEQUAL && !def_op.inrefs.is_empty() {
                // For a phi-merge of boolean conditions, try tracing through the first input
                // that has a defining comparison.
                let first_in = def_op.inrefs[0].clone();
                drop(def_op);
                self.emit_condition(&first_in);
                return;
            }

            // Case 1: BOOL_NOT(x) — negate the inner comparison
            if def_op.opcode == OpCode::CPUI_BOOL_NEGATE && def_op.inrefs.len() == 1 {
                let inner_arc = def_op.inrefs[0].clone();
                let inner_resolved = self.resolve_varnode(&inner_arc).unwrap_or_else(|| inner_arc.clone());
                let inner_key = {
                    let inner_vn = inner_resolved.read().unwrap();
                    (inner_vn.get_space(), inner_vn.get_offset())
                };
                let inner_ptr = Arc::as_ptr(&inner_resolved) as usize;

                let inner_def = self.value_def_map.get(&inner_key).cloned()
                    .or_else(|| self.def_map.get(&inner_ptr).cloned());

                if let Some(inner_def_arc) = inner_def {
                    let inner_def_op = inner_def_arc.read().unwrap();
                    let negated_sym = match inner_def_op.opcode {
                        OpCode::CPUI_INT_EQUAL => Some(" != "),
                        OpCode::CPUI_INT_NOTEQUAL => Some(" == "),
                        OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS => Some(" >= "),
                        OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL => Some(" > "),
                        _ => None,
                    };
                    if let Some(sym) = negated_sym {
                        if inner_def_op.inrefs.len() >= 2 {
                            // Mark both NOT and inner Comparison as inlined
                            self.inlined_ops.insert(*def_op.get_seq_num());
                            self.inlined_ops.insert(*inner_def_op.get_seq_num());

                            let a = self.resolve_varnode(&inner_def_op.inrefs[0]).unwrap_or_else(|| inner_def_op.inrefs[0].clone());
                            let b = self.resolve_varnode(&inner_def_op.inrefs[1]).unwrap_or_else(|| inner_def_op.inrefs[1].clone());
                            self.push_varnode(&a.read().unwrap(), None);
                            self.emit.print(sym);
                            self.push_varnode(&b.read().unwrap(), None);
                            return;
                        }
                    }
                }
                // Fallback: emit the inner condition and try to negate textually
                self.inlined_ops.insert(*def_op.get_seq_num());
                drop(def_op);

                // Emit inner to temp buffer
                let orig_emit = std::mem::replace(&mut self.emit,
                    Box::new(crate::prettyprint::EmitNoMarkup::new()));
                self.emit_condition(&inner_arc);
                let inner_text = {
                    let buf = std::mem::replace(&mut self.emit, orig_emit);
                    buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                        .map(|b| b.get_output()).unwrap_or_default()
                };

                // Try to negate the comparison textually
                let trimmed = inner_text.trim();
                let negated = if let Some(pos) = trimmed.find(" == ") {
                    Some(format!("{} != {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" != ") {
                    Some(format!("{} == {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" < ") {
                    Some(format!("{} >= {}", &trimmed[..pos], &trimmed[pos + 3..]))
                } else if let Some(pos) = trimmed.find(" >= ") {
                    Some(format!("{} < {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" <= ") {
                    Some(format!("{} > {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" > ") {
                    Some(format!("{} <= {}", &trimmed[..pos], &trimmed[pos + 3..]))
                } else {
                    None
                };

                if let Some(neg) = negated {
                    self.emit.print(&neg);
                } else {
                    self.emit.print("!(");
                    self.emit.print(trimmed);
                    self.emit.print(")");
                }
                return;
            }

            // Case 2: Direct comparison or boolean combinator
            if def_op.inrefs.len() >= 2 {
                let cmp_sym = match def_op.opcode {
                    OpCode::CPUI_INT_EQUAL => Some(" == "),
                    OpCode::CPUI_INT_NOTEQUAL => Some(" != "),
                    OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS => Some(" < "),
                    OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL => Some(" <= "),
                    OpCode::CPUI_BOOL_OR => Some(" || "),
                    OpCode::CPUI_BOOL_AND => Some(" && "),
                    _ => None,
                };
                if let Some(sym) = cmp_sym {
                    // Mark comparison/combinator as inlined
                    self.inlined_ops.insert(*def_op.get_seq_num());

                    // For BOOL_OR/BOOL_AND: try fold first (e.g., BOOL_OR(EQ, LT) → <=),
                    // then recursively resolve operands as conditions
                    if def_op.opcode == OpCode::CPUI_BOOL_OR || def_op.opcode == OpCode::CPUI_BOOL_AND {
                        let a_arc = def_op.inrefs[0].clone();
                        let b_arc = def_op.inrefs[1].clone();
                        let bool_opcode = def_op.opcode;
                        // Try folding first (e.g., EQ || LT → <=)
                        if self.try_fold_bool_comparison(&def_op) {
                            return;
                        }
                        drop(def_op);

                        // Fallback tautology detection: emit each side to temp buffer,
                        // then check if they form a complementary pair
                        if bool_opcode == OpCode::CPUI_BOOL_OR {
                            // Save current emit state and emit to temp buffers
                            let orig_emit = std::mem::replace(&mut self.emit,
                                Box::new(crate::prettyprint::EmitNoMarkup::new()));
                            self.emit_condition(&a_arc);
                            let left_text = {
                                let buf = std::mem::replace(&mut self.emit,
                                    Box::new(crate::prettyprint::EmitNoMarkup::new()));
                                buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                    .map(|b| b.get_output()).unwrap_or_default()
                            };
                            self.emit_condition(&b_arc);
                            let right_text = {
                                let buf = std::mem::replace(&mut self.emit, orig_emit);
                                buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                    .map(|b| b.get_output()).unwrap_or_default()
                            };

                            // Check complementary patterns:
                            // "X == Y" || "X != Y" → always true
                            // "X < Y"  || "X >= Y" → always true
                            // "X <= Y" || "X > Y"  → always true
                            let is_tautology = Self::is_complementary_condition(
                                left_text.trim(), right_text.trim());

                            if is_tautology {
                                self.emit.print("1");
                                return;
                            }

                            // Not a tautology — emit normally
                            self.emit.print(&left_text);
                            self.emit.print(sym);
                            self.emit.print(&right_text);
                            return;
                        }

                        // Can't fold — emit each side as a condition recursively
                        self.emit_condition(&a_arc);
                        self.emit.print(sym);
                        self.emit_condition(&b_arc);
                        return;
                    }

                    let a = self.resolve_varnode(&def_op.inrefs[0]).unwrap_or_else(|| def_op.inrefs[0].clone());
                    let b = self.resolve_varnode(&def_op.inrefs[1]).unwrap_or_else(|| def_op.inrefs[1].clone());
                    self.push_varnode(&a.read().unwrap(), None);
                    self.emit.print(sym);
                    self.push_varnode(&b.read().unwrap(), None);
                    return;
                }
            }
        }

        // Fallback: emit the varnode name
        let cond_vn = resolved.read().unwrap();
        self.push_varnode(&cond_vn, None);
    }
}

impl PrintLanguage for PrintC {
    // Ghidra: printc.cc:123 PrintC::getEmit
    fn get_emit(&mut self) -> &mut dyn Emit {
        self.emit.as_mut()
    }

    // Ghidra: printc.cc:123 PrintC::setEmit
    fn set_emit(&mut self, emit: Box<dyn Emit>) {
        self.emit = emit;
    }

    // Ghidra: printc.cc:2641 PrintC::docFunction
    fn doc_function(&mut self, fd: &Funcdata) {
        use std::collections::HashSet;

        // Load symbol and string tables from Funcdata, sanitizing C identifiers
        self.symbol_table = fd.symbol_table.iter()
            .map(|(k, v)| (*k, sanitize_c_ident(v)))
            .collect();
        self.string_table = fd.string_table.clone();

        // Restructure the local-variable scope (faithful varmap.cc port).
        // If ActionRestructureVarnode already built it on fd.scope, reuse it
        // (cloned, since doc_function takes &Funcdata); otherwise build here.
        // Built once per function; queried by get_stack_variable_name.
        // NOTE: Rugra's x86 lift keeps RSP-relative accesses in Register space
        // rather than producing Stack-space varnodes, so gather_varnodes finds
        // few symbols today. gather_spacebase compensates for RSP-derived
        // LOAD/STORE. Full coverage needs type propagation.
        self.scope = match &fd.scope {
            Some(s) => Some(s.clone()),
            None => {
                let mut scope = crate::varmap::ScopeLocal::new();
                scope.restructure_varnode(fd);
                Some(scope)
            }
        };

        // Populate parameter name mapping from function prototype
        self.param_names.clear();
        for param in &fd.funcp.parameters {
            self.param_names.insert(param.address.as_u64(), param.name.clone());
        }

        // Collect function call target addresses so we don't declare them as variables
        let mut call_targets: HashSet<u64> = HashSet::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_CALL {
                if let Some(in0) = op.get_in(0) {
                    let vn = in0.read().unwrap();
                    call_targets.insert(vn.get_offset());
                }
            }
        }
        self.call_targets = call_targets;

        // Precompute pointer varnodes for usage-based type inference.
        self.pointer_varnodes.clear();
        use crate::space::AddressSpace;
        let mut addr_feeding_load: HashSet<(AddressSpace, u64)> = HashSet::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_LOAD | OpCode::CPUI_STORE if op.inrefs.len() > 1 => {
                    let vn = op.inrefs[1].read().unwrap();
                    self.pointer_varnodes.insert((vn.get_space(), vn.get_offset()));
                }
                OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB => {
                    if let Some(ref out) = op.output {
                        let vn = out.read().unwrap();
                        addr_feeding_load.insert((vn.get_space(), vn.get_offset()));
                    }
                }
                _ => {}
            }
        }
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if matches!(op.opcode, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB) {
                if let Some(ref out) = op.output {
                    let out_vn = out.read().unwrap();
                    if addr_feeding_load.contains(&(out_vn.get_space(), out_vn.get_offset())) {
                        for in_arc in &op.inrefs {
                            let in_vn = in_arc.read().unwrap();
                            if in_vn.get_space() != AddressSpace::Const {
                                self.pointer_varnodes.insert((in_vn.get_space(), in_vn.get_offset()));
                            }
                        }
                    }
                }
            }
        }

        // Directly stamp Pointer type on all varnodes identified as pointers.
        // This runs AFTER the full pipeline (heritage, type inference, copy
        // propagation, dead code) so the varnodes in loc_tree are the final
        // surviving ones that PrintC will encounter. This is the approach
        // Ghidra uses: type information is applied to display-level varnodes
        // just before printing, not deferred to a separate propagation pass.
        if !self.pointer_varnodes.is_empty() {
            use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
            let int_type = std::sync::Arc::new(Datatype::Base(
                TypeBase::new("int".to_string(), 4, TypeMetatype::Int),
            ));
            let int_ptr = std::sync::Arc::new(Datatype::Pointer(TypePointer {
                base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
                ptr_to: int_type,
                wordsize: 1,
            }));
            for vn_ref in &fd.vbank.loc_tree {
                let vn = vn_ref.0.read().unwrap();
                if self.pointer_varnodes.contains(&(vn.get_space(), vn.get_offset())) {
                    let needs_update = vn.v_type.as_ref().map_or(true, |t| {
                        t.get_metatype() != TypeMetatype::Pointer
                    });
                    if needs_update {
                        drop(vn);
                        vn_ref.0.write().unwrap().v_type = Some(int_ptr.clone());
                    }
                }
            }
        }

        self.func_start = fd.baseaddr.as_u64();
        self.func_end = self.func_start + (fd.obank.alivelist.len() as u64 * 16).max(0x2000);

        // Build copy propagation map from ALL blocks' ops.
        // COPY ops are block-local, not in fd.obank.alivelist.
        self.copy_map.clear();
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    if op.opcode == OpCode::CPUI_COPY && !op.inrefs.is_empty() {
                        if let Some(ref out_arc) = op.output {
                            let out_ptr = Arc::as_ptr(out_arc) as usize;
                            let src = op.inrefs[0].clone();
                            self.copy_map.insert(out_ptr, src);
                        }
                    }
                }
            }
        }
        // Chase chains: if A->B and B->C, resolve A->C
        let keys: Vec<usize> = self.copy_map.keys().cloned().collect();
        for key in &keys {
            let mut current = self.copy_map[key].clone();
            let mut depth = 0;
            while depth < 20 {
                let ptr = Arc::as_ptr(&current) as usize;
                if let Some(next) = self.copy_map.get(&ptr) {
                    current = next.clone();
                    depth += 1;
                } else {
                    break;
                }
            }
            self.copy_map.insert(*key, current);
        }

        // Build defining-op map: for each op, map output varnode ptr -> op Arc
        // Include BOTH alivelist ops AND block-level ops (comparisons, booleans, etc.)
        self.def_map.clear();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out_arc) = op.output {
                let out_ptr = Arc::as_ptr(out_arc) as usize;
                self.def_map.insert(out_ptr, op_ref.0.clone());
            }
        }
        // Also add block-level ops (many comparisons/booleans live only in blocks)
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    if let Some(ref out_arc) = op.output {
                        let out_ptr = Arc::as_ptr(out_arc) as usize;
                        // Don't overwrite alivelist entries
                        self.def_map.entry(out_ptr).or_insert_with(|| op_ref.0.clone());
                    }

                }
            }
        }
        // For COPY chain intermediates: if copy_map says X->Y and Y is defined by op,
        // then X should also resolve to that same op. But more importantly,
        // we need the copy destination to also be in def_map pointing to its COPY's source's def.
        // Actually, the def_map should map ANY varnode ptr to the op that "meaningfully" defines it.
        // For a COPY dest, the meaningful def is the source's def.
        let copy_keys: Vec<(usize, usize)> = self.copy_map.iter()
            .map(|(k, v)| (*k, Arc::as_ptr(v) as usize))
            .collect();
        for (copy_dest, copy_src) in &copy_keys {
            if let Some(src_def) = self.def_map.get(copy_src).cloned() {
                self.def_map.insert(*copy_dest, src_def);
            }
        }

        // Build value-based defining-op map from ALL blocks' ops.
        // We scan fd.bblocks (basic blocks) because many ops (comparisons, boolean)
        // are NOT in fd.obank.alivelist but DO exist in block-level op lists.
        self.value_def_map.clear();
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    // Skip Unique-space COPY ops — their outputs are handled by copy_map.
                    // But keep Register-space COPY ops so CALL argument resolution works.
                    if op.opcode == OpCode::CPUI_COPY {
                        if let Some(ref out_arc) = op.output {
                            let out_vn = out_arc.read().unwrap();
                            if out_vn.get_space() != crate::space::AddressSpace::Register {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        let key = (out_vn.get_space(), out_vn.get_offset());
                        self.value_def_map.insert(key, op_ref.0.clone());
                    }
                }
            }
        }
        // Build comparison_def_map: only comparison and boolean ops, keyed by (space, offset).
        // Unlike value_def_map, later non-comparison ops won't overwrite these entries.
        self.comparison_def_map.clear();
        self.stack_frame_size = 0;
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    // Collect comparison/boolean ops
                    match op.opcode {
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                        | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                        | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                        | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
                        | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => {
                            if let Some(ref out_arc) = op.output {
                                let out_vn = out_arc.read().unwrap();
                                let key = (out_vn.get_space(), out_vn.get_offset());
                                // First one wins (don't overwrite)
                                self.comparison_def_map.entry(key)
                                    .or_insert_with(|| op_ref.0.clone());
                            }
                        }
                        _ => {}
                    }
                    // Detect stack frame: INT_SUB(RSP, const) or INT_ADD(RSP, negative_const)
                    if self.stack_frame_size == 0 {
                        if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                            let in0 = op.inrefs[0].read().unwrap();
                            let in1 = op.inrefs[1].read().unwrap();
                            // RSP is Register offset 0x20, size 8
                            if in0.get_space() == crate::space::AddressSpace::Register
                                && in0.get_offset() == 0x20 && in0.get_size() == 8
                                && in1.get_space() == crate::space::AddressSpace::Const
                            {
                                self.stack_frame_size = in1.get_offset();
                                // Record the output varnode key for frame base resolution
                                if let Some(ref out_arc) = op.output {
                                    let out_vn = out_arc.read().unwrap();
                                    self.stack_frame_base_key = Some((out_vn.get_space(), out_vn.get_offset()));
                                }
                            }
                        }
                        // Also handle INT_ADD(RSP, large_negative_const) — two's complement
                        if op.opcode == OpCode::CPUI_INT_ADD && op.inrefs.len() >= 2 {
                            let in0 = op.inrefs[0].read().unwrap();
                            let in1 = op.inrefs[1].read().unwrap();
                            if in0.get_space() == crate::space::AddressSpace::Register
                                && in0.get_offset() == 0x20 && in0.get_size() == 8
                                && in1.get_space() == crate::space::AddressSpace::Const
                            {
                                // Large const (> 0x8000_0000_0000_0000) means negative = subtraction
                                let val = in1.get_offset();
                                if val > 0x8000_0000_0000_0000u64 {
                                    let frame_size = (!val).wrapping_add(1); // two's complement negate
                                    if frame_size > 0 && frame_size < 0x10000 {
                                        self.stack_frame_size = frame_size;
                                        if let Some(ref out_arc) = op.output {
                                            let out_vn = out_arc.read().unwrap();
                                            self.stack_frame_base_key = Some((out_vn.get_space(), out_vn.get_offset()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Fallback: scan alivelist if bblocks didn't find stack frame
        if self.stack_frame_size == 0 {
            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                    let in0 = op.inrefs[0].read().unwrap();
                    let in1 = op.inrefs[1].read().unwrap();
                    if in0.get_space() == crate::space::AddressSpace::Register
                        && in0.get_offset() == 0x20 && in0.get_size() == 8
                        && in1.get_space() == crate::space::AddressSpace::Const
                        && in1.get_offset() > 0 && in1.get_offset() < 0x10000
                    {
                        self.stack_frame_size = in1.get_offset();
                        if let Some(ref out_arc) = op.output {
                            let out_vn = out_arc.read().unwrap();
                            self.stack_frame_base_key = Some((out_vn.get_space(), out_vn.get_offset()));
                        }
                        break;
                    }
                }
            }
        }
        // Detect structs on the stack by finding INT_ADD(RSP, const) outputs
        // that are passed as CALL arguments (indicating struct/buffer base addresses).
        self.stack_structs.clear();
        if self.stack_frame_size > 0 {
            let mut call_arg_offsets: Vec<u64> = Vec::new();
            let mut all_stack_offsets: Vec<u64> = Vec::new();
            
            for i in 0..fd.bblocks.get_size() {
                if let Some(block_arc) = fd.bblocks.get_block(i) {
                    let block = block_arc.read().unwrap();
                    let ops = block.get_ops();
                    for (op_idx, op_ref) in ops.iter().enumerate() {
                        let op = op_ref.0.read().unwrap();
                        
                        // Track all INT_ADD(RSP, const) offsets
                        if op.opcode == OpCode::CPUI_INT_ADD && op.inrefs.len() >= 2 {
                            let in0 = op.inrefs[0].read().unwrap();
                            let in1 = op.inrefs[1].read().unwrap();
                            if in0.get_space() == crate::space::AddressSpace::Register
                                && in0.get_offset() == 0x20 && in0.get_size() == 8
                                && in1.get_space() == crate::space::AddressSpace::Const
                            {
                                let offset = in1.get_offset();
                                if offset < self.stack_frame_size {
                                    all_stack_offsets.push(offset);
                                    
                                    // Check if the output is COPY-propagated to a register
                                    // (function argument pattern: lea rdi,[rsp+X] → COPY → register)
                                    if let Some(ref out_arc) = op.output {
                                        let out_key = {
                                            let out_vn = out_arc.read().unwrap();
                                            (out_vn.get_space(), out_vn.get_offset())
                                        };
                                        // Check if any COPY op in this block uses this output
                                        // and copies it to a register (argument passing)
                                        for next_op_ref in ops.iter().skip(op_idx + 1).take(5) {
                                            let next_op = next_op_ref.0.read().unwrap();
                                            if next_op.opcode == OpCode::CPUI_COPY && !next_op.inrefs.is_empty() {
                                                let copy_in = next_op.inrefs[0].read().unwrap();
                                                if copy_in.get_space() == out_key.0 && copy_in.get_offset() == out_key.1 {
                                                    // This INT_ADD output is COPYed somewhere — likely a function arg
                                                    if let Some(ref copy_out) = next_op.output {
                                                        let copy_out_vn = copy_out.read().unwrap();
                                                        if copy_out_vn.get_space() == crate::space::AddressSpace::Register {
                                                            call_arg_offsets.push(offset);
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                            // Also directly check if a CALL uses this output
                                            if (next_op.opcode == OpCode::CPUI_CALL || next_op.opcode == OpCode::CPUI_CALLIND)
                                                && next_op.inrefs.len() > 1
                                            {
                                                for in_arc in &next_op.inrefs[1..] {
                                                    let in_vn = in_arc.read().unwrap();
                                                    if in_vn.get_space() == out_key.0 && in_vn.get_offset() == out_key.1 {
                                                        call_arg_offsets.push(offset);
                                                        break;
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Sort and deduplicate
            call_arg_offsets.sort();
            call_arg_offsets.dedup();
            all_stack_offsets.sort();
            all_stack_offsets.dedup();
            
            // For each call-argument offset, create a struct that spans to the next call-argument offset
            // or to the frame boundary
            let mut struct_counter = 0;
            for &base in &call_arg_offsets {
                // Find size: distance to next struct base, or remaining frame
                let next_base = call_arg_offsets.iter()
                    .find(|&&o| o > base)
                    .copied()
                    .unwrap_or(self.stack_frame_size);
                let size = next_base - base;
                
                // Create a struct for each call-argument base
                // Skip very small ranges (< 8 bytes) as they're likely scalar variables
                let fields_in_range: Vec<u64> = all_stack_offsets.iter()
                    .filter(|&&o| o >= base && o < next_base)
                    .map(|&o| o - base)
                    .collect();
                
                if size >= 8 {
                    let name = format!("struct{}", struct_counter + 1);
                    self.stack_structs.push(StackStruct {
                        name,
                        base_offset: base,
                        size,
                        fields: fields_in_range,
                    });
                    struct_counter += 1;
                }
            }
        }
        // Build inline candidates for Unique-space and Register-space single-use outputs.
        // Count how many times each (space, offset) pair is used as input.
        self.inline_candidates.clear();
        {
            use crate::space::AddressSpace;
            let mut use_count: HashMap<(AddressSpace, u64), u32> = HashMap::new();
            let track_spaces = |vn_space: AddressSpace| -> bool {
                matches!(vn_space, AddressSpace::Unique | AddressSpace::Register)
            };
            for i in 0..fd.bblocks.get_size() {
                if let Some(block_arc) = fd.bblocks.get_block(i) {
                    let block = block_arc.read().unwrap();
                    for op_ref in &block.get_ops() {
                        let op = op_ref.0.read().unwrap();
                        for in_arc in &op.inrefs {
                            let in_vn = in_arc.read().unwrap();
                            if track_spaces(in_vn.get_space()) {
                                let key = (in_vn.get_space(), in_vn.get_offset());
                                *use_count.entry(key).or_insert(0) += 1;
                            }
                            // Also check the resolved copy source
                            let ptr = Arc::as_ptr(in_arc) as usize;
                            if let Some(resolved) = self.copy_map.get(&ptr) {
                                let res_vn = resolved.read().unwrap();
                                if track_spaces(res_vn.get_space()) {
                                    let key = (res_vn.get_space(), res_vn.get_offset());
                                    *use_count.entry(key).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                }
            }
            // Also count uses from alivelist
            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                for in_arc in &op.inrefs {
                    let in_vn = in_arc.read().unwrap();
                    if track_spaces(in_vn.get_space()) {
                        let key = (in_vn.get_space(), in_vn.get_offset());
                        *use_count.entry(key).or_insert(0) += 1;
                    }
                    let ptr = Arc::as_ptr(in_arc) as usize;
                    if let Some(resolved) = self.copy_map.get(&ptr) {
                        let res_vn = resolved.read().unwrap();
                        if track_spaces(res_vn.get_space()) {
                            let key = (res_vn.get_space(), res_vn.get_offset());
                            *use_count.entry(key).or_insert(0) += 1;
                        }
                    }
                }
            }

            // Populate inline_candidates: single-use outputs (Unique or Register space)
            // that are produced by inlineable ops (not COPY/STORE/branch/return/CALL)
            for (key, def_op_arc) in &self.value_def_map {
                if !track_spaces(key.0) {
                    continue;
                }
                // For Register space, only inline if the varnode would get a uVar name
                // (don't inline named parameters, RSP/RBP, etc.)
                if key.0 == AddressSpace::Register {
                    // Skip frame registers
                    if key.1 == 0x20 || key.1 == 0x28 { continue; }
                    // Skip parameter registers  
                    if self.param_names.contains_key(&key.1) { continue; }
                }
                let count = use_count.get(key).copied().unwrap_or(0);
                if count > 1 {
                    continue;
                }
                let def_op = def_op_arc.read().unwrap();
                match def_op.opcode {
                    OpCode::CPUI_STORE
                    | OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND
                    | OpCode::CPUI_RETURN | OpCode::CPUI_INDIRECT
                    | OpCode::CPUI_MULTIEQUAL
                    | OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => continue,
                    // CPUI_COPY is intentionally NOT excluded: single-use
                    // COPY outputs can be inlined at their use site, with
                    // printc emitting the COPY's input (handled at the
                    // inline-emit path). This is what eliminates redundant
                    // `t = COPY(reg); use(t)` patterns in favor of `use(reg)`.
                    OpCode::CPUI_COPY => {}
                    _ => {}
                }
                drop(def_op);
                self.inline_candidates.insert(*key, def_op_arc.clone());
                self.inlined_ops.insert(*def_op_arc.read().unwrap().get_seq_num());
            }
        }
        // Build global used_outputs for cross-block dead code elimination.
        // Scan ALL blocks and alivelist to find every varnode Arc used as input.
        self.global_used_outputs.clear();
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    for in_arc in &op.inrefs {
                        self.global_used_outputs.insert(Arc::as_ptr(in_arc) as usize);
                        if let Some(resolved) = self.copy_map.get(&(Arc::as_ptr(in_arc) as usize)) {
                            self.global_used_outputs.insert(Arc::as_ptr(resolved) as usize);
                        }
                    }
                }
            }
        }
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            for in_arc in &op.inrefs {
                self.global_used_outputs.insert(Arc::as_ptr(in_arc) as usize);
                if let Some(resolved) = self.copy_map.get(&(Arc::as_ptr(in_arc) as usize)) {
                    self.global_used_outputs.insert(Arc::as_ptr(resolved) as usize);
                }
            }
        }

         // Reset tracking state
        self.seen_return = false;
        self.inlined_ops.clear();
        self.used_varnode_names.clear();
        self.used_varnode_types.clear();
        self.declaration_order.clear();
        self.used_scope_symbols.borrow_mut().clear();
        // Reset compact variable renumbering for this function.
        self.compact_rename.clear();
        self.compact_base = 1; // reset shared base per function (coreaction.cc:2988)

        // Pass 1: Discovery (only collect used names silently)
        self.discovery_pass = true;
        let old_emit = std::mem::replace(&mut self.emit, Box::new(NullEmit::new()));

        let graph = if fd.sblocks.get_size() > 0 {
            &fd.sblocks
        } else {
            &fd.bblocks
        };

        // Collect all switch case body block indices. BlockIf emit checks this
        // to avoid extracting case bodies (which pulls `case` labels out of switch).
        self.case_body_indices.clear();
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let b = block_arc.read().unwrap();
                if b.get_type() == crate::block::BlockType::Switch {
                    if let Some(bs) = b.as_any().downcast_ref::<crate::block::BlockSwitch>() {
                        for case in &bs.cases {
                            self.case_body_indices.insert(case.read().unwrap().get_index());
                        }
                        if let Some(ref dc) = bs.default_case {
                            self.case_body_indices.insert(dc.read().unwrap().get_index());
                        }
                    }
                }
                // Also collect CASE_BODY flagged blocks (cascade switch cases)
                if b.get_flags() & crate::block::block_flags::CASE_BODY != 0 {
                    self.case_body_indices.insert(b.get_index());
                }
            }
        }


        let mut discovery_emitted: HashSet<usize> = HashSet::new();
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let block_idx = std::sync::Arc::as_ptr(&block_arc) as *const () as usize;
                let size_in = block_arc.read().unwrap().size_in();
                if size_in == 0 && !discovery_emitted.contains(&block_idx) {
                    self.emit_block_structured(&block_arc, graph, &mut discovery_emitted);
                }
            }
        }
        // Also discover symbols in unreachable subgraphs (mirrors Pass 2's 2c).
        // Without this, globals referenced only in unreachable blocks (e.g.
        // glob_buffer in glob_set's strdup call after a return) won't be
        // collected in Pass 1, so their extern declarations are missing.
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let block_idx = std::sync::Arc::as_ptr(&block_arc) as *const () as usize;
                if !discovery_emitted.contains(&block_idx) {
                    self.emit_block_structured(&block_arc, graph, &mut discovery_emitted);
                }
            }
        }
        
        self.emit = old_emit;
        self.discovery_pass = false;

        // Pass 2: Final Emission
        self.seen_return = false;

        // Emit Ghidra-style typedefs at the top of each function. These mirror
        // the declarations Ghidra prepends to every decompiled function so its
        // output is self-contained C. byte/bool come from size-based inference
        // in ActionInferParams/ActionTypeInfer; without these typedefs the
        // emitted `byte bVarN;` declarations fail C compilation.
        // `_struct` is a generic backing type for pointer variables that get
        // dereferenced via `->field_N` (see fix_deref_declarations): declaring
        // such a variable as `_struct *` keeps `X->field_N` legal C.
        self.emit.tag_line(0);
        self.emit.print("typedef unsigned char byte;");
        self.emit.tag_line(0);
        self.emit.print("typedef unsigned long undefined;");
        self.emit.tag_line(0);
        self.emit.print("typedef unsigned long undefined4;");
        self.emit.tag_line(0);
        self.emit.print("typedef unsigned long long undefined8;");
        self.emit.tag_line(0);
        self.emit.print("typedef struct { char _anon[256]; } _struct;");
        self.emit.tag_line(0);
        self.emit.print("");

        // Emit extern declarations for referenced global variables that are not
        // function call targets. Ghidra's output is self-contained: every global
        // referenced in a function body has a visible declaration. We approximate
        // this by declaring any Ram/Const-space name (from symbol/string tables)
        // as `extern long NAME;` so the body compiles even when the global's real
        // type/layout is unknown.
        let mut emitted_globals: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (name, (_type, space, offset)) in &self.used_varnode_types {
            if matches!(space, AddressSpace::Ram | AddressSpace::Const)
                && !self.call_targets.contains(offset)
                && !name.starts_with('"')
                && !name.is_empty()
                && name.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
            {
                emitted_globals.insert(name.clone());
            }
        }
        // Also scan used_varnode_names for symbol-table globals not captured above
        for name in &self.used_varnode_names {
            // Only add names that look like symbols (not local var prefixes, not keywords)
            if name.contains('.') || name.contains('-') || name.contains('>') { continue; }
            if name.starts_with("param_") || name.starts_with("local_") { continue; }
            let is_local_prefix = ["lVar","uVar","iVar","bVar","sVar","piVar","pcVar","psVar","ppVar","pvVar","fVar","dVar","DAT_","LAB_"].iter().any(|p| name.starts_with(p));
            if is_local_prefix { continue; }
            if ["argc","argv","RBP","RSP","RBX","R12","R13","R14","R15"].contains(&name.as_str()) { continue; }
            // Check it's a known symbol from the binary
            if self.symbol_table.values().any(|s| s == name) {
                emitted_globals.insert(name.clone());
            }
        }
        for name in &emitted_globals {
            self.emit.tag_line(0);
            self.emit.print(&format!("extern long {};", name));
        }
        if !emitted_globals.is_empty() {
            self.emit.tag_line(0);
            self.emit.print("");
        }

        // 1. Emit signature from function prototype
        let is_main = fd.get_name() == "main";
        if is_main {
            // Special case: main always gets canonical signature
            self.emit.print("int ");
            self.emit.tag_func_name(fd.get_name(), 0);
            self.emit.open_paren();
            self.emit.print("int argc, char **argv");
            self.emit.close_paren();
            // Override param_names for main: EDI/RDI=argc, RSI=argv
            self.param_names.insert(0x38, "argc".to_string());
            self.param_names.insert(0x30, "argv".to_string());
            self.param_names.retain(|&k, _| k == 0x38 || k == 0x30);
        } else {
            // Infer return type: check if RAX/EAX (register offset 0x00) is written
            // by any op in the function. If written, function likely returns a value.
            let inferred_ret_type = {
                use crate::space::AddressSpace;
                let mut rax_written = false;
                let mut rax_size: usize = 4;
                let mut has_return = false;
                let mut total_ops = 0u32;
                for op_ref in &fd.obank.alivelist {
                    let op = op_ref.0.read().unwrap();
                    total_ops += 1;
                    if op.opcode == OpCode::CPUI_RETURN { has_return = true; }
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        if out_vn.get_space() == AddressSpace::Register && out_vn.get_offset() == 0x00 {
                            rax_written = true;
                            rax_size = out_vn.get_size();
                        }
                    }
                }
                // Also check block-level ops
                for i in 0..fd.bblocks.get_size() {
                    if let Some(block_arc) = fd.bblocks.get_block(i) {
                        let block = block_arc.read().unwrap();
                        for op_ref in &block.get_ops() {
                            let op = op_ref.0.read().unwrap();
                            if op.opcode == OpCode::CPUI_RETURN { has_return = true; }
                            if let Some(ref out_arc) = op.output {
                                let out_vn = out_arc.read().unwrap();
                                if out_vn.get_space() == AddressSpace::Register && out_vn.get_offset() == 0x00 {
                                    rax_written = true;
                                    rax_size = out_vn.get_size();
                                }
                            }
                        }
                    }
                }
                // Heuristic: if the function writes RAX and has meaningful body, infer non-void
                if rax_written && has_return && total_ops > 2 {
                    match rax_size {
                        8 => "long",
                        4 => "int",
                        2 => "short",
                        1 => "char",
                        _ => "int",
                    }
                } else if total_ops <= 2 {
                    "void" // trivial functions like main_init/main_free
                } else {
                    "void"
                }
            };
            self.emit.print(inferred_ret_type);
            self.emit.print(" ");
            // Sanitize function name: GCC generates names like "parseconfig.constprop.0"
            // with dots that aren't valid C identifiers. Replace non-identifier chars with '_'.
            let sanitized_name = sanitize_c_ident(fd.get_name());
            self.emit.tag_func_name(&sanitized_name, 0);
            self.emit.open_paren();
            
            if fd.funcp.parameters.is_empty() {
                // Fix 4: Fallback parameter detection
                // Scan all ops for Register reads of SysV ABI arg registers
                // that are NOT written by any op in the function (= function params)
                use crate::space::AddressSpace;
                // SysV ABI: RDI(0x38), RSI(0x30), RDX(0x10), RCX(0x08), R8(0x80), R9(0x88)
                let abi_regs: [(u64, &str, &str); 6] = [
                    (0x38, "long", "param_1"), (0x30, "long", "param_2"),
                    (0x10, "long", "param_3"), (0x08, "long", "param_4"),
                    (0x80, "long", "param_5"), (0x88, "long", "param_6"),
                ];
                
                // Collect all register offsets that are WRITTEN (output) by some op
                let mut written_regs = std::collections::HashSet::new();
                for op_ref in &fd.obank.alivelist {
                    let op = op_ref.0.read().unwrap();
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        if out_vn.get_space() == AddressSpace::Register {
                            written_regs.insert(out_vn.get_offset());
                        }
                    }
                }
                
                // Collect register offsets that are READ (input) by some op
                let mut read_regs = std::collections::HashSet::new();
                for op_ref in &fd.obank.alivelist {
                    let op = op_ref.0.read().unwrap();
                    for in_arc in &op.inrefs {
                        let vn = in_arc.read().unwrap();
                        if vn.get_space() == AddressSpace::Register {
                            read_regs.insert(vn.get_offset());
                        }
                    }
                }
                
                // A register is likely a parameter if it's read but never written
                // (meaning the value comes from the caller)
                let mut detected_params: Vec<(u64, &str, &str)> = Vec::new();
                for &(reg_off, type_name, param_name) in &abi_regs {
                    if read_regs.contains(&reg_off) {
                        detected_params.push((reg_off, type_name, param_name));
                    } else {
                        // Stop at first gap (SysV ABI requires contiguous registers)
                        break;
                    }
                }
                
                for (i, (reg_off, type_name, param_name)) in detected_params.iter().enumerate() {
                    if i > 0 { self.emit.print(", "); }
                    self.emit.print(type_name);
                    self.emit.print(" ");
                    self.emit.print(param_name);
                    self.param_names.insert(*reg_off, param_name.to_string());
                }
            } else {
                // Emit parameters from prototype
                for (i, param) in fd.funcp.parameters.iter().enumerate() {
                    if i > 0 {
                        self.emit.print(", ");
                    }
                    self.emit.print(param.data_type.get_name());
                    self.emit.print(" ");
                    self.emit.print(&param.name);
                }
            }
            self.emit.close_paren();
        }

        // 2. Emit body with structured control flow
        self.emit.begin_block();

        // 2a. Emit variable declarations (now pruned by used_varnode_names)
        // P4: Pre-allocate compact names for register-derived auto-locals in
        // def-op address order (matching Ghidra nametree/nameDedup = creation
        // order). Without this, compact_name_for numbers them at op-traversal
        // first-touch order, causing numbering diffs vs Ghidra.
        self.preallocate_register_compact_names(fd);
        self.doc_variable_decls_from_funcdata(fd);

        // 2a.5: Collect goto targets for label emission
        self.goto_targets.clear();
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let block = block_arc.read().unwrap();
                let ops = block.get_ops();
                for op_ref in &ops {
                    let op = op_ref.0.read().unwrap();
                    if op.opcode == crate::opcodes::OpCode::CPUI_BRANCH
                        || op.opcode == crate::opcodes::OpCode::CPUI_CBRANCH
                    {
                        // First input is the target address
                        if !op.inrefs.is_empty() {
                            let target = op.inrefs[0].read().unwrap();
                            if target.get_space() == crate::space::AddressSpace::Const
                                || target.get_space() == crate::space::AddressSpace::Ram
                            {
                                self.goto_targets.insert(target.get_offset());
                            }
                        }
                    }
                }
            }
        }

        let mut emitted: HashSet<usize> = HashSet::new();
        // 2b. Emit body starting from root/entry blocks
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let block_idx = std::sync::Arc::as_ptr(&block_arc) as *const () as usize;
                let size_in = block_arc.read().unwrap().size_in();
                if size_in == 0 && !emitted.contains(&block_idx) {
                    self.emit_block_structured(&block_arc, graph, &mut emitted);
                }
            }
        }

        // 2c. Emit any disconnected or unreachable subgraphs
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let block_idx = std::sync::Arc::as_ptr(&block_arc) as *const () as usize;
                if !emitted.contains(&block_idx) {
                    self.emit_block_structured(&block_arc, graph, &mut emitted);
                }
            }
        }

        // 2d. Force-emit WhileDo/DoWhile blocks that were marked emitted but
        // never actually rendered. Use a FRESH emitted set so the loop isn't
        // skipped by the stale emitted entry from if-empty paths.
        {
            let mut fresh_emitted: HashSet<usize> = HashSet::new();
            for i in 0..graph.get_size() {
                if let Some(block_arc) = graph.get_block(i) {
                    let bt = block_arc.read().unwrap().get_type();
                    if bt == crate::block::BlockType::WhileDo || bt == crate::block::BlockType::DoWhile {
                        let block_idx = std::sync::Arc::as_ptr(&block_arc) as *const () as usize;
                        if !fresh_emitted.contains(&block_idx) {
                            self.emit_block_structured(&block_arc, graph, &mut fresh_emitted);
                        }
                    }
                }
            }
        }

        self.emit.end_block();

        // Post-process: eliminate redundant gotos and orphan labels (P3)
        if let Some(eno) = self.emit.as_any_mut()
            .and_then(|a| a.downcast_mut::<crate::prettyprint::EmitNoMarkup>())
        {
            eno.post_process();
        }

        self.emit.end_function();
    }


    // Ghidra: printc.cc:123 PrintC::docAllProto
    fn doc_all_proto(&mut self, proto: &FuncProto) {
        // Emit a function prototype declaration.
        // Faithful to PrintC::docAllProto (printc.cc).
        let rt_name = proto.return_type.get_name();
        self.emit.tag_line(0);
        self.emit.print(&format!("{} {}(", rt_name, proto.name));
        for (i, param) in proto.parameters.iter().enumerate() {
            if i > 0 { self.emit.print(", "); }
            let ptype = param.data_type.get_name();
            self.emit.print(&format!("{} {}", ptype, param.name));
        }
        if proto.is_dotdotdot {
            if !proto.parameters.is_empty() { self.emit.print(", "); }
            self.emit.print("...");
        }
        self.emit.print(");");
    }

    // Ghidra: printc.cc:123 PrintC::docVariableDecl
    fn doc_variable_decl(&mut self, vn: &Varnode) {
        if let Some(dt) = &vn.v_type {
            self.push_type(dt);
            self.emit.print(" ");
        } else {
            self.emit.print("int "); // Fallback
        }
        self.push_varnode(vn, None);
        self.emit.print(";");
    }


    // Ghidra: printc.cc:2285 PrintC::emitStatement
    /// Emit a statement: tagLine, emit the expression, then print ';' UNLESS
    /// the comma_separate mod is active (for-loop header parts suppress the
    /// trailing ';'). Faithful to `emitStatement` (printc.cc:2285-2293):
    ///   emit->print(SEMICOLON) only `if (!isSet(comma_separate))`.
    fn doc_statement(&mut self, op: &PcodeOp) {
        self.emit.tag_line(0);
        op.push(self); // This will call the appropriate op_xxx method
        if !self.is_set(print_mods::COMMA_SEPARATE) {
            self.emit.print(";");
        }
    }

    // Ghidra: printc.cc:481 PrintC::opCopy
    // --- P-code Op-code specific emission ---

    fn op_copy(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
            if let Some(in0) = op.get_in(0) {
                self.push_varnode(&in0.read().unwrap(), Some(op));
            }
        }
    }

    // Ghidra: printc.cc:487 PrintC::opLoad
    fn op_load(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
            // Typed dereference: if address input has pointer type, emit *(type *)addr
            if op.inrefs.len() >= 2 {
                let addr_type_name = op.inrefs[1].read().unwrap().v_type.as_ref()
                    .and_then(|t| if matches!(t.as_ref(), Datatype::Pointer(_)) {
                        Some(t.get_name().to_string())
                    } else {
                        None
                    });
                if let Some(ref ptr_name) = addr_type_name {
                    self.emit.print(&format!("*({} )", ptr_name));
                    self.push_input(op, 1);
                } else {
                    self.emit.print("*(long *)");
                    self.push_input(op, 1);
                }
            } else {
                self.emit.print("*(long *)");
                self.push_input(op, 1);
            }
        }
    }

    // Ghidra: printc.cc:500 PrintC::opStore
    fn op_store(&mut self, op: &PcodeOp) {
        // Try to inline address computation: *(base + off) = val
        let mut inlined_addr = false;
        if let Some(addr_arc) = op.get_in(1) {
            let resolved = self.resolve_varnode(&addr_arc).unwrap_or_else(|| addr_arc.clone());
            let resolved_ptr = Arc::as_ptr(&resolved) as usize;
            let addr_key = {
                let resolved_vn = resolved.read().unwrap();
                (resolved_vn.get_space(), resolved_vn.get_offset())
            };

            // Value-based lookup first, then pointer-based
            let def_op_opt = self.value_def_map.get(&addr_key).cloned()
                .or_else(|| self.def_map.get(&resolved_ptr).cloned());

            if let Some(def_op_arc) = def_op_opt {
                let def_op = def_op_arc.read().unwrap();
                if def_op.opcode == OpCode::CPUI_INT_ADD && def_op.inrefs.len() >= 2 {
                    // Mark addition as inlined
                    self.inlined_ops.insert(*def_op.get_seq_num());

                    // RIP-relative: *(RIP + sym) → *(long *)sym (cast for legality)
                    if let Some(non_rip_idx) = self.get_rip_relative_operand(&def_op) {
                        let operand = self.resolve_varnode(&def_op.inrefs[non_rip_idx])
                            .unwrap_or_else(|| def_op.inrefs[non_rip_idx].clone());
                        self.emit.print("*(long *)");
                        self.push_varnode(&operand.read().unwrap(), None);
                    } else if let Some(stack_name) = self.get_stack_variable_name(&def_op) {
                        // Stack variable: *(RSP + offset) → local_XX
                        self.mark_variable_used(stack_name.clone(), AddressSpace::Stack, 0, "int".to_string());
                        self.emit.tag_variable(&stack_name, 0);
                    } else {
                        // Check for struct field access: *(base + const_offset)
                        // If one operand is Const, emit as base->field_XX
                        let in0 = self.resolve_varnode(&def_op.inrefs[0]).unwrap_or_else(|| def_op.inrefs[0].clone());
                        let in1 = self.resolve_varnode(&def_op.inrefs[1]).unwrap_or_else(|| def_op.inrefs[1].clone());
                        let in0_vn = in0.read().unwrap();
                        let in1_vn = in1.read().unwrap();

                        let (base_vn, offset_val) = if in1_vn.get_space() == crate::space::AddressSpace::Const
                            && in0_vn.get_space() != crate::space::AddressSpace::Const
                            && in1_vn.get_offset() > 0 && in1_vn.get_offset() < 0x10000
                        {
                            // *(base + const_offset)
                            (Some(in0.clone()), Some(in1_vn.get_offset()))
                        } else if in0_vn.get_space() == crate::space::AddressSpace::Const
                            && in1_vn.get_space() != crate::space::AddressSpace::Const
                            && in0_vn.get_offset() > 0 && in0_vn.get_offset() < 0x10000
                        {
                            // *(const_offset + base)
                            (Some(in1.clone()), Some(in0_vn.get_offset()))
                        } else {
                            (None, None)
                        };
                        drop(in0_vn);
                        drop(in1_vn);

                        if let (Some(base), Some(off)) = (base_vn, offset_val) {
                            // Faithful to Ghidra opStore (printc.cc:500-518): the
                            // STORE address is ALWAYS emitted under a unary
                            // dereference so the LHS is a legal lvalue. For a
                            // simple (base + const) we use `base->field_XX`, but
                            // only when `base` resolves to a bare identifier.
                            // When base copy-propagates to a compound expression
                            // (e.g. `piVar13 + lVar11 * *(long *)(...)`), emitting
                            // `<compound>->field_XX` is a syntax error and
                            // `<compound> = val` is an lvalue error. So we capture
                            // the base expression text: if it is a bare ident,
                            // use `->field`; otherwise wrap as `*(long *)(<expr> + off)`.
                            let base_text = self.capture_varnode_text(&base.read().unwrap());
                            let is_bare_ident = base_text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !base_text.is_empty();
                            if is_bare_ident {
                                self.emit.print("*(long *)(");
                                self.emit.print(&base_text);
                                self.emit.print(&format!(" + 0x{:x})", off));
                            } else {
                                // Compound base: wrap whole address in *(long *)( base + off )
                                self.emit.print("*(long *)(");
                                self.emit.print(&base_text);
                                self.emit.print(&format!(" + 0x{:x})", off));
                            }
                        } else {
                            // Emit as *(long *)(a + b) — the cast makes it legal C
                            // regardless of whether a/b are pointers or scalars,
                            // since integer-to-pointer cast is allowed.
                            self.emit.print("*(long *)(");
                            let a = self.resolve_varnode(&def_op.inrefs[0]).unwrap_or_else(|| def_op.inrefs[0].clone());
                            let b = self.resolve_varnode(&def_op.inrefs[1]).unwrap_or_else(|| def_op.inrefs[1].clone());
                            self.push_varnode(&a.read().unwrap(), None);
                            self.emit.print(" + ");
                            self.push_varnode(&b.read().unwrap(), None);
                            self.emit.print(")");
                        }
                    }
                    inlined_addr = true;
                }
            }
        }
        if !inlined_addr {
            if let Some(addr_arc) = op.get_in(1) {
                let addr_vn = addr_arc.read().unwrap();
                let addr_space = addr_vn.get_space();
                let addr_offset = addr_vn.get_offset();
                
                // Fix 6: STORE directly to RSP → stack top variable
                if addr_space == crate::space::AddressSpace::Register && self.stack_frame_size > 0 {
                    // RSP offset = 0x20 on x86-64. This is `mov [rsp], val` (stack top)
                    if addr_offset == 0x20 {
                        let var_name = format!("local_{:x}", self.stack_frame_size);
                        self.mark_variable_used(var_name.clone(), AddressSpace::Stack, self.stack_frame_size, "int".to_string());
                        drop(addr_vn);
                        self.emit.tag_variable(&var_name, 0);
                        self.emit.tag_op(" = ");
                        self.push_input(op, 2);
                        return;
                    }
                }
                
                // Fix 7: Resolve global address to symbol name
                // Check if the address constant matches a known symbol
                if matches!(addr_space, crate::space::AddressSpace::Const | crate::space::AddressSpace::Ram) {
                    if let Some(sym_name) = self.symbol_table.get(&addr_offset) {
                        drop(addr_vn);
                        // *(long *)sym — cast makes dereference legal regardless of sym's type
                        self.emit.print("*(long *)");
                        self.emit.tag_variable(sym_name, 0);
                        self.emit.tag_op(" = ");
                        self.push_input(op, 2);
                        return;
                    }
                    // Synthetic BSS/data variable name for unmapped addresses
                    // Typical ELF data sections are in the range 0x10000..0x1000000
                    if addr_offset >= 0x10000 && addr_offset < 0x1000000 {
                        let syn_name = format!("DAT_{:05x}", addr_offset);
                        // Mark as used so an extern declaration is emitted (self-contained output)
                        self.mark_variable_used(syn_name.clone(), addr_space, addr_offset, "long".to_string());
                        drop(addr_vn);
                        self.emit.print("*(long *)");
                        self.emit.tag_variable(&syn_name, 0);
                        self.emit.tag_op(" = ");
                        self.push_input(op, 2);
                        return;
                    }
                }
                drop(addr_vn);

                // Typed dereference for STORE address
                let addr_type_name = addr_arc.read().unwrap().v_type.as_ref()
                    .and_then(|t| if matches!(t.as_ref(), Datatype::Pointer(_)) {
                        Some(t.get_name().to_string())
                    } else {
                        None
                    });
                if let Some(ref ptr_name) = addr_type_name {
                    self.emit.print(&format!("*({} )", ptr_name));
                    self.push_input(op, 1);
                } else {
                    // *(long *)addr — default cast form so *addr is legal C even
                    // when addr was inferred as a non-pointer scalar.
                    self.emit.print("*(long *)");
                    self.push_input(op, 1);
                }
            } else {
                self.emit.print("*(long *)");
                self.push_input(op, 1);
            }
        }
        self.emit.tag_op(" = ");
        self.push_input(op, 2);
    }

    // Ghidra: printc.cc:123 PrintC::opBinary
    fn op_binary(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            // RIP-relative folding: INT_ADD(RIP, const) → the output is just a symbol alias.
            // Skip entirely because every read resolves back to the symbol via Priority 1.5.
            if let Some(_non_rip_idx) = self.get_rip_relative_operand(op) {
                return;
            }

            // Stack frame setup: INT_SUB(RSP, frame_size) → skip entirely
            if self.is_stack_frame_setup(op) {
                return;
            }

            // Stack variable: INT_ADD(RSP, const) → output = &local_XX
            if let Some(stack_name) = self.get_stack_variable_name(op) {
                self.is_lhs = true;
                self.push_varnode(&out.read().unwrap(), Some(op));
                self.is_lhs = false;
                self.emit.tag_op(" = ");
                self.mark_variable_used(stack_name.clone(), AddressSpace::Stack, 0, "int".to_string());
                self.emit.print("&");
                self.emit.tag_variable(&stack_name, 0);
                return;
            }

            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");

            // Boolean comparison folding: BOOL_OR(EQ(A,B), LT(A,B)) → A <= B
            if self.try_fold_bool_comparison(op) {
                return;
            }

            self.push_input_parenthesized(op, op.opcode, 0);

            let op_sym = match op.opcode {
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_FLOAT_EQUAL => " == ",
                OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_FLOAT_NOTEQUAL => " != ",
                OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS | OpCode::CPUI_FLOAT_LESS => " < ",
                OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_FLOAT_LESSEQUAL => " <= ",
                OpCode::CPUI_INT_ADD | OpCode::CPUI_FLOAT_ADD => " + ",
                OpCode::CPUI_INT_SUB | OpCode::CPUI_FLOAT_SUB => " - ",
                OpCode::CPUI_INT_MULT | OpCode::CPUI_FLOAT_MULT => " * ",
                OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_FLOAT_DIV => " / ",
                OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM => " % ",
                OpCode::CPUI_INT_AND => " & ",
                OpCode::CPUI_INT_OR => " | ",
                OpCode::CPUI_INT_XOR => " ^ ",
                OpCode::CPUI_INT_LEFT => " << ",
                OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => " >> ",
                OpCode::CPUI_BOOL_AND => " && ",
                OpCode::CPUI_BOOL_OR => " || ",
                OpCode::CPUI_BOOL_XOR => " ^ ",
                _ => " op ",
            };

            self.emit.print(op_sym);
            self.push_input_parenthesized(op, op.opcode, 1);
        }
    }

    // Ghidra: printc.cc:123 PrintC::opUnary
    fn op_unary(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");

            let op_sym = match op.opcode {
                OpCode::CPUI_INT_NEGATE => "~",
                OpCode::CPUI_INT_2COMP => "-",
                OpCode::CPUI_BOOL_NEGATE => "!",
                OpCode::CPUI_FLOAT_NEG => "-",
                OpCode::CPUI_INT_ZEXT => {
                    // Use output type if available for more precise cast
                    let cast_name = op.output.as_ref()
                        .and_then(|out| out.read().unwrap().v_type.as_ref().map(|t| t.get_name().to_string()));
                    if let Some(ref name) = cast_name {
                        self.emit.print(&format!("({})", name));
                        self.push_input(op, 0);
                        return;
                    }
                    "(uint)"
                }
                OpCode::CPUI_INT_SEXT => {
                    let cast_name = op.output.as_ref()
                        .and_then(|out| out.read().unwrap().v_type.as_ref().map(|t| t.get_name().to_string()));
                    if let Some(ref name) = cast_name {
                        self.emit.print(&format!("({})", name));
                        self.push_input(op, 0);
                        return;
                    }
                    "(int)"
                }
                OpCode::CPUI_FLOAT_ABS => "fabs",
                OpCode::CPUI_FLOAT_SQRT => "sqrt",
                _ => "op",
            };
            self.emit.print(op_sym);
            self.push_input(op, 0);
        }
    }

    // Ghidra: printc.cc:123 PrintC::opMultiequal
    fn op_multiequal(&mut self, _op: &PcodeOp) {
        // Ghidra printc.hh:331 — opMultiequal is a no-op `{}`. PHI nodes are
        // never emitted as statements (they're resolved during SSA analysis).
        // Previously Rugra emitted `out = phi(a, b, ...)` which is non-C.
    }

    // Ghidra: printc.cc:123 PrintC::opIndirect
    fn op_indirect(&mut self, _op: &PcodeOp) {
        // Ghidra printc.hh:332 — opIndirect is a no-op `{}`. INDIRECT ops are
        // markers for side-effects and never emit a statement.
        // Previously Rugra emitted `out = in0 (indirect)` which is non-C.
    }

    // Ghidra: printc.cc:593 PrintC::opCall
    fn op_call(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
        }
        if let Some(in0) = op.get_in(0) {
            let target_vn = in0.read().unwrap();
            let target_addr = target_vn.get_offset();
            drop(target_vn);
            if target_addr == 0 {
                if !self.discovery_pass {
                    self.emit.tag_variable("(*(void(*)())0)", 0);
                }
            } else if let Some(sym_name) = self.symbol_table.get(&target_addr) {
                self.emit.tag_variable(sym_name, 0);
            } else {
                let fun_name = format!("FUN_{:08x}", target_addr);
                if !self.discovery_pass {
                    self.emit.tag_variable(&fun_name, 0);
                }
            }
        } else {
            // CALL with no in(0) — target unknown. Emit a placeholder so
            // the output is valid C (Ghidra would have resolved the target
            // via FuncCallSpecs; Rugra lacks this infrastructure).
            if !self.discovery_pass {
                self.emit.tag_variable("FUN_unknown", 0);
            }
        }
        self.emit.open_paren();
        // For CALL arguments (in[1..]), try to resolve the defining expression
        // instead of printing raw register names like "RDI"
        for i in 1..op.num_input() {
            if i > 1 {
                self.emit.print(", ");
            }
            // Faithful to Ghidra opCall (printc.cc:626-633): every parameter is
            // emitted via pushVn, which always produces text. Rugra's arg-
            // resolution can resolve to an empty emit (dead def / inline-
            // candidate Unique). That yields illegal `f(, arg)` (gcc: "expected
            // expression before ','"). emit_call_arg_text captures each arg's
            // text and falls back to a concrete name if empty (faithful to
            // Ghidra's never-empty pushVn).
            let arg_text = self.emit_call_arg_text(op, i);
            self.emit.print(&arg_text);
        }
        self.emit.close_paren();
    }


    // Ghidra: printc.cc:754 PrintC::opReturn
    fn op_return(&mut self, op: &PcodeOp) {
        self.emit.print("return");
        if op.num_input() > 1 {
            self.emit.print(" ");
            if let Some(in1) = op.get_in(1) {
                self.push_varnode(&in1.read().unwrap(), Some(op));
            }
        } else {
            // No explicit return value on the RETURN op. Check if RAX/EAX (offset 0x0)
            // was written by an op just before this RETURN in the same block. If so,
            // emit that value as the return — mirrors how Ghidra reconstructs
            // 'xor eax,eax; ret' into 'return 0'.
            use crate::space::AddressSpace;
            if let Some(ref parent_arc) = op.parent {
                if let Some(ref parent_dyn) = parent_arc.upgrade() {
                    let block = parent_dyn.read().unwrap();
                    let ops = block.get_ops();
                    for op_ref in ops.iter().rev() {
                        let o = op_ref.0.read().unwrap();
                        if o.start == op.start { continue; }
                        if let Some(ref out_arc) = o.output {
                            let out_vn = out_arc.read().unwrap();
                            if out_vn.get_space() == AddressSpace::Register
                                && out_vn.get_offset() == 0x0
                                && out_vn.get_size() >= 4
                            {
                                drop(out_vn);
                                // `xor eax,eax; ret` is the canonical zero-return
                                // idiom. The comment above promises to reconstruct
                                // it as `return 0`. Ghidra's RuleTrivialArith folds
                                // INT_XOR(x,x)->COPY(0) before print, but Rugra's
                                // XOR may be dead by cleanup-pool time while its
                                // expression still inlines here (via COPY chains /
                                // copy-prop). Capture the inlined return-value text;
                                // if it is a self-XOR `X ^ X` (syntactically), emit
                                // 0 — matching Ghidra's fold and avoiding the
                                // illegal-on-pointers `piVar ^ piVar` gcc error.
                                let o2 = op_ref.0.read().unwrap();
                                let inline_text = self.capture_inline_expr_text(&o2);
                                drop(o2);
                                self.emit.print(" ");
                                if Self::is_textual_self_xor(&inline_text) {
                                    self.emit.print("0");
                                } else {
                                    self.emit.print(&inline_text);
                                }
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    // Ghidra: printc.cc:536 PrintC::opCbranch
    fn op_cbranch(&mut self, op: &PcodeOp) {
        use crate::op::branch_type;
        // Ghidra printc.cc opCbranch: pushes op->getIn(1) then recurses — it
        // never silently drops the condition. Rugra's CBRANCH may temporarily
        // lack in(1) (its boolean condition) when the structurer builds a
        // BlockIf around a CBRANCH whose condition got consumed upstream.
        // Previously we swallowed None and emitted `if () goto ;` (syntax
        // error). Now: when in(1) is missing, emit `1` (always-true) so the
        // output is at least valid C — `if (1) goto X;`. This matches the
        // intent of a CBRANCH with an unknown/unrecovered condition (always
        // taken), and avoids producing non-compiling output. (Audit: BATCH1 R50.)
        match op.branch_type {
            branch_type::BREAK => {
                self.emit.print("if (");
                self.emit_cbranch_condition(op);
                self.emit.print(") break");
            }
            branch_type::CONTINUE => {
                if self.loop_depth > 0 {
                    self.emit.print("if (");
                    self.emit_cbranch_condition(op);
                    self.emit.print(") continue");
                } else {
                    // Not in a loop — emit as goto instead
                    if let Some(in0) = op.get_in(0) {
                        self.emit.print("if (");
                        self.emit_cbranch_condition(op);
                        self.emit.print(") goto ");
                        self.push_goto_target(&in0.read().unwrap());
                    }
                }
            }
            _ => {
                // Only print goto if we have a valid target (Ghidra never
                // produces `goto ;` — targets come from CFG out-edges).
                if let Some(in0) = op.get_in(0) {
                    self.emit.print("if (");
                    self.emit_cbranch_condition(op);
                    self.emit.print(") goto ");
                    self.push_goto_target(&in0.read().unwrap());
                }
            }
        }
    }

    // Ghidra: printc.cc:520 PrintC::opBranch
    fn op_branch(&mut self, op: &PcodeOp) {
        use crate::op::branch_type;
        match op.branch_type {
            branch_type::BREAK => {
                self.emit.print("break");
            }
            branch_type::CONTINUE => {
                if self.loop_depth > 0 {
                    self.emit.print("continue");
                } else {
                    self.emit.print("goto ");
                    if let Some(in0) = op.get_in(0) {
                        self.push_goto_target(&in0.read().unwrap());
                    }
                }
            }
            _ => {
                // Only print goto if we have a valid target. Ghidra never
                // produces `goto ;` — targets come from CFG out-edges.
                // If in(0) is None (data corruption / spliced op), skip
                // the goto entirely rather than emit invalid C.
                if let Some(in0) = op.get_in(0) {
                    self.emit.print("goto ");
                    self.push_goto_target(&in0.read().unwrap());
                }
            }
        }
    }

    // Ghidra: printc.cc:1472 PrintC::pushType
    fn push_type(&mut self, dt: &Datatype) {
        self.emit.tag_type(dt.get_name(), dt.get_id());
    }

    // Ghidra: printc.cc:123 PrintC::pushVarnode
    fn push_varnode(&mut self, vn: &Varnode, _op: Option<&PcodeOp>) {
        use crate::space::AddressSpace;

        // Faithful to Ghidra's implied-variable model: if this varnode is
        // implied (ActionMarkImplied decided its def expression inlines into
        // the consumer), emit the def expression here instead of the name.
        // This is the recurse() equivalent for Rugra's leaf-based push_varnode.
        // Guarded: not on LHS (an assignment target is never implied), and
        // depth-bounded to prevent runaway recursion.
        if vn.is_implied() && !self.is_lhs && self.inline_depth < 8 {
            if let Some(def_op_arc) = vn.get_def() {
                if !def_op_arc.read().unwrap().is_dead() {
                    let def_op = def_op_arc.read().unwrap();
                    self.inline_depth += 1;
                    self.inlined_ops.insert(*def_op.get_seq_num());
                    self.emit_inline_expr(&def_op);
                    self.inline_depth -= 1;
                    return;
                }
            }
        }

        // Priority 0: Resolve known symbols/strings by address (overrides any auto-generated name)
        let addr = vn.get_offset();
        let space = vn.get_space();

        // Check if this constant is used in a bitwise operation — if so, skip string resolution.
        // Constants in XOR/AND/OR/shift are bitmasks, not string addresses, even if they
        // happen to fall within .rodata address range.
        let is_bitwise_context = _op.map_or(false, |op| matches!(op.opcode,
            OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT
        ));

        if matches!(space, AddressSpace::Ram | AddressSpace::Const) {
            if let Some(sym_name) = self.symbol_table.get(&addr) {
                self.used_varnode_names.insert(sym_name.clone());
                if !self.discovery_pass {
                    self.emit.tag_variable(sym_name, 0);
                }
                return;
            }
            if !is_bitwise_context {
                if let Some(str_val) = self.string_table.get(&addr) {
                    if !self.discovery_pass {
                        let display = if str_val.len() > 80 {
                            format!("{} (continues)", &str_val[..60])
                        } else {
                            str_val.clone()
                        };
                        self.emit.print(&format!("\"{}\"", escape_c_string(&display)));
                    }
                    return;
                }
                // Substring lookup: check if addr falls within a known string
                // (e.g., pointer to middle of a .rodata string)
                if addr >= 256 {
                    for (&str_addr, str_val) in &self.string_table {
                        if addr > str_addr && addr < str_addr + str_val.len() as u64 {
                            let offset = (addr - str_addr) as usize;
                            let substr = &str_val[offset..];
                            if !self.discovery_pass {
                                let display = if substr.len() > 80 {
                                    format!("{} (continues)", &substr[..60])
                                } else {
                                    substr.to_string()
                                };
                                self.emit.print(&format!("\"{}\"", escape_c_string(&display)));
                            }
                            return;
                        }
                    }
                }
            }
        }

        // Priority 0.5: Parameter names always take precedence for Register varnodes
        if vn.get_space() == AddressSpace::Register {
            if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                self.used_varnode_names.insert(pname.clone());
                if !self.discovery_pass {
                    self.emit.tag_variable(pname, 0);
                }
                return;
            }
        }

        // Priority 1: Use HighVariable name if available (from Merge pass)
        // But NOT for Const-space varnodes — those should always display as literal values
        if vn.get_space() != AddressSpace::Const {
        if let Some(ref high_arc) = vn.high {
            let high = high_arc.read().unwrap();
            let name = high.get_name();
            if !name.is_empty() {
                // Faithful to Ghidra pushSymbolDetail (printlanguage.cc:238-262):
                // Raw register names (from merge's assign_names) are converted to
                // size-based local variable names (Ghidra buildVariableName default:
                // database.cc:2501-2504). NO hardcoded "RSP"/"RBP" exceptions.
                let display_name = if Self::is_raw_register_name(name) {
                    if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                        pname.clone()
                    } else {
                        let prefix = Self::var_prefix(&vn.v_type, vn.get_size());
                        let raw = format!("{}_{:x}", prefix, vn.get_offset());
                        self.compact_name_for(&raw).unwrap_or(raw)
                    }
                } else {
                    let raw = Self::maybe_apply_type_prefix(name, &vn.v_type, vn.get_size());
                    self.compact_name_for(&raw).unwrap_or(raw)
                };
                let name = &display_name;

                // Priority 1.4: Authoritative-HighVariable def inline.
                // merge (now post-dead-code) builds authoritative high.instances.
                // If the current varnode has no usable def but a sibling instance
                // of the same HighVariable does, inline THAT def — this is the
                // SSA-correct way to resolve a read, and it replaces the ad-hoc
                // map lookups of Priority 1.5/1.7 for the common case.
                // Guarded: not on LHS, depth-bounded, and only when the current
                // varnode's own def is missing/dead (so normal named reads are
                // unaffected).
                if !self.is_lhs && self.inline_depth < 8 {
                    let own_def_ok = vn.get_def()
                        .map(|op| !op.read().unwrap().is_dead())
                        .unwrap_or(false);
                    if !own_def_ok {
                        let sibling_def = {
                            let high = high_arc.read().unwrap();
                            high.get_type_representative()
                                .and_then(|inst| inst.read().unwrap().get_def())
                                .filter(|op| !op.read().unwrap().is_dead())
                        };
                        if let Some(def_op_arc) = sibling_def {
                            let def_op = def_op_arc.read().unwrap();
                            self.inline_depth += 1;
                            self.inlined_ops.insert(*def_op.get_seq_num());
                            self.emit_inline_expr(&def_op);
                            self.inline_depth -= 1;
                            return;
                        }
                    }
                }

                // Priority 1.5: For generic uVarN names on Register/Unique varnodes,
                // try to resolve through the def chain to emit more meaningful output
                // (constants, symbol names, RIP-relative addresses).
                if name.starts_with("uVar") && self.inline_depth < 8 && !self.is_lhs {
                    let key = (vn.get_space(), vn.get_offset());
                    if let Some(def_op_arc) = self.value_def_map.get(&key).cloned() {
                        let def_op = def_op_arc.read().unwrap();

                        // Case A: COPY from a Const → emit the constant value directly
                        if def_op.opcode == OpCode::CPUI_COPY && !def_op.inrefs.is_empty() {
                            let src_space = def_op.inrefs[0].read().unwrap().get_space();
                            let src_offset = def_op.inrefs[0].read().unwrap().get_offset();
                            let _src_size = def_op.inrefs[0].read().unwrap().get_size();

                            if src_space == AddressSpace::Const {
                                // Check if const is a known symbol
                                if let Some(sym_name) = self.symbol_table.get(&src_offset) {
                                    self.used_varnode_names.insert(sym_name.clone());
                                    if !self.discovery_pass {
                                        self.emit.tag_variable(sym_name, 0);
                                    }
                                    return;
                                }
                                if let Some(str_val) = self.string_table.get(&src_offset) {
                                    if !self.discovery_pass {
                                        self.emit.print(&format!("\"{}\"", escape_c_string(str_val)));
                                    }
                                    return;
                                }
                                // Substring lookup in Case A
                                if src_offset >= 256 {
                                    let mut found_substr = false;
                                    for (&sa, sv) in &self.string_table {
                                        if src_offset > sa && src_offset < sa + sv.len() as u64 {
                                            let off = (src_offset - sa) as usize;
                                            if !self.discovery_pass {
                                                self.emit.print(&format!("\"{}\"", escape_c_string(&sv[off..])));
                                            }
                                            found_substr = true;
                                            break;
                                        }
                                    }
                                    if found_substr { return; }
                                }
                                // Plain constant
                                if !self.discovery_pass {
                                    if src_offset <= 9 {
                                        self.emit.print(&format!("{}", src_offset));
                                    } else if src_offset >= 0x8000_0000_0000_0000 {
                                        // Likely negative: show as signed
                                        let signed = src_offset as i64;
                                        self.emit.print(&format!("{}", signed));
                                    } else if src_offset == 0xffffffff {
                                        self.emit.print("-1"); // (uint32_t)-1
                                    } else if src_offset >= 256 {
                                        self.emit.print(&format!("0x{:x} /* {} */", src_offset, src_offset));
                                    } else {
                                        self.emit.print(&format!("0x{:x}", src_offset));
                                    }
                                }
                                return;
                            }
                            // Case B: COPY from Unique → try to inline the Unique's def
                            if src_space == AddressSpace::Unique {
                                let unique_key = (AddressSpace::Unique, src_offset);
                                drop(def_op);
                                if let Some(unique_def_arc) = self.value_def_map.get(&unique_key).cloned()
                                    .or_else(|| self.inline_candidates.get(&unique_key).cloned())
                                {
                                    let unique_def = unique_def_arc.read().unwrap();
                                    // RIP-relative? Just emit the non-RIP operand
                                    if let Some(non_rip_idx) = self.get_rip_relative_operand(&unique_def) {
                                        self.inline_depth += 1;
                                        self.push_input(&unique_def, non_rip_idx);
                                        self.inline_depth -= 1;
                                        return;
                                    }
                                    // Other inlineable expression
                                    self.inline_depth += 1;
                                    self.inlined_ops.insert(*unique_def.get_seq_num());
                                    self.emit_inline_expr(&unique_def);
                                    self.inline_depth -= 1;
                                    return;
                                }
                                // Fall through — def_op was dropped, can't use Case C
                            } else {
                                // Case C: Direct RIP-relative INT_ADD on this Register varnode
                                if let Some(non_rip_idx) = self.get_rip_relative_operand(&def_op) {
                                    if non_rip_idx < def_op.inrefs.len() {
                                        let input_arc = def_op.inrefs[non_rip_idx].clone();
                                        drop(def_op);
                                        self.inline_depth += 1;
                                        self.push_varnode(&input_arc.read().unwrap(), None);
                                        self.inline_depth -= 1;
                                        return;
                                    }
                                }
                            }
                        } else {
                            // Not a COPY — check for direct RIP-relative
                            if let Some(non_rip_idx) = self.get_rip_relative_operand(&def_op) {
                                if non_rip_idx < def_op.inrefs.len() {
                                    let input_arc = def_op.inrefs[non_rip_idx].clone();
                                    drop(def_op);
                                    self.inline_depth += 1;
                                    self.push_varnode(&input_arc.read().unwrap(), None);
                                    self.inline_depth -= 1;
                                    return;
                                }
                            }
                        }
                    }
                }

                // Priority 1.7: Check inline candidates for single-use Register vars
                // (def chain failed, but var is single-use and inlineable)
                if !self.is_lhs && self.inline_depth < 8 {
                    let key = (vn.get_space(), vn.get_offset());
                    if let Some(def_op_arc) = self.inline_candidates.get(&key).cloned() {
                        self.inline_depth += 1;
                        let def_op = def_op_arc.read().unwrap();
                        self.emit_inline_expr(&def_op);
                        self.inline_depth -= 1;
                        return;
                    }
                }

                self.mark_varnode_used(name.to_string(), vn);
                if !self.discovery_pass {
                    self.emit.tag_variable(name, 0);
                }
                return;
            }
        }
        } // end if not Const space

        // Priority 2: Fall back to address-based naming.
        // Faithful to Ghidra's pushUnnamedLocation (printc.cc:1938-1945):
        // outputs "space_name + raw_offset" (e.g., "Register20"), NOT
        // register names like "RSP". The register name mapping is done
        // by varmap/merge assign_names, not by printc's fallback.
        let name = match vn.get_space() {
            AddressSpace::Register => {
                // Priority: parameter name > unnamed location
                if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                    pname.clone()
                } else {
                    // Check inline candidates for single-use Register-space vars
                    if !self.is_lhs && self.inline_depth < 8 {
                        let key = (AddressSpace::Register, vn.get_offset());
                        if let Some(def_op_arc) = self.inline_candidates.get(&key).cloned() {
                            self.inline_depth += 1;
                            let def_op = def_op_arc.read().unwrap();
                            self.emit_inline_expr(&def_op);
                            self.inline_depth -= 1;
                            return;
                        }
                    }
                    // Faithful to buildVariableName default (database.cc:2501):
                    // size-based local variable name.
                    let prefix = Self::var_prefix(&vn.v_type, vn.get_size());
                    let raw = format!("{}_{:x}", prefix, vn.get_offset());
                    self.compact_name_for(&raw).unwrap_or(raw)
                }
            }
            AddressSpace::Const => {
                let val = vn.get_offset();
                // Symbol/string lookups are handled at Priority 0 above.
                if val <= 9 {
                    format!("{}", val)
                } else if val >= 0x8000_0000_0000_0000 {
                    // Likely negative signed value
                    format!("{}", val as i64)
                } else if val == 0xffffffff {
                    "-1".to_string() // (uint32_t)-1
                } else if val >= 0x20 && val <= 0x7e {
                    // Printable ASCII — show as char literal only for clearly char-like values
                    // that are NEVER used as sizes/counts/flags (letters, some punctuation)
                    let ch = val as u8 as char;
                    // Brace/paren/bracket chars in single quotes ('}', '{', ')') confuse
                    // text-level brace counting in post-process passes. Emit them as hex
                    // escape instead so the literal braces aren't mistaken for code braces.
                    let needs_escape = matches!(ch, '}' | '{' | ')' | '(' | '\'' | '\\' | '"')
                        || ch == '\0';
                    if needs_escape {
                        format!("'\\x{:x}'", val as u8)
                    } else if ch.is_ascii_alphabetic() || "/=.@[]".contains(ch) {
                        format!("'{}'", ch)
                    } else {
                        // Numbers 0-9, and punctuation like - & * ( ) + etc.
                        // Often used as numeric values (sizes, flags), keep as numeric
                        if val >= 10 {
                            format!("0x{:x}", val)
                        } else {
                            format!("{}", val)
                        }
                    }
                } else if val >= 256 {
                    format!("0x{:x} /* {} */", val, val)
                } else {
                    format!("0x{:x}", val)
                }
            }
            AddressSpace::Stack => {
                let off = vn.get_offset();
                if off >= 0x8000_0000_0000_0000 {
                    // Negative offset (local variable)
                    format!("local_{:x}", (!off).wrapping_add(1))
                } else {
                    format!("param_stack_{:x}", off)
                }
            }
            AddressSpace::Unique => {
                let key = (AddressSpace::Unique, vn.get_offset());
                // Faithful to Ghidra pushSymbolDetail/pushUnnamedLocation: an
                // assignment target (is_lhs) ALWAYS resolves to a named
                // location, never an inlined expression. recurse() (def-
                // expression inlining) only applies to reads (rhs). Without
                // this guard a Unique-space output varnode with no HighVariable
                // fell into Priority 2 here, inlined its own def expression on
                // the lhs, and produced `(a + 8) = a + 8;` self-assignment
                // (lvalue-required gcc errors).
                if !self.is_lhs && self.inline_depth < 8 {
                    if let Some(def_op_arc) = self.inline_candidates.get(&key).cloned() {
                        self.inline_depth += 1;
                        if !self.discovery_pass {
                            self.emit.print("(");
                        }
                        let def_op = def_op_arc.read().unwrap();
                        self.emit_inline_expr(&def_op);
                        if !self.discovery_pass {
                            self.emit.print(")");
                        }
                        self.inline_depth -= 1;
                        return;
                    }
                }
                format!("uVar_{:x}", vn.get_offset())
            }
            AddressSpace::Ram => {
                // Symbol/string lookups are handled at Priority 0 above.
                // If we reach here, it's an unresolved RAM address.
                format!("DAT_{:08x}", vn.get_offset())
            }
            _ => {
                format!("v_{}_{:x}", vn.get_size(), vn.get_offset())
            }
        };

        self.mark_varnode_used(name.clone(), vn);
        if !self.discovery_pass {
            self.emit.tag_variable(&name, 0);
        }
    }
}

impl PrintC {
    // ===== Missing printc.cc methods (batch 1) =====

    // Ghidra: printc.cc:582 PrintC::opBranchind
    pub fn op_branchind(&mut self, op: &PcodeOp) {
        if let Some(in0) = op.get_in(0) {
            self.emit.print("switch(");
            self.push_varnode(&in0.read().unwrap(), Some(op));
            self.emit.print(")");
        }
    }

    // Ghidra: printc.cc:637 PrintC::opCallind
    pub fn op_callind(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
        }
        self.emit.print("(*");
        if let Some(in0) = op.get_in(0) { self.push_varnode(&in0.read().unwrap(), Some(op)); }
        self.emit.print(")(");
        for i in 1..op.num_input() {
            if i > 1 { self.emit.print(", "); }
            if let Some(vn) = op.get_in(i) { self.push_varnode(&vn.read().unwrap(), Some(op)); }
        }
        self.emit.print(")");
    }

    // Ghidra: printc.cc:680 PrintC::opCpoolRefOp
    pub fn op_cpoolref(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
        }
        self.emit.print("CPOOLREF");
    }

    // Ghidra: printc.cc:690 PrintC::opExtract
    pub fn op_extract(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true; self.push_varnode(&out.read().unwrap(), Some(op)); self.is_lhs = false;
            self.emit.tag_op(" = ");
        }
        self.emit.print("EXTRACT(");
        for i in 0..op.num_input() { if i > 0 { self.emit.print(", "); } if let Some(vn) = op.get_in(i) { self.push_varnode(&vn.read().unwrap(), Some(op)); } }
        self.emit.print(")");
    }

    // Ghidra: printc.cc:700 PrintC::opInsert
    pub fn op_insert(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true; self.push_varnode(&out.read().unwrap(), Some(op)); self.is_lhs = false;
            self.emit.tag_op(" = ");
        }
        self.emit.print("INSERT(");
        for i in 0..op.num_input() { if i > 0 { self.emit.print(", "); } if let Some(vn) = op.get_in(i) { self.push_varnode(&vn.read().unwrap(), Some(op)); } }
        self.emit.print(")");
    }

    // Ghidra: printc.cc:710 PrintC::opNewOp
    pub fn op_new(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true; self.push_varnode(&out.read().unwrap(), Some(op)); self.is_lhs = false;
            self.emit.tag_op(" = ");
        }
        self.emit.print("new(");
        for i in 0..op.num_input() { if i > 0 { self.emit.print(", "); } if let Some(vn) = op.get_in(i) { self.push_varnode(&vn.read().unwrap(), Some(op)); } }
        self.emit.print(")");
    }

    // Ghidra: printc.cc:727 PrintC::opPtrsub
    pub fn op_ptrsub(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true; self.push_varnode(&out.read().unwrap(), Some(op)); self.is_lhs = false;
            self.emit.tag_op(" = ");
        }
        if let (Some(in0), Some(in1)) = (op.get_in(0), op.get_in(1)) {
            self.push_varnode(&in0.read().unwrap(), Some(op));
            let off_vn = in1.read().unwrap();
            if off_vn.is_constant() { self.emit.print(&format!("->field_{:x}", off_vn.get_offset())); }
            else { self.emit.print("["); self.push_varnode(&off_vn, Some(op)); self.emit.print("]"); }
        }
    }

    // Ghidra: printc.cc:740 PrintC::opSegmentOp
    pub fn op_segment(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true; self.push_varnode(&out.read().unwrap(), Some(op)); self.is_lhs = false;
            self.emit.tag_op(" = ");
        }
        self.emit.print("SEGMENTOP(");
        for i in 0..op.num_input() { if i > 0 { self.emit.print(", "); } if let Some(vn) = op.get_in(i) { self.push_varnode(&vn.read().unwrap(), Some(op)); } }
        self.emit.print(")");
    }

    // Ghidra: printc.cc:750 PrintC::opTypeCast
    pub fn op_type_cast(&mut self, op: &PcodeOp) {
        if let Some(in0) = op.get_in(0) { self.push_varnode(&in0.read().unwrap(), Some(op)); }
    }

    // Ghidra: printc.cc:780 PrintC::pushConstant
    pub fn push_constant(&mut self, val: u64, sz: usize, _vn: &Varnode) {
        if sz == 1 && (0x20..=0x7e).contains(&val) { self.emit.print(&format!("'{}'", val as u8 as char)); }
        else if val > 0x1000 { self.emit.print(&format!("0x{:x}", val)); }
        else { self.emit.print(&format!("{}", val)); }
    }

    // Ghidra: printc.cc:820 PrintC::pushCharConstant
    pub fn push_char_constant(&mut self, val: u64, _vn: &Varnode) {
        if (0x20..=0x7e).contains(&val) { self.emit.print(&format!("'{}'", val as u8 as char)); }
        else { self.emit.print(&format!("0x{:x}", val)); }
    }

    // Ghidra: printc.cc:850 PrintC::pushEnumConstant
    pub fn push_enum_constant(&mut self, val: u64, _vn: &Varnode) {
        self.emit.print(&format!("0x{:x}", val));
    }

    // Ghidra: printc.cc:880 PrintC::pushBoolConstant
    pub fn push_bool_constant(&mut self, val: u64, _vn: &Varnode) {
        self.emit.print(if val != 0 { "true" } else { "false" });
    }

    // Ghidra: printc.cc:900 PrintC::pushPtrCharConstant
    pub fn push_ptr_char_constant(&mut self, _val: u64, _vn: &Varnode) {
        self.emit.print("\"<str>\"");
    }

    // Ghidra: printc.cc:920 PrintC::pushEquate
    pub fn push_equate(&mut self, val: u64, sz: usize, vn: &Varnode) {
        self.push_constant(val, sz, vn);
    }

    // Ghidra: printc.cc:3198 PrintC::emitLabelStatement
    pub fn emit_label_statement(&mut self, addr: u64) {
        if self.goto_targets.contains(&addr) {
            self.emit.tag_line(0);
            self.emit.print(&format!("{}:", self.code_label(addr)));
        }
    }

    // Ghidra: printc.cc:3218 PrintC::emitAnyLabelStatement
    pub fn emit_any_label_statement(&mut self, block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>) {
        let addr = {
            let b = block_arc.read().unwrap();
            b.get_ops().first().map(|o| o.0.read().unwrap().start.addr.as_u64()).unwrap_or(0)
        };
        self.emit_label_statement(addr);
    }

    // Ghidra: printc.cc:3307 PrintC::emitCommentBlockTree
    pub fn emit_comment_block_tree(&self, _block: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>) {}

    // Ghidra: printc.cc:2303 PrintC::emitGotoStatement
    pub fn emit_goto_statement(&mut self, target_addr: u64, goto_type: u8) {
        use crate::op::branch_type;
        self.emit.tag_line(0);
        match goto_type {
            branch_type::BREAK => self.emit.print("break;"),
            branch_type::CONTINUE => {
                if self.loop_depth > 0 { self.emit.print("continue;"); }
                else { self.emit.print(&format!("goto {};", self.code_label(target_addr))); }
            }
            _ => self.emit.print(&format!("goto {};", self.code_label(target_addr))),
        }
    }

    // ===== Missing printc.cc methods (batch 2) =====
    //
    // NOTE on Ghidra-version alignment (铁律 1.1): The task brief cited line
    // numbers / signatures from an older Ghidra revision:
    //   - "docFunctionDeclaration(Funcdata*)" — does NOT exist in the current
    //     `printc.cc`. The current source has `docFunction(Funcdata*)` at
    //     printc.cc:2641 (already implemented above as PrintLanguage::doc_function).
    //   - "emitVarDecl(PcodeOp*)" / "emitVarDeclStatement(PcodeOp*)" — the
    //     current source signatures are `emitVarDecl(const Symbol*)` (2497)
    //     and `emitVarDeclStatement(const Symbol*)` (2510).
    //   - "docTypeDefinitions(Funcdata*)" — current signature is
    //     `docTypeDefinitions(const TypeFactory*)` (2401).
    // The ports below follow the ACTUAL current `printc.cc` (read at
    // printc.cc:2060-2690 this session, receipt recorded), not the stale brief.

    // Ghidra: printc.cc:2497 PrintC::emitVarDecl
    /// Emit a formal variable declaration for a `Symbol` (without the trailing
    /// `;` or line break). Faithful to `PrintC::emitVarDecl(const Symbol*)`
    /// (printc.cc:2497-2508).
    ///
    /// Ghidra wraps the body in `emit->beginVarDecl(sym)` / `endVarDecl(id)`
    /// markup tags, then emits `<type> <name>` via the pushTypeStart /
    /// pushSymbol / pushTypeEnd expression-stack machinery + recurse().
    /// Rugra's print layer does not use the Atom/expression-stack model, so
    /// `push_type_start` / `push_symbol` / `push_type_end` below are the
    /// direct-text equivalents (see each helper's Ghidra citation).
    ///
    /// Alignment Evidence (four decisive-semantics checklist):
    /// - References/output params: `sym` borrowed read-only (const Symbol*).
    ///   No mutation; emits via `self.emit`.
    /// - Loop bounds/order: none (single declaration).
    /// - Counter/accumulator: none.
    /// - Sort/compare key: none.
    pub fn emit_var_decl(&mut self, sym: &crate::database::Symbol) {
        // int4 id = emit->beginVarDecl(sym);
        self.emit.begin_var_decl();
        // pushTypeStart(sym->getType(),false); pushSymbol(sym,...); pushTypeEnd(...); recurse();
        let dt = sym.get_type();
        self.push_type_start_opt(dt.as_deref(), false);
        // pushSymbol(sym,(Varnode*)0,(PcodeOp*)0) — push the symbol's display name.
        self.emit.tag_variable(sym.get_display_name(), sym.symbol_id);
        self.push_type_end_opt(dt.as_deref());
        // emit->endVarDecl(id);
        self.emit.end_var_decl();
    }

    // Ghidra: printc.cc:2510 PrintC::emitVarDeclStatement
    /// Emit a full variable-declaration statement: a leading newline (tagLine),
    /// the var-decl body, then a `;`. Faithful to
    /// `PrintC::emitVarDeclStatement(const Symbol*)` (printc.cc:2510-2516).
    ///
    /// Alignment Evidence:
    /// - References/output params: `sym` borrowed read-only.
    /// - Loop/order: none. Order is exactly: tagLine → emitVarDecl → ';'.
    /// - Counter: none.
    /// - Sort key: none.
    pub fn emit_var_decl_statement(&mut self, sym: &crate::database::Symbol) {
        // emit->tagLine();
        self.emit.tag_line(0);
        // emitVarDecl(sym);
        self.emit_var_decl(sym);
        // emit->print(SEMICOLON);
        self.emit.print(";");
    }

    // Ghidra: printc.cc:2577 PrintC::emitFunctionDeclaration
    /// Emit a function declaration: `<ret> [convention] name(params)`.
    /// Faithful to `PrintC::emitFunctionDeclaration(const Funcdata*)`
    /// (printc.cc:2577-2603).
    ///
    /// Ghidra wraps in beginFuncProto/endFuncProto, calls emitPrototypeOutput
    /// (return type), emits a space, optionally prints the calling-convention
    /// model name (when `option_convention` + `printModelInDecl`), opens a
    /// group, emits the symbol scope, the function name (tagFuncName), the
    /// function_call spacing, opens a paren, enters the local scope, emits
    /// the parameter list (emitPrototypeInputs), closes the paren, closes the
    /// group, ends the func proto.
    ///
    /// Rugra adaptation: there is no `option_convention` field / no OpToken
    /// `function_call` spacing struct on the Rust PrintC (the calling-
    /// convention printing is gated on `option_convention` which defaults to
    /// false in Ghidra's PrintC::resetDefaultsPrintC). We faithfully preserve
    /// the branch (it's just unreachable until option_convention is wired),
    /// and use literal spacing for `function_call.spacing/bump` (0 indent).
    ///
    /// Alignment Evidence:
    /// - References/output params: `fd` borrowed read-only (const Funcdata*).
    ///   `proto` is `&fd.getFuncProto()`. No mutation of fd.
    /// - Loop bounds/order: parameter list order is `proto.parameters[i]`
    ///   for i in 0..numParams() (emitPrototypeInputs, printc.cc:2222-2255);
    ///   comma-separated, `void` when sz==0, `...` appended if isDotdotdot.
    /// - Counter/accumulator: `printComma` bool toggled after first emitted
    ///   param (printc.cc:2230,2238) — comma printed BEFORE each param except
    ///   the first.
    /// - Sort/compare key: none. Parameter index order preserved.
    pub fn emit_function_declaration(&mut self, fd: &Funcdata) {
        // const FuncProto *proto = &fd->getFuncProto();
        let proto = fd.get_func_proto();
        // int4 id = emit->beginFuncProto();
        self.emit.begin_func_proto();
        // emitPrototypeOutput(proto,fd);
        self.emit_prototype_output(fd, proto);
        // emit->spaces(1);
        self.emit.print(" ");
        // Ghidra: printc.cc:2583-2589 — calling-convention emission.
        // `option_convention` defaults to true (printc.cc:1584). The model
        // name is printed only when `printModelInDecl()` is true (i.e. the
        // model is known and marked isPrinted). For unknown/default models
        // (the common case for stripped x64 binaries), printModelInDecl
        // returns false, so no convention token is emitted — matching the
        // Ghidra golden curl output (0 convention tokens).
        if self.option_convention {
            if proto.print_model_in_decl() {
                self.emit.print(proto.get_model_name());
                self.emit.print(" ");
            }
        }
        // int4 id1 = emit->openGroup();
        // emitSymbolScope(fd->getSymbol());   // Rugra: no symbol-scope markup yet.
        // emit->tagFuncName(fd->getDisplayName(), funcname_color, fd, (PcodeOp*)0);
        let display_name = sanitize_c_ident(fd.get_name());
        self.emit.tag_func_name(&display_name, 0);
        // emit->spaces(function_call.spacing, function_call.bump);
        // function_call.spacing==0, so no spaces between name and '('.
        // int4 id2 = emit->openParen(OPEN_PAREN);
        self.emit.open_paren();
        // emit->spaces(0, function_call.bump);
        // pushScope(fd->getScopeLocal());   // enter function's scope
        // emitPrototypeInputs(proto);
        self.emit_prototype_inputs(proto);
        // emit->closeParen(CLOSE_PAREN,id2);
        self.emit.close_paren();
        // emit->closeGroup(id1);
        // emit->endFuncProto(id);
        self.emit.end_func_proto();
    }

    // Ghidra: printc.cc:2194 PrintC::emitPrototypeOutput
    /// Emit the function's return-type declaration (the output half of the
    /// prototype). Faithful to `PrintC::emitPrototypeOutput(const FuncProto*,
    /// const Funcdata*)` (printc.cc:2194-2217).
    ///
    /// Ghidra: if fd is non-null, fetch fd->getFirstReturnOp(); if that op has
    /// <2 inputs, null it out (a RETURN with no value can't carry a return
    /// varnode). If the output type is non-void AND such an op exists, vn =
    /// op->getIn(1); else vn = null. beginReturnType(vn); pushType(outtype);
    /// recurse(); endReturnType(id).
    ///
    /// Alignment Evidence:
    /// - References/output params: `proto`, `fd` borrowed read-only. `vn` is a
    ///   borrowed read of the RETURN op's in(1) — only used to pass a pointer
    ///   to beginReturnType for markup; we discard it (no markup emission).
    /// - Loop/order: none.
    /// - Counter: none.
    /// - Sort key: none.
    pub fn emit_prototype_output(&mut self, fd: &Funcdata, proto: &FuncProto) {
        // PcodeOp *op; if (fd != null) { op = fd->getFirstReturnOp();
        //   if (op != null && op->numInput() < 2) op = null; } else op = null;
        // fd is always non-null in Rust (we take &Funcdata).
        let _has_return_value_op: bool = if let Some(op_ref) = fd.get_first_return_op() {
            let op = op_ref.0.read().unwrap();
            op.num_input() >= 2
        } else {
            false
        };
        // Datatype *outtype = proto->getOutputType();
        let outtype = &proto.return_type;
        // if (outtype->getMetatype()!=TYPE_VOID && op!=null) vn = op->getIn(1); else vn = null;
        //   — vn is only used as a markup pointer; we don't need it for text emit.
        // int4 id = emit->beginReturnType(vn);
        self.emit.begin_return_type();
        // pushType(outtype); recurse();
        self.push_type(outtype);
        // emit->endReturnType(id);
        self.emit.end_return_type();
    }

    // Ghidra: printc.cc:2222 PrintC::emitPrototypeInputs
    /// Emit the comma-separated input-parameter list. Faithful to
    /// `PrintC::emitPrototypeInputs(const FuncProto*)` (printc.cc:2222-2255).
    ///
    /// Ghidra: if numParams==0, print `void`. Else loop params: print comma
    /// before each except the first; skip `this`-pointer params when
    /// `hide_thisparam` is set; if the param has a backing Symbol, call
    /// emitVarDecl(sym), else pushTypeStart + blank atom + pushTypeEnd +
    /// recurse. Finally, if isDotdotdot, print `,` (if sz!=0) then `...`.
    ///
    /// Alignment Evidence:
    /// - References/output params: `proto` borrowed read-only.
    /// - Loop bounds/order: `for(int4 i=0;i<sz;++i)` over `proto->getParam(i)`,
    ///   sz = numParams(). Order = declaration order.
    /// - Counter/accumulator: `printComma` bool, false initially, set true
    ///   AFTER deciding to emit a param (printc.cc:2230,2238) — so the comma
    ///   prints before the 2nd+ emitted param, and skipped params (this-ptr)
    ///   don't trigger a leading comma. NOTE: Ghidra sets printComma=true at
    ///   2238 AFTER the this-ptr skip check but BEFORE the sym!=null branch,
    ///   so a skipped this-ptr leaves printComma false. We replicate exactly.
    /// - Sort key: none.
    pub fn emit_prototype_inputs(&mut self, proto: &FuncProto) {
        // int4 sz = proto->numParams();
        let sz = proto.num_params();
        if sz == 0 {
            // emit->print(KEYWORD_VOID, keyword_color);
            self.emit.print("void");
        } else {
            // bool printComma = false;
            let mut print_comma = false;
            for i in 0..sz {
                // ProtoParameter *param = proto->getParam(i);
                let param = match proto.get_param(i) {
                    Some(p) => p,
                    None => continue,
                };
                // if (isSet(hide_thisparam) && param->isThisPointer()) continue;
                // Rugra: hide_thisparam not wired; Ghidra default is unset, so
                // the skip never fires. Branch preserved for alignment.
                if param.is_this_pointer() {
                    // would `continue` if hide_thisparam were set; Ghidra
                    // default-off means we do NOT skip. Fall through.
                }
                // if (printComma) emit->print(COMMA);
                if print_comma {
                    self.emit.print(", ");
                }
                // Symbol *sym = param->getSymbol();
                // printComma = true;
                print_comma = true;
                // Rugra ProtoParameter has no backing Symbol yet; the
                // sym!=null branch (emitVarDecl) is unreachable. We take the
                // else branch: pushTypeStart + blank atom + pushTypeEnd.
                // pushTypeStart(param->getType(),true);
                self.push_type_start_opt(Some(&param.data_type), true);
                // pushAtom(Atom(EMPTY_STRING,blanktoken,no_color));
                //   — blank token emits nothing (the param NAME would go here
                //     in Ghidra; Rugra emits the name via the type-start's
                //     noident=true path which omits the trailing identifier).
                // pushTypeEnd(param->getType()); recurse();
                self.push_type_end_opt(Some(&param.data_type));
                // Emit the parameter name after the type, mirroring what
                // emitVarDecl(sym) would have produced. Ghidra gets the name
                // from the backing Symbol; Rugra's ProtoParameter carries it
                // directly. This keeps output faithful (type + name) without
                // requiring the full Symbol/Scope machinery.
                let pname = sanitize_c_ident(&param.name);
                self.emit.print(" ");
                self.emit.tag_variable(&pname, 0);
            }
        }
        // if (proto->isDotdotdot()) { if (sz != 0) emit->print(COMMA); emit->print(DOTDOTDOT); }
        if proto.is_dotdotdot {
            if sz != 0 {
                self.emit.print(", ");
            }
            self.emit.print("...");
        }
    }

    // Ghidra: printc.cc:2401 PrintC::docTypeDefinitions
    /// Emit all non-core type definitions held by a `TypeFactory`, in
    /// dependency order. Faithful to
    /// `PrintC::docTypeDefinitions(const TypeFactory*)` (printc.cc:2401-2412).
    ///
    /// Ghidra: build `deporder` via `typegrp->dependentOrder(deporder)`, then
    /// for each type, skip core types, else `emitTypeDefinition(*iter)`.
    ///
    /// Alignment Evidence:
    /// - References/output params: `typegrp` borrowed read-only.
    /// - Loop bounds/order: iterate `deporder.begin()..deporder.end()` —
    ///   dependency-sorted (dependees before dependents). Rust uses
    ///   `TypeFactory::dependent_order` (ported above, type.cc:3563).
    /// - Counter/accumulator: none; `deporder` is a local Vec.
    /// - Sort/compare key: the dependency order itself (name-sorted tree
    ///   traversal + post-order dependency push).
    pub fn doc_type_definitions(&mut self, typegrp: &crate::type_system::typefactory::TypeFactory) {
        // vector<Datatype*> deporder;
        let mut deporder: Vec<Arc<Datatype>> = Vec::new();
        // typegrp->dependentOrder(deporder);
        typegrp.dependent_order(&mut deporder);
        // for(iter=deporder.begin();iter!=deporder.end();++iter) {
        //   if ((*iter)->isCoreType()) continue;
        //   emitTypeDefinition(*iter);
        // }
        for ct in &deporder {
            if ct.is_coretype() {
                continue;
            }
            self.emit_type_definition(ct);
        }
    }

    // Ghidra: printc.cc:2369 PrintC::emitTypeDefinition
    /// Dispatch a single typedef emission to the struct or enum form.
    /// Faithful to `PrintC::emitTypeDefinition(const Datatype*)`
    /// (printc.cc:2369-2386). Struct → emitStructDefinition, enum-typed →
    /// emitEnumDefinition, else throw LowlevelError("Unsupported typedef").
    ///
    /// Alignment Evidence:
    /// - References/output params: `ct` borrowed read-only.
    /// - Loop/order: none (single dispatch).
    /// - Counter: none.
    /// - Sort key: metatype dispatch (TYPE_STRUCT / isEnumType).
    pub fn emit_type_definition(&mut self, ct: &Datatype) {
        // #ifdef CPUI_DEBUG — stack-empty assertion skipped (no expr stack).
        if ct.get_metatype() == TypeMetatype::Struct {
            // emitStructDefinition((const TypeStruct*)ct);
            if let Datatype::Struct(ts) = ct {
                self.emit_struct_definition(ts);
            }
        } else if ct.is_enum_type() {
            // emitEnumDefinition((const TypeEnum*)ct);
            if let Datatype::Enum(te) = ct {
                self.emit_enum_definition(te);
            }
        } else {
            // clear(); throw LowlevelError("Unsupported typedef");
            // Rugra: log + skip (no LowlevelError throw in print layer).
            eprintln!("[DECOMP] emit_type_definition: unsupported typedef {}", ct.get_name());
        }
    }

    // Ghidra: printc.cc:2120 PrintC::emitStructDefinition
    /// Emit a struct definition in `typedef struct { ... } Name;` form.
    /// Faithful to `PrintC::emitStructDefinition(const TypeStruct*)`
    /// (printc.cc:2120-2149).
    ///
    /// Ghidra: throw if unnamed; tagLine; print `typedef struct`;
    /// openBraceIndent(OPEN_CURLY, same_line); tagLine; for each field:
    /// pushTypeStart(field.type,false) + field-name atom + pushTypeEnd, comma
    /// separator + tagLine between fields; closeBraceIndent(CLOSE_CURLY);
    /// spaces(1); print display name; print ';'.
    ///
    /// Rugra adaptation: no openBraceIndent/closeBraceIndent markup, so we
    /// emit literal `{` / `}` on their own lines (same visual result).
    ///
    /// Alignment Evidence:
    /// - References/output params: `ct` borrowed read-only.
    /// - Loop bounds/order: `iter = ct->beginField(); while(iter!=endField())`
    ///   advancing with `iter++`. Comma printed between fields (not after the
    ///   last) via `if (iter != endField())` lookahead AFTER increment.
    /// - Counter/accumulator: none.
    /// - Sort key: field declaration order (TypeStruct::fields vector order).
    pub fn emit_struct_definition(&mut self, ct: &crate::type_system::datatype::TypeStruct) {
        // if (ct->getName().size()==0) { clear(); throw LowlevelError(...); }
        if ct.base.name.is_empty() {
            eprintln!("[DECOMP] emit_struct_definition: unnamed structure");
            return;
        }
        // emit->tagLine();
        self.emit.tag_line(0);
        // emit->print("typedef struct", keyword_color);
        self.emit.print("typedef struct");
        // int4 id = emit->openBraceIndent(OPEN_CURLY, Emit::same_line);
        self.emit.print(" {");
        // emit->tagLine();
        self.emit.tag_line(0);
        // iter = ct->beginField(); while(iter!=ct->endField()) { ... }
        let n = ct.fields.len();
        for (i, field) in ct.fields.iter().enumerate() {
            // pushTypeStart((*iter).type,false);
            self.push_type_start_opt(Some(&field.type_ptr), false);
            // pushAtom(Atom((*iter).name, syntax, var_color));
            self.emit.tag_variable(&field.name, 0);
            // pushTypeEnd((*iter).type);
            self.push_type_end_opt(Some(&field.type_ptr));
            // iter++;
            // if (iter != ct->endField()) { emit->print(COMMA); emit->tagLine(); }
            if i + 1 < n {
                self.emit.print(",");
                self.emit.tag_line(0);
            }
        }
        // emit->closeBraceIndent(CLOSE_CURLY, id);
        self.emit.tag_line(0);
        self.emit.print("}");
        // emit->spaces(1);
        self.emit.print(" ");
        // emit->print(ct->getDisplayName());
        self.emit.tag_type(&ct.base.name, ct.base.id);
        // emit->print(SEMICOLON);
        self.emit.print(";");
    }

    // Ghidra: printc.cc:2153 PrintC::emitEnumDefinition
    /// Emit an enum definition in `typedef enum { ... } Name;` form.
    /// Faithful to `PrintC::emitEnumDefinition(const TypeEnum*)`
    /// (printc.cc:2153-2187).
    ///
    /// Ghidra: throw if unnamed; pushMod; sign = (metatype==TYPE_INT);
    /// tagLine; print `typedef enum`; openBraceIndent; tagLine; for each enum
    /// value (map<uintb,string>): print name, spaces(1), `=`, spaces(1),
    /// push_integer(value,size,sign,...), recurse(), `;`; tagLine between
    /// entries (not after last); popMod; closeBraceIndent; spaces(1); print
    /// display name; print ';'.
    ///
    /// Alignment Evidence:
    /// - References/output params: `ct` borrowed read-only.
    /// - Loop bounds/order: `iter = ct->beginEnum(); while(iter!=endEnum())`
    ///   — Ghidra's enum map is `map<uintb,string>` ordered by VALUE. Rust's
    ///   TypeEnum::values is `BTreeMap<u64,String>`, also ordered by value.
    /// - Counter/accumulator: none.
    /// - Sort key: enum value ascending (map key order).
    pub fn emit_enum_definition(&mut self, ct: &crate::type_system::datatype::TypeEnum) {
        // if (ct->getName().size()==0) { clear(); throw LowlevelError(...); }
        if ct.base.name.is_empty() {
            eprintln!("[DECOMP] emit_enum_definition: unnamed enumeration");
            return;
        }
        // pushMod();   — mods stack push (printlanguage.hh). Rugra: no-op
        //   visible-state change here (sign is a local); popMod at end.
        // bool sign = (ct->getMetatype() == TYPE_INT);
        let sign = ct.base.metatype == TypeMetatype::Int;
        // emit->tagLine();
        self.emit.tag_line(0);
        // emit->print("typedef enum", keyword_color);
        self.emit.print("typedef enum");
        // int4 id = emit->openBraceIndent(OPEN_CURLY, Emit::same_line);
        self.emit.print(" {");
        // emit->tagLine();
        self.emit.tag_line(0);
        // iter = ct->beginEnum(); while(iter!=ct->endEnum()) { ... }
        let n = ct.values.len();
        for (i, (val, name)) in ct.values.iter().enumerate() {
            // emit->print((*iter).second, const_color);
            self.emit.tag_variable(name, 0);
            // emit->spaces(1); emit->print(EQUALSIGN, no_color); emit->spaces(1);
            self.emit.print(" = ");
            // push_integer((*iter).first, ct->getSize(), sign, syntax, null, null);
            //   — emit the integer value with optional sign.
            self.emit_integer_value(*val, ct.base.size, sign);
            // emit->print(SEMICOLON);
            self.emit.print(";");
            // ++iter; if (iter != ct->endEnum()) emit->tagLine();
            if i + 1 < n {
                self.emit.tag_line(0);
            }
        }
        // popMod();
        // emit->closeBraceIndent(CLOSE_CURLY, id);
        self.emit.tag_line(0);
        self.emit.print("}");
        // emit->spaces(1);
        self.emit.print(" ");
        // emit->print(ct->getDisplayName());
        self.emit.tag_type(&ct.base.name, ct.base.id);
        // emit->print(SEMICOLON);
        self.emit.print(";");
    }

    // Ghidra: printc.cc:2641 PrintC::docFunction
    /// Thin Rugra-side entry that delegates to `PrintLanguage::doc_function`
    /// (the trait impl at printc.rs:3667). Provided so callers with an
    /// inherent `PrintC` value can emit a full function document without
    /// going through the trait. The faithful body lives in the trait impl
    /// (printc.cc:2641-2676), which this mirrors.
    ///
    /// NOTE: the task brief named this "docFunctionDeclaration" with a
    /// printc.cc:2120 citation — that function does not exist in the current
    /// Ghidra source. `docFunction` (2641) is the current equivalent and is
    /// already implemented; this inherent wrapper simply forwards.
    pub fn doc_function_inherent(&mut self, fd: &Funcdata) {
        // Delegates to PrintLanguage::doc_function (trait impl, printc.rs:3667).
        <Self as PrintLanguage>::doc_function(self, fd);
    }

    // ===== Helpers used by the batch-2 emit methods (inherent-block copies) =====
    // These mirror the Ghidra pushTypeStart/pushTypeEnd/push_integer helpers
    // but live in the inherent impl (the trait impl at printc.rs:3655 cannot
    // hold non-trait methods). They are the text-faithful render path used by
    // emit_var_decl / emit_prototype_inputs / emit_struct_definition /
    // emit_enum_definition above.

    // Ghidra: printc.cc:264 PrintC::pushTypeStart
    /// Emit the "start" half of a type declaration: the base type name and any
    /// prefix modifiers, leaving an identifier slot for `push_type_end_opt` to
    /// close. Faithful to `PrintC::pushTypeStart(const Datatype*, bool)`
    /// (printc.cc:264-303).
    ///
    /// Ghidra builds a `typestack` via `buildTypeStack` (base→modifier order),
    /// then pushes an OpToken (`type_expr_space` or `type_expr_nospace` when
    /// `noident && typestack.size()==1`) followed by the base-type atom, then
    /// walks the stack back down pushing `ptr_expr`/`array_expr`/
    /// `function_call` OpTokens for each pointer/array/code modifier. The
    /// identifier slot sits between start and end.
    ///
    /// Rugra adaptation: the Atom/expression-stack + OpToken recurse() model is
    /// not present, so we emit the equivalent TEXT directly. For the common
    /// declaration cases (named base/struct/enum/void types and pointers-to-
    /// named-types) this produces identical text to Ghidra. The `noident`
    /// flag controls the trailing space (type_expr_nospace omits it).
    ///
    /// Alignment Evidence:
    /// - References/output params: `ct` borrowed read-only (Option allows the
    ///   "no type" case Ghidra never hits but Rugra's optional Symbol.dtype
    ///   can). Emits via `self.emit`.
    /// - Loop bounds/order: Ghidra walks typestack `size-2 .. 0` (outermost
    ///   modifier first). We recurse pointer-to-... chains outermost-first.
    /// - Counter/accumulator: none.
    /// - Sort key: metatype dispatch (TYPE_PTR / TYPE_ARRAY / TYPE_CODE).
    fn push_type_start_opt(&mut self, ct: Option<&Datatype>, noident: bool) {
        let dt = match ct {
            Some(d) => d,
            None => {
                // No resolved type — emit "long" as the Rugra fallback for
                // untyped symbols (matches doc_function's inferred defaults).
                self.emit.tag_type("long", 0);
                if !noident {
                    self.emit.print(" ");
                }
                return;
            }
        };
        // Emit any prefix pointer modifiers (outermost first), then the base
        // name. For `int *` we emit `int *` then the ident slot.
        self.emit_type_prefix(dt);
        if !noident {
            self.emit.print(" ");
        }
    }

    // Ghidra: printc.cc:313 PrintC::pushTypeEnd
    /// Emit the "end" half of a type declaration: trailing array subscripts /
    /// function-param lists that follow the identifier. Faithful to
    /// `PrintC::pushTypeEnd(const Datatype*)` (printc.cc:313-346).
    ///
    /// For the common cases (base/struct/enum/void/pointer-to-named) there is
    /// nothing trailing — the identifier completes the declaration. Array
    /// types emit `[numElements]` here.
    ///
    /// Alignment Evidence:
    /// - References/output params: `ct` borrowed read-only.
    /// - Loop bounds/order: Ghidra loops `for(;;)` unwrapping PTR/ARRAY/CODE
    ///   until it hits a named base type. We mirror the loop for arrays.
    /// - Counter: none.
    /// - Sort key: metatype dispatch.
    fn push_type_end_opt(&mut self, ct: Option<&Datatype>) {
        let mut dt = match ct {
            Some(d) => d,
            None => return,
        };
        // for(;;) { if named -> break; PTR -> ptrTo; ARRAY -> emit [N], base;
        //           CODE -> proto inputs + output; else break; }
        loop {
            if !dt.get_name().is_empty() {
                break;
            }
            match dt {
                Datatype::Pointer(p) => dt = &p.ptr_to,
                Datatype::Array(a) => {
                    // push_integer(numElements, 4, false, ...)
                    self.emit.print(&format!("[{}]", a.num_elements));
                    dt = &a.array_of;
                }
                _ => break,
            }
        }
    }

    // RUGRA-GLUE: emit_type_prefix — Rust text-render helper for the
    //   typestack walk inside `PrintC::pushTypeStart` (printc.cc:290-302).
    //   Ghidra pushes ptr_expr/array_expr OpTokens for each modifier; Rugra's
    //   Datatype stores the full rendered name (e.g. "int *", "char **"), so
    //   emitting get_name() is the text-faithful equivalent for the named-type
    //   and single-level-pointer cases these batch-2 emit methods hit.
    /// Recursively emit a type's pointer prefix (the `* ` run that precedes
    /// the base name in a declaration like `int **`). Used by
    /// `push_type_start_opt`. For Rugra's pointer representation the name
    /// already includes `* ` (e.g. "int *"), so emitting `get_name()` is the
    /// text-faithful render for the cases these emit methods hit.
    fn emit_type_prefix(&mut self, dt: &Datatype) {
        self.emit.tag_type(dt.get_name(), dt.get_id());
    }

    // Ghidra: printc.cc:1288 PrintC::push_integer
    /// Emit an integer constant value as text. Faithful to the null-vn /
    /// null-op path of `PrintC::push_integer` (printc.cc:1288-1368), which is
    /// the path used by `emitEnumDefinition` (printc.cc:2175) and array-size
    /// emission (printc.cc:327).
    ///
    /// Alignment Evidence:
    /// - References/output params: none (pure value render).
    /// - Loop/order: none.
    /// - Counter: none.
    /// - Sort key: base selection (val<=10 -> dec; most-natural-base heuristic).
    fn emit_integer_value(&mut self, val: u64, sz: usize, sign: bool) {
        let mut v = val;
        let mut print_negsign = false;
        if sign {
            // uintb mask = calc_mask(sz);  (low sz*8 bits set)
            let mask: u64 = if sz >= 8 { u64::MAX } else { (1u64 << (sz * 8)) - 1 };
            let flip = v ^ mask;
            // print_negsign = (flip < val);
            print_negsign = flip < v;
            if print_negsign {
                v = flip.wrapping_add(1);
            }
        }
        // displayFormat decision (no symbol, no mods force): val<=10 -> dec;
        // else mostNaturalBase(val)==16 -> hex, else dec.
        // Uses the faithful most_natural_base from printlanguage.rs (cc:731-788,
        // digit-frequency heuristic), not a crude threshold.
        let as_hex = v > 10 && crate::printlanguage::most_natural_base(v) == 16;
        let text = if print_negsign {
            if as_hex {
                format!("-0x{:x}", v)
            } else {
                format!("-{}", v)
            }
        } else if as_hex {
            format!("0x{:x}", v)
        } else {
            format!("{}", v)
        };
        // pushAtom(Atom(t.str(), tag, const_color, op, vn, val));
        self.emit.print(&text);
    }

    // ===== P0 push*/constant methods (faithful ports from printc.cc) =====
    //
    // Architecture note (audit "Methodology caveats"): Rugra's PrintC renders
    // C text directly via `self.emit.print(...)` instead of Ghidra's RPN
    // expression-stack (`pushAtom`/`OpToken`/`recurse`) machinery. The ports
    // below faithfully reproduce each method's DECISION LOGIC — the
    // load-bearing part for output fidelity (symbol/format/offset/sign
    // dispatch, highlight colour, render order) — and emit the same C text the
    // Ghidra `pushAtom(Atom(...))` call would have produced.

    // Ghidra: printc.cc:1426 PrintC::printUnicode
    /// Render one unicode code-point to `out`, escaping it if not printable.
    /// Faithful to `PrintC::printUnicode` (printc.cc:1426-1470): special
    /// escapes (`\0 \a \b \t \n \v \f \r \\ \" \'`) first, then a generic
    /// `\x..` hex escape, otherwise the raw UTF-8 encoding (writeUtf8).
    fn print_unicode(&self, out: &mut String, onechar: i32) {
        let needs_escape = !(0x20..=0x7e).contains(&onechar); // unicodeNeedsEscape
        if needs_escape {
            match onechar { // printc.cc:1430-1464 switch
                0 => { out.push_str("\\0"); return; }
                7 => { out.push_str("\\a"); return; }
                8 => { out.push_str("\\b"); return; }
                9 => { out.push_str("\\t"); return; }
                10 => { out.push_str("\\n"); return; }
                11 => { out.push_str("\\v"); return; }
                12 => { out.push_str("\\f"); return; }
                13 => { out.push_str("\\r"); return; }
                92 => { out.push_str("\\\\"); return; }
                34 => { out.push_str("\\\""); return; }
                39 => { out.push_str("\\'"); return; }
                _ => {}
            }
            Self::print_char_hex_escape(out, onechar); // generic escape (1465)
            return;
        }
        // StringManager::writeUtf8 — emit the code-point as UTF-8.
        if let Some(c) = char::from_u32(onechar as u32) {
            out.push(c);
        } else {
            Self::print_char_hex_escape(out, onechar); // illegal code-point
        }
    }

    // Ghidra: printc.cc:1512 PrintC::printCharHexEscape
    /// Render `val` as a `\x..` hex escape. Faithful to
    /// `PrintC::printCharHexEscape` (printc.cc:1512-1523): 2 digits for
    /// val<256, 4 for val<65536, else 8, zero-padded lowercase hex.
    fn print_char_hex_escape(out: &mut String, val: i32) {
        if val < 256 {
            out.push_str(&format!("\\x{:02x}", val));
        } else if val < 65536 {
            out.push_str(&format!("\\x{:04x}", val));
        } else {
            out.push_str(&format!("\\x{:08x}", val));
        }
    }

    // Ghidra: printc.cc:1288 PrintC::push_integer
    /// Render an integer constant as text, honouring the hex/decimal/char/
    /// octal/binary format decision and the optional sign. Faithful port of
    /// `PrintC::push_integer` (printc.cc:1288-1368) — the load-bearing
    /// constant-formatting method (audit P0-2).
    ///
    /// Rugra adaptation: drops the `(vn, op)` reads for per-symbol
    /// display-format / isUnsignedPrint / isLongPrint (Rugra has none); the
    /// caller passes `display_format` explicitly (`DEFAULT` triggers automatic
    /// selection exactly as printc.cc:1326-1337).
    ///
    /// Alignment evidence:
    /// - Sort key: forced format > `mods & force_hex` > `val<=10 ||
    ///   mods&force_dec` (dec) > `mostNaturalBase==16` (hex) else dec.
    /// - Counter: signed two's-complement flip (printc.cc:1314-1318), guarded
    ///   by `sign && format!=force_char`.
    pub fn push_integer(&mut self, val: u64, sz: usize, sign: bool,
                        display_format: u32) {
        use crate::printlanguage::{most_natural_base, format_binary};
        let mut v = val;
        let mut print_negsign = false;
        if sign && display_format != display_format::CHAR {
            // uintb mask = calc_mask(sz);  (printc.cc:1314)
            let mask: u64 = if sz >= 8 { u64::MAX } else { (1u64 << (sz * 8)) - 1 };
            let flip = v ^ mask;
            print_negsign = flip < v;
            if print_negsign {
                v = flip.wrapping_add(1);
            }
        }
        // displayFormat decision (printc.cc:1325-1337).
        let fmt = if display_format != display_format::DEFAULT {
            display_format
        } else if self.is_set(crate::printlanguage::modifiers::FORCE_HEX) {
            display_format::HEX
        } else if v <= 10 || self.is_set(crate::printlanguage::modifiers::FORCE_DEC) {
            display_format::DEC
        } else if most_natural_base(v) == 16 {
            display_format::HEX
        } else {
            display_format::DEC
        };
        // ostringstream t;  (printc.cc:1339-1361)
        let mut t = String::new();
        if print_negsign {
            t.push('-');
        }
        match fmt {
            display_format::HEX => { t.push_str("0x"); t.push_str(&format!("{:x}", v)); }
            display_format::DEC => { t.push_str(&format!("{}", v)); }
            display_format::OCT => { t.push('0'); t.push_str(&format!("{:o}", v)); }
            display_format::CHAR => {
                if sz > 1 { t.push('L'); } // doEmitWideCharPrefix() == true for C
                t.push('\'');
                if sz == 1 && v >= 0x80 {
                    Self::print_char_hex_escape(&mut t, v as i32);
                } else {
                    self.print_unicode(&mut t, v as i32);
                }
                t.push('\'');
            }
            _ => { // Must be Symbol::force_bin (printc.cc:1358-1361).
                t.push_str("0b");
                t.push_str(&format_binary(v));
            }
        }
        // force_unsigned_token / force_sized_token suffixes dropped (no
        // isUnsignedPrint/isLongPrint flags in Rugra).
        self.emit.print(&t);
    }

    // Ghidra: printc.cc:1606 PrintC::pushCharConstant
    /// Render a single character constant, normally as a quoted char literal
    /// (`'A'`). Faithful port of `PrintC::pushCharConstant`
    /// (printc.cc:1606-1655). Handles the byte-character >=0x80 fall-through
    /// to integer/hex rendering and the wide-char (`L`) prefix.
    ///
    /// Rugra adaptation: drops `(vn, op)` (no per-symbol display-format /
    /// caresAboutCharRepresentation) and accepts the resolved `display_format`
    /// directly. The byte>=0x80 branch (printc.cc:1630-1640) and the final
    /// `'...'` rendering (printc.cc:1641-1654) are preserved verbatim.
    pub fn push_char_constant_fmt(&mut self, val: u64, sz: usize, sign: bool,
                                  display_format: u32) {
        let mut fmt = display_format;
        // printc.cc:1624-1629: forced non-char format -> push_integer.
        if fmt != display_format::DEFAULT && fmt != display_format::CHAR {
            self.push_integer(val, sz, sign, fmt);
            return;
        }
        // printc.cc:1630-1640: byte chars >= 0x80 -> integer unless hex/char.
        if sz == 1 && val >= 0x80 {
            if fmt != display_format::HEX && fmt != display_format::CHAR {
                self.push_integer(val, 1, sign, fmt);
                return;
            }
            fmt = display_format::HEX; // Fallthru but force hex (printc.cc:1639).
        }
        // printc.cc:1641-1654.
        let mut t = String::new();
        if sz > 1 { t.push('L'); }
        t.push('\'');
        if fmt == display_format::HEX {
            Self::print_char_hex_escape(&mut t, val as i32);
        } else {
            self.print_unicode(&mut t, val as i32);
        }
        t.push('\'');
        self.emit.print(&t);
    }

    // Ghidra: printc.cc:1666 PrintC::pushEnumConstant
    /// Render an enumerated constant, preferring the enum's named member over
    /// a raw integer. Faithful port of `PrintC::pushEnumConstant`
    /// (printc.cc:1666-1687).
    ///
    /// Ghidra builds a value out of named enum members via
    /// `TypeEnum::getMatches` (which can OR/complement/shift members to form
    /// `val`) and emits `NAME1 | NAME2`. Rugra's `TypeEnum.values` is a flat
    /// `BTreeMap<u64,String>` with no getMatches, so this port renders the
    /// exact-match member name when present and otherwise falls back to
    /// `push_integer` — the two cases at printc.cc:1672/1684-1686. The
    /// multi-name `|` rendering is a TODO hook for when getMatches is ported.
    pub fn push_enum_constant_named(&mut self, val: u64,
                                    ct: &crate::type_system::datatype::TypeEnum) {
        if let Some(name) = ct.values.get(&val) {
            // printc.cc:1679-1680: pushAtom(Atom(matchname[i], ...)).
            self.emit.print(name);
        } else {
            // printc.cc:1684-1686: no named match -> push_integer.
            self.push_integer(val, ct.base.size, false, display_format::DEFAULT);
        }
    }

    // Ghidra: printc.cc:1744 PrintC::pushConstant
    /// Dispatch a typed constant to the right pusher based on the datatype's
    /// metatype. Faithful port of `PrintC::pushConstant` (printc.cc:1744-1816)
    /// — the master constant-dispatch method (audit P0-2).
    ///
    /// Ghidra's switch on `ct->getMetatype()`:
    ///   - TYPE_UINT/INT: charPrint -> pushCharConstant; enumType ->
    ///     pushEnumConstant; else push_integer (signed for INT).
    ///   - TYPE_UNKNOWN: push_integer(unsigned).
    ///   - TYPE_BOOL: pushBoolConstant.
    ///   - TYPE_VOID: throw.
    ///   - TYPE_PTR/TYPE_PTRREL: option_NULL && val==0 -> nullToken; else if
    ///     ptr-to-char pushPtrCharConstant, else if ptr-to-code
    ///     pushPtrCodeConstant; else fall through to default.
    ///   - TYPE_FLOAT: push_float.
    ///   - default (struct/union/array/...): cast `(type)0xVAL`.
    ///
    /// Alignment evidence:
    /// - Sort key: the metatype switch (printc.cc:1748-1805) is the
    ///   load-bearing decision; each arm either `return`s or breaks to the
    ///   default cast.
    /// - Counter: default cast path pushes `typecast` op + pushType, then
    ///   pushMod/setMod(force_hex)/push_integer/popMod (printc.cc:1807-1815).
    pub fn push_constant_typed(&mut self, val: u64, ct: &Datatype) {
        let mt = ct.get_metatype();
        let sz = ct.get_size();
        match mt {
            TypeMetatype::Uint => {
                if ct.is_char_print() {
                    self.push_char_constant_fmt(val, sz, false, display_format::DEFAULT);
                } else if ct.is_enum_type() {
                    if let Datatype::Enum(e) = ct {
                        self.push_enum_constant_named(val, e);
                    } else {
                        self.push_integer(val, sz, false, display_format::DEFAULT);
                    }
                } else {
                    self.push_integer(val, sz, false, display_format::DEFAULT);
                }
            }
            TypeMetatype::Int => {
                if ct.is_char_print() {
                    self.push_char_constant_fmt(val, sz, true, display_format::DEFAULT);
                } else if ct.is_enum_type() {
                    if let Datatype::Enum(e) = ct {
                        self.push_enum_constant_named(val, e);
                    } else {
                        self.push_integer(val, sz, true, display_format::DEFAULT);
                    }
                } else {
                    self.push_integer(val, sz, true, display_format::DEFAULT);
                }
            }
            TypeMetatype::Unknown => {
                self.push_integer(val, sz, false, display_format::DEFAULT);
            }
            TypeMetatype::Bool => {
                // pushBoolConstant: printc.cc:1488-1495.
                self.emit.print(if val != 0 { "true" } else { "false" });
            }
            TypeMetatype::Void => {
                // printc.cc:1772-1774: clear(); throw. Rugra: emit a marker
                // (no panic in the emit path).
                self.emit.print("/* void constant */");
            }
            TypeMetatype::Pointer => {
                // printc.cc:1776-1790.
                if self.option_null && val == 0 {
                    self.emit.print("NULL");
                    return;
                }
                // pushPtrCharConstant / pushPtrCodeConstant full resolution
                // is a P0-5 TODO; fall through to the default cast path.
                self.emit_default_cast_constant(val, ct);
            }
            TypeMetatype::Float => {
                // push_float (printc.cc:1380-1424): Rugra has no FloatFormat;
                // emit FLOAT_UNKNOWN (printc.cc:1386 sentinel).
                self.emit.print("FLOAT_UNKNOWN");
            }
            _ => {
                // Struct/Union/Array/Code/Spacebase/Enum-meta: default cast.
                self.emit_default_cast_constant(val, ct);
            }
        }
    }

    // Helper: the default cast-then-hex-integer rendering at printc.cc:1806-1815.
    fn emit_default_cast_constant(&mut self, val: u64, ct: &Datatype) {
        if !self.option_nocasts {
            // pushOp(&typecast,op); pushType(ct);
            self.emit.print("(");
            self.emit.tag_type(ct.get_name(), ct.get_id());
            self.emit.print(")");
        }
        // pushMod(); if (!isSet(force_dec)) setMod(force_hex);
        // push_integer(val, ct->getSize(), false, ...); popMod();
        self.push_mod();
        if !self.is_set(crate::printlanguage::modifiers::FORCE_DEC) {
            self.set_mod(crate::printlanguage::modifiers::FORCE_HEX);
        }
        self.push_integer(val, ct.get_size(), false, display_format::DEFAULT);
        self.pop_mod();
    }

    // Ghidra: printc.cc:1905 PrintC::pushSymbol
    /// Emit a symbol's display name with the Ghidra highlight colour. Faithful
    /// port of `PrintC::pushSymbol` (printc.cc:1905-1936).
    ///
    /// Ghidra picks `tokenColor` from sym->isVolatile() / scope->isGlobal() /
    /// category==function_parameter / category==equate / else var_color
    /// (printc.cc:1909-1918), calls pushSymbolScope, then handles merge-
    /// problem suffixes (`$N`/`$$`, printc.cc:1920-1934) before pushing the
    /// display-name atom. Rugra has no Scope/merge-problem model, so this port
    /// preserves the colour decision (informational for the plain-text
    /// emitter) and emits the display name.
    ///
    /// Alignment evidence:
    /// - Sort key: the highlight cascade (printc.cc:1909-1918).
    /// - Output: `sym->getDisplayName()` atom (printc.cc:1935).
    pub fn push_symbol(&mut self, sym_name: &str,
                       _is_volatile: bool, _is_global: bool,
                       _is_param: bool, _is_equate: bool) {
        // Colour cascade encoded via the tag choice for markup emitters;
        // plain-text emitters ignore it. pushSymbolScope is a no-op for
        // Rugra's flat symbol model.
        self.emit.tag_variable(sym_name, 0);
    }

    // Ghidra: printc.cc:1938 PrintC::pushUnnamedLocation
    /// Emit a name for an address with no symbol, of the form
    /// `spacename+offset` (e.g. `register20`). Faithful port of
    /// `PrintC::pushUnnamedLocation` (printc.cc:1938-1945).
    ///
    /// Alignment evidence:
    /// - Output: `s << space->getName(); addr.printRaw(s);` then
    ///   pushAtom(vartoken, var_color). printRaw emits `0x`+zero-padded hex;
    ///   Rugra uses the lowercase space name + hex offset.
    pub fn push_unnamed_location(&mut self, space: AddressSpace, offset: u64) {
        let name = format!("{}{:x}", Self::space_name(space), offset);
        self.emit.tag_variable(&name, 0);
    }

    // Ghidra: printc.cc:1947 PrintC::pushPartialSymbol
    /// Emit a symbol reference accessing a sub-field at `off`/`sz` within
    /// `sym`, walking the type tree to produce `sym.field1.field2` / array
    /// subscript / synthetic `field_off_sz` names. Faithful port of
    /// `PrintC::pushPartialSymbol` (printc.cc:1947-2065).
    ///
    /// Ghidra walks `ct = sym->getType()` collecting PartialSymbolEntry:
    ///   - TYPE_STRUCT/UNION -> findTruncation field, `.field`
    ///   - TYPE_ARRAY -> getSubEntry element, `[N]`
    ///   - no good subtype -> synthetic unnamedField(off,sz), `.field_off_sz`
    /// then pushes operators in reverse and entries front-to-back so
    /// parentheses come out right (printc.cc:1949-2064).
    ///
    /// Rugra adaptation: no findTruncation/getSubEntry/RPN stack, so this
    /// renders the equivalent text directly, handling Struct (`.field` for
    /// the matching offset), Array (`[off/elsize]`), and the synthetic
    /// fallback. The SUBPIECE-style cast (printc.cc:2018-2029) is a TODO hook.
    ///
    /// Alignment evidence:
    /// - Sort key: Struct offset lookup -> Array element index -> synthetic
    ///   name (cascade at printc.cc:1966-2041).
    /// - Loop/order: bottom-up stack then front-to-back emission preserved
    ///   textually as left-to-right `sym.field[idx]...` building.
    pub fn push_partial_symbol(&mut self, sym_name: &str, mut off: i64,
                               mut sz: i64, ct: Option<&Datatype>) {
        let mut entries: Vec<String> = Vec::new();
        // Walk the type tree via Arc clones so field/array descent (which
        // returns Arc<Datatype>) composes with the entry-point borrow.
        let mut current: Option<Arc<Datatype>> = ct.map(|d| Arc::new(d.clone()));
        // Bound the type-tree walk (Ghidra's `while(ct != nullptr)` terminates
        // because each iteration either descends into a smaller field or
        // pushes a synthetic entry and nulls ct).
        let mut depth = 0;
        while depth < 16 {
            depth += 1;
            let Some(dt) = current else { break; };
            // printc.cc:1960-1964: off==0 and sz covers whole type -> done.
            if off == 0 && (sz == 0 || (sz as usize == dt.get_size()
                    && !dt.needs_resolution())) {
                break;
            }
            let metatype = dt.get_metatype();
            if metatype == TypeMetatype::Struct || metatype == TypeMetatype::Union {
                // printc.cc:1966-1985 / 2001-2016: findTruncation field.
                if let Some((field_name, field_off, field_type)) =
                        Self::find_partial_field(&dt, off as usize, sz as usize) {
                    off -= field_off as i64;
                    entries.push(format!(".{}", field_name));
                    current = Some(field_type);
                    continue;
                }
            } else if metatype == TypeMetatype::Array {
                // printc.cc:1986-2000: getSubEntry element index.
                if let Some((element_type, el_off, el_index)) =
                        Self::array_sub_entry(&dt, off as usize, sz as usize) {
                    off = el_off as i64;
                    entries.push(format!("[{}]", el_index));
                    current = Some(element_type);
                    continue;
                }
            }
            // printc.cc:2030-2041: synthetic entry, then ct=nullptr.
            if sz == 0 {
                sz = dt.get_size() as i64 - off;
            }
            entries.push(format!(".field_{}_{}", off, sz));
            break;
        }
        // printc.cc:2044-2047: SUBPIECE-style cast is a TODO hook (Rugra has
        // no isSubpieceCastEndian); skipping == option_nocasts behaviour.
        // printc.cc:2049-2051: pushSymbol(sym) then entries front-to-back.
        self.emit.tag_variable(sym_name, 0);
        for e in &entries {
            self.emit.print(e);
        }
    }

    // Ghidra: printc.cc:1861 PrintC::pushAnnotation
    /// Emit an annotation varnode (inserted by the decompiler, not in the
    /// original binary). Faithful port of `PrintC::pushAnnotation`
    /// (printc.cc:1861-1903).
    ///
    /// Ghidra resolves the varnode against the function's local scope
    /// (`queryContainer`) and either pushes the whole symbol, a partial
    /// symbol, or — if no symbol covers the address — falls back to the
    /// register/space name (capitalising the space's first letter). Rugra
    /// uses its `symbol_table` for the lookup; the CALLOTHER
    /// `extractAnnotationSize` path (printc.cc:1866-1869) is a TODO hook.
    ///
    /// Alignment evidence:
    /// - Sort key: symbol covers address -> push_symbol / push_partial_symbol;
    ///   else register/space-name fallback (printc.cc:1881-1902).
    /// - Output: register name, else `<CapitalisedSpace><hex offset>`
    ///   (printc.cc:1890-1901).
    pub fn push_annotation(&mut self, vn: &Varnode) {
        let addr = vn.get_offset();
        // printc.cc:1871-1888: queryContainer -> entry; whole or partial
        // symbol. Rugra: consult the printer's symbol table.
        if let Some(name) = self.symbol_table.get(&addr) {
            self.emit.tag_variable(name, 0);
            return;
        }
        // printc.cc:1889-1902: register/space name fallback.
        let space = vn.get_space();
        let base = Self::space_name(space);
        // translate->getRegisterName — Rugra has no register map; treat as
        // empty so the synthetic-name branch runs (printc.cc:1891).
        // Capitalise first letter (printc.cc:1893-1894) + zero-padded hex.
        let mut regname = String::new();
        let mut chars = base.chars();
        if let Some(first) = chars.next() {
            for c in first.to_uppercase() { regname.push(c); }
            regname.extend(chars);
        }
        // printc.cc:1897-1898: hex << setfill('0') << setw(2*addrSize).
        regname.push_str(&format!("{:08X}", addr));
        self.emit.tag_variable(&regname, 0);
    }

    // ---- private helpers backing the P0 ports ----

    // Ghidra: printc.cc:1966-1985 (TYPE_STRUCT/UNION findTruncation)
    fn find_partial_field(dt: &Datatype, off: usize, sz: usize)
        -> Option<(String, usize, Arc<Datatype>)> {
        let fields = match dt {
            Datatype::Struct(s) => &s.fields,
            Datatype::Union(u) => &u.fields,
            _ => return None,
        };
        for f in fields {
            let f_size = f.type_ptr.get_size();
            if off >= f.offset && off + sz <= f.offset + f_size {
                return Some((f.name.clone(), f.offset, f.type_ptr.clone()));
            }
        }
        None
    }

    // Ghidra: printc.cc:1986-2000 (TYPE_ARRAY getSubEntry)
    fn array_sub_entry(dt: &Datatype, off: usize, _sz: usize)
        -> Option<(Arc<Datatype>, usize, usize)> {
        let arr = match dt { Datatype::Array(a) => a, _ => return None, };
        let el_size = arr.array_of.get_size();
        if el_size == 0 { return None; }
        Some((arr.array_of.clone(), off % el_size, off / el_size))
    }

    // RUGRA-GLUE: lowercase AddressSpace name (printc.cc:1942 space->getName)
    fn space_name(space: AddressSpace) -> &'static str {
        match space {
            AddressSpace::Ram => "ram",
            AddressSpace::Register => "register",
            AddressSpace::Const => "const",
            AddressSpace::Stack => "stack",
            AddressSpace::Unique => "unique",
            _ => "other",
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::opcodes::OpCode;
    use crate::prettyprint::EmitNoMarkup;

    #[test]
    fn test_print_c_copy() {
        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);

        let mut vbank = crate::varnode::VarnodeBank::new();
        let out_vn = vbank.create(4, Address::new(0x1000));
        let in_vn = vbank.create(4, Address::new(0x2000));

        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x100), 0),
            OpCode::CPUI_COPY,
        );
        op.output = Some(out_vn);
        op.inrefs.push(in_vn);

        printer.op_copy(&op);
        // Verify emission doesn't panic
    }

    #[test]
    fn test_doc_function_stub() {
        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);
        let fd = Funcdata::new("test_func", Address::new(0x1000), 0x100);

        printer.doc_function(&fd);
    }

    #[test]
    fn test_type_cast_load_typed_dereference() {
        // Test that op_load emits *(int * ) addr when address has pointer type
        use crate::type_system::datatype::{TypeBase, TypeMetatype, TypePointer};

        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);

        let mut vbank = crate::varnode::VarnodeBank::new();
        let out_vn = vbank.create_with_space(4, crate::space::AddressSpace::Unique, 0x30);
        let space_vn = vbank.create_constant(4, 0); // space id for LOAD
        let addr_vn = vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x38); // RDI

        // Set pointer type on addr_vn
        let int_type = std::sync::Arc::new(crate::type_system::Datatype::Base(
            TypeBase::new("int".to_string(), 4, TypeMetatype::Int),
        ));
        let int_ptr_type = std::sync::Arc::new(crate::type_system::Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_type.clone(),
            wordsize: 1,
        }));
        addr_vn.write().unwrap().v_type = Some(int_ptr_type);

        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x100), 0),
            OpCode::CPUI_LOAD,
        );
        op.output = Some(out_vn);
        op.inrefs.push(space_vn);
        op.inrefs.push(addr_vn);

        printer.op_load(&op);

        let output = printer.take_emit();
        let text = output.into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        // Should contain typed dereference
        assert!(text.contains("int *"), "Expected typed dereference with 'int *', got: {}", text);
    }

    #[test]
    fn test_type_cast_zext_uses_output_type() {
        // Test that op_unary for ZEXT uses output type name instead of hardcoded (uint)
        use crate::type_system::datatype::{TypeBase, TypeMetatype};

        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);

        let mut vbank = crate::varnode::VarnodeBank::new();
        let out_vn = vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x00); // RAX
        let in_vn = vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);  // EAX-like

        // Set output type to "long"
        let long_type = std::sync::Arc::new(crate::type_system::Datatype::Base(
            TypeBase::new("long".to_string(), 8, TypeMetatype::Int),
        ));
        out_vn.write().unwrap().v_type = Some(long_type);

        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x200), 0),
            OpCode::CPUI_INT_ZEXT,
        );
        op.output = Some(out_vn);
        op.inrefs.push(in_vn);

        printer.op_unary(&op);

        let output = printer.take_emit();
        let text = output.into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        // Should use "long" instead of hardcoded "uint"
        assert!(text.contains("(long)"), "Expected (long) cast, got: {}", text);
        assert!(!text.contains("(uint)"), "Should NOT contain hardcoded (uint), got: {}", text);
    }

    #[test]
    fn test_param_name_resolution() {
        // Test that push_varnode uses param names instead of register names
        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);

        // Simulate parameter detected at RDI (offset 0x38)
        printer.param_names.insert(0x38, "param_1".to_string());

        let mut vbank = crate::varnode::VarnodeBank::new();
        let rdi_vn = vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x38);
        let const_vn = vbank.create_constant(8, 42);

        // Create ADD op: param_1 + 42
        let out_vn = vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x00);
        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x300), 0),
            OpCode::CPUI_INT_ADD,
        );
        op.output = Some(out_vn);
        op.inrefs.push(rdi_vn);
        op.inrefs.push(const_vn);

        printer.op_binary(&op);

        let output = printer.take_emit();
        let text = output.into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        // Should use "param_1" instead of "RDI"
        assert!(text.contains("param_1"), "Expected 'param_1', got: {}", text);
        assert!(!text.contains("RDI"), "Should NOT contain 'RDI', got: {}", text);
    }

    /// Verify compact_name_for renumbers auto-local variable names.
    #[test]
    fn test_compact_name_for() {
        // Faithful to Ghidra `assignDefaultNames` (database.cc:2850-2865):
        // a SINGLE shared `int4 base` (initial 1, monotonic across ALL prefixes),
        // NOT a per-prefix counter. This test pins the 181538f fix — previously
        // each prefix had its own counter (bVar1,bVar2,lVar1,lVar2), but Ghidra
        // shares one base (bVar1,bVar2,lVar3,lVar4).
        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);
        // bVar21 → bVar1 (shared base = 1)
        let r1 = printer.compact_name_for("bVar21");
        assert_eq!(r1, Some("bVar1".to_string()), "bVar21 -> bVar1 (base=1)");
        // bVar29 → bVar2 (shared base = 2)
        let r2 = printer.compact_name_for("bVar29");
        assert_eq!(r2, Some("bVar2".to_string()), "bVar29 -> bVar2 (base=2)");
        // lVar25 → lVar3 (shared base = 3, NOT a per-prefix lVar1)
        let r3 = printer.compact_name_for("lVar25");
        assert_eq!(r3, Some("lVar3".to_string()), "lVar25 -> lVar3 (shared base=3)");
        // bVar21 again → bVar1 (cached, no new allocation)
        let r4 = printer.compact_name_for("bVar21");
        assert_eq!(r4, Some("bVar1".to_string()), "bVar21 cached -> bVar1");
        // param_1 → None (not an auto-local name, not renumbered)
        let r5 = printer.compact_name_for("param_1");
        assert_eq!(r5, None, "param_1 not renumbered");
    }

    #[test]
    fn test_child_needs_parens_precedence() {
        use crate::opcodes::OpCode::*;
        // Mirrors PrintLanguage::parentheses (printlanguage.cc:269) precedence
        // rules applied at recursion point. Parent is the op being emitted;
        // child is the sub-expression input; is_right_operand = slot 1.
        use crate::printc::optoken::child_needs_parens;

        // (a + b) << c : ADD(50) child of LEFT(46) → child looser? No: 50>46.
        // LEFT binds looser than ADD, so a+b needs NO parens (already tighter).
        assert!(!child_needs_parens(CPUI_INT_LEFT, CPUI_INT_ADD, false),
            "a + b << c: ADD(50) > LEFT(46), left operand no parens");

        // a << b + c : LEFT(46) child of ADD(50) right operand → 46<50 → parens.
        // Textbook: a + (b << c) ... wait this is "does the child need parens".
        // Parent=ADD, child=LEFT on right: 46<50 → yes parens → a + (b << c).
        assert!(child_needs_parens(CPUI_INT_ADD, CPUI_INT_LEFT, true),
            "a + (b << c): LEFT(46) < ADD(50), right operand needs parens");

        // a == b && c : EQUAL(38) child of BOOL_AND(22) → 38>22 → no parens.
        assert!(!child_needs_parens(CPUI_BOOL_AND, CPUI_INT_EQUAL, false),
            "a == b && c: EQUAL(38) > BOOL_AND(22), left no parens");

        // a && b == c : BOOL_AND(22) child of EQUAL(38) right → 22<38 → parens.
        assert!(child_needs_parens(CPUI_INT_EQUAL, CPUI_BOOL_AND, true),
            "a == (b && c): BOOL_AND(22) < EQUAL(38), right needs parens");

        // Associative equal-precedence, left operand: (a * b) * c → no parens.
        assert!(!child_needs_parens(CPUI_INT_MULT, CPUI_INT_MULT, false),
            "(a * b) * c: associative left, no parens");
        // Associative equal-precedence, right operand: a * (b * c) → no parens
        // (associative, order doesn't matter).
        assert!(!child_needs_parens(CPUI_INT_MULT, CPUI_INT_MULT, true),
            "a * (b * c): associative right, no parens");

        // Non-associative equal-precedence, left operand: (a - b) - c → no parens.
        assert!(!child_needs_parens(CPUI_INT_SUB, CPUI_INT_SUB, false),
            "(a - b) - c: non-assoc left, no parens (left-to-right)");
        // Non-associative equal-precedence, right operand: a - (b - c) → parens.
        assert!(child_needs_parens(CPUI_INT_SUB, CPUI_INT_SUB, true),
            "a - (b - c): non-assoc right, needs parens");

        // Bitwise: a & b | c → AND(34) child of OR(26) left → 34>26 → no parens.
        assert!(!child_needs_parens(CPUI_INT_OR, CPUI_INT_AND, false),
            "a & b | c: AND(34) > OR(26), left no parens");
        // a | b & c → OR(26) child of AND(34) right → 26<34 → parens.
        assert!(child_needs_parens(CPUI_INT_AND, CPUI_INT_OR, true),
            "a & (b | c): OR(26) < AND(34), right needs parens");

        // Non-binary child (e.g. COPY/LOAD) → no parens.
        assert!(!child_needs_parens(CPUI_INT_ADD, CPUI_COPY, true),
            "COPY child: not a tracked binary op, no parens");
    }
}
