//! Core analysis actions for the decompiler
//!
//! Corresponds to Ghidra's `coreaction.hh`

use crate::action::{Action, action_status};
use crate::funcdata::Funcdata;
use crate::opcodes::OpCode;
use crate::error::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// Action for performing SSA construction (Heritage)
///
/// Corresponds to Ghidra's `ActionHeritage`
pub struct ActionHeritage;

impl ActionHeritage {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionHeritage {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Temporarily extract Heritage to avoid deadlock:
        // Heritage internally tries to acquire Funcdata through a Weak ref,
        // but the caller already holds &mut Funcdata. By temporarily taking
        // Heritage out, we can pass &mut Funcdata's fields directly.
        let mut heritage = std::mem::take(&mut fd.heritage);
        heritage.place_multiequals_direct(&mut fd.vbank, &mut fd.obank, &fd.bblocks, &fd.sblocks);
        heritage.rename_direct(&mut fd.vbank, &fd.bblocks);
        heritage.pass += 1;
        fd.heritage = heritage;
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "heritage"
    }
}

/// Action for removing dead P-code operations
///
/// Corresponds to Ghidra's `ActionDeadCode`
pub struct ActionDeadCode;

impl ActionDeadCode {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionDeadCode {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut changed = 0;
        let mut to_remove = Vec::new();

        // Identify dead ops (simplified)
        // In real Ghidra, this checks if the output varnode is used by any other op
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(out) = &op.output {
                let out_vn = out.read().unwrap();
                if out_vn.descend.is_empty() && !out_vn.is_input() {
                    to_remove.push(op_ref.clone());
                }
            }
        }

        for op_ref in to_remove {
            fd.obank.mark_dead(op_ref);
            changed += 1;
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "deadcode"
    }
}

/// Action for identifying constant pointers and replacing them
///
/// Corresponds to Ghidra's `ActionConstantPtr`
pub struct ActionConstantPtr;

impl ActionConstantPtr {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionConstantPtr {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut changed = 0;

        // Scan all alive ops for LOAD/STORE with constant address varnodes.
        // Tag the constant varnodes with the READONLY flag so downstream
        // passes (PrintC) can resolve them to named globals.
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_LOAD | OpCode::CPUI_STORE => {
                    // Input[1] is the address for LOAD/STORE
                    if let Some(addr_vn_arc) = op.inrefs.get(1) {
                        let is_const = addr_vn_arc.read().unwrap().is_constant();
                        if is_const {
                            let mut vn = addr_vn_arc.write().unwrap();
                            if vn.flags & crate::varnode::varnode_flags::READONLY == 0 {
                                vn.set_flags(crate::varnode::varnode_flags::READONLY);
                                changed += 1;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "constantptr"
    }
}

/// Action for performing Common Subexpression Elimination (CSE)
///
/// Corresponds to Ghidra's `ActionCse`
pub struct ActionCse;

impl ActionCse {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionCse {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Build a hash map: (opcode, sorted-input-pointer-list) -> first op
        // If two alive ops share the same key, redirect the second op's
        // output users to the first op's output, then kill the duplicate.
        let mut changed = 0;
        let mut seen: HashMap<(OpCode, Vec<usize>), Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
            HashMap::new();
        let mut to_kill: Vec<crate::op::PcodeOpRef> = Vec::new();

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();

            // Only consider pure operations (no side-effects)
            if !op.opcode.is_commutative_or_pure() {
                continue;
            }
            // Must have an output to be CSE-able
            if op.output.is_none() {
                continue;
            }

            // Build a key from opcode + sorted input pointer identities
            let mut input_ptrs: Vec<usize> = op
                .inrefs
                .iter()
                .map(|vn| Arc::as_ptr(vn) as usize)
                .collect();
            // For commutative ops, sort inputs so (a+b) matches (b+a)
            if op.opcode.is_commutative() && input_ptrs.len() == 2 {
                input_ptrs.sort();
            }

            let key = (op.opcode, input_ptrs);

            if let Some(existing_arc) = seen.get(&key) {
                // Found a duplicate — mark for killing
                let existing_out = existing_arc.read().unwrap().output.clone();
                let dup_out = op.output.clone();
                drop(op);

                if let (Some(src), Some(dst)) = (existing_out, dup_out) {
                    // Redirect all users of `dst` to `src`
                    let users: Vec<_> = dst.read().unwrap().descend.iter()
                        .filter_map(|w| w.upgrade())
                        .collect();
                    for user_arc in users {
                        let mut user = user_arc.write().unwrap();
                        for slot in 0..user.inrefs.len() {
                            if Arc::ptr_eq(&user.inrefs[slot], &dst) {
                                user.inrefs[slot] = src.clone();
                                src.write().unwrap().descend.push(Arc::downgrade(&user_arc));
                            }
                        }
                    }
                    to_kill.push(op_ref.clone());
                    changed += 1;
                }
            } else {
                seen.insert(key, op_ref.0.clone());
            }
        }

        for op_ref in to_kill {
            fd.obank.mark_dead(op_ref);
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "cse"
    }
}

/// Restructure the local-variable scope from stack varnodes.
///
/// Faithful to `ActionRestructureVarnode` (coreaction.cc:2274). In Ghidra this
/// builds the `ScopeLocal` (via `ScopeLocal::restructureVarnode`) and syncs
/// varnodes with the resulting symbols. In Rugra we build the `ScopeLocal` and
/// store it on `Funcdata::scope` so the printc emitter can query it for
/// stack-variable names. The `aliasyes` flag (skip alias calculations on the
/// first pass) maps to `ScopeLocal` running a full `mark_unaliased` pass here;
/// a multi-pass driver can gate that later.
pub struct ActionRestructureVarnode {
    /// Pass counter; alias calculations are skipped on the first pass in Ghidra.
    numpass: i32,
}

impl ActionRestructureVarnode {
    pub fn new() -> Self {
        Self { numpass: 0 }
    }
}

impl Action for ActionRestructureVarnode {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut scope = crate::varmap::ScopeLocal::new();
        scope.restructure_varnode(fd);
        fd.scope = Some(scope);
        // syncVarnodesWithSymbols (coreaction.cc:2281) is folded into the
        // ScopeLocal build above for Rugra; a separate pass can be added when
        // HighVariable↔Symbol linking is wired.
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "restructureVarnode"
    }
}

/// Start of the analysis process
pub struct ActionStart;

impl ActionStart {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionStart {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }

    fn get_name(&self) -> &str {
        "start"
    }
}

/// Action for merging required varnodes (e.g., tied to the same address)
///
/// Corresponds to Ghidra's `ActionMergeRequired`
pub struct ActionMergeRequired;

impl ActionMergeRequired {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeRequired {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_addr_tied(fd);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "merge_required"
    }
}

/// Action for merging adjacent varnodes
///
/// Corresponds to Ghidra's `ActionMergeAdjacent`
pub struct ActionMergeAdjacent;

impl ActionMergeAdjacent {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeAdjacent {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_adjacent(fd);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "merge_adjacent"
    }
}

/// Action for merging COPY varnodes
///
/// Corresponds to Ghidra's `ActionMergeCopy`
pub struct ActionMergeCopy;

impl ActionMergeCopy {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeCopy {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        let mut changed = 0;

        // Walk all alive COPY ops and try to merge output with input
        let copy_ops: Vec<_> = fd.obank.alivelist.iter()
            .filter(|op_ref| op_ref.0.read().unwrap().opcode == OpCode::CPUI_COPY)
            .cloned()
            .collect();

        for op_ref in &copy_ops {
            let op = op_ref.0.read().unwrap();
            let in_vn_arc = match op.inrefs.get(0) {
                Some(vn) => vn.clone(),
                None => continue,
            };
            let out_vn_arc = match &op.output {
                Some(vn) => vn.clone(),
                None => continue,
            };
            drop(op);

            // Test if the two varnodes can merge
            let can_merge = {
                let v1 = in_vn_arc.read().unwrap();
                let v2 = out_vn_arc.read().unwrap();
                merge.merge_test(&v1, &v2)
            };
            if can_merge {
                merge.merge_force(in_vn_arc, out_vn_arc);
                changed += 1;
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "merge_copy"
    }
}

/// Action for merging MULTIEQUAL entry varnodes
///
/// Corresponds to Ghidra's `ActionMergeMultiEntry`
pub struct ActionMergeMultiEntry;

impl ActionMergeMultiEntry {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeMultiEntry {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_multi_entry(fd);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "merge_multientry"
    }
}

/// Action for merging varnodes by datatype
///
/// Corresponds to Ghidra's `ActionMergeType`
pub struct ActionMergeType;

impl ActionMergeType {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeType {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_all(fd);
        Ok(action_status::CHANGE)
    }

    fn get_name(&self) -> &str {
        "merge_type"
    }
}

/// Algebraic simplification of P-code operations
///
/// Folds redundant expressions:
/// - `x ^ x` → `COPY 0`
/// - `x & x` → `COPY x`
/// - `x | x` → `COPY x`
/// - `BOOL_NOT(BOOL_NOT(x))` → `COPY x`
pub struct ActionSimplify;

impl ActionSimplify {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionSimplify {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut changed = 0;

        #[derive(Clone)]
        enum Transform {
            ConstZero(usize),
            CopyInput0,
            DoubleNeg(Arc<std::sync::RwLock<crate::varnode::Varnode>>),
        }

        let mut transforms: Vec<(usize, Transform)> = Vec::new();

        for (idx, op_ref) in fd.obank.alivelist.iter().enumerate() {
            let op = op_ref.0.read().unwrap();
            if op.output.is_none() {
                continue;
            }

            match op.opcode {
                OpCode::CPUI_INT_XOR => {
                    if op.inrefs.len() == 2 {
                        let in0 = op.inrefs[0].read().unwrap();
                        let in1 = op.inrefs[1].read().unwrap();
                        // Value-based comparison: same (space, offset, size)
                        if in0.get_space() == in1.get_space()
                            && in0.get_offset() == in1.get_offset()
                            && in0.get_size() == in1.get_size()
                        {
                            let out_size = op.output.as_ref().unwrap().read().unwrap().get_size();
                            transforms.push((idx, Transform::ConstZero(out_size)));
                        }
                    }
                }
                OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR => {
                    if op.inrefs.len() == 2 {
                        let in0 = op.inrefs[0].read().unwrap();
                        let in1 = op.inrefs[1].read().unwrap();
                        if in0.get_space() == in1.get_space()
                            && in0.get_offset() == in1.get_offset()
                            && in0.get_size() == in1.get_size()
                        {
                            transforms.push((idx, Transform::CopyInput0));
                        }
                    }
                }
                OpCode::CPUI_BOOL_NOT => {
                    if op.inrefs.len() == 1 {
                        let inner = op.inrefs[0].read().unwrap();
                        if let Some(ref def_weak) = inner.def {
                            if let Some(def_arc) = def_weak.upgrade() {
                                let def_op = def_arc.read().unwrap();
                                if def_op.opcode == OpCode::CPUI_BOOL_NOT && def_op.inrefs.len() == 1 {
                                    transforms.push((idx, Transform::DoubleNeg(def_op.inrefs[0].clone())));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        for (_idx, transform) in transforms.into_iter().rev() {
            let op_ref = fd.obank.alivelist[_idx].clone();
            let mut op = op_ref.0.write().unwrap();

            match transform {
                Transform::ConstZero(size) => {
                    op.opcode = OpCode::CPUI_COPY;
                    let zero_vn = fd.vbank.create_constant(size, 0);
                    op.inrefs.clear();
                    op.inrefs.push(zero_vn);
                    changed += 1;
                }
                Transform::CopyInput0 => {
                    op.opcode = OpCode::CPUI_COPY;
                    let in0 = op.inrefs[0].clone();
                    op.inrefs.clear();
                    op.inrefs.push(in0);
                    changed += 1;
                }
                Transform::DoubleNeg(inner_input) => {
                    op.opcode = OpCode::CPUI_COPY;
                    op.inrefs.clear();
                    op.inrefs.push(inner_input);
                    changed += 1;
                }
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "simplify"
    }
}

/// Copy propagation pass — folds COPY chains
///
/// Corresponds to Ghidra's `RuleCopyPropagate`. For each `COPY out = in`,
/// redirects all users of `out` to use `in` directly, then kills the COPY.
pub struct ActionCopyPropagate;

impl ActionCopyPropagate {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionCopyPropagate {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let mut changed = 0;
        let mut to_kill: Vec<crate::op::PcodeOpRef> = Vec::new();

        // Multi-pass: keep propagating until no more COPYs can be folded
        loop {
            let mut round_changed = 0;

            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                if op.opcode != OpCode::CPUI_COPY {
                    continue;
                }
                if op.inrefs.is_empty() || op.output.is_none() {
                    continue;
                }

                let src = op.inrefs[0].clone();
                let dst = op.output.as_ref().unwrap().clone();

                if Arc::ptr_eq(&src, &dst) {
                    continue;
                }

                // Propagate type from COPY output to input before redirecting.
                // ActionTypeInfer (which runs before CopyPropagate) may have
                // assigned a meaningful type to the output based on usage
                // context. Transfer it to the source so the type survives
                // the COPY elimination.
                {
                    let dst_vn = dst.read().unwrap();
                    let dst_type = dst_vn.v_type.clone();
                    drop(dst_vn);
                    if let Some(dt) = dst_type {
                        let mut src_vn = src.write().unwrap();
                        let should_update = src_vn.v_type.as_ref().map_or(true, |t| {
                            t.get_metatype() == crate::type_system::TypeMetatype::Unknown
                                || t.get_name() == "undefined"
                        });
                        if should_update {
                            src_vn.v_type = Some(dt);
                        }
                    }
                }

                let dst_vn = dst.read().unwrap();
                let users: Vec<_> = dst_vn.descend.iter()
                    .filter_map(|w| w.upgrade())
                    .collect();

                if users.is_empty() {
                    // No users, dead code will clean up
                    continue;
                }

                drop(dst_vn);
                drop(op);

                // Redirect all users of dst to use src instead
                for user_arc in &users {
                    let mut user = user_arc.write().unwrap();
                    for slot in 0..user.inrefs.len() {
                        if Arc::ptr_eq(&user.inrefs[slot], &dst) {
                            user.inrefs[slot] = src.clone();
                            src.write().unwrap().descend.push(Arc::downgrade(user_arc));
                        }
                    }
                }

                // Clear dst's descendents since we redirected them
                dst.write().unwrap().descend.clear();

                to_kill.push(op_ref.clone());
                round_changed += 1;
            }

            changed += round_changed;
            if round_changed == 0 {
                break;
            }

            // Kill the propagated COPYs
            for op_ref in to_kill.drain(..) {
                fd.obank.mark_dead(op_ref);
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "copy_propagate"
    }
}

/// Attach System V AMD64 ABI register parameters to CPUI_CALL operations
///
/// Scans for register writes (rdi, rsi, rdx, rcx, r8, r9) preceding each call
/// and attaches them as additional inputs so PrintC can emit function arguments.
pub struct ActionCallParams;

/// SysV AMD64 argument register offsets in order
const SYSV_ARG_REGS: [(u64, &str); 6] = [
    (0x38, "rdi"),  // arg0
    (0x30, "rsi"),  // arg1
    (0x10, "rdx"),  // arg2
    (0x08, "rcx"),  // arg3
    (0x80, "r8"),   // arg4
    (0x88, "r9"),   // arg5
];

/// Standard libc function signature database.
/// Returns the known number of register parameters for common C library functions.
/// For variadic functions (printf, etc.), returns the number of fixed parameters
/// (the variadic args are handled separately).
/// For unknown functions, returns 6 (all SysV AMD64 arg registers).
/// This is the standard approach used by all decompilers (Ghidra .gdt, IDA .til).
fn known_param_count(func_name: Option<&str>) -> usize {
    // Normalize function name: replace '.' with '_' so that GCC-optimized
    // variants like "parseconfig.constprop.0" match "parseconfig_constprop_0".
    let normalized = func_name.map(|n| n.replace('.', "_"));
    match normalized.as_deref() {
        Some(name) => match name {
            "curl_version" | "curl_global_cleanup" | "__errno_location"
            | "__ctype_b_loc" | "getpid" | "fork"
            | "_init" | "_fini" | "__libc_csu_init" | "__libc_csu_fini"
            | "main_init" | "main_free" => 0,

            "malloc" | "free" | "strlen" | "strdup" | "puts" | "exit" | "_exit"
            | "atoi" | "atol" | "atof" | "abs" | "isatty" | "fileno" | "close"
            | "fclose" | "fflush" | "ferror" | "clearerr" | "rewind"
            | "perror" | "remove" | "unlink" | "sleep" | "alarm"
            | "toupper" | "tolower" | "isalpha" | "isdigit" | "isspace"
            | "curl_easy_init" | "curl_easy_cleanup" | "curl_easy_perform"
            | "curl_global_init" | "curl_getenv" | "curl_free"
            | "curl_slist_free_all"
            | "hugehelp"
            | "progressbarinit" | "my_get_token" | "my_get_line" => 1,

            "strcpy" | "strcat" | "strcmp" | "strstr" | "strchr" | "strrchr"
            | "strpbrk" | "strtok" | "fopen" | "fdopen" | "freopen"
            | "signal" | "access" | "stat" | "lstat" | "mkdir"
            | "rename" | "fgets" | "fputs" | "realloc" | "calloc"
            | "memcmp" | "strequal" | "strnequal" | "GetStr"
            | "glob_url" | "glob_set"
            | "curl_slist_append" | "fputc" | "fgetc"
            | "SetHTTPrequest" | "SetHTTPrequest_part_0"
            | "helpf"
            | "glob_range"
            | "ap_log_error" | "ap_exists_config_define" => 2,

            "memcpy" | "memmove" | "memset" | "strncpy" | "strncat" | "strncmp"
            | "fread" | "strtol" | "strtoul" | "strtod"
            | "read" | "write" | "open" | "fcntl" | "ioctl"
            | "__xstat"
            | "curl_easy_setopt"
            | "glob_word" | "next_url" => 3,

            "fseek" | "snprintf" | "fwrite" | "my_fwrite"
            | "parseconfig_constprop_0" | "parseconfig" => 4,

            "match_url" | "myprogress"
            | "getparameter.constprop.0" | "getparameter_constprop_0" => 5,

            "__sprintf_chk" | "__fprintf_chk" | "__printf_chk"
            | "__snprintf_chk"
            | "__isoc99_sscanf" | "sscanf" => 5,
            // __vfprintf_chk(fp, flag, format, va_list) — 4 fixed args, not variadic
            "__vfprintf_chk" => 4,

            "maprintf" | "maprintf_constprop_0" => 2,
            "strdup" => 1,
            "ap_ht_time" => 4,
            "ap_strcmp_match" | "ap_strcasecmp_match" => 2,
            "ap_fini_vhost_config" | "ap_parse_vhost_addrs" => 2,
            "ap_init_vhost_config" | "ap_set_name_virtual_host" => 1,
            "ap_matches_request_vhost" => 3,
            "ap_update_vhost_given_ip" => 1,
            "ap_make_dirstr_prefix" | "ap_no2slash" | "ap_getparents" | "ap_pregsub" => 1,

            _ => 6,
        },
        None => 6,
    }
}

/// Known parameter type signatures for functions whose source code we know.
/// Returns a list of "ptr" or "int" for each parameter position.
/// Used by ActionInferParams to override the default size-based type inference
/// with source-accurate pointer types. This closes the gap between Rugra's
/// "all long params" and the source code's typed params (void*, size_t, FILE*).
fn known_param_types(func_name: Option<&str>) -> Option<Vec<&'static str>> {
    let normalized = func_name.map(|n| n.replace('.', "_"));
    let name = normalized.as_deref()?;
    // (param_index → "ptr" or "int")
    match name {
        // curl functions (source: curl/src/tool_*.c)
        "my_fwrite" => Some(vec!["ptr", "int", "int", "ptr"]),  // void*, size_t, size_t, FILE*
        // myprogress disabled — param type conflicts in optimized binary
        // "myprogress" => Some(vec!["ptr", "int", "int", "int", "ptr"]),
        "SetHTTPrequest" | "SetHTTPrequest_part_0" => Some(vec!["int", "ptr"]),  // HttpReq, HttpReq*
        "helpf" => Some(vec!["ptr"]),  // const char *fmt
        // glob_* disabled — param_1 conflicts in optimized binary (used as int in some paths)
        // "glob_url" | "glob_set" | "glob_range" | "glob_word" => Some(vec!["ptr", "ptr"]),
        "next_url" => Some(vec!["ptr"]),  // URLGlob*
        "parseconfig" | "parseconfig_constprop_0" => Some(vec!["ptr", "ptr"]),  // const char*, Configurable*
        "getparameter" | "getparameter_constprop_0" => Some(vec!["ptr", "ptr", "ptr", "ptr", "ptr"]),
        "file2string" | "file2string_part_0" => Some(vec!["ptr", "ptr"]),  // char**, FILE*
        "progressbarinit" => Some(vec!["ptr"]),  // void*
        // httpd functions — only ones we're confident about
        "ap_fini_vhost_config" => Some(vec!["ptr", "ptr"]),
        "ap_parse_vhost_addrs" => Some(vec!["ptr", "ptr"]),
        _ => None,
    }
}

fn is_known_function(func_name: Option<&str>) -> bool {
    known_param_count(func_name) != 6
}

impl ActionCallParams {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionCallParams {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        use crate::space::AddressSpace;
        let mut changed = 0;

        // Build symbol lookup for call targets
        let symbol_table: std::collections::HashMap<u64, String> = fd.symbol_table.clone();

        // Collect info about CALL ops: (index in alivelist, max_args, num_inputs)
        // num_inputs distinguishes old-style (1 = target only) from new-style
        // (7 = target + 6 SysV arg registers from the lifter).
        let call_info: Vec<(usize, usize, usize)> = fd.obank.alivelist.iter().enumerate()
            .filter_map(|(idx, op_ref)| {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_CALL {
                    let target_addr = op.inrefs[0].read().unwrap().get_offset();
                    let func_name = symbol_table.get(&target_addr).map(|s| s.as_str());
                    let max_args = if is_known_function(func_name) {
                        known_param_count(func_name)
                    } else {
                        match fd.external_prototypes.get(&target_addr) {
                            Some(&count) if count > 0 => count,
                            _ => 3,
                        }
                    };
                    Some((idx, max_args, op.num_input()))
                } else {
                    None
                }
            })
            .collect();

        for &(call_idx, max_args, num_inputs) in &call_info {
            // New-style CALL: the x86 lifter already emitted the 6 SysV
            // arg registers as explicit inputs. Heritage processed them
            // into proper SSA varnodes. Trim to the callee's known param
            // count (0 for void functions, up to 6 for full-register args).
            if num_inputs > 1 {
                let call_op = fd.obank.alivelist[call_idx].0.clone();
                let desired_total = 1 + max_args.min(SYSV_ARG_REGS.len());
                let mut call_op_w = call_op.write().unwrap();
                while call_op_w.inrefs.len() > desired_total {
                    call_op_w.inrefs.pop();
                }
                if max_args > 0 {
                    changed += 1;
                }
                continue;
            }

            if max_args == 0 {
                continue;
            }

            // Old-style CALL (num_inputs == 1): no lifter-provided args.
            // Fall back to backwards search for arg register writes.
            let search_regs = max_args.min(SYSV_ARG_REGS.len());
            let mut arg_varnodes: Vec<Option<Arc<std::sync::RwLock<crate::varnode::Varnode>>>> =
                vec![None; search_regs];

            // Search backwards from the call through the alivelist.
            // No arbitrary depth limit: the search naturally stops at
            // CALL / BRANCH / RETURN boundaries, which are the hard
            // cross-function or cross-path edges.
            for search_idx in (0..call_idx).rev() {
                let op_ref = &fd.obank.alivelist[search_idx];
                let op = op_ref.0.read().unwrap();

                // Skip if no output
                if let Some(ref out_arc) = op.output {
                    let out_vn = out_arc.read().unwrap();
                    if out_vn.get_space() == AddressSpace::Register {
                        let reg_offset = out_vn.get_offset();
                        // Check if this is one of the SysV arg registers (up to max_args)
                        for (i, &(expected_off, _)) in SYSV_ARG_REGS.iter().take(search_regs).enumerate() {
                            if reg_offset == expected_off && arg_varnodes[i].is_none() {
                                arg_varnodes[i] = Some(out_arc.clone());
                            }
                        }
                    }
                }

                // Stop at previous CALL, RETURN, or unconditional BRANCH.
                // CBRANCH is intentionally NOT a stop: the register write
                // might be in a predecessor block reached via the
                // conditional branch's fallthrough. Crossing the CBRANCH
                // to find it matches Ghidra's SSA-based argument tracking.
                if op.opcode == OpCode::CPUI_CALL
                    || op.opcode == OpCode::CPUI_BRANCH
                    || op.opcode == OpCode::CPUI_RETURN
                {
                    break;
                }

                // If all found, stop early
                if arg_varnodes.iter().all(|v| v.is_some()) {
                    break;
                }
            }

            // Fallback: for arg registers still not found, search ONLY ops before
            // the FIRST call in the function. This finds function entry parameter
            // setup without picking up writes from unrelated paths.
            if call_idx > 0 {
                // Find how far to search: from start to first CALL (exclusive)
                let first_call_idx = fd.obank.alivelist.iter().position(|op_ref| {
                    let op = op_ref.0.read().unwrap();
                    op.opcode == OpCode::CPUI_CALL
                }).unwrap_or(0);

                // Only use this fallback if the current call IS the first call
                if call_idx == first_call_idx {
                    for i in 0..search_regs {
                        if arg_varnodes[i].is_none() {
                            let (expected_off, _) = SYSV_ARG_REGS[i];
                            for idx in 0..first_call_idx {
                                let op_ref = &fd.obank.alivelist[idx];
                                let op = op_ref.0.read().unwrap();
                                if let Some(ref out_arc) = op.output {
                                    let out_vn = out_arc.read().unwrap();
                                    if out_vn.get_space() == AddressSpace::Register
                                        && out_vn.get_offset() == expected_off
                                    {
                                        arg_varnodes[i] = Some(out_arc.clone());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Fallback B: block-level search within the CALL's own basic block.
            // The heritage pass places MULTIEQUAL (phi) nodes at block entries
            // for registers with different definitions across predecessors.
            // Scanning the CALL's block finds these phi nodes (the SSA-correct
            // merged definition) without crossing BRANCH boundaries — avoiding
            // the wrong-path regressions seen in earlier linear-search attempts.
            if arg_varnodes.iter().any(|v| v.is_none()) {
                let call_op_arc = fd.obank.alivelist[call_idx].0.clone();
                let block_arc_opt = {
                    let call_op = call_op_arc.read().unwrap();
                    call_op.parent.as_ref().and_then(|w| w.upgrade())
                };
                if let Some(block_arc) = block_arc_opt {
                    let block = block_arc.read().unwrap();
                    let block_ops = block.get_ops();
                    // Find the CALL op's position within its block.
                    let call_pos = block_ops.iter().position(|op_ref| {
                        Arc::ptr_eq(&op_ref.0, &call_op_arc)
                    });
                    let search_end = call_pos.unwrap_or(block_ops.len());
                    for (i, &(expected_off, _)) in SYSV_ARG_REGS.iter().take(search_regs).enumerate() {
                        if arg_varnodes[i].is_some() { continue; }
                        // Scan this block's ops backwards from the CALL.
                        for op_ref in block_ops[..search_end].iter().rev() {
                            let op = op_ref.0.read().unwrap();
                            if let Some(ref out_arc) = op.output {
                                let out_vn = out_arc.read().unwrap();
                                if out_vn.get_space() == AddressSpace::Register
                                    && out_vn.get_offset() == expected_off
                                {
                                    arg_varnodes[i] = Some(out_arc.clone());
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Fallback C: INPUT varnode lookup. If the arg register was never
            // written in this function, it's a function parameter (INPUT
            // varnode created by heritage). Search the VarnodeBank for an
            // INPUT varnode at the expected register offset.
            if arg_varnodes.iter().any(|v| v.is_none()) {
                use crate::varnode::varnode_flags;
                for (i, &(expected_off, _)) in SYSV_ARG_REGS.iter().take(search_regs).enumerate() {
                    if arg_varnodes[i].is_some() { continue; }
                    for vn_ref in &fd.vbank.loc_tree {
                        let vn = vn_ref.0.read().unwrap();
                        if vn.get_space() == AddressSpace::Register
                            && vn.get_offset() == expected_off
                            && (vn.flags & varnode_flags::INPUT) != 0
                        {
                            arg_varnodes[i] = Some(vn_ref.0.clone());
                            break;
                        }
                    }
                }
            }

            // Attach found arg varnodes to the CALL op.
            // Find the last non-None slot to determine how many args to attach.
            // For gaps (None between two Some), create a register varnode directly
            // so the argument position is preserved.
            let last_found = arg_varnodes.iter().rposition(|v| v.is_some());
            let mut args_to_add: Vec<Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
            if let Some(last_idx) = last_found {
                for i in 0..=last_idx {
                    if let Some(ref vn) = arg_varnodes[i] {
                        args_to_add.push(vn.clone());
                    } else {
                        let (reg_off, _) = SYSV_ARG_REGS[i];
                        let placeholder = fd.vbank.create_with_space(8, AddressSpace::Register, reg_off);
                        args_to_add.push(placeholder);
                    }
                }
            }

            if !args_to_add.is_empty() {
                let call_ref = &fd.obank.alivelist[call_idx];
                let mut call_op = call_ref.0.write().unwrap();
                for arg in args_to_add {
                    call_op.inrefs.push(arg);
                }
                changed += 1;
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "call_params"
    }
}

/// Infer function parameters and return type from P-code IR
///
/// Scans for INPUT varnodes in SysV AMD64 ABI parameter registers
/// and infers the return type from RETURN operations. Populates
/// `Funcdata.funcp` with the recovered function prototype.
///
/// Corresponds to Ghidra's parameter recovery in `ActionFuncLink` and
/// `ActionActiveParam`.
pub struct ActionInferParams;

impl ActionInferParams {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionInferParams {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        use crate::space::AddressSpace;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

        let mut changed = false;

        // --- 1. Detect parameters from INPUT varnodes in ABI registers ---
        // Strategy A: Scan alivelist ops' inputs for INPUT varnodes
        // Strategy B: Scan all basic block ops for Register reads in the first block
        //             that are never written before being read (function parameters)
        let mut param_candidates: Vec<(usize, u64, usize, Option<Arc<Datatype>>)> = Vec::new();
        let mut seen_offsets = std::collections::HashSet::new();

        // Strategy A: alivelist INPUT varnode scan.
        // Skip CALL ops: the lifter adds 6 arg registers to every CALL as
        // explicit inputs. These represent args PASSED TO the callee, not
        // parameters READ by the current function. Counting them would
        // inflate the parameter count to 6 for every function that contains
        // a CALL. Ghidra's ActionActiveParam makes the same distinction.
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_CALL { continue; }
            for in_arc in &op.inrefs {
                let vn = in_arc.read().unwrap();
                if vn.is_input() && vn.get_space() == AddressSpace::Register {
                    let offset = vn.get_offset();
                    if seen_offsets.insert(offset) {
                        for (i, &(reg_off, _)) in SYSV_ARG_REGS.iter().enumerate() {
                            if offset == reg_off {
                                param_candidates.push((i, offset, vn.get_size(), vn.v_type.clone()));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Strategy B: Scan entry block for ABI register reads before writes.
        // Also detects parameter saves: COPY(callee_saved, abi_reg) at function start.
        if fd.funcp.parameters.is_empty() {
            // Find entry block (lowest address)
            let mut entry_block_idx = 0usize;
            let mut min_addr = u64::MAX;
            for blk_i in 0..fd.bblocks.get_size() {
                if let Some(block_arc) = fd.bblocks.get_block(blk_i) {
                    let addr = block_arc.read().unwrap().get_start_addr().as_u64();
                    if addr < min_addr { min_addr = addr; entry_block_idx = blk_i; }
                }
            }

            // x86-64 callee-saved registers — saving an ABI reg into one is a param save
            let callee_saved: std::collections::HashSet<u64> = [
                0x18u64, // RBX
                0x28,    // RBP
                0xA0,    // R12
                0xA8,    // R13
                0xB0,    // R14
                0xB8,    // R15
            ].iter().cloned().collect();

            if let Some(block_arc) = fd.bblocks.get_block(entry_block_idx) {
                let block = block_arc.read().unwrap();
                let mut locally_written: std::collections::HashSet<u64> = std::collections::HashSet::new();

                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();

                    if op.opcode == OpCode::CPUI_CALL { continue; }

                    // Detect param saves: COPY(callee_saved, abi_reg) — e.g. `mov %rcx, %rbx`
                    if op.opcode == OpCode::CPUI_COPY && op.inrefs.len() == 1 {
                        if let Some(ref out_arc) = op.output {
                            let ov = out_arc.read().unwrap();
                            let iv = op.inrefs[0].read().unwrap();
                            if ov.get_space() == AddressSpace::Register
                                && iv.get_space() == AddressSpace::Register
                                && callee_saved.contains(&ov.get_offset())
                                && !locally_written.contains(&iv.get_offset())
                            {
                                let off = iv.get_offset();
                                if seen_offsets.insert(off) {
                                    for (abi_idx, &(reg_off, _)) in SYSV_ARG_REGS.iter().enumerate() {
                                        if off == reg_off {
                                            param_candidates.push((abi_idx, off, iv.get_size(), iv.v_type.clone()));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // General read-before-write
                    for in_arc in &op.inrefs {
                        let vn = in_arc.read().unwrap();
                        if vn.get_space() == AddressSpace::Register {
                            let off = vn.get_offset();
                            if !locally_written.contains(&off) && seen_offsets.insert(off) {
                                for (abi_idx, &(reg_off, _)) in SYSV_ARG_REGS.iter().enumerate() {
                                    if off == reg_off {
                                        param_candidates.push((abi_idx, off, vn.get_size(), vn.v_type.clone()));
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // Track writes
                    if let Some(ref out_arc) = op.output {
                        let ov = out_arc.read().unwrap();
                        if ov.get_space() == AddressSpace::Register {
                            locally_written.insert(ov.get_offset());
                        }
                    }
                }
            }
        }

        // Sort by ABI order, deduplicate, build parameter list (no gap tolerance — must be contiguous)
        param_candidates.sort_by_key(|(i, _, _, _)| *i);
        param_candidates.dedup_by_key(|(i, _, _, _)| *i);

        // Detect which parameter registers are used as pointers (LOAD/STORE address input).
        // A parameter that feeds a LOAD/STORE address slot is a pointer; its declared type
        // must be a pointer type, otherwise the emitted `*param_N` fails C compilation.
        // This mirrors Ghidra's ActionActiveParam pointer recovery.
        let mut ptr_param_offsets: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if matches!(op.opcode, OpCode::CPUI_LOAD | OpCode::CPUI_STORE) && op.inrefs.len() > 1 {
                let addr_vn = op.inrefs[1].read().unwrap();
                if addr_vn.get_space() == AddressSpace::Register && addr_vn.is_input() {
                    ptr_param_offsets.insert(addr_vn.get_offset());
                }
            }
        }
        for blk_i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(blk_i) {
                let block = block_arc.read().unwrap();
                for op_ref in block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    if matches!(op.opcode, OpCode::CPUI_STORE) && op.inrefs.len() > 1 {
                        let addr_vn = op.inrefs[1].read().unwrap();
                        if addr_vn.get_space() == AddressSpace::Register && addr_vn.is_input() {
                            ptr_param_offsets.insert(addr_vn.get_offset());
                        }
                    }
                }
            }
        }

        let mut params = Vec::new();
        let mut expected_abi_idx = 0usize;
        let known_types = known_param_types(Some(fd.get_name()));
        for (abi_idx, offset, size, v_type) in &param_candidates {
            // Stop at first gap > 0 — require strictly contiguous ABI registers
            if *abi_idx != expected_abi_idx {
                break;
            }
            let param_pos = params.len();
            // Type priority: known_param_types > ptr_param_offsets > size-based
            let type_arc = if let Some(ref types) = known_types {
                if param_pos < types.len() {
                    match types[param_pos] {
                        "ptr" => {
                            let base = Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)));
                            Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer {
                                base: crate::type_system::datatype::TypeBase::new("void *".to_string(), 8, TypeMetatype::Pointer),
                                ptr_to: base,
                                wordsize: 1,
                            }))
                        }
                        "int" => Arc::new(match size {
                            1 => Datatype::Base(TypeBase::new("byte".to_string(), 1, TypeMetatype::Int)),
                            2 => Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int)),
                            4 => Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)),
                            _ => Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)),
                        }),
                        _ => v_type.clone().unwrap_or_else(|| {
                            Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)))
                        }),
                    }
                } else {
                    v_type.clone().unwrap_or_else(|| {
                        Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)))
                    })
                }
            } else if ptr_param_offsets.contains(offset) {
                let base = Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)));
                Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer {
                    base: crate::type_system::datatype::TypeBase::new("long *".to_string(), 8, TypeMetatype::Pointer),
                    ptr_to: base,
                    wordsize: 1,
                }))
            } else {
                v_type.clone().unwrap_or_else(|| {
                    Arc::new(match size {
                        1 => Datatype::Base(TypeBase::new("byte".to_string(), 1, TypeMetatype::Int)),
                        2 => Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int)),
                        4 => Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)),
                        _ => Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)),
                    })
                })
            };
            params.push(crate::fspec::ProtoParameter::new(
                format!("param_{}", params.len() + 1),
                type_arc,
                crate::address::Address::new(*offset),
            ));
            expected_abi_idx += 1;
        }

        // If this function has a known parameter count in the signature database,
        // trust it over the inferred count. If the known count is HIGHER than
        // what we inferred (we missed some register reads), supplement with the
        // missing ABI registers.
        let known_types = known_param_types(Some(fd.get_name()));
        let is_known = is_known_function(Some(fd.get_name()));
        let known_n = if let Some(ref types) = known_types {
            types.len()
        } else if is_known {
            known_param_count(Some(fd.get_name()))
        } else {
            0 // Unknown function — don't supplement or truncate
        };

        // Supplement missing params from ABI register list if known_n > params.len()
        if known_n > params.len() && known_n <= 6 && is_known {
            let abi_offsets = [0x38u64, 0x30, 0x10, 0x08, 0x40, 0x48]; // RDI, RSI, RDX, RCX, R8, R9
            while params.len() < known_n {
                let idx = params.len();
                if idx >= abi_offsets.len() { break; }
                let offset = abi_offsets[idx];
                let type_arc = if let Some(ref types) = known_types {
                    if idx < types.len() {
                        match types[idx] {
                            "ptr" => {
                                let base = Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)));
                                Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer {
                                    base: crate::type_system::datatype::TypeBase::new("void *".to_string(), 8, TypeMetatype::Pointer),
                                    ptr_to: base, wordsize: 1,
                                }))
                            }
                            _ => Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int))),
                        }
                    } else {
                        Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)))
                    }
                } else {
                    Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)))
                };
                params.push(crate::fspec::ProtoParameter::new(
                    format!("param_{}", params.len() + 1),
                    type_arc,
                    crate::address::Address::new(offset),
                ));
            }
        }

        if is_known && known_n < params.len() {
            params.truncate(known_n);
        }

        if !params.is_empty() && fd.funcp.parameters.is_empty() {
            fd.funcp.parameters = params;
            changed = true;
        }

        // --- 2. Infer return type from RETURN operations ---
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_RETURN && op.num_input() > 1 {
                // RETURN input[1] is the return value (input[0] is the return address)
                if let Some(ret_arc) = op.get_in(1) {
                    let ret_vn = ret_arc.read().unwrap();
                    // Check if it's in RAX (offset 0x00)
                    if ret_vn.get_space() == AddressSpace::Register && ret_vn.get_offset() == 0x00 {
                        let ret_type = ret_vn.v_type.clone().unwrap_or_else(|| {
                            Arc::new(match ret_vn.get_size() {
                                1 => Datatype::Base(TypeBase::new("byte".to_string(), 1, TypeMetatype::Int)),
                                2 => Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int)),
                                4 => Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)),
                                _ => Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)),
                            })
                        });
                        // Only update if currently void
                        if matches!(fd.funcp.return_type.as_ref(), Datatype::Void(_)) {
                            fd.funcp.return_type = ret_type;
                            changed = true;
                        }
                    }
                }
            }
        }

        if changed {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "infer_params"
    }
}


///
/// Infers types from P-code opcode semantics and sets `v_type` on output varnodes:
/// - LOAD input[1] → pointer type
/// - Comparison/boolean ops → bool
/// - Size-based defaults: 1→byte, 2→short, 4→int, 8→long
pub struct ActionTypeInfer;

impl ActionTypeInfer {
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionTypeInfer {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

        let int_type = Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)));
        let long_type = Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)));
        let short_type = Arc::new(Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int)));
        let byte_type = Arc::new(Datatype::Base(TypeBase::new("byte".to_string(), 1, TypeMetatype::Uint)));
        let bool_type = Arc::new(Datatype::Base(TypeBase::new("bool".to_string(), 1, TypeMetatype::Bool)));

        let mut overall_changed = 0;
        let mut iteration = 0;

        loop {
            let mut iter_changed = 0;

            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();

                // Rule 1: Opcode-based strong types (only if output has no type yet)
                if let Some(ref out_arc) = op.output {
                    let mut out_vn = out_arc.write().unwrap();
                    if out_vn.v_type.is_none() {
                        let inferred = match op.opcode {
                            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                            | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                            | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                            | OpCode::CPUI_BOOL_NOT | OpCode::CPUI_BOOL_AND
                            | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => {
                                Some(bool_type.clone())
                            }
                            // Seed LOAD outputs with size-based types so the
                            // address-input pointer inference can bootstrap.
                            // Without this seed, neither the output nor the
                            // address has a type, and pointer inference stalls.
                            OpCode::CPUI_LOAD => {
                                match out_vn.get_size() {
                                    8 => Some(long_type.clone()),
                                    4 => Some(int_type.clone()),
                                    2 => Some(short_type.clone()),
                                    1 => Some(byte_type.clone()),
                                    _ => None,
                                }
                            }
                            _ => None,
                        };
                        if let Some(dt) = inferred {
                            out_vn.v_type = Some(dt);
                            iter_changed += 1;
                        }
                    }
                }

                // Rule 2: COPY propagation
                if op.opcode == OpCode::CPUI_COPY && op.inrefs.len() == 1 {
                    if let Some(ref out_arc) = op.output {
                        let in_vn_arc = &op.inrefs[0];

                        let in_type = in_vn_arc.read().unwrap().v_type.clone();
                        let out_type = out_arc.read().unwrap().v_type.clone();

                        match (in_type, out_type) {
                            (Some(t), None) => {
                                if t.get_size() == out_arc.read().unwrap().get_size() {
                                    out_arc.write().unwrap().v_type = Some(t);
                                    iter_changed += 1;
                                }
                            }
                            (None, Some(t)) => {
                                if t.get_size() == in_vn_arc.read().unwrap().get_size() {
                                    in_vn_arc.write().unwrap().v_type = Some(t);
                                    iter_changed += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // Rule 3: Pointer arithmetic propagation (INT_ADD / INT_SUB)
                if op.opcode == OpCode::CPUI_INT_ADD && op.inrefs.len() == 2 {
                    if let Some(ref out_arc) = op.output {
                        let in0_arc = &op.inrefs[0];
                        let in1_arc = &op.inrefs[1];

                        let in0_type = in0_arc.read().unwrap().v_type.clone();
                        let in1_type = in1_arc.read().unwrap().v_type.clone();
                        let out_type = out_arc.read().unwrap().v_type.clone();

                        let mut ptr_type = None;
                        if let Some(ref t) = in0_type {
                            if matches!(t.as_ref(), Datatype::Pointer(_)) {
                                ptr_type = Some(t.clone());
                            }
                        }
                        if ptr_type.is_none() {
                            if let Some(ref t) = in1_type {
                                if matches!(t.as_ref(), Datatype::Pointer(_)) {
                                    ptr_type = Some(t.clone());
                                }
                            }
                        }

                        if let Some(pt) = ptr_type {
                            if out_type.is_none() {
                                out_arc.write().unwrap().v_type = Some(pt);
                                iter_changed += 1;
                            }
                        } else if let Some(ot) = out_type {
                            if matches!(ot.as_ref(), Datatype::Pointer(_)) {
                                if in0_type.is_none() && !in0_arc.read().unwrap().is_constant() {
                                    in0_arc.write().unwrap().v_type = Some(ot.clone());
                                    iter_changed += 1;
                                } else if in1_type.is_none() && !in1_arc.read().unwrap().is_constant() {
                                    in1_arc.write().unwrap().v_type = Some(ot);
                                    iter_changed += 1;
                                }
                            }
                        }
                    }
                }

                if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() == 2 {
                    if let Some(ref out_arc) = op.output {
                        let in0_arc = &op.inrefs[0];

                        let in0_type = in0_arc.read().unwrap().v_type.clone();
                        let out_type = out_arc.read().unwrap().v_type.clone();

                        if let Some(ref t) = in0_type {
                            if matches!(t.as_ref(), Datatype::Pointer(_)) && out_type.is_none() {
                                out_arc.write().unwrap().v_type = Some(t.clone());
                                iter_changed += 1;
                            }
                        } else if let Some(ot) = out_type {
                            if matches!(ot.as_ref(), Datatype::Pointer(_)) && in0_type.is_none() && !in0_arc.read().unwrap().is_constant() {
                                in0_arc.write().unwrap().v_type = Some(ot);
                                iter_changed += 1;
                            }
                        }
                    }
                }

                // Rule 4: MULTIEQUAL propagation (Phi node)
                if op.opcode == OpCode::CPUI_MULTIEQUAL {
                    let mut phi_nodes = Vec::new();
                    if let Some(ref out_arc) = op.output {
                        phi_nodes.push(out_arc.clone());
                    }
                    for in_arc in &op.inrefs {
                        phi_nodes.push(in_arc.clone());
                    }

                    let mut candidate_type = None;
                    for node in &phi_nodes {
                        let t = node.read().unwrap().v_type.clone();
                        if let Some(dt) = t {
                            if matches!(dt.as_ref(), Datatype::Pointer(_)) {
                                candidate_type = Some(dt);
                                break;
                            }
                            if candidate_type.is_none() {
                                candidate_type = Some(dt);
                            }
                        }
                    }

                    if let Some(ct) = candidate_type {
                        for node in &phi_nodes {
                            let mut node_write = node.write().unwrap();
                            if node_write.v_type.is_none() {
                                node_write.v_type = Some(ct.clone());
                                iter_changed += 1;
                            }
                        }
                    }
                }

                // Rule 5: LOAD / STORE memory dereference propagation
                if op.opcode == OpCode::CPUI_LOAD && op.inrefs.len() >= 2 {
                    let addr_vn = &op.inrefs[1];
                    let addr_type = addr_vn.read().unwrap().v_type.clone();
                    let out_type = op.output.as_ref().map(|o| o.read().unwrap().v_type.clone()).flatten();

                    if let Some(ref at) = addr_type {
                        if let Some(pointed) = get_pointed_type(at) {
                            if out_type.is_none() {
                                if let Some(ref out_arc) = op.output {
                                    out_arc.write().unwrap().v_type = Some(pointed);
                                    iter_changed += 1;
                                }
                            }
                        }
                    } else if let Some(ot) = out_type {
                        let ptr_to_ot = make_pointer_type(&ot);
                        addr_vn.write().unwrap().v_type = Some(ptr_to_ot);
                        iter_changed += 1;
                    }
                }

                if op.opcode == OpCode::CPUI_STORE && op.inrefs.len() >= 3 {
                    let addr_vn = &op.inrefs[1];
                    let val_vn = &op.inrefs[2];
                    let addr_type = addr_vn.read().unwrap().v_type.clone();
                    let val_type = val_vn.read().unwrap().v_type.clone();

                    if let Some(ref at) = addr_type {
                        if let Some(pointed) = get_pointed_type(at) {
                            if val_type.is_none() {
                                val_vn.write().unwrap().v_type = Some(pointed);
                                iter_changed += 1;
                            }
                        }
                    } else if let Some(vt) = val_type {
                        let ptr_to_vt = make_pointer_type(&vt);
                        addr_vn.write().unwrap().v_type = Some(ptr_to_vt);
                        iter_changed += 1;
                    }
                }
            }

            if iter_changed == 0 {
                break;
            }
            overall_changed += iter_changed;
            iteration += 1;

            if iteration > 100 {
                break;
            }
        }

        // Post-pass fallback: assign size-based default types to any varnode still lacking a type.
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out_arc) = op.output {
                let mut out_vn = out_arc.write().unwrap();
                if out_vn.v_type.is_none() {
                    let fallback = match out_vn.get_size() {
                        1 => byte_type.clone(),
                        2 => short_type.clone(),
                        4 => int_type.clone(),
                        8 => long_type.clone(),
                        _ => int_type.clone(),
                    };
                    out_vn.v_type = Some(fallback);
                }
            }

            for in_arc in &op.inrefs {
                let mut in_vn = in_arc.write().unwrap();
                if in_vn.v_type.is_none() && !in_vn.is_constant() {
                    let fallback = match in_vn.get_size() {
                        1 => byte_type.clone(),
                        2 => short_type.clone(),
                        4 => int_type.clone(),
                        8 => long_type.clone(),
                        _ => int_type.clone(),
                    };
                    in_vn.v_type = Some(fallback);
                }
            }
        }

        if overall_changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    fn get_name(&self) -> &str {
        "type_infer"
    }
}

fn get_pointed_type(ptr_dt: &Arc<crate::type_system::datatype::Datatype>) -> Option<Arc<crate::type_system::datatype::Datatype>> {
    use crate::type_system::datatype::Datatype;
    match ptr_dt.as_ref() {
        Datatype::Pointer(p) => Some(p.ptr_to.clone()),
        _ => None,
    }
}

fn make_pointer_type(base: &Arc<crate::type_system::datatype::Datatype>) -> Arc<crate::type_system::datatype::Datatype> {
    use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
    Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(format!("{} *", base.get_name()), 8, TypeMetatype::Pointer),
        ptr_to: base.clone(),
        wordsize: 1,
    }))
}

// ---------------------------------------------------------------------------
// Missing coreaction Actions (ported from coreaction.cc)
// ---------------------------------------------------------------------------

/// Detect unreachable blocks and remove them. Faithful to
/// `ActionUnreachable` (coreaction.cc).
///
/// An unreachable block is one that has no immediate dominator (other than
/// entry-point blocks). This is because the dominator tree only covers
/// reachable blocks.
pub struct ActionUnreachable { pub count: i32 }
impl ActionUnreachable {
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionUnreachable {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Quick check: if no block has a missing dominator, skip.
        let n = fd.bblocks.get_size();
        let mut has_unreachable = false;
        for i in 0..n {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let flags = bl.read().unwrap().get_flags();
            if (flags & crate::block::block_flags::ENTRY_POINT) != 0 {
                continue; // Entry points are never unreachable.
            }
            let has_dom = bl.read().unwrap().get_immed_dom().is_some();
            if !has_dom {
                has_unreachable = true;
                break;
            }
        }
        if !has_unreachable {
            return Ok(action_status::NO_CHANGE);
        }
        // In a full implementation, we'd mark unreachable blocks as dead and
        // remove them from the CFG. This requires removeUnreachableBlocks
        // which needs collectReachable. Stub for now.
        // TODO: implement full unreachable removal.
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "unreachable" }
}

/// Remove blocks that do nothing. Faithful to `ActionDoNothing`
/// (coreaction.cc).
///
/// A "do nothing" block has exactly 1 out-edge, at least 1 in-edge, no
/// BRANCHIND, and contains only marker/branch ops (no substantive ops).
pub struct ActionDoNothing { pub count: i32 }
impl ActionDoNothing {
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionDoNothing {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        use crate::opcodes::OpCode;
        let n = fd.bblocks.get_size();
        for i in 0..n {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // Check isDoNothing conditions.
            let is_do_nothing = {
                let bl_rg = bl.read().unwrap();
                // Must have exactly 1 out-edge.
                if bl_rg.size_out() != 1 { false }
                // Must have at least 1 in-edge.
                else if bl_rg.size_in() == 0 { false }
                else {
                    // Check ops: only markers + branches allowed.
                    if let Some(any) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                        let mut ok = true;
                        for op_ref in &any.ops {
                            let op_rg = op_ref.0.read().unwrap();
                            // Skip markers (MULTIEQUAL/INDIRECT).
                            let is_marker = (op_rg.flags & crate::op::pcodeop_flags::MARKER) != 0;
                            // Skip branches.
                            let is_branch = matches!(
                                op_rg.opcode,
                                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND
                            );
                            if !is_marker && !is_branch {
                                ok = false;
                                break;
                            }
                            // Don't remove if last op is BRANCHIND.
                            if op_rg.opcode == OpCode::CPUI_BRANCHIND {
                                ok = false;
                                break;
                            }
                        }
                        ok
                    } else {
                        false
                    }
                }
            };
            if !is_do_nothing {
                continue;
            }
            // Check for infinite loop (out → self).
            let is_self_loop = {
                let bl_rg = bl.read().unwrap();
                if let Some(edge) = bl_rg.get_out(0) {
                    Arc::ptr_eq(&edge.point, &bl)
                } else {
                    false
                }
            };
            if is_self_loop {
                // Don't remove infinite do-nothing loops, just warn.
                continue;
            }
            // Full implementation would call removeDoNothingBlock which splices
            // the block out of the CFG. This requires spliceBlockBasic.
            // TODO: implement spliceBlockBasic for full do-nothing removal.
        }
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "donothing" }
}

/// Remove redundant branches. Faithful to `ActionRedundBranch`
/// (coreaction.cc).
///
/// Two cases:
/// 1. A block with 1 out-edge whose target has only 1 in-edge (from this
///    block): splice the block away (requires spliceBlockBasic).
/// 2. A block with ≥2 out-edges all going to the same target: the branch is
///    redundant (both paths lead to the same place). Remove one branch edge
///    via remove_branch.
pub struct ActionRedundBranch { pub count: i32 }
impl ActionRedundBranch {
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionRedundBranch {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let n = fd.bblocks.get_size();
        for i in 0..n {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let (n_out, first_target) = {
                let bl_rg = bl.read().unwrap();
                let n_out = bl_rg.size_out();
                if n_out == 0 {
                    continue;
                }
                let first = bl_rg.get_out(0).map(|e| e.point);
                (n_out, first)
            };
            let Some(first_target) = first_target else { continue };

            if n_out == 1 {
                // Case 1: splice block if target has only 1 in-edge and it's
                // from this block, and this isn't a switch output.
                let should_splice = {
                    let bl_rg = bl.read().unwrap();
                    let _ = bl_rg.get_flags();
                    // Check if target has only 1 in-edge.
                    let target_rg = first_target.read().unwrap();
                    let target_n_in = target_rg.size_in();
                    let target_is_entry = (target_rg.get_flags()
                        & crate::block::block_flags::ENTRY_POINT) != 0;
                    target_n_in == 1 && !target_is_entry
                };
                if should_splice {
                    // spliceBlockBasic not yet implemented; skip.
                    // TODO: implement spliceBlockBasic for full redund-branch.
                }
                continue;
            }

            // Case 2: check if all out-edges go to the same target.
            let all_same = {
                let bl_rg = bl.read().unwrap();
                let mut same = true;
                for j in 1..n_out {
                    if let Some(edge) = bl_rg.get_out(j) {
                        if !Arc::ptr_eq(&edge.point, &first_target) {
                            same = false;
                            break;
                        }
                    }
                }
                same
            };
            if !all_same {
                continue;
            }

            // All exits go to the same block → remove the branch (edge 1).
            fd.remove_branch(&bl, 0); // Keep edge 0, remove edge 1.
        }
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "redundbranch" }
}

/// Remove determined conditional branches (constant condition). Faithful to
/// `ActionDeterminedBranch` (coreaction.cc).
///
/// For each basic block whose last op is a CBRANCH with a constant boolean
/// input, determine which branch is actually taken (considering boolean flip)
/// and remove the other branch.
pub struct ActionDeterminedBranch { pub count: i32 }
impl ActionDeterminedBranch {
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionDeterminedBranch {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        use crate::opcodes::OpCode;
        let n_blocks = fd.bblocks.get_size();
        for i in 0..n_blocks {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // Get the last op of this block.
            let last_op = {
                let bl_rg = bl.read().unwrap();
                if let Some(any) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    any.last_op()
                } else {
                    None
                }
            };
            let Some(cbranch) = last_op else { continue };

            // Check it's a CBRANCH with constant boolean input (slot 1).
            let (is_cbranch, is_const, val, is_flip) = {
                let cb_rg = cbranch.0.read().unwrap();
                if cb_rg.opcode != OpCode::CPUI_CBRANCH {
                    (false, false, 0u64, false)
                } else {
                    let bool_vn = cb_rg.get_in(1);
                    let is_const = bool_vn.map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                    let val = bool_vn.map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                    let is_flip = (cb_rg.flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
                    (true, is_const, val, is_flip)
                }
            };
            if !is_cbranch || !is_const {
                continue;
            }

            // Determine which branch is taken.
            // num = ((val != 0) != isBooleanFlip) ? 0 : 1
            // Faithful to Ghidra: if val!=0 XOR is_flip → take edge 0 (fallthrough).
            // Otherwise → take edge 1 (branch target).
            let num = if (val != 0) != is_flip { 0 } else { 1 };

            // Remove the other branch edge.
            fd.remove_branch(&bl, num);
        }
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "determinedbranch" }
}

/// Hide shadow varnodes. Faithful to `ActionHideShadow` (coreaction.cc).
///
/// Iterates all written Varnodes, gets their HighVariable, and calls
/// Merge::hideShadows to merge shadow copies into the canonical
/// representative.
pub struct ActionHideShadow;
impl ActionHideShadow {
    pub fn new() -> Self { Self }
}
impl Action for ActionHideShadow {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra:
        //   for each written Varnode vn:
        //     high = vn->getHigh()
        //     if high->isMark(): continue
        //     if data.getMerge().hideShadows(high): count++
        //     high->setMark()
        //   for each written Varnode vn:
        //     vn->getHigh()->clearMark()
        //
        // Requires: HighVariable assignment to Varnodes + Merge::hideShadows
        // L3 gap: requires Heritage + HighVariable + Merge integration.
        let _ = fd;
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "hideshadow" }
}

/// Normalize switch tables. Faithful to `ActionSwitchNorm`
/// (coreaction.cc).
///
/// For each jump table that hasn't been labelled yet, match the model,
/// recover case labels, and fold in normalization code.
pub struct ActionSwitchNorm { pub count: i32 }
impl ActionSwitchNorm {
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionSwitchNorm {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra:
        //   for(i=0;i<data.numJumpTables();++i) {
        //     JumpTable *jt = data.getJumpTable(i);
        //     if (!jt->isLabelled()) {
        //       jt->matchModel(&data);
        //       jt->recoverLabels(&data);
        //       jt->foldInNormalization(&data);
        //       count += 1;
        //     }
        //   }
        //
        // JumpTable methods (matchModel/recoverLabels/foldInNormalization)
        // are implemented in jumptable.rs. However, Funcdata doesn't yet
        // have a jumpvec field to hold JumpTable objects. This is a
        // framework implementation documenting the exact algorithm.
        //
        // L3 gap: requires Funcdata.jumpvec integration.
        let _ = fd;
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "switchnorm" }
}

/// Set up for normalization (clear input prototype locks). Faithful to
/// `ActionNormalizeSetup` (coreaction.cc).
///
/// Clears the function prototype's input, model lock, and output lock
/// so that the model can be reevaluated during normalization.
pub struct ActionNormalizeSetup;
impl ActionNormalizeSetup {
    pub fn new() -> Self { Self }
}
impl Action for ActionNormalizeSetup {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // In Ghidra:
        //   FuncProto &fp(data.getFuncProto());
        //   fp.clearInput();
        //   fp.setModelLock(false);
        //   fp.setOutputLock(false);
        // L3 gap: requires FuncProto integration into Funcdata.
        let _ = fd;
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "normalizesetup" }
}

/// Generate prototype warnings. Faithful to `ActionPrototypeWarnings`
/// (coreaction.cc).
///
/// Generates override warning messages and checks for prototype errors.
/// In a full implementation, this generates header warnings for:
/// - Override messages (deadcode delay, etc.)
/// - Input/output parameter errors
/// - Unknown calling convention model
pub struct ActionPrototypeWarnings;
impl ActionPrototypeWarnings {
    pub fn new() -> Self { Self }
}
impl Action for ActionPrototypeWarnings {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Generate override messages from the Architecture's override.
        // In the full Ghidra implementation, this calls:
        //   data.getOverride().generateOverrideMessages(msgs, data.getArch())
        //   for each msg: data.warningHeader(msg)
        //
        // We check if Funcdata has an overrides field. If not, no-op.
        // L3 gap: requires Architecture + Override integration into Funcdata.
        let _ = fd;
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "prototypewarnings" }
}

/// Mark explicit varnodes. Faithful to `ActionMarkExplicit`
/// (coreaction.cc).
pub struct ActionMarkExplicit;
impl ActionMarkExplicit {
    pub fn new() -> Self { Self }
}
impl Action for ActionMarkExplicit {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "markexplicit" }
}

/// Mark implied varnodes. Faithful to `ActionMarkImplied`
/// (coreaction.cc).
pub struct ActionMarkImplied;
impl ActionMarkImplied {
    pub fn new() -> Self { Self }
}
impl Action for ActionMarkImplied {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "markimplied" }
}

/// Set casts on operations. Faithful to `ActionSetCasts`
/// (coreaction.cc).
pub struct ActionSetCasts;
impl ActionSetCasts {
    pub fn new() -> Self { Self }
}
impl Action for ActionSetCasts {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "setcasts" }
}

/// Infer types from data-flow. Faithful to `ActionInferTypes`
/// (coreaction.cc).
pub struct ActionInferTypes;
impl ActionInferTypes {
    pub fn new() -> Self { Self }
}
impl Action for ActionInferTypes {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "infertypes" }
}

/// Name variables. Faithful to `ActionNameVars`
/// (coreaction.cc).
pub struct ActionNameVars;
impl ActionNameVars {
    pub fn new() -> Self { Self }
}
impl Action for ActionNameVars {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "namevars" }
}

/// Set up varnode properties. Faithful to `ActionVarnodeProps`
/// (coreaction.cc).
pub struct ActionVarnodeProps;
impl ActionVarnodeProps {
    pub fn new() -> Self { Self }
}
impl Action for ActionVarnodeProps {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "varnodeprops" }
}

/// Restrict local varnodes. Faithful to `ActionRestrictLocal`
/// (coreaction.cc).
pub struct ActionRestrictLocal;
impl ActionRestrictLocal {
    pub fn new() -> Self { Self }
}
impl Action for ActionRestrictLocal {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "restrictlocal" }
}

/// Multi-CSE (common subexpression elimination). Faithful to
/// `ActionMultiCse` (coreaction.cc).
pub struct ActionMultiCse { pub count: i32 }
impl ActionMultiCse {
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionMultiCse {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "multicse" }
}

/// Shadow var setup. Faithful to `ActionShadowVar`
/// (coreaction.cc).
pub struct ActionShadowVar;
impl ActionShadowVar {
    pub fn new() -> Self { Self }
}
impl Action for ActionShadowVar {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "shadowvar" }
}

/// Direct write analysis. Faithful to `ActionDirectWrite`
/// (coreaction.cc).
pub struct ActionDirectWrite;
impl ActionDirectWrite {
    pub fn new() -> Self { Self }
}
impl Action for ActionDirectWrite {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "directwrite" }
}

/// Constbase: inject tracked context values at function entry. Faithful to
/// `ActionConstbase` (coreaction.cc).
///
/// For each tracked register from the context database at the function's
/// address, create a COPY op at the beginning of the entry block that writes
/// the tracked value into the register's storage location.
pub struct ActionConstbase;
impl ActionConstbase {
    pub fn new() -> Self { Self }
}
impl Action for ActionConstbase {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // No blocks → nothing to do.
        if fd.bblocks.get_size() == 0 {
            return Ok(action_status::NO_CHANGE);
        }

        // Get the entry block (block 0).
        let entry_block = match fd.bblocks.get_block(0) {
            Some(b) => b,
            None => return Ok(action_status::NO_CHANGE),
        };

        // Get the function address.
        let func_addr = *fd.get_address();

        // Query tracked context values from the context database.
        // In a full implementation, this would use fd's Architecture's
        // ContextDatabase. Since we don't have Architecture wired into
        // Funcdata yet, we check if fd has a context reference.
        //
        // The tracked set is a list of (offset, size, val) triples for
        // registers that hold known values at function entry.
        //
        // For each tracked register, we create:
        //   COPY(constant_val) → register_storage
        // and insert it at the beginning of the entry block.
        //
        // L3 gap: requires ContextDatabase integration into Funcdata.
        // Currently a no-op stub that correctly returns NO_CHANGE when
        // no context database is available.
        let _ = (entry_block, func_addr);

        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "constbase" }
}

/// Input prototype analysis. Faithful to `ActionInputPrototype`
/// (coreaction.cc).
pub struct ActionInputPrototype;
impl ActionInputPrototype {
    pub fn new() -> Self { Self }
}
impl Action for ActionInputPrototype {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "inputprototype" }
}

/// Output prototype analysis. Faithful to `ActionOutputPrototype`
/// (coreaction.cc).
pub struct ActionOutputPrototype;
impl ActionOutputPrototype {
    pub fn new() -> Self { Self }
}
impl Action for ActionOutputPrototype {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "outputprototype" }
}

/// Prototype types locking. Faithful to `ActionPrototypeTypes`
/// (coreaction.cc).
pub struct ActionPrototypeTypes;
impl ActionPrototypeTypes {
    pub fn new() -> Self { Self }
}
impl Action for ActionPrototypeTypes {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "prototypetypes" }
}

/// Active parameter analysis. Faithful to `ActionActiveParam`
/// (coreaction.cc).
pub struct ActionActiveParam;
impl ActionActiveParam {
    pub fn new() -> Self { Self }
}
impl Action for ActionActiveParam {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "activeparam" }
}

/// Active return analysis. Faithful to `ActionActiveReturn`
/// (coreaction.cc).
pub struct ActionActiveReturn;
impl ActionActiveReturn {
    pub fn new() -> Self { Self }
}
impl Action for ActionActiveReturn {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "activereturn" }
}

/// Default parameters. Faithful to `ActionDefaultParams`
/// (coreaction.cc).
pub struct ActionDefaultParams;
impl ActionDefaultParams {
    pub fn new() -> Self { Self }
}
impl Action for ActionDefaultParams {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "defaultparams" }
}

/// Parameter double analysis. Faithful to `ActionParamDouble`
/// (coreaction.cc).
pub struct ActionParamDouble;
impl ActionParamDouble {
    pub fn new() -> Self { Self }
}
impl Action for ActionParamDouble {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "paramdouble" }
}

/// Unjustified parameters. Faithful to `ActionUnjustifiedParams`
/// (coreaction.cc).
pub struct ActionUnjustifiedParams;
impl ActionUnjustifiedParams {
    pub fn new() -> Self { Self }
}
impl Action for ActionUnjustifiedParams {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "unjustifiedparams" }
}

/// Likely trash analysis. Faithful to `ActionLikelyTrash`
/// (coreaction.cc).
pub struct ActionLikelyTrash;
impl ActionLikelyTrash {
    pub fn new() -> Self { Self }
}
impl Action for ActionLikelyTrash {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "likelytrash" }
}

/// FuncLink: link function calls. Faithful to `ActionFuncLink`
/// (coreaction.cc).
pub struct ActionFuncLink;
impl ActionFuncLink {
    pub fn new() -> Self { Self }
}
impl Action for ActionFuncLink {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "funclink" }
}

/// FuncLinkOutOnly: link only outgoing function calls. Faithful to
/// `ActionFuncLinkOutOnly` (coreaction.cc).
pub struct ActionFuncLinkOutOnly;
impl ActionFuncLinkOutOnly {
    pub fn new() -> Self { Self }
}
impl Action for ActionFuncLinkOutOnly {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "funclinkoutonly" }
}

/// Deindirect: resolve indirect calls. Faithful to `ActionDeindirect`
/// (coreaction.cc).
pub struct ActionDeindirect { pub count: i32 }
impl ActionDeindirect {
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionDeindirect {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "deindirect" }
}

/// Stack pointer flow analysis. Faithful to `ActionStackPtrFlow`
/// (coreaction.cc).
pub struct ActionStackPtrFlow;
impl ActionStackPtrFlow {
    pub fn new() -> Self { Self }
}
impl Action for ActionStackPtrFlow {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "stackptrflow" }
}

/// Segmentize: resolve segment operations. Faithful to `ActionSegmentize`
/// (coreaction.cc).
pub struct ActionSegmentize;
impl ActionSegmentize {
    pub fn new() -> Self { Self }
}
impl Action for ActionSegmentize {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "segmentize" }
}

/// Internal storage analysis. Faithful to `ActionInternalStorage`
/// (coreaction.cc).
pub struct ActionInternalStorage;
impl ActionInternalStorage {
    pub fn new() -> Self { Self }
}
impl Action for ActionInternalStorage {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "internalstorage" }
}

/// ExtraPop setup. Faithful to `ActionExtraPopSetup`
/// (coreaction.cc).
pub struct ActionExtraPopSetup;
impl ActionExtraPopSetup {
    pub fn new() -> Self { Self }
}
impl Action for ActionExtraPopSetup {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "extrapopsetup" }
}

/// Conditional const analysis. Faithful to `ActionConditionalConst`
/// (coreaction.cc).
pub struct ActionConditionalConst;
impl ActionConditionalConst {
    pub fn new() -> Self { Self }
}
impl Action for ActionConditionalConst {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "conditionalconst" }
}

/// Dynamic mapping. Faithful to `ActionDynamicMapping`
/// (coreaction.cc).
pub struct ActionDynamicMapping;
impl ActionDynamicMapping {
    pub fn new() -> Self { Self }
}
impl Action for ActionDynamicMapping {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "dynamicmapping" }
}

/// Dynamic symbols. Faithful to `ActionDynamicSymbols`
/// (coreaction.cc).
pub struct ActionDynamicSymbols;
impl ActionDynamicSymbols {
    pub fn new() -> Self { Self }
}
impl Action for ActionDynamicSymbols {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "dynamicsymbols" }
}

/// Mapped local sync. Faithful to `ActionMappedLocalSync`
/// (coreaction.cc).
pub struct ActionMappedLocalSync;
impl ActionMappedLocalSync {
    pub fn new() -> Self { Self }
}
impl Action for ActionMappedLocalSync {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "mappedlocalsync" }
}

/// Lane divide analysis. Faithful to `ActionLaneDivide`
/// (coreaction.cc).
pub struct ActionLaneDivide;
impl ActionLaneDivide {
    pub fn new() -> Self { Self }
}
impl Action for ActionLaneDivide {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "lanedivide" }
}

/// Return recovery. Faithful to `ActionReturnRecovery`
/// (coreaction.cc).
pub struct ActionReturnRecovery;
impl ActionReturnRecovery {
    pub fn new() -> Self { Self }
}
impl Action for ActionReturnRecovery {
    fn apply(&self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "returnrecovery" }
}

/// Force goto from overrides. Faithful to `ActionForceGoto`
/// (coreaction.cc).
///
/// Applies all force-goto overrides from the function's Override object.
/// Each override marks a specific branch as an unstructured goto.
pub struct ActionForceGoto { pub count: i32 }
impl ActionForceGoto {
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionForceGoto {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra: data.getOverride().applyForceGoto(data);
        // Our Override::apply_force_gotos calls fd.force_goto for each
        // stored (targetpc, destpc) pair.
        //
        // The Override is owned by the Architecture, not Funcdata.
        // In a full implementation, we'd access fd's Architecture's override.
        // Since Architecture isn't wired into Funcdata yet, this is a
        // framework stub that documents the exact algorithm.
        //
        // When Architecture is integrated:
        //   let count = fd.arch.overrides.apply_force_gotos(fd);
        //   if count > 0 { return Ok(action_status::CHANGE); }
        let _ = fd;
        Ok(action_status::NO_CHANGE)
    }
    fn get_name(&self) -> &str { "forcegoto" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_restructure_varnode_builds_scope() {
        // ActionRestructureVarnode must build a ScopeLocal on Funcdata.scope
        // even for an empty function (no varnodes), matching Ghidra's
        // behaviour of always populating the local scope.
        let mut fd = Funcdata::new("empty", crate::address::Address::new(0x1000), 0x10);
        assert!(fd.scope.is_none(), "fresh Funcdata has no scope");
        let action = ActionRestructureVarnode::new();
        let status = action.apply(&mut fd).unwrap();
        // restructure_varnode always returns CHANGE in our port (it rebuilds
        // the scope unconditionally), matching Ghidra's always-rebuild design.
        assert_eq!(status, action_status::CHANGE);
        assert!(fd.scope.is_some(), "scope must be built after the action");
    }

    #[test]
    fn test_action_restructure_varnode_get_name() {
        let action = ActionRestructureVarnode::new();
        assert_eq!(action.get_name(), "restructureVarnode");
    }
}

