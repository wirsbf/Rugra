//! End-to-end decompilation demo for the curl binary — ALL functions
//! Run with: cargo run --example curl_decompile

use goblin::Object;
use iced_x86::{Decoder as IcedDecoder, DecoderOptions, FlowControl, OpKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::panic::{self, AssertUnwindSafe};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use rugra::action::ActionDatabase;
use rugra::address::Address;
use rugra::debugproto::{DebugGlobalDatabase, DebugPrototypeDatabase};
use rugra::disasm::sleigh_lift::SleighLifter;
use rugra::disasm::{Disassembler, X86Lifter, X86_64Disassembler};
use rugra::funcdata::Funcdata;
use rugra::override_rs::{FlowOverride, FlowOverrideRecord};
use rugra::prettyprint::EmitPrettyPrint;
use rugra::printc::PrintC;
use rugra::printlanguage::PrintLanguage;

/// The locked 12.0.4 golden corpus for the curl fixture: every function the
/// canonical Ghidra analyzeHeadless run decompiled
/// (`tests/golden/ghidra_curl_1204.provenance.json` ledger, 124 entries,
/// oracle commit e40ed13014025f82488b1f8f7bca566894ac376b). Offsets are the
/// ledger's Ghidra addresses rebased by the analyzeHeadless image base
/// 0x100000 to match this PIE's ELF-relative virtual addresses, which is the
/// same normalization `tools/compare_ghidra.py` applies when matching.
///
/// Ghidra discovered these via its loader/PLT/external analyzers; Rugra has
/// no function-discovery layer yet, so the driver takes the corpus list from
/// the locked ledger (FULL-CORPUS-0001). ELF symbols still win for naming and
/// sizing wherever they exist at the same address.
const GOLDEN_CORPUS_LEDGER: [(u64, &str, u32); 124] = [
    (0x2000, "_init", 27u32),
    (0x2020, "FUN_00102020", 13u32),
    (0x22e0, "__cxa_finalize", 11u32),
    (0x22f0, "free", 11u32),
    (0x2300, "__vfprintf_chk", 11u32),
    (0x2310, "strcpy", 11u32),
    (0x2320, "puts", 11u32),
    (0x2330, "isatty", 11u32),
    (0x2340, "curl_easy_perform", 11u32),
    (0x2350, "curl_slist_append", 11u32),
    (0x2360, "fclose", 11u32),
    (0x2370, "strlen", 11u32),
    (0x2380, "__stack_chk_fail", 11u32),
    (0x2390, "strchr", 11u32),
    (0x23a0, "strrchr", 11u32),
    (0x23b0, "maprintf", 11u32),
    (0x23c0, "fputc", 11u32),
    (0x23d0, "fgets", 11u32),
    (0x23e0, "strtol", 11u32),
    (0x23f0, "memcpy", 11u32),
    (0x2400, "time", 11u32),
    (0x2410, "fileno", 11u32),
    (0x2420, "__xstat", 11u32),
    (0x2430, "malloc", 11u32),
    (0x2440, "__isoc99_sscanf", 11u32),
    (0x2450, "curl_easy_init", 11u32),
    (0x2460, "curl_getenv", 11u32),
    (0x2470, "realloc", 11u32),
    (0x2480, "__printf_chk", 11u32),
    (0x2490, "curl_version", 11u32),
    (0x24a0, "curl_slist_free_all", 11u32),
    (0x24b0, "fopen", 11u32),
    (0x24c0, "strcat", 11u32),
    (0x24d0, "curl_easy_setopt", 11u32),
    (0x24e0, "curl_getdate", 11u32),
    (0x24f0, "exit", 11u32),
    (0x2500, "fwrite", 11u32),
    (0x2510, "__fprintf_chk", 11u32),
    (0x2520, "curl_easy_cleanup", 11u32),
    (0x2530, "strdup", 11u32),
    (0x2540, "strequal", 11u32),
    (0x2550, "curl_formparse", 11u32),
    (0x2560, "strstr", 11u32),
    (0x2570, "strnequal", 11u32),
    (0x2580, "__ctype_b_loc", 11u32),
    (0x2590, "__sprintf_chk", 11u32),
    (0x25a0, "main", 3510u32),
    (0x3370, "_start", 47u32),
    (0x33a0, "deregister_tm_clones", 34u32),
    (0x33d0, "register_tm_clones", 51u32),
    (0x3410, "__do_global_dtors_aux", 54u32),
    (0x3450, "frame_dummy", 9u32),
    (0x3460, "my_fwrite", 92u32),
    (0x34d0, "myprogress", 477u32),
    (0x36d0, "GetStr", 68u32),
    (0x3720, "my_get_token", 241u32),
    (0x3840, "my_get_line", 308u32),
    (0x3980, "helpf", 267u32),
    (0x3a90, "file2string", 403u32),
    (0x3c50, "SetHTTPrequest", 43u32),
    (0x3c80, "parseconfig", 633u32),
    (0x3f00, "getparameter", 2609u32),
    (0x4960, "main_init", 7u32),
    (0x4970, "main_free", 5u32),
    (0x4980, "SetHTTPrequest", 24u32),
    (0x49a0, "progressbarinit", 90u32),
    (0x4a00, "hugehelp", 84u32),
    (0x4a60, "glob_word", 323u32),
    (0x4bc0, "glob_set", 400u32),
    (0x4d60, "glob_range", 503u32),
    (0x4f70, "glob_url", 116u32),
    (0x4ff0, "next_url", 502u32),
    (0x5220, "match_url", 443u32),
    (0x5400, "__libc_csu_init", 101u32),
    (0x5470, "__libc_csu_fini", 5u32),
    (0x5478, "_fini", 13u32),
    (0x19000, "free", 1u32),
    (0x19008, "__vfprintf_chk", 1u32),
    (0x19010, "_ITM_deregisterTMCloneTable", 1u32),
    (0x19018, "strcpy", 1u32),
    (0x19020, "puts", 1u32),
    (0x19028, "isatty", 1u32),
    (0x19030, "curl_easy_perform", 1u32),
    (0x19038, "curl_slist_append", 1u32),
    (0x19040, "fclose", 1u32),
    (0x19048, "strlen", 1u32),
    (0x19050, "__stack_chk_fail", 1u32),
    (0x19058, "strchr", 1u32),
    (0x19060, "strrchr", 1u32),
    (0x19068, "maprintf", 1u32),
    (0x19070, "fputc", 1u32),
    (0x19078, "__libc_start_main", 1u32),
    (0x19080, "fgets", 1u32),
    (0x19088, "__gmon_start__", 1u32),
    (0x19090, "strtol", 1u32),
    (0x19098, "memcpy", 1u32),
    (0x190a0, "time", 1u32),
    (0x190a8, "fileno", 1u32),
    (0x190b0, "__xstat", 1u32),
    (0x190b8, "malloc", 1u32),
    (0x190c0, "__isoc99_sscanf", 1u32),
    (0x190c8, "curl_easy_init", 1u32),
    (0x190d0, "curl_getenv", 1u32),
    (0x190d8, "realloc", 1u32),
    (0x190e0, "__printf_chk", 1u32),
    (0x190e8, "curl_version", 1u32),
    (0x190f0, "curl_slist_free_all", 1u32),
    (0x190f8, "fopen", 1u32),
    (0x19100, "strcat", 1u32),
    (0x19108, "curl_easy_setopt", 1u32),
    (0x19110, "curl_getdate", 1u32),
    (0x19118, "exit", 1u32),
    (0x19120, "fwrite", 1u32),
    (0x19128, "__fprintf_chk", 1u32),
    (0x19130, "_ITM_registerTMCloneTable", 1u32),
    (0x19138, "curl_easy_cleanup", 1u32),
    (0x19140, "strdup", 1u32),
    (0x19148, "strequal", 1u32),
    (0x19150, "curl_formparse", 1u32),
    (0x19158, "strstr", 1u32),
    (0x19160, "strnequal", 1u32),
    (0x19168, "__ctype_b_loc", 1u32),
    (0x19170, "__sprintf_chk", 1u32),
    (0x19178, "__cxa_finalize", 1u32),
];

/// Where a driver function entry came from. `ElfSymbol` entries carry a
/// full ELF symbol (address+size+name) and the worker re-validates it;
/// `LedgerEntry` entries (PLT stubs, `_init`/`_fini`, zero-sized symtab
/// functions, EXTERNAL-space entries) come from the locked golden ledger
/// and have no validating ELF symbol, so the worker validates them through
/// the section/file-offset checks instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FunctionOrigin {
    ElfSymbol,
    LedgerEntry,
}

/// Information about one function in the ELF
struct FuncInfo {
    vaddr: u64,
    size: usize,
    file_offset: u64,
    name: String,
    origin: FunctionOrigin,
}

// RUGRA-GLUE: copies immutable function coordinates into the worker protocol.
fn worker_target(func: &FuncInfo) -> WorkerTarget {
    WorkerTarget {
        vaddr: func.vaddr,
        size: func.size,
        file_offset: func.file_offset,
        name: func.name.clone(),
        symbol_backed: func.origin == FunctionOrigin::ElfSymbol,
    }
}

/// Produce the unique-ELF-owner, direct-known-entry portion of Ghidra's
/// Shared Return Calls Program metadata from the standalone front-end. The locked Java
/// producer (`SharedReturnAnalysisCmd.processFunctionJumpReferences`,
/// lines 376-425) starts with jump references to known function entries,
/// rejects conditional/multi-flow/thunk/self-entry cases, and emits
/// CALL_RETURN for the remaining instruction. A standalone ELF has no
/// pre-existing Program overrides; conflict-preserving merge is enforced at
/// the worker ingress below.
///
/// Rugra's standalone projection supplies these facts without a Program
/// database: STT_FUNC symbols define function entries/bodies, PLT relocation
/// entries extend the function-entry set, and iced-x86 supplies one direct
/// memory-flow reference for each direct branch instruction. The analyzer's
/// separate contiguous-function discovery, ownerless sources, discontiguous
/// bodies, and Program-added multi-flow references are deliberately not
/// inferred here.
// RUGRA-GLUE: standalone Program-metadata producer for the curl driver; the mapped producer is Java SharedReturnAnalysisCmd, not native decompiler C++.
fn collect_known_entry_shared_return_overrides(
    binary_image: &[u8],
    elf: &goblin::elf::Elf,
    plt_entries: &HashMap<u64, String>,
) -> Result<Vec<FlowOverrideRecord>, Box<dyn std::error::Error>> {
    const SHF_EXECINSTR: u64 = 0x4;
    const SHT_PROGBITS: u32 = 1;

    // FunctionManager has one function per entry. Keep that identity exact:
    // aliases with the same entry must describe the same non-empty body or
    // the standalone projection fails visibly instead of choosing one.
    let mut function_entries = BTreeSet::new();
    let mut body_ends = BTreeMap::<u64, u64>::new();
    for symbol in elf
        .syms
        .iter()
        .chain(elf.dynsyms.iter())
        .filter(|symbol| symbol.is_function())
    {
        if symbol.st_value == 0 {
            continue;
        }
        function_entries.insert(symbol.st_value);
        if symbol.st_size == 0 {
            continue;
        }
        let end = symbol
            .st_value
            .checked_add(symbol.st_size)
            .ok_or_else(|| format!("function extent overflows at 0x{:x}", symbol.st_value))?;
        match body_ends.insert(symbol.st_value, end) {
            Some(previous) if previous != end => {
                return Err(format!(
                    "conflicting ELF function bodies at 0x{:x}: 0x{:x} and 0x{:x}",
                    symbol.st_value, previous, end
                )
                .into())
            }
            _ => {}
        }
    }
    // Ghidra's ELF/PLT analyzers materialize relocation-backed PLT slots as
    // functions before Shared Return Calls runs. Their names are irrelevant;
    // only the relocation-derived entry addresses participate here.
    function_entries.extend(plt_entries.keys().copied());

    // FunctionManager bodies cannot overlap. Detect malformed/ambiguous ELF
    // ownership before scanning any references.
    let mut previous_body: Option<(u64, u64)> = None;
    for (&entry, &end) in &body_ends {
        if let Some((previous_entry, previous_end)) = previous_body {
            if entry < previous_end {
                return Err(format!(
                    "overlapping ELF function bodies: 0x{previous_entry:x}..0x{previous_end:x} and 0x{entry:x}..0x{end:x}"
                )
                .into());
            }
        }
        previous_body = Some((entry, end));
    }

    let mut result = BTreeMap::<(u64, u64), FlowOverrideRecord>::new();
    for (&owner_entry, &owner_end) in &body_ends {
        let owner_size = owner_end - owner_entry;
        let mut containing_sections = Vec::new();
        for candidate in &elf.section_headers {
            if (candidate.sh_flags & SHF_EXECINSTR) == 0
                || candidate.sh_type != SHT_PROGBITS
            {
                continue;
            }
            let section_end = candidate.sh_addr.checked_add(candidate.sh_size).ok_or_else(|| {
                format!("executable section extent overflows at 0x{:x}", candidate.sh_addr)
            })?;
            if owner_entry >= candidate.sh_addr && owner_end <= section_end {
                containing_sections.push(candidate);
            }
        }
        let section = match containing_sections.as_slice() {
            [section] => *section,
            [] => {
                // Program has no Instruction at a function whose body is not
                // in an executable PROGBITS section, matching the Java null
                // check.
                continue;
            }
            sections => {
                return Err(format!(
                    "function body 0x{owner_entry:x}..0x{owner_end:x} belongs to {} executable sections",
                    sections.len()
                )
                .into())
            }
        };
        let file_start_u64 = section
            .sh_offset
            .checked_add(owner_entry - section.sh_addr)
            .ok_or_else(|| format!("function file offset overflows at 0x{owner_entry:x}"))?;
        let file_end_u64 = file_start_u64
            .checked_add(owner_size)
            .ok_or_else(|| format!("function file extent overflows at 0x{owner_entry:x}"))?;
        let file_start = usize::try_from(file_start_u64)?;
        let file_end = usize::try_from(file_end_u64)?;
        let function_bytes = binary_image.get(file_start..file_end).ok_or_else(|| {
            format!(
                "function bytes outside ELF image: 0x{owner_entry:x}..0x{owner_end:x}"
            )
        })?;
        let mut decoder =
            IcedDecoder::with_ip(64, function_bytes, owner_entry, DecoderOptions::NONE);
        let mut owner_records = Vec::new();
        let mut owner_valid = true;
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                eprintln!(
                    "[PREPASS] Shared Return Calls skipped ELF body 0x{owner_entry:x}..0x{owner_end:x}: invalid instruction at 0x{:x}",
                    instruction.ip()
                );
                owner_valid = false;
                break;
            }
            // getJumpRefsToFunction: direct jump only, with conditional jumps
            // disabled by the locked analyzer default. Calls and indirect
            // branches do not enter the incoming jump-reference list.
            if instruction.flow_control() != FlowControl::UnconditionalBranch {
                continue;
            }
            let target = match instruction.op0_kind() {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    instruction.near_branch64()
                }
                _ => continue,
            };
            if !function_entries.contains(&target) {
                continue;
            }
            let source = instruction.ip();
            let instruction_end = source
                .checked_add(instruction.len() as u64)
                .ok_or_else(|| format!("instruction extent overflows at 0x{source:x}"))?;
            if instruction_end > owner_end {
                return Err(format!(
                    "instruction crosses function body at 0x{source:x}: end=0x{instruction_end:x} body_end=0x{owner_end:x}"
                )
                .into());
            }

            // getSingleFlowReferenceFrom: this direct iced branch projection
            // has exactly one memory flow reference, namely `target`.
            // FunctionManager::getFunctionAt(source): do not override thunks.
            if function_entries.contains(&source) {
                continue;
            }
            // Do not reinterpret a jump from inside the destination function
            // back to that same function's entry.
            if body_ends
                .get(&target)
                .is_some_and(|&destination_end| source >= target && source < destination_end)
            {
                continue;
            }

            // A Program Instruction has a single owning function body. Fail
            // on overlapping ELF bodies instead of picking an owner by order.
            let owners: Vec<u64> = body_ends
                .iter()
                .filter_map(|(&entry, &end)| (source >= entry && source < end).then_some(entry))
                .collect();
            if owners.as_slice() != [owner_entry] {
                return Err(format!(
                    "ambiguous source function for branch 0x{source:x}: {owners:?}"
                )
                .into());
            }

            let record = FlowOverrideRecord {
                function_address: owner_entry,
                override_address: source,
                flow_type: FlowOverride::CallReturn,
            };
            owner_records.push(record);
        }
        if !owner_valid {
            continue;
        }
        for record in owner_records {
            let key = (record.function_address, record.override_address);
            if let Some(previous) = result.insert(key, record) {
                if previous != record {
                    return Err(format!(
                        "conflicting flow overrides for 0x{:x}:0x{:x}",
                        record.function_address, record.override_address
                    )
                    .into());
                }
            }
        }
    }
    Ok(result.into_values().collect())
}

const WORKER_PROTOCOL_VERSION: u32 = 2;
// Per-function decompile deadline. Aligned with Ghidra's suggested
// per-function decompile timeout — DecompileOptions.java:289
// SUGGESTED_DECOMPILE_TIMEOUT_SECS = 30, installed as the default at :522
// and read back at :585. The previous 10s deadline sat below the oracle's
// budget and reaped main (3510 bytes; action phase ~11.5s) before it could
// emit anything, so the locked DWARF `int main(int argc, char **argv)`
// prototype never reached the corpus output.
fn function_timeout() -> Duration {
    // Diagnostic env knob: an over-budget function (e.g. main, which does
    // not converge in the post-blockstruct action loop — pre-existing at the
    // branch head) can be given a larger wall budget for measurement without
    // rebuilding. Defaults to the canonical 30s above.
    std::env::var("RUGRA_FUNC_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(30))
}
const FUNCTION_TIMEOUT: Duration = Duration::from_secs(30);
const WORKER_MODE_ARG: &str = "--rugra-curl-function-worker";
const WORKER_LABEL_ARG: &str = "--probe-label";
const DESCENDANT_MODE_ARG: &str = "--rugra-timeout-descendant-probe";
const SELF_TEST_ARG: &str = "--rugra-timeout-isolation-self-test";
const COMPARE_FUNCTION_ARG: &str = "--rugra-timeout-isolation-compare-function";
const SELECT_FUNCTION_ARG: &str = "--rugra-selected-function";
const WORKER_PANIC_EXIT: i32 = 70;
const WORKER_ERROR_EXIT: i32 = 71;
const WORKER_INVALID_REQUEST_EXIT: i32 = 72;
const WORKER_OUTPUT_EXIT: i32 = 73;
const MAX_WORKER_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_WORKER_STDOUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_WORKER_STDERR_BYTES: usize = 16 * 1024 * 1024;
const SIGKILL: i32 = 9;
const ESRCH: i32 = 3;
const PR_SET_PDEATHSIG: i32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WorkerTarget {
    vaddr: u64,
    size: usize,
    file_offset: u64,
    name: String,
    /// Whether an ELF symbol (address+size+name) backs this target and the
    /// worker must re-validate against it. Ledger-only targets (PLT stubs,
    /// `_init`/`_fini`, EXTERNAL-space entries) are validated through the
    /// ELF section/file-offset checks instead.
    symbol_backed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DecompileRequest {
    binary_image: Vec<u8>,
    target: WorkerTarget,
    symbol_entries: Vec<(u64, String)>,
    string_entries: Vec<(u64, String)>,
    prototype_entries: Vec<(u64, usize)>,
    flow_override_entries: Vec<FlowOverrideRecord>,
    /// B3-COREACTION-CONSTANTPTR-0001 (b): the a0 `.rodata` DAT label layer
    /// (address, name) the worker installs into the Database symbol graph
    /// (add_symbol_mapped on the global scope), so ActionConstantPtr's
    /// `queryContainer(rampoint,1,Address())` (coreaction.cc:1151) fires on
    /// hugehelp's alias constants.
    rodata_dat_entries: Vec<(u64, String)>,
    /// `.rodata` section extent `(base_vaddr, size)` — the readonly property
    /// range source (`Database::setPropertyRange(Varnode::readonly, ...)`,
    /// the loader registration channel of architecture.cc:1371-1383).
    rodata_span: Option<(u64, u64)>,
    /// MAINDIFF-GLOBAL-0001: the Program-DB global symbol layer (address,
    /// name, byte size, is-pointer-slot) — ELF OBJECT symbols, GOT PTR_
    /// labels and .data PTR_DAT_ pointer labels the worker installs into
    /// the Database global scope, where `Funcdata::mapGlobals` /
    /// `linkSymbol` / `setVarnodeProperties` query them
    /// (funcdata_varnode.cc:25/1156/1653). Pointer slots carry `undefined *`
    /// (the oracle's facing type for PTR_ labels — golden witness
    /// `PTR___gmon_start___00116fe8 != (undefined *)0x0`).
    db_symbol_entries: Vec<(u64, String, i32, bool)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PrototypeRequest {
    binary_image: Vec<u8>,
    target: WorkerTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum IsolationProbe {
    Success { token: String },
    Hang { token: String },
    Panic { token: String },
    NonZero { token: String },
    OutputDisconnect { token: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum WorkerJob {
    InferPrototype {
        protocol_version: u32,
        request: PrototypeRequest,
    },
    Decompile {
        protocol_version: u32,
        request: DecompileRequest,
    },
    Probe {
        protocol_version: u32,
        probe: IsolationProbe,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum WorkerPayload {
    Prototype(usize),
    Decompile(Option<String>),
    ProbeSuccess(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MonitorMode {
    Deadline,
    DisconnectProbe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestMode {
    Valid,
    MalformedProbe,
}

#[derive(Debug)]
enum WorkerOutcome {
    Success(WorkerPayload),
    Timeout,
    Panic,
    NonZero(String),
    InputDisconnected(String),
    OutputDisconnected(String),
    MonitorDisconnected,
    WaitFailed(String),
    CleanupFailed(String),
    SpawnFailed(String),
    InvalidRequest(String),
}

#[derive(Debug)]
struct WorkerRun {
    outcome: WorkerOutcome,
    stderr: Vec<u8>,
}

#[derive(Debug)]
enum WorkerFailure {
    InvalidRequest(String),
    Job(String),
}

// RUGRA-GLUE: tallies per-function outcomes across the golden-corpus run for the Summary line.
#[derive(Default)]
struct CorpusStats {
    decompiled: usize,
    empty_output: usize,
    timeouts: usize,
    panic: usize,
    external_stubs: usize,
    external_stub_decls: usize,
    worker_failures: usize,
    protocol_failures: usize,
}

impl CorpusStats {
    // RUGRA-GLUE: every attempted function lands in exactly one bucket.
    fn attempted(&self) -> usize {
        self.decompiled
            + self.empty_output
            + self.timeouts
            + self.panic
            + self.external_stubs
            + self.external_stub_decls
            + self.worker_failures
            + self.protocol_failures
    }
}

// RUGRA-GLUE: classifies a worker failure as an EXTERNAL-space ledger entry (no ELF section backs its address) using the worker's own replayed diagnostic.
fn is_external_stub_failure(stderr: &[u8]) -> bool {
    std::str::from_utf8(stderr)
        .map(|text| text.contains("no ELF section contains"))
        .unwrap_or(false)
}

// ============================================================================
// EXTERNAL-block import stubs (EXTERNAL-STUB-SUPPORT-0001)
// ----------------------------------------------------------------------------
// Oracle behavior (locked 12.0.4, commit e40ed13): the Ghidra ELF importer
// allocates an artificial EXTERNAL *memory block* in the default space for
// undefined imports — ElfProgramBuilder.getNextExternalBlockEntryAddress
// (ElfProgramBuilder.java:1496-1530) hands out one 8-byte entry per UND
// .dynsym symbol in symbol-table order, and createExternalBlock
// (ElfProgramBuilder.java:1532-1556) backs them with an uninitialized block
// whose base is the 0x1000-aligned start of the last unallocated linkage
// range (allocateLinkageBlock + ElfLoadAdapter.getLinkageBlockAlignment,
// ElfLoadAdapter.java:445). For this PIE: last allocatable byte = end of
// .bss = 0x18680, so the block starts at normalized 0x19000 (= Ghidra
// 0x119000 at the analyzeHeadless image base 0x100000) — exactly the 48
// ledger entries 0x19000..0x19178.
//
// When the decompiler is pointed at such a function, every translation step
// fails as bad instruction data — the Ghidra Java getInstruction bridge
// refuses EXTERNAL-block locations (DecompileCallback.java:417-419 throws
// UnknownInstructionException), which enters flow.cc:446-456 as a
// BadDataError: `step = 1` (the ledger's `size: 1`), an artificial
// badinstruction halt (flow.cc:592-601) printed by PrintC::opReturn as
// `halt_baddata();` (printc.cc:770-772), the address-attached warning
// "Bad instruction - Truncating control flow here" (flow.cc:451) and the
// header warning "Control flow encountered bad instruction data"
// (flow.cc:454). The locked-parameter signatures come from Ghidra's libc
// signature data; with an unknown calling convention they additionally
// produce the "Unknown calling convention -- yet parameter storage is
// locked" header warning (ActionPrototypeWarnings, coreaction.cc:4903-4907).
// The `name@@GLIBC_x.y` body comment is the ELF versioned symbol
// (.gnu.version + .gnu.version_r) carried into the listing.
// ============================================================================

// RUGRA-GLUE: one undefined .dynsym import with its GNU version tag; the
// Ghidra platform side keeps this as the external symbol + its versioned
// namespace (ExternalManagerDB / SymbolManager.getExternalSymbol, Java).
struct ExternalImport {
    name: String,
    /// Version tag from .gnu.version/.gnu.version_r (e.g. "GLIBC_2.2.5").
    version: Option<String>,
}

// RUGRA-GLUE: documented libc prototypes for imported symbols — delegates to
// the single source of truth in rugra::debugproto::LibcSignatureTable (see
// there for the Ghidra generic_clib boundary this mirrors).
fn libc_import_signature(name: &str) -> Option<(&'static str, &'static str)> {
    let signature = rugra::debugproto::LibcSignatureTable::default();
    signature
        .lookup(name)
        .map(|sig| (sig.return_type, sig.parameters))
}

// RUGRA-GLUE: driver-side call-spec resolution, the observable equivalent of
// Ghidra's FlowInfo::queryCall (flow.cc:656-672) + ActionDefaultParams'
// callee-proto copy (coreaction.cc:2322-2330). Ghidra's queryFunction hits
// the Program database the platform analyzers populated (PLT thunk -> EXTERNAL
// symbol with the generic_clib locked signature); Rugra's front-end state is
// the driver's ELF/PLT symbol table plus the locked libc ABI table. For each

// ============================================================================
// FLOW-NORETURN-DATA-0001: "Non-Returning Functions - Known" data source
//
// Ghidra's Java analyzer `NoReturnFunctionAnalyzer` (NAME = "Non-Returning
// Functions - Known", Ghidra/Features/Base/src/main/java/ghidra/app/plugin/
// core/analysis/NoReturnFunctionAnalyzer.java @ oracle e40ed13014) walks the
// primary symbol table, strips leading '_' chars from each symbol name, and
// on an exact (case-sensitive) match against the per-format name list calls
// `Function.setNoReturn(true)` — the program-database flag that the
// decompiler later reads via queryCall's `copyFlowEffects`
// (flow.cc:663-669), making `checkForFlowModification` (flow.cc:636-651)
// insert `artificialHalt(PcodeOp::noreturn)` after the CALL and emit the
// "Subroutine does not return" warning. The name list is selected per
// executable format by data/noReturnFunctionConstraints.xml; for this ELF
// fixture it is data/ElfFunctionsThatDoNotReturn (21 names, byte-exact
// below, file order preserved). That data file carries no trailing-`*`
// wildcard entries, so the analyzer's wildcard prefix set is empty for ELF
// and only the exact-match path applies here.
//
// Matching semantics ported from NoReturnFunctionAnalyzer.added() /
// loadFunctionNamesIfNeeded():
//   * strip ALL leading '_' from the symbol name (`__stack_chk_fail` ->
//     `stack_chk_fail`, `_exit` -> `exit`); the list itself has no leading
//     underscores (the loader strips-and-warns on any).
//   * exact, case-sensitive containment (`Unwind_Resume` and the mangled
//     `ZSt9terminatev` / `ZN10__cxxabiv111__terminateEPFvvE` keep their
//     case: `_ZSt9terminatev` matches only through underscore stripping).
//   * the analyzer's namespace guard (skip when the parent namespace is
//     neither global, library, nor std — protects demangled class methods
//     like `Menu::_exit()`) is vacuous for this driver: the ELF symbol table
//     carries raw mangled names with no namespace structure, and a mangled
//     method name (`_ZN5Menu5_exitEv`) never exact-matches the list anyway.
// ============================================================================

/// Ghidra's `ElfFunctionsThatDoNotReturn` name list (oracle commit
/// e40ed13014, Ghidra/Features/Base/data/ElfFunctionsThatDoNotReturn, 21
/// non-comment lines verbatim in file order). Selected for this fixture by
/// data/noReturnFunctionConstraints.xml's
/// `executable_format name="Executable and Linking Format (ELF)"` fallback
/// entry (the curl fixture has no golang/rustc compiler spec).
const KNOWN_NO_RETURN_ELF_NAMES: [&str; 21] = [
    "exit",
    "cexit",
    "c_exit",
    "abort",
    "reboot",
    "longjmp",
    "longjmp_chk",
    "siglongjmp",
    "panic",
    "stack_chk_fail",
    "cxa_throw",
    "cxa_terminate",
    "cxa_call_unexpected",
    "cxa_bad_cast",
    "Unwind_Resume",
    "assert_fail",
    "assert_rtn",
    "fortify_fail",
    "ZSt9terminatev",
    "ZN10__cxxabiv111__terminateEPFvvE",
    "pthread_exit",
];

// RUGRA-GLUE: Java-side analyzer (NoReturnFunctionAnalyzer.added) with no
// decompiler-C++ counterpart; this driver function is the program-database
// seeding equivalent on Rugra's side of the front-end boundary.
/// Strip leading '_' chars from a raw ELF symbol name, mirroring the
/// analyzer's `while (name.charAt(startIndex) == '_') ++startIndex;` loop.
/// ASCII-only names from the ELF strtab; the '_' byte prefix is what the
/// Java loop consumes, so byte indexing is exact here.
pub fn strip_leading_underscores(name: &str) -> &str {
    name.trim_start_matches('_')
}

// RUGRA-GLUE: Java-side analyzer (NoReturnFunctionAnalyzer.added) with no
// decompiler-C++ counterpart; see the module note above.
/// Exact no-return classification for a raw ELF symbol name: strip leading
/// underscores, then case-sensitive containment in the Known list (the ELF
/// list has no wildcard entries, so no prefix path applies).
pub fn is_known_no_return(symbol_name: &str) -> bool {
    KNOWN_NO_RETURN_ELF_NAMES
        .contains(&strip_leading_underscores(symbol_name))
}

// RUGRA-GLUE: Java-side analyzer makeNoReturnFunction
// (NoReturnFunctionAnalyzer.java:121-180, the functionAt.setNoReturn(true)
// calls at :144/:168) with no decompiler-C++ counterpart; the driver's
// program-database equivalent for the function being decompiled.
/// Pre-flow function-attribute half of FLOW-NORETURN-DATA-0001: set
/// `no_return` on the decompiled function's own FuncProto when its primary
/// symbol name matches the Known list — the analyzer's
/// `functionAt.setNoReturn(true)` DB attribute, which flow-time queryCall
/// reads via copyFlowEffects (flow.cc:663-664) for callers' call sites.
/// Idempotent: re-marking keeps the bit, and a non-matching name never
/// clears it (the analyzer never unsets the flag on non-matches). Returns
/// whether the function was marked (for the [PREPASS] log).
pub fn mark_known_no_return_function(fd: &mut Funcdata, symbol_name: &str) -> bool {
    if !is_known_no_return(symbol_name) {
        return false;
    }
    fd.funcp.set_no_return(true);
    true
}

// RUGRA-GLUE: the analyzer's program-database marking + Ghidra's
// FlowInfo::queryCall queryFunction boundary (flow.cc:660) in one
// driver-owned table; Rugra's Funcdata owns no per-callee Funcdata at flow
// time, so the driver hands the callee `funcp` slices to
// rugra::flow::follow_flow_with_callee_protos.
/// Flow-visible callee table (FLOW-NORETURN-DATA-0001 segment (c)):
/// iterate the driver-seeded symbol table and, for every symbol matching
/// the Known no-return list, build the minimal callee FuncProto — the
/// `funcp` slice `queryFunction` returns for the matched function: the
/// default proto shape (symbol name + void return, all flags clear) with
/// the analyzer's `setNoReturn(true)` DB attribute set. The flow-time
/// consumer (`FlowInfo::query_call`'s `copy_flow_effects`, flow.cc:663-664)
/// reads only the `is_inline|no_return` flag subset, so the void return and
/// empty parameter list carry no additional semantics; addresses never
/// called remain inert entries (Ghidra's analyzer equally marks functions
/// that some decompilation never queries).
pub fn known_no_return_callee_protos(
    symbol_table: &HashMap<u64, String>,
) -> BTreeMap<u64, rugra::fspec::FuncProto> {
    symbol_table
        .iter()
        .filter(|(_, name)| is_known_no_return(name))
        .map(|(&address, name)| {
            // The same default-proto construction Funcdata::new gives the
            // decompiled function itself (funcdata.rs:525-531) — Ghidra's
            // FuncCallSpecs ctor "clones a default" for fresh specs.
            let mut proto = rugra::fspec::FuncProto::new(
                name.clone(),
                std::sync::Arc::new(rugra::type_system::datatype::Datatype::Void(
                    rugra::type_system::datatype::TypeBase::new(
                        "void".to_string(),
                        0,
                        rugra::type_system::datatype::TypeMetatype::Void,
                    ),
                )),
            );
            proto.set_no_return(true);
            (address, proto)
        })
        .collect()
}

// callspec with a direct entry address: (1) set_funcdata with the symbol's
// display name, (2) when the symbol is a table import, install the locked
// signature proto on the call site, (3) when the entry address has a DWARF
// definition, install the locked DWARF callee proto (the
// queryCall→ActionDefaultParams copy boundary for debug-backed functions),
// (4) refresh the CALL op's typed fspec annotation against the same stable
// callspec owner. Unresolved targets are left exactly as flow produced them
// (unknown). Returns (named, locked libc signatures, locked DWARF
// signatures, relinked call ops, known no-return callees marked).
fn link_call_specs(
    fd: &mut rugra::funcdata::Funcdata,
    libc_signatures: &rugra::debugproto::LibcSignatureTable,
    debug_db: &rugra::debugproto::DebugPrototypeDatabase,
    fn_name: &str,
    type_names: &std::collections::HashMap<String, std::sync::Arc<rugra::type_system::datatype::Datatype>>,
) -> (usize, usize, usize, usize, usize) {
    // Keep the stable owner with each direct target. Multiple CALLs may share
    // one machine address, so an address lookup is not an identity lookup.
    let targets: Vec<_> = fd
        .callspecs
        .iter()
        .filter_map(|owner| {
            let spec = owner.read().unwrap();
            spec.entry_addr
                .map(|entry| (owner.clone(), spec.op_addr.as_u64(), entry.as_u64()))
        })
        .collect();
    // CALLSPEC-ENV-SCOPE-0001: the model carrier for the DWARF callee copy
    // is the same resolved default model the decompiled function's own
    // FuncProto carries after set_arch (both Funcdata objects would bind the
    // Architecture defaultfp; FUNCPROTO-MODEL-BIND-0001).
    let model_carrier = fd.funcp.clone();
    let mut named = 0usize;
    let mut signatures = 0usize;
    let mut dwarf_signatures = 0usize;
    let mut noreturn_marked = 0usize;
    for (owner, op_addr, entry) in targets {
        // flow.cc:660: queryFunction(entry) -> the PLT thunk's symbol name.
        let Some(name) = fd.symbol_table.get(&entry).cloned() else {
            continue; // Unknown target: stays unknown (no queryCall hit).
        };
        // flow.cc:662: fspecs.setFuncdata(otherfunc) — entry + display name.
        owner
            .write()
            .unwrap()
            .set_funcdata(&name, rugra::address::Address::new(entry));
        named += 1;
        // coreaction.cc:2327: fc->copy(otherfunc->getFuncProto()) — the
        // platform side's locked callee signature for the resolved target.
        // Two disjoint sources at this boundary (a .plt.sec/.plt/.plt.got
        // thunk address never carries a DWARF definition, and a DWARF
        // definition's function name is never a generic_clib import):
        //   (a) the generic_clib locked signature for the imported symbol;
        //   (b) the DWARF-analyzer locked signature for a debug-info callee
        //       (headless golden main: `glob_url(&urls,pcVar12,&urlnum)`
        //       3-arg and `curl_version()` 0-arg render from this boundary).
        // A call-site prototype with an explicitly selected model is already
        // authoritative.  Signature discovery may fill an unresolved model,
        // but must not overwrite a prior override.
        let mut installed = owner.read().unwrap().prototype.has_model();
        if !installed {
            match libc_signatures.locked_proto(&name, &model_carrier, Some(type_names)) {
                Ok(Some(proto)) => {
                    owner.write().unwrap().prototype = proto;
                    signatures += 1;
                    installed = true;
                }
                Ok(None) => {}
                Err(error) => eprintln!(
                    "[PREPASS] {} callspec@0x{:x}: libc signature for {} rejected: {}",
                    fn_name, op_addr, name, error
                ),
            }
        }
        if !installed {
            match debug_db.locked_callsite_proto(entry, &model_carrier) {
                Ok(Some(proto)) => {
                    owner.write().unwrap().prototype = proto;
                    dwarf_signatures += 1;
                }
                Ok(None) => {}
                Err(error) => eprintln!(
                    "[PREPASS] {} callspec@0x{:x}: DWARF signature for {} rejected: {}",
                    fn_name, op_addr, name, error
                ),
            }
        }
        // flow.cc:663-664 copyFlowEffects position (FLOW-NORETURN-DATA-0001):
        // the "Non-Returning Functions - Known" analyzer has already set
        // no_return on the callee's program-database FuncProto, and
        // queryCall copies that flag onto the callsite independent of the
        // model lock — so the bit lands whether or not a locked libc
        // signature was installed above (fspec.cc copyFlowEffects copies the
        // is_inline|no_return flag subset only). Rugra's flow-time
        // query_call slice (src/flow.rs) does not yet consume this
        // (CALLSPEC-NORETURN-WIRE-0001 segment (b)); the marking here is the
        // driver's program-database half of the channel.
        if is_known_no_return(&name) {
            owner.write().unwrap().prototype.set_no_return(true);
            noreturn_marked += 1;
        }
    }
    // flow.cc:685 / fspec.cc:5450: opSetInput(op, newVarnodeCallSpecs(fc)).
    // Ghidra's fspec varnode is a pointer to the FuncCallSpecs. D0 preserves
    // that exact owner identity through a typed Weak carried by the temporary
    // Iop annotation; TypeOp/PrintC consumption remains a separate residual.
    let relinked = relink_call_spec_targets(fd);
    (named, signatures, dwarf_signatures, relinked, noreturn_marked)
}

// RUGRA-GLUE: refresh each direct CALL's fspec annotation from its stable
// callspec owner. The driver temporarily retains the entry-address offset for
// its legacy PrintC bridge, but identity is exclusively the typed Weak handle;
// a raw constant with the same bits cannot resolve a callspec.
fn relink_call_spec_targets(fd: &mut rugra::funcdata::Funcdata) -> usize {
    use rugra::space::AddressSpace;
    use rugra::varnode::varnode_flags;
    let specs: Vec<_> = fd
        .callspecs
        .iter()
        .filter_map(|owner| {
            owner
                .read()
                .unwrap()
                .entry_addr
                .map(|entry| (owner.clone(), entry.as_u64()))
        })
        .collect();
    let mut relinked = 0usize;
    for (owner, entry) in specs {
        let op_arc = owner.read().unwrap().op.upgrade();
        let Some(op_arc) = op_arc else {
            continue;
        };
        let vn = fd.vbank.create_with_space(
            std::mem::size_of::<usize>(),
            AddressSpace::Iop,
            entry,
        );
        {
            let mut annotation = vn.write().unwrap();
            annotation.set_flags(varnode_flags::ANNOTATION);
            annotation.bind_call_spec(&owner);
        }
        let _ = fd.assign_high(&vn);
        let op_ref = rugra::op::PcodeOpRef(op_arc);
        fd.op_set_input(&op_ref, vn, 0);
        relinked += 1;
    }
    relinked
}

// RUGRA-GLUE: collects the EXTERNAL-block import slots in allocation order:
// every undefined .dynsym symbol (functions and weak notypes alike; defined
// objects like stdout/stdin/stderr get no slot), each with its GNU version
// tag resolved through .gnu.version indices into .gnu.version_r.
fn collect_external_imports(elf: &goblin::elf::Elf) -> Vec<ExternalImport> {
    // Version name per .gnu.version_r auxiliary index (aux.vna_other); the
    // names resolve through .dynstr (goblin's symver doc example:
    // binary.dynstrtab.get_at(aux.vna_name)).
    let mut version_names: std::collections::HashMap<u16, String> = Default::default();
    if let Some(verneed) = &elf.verneed {
        for file in verneed.iter() {
            for aux in file.iter() {
                if let Some(name) = elf.dynstrtab.get_at(aux.vna_name) {
                    version_names.insert(aux.vna_other, name.to_string());
                }
            }
        }
    }
    let versym_of = |sym_index: usize| -> Option<String> {
        let versyms = elf.versym.as_ref()?;
        let entry = versyms.get_at(sym_index)?;
        // .gnu.version encodes the index in the low 15 bits; 0 = *local*,
        // 1 = *global* (unversioned).
        let index = entry.vs_val & goblin::elf::symver::VERSYM_VERSION;
        if index <= goblin::elf::symver::VER_NDX_GLOBAL {
            return None;
        }
        version_names.get(&index).cloned()
    };
    let mut imports = Vec::new();
    for (index, sym) in elf.dynsyms.iter().enumerate() {
        if sym.st_shndx == 0 {
            // SHN_UNDEF: this is an import the EXTERNAL block allocates for.
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    imports.push(ExternalImport {
                        name: name.to_string(),
                        version: versym_of(index),
                    });
                }
            }
        }
    }
    imports
}

// RUGRA-GLUE (B3-COREACTION-CONSTANTPTR-0001 b): builds the vaddr-keyed
// memory image the worker's loader-backed StringManager reads through — the
// PT_LOAD segments laid out at their virtual addresses, NOBITS (.bss)
// zero-filled, exactly what Ghidra's loader hands getStringData
// (stringmanage.cc:427-475 loadFill loop).
fn worker_memory_load_image(elf: &goblin::elf::Elf, buffer: &[u8]) -> rugra::loadimage::RawLoadImage {
    const PT_LOAD: u32 = 1;
    let mut top = 0usize;
    for ph in elf.program_headers.iter() {
        if ph.p_type == PT_LOAD {
            top = top
                .max((ph.p_vaddr as usize).saturating_add(ph.p_memsz as usize));
        }
    }
    let mut image = vec![0u8; top];
    for ph in elf.program_headers.iter() {
        if ph.p_type == PT_LOAD {
            let vaddr = ph.p_vaddr as usize;
            let file_size = ph.p_filesz as usize;
            let src = buffer
                .get(ph.p_offset as usize..(ph.p_offset as usize).saturating_add(file_size))
                .unwrap_or(&[]);
            let dst_end = vaddr.saturating_add(src.len()).min(top);
            if vaddr < dst_end {
                image[vaddr..dst_end].copy_from_slice(&src[..dst_end - vaddr]);
            }
        }
    }
    rugra::loadimage::RawLoadImage::from_bytes("curl", 0, image)
}

fn external_block_base(elf: &goblin::elf::Elf) -> u64 {
    const SHF_ALLOC: u64 = 0x2;
    const LINKAGE_BLOCK_ALIGNMENT: u64 = 0x1000;
    let last_alloc_end = elf
        .section_headers
        .iter()
        .filter(|header| (header.sh_flags & SHF_ALLOC) != 0)
        .map(|header| header.sh_addr.saturating_add(header.sh_size))
        .max()
        .unwrap_or(0);
    last_alloc_end.div_ceil(LINKAGE_BLOCK_ALIGNMENT) * LINKAGE_BLOCK_ALIGNMENT
}

// RUGRA-GLUE: renders the EXTERNAL-block stub section byte-faithfully to the
// locked golden form (ghidra_curl_1204.c entries 0x119000..0x119178). Every
// line cites its oracle source: the two warnings, the truncating comment and
// `halt_baddata();` are the flow.cc:446-456 / printc.cc:770-772 observables,
// the second warning only fires when parameter storage is locked
// (coreaction.cc:4903-4907), and the versioned-symbol comment only for
// .gnu.version-tagged imports. An empty parameter list prints as `(void)`.
fn external_stub_section(name: &str, import: &ExternalImport) -> String {
    let mut out = String::new();
    // flow.cc:454 header warning (every EXTERNAL-block function hits it).
    out.push_str("\n/* WARNING: Control flow encountered bad instruction data */\n");
    let signature = match libc_import_signature(&import.name) {
        Some((return_type, parameters)) => {
            // coreaction.cc:4903-4907: unknown calling convention + locked
            // parameter storage.
            out.push_str(
                "/* WARNING: Unknown calling convention -- yet parameter storage is locked */\n",
            );
            if parameters.is_empty() {
                format!("{} {}(void)", return_type, name)
            } else {
                format!("{} {}({})", return_type, name, parameters)
            }
        }
        None => format!("void {}(void)", name),
    };
    out.push('\n');
    out.push_str(&signature);
    out.push_str("\n\n{\n");
    // flow.cc:451 address-attached warning, printed at the halt statement's
    // position (20-space comment indent, 2-space statement indent).
    out.push_str(
        "                    /* WARNING: Bad instruction - Truncating control flow here */\n",
    );
    // The versioned external symbol (e.g. free@@GLIBC_2.2.5) rides along as
    // a listing comment at the block entry.
    if let Some(version) = &import.version {
        out.push_str(&format!("                    /* {}@@{} */\n", name, version));
    }
    // printc.cc:770-772 PrintC::opReturn, badinstruction arm. The trailing
    // blank line reproduces the section separator the golden uses between
    // functions (`}\n\n\n` before the next `/* ----` header once println
    // appends the line's newline).
    out.push_str("  halt_baddata();\n}\n\n");
    out
}


#[derive(Clone, Debug)]
enum DriverMode {
    All,
    CompareFunctions(Vec<String>),
    SelectedFunctions(Vec<String>),
}

unsafe extern "C" {
    fn getpgid(pid: i32) -> i32;
    fn getppid() -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
    fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
}

/// AnalyzeHeadless image base of the locked 12.0.4 golden run for this PIE
/// (the same rebase convention as GOLDEN_CORPUS_LEDGER above: golden/ledger
/// Ghidra addresses are this driver's base-0 addresses + 0x100000).
const ANALYZE_HEADLESS_IMAGE_BASE: u64 = 0x100000;

// RUGRA-GLUE: default data label format of the platform analyzers: "DAT_" +
// 8-hex-digit of the image-based address (golden witnesses: DAT_00107180 for
// base-0 0x7180, DAT_00117020 for base-0 0x17020, DAT_001061d9 for base-0
// 0x61d9). The decompiler core never mints DAT symbols itself — Ghidra's
// labels come from the platform analyzers via <symboltable> (B3 audit §1.2;
// database.cc:957-958 stackContainer leaves the entry NULL for unmapped
// data), so this driver-side name stands in for that platform layer.
// Pointer-typed referenced data takes the PTR_DAT_ prefix instead (golden
// :1678 `&PTR_DAT_00117020`); that typing belongs to the (a1) SymbolEntry
// layer and is intentionally not modeled by this name-only proxy.
fn synthetic_dat_name(base0_addr: u64) -> String {
    format!("DAT_{:08x}", ANALYZE_HEADLESS_IMAGE_BASE + base0_addr)
}

// Ghidra: stringmanage.cc:347 StringManager::getCodepoint
/// charsize==1 (UTF-8) specialization of `StringManager::getCodepoint`
/// (stringmanage.cc:347-410): the `(val&0x80)==0` ASCII fast path, the
/// `(val&0xe0)==0xc0` / `(val&0xf0)==0xe0` / `(val&0xf8)==0xf0` prefix
/// chains with mandatory `0x80..0xBF` continuation bytes, the fall-through
/// `return -1` for anything else (stringmanage.cc:391 — bare continuation
/// bytes such as the 0xAD soft hyphen inside the 0x7180/0x99a8/0xc1d8
/// hugehelp aliases land here), and the closing surrogate/0x10FFFF range
/// checks. Returns `(codepoint, bytes consumed)`; `(-1, _)` marks an
/// invalid encoding. Bounds-checked continuations are result-equivalent to
/// the oracle for NUL-terminated slices: a prefix byte directly before the
/// NUL always fails its first continuation check against the NUL byte.
fn get_codepoint_utf8(buf: &[u8], i: usize) -> (i64, usize) {
    let continuation = |j: usize| -> Option<i64> {
        buf.get(j)
            .map(|&b| b as i64)
            .filter(|b| (b & 0xc0) == 0x80)
    };
    let val = buf[i] as i64;
    let (codepoint, sk) = if (val & 0x80) == 0 {
        (val, 1)
    } else if (val & 0xe0) == 0xc0 {
        match continuation(i + 1) {
            Some(val2) => (((val & 0x1f) << 6) | (val2 & 0x3f), 2),
            None => (-1, 2),
        }
    } else if (val & 0xf0) == 0xe0 {
        match (continuation(i + 1), continuation(i + 2)) {
            (Some(val2), Some(val3)) => (
                ((val & 0xf) << 12) | ((val2 & 0x3f) << 6) | (val3 & 0x3f),
                3,
            ),
            _ => (-1, 3),
        }
    } else if (val & 0xf8) == 0xf0 {
        match (
            continuation(i + 1),
            continuation(i + 2),
            continuation(i + 3),
        ) {
            (Some(val2), Some(val3), Some(val4)) => (
                ((val & 7) << 18)
                    | ((val2 & 0x3f) << 12)
                    | ((val3 & 0x3f) << 6)
                    | (val4 & 0x3f),
                4,
            ),
            _ => (-1, 4),
        }
    } else {
        // stringmanage.cc:391 fall-through: bare continuation (0x80..0xBF)
        // or 0xF8..0xFF lead byte is not a valid UTF-8 encoding start.
        (-1, 1)
    };
    if codepoint >= 0xd800 && (codepoint > 0x10ffff || codepoint <= 0xdfff) {
        return (-1, sk);
    }
    (codepoint, sk)
}

// Ghidra: stringmanage.cc:324 StringManager::checkCharacters
/// Driver-side string admission gate mirroring the locked oracle's negative
/// string path: `StringManagerUnicode::getStringData` (stringmanage.cc:427)
/// calls `StringManager::checkCharacters` (stringmanage.cc:324-339), whose
/// codepoint walk returns -1 on any invalid encoding, leaving the cached
/// buffer empty so `StringManager::isString` (stringmanage.cc:166) is false —
/// which is what keeps `RulePtrsubCharConstant` from folding the PTRSUB
/// (ruleaction.cc:7375) and what golden expresses as `&DAT_00107180` for the
/// 0x7180-class hugehelp aliases (B3 audit §2.2 B4 / B4 §6). Runs without a
/// NUL terminator inside the loaded section are rejected the same way the
/// oracle's loadFill run-off (DataUnavailError, stringmanage.cc:463-465)
/// leaves the negative cache in place. The slice must include the trailing
/// NUL byte.
fn check_characters_utf8(bytes_with_terminator: &[u8]) -> bool {
    let mut i = 0usize;
    while i < bytes_with_terminator.len() {
        let (codepoint, skip) = get_codepoint_utf8(bytes_with_terminator, i);
        if codepoint < 0 {
            return false;
        }
        if codepoint == 0 {
            return true;
        }
        i += skip;
    }
    false
}

// RUGRA-GLUE: driver .rodata string pre-scan (examples-only stand-in for the
// platform string analyzer's data; the production isString path is the
// src-side StringManager lease, B4). Admission keeps the driver's previous
// extraction shape (first byte printable/whitespace, then the NUL-terminated
// run) and adds the oracle codepoint validity gate above, so strings with
// invalid UTF-8 no longer enter the table: without this, the later Rule
// folding would invert golden's `&DAT_*` classification (B3 前置警告).
fn scan_rodata_strings(rodata: &[u8], base_vaddr: u64) -> HashMap<u64, String> {
    let mut string_table = HashMap::new();
    let mut i = 0;
    while i < rodata.len() {
        let first = rodata[i];
        if first.is_ascii_graphic()
            || first == b' '
            || first == b'\n'
            || first == b'\t'
            || first == b'\r'
        {
            let str_start = i;
            while i < rodata.len() && rodata[i] != 0 {
                i += 1;
            }
            let str_len = i - str_start;
            let va = base_vaddr + str_start as u64;
            // NUL-terminated runs only, and only with a valid codepoint
            // sequence (check_characters_utf8 includes the trailing NUL).
            if str_len >= 1
                && i < rodata.len()
                && check_characters_utf8(&rodata[str_start..i + 1])
            {
                let s = String::from_utf8_lossy(&rodata[str_start..str_start + str_len]);
                if s.chars().all(|c| c.is_ascii() || c == '\u{FFFD}') {
                    // Replace lossy replacement chars for clean display
                    let clean: String = s.chars().filter(|c| c.is_ascii()).collect();
                    if !clean.is_empty() {
                        string_table.insert(va, clean);
                    }
                }
            }
        }
        i += 1;
    }
    string_table
}

// RUGRA-GLUE: driver-side synthetic .rodata DAT labels — the decompiler core
// has no counterpart (see synthetic_dat_name above). Segment-(a1) interface
// reservation (B3-COREACTION-CONSTANTPTR-0001 §a0): this map is the driver
// half of the Program-DB entry layer. When Funcdata grows the
// query_container channel (audit C1/C2), these entries populate the global
// scope's SymbolEntries (addr + per-byte proxy size 1 + golden-aligned name)
// so `ActionConstantPtr::isPointer`'s queryContainer(needexacthit=true) can
// hit the 0x7180-class aliases. Until that wiring lands this map has NO
// consumer by design (zero E2E delta); it deliberately does not feed the
// legacy symbol_entries name proxy, because printc's pushConstant resolves
// symbol_table before string_table and would otherwise rename raw .rodata
// constants ahead of the Action-side gating that segment (b) ports.
fn scan_rodata_dat_entries(
    rodata: &[u8],
    base_vaddr: u64,
    symbol_table: &HashMap<u64, String>,
) -> BTreeMap<u64, String> {
    let mut entries = BTreeMap::new();
    // Same manageable-section cap as the .data/.bss synthetic loop below.
    if rodata.len() as u64 > 0x10000 {
        return entries;
    }
    for off in 0..rodata.len() as u64 {
        let addr = base_vaddr + off;
        if !symbol_table.contains_key(&addr) {
            entries.insert(addr, synthetic_dat_name(addr));
        }
    }
    entries
}

// RUGRA-GLUE: hidden driver modes exercise process isolation without changing normal curl output.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let [_, mode, token, expected_parent] = args.as_slice() {
        if mode == DESCENDANT_MODE_ARG && valid_probe_token(token) {
            let expected_parent = expected_parent.parse::<i32>().unwrap_or_default();
            if expected_parent <= 1 {
                std::process::exit(WORKER_INVALID_REQUEST_EXIT);
            }
            run_descendant_probe(expected_parent);
        }
    }
    if args.get(1).map(String::as_str) == Some(WORKER_MODE_ARG) {
        let valid_args = match args.as_slice() {
            [_, mode] if mode == WORKER_MODE_ARG => true,
            [_, mode, label_arg, token]
                if mode == WORKER_MODE_ARG
                    && label_arg == WORKER_LABEL_ARG
                    && valid_probe_token(token) =>
            {
                true
            }
            _ => false,
        };
        if !valid_args {
            eprintln!("[WORKER-ERROR] invalid internal worker arguments");
            std::process::exit(WORKER_INVALID_REQUEST_EXIT);
        }
        std::process::exit(run_worker_entry());
    }
    if args.get(1).map(String::as_str) == Some(SELF_TEST_ARG) {
        let result = match args.as_slice() {
            [_, mode, token] if mode == SELF_TEST_ARG && valid_probe_token(token) => {
                run_timeout_isolation_self_test(token)
            }
            _ => Err(format!(
                "usage: {} {} <safe-token>",
                args.first().map(String::as_str).unwrap_or("curl_decompile"),
                SELF_TEST_ARG
            )),
        };
        if let Err(error) = result {
            eprintln!("timeout isolation self-test failed: {error}");
            std::process::exit(1);
        }
        return;
    }

    let mode = match args.as_slice() {
        [_] => DriverMode::All,
        [_, option, functions @ ..]
            if option == COMPARE_FUNCTION_ARG
                && !functions.is_empty()
                && functions.iter().all(|function| !function.is_empty()) =>
        {
            DriverMode::CompareFunctions(functions.to_vec())
        }
        [_, option, functions @ ..]
            if option == SELECT_FUNCTION_ARG
                && !functions.is_empty()
                && functions.iter().all(|function| !function.is_empty()) =>
        {
            DriverMode::SelectedFunctions(functions.to_vec())
        }
        _ => {
            eprintln!(
                "usage: {} [{} <function> ... | {} <function> ...]",
                args.first().map(String::as_str).unwrap_or("curl_decompile"),
                COMPARE_FUNCTION_ARG,
                SELECT_FUNCTION_ARG
            );
            std::process::exit(2);
        }
    };

    // Run in a thread with a large stack to avoid stack overflow from
    // deeply nested ActionGroup.perform recursion in the repeatapply pipeline.
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024) // 256MB
        .spawn(move || {
            if let Err(e) = run_main(mode) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        })
        .expect("Failed to spawn stack thread");
    child.join().expect("Worker thread panicked");
}

// RUGRA-GLUE: internal probe labels are argv data, never shell fragments.
fn valid_probe_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

// RUGRA-GLUE: a descendant fault probe inherits the worker group and dies if its direct parent disappears.
fn run_descendant_probe(expected_parent: i32) -> ! {
    let configured = unsafe { prctl(PR_SET_PDEATHSIG, SIGKILL as usize, 0, 0, 0) };
    let actual_parent = unsafe { getppid() };
    if configured != 0 || actual_parent != expected_parent {
        std::process::exit(WORKER_INVALID_REQUEST_EXIT);
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

// RUGRA-GLUE: converts a caught Rust panic into a bounded single-line worker diagnostic.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    let message = if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else {
        "non-string panic payload".to_string()
    };
    message
        .replace(['\n', '\r'], " ")
        .chars()
        .take(512)
        .collect()
}

// RUGRA-GLUE: the worker executes on the same large stack as the former in-process analysis thread.
fn run_worker_entry() -> i32 {
    let worker = match std::thread::Builder::new()
        .name("curl-function-worker".to_string())
        .stack_size(256 * 1024 * 1024)
        .spawn(|| panic::catch_unwind(AssertUnwindSafe(run_worker_from_stdin)))
    {
        Ok(worker) => worker,
        Err(error) => {
            eprintln!("[WORKER-ERROR] unable to create large-stack worker: {error}");
            return WORKER_ERROR_EXIT;
        }
    };

    let payload = match worker.join() {
        Ok(Ok(Ok(payload))) => payload,
        Ok(Ok(Err(WorkerFailure::InvalidRequest(error)))) => {
            eprintln!("[WORKER-PROTOCOL] {error}");
            return WORKER_INVALID_REQUEST_EXIT;
        }
        Ok(Ok(Err(WorkerFailure::Job(error)))) => {
            eprintln!("[WORKER-ERROR] {error}");
            return WORKER_ERROR_EXIT;
        }
        Ok(Err(payload)) | Err(payload) => {
            eprintln!("[WORKER-PANIC] {}", panic_message(payload.as_ref()));
            return WORKER_PANIC_EXIT;
        }
    };

    let response = match bincode::serialize(&payload) {
        Ok(response) if response.len() <= MAX_WORKER_STDOUT_BYTES => response,
        Ok(response) => {
            eprintln!(
                "[WORKER-ERROR] encoded response is too large: {} bytes",
                response.len()
            );
            return WORKER_OUTPUT_EXIT;
        }
        Err(error) => {
            eprintln!("[WORKER-ERROR] unable to encode response: {error}");
            return WORKER_OUTPUT_EXIT;
        }
    };
    let mut stdout = io::stdout().lock();
    if let Err(error) = stdout.write_all(&response).and_then(|()| stdout.flush()) {
        eprintln!("[WORKER-ERROR] response channel disconnected: {error}");
        return WORKER_OUTPUT_EXIT;
    }
    0
}

// RUGRA-GLUE: bounded binary protocol prevents partial stdout from being mistaken for C output.
fn run_worker_from_stdin() -> Result<WorkerPayload, WorkerFailure> {
    let mut encoded = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_WORKER_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|error| {
            WorkerFailure::InvalidRequest(format!("unable to read worker request: {error}"))
        })?;
    if encoded.len() > MAX_WORKER_REQUEST_BYTES {
        return Err(WorkerFailure::InvalidRequest(format!(
            "worker request exceeds {} bytes",
            MAX_WORKER_REQUEST_BYTES
        )));
    }
    let job: WorkerJob = bincode::deserialize(&encoded).map_err(|error| {
        WorkerFailure::InvalidRequest(format!("invalid worker request: {error}"))
    })?;
    run_worker_job(&job)
}

// RUGRA-GLUE: one worker job owns all mutable decompiler state for exactly one function.
fn run_worker_job(job: &WorkerJob) -> Result<WorkerPayload, WorkerFailure> {
    match job {
        WorkerJob::InferPrototype {
            protocol_version,
            request,
        } => {
            if *protocol_version != WORKER_PROTOCOL_VERSION {
                return Err(WorkerFailure::InvalidRequest(format!(
                    "worker protocol version mismatch: expected {}, received {}",
                    WORKER_PROTOCOL_VERSION, protocol_version
                )));
            }
            infer_prototype_request(request)
                .map(WorkerPayload::Prototype)
                .map_err(WorkerFailure::Job)
        }
        WorkerJob::Decompile {
            protocol_version,
            request,
        } => {
            if *protocol_version != WORKER_PROTOCOL_VERSION {
                return Err(WorkerFailure::InvalidRequest(format!(
                    "worker protocol version mismatch: expected {}, received {}",
                    WORKER_PROTOCOL_VERSION, protocol_version
                )));
            }
            decompile_request(request)
                .map(WorkerPayload::Decompile)
                .map_err(WorkerFailure::Job)
        }
        WorkerJob::Probe {
            protocol_version,
            probe,
        } => {
            if *protocol_version != WORKER_PROTOCOL_VERSION {
                return Err(WorkerFailure::InvalidRequest(format!(
                    "worker protocol version mismatch: expected {}, received {}",
                    WORKER_PROTOCOL_VERSION, protocol_version
                )));
            }
            let token = match probe {
                IsolationProbe::Success { token }
                | IsolationProbe::Hang { token }
                | IsolationProbe::Panic { token }
                | IsolationProbe::NonZero { token }
                | IsolationProbe::OutputDisconnect { token } => token,
            };
            if !valid_probe_token(token) {
                return Err(WorkerFailure::InvalidRequest(
                    "invalid isolation probe token".to_string(),
                ));
            }
            match probe {
                IsolationProbe::Success { token } => Ok(WorkerPayload::ProbeSuccess(format!(
                    "probe-success:{token}"
                ))),
                IsolationProbe::Hang { token } => {
                    let descendant = std::env::current_exe()
                        .map_err(|error| {
                            WorkerFailure::Job(format!(
                                "unable to resolve probe executable: {error}"
                            ))
                        })?
                        .to_owned();
                    let descendant = Command::new(descendant)
                        .arg(DESCENDANT_MODE_ARG)
                        .arg(token)
                        .arg(std::process::id().to_string())
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .map_err(|error| {
                            WorkerFailure::Job(format!(
                                "unable to spawn descendant probe: {error}"
                            ))
                        })?;
                    let worker_pid = std::process::id();
                    let process_group = unsafe { getpgid(worker_pid as i32) };
                    eprintln!(
                        "[TIMEOUT-PROBE] ready token={token} worker_pid={worker_pid} descendant_pid={} pgid={process_group}",
                        descendant.id()
                    );
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                IsolationProbe::Panic { token } => {
                    panic!("intentional timeout-isolation probe panic: {token}")
                }
                IsolationProbe::NonZero { token } => {
                    Err(WorkerFailure::Job(format!(
                        "intentional timeout-isolation failure: {token}"
                    )))
                }
                IsolationProbe::OutputDisconnect { .. } => std::process::exit(0),
            }
        }
    }
}

// RUGRA-GLUE: re-validates a controller-supplied target against the ELF symbol table before the worker trusts its coordinates.
fn elf_symbol_matches(elf: &goblin::elf::Elf, target: &WorkerTarget) -> bool {
    elf.syms.iter().any(|symbol| {
        symbol.st_value == target.vaddr
            && symbol.st_size as usize == target.size
            && elf.strtab.get_at(symbol.st_name) == Some(target.name.as_str())
    })
}

// FUNCPROTO-MODEL-BIND-0001: locked x86-64 address-space facts shared by the
// spec host (index-ordered like the oracle's AddrSpaceManager enumeration —
// only name/highest are consulted by the parse).
const SPEC_SPACES: [(&str, u64); 9] = [
    ("const", u64::MAX),
    ("OTHER", u64::MAX),
    ("unique", 0xffff_ffff),
    ("ram", u64::MAX),
    ("register", 0xffff_ffff),
    ("fspec", u64::MAX),
    ("iop", u64::MAX),
    ("join", 0xffff_ffff),
    ("stack", u64::MAX),
];

// FUNCPROTO-MODEL-BIND-0001: `Translate::getUniqueStart(Translate::INJECT)`
// for the locked x86-64 .sla (0x200 + the .sla unique base; verified against
// the locked oracle run in the cspec text-ingest fixture).
const SPEC_UNIQUE_INJECT_BASE: u64 = 0x364_400;

// FUNCPROTO-MODEL-BIND-0001: language host for the worker-side compiler-spec
// parse — registers from the real .sla, spaces from the locked table.
struct WorkerSpecHost {
    registers: HashMap<String, rugra::fspec::VarnodeData>,
}

fn spec_space_by_name(name: &str) -> Option<rugra::space::AddressSpace> {
    use rugra::space::AddressSpace;
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

impl rugra::arch::SpecQuery for WorkerSpecHost {
    fn get_register(&self, name: &str) -> Option<rugra::fspec::VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<rugra::space::AddressSpace> {
        spec_space_by_name(name)
    }
    fn space_highest(&self, spc: rugra::space::AddressSpace) -> u64 {
        let name = match spc {
            rugra::space::AddressSpace::Const => "const",
            rugra::space::AddressSpace::Other(_) => "OTHER",
            rugra::space::AddressSpace::Unique => "unique",
            rugra::space::AddressSpace::Ram => "ram",
            rugra::space::AddressSpace::Register => "register",
            rugra::space::AddressSpace::Stack => "stack",
            rugra::space::AddressSpace::Iop => "iop",
            rugra::space::AddressSpace::Join => "join",
            rugra::space::AddressSpace::Overlay => "OTHER",
        };
        SPEC_SPACES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, highest)| *highest)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        SPEC_UNIQUE_INJECT_BASE
    }
}

impl rugra::pcodeparse::SleighSymbolLookup for WorkerSpecHost {
    fn find_symbol(&self, name: &str) -> Option<rugra::pcodeparse::SleighSymbol> {
        self.registers.get(name).map(|vd| rugra::pcodeparse::SleighSymbol {
            name: name.to_string(),
            kind: rugra::pcodeparse::SleightSymbolKind::Varnode(rugra::varnode::VarnodeData {
                space: vd.space,
                offset: vd.offset,
                size: vd.size.max(0) as usize,
            }),
        })
    }
}

// FUNCPROTO-MODEL-BIND-0001: worker-local Architecture built from the locked
// production compiler spec.  Ghidra's BfdArchitecture::init completes
// (Architecture::parseCompilerConfig establishes `defaultfp`,
// architecture.cc:1239-1351, with the "No default prototype specified" guard
// at cc:1337-1341) before any Funcdata is constructed, so the named-ctor
// chain `Funcdata::Funcdata -> funcp.setScope -> setModel(defaultfp)`
// (funcdata.cc:48-69, fspec.cc:3879-3884) always observes a resolved model.
// The worker mirrors that ordering: the Architecture is built once per
// worker process and attached to the Funcdata before any prototype overlay
// (DWARF/PLT) can lock a modelless prototype.
// CURL-CSPEC-SNAPSHOT-0001 residual: the spec bytes are read from the
// process cwd (`sleigh_specs/x86-64-gcc.cspec`, same convention as the
// default SLEIGH asset path) instead of being carried and
// fingerprint-verified inside the worker request.
fn worker_architecture() -> Result<std::sync::Arc<rugra::arch::Architecture>, String> {
    worker_architecture_with_program_db(None, None)
}

// B3-COREACTION-CONSTANTPTR-0001 (b): the decompile entry hands the
// first-init builder the Program-DB symbol graph (the Funcdata query
// channel's data source: Architecture::symboltab owns the Database in
// Ghidra) and the loader-backed string manager source (Ghidra's
// buildStringManager reads through the loader, architecture.cc:1391-1401
// — buildLoader precedes buildStringManager). One worker process serves
// one job, so the first initializer fixes these for the process.
fn worker_architecture_with_program_db(
    symboltab: Option<std::sync::Arc<std::sync::RwLock<rugra::database::Database>>>,
    loader: Option<std::sync::Arc<dyn rugra::loadimage::LoadImage>>,
) -> Result<std::sync::Arc<rugra::arch::Architecture>, String> {
    static CACHE: std::sync::OnceLock<
        Result<std::sync::Arc<rugra::arch::Architecture>, String>,
    > = std::sync::OnceLock::new();
    if let Some(cached) = CACHE.get() {
        return cached.clone();
    }
    let built = build_worker_architecture(symboltab, loader);
    // One initializer per worker process (one job per process); a losing
    // racing writer is impossible by construction, the set result is still
    // checked for symmetry with the OnceLock contract.
    let _ = CACHE.set(built.clone());
    built
}

fn build_worker_architecture(
    symboltab: Option<std::sync::Arc<std::sync::RwLock<rugra::database::Database>>>,
    loader: Option<std::sync::Arc<dyn rugra::loadimage::LoadImage>>,
) -> Result<std::sync::Arc<rugra::arch::Architecture>, String> {
    (|| {
        let cspec_bytes = fs::read("sleigh_specs/x86-64-gcc.cspec")
            .map_err(|error| format!("unable to read compiler spec: {error}"))?;
        let sleigh = rugra::sleigh_ffi::SleighCtx::new()
            .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
        let mut registers = HashMap::new();
        let mut register_xref: Vec<(i32, u64, i32, String)> = Vec::new();
        for index in 0..sleigh.num_registers() {
            let Some((name, space, offset, size)) = sleigh.register_info(index) else {
                continue;
            };
            let Ok(space_id) = u8::try_from(space) else {
                continue;
            };
            // B3-VARMAP-REGNAME-0001: the same enumeration feeds the
            // Architecture register_xref (SleighBase::getAllRegisters →
            // varnode_xref, sleighbase.cc:182-186) that
            // Architecture::get_register_name (sleighbase.cc:144-168) walks
            // for ScopeInternal::buildVariableName's register queries.
            register_xref.push((space, offset, size, name.to_string()));
            registers.insert(
                name.to_string(),
                rugra::fspec::VarnodeData {
                    space: rugra::space::AddressSpace::from_id(space_id),
                    offset,
                    size,
                },
            );
        }
        let host = Arc::new(WorkerSpecHost { registers });
        let mut store = rugra::marshal::DocumentStorage::new();
        let doc = store
            .parse_document(&cspec_bytes)
            .map_err(|error| format!("compiler spec parse failed: {error}"))?;
        let root = doc
            .root
            .clone()
            .ok_or_else(|| "compiler spec has no root element".to_string())?;
        if root
            .read()
            .map_err(|_| "compiler spec element lock poisoned".to_string())?
            .name
            != "compiler_spec"
        {
            return Err("compiler spec root is not compiler_spec".to_string());
        }
        store.register_tag(&root);
        let mut arch = rugra::arch::Architecture::new();
        arch.archid = "x86:LE:64:default".to_string();
        // B3-VARMAP-REGNAME-0001: install the SLEIGH register
        // cross-reference (SleighBase::buildXrefs → varnode_xref,
        // sleighbase.cc:79-96, materialized through getAllRegisters at
        // :182-186) so Architecture::get_register_name — the
        // sleighbase.cc:144-168 port ScopeLocal::get_register_name
        // delegates to — answers with the oracle's register names
        // (XMM0_Qa at register:0x110, CW at 0x3c, ...), replacing the
        // former 25-entry hardwired GPR table whose gaps produced
        // `in_register_00000110`-style raw leaks.
        arch.set_register_xref(register_xref);
        // Ghidra: sleigh_arch.cc:241-245 SleighArchitecture::buildCommentDB
        // (UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ①). Architecture::init
        // (architecture.cc:1391-1414) calls buildCommentDB at :1400, before
        // restoreFromSpec (:1405) — this function is Rugra's worker-side
        // equivalent of that init sequence (cspec parse below is the
        // restoreFromSpec step), so the in-memory CommentDatabaseInternal is
        // allocated at the same point here. Every Funcdata::warningHeader /
        // warning (funcdata.cc:135/119) — including ActionPrototypeWarnings'
        // "Unknown calling convention" comments (coreaction.cc:4908) — then
        // stores into this database instead of falling back to stderr.
        arch.set_commentdb(std::sync::Arc::new(std::sync::RwLock::new(
            rugra::comment::CommentDatabaseInternal::new(),
        )));
        // Ghidra: architecture.cc:1391-1414 Architecture::init builds the
        // TypeFactory unconditionally (buildTypegrp at :1398, before
        // buildCommentDB :1400) — every Funcdata sees `data.getArch()->types`.
        // RULE-PTRARITH-ADDTREE-0001: without a factory, ActionInferTypes'
        // PTRSUB/PTRADD/INT_ADD pointer arms (TypeOpPtrsub::propagateType →
        // propagateAddIn2Out → downChain) silently dead-end, so field-pointer
        // types (URLGlob* → char** literal / URLPattern* pattern) never reach
        // RulePtrArith and `INT_ADD(param_copy, 0x38)`→LOAD stays raw.
        // The data_organization decode + setup_sizes mirror
        // parseCompilerConfig's ELEM_DATA_ORGANIZATION arm (architecture.cc:1269)
        // and its trailing types->setupSizes() (architecture.cc:1350), using
        // the same locked cspec DOM parsed above.
        {
            let mut types = rugra::type_system::typefactory::TypeFactory::new(8);
            let data_org = root
                .read()
                .map_err(|_| "compiler spec element lock poisoned".to_string())?
                .children
                .iter()
                .find(|child| {
                    child
                        .read()
                        .map(|element| element.name == "data_organization")
                        .unwrap_or(false)
                })
                .cloned()
                .ok_or_else(|| "compiler spec has no data_organization".to_string())?;
            let registry = Arc::new(std::sync::RwLock::new(
                rugra::marshal::IdRegistry::new(),
            ));
            let mut decoder =
                rugra::marshal::TreeDecoder::new(data_org, registry);
            types.decode_data_organization(&mut decoder);
            types.setup_sizes(&rugra::type_system::typefactory::SizeArchInputs {
                stack_spacebase_size: Some(8),
                default_data_space_addr_size: 8,
                default_size: 8,
                far_pointer: None,
            });
            arch.set_types(Arc::new(std::sync::RwLock::new(types)));
        }
        let mut inject_lib =
            rugra::pcodeinject::PcodeInjectLibrary::new(SPEC_UNIQUE_INJECT_BASE);
        inject_lib.set_sleigh_lookup(host.clone());
        arch.pcodeinjectlib = Some(Arc::new(std::sync::RwLock::new(inject_lib)));
        arch.userops = Some(Arc::new(std::sync::RwLock::new(
            rugra::userop::UserOpManage::new(),
        )));
        // ARCH-CONTEXT-TRACKED-0001: Architecture::restoreFromSpec runs
        // parseProcessorConfig BEFORE parseCompilerConfig
        // (architecture.cc:639->641); its ELEM_CONTEXT_DATA arm
        // (architecture.cc:1190) feeds ContextInternal::decodeFromSpec.
        // The full pspec text pipeline is the ARCH-0001 residual; this
        // minimal wiring parses the locked x86-64.pspec bytes with the
        // worker's DocumentStorage and hands every <context_data> child
        // to the mapped Architecture::decode_context_data (same DOM
        // extraction model as tests/oracle/arch_context_tracked_1204.rs),
        // making the tracked registers (DF=0) queryable when
        // ActionConstbase runs (coreaction.cc:692).
        let pspec_bytes = fs::read("sleigh_specs/x86-64.pspec")
            .map_err(|error| format!("unable to read processor spec: {error}"))?;
        let pspec_doc = store
            .parse_document(&pspec_bytes)
            .map_err(|error| format!("processor spec parse failed: {error}"))?;
        let pspec_root = pspec_doc
            .root
            .clone()
            .ok_or_else(|| "processor spec has no root element".to_string())?;
        if pspec_root
            .read()
            .map_err(|_| "processor spec element lock poisoned".to_string())?
            .name
            != "processor_spec"
        {
            return Err("processor spec root is not processor_spec".to_string());
        }
        let pspec_children: Vec<_> = pspec_root
            .read()
            .map_err(|_| "processor spec element lock poisoned".to_string())?
            .children
            .clone();
        let pspec_registry = Arc::new(std::sync::RwLock::new(rugra::marshal::IdRegistry::new()));
        for child in pspec_children {
            let child_name = child
                .read()
                .map_err(|_| "processor spec element lock poisoned".to_string())?
                .name
                .clone();
            if child_name != "context_data" {
                continue;
            }
            let mut decoder =
                rugra::marshal::TreeDecoder::new(child, pspec_registry.clone());
            arch.decode_context_data(&mut decoder, host.as_ref())
                .map_err(|error| format!("processor spec context_data decode failed: {error}"))?;
        }
        arch.parse_compiler_config(&mut store, host.as_ref(), 8)
            .map_err(|error| format!("compiler spec parse failed: {error}"))?;
        if arch.defaultfp.is_none() {
            return Err("No default prototype specified".to_string());
        }
        // B3-COREACTION-CONSTANTPTR-0001 (b): Ghidra's Architecture owns its
        // symboltab, loader-backed string manager and TypeFactory from init
        // (architecture.cc:1391-1414: buildTypeFactory -> buildStringManager
        // precede any Funcdata). Install the query-channel Database (the
        // Funcdata query_container_parent_scope data source), the loader and
        // its StringManager (ruleaction.cc:7375's isString backend), and the
        // canonical TypeFactory (TYPE-WIRING-0001) so spacebaseConstant's
        // output typing (funcdata.cc:365-366/415) resolves through the same
        // factory the printer observes.
        if let Some(db) = symboltab.clone() {
            arch.symboltab = Some(db);
        }
        if let Some(loader) = loader {
            arch.loader = Some(loader);
            arch.build_string_manager();
        }
        // MAINDIFF-UNIQLEAK-0001: seed the Architecture's `symboltab`
        // (`Database`, database.rs) global scope with the binary's sized
        // global Symbols — DWARF static variables (typed) plus ELF OBJECT
        // symbols — mirroring the Ghidra front-end's Program symbol table
        // that `Scope::queryProperties`' parent-scope walk
        // (database.cc:943 stackContainer, reached from
        // `Funcdata::linkSymbol` funcdata_varnode.cc:1169) reads from.
        // Seeds into the query-channel Database when the front-end supplied
        // one (B3 rodata entries stay intact); a fresh Database otherwise.
        // Without entries in this channel the parent-walk finds nothing,
        // and linkSymbol minted a dead ScopeLocal `in_ram_` symbol for
        // every global-sourced heritage input (37 dead declarations in
        // main alone; the golden declares none because the global Symbol
        // absorbs them). CWD-relative read, same pattern as the
        // sleigh_specs loads above; on read failure the channel stays
        // empty and behavior falls back to the symbol_table proxy.
        {
            if arch.symboltab.is_none() {
                arch.symboltab = Some(Arc::new(std::sync::RwLock::new(
                    rugra::database::Database::new(false),
                )));
            }
            if let Ok(image) = fs::read("examples/curl") {
            let db_arc = arch.symboltab.clone().unwrap();
            let mut db = db_arc.write().unwrap();
            let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
            if let Ok(globals) = DebugGlobalDatabase::parse_elf(&image) {
                for (&address, global) in globals.iter() {
                    let size = global.data_type.get_size().max(1) as i32;
                    let scope = db.global_scope_id;
                    let _ = db.add_symbol_mapped(
                        scope,
                        &global.name,
                        Some(global.data_type.clone()),
                        Address::new(address),
                        size,
                    );
                    seen.insert(address);
                }
            }
            if let Ok(Object::Elf(elf)) = Object::parse(&image) {
                for sym in elf.syms.iter() {
                    let is_object = goblin::elf::sym::st_type(sym.st_info)
                        == goblin::elf::sym::STT_OBJECT;
                    if !is_object || sym.st_size == 0 || sym.is_import() {
                        continue;
                    }
                    let address = sym.st_value;
                    if address == 0 || !seen.insert(address) {
                        continue;
                    }
                    let Some(name) = elf.strtab.get_at(sym.st_name) else {
                        continue;
                    };
                    if name.is_empty() {
                        continue;
                    }
                    let size = sym.st_size as i32;
                    let dtype = std::sync::Arc::new(rugra::type_system::datatype::Datatype::Base(
                        rugra::type_system::datatype::TypeBase::new(
                            format!("undefined{size}"),
                            size as usize,
                            rugra::type_system::datatype::TypeMetatype::Unknown,
                        ),
                    ));
                    let scope = db.global_scope_id;
                    let _ = db.add_symbol_mapped(
                        scope,
                        name,
                        Some(dtype),
                        Address::new(address),
                        size,
                    );
                }
            }
            }
        }
        let types = arch.ensure_types();
        // The raw shared_default factory starts with an empty alignment
        // map; the arch-attach guard (type.cc: "if (alignMap.empty())
        // setDefaultAlignmentMap()", mirrored at typefactory.rs:2437) runs
        // when a spec-decoded factory meets its Architecture. The worker's
        // canonical factory takes the same default map before any
        // getBase/findAdd consumer runs. The spacebase scope source gives
        // TypeSpacebase::get_sub_type the global scope snapshot Ghidra
        // resolves dynamically (getMap, type.cc:2935-2945).
        {
            let mut tf = types.write().unwrap();
            tf.set_default_alignment_map();
            tf.set_spacebase_scope_source(symboltab.clone());        }
        Ok(Arc::new(arch))
    })()
}

// RUGRA-GLUE: reconstructs the original per-function prototype pre-pass inside the cancellable worker.
fn infer_prototype_request(request: &PrototypeRequest) -> Result<usize, String> {
    let obj = Object::parse(&request.binary_image)
        .map_err(|error| format!("unable to parse prototype worker ELF image: {error}"))?;
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => return Err("prototype worker input is not an ELF image".to_string()),
    };
    let target = &request.target;
    if target.symbol_backed && !elf_symbol_matches(elf, target) {
        return Err(format!(
            "prototype target no longer matches ELF symbol: {} @ 0x{:x} size {}",
            target.name, target.vaddr, target.size
        ));
    }

    let start = usize::try_from(target.file_offset)
        .map_err(|_| "prototype target file offset does not fit usize".to_string())?;
    if start >= request.binary_image.len() {
        return Err(format!(
            "prototype target file offset is outside image: 0x{:x}",
            target.file_offset
        ));
    }
    let end = start
        .saturating_add(target.size.min(4096))
        .min(request.binary_image.len());
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm
        .disassemble(&request.binary_image[start..end], Address::new(target.vaddr))
        .map_err(|error| format!("prototype disassembly failed: {error}"))?;

    let mut lifter = X86Lifter::new();
    let mut raw_ops = Vec::new();
    for instruction in &instructions {
        let mut ops = lifter.lift(instruction);
        for op in &mut ops {
            op.set_seq_num(rugra::address::SeqNum::new(instruction.address, 0));
        }
        raw_ops.extend(ops);
    }

    let mut fd = Funcdata::new(&target.name, Address::new(target.vaddr), target.size as i32);
    // FUNCPROTO-MODEL-BIND-0001: attach the worker-local Architecture before
    // any analysis — the named-ctor model binding (FuncProto::setScope ->
    // setModel(defaultfp)) rides on it.
    fd.set_arch(worker_architecture()?);
    fd.inject_raw_ops(&raw_ops);
    fd.run_heritage_direct();
    use rugra::action::Action;
    let mut infer = rugra::coreaction::ActionInferParams::new();
    let _ = infer.apply(&mut fd);
    Ok(fd.funcp.num_params())
}

// RUGRA-GLUE: reconstructs the former thread closure from a complete immutable request snapshot.
fn decompile_request(request: &DecompileRequest) -> Result<Option<String>, String> {
    let obj = Object::parse(&request.binary_image)
        .map_err(|error| format!("unable to parse worker ELF image: {error}"))?;
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => return Err("worker input is not an ELF image".to_string()),
    };
    let target = &request.target;
    if target.symbol_backed && !elf_symbol_matches(elf, target) {
        return Err(format!(
            "worker target no longer matches ELF symbol: {} @ 0x{:x} size {}",
            target.name, target.vaddr, target.size
        ));
    }
    let Some(section) = elf.section_headers.iter().find(|section| {
        target.vaddr >= section.sh_addr
            && target.vaddr < section.sh_addr.saturating_add(section.sh_size)
    }) else {
        return Err(format!("no ELF section contains 0x{:x}", target.vaddr));
    };
    let expected_file_offset = section.sh_offset + (target.vaddr - section.sh_addr);
    if expected_file_offset != target.file_offset {
        return Err(format!(
            "worker target file offset mismatch: expected 0x{:x}, received 0x{:x}",
            expected_file_offset, target.file_offset
        ));
    }
    let section_start = usize::try_from(section.sh_offset)
        .map_err(|_| "ELF section offset does not fit usize".to_string())?;
    let section_end_u64 = section
        .sh_offset
        .checked_add(section.sh_size)
        .ok_or_else(|| "ELF section range overflow".to_string())?;
    let section_end = usize::try_from(section_end_u64)
        .map_err(|_| "ELF section end does not fit usize".to_string())?;
    let section_image = request
        .binary_image
        .get(section_start..section_end)
        .ok_or_else(|| "ELF section range is outside the input image".to_string())?;

    // B3-COREACTION-CONSTANTPTR-0001 (b): the Program-DB symbol graph
    // ActionConstantPtr queries (coreaction.cc:1151 via the Funcdata
    // query-channel). Ghidra's platform analyzers populate the global scope
    // before decompilation: the ASCII strings analyzer types discovered
    // strings as char arrays, referenced-but-untyped data gets DAT labels
    // with undefined type. The driver mirrors that split using the a0
    // `.rodata` DAT label layer: string-classified addresses (the request's
    // string_entries, already gated by stringmanage.cc's UTF-8
    // checkCharacters) carry `char[len]`, everything else stays untyped.
    // The `.rodata` extent registers the readonly property range
    // (`Database::setPropertyRange(Varnode::readonly, ...)`, the loader
    // channel of architecture.cc:1371-1383) RulePtrsubCharConstant /
    // PrintC::pushPtrCharConstant consume via isReadOnly.
    // MAINDIFF-GLOBAL-0001: the DWARF globals layer parses before the
    // Program-DB construction — its names/types feed the DB merge below.
    let debug_globals = DebugGlobalDatabase::parse_elf(&request.binary_image)
        .map_err(|error| format!("unable to import DWARF globals: {error}"))?;
    let program_db: Option<std::sync::Arc<std::sync::RwLock<rugra::database::Database>>> =
        if request.rodata_dat_entries.is_empty() && request.db_symbol_entries.is_empty() {
            None
        } else {
            let db_arc = std::sync::Arc::new(std::sync::RwLock::new(
                rugra::database::Database::new(false),
            ));
            let string_addrs: HashMap<u64, &String> = request
                .string_entries
                .iter()
                .map(|(address, value)| (*address, value))
                .collect();
            // MAINDIFF-GLOBAL-0001: the DWARF display-name overlay —
            // function-static variables take their enclosing function's
            // namespace (Ghidra's DWARF analyzer imports them into the
            // function namespace; locked witnesses: my_get_token::save at
            // 0x17510, next_url::beenhere at 0x17518). DWARF names win over
            // the ELF importer layer at the same address.
            let dwarf_display_names: HashMap<u64, (String, std::sync::Arc<rugra::type_system::datatype::Datatype>, i32)> = debug_globals
                .iter()
                .map(|(&address, global)| {
                    let name = match &global.parent_function {
                        Some(parent) => format!("{}::{}", parent, global.name),
                        None => global.name.clone(),
                    };
                    (address, (name, global.data_type.clone(), global.data_type.get_size() as i32))
                })
                .collect();
            {
                let mut db = db_arc.write().unwrap();
                let global = db.global_scope_id;
                // The global scope owns the whole ram space (cspec <global>;
                // stack locals live in function-local scopes Ghidra attaches
                // later, none exist in this projection).
                if let Some(rng) = rugra::address::Range::new(
                    Address::new(0),
                    Address::new(u64::MAX),
                ) {
                    db.add_range(global, rng);
                }
                let mut typed = 0usize;
                // The strings-analyzer split: untyped referenced data gets
                // the DAT label's undefined8 (pointer-slot width — see the
                // entry_size note below); string-classified addresses get
                // char[len+1].
                let undefined8 = rugra::type_system::typefactory::TypeFactory::shared_default()
                    .write()
                    .unwrap()
                    .get_base(8, rugra::type_system::datatype::TypeMetatype::Unknown);
                // STRCONST-SPANNONOVERLAP: the oracle's Program DB Data layout
                // is strictly non-overlapping (Ghidra cannot create Data over
                // bytes another Data covers), and the strings-analyzer
                // char-array Data owns its whole span [S, S+len+1) — run
                // bytes plus NUL. A per-byte DAT entry inside that span, or
                // an 8-byte slot entry crossing the string start, would win
                // Scope::findContainer's smallest-containing-entry pick
                // (database.cc:2250-2270: containing entries ordered latest-
                // start-first, smallest size wins) over the string entry at
                // S — shadowing the char-array hit ActionConstantPtr's
                // cc:1152-1160 string arm (and RulePtrsubCharConstant
                // downstream) need. Witnesses: the hugehelp folding strings
                // at 0xea40/0x11270/0x13ad0 each start right after padding
                // NULs (0xea3f/...) whose per-byte DAT_0010ea3f-class
                // entries previously spanned the string start and encoded
                // the constant as `&DAT_prev + 1` (undefined8, not char*),
                // breaking the fold. The skip/clip restores the oracle
                // property: at a string start the only containing entry is
                // the string entry.
                let mut string_starts: Vec<u64> = string_addrs.keys().copied().collect();
                string_starts.sort_unstable();
                for (address, name) in &request.rodata_dat_entries {
                    let dtype = string_addrs.get(address).map(|value| {
                        // strings analyzer product: char array over the run
                        // including its NUL terminator.
                        let char_base = rugra::type_system::datatype::TypeBase::new_char(
                            "char".to_string(),
                            rugra::type_system::datatype::TypeMetatype::Int,
                        );
                        let len = value.len() + 1;
                        std::sync::Arc::new(rugra::type_system::datatype::Datatype::Array(
                            rugra::type_system::datatype::TypeArray {
                                base: rugra::type_system::datatype::TypeBase::new(
                                    String::new(),
                                    len,
                                    rugra::type_system::datatype::TypeMetatype::Array,
                                ),
                                array_of: std::sync::Arc::new(
                                    rugra::type_system::datatype::Datatype::Base(char_base),
                                ),
                                num_elements: len,
                            },
                        ))
                    });
                    if dtype.is_some() {
                        typed += 1;
                    }
                    let is_string = string_addrs.contains_key(address);
                    let dtype =
                        dtype.or_else(|| undefined8.clone());
                    if !is_string {
                        // STRCONST-SPANNONOVERLAP: greatest admitted string
                        // start <= address (rodata_dat_entries iterates in
                        // BTreeMap order, but the span test needs the
                        // predecessor regardless).
                        let pos = string_starts.partition_point(|&s| s <= *address);
                        if pos > 0 {
                            let start = string_starts[pos - 1];
                            let span_end = start
                                + string_addrs[&start].len() as u64
                                + 1; // run bytes + NUL, exclusive
                            // Interior byte of a string Data: no oracle
                            // counterpart (the string entry owns it) — skip.
                            if *address < span_end {
                                continue;
                            }
                        }
                    }
                    // Non-string referenced .rodata data takes the pointer
                    // slot width (8): every non-string reference in this
                    // corpus is a pointer reference (golden witnesses
                    // DAT_00107178/DAT_00107180 are adjacent 8-byte slots),
                    // and the oracle's mapGlobals never reports the
                    // "overlap smaller symbols" header
                    // (funcdata_varnode.cc:1717) — which a 1-byte entry
                    // under an 8-byte persist group would trigger.
                    // STRCONST-SPANNONOVERLAP: clipped so the span cannot
                    // cross the next string start (an oracle Data can never
                    // overlap the string Data's first byte).
                    let mut entry_size = if is_string {
                        dtype.as_ref().map(|t| t.get_size() as i32).unwrap_or(1)
                    } else {
                        8
                    };
                    if !is_string {
                        let pos = string_starts.partition_point(|&s| s <= *address);
                        if let Some(&next_start) = string_starts.get(pos) {
                            entry_size = entry_size.min((next_start - *address) as i32);
                        }
                    }
                    let symbol_id =
                        db.add_symbol_mapped(global, name, dtype, Address::new(*address), entry_size);
                    if let Some(symbol_id) = symbol_id {
                        // MAINDIFF-STRCONST-0001 (a): the strings-analyzer
                        // Data carries a LOCKED char-array type (the
                        // ATTRIB_TYPELOCK channel of Symbol::decodeHeader,
                        // database.cc:439-442), so
                        // Funcdata::spacebaseConstant's `sym->isTypeLocked()`
                        // (funcdata.cc:416) keeps the PTRSUB output's
                        // char-pointer type locked against later type
                        // propagation, letting RulePtrsubCharConstant's
                        // charPrint guard pass.
                        if string_addrs.contains_key(address) {
                            db.set_symbol_flag(
                                global,
                                symbol_id,
                                rugra::database::symbol_flags::TYPELOCK,
                                true,
                            );
                        }
                        // (b): every global in the read-only `.rodata`
                        // memory block carries Varnode::readonly on its
                        // symbol (ATTRIB_READONLY, database.cc:435-438) —
                        // the entry-hit arm of Scope::queryProperties
                        // (database.cc:1273) folds it into the readonly
                        // answers RulePtrsubCharConstant (ruleaction.cc:
                        // 7372) and PrintC::pushPtrCharConstant
                        // (printc.cc:1709) consume.
                        db.set_symbol_flag(
                            global,
                            symbol_id,
                            rugra::database::symbol_flags::READONLY,
                            true,
                        );
                    }
                }
                // MAINDIFF-GLOBAL-0001: the global symbol layer — ELF OBJECT
                // symbols, GOT PTR_ labels, .data PTR_DAT_ labels. Entries
                // whose address is DWARF-covered are skipped: the DWARF
                // layer below installs the oracle's final name + real type
                // at that address (one entry per address keeps
                // queryContainer's smallest-entry pick unambiguous).
                let mut seeded_db_symbols = 0usize;
                // `undefined *`: pointer over the oracle's named 1-byte
                // "undefined" core type (golden witness `(undefined *)0x0`;
                // Ghidra's PTR_ labels are pointers by construction).
                let undefined_star = {
                    let base = std::sync::Arc::new(
                        rugra::type_system::datatype::Datatype::Base(
                            rugra::type_system::datatype::TypeBase::new(
                                "undefined".to_string(),
                                1,
                                rugra::type_system::datatype::TypeMetatype::Unknown,
                            ),
                        ),
                    );
                    rugra::type_system::typefactory::TypeFactory::shared_default()
                        .write()
                        .unwrap()
                        .get_type_pointer_default(base)
                };
                for &(address, ref name, size, pointer_slot) in &request.db_symbol_entries {
                    if dwarf_display_names.contains_key(&address) {
                        continue;
                    }
                    let dtype = if pointer_slot {
                        Some(undefined_star.clone())
                    } else {
                        undefined8.clone()
                    };
                    db.add_symbol_mapped(global, name, dtype, Address::new(address), size.max(1));
                    seeded_db_symbols += 1;
                }
                // The DWARF layer: real names + real Datatypes (config ->
                // Configurable 304B with member offsets, glob_buffer ->
                // char[4096], ...).
                for (&address, (name, dtype, size)) in &dwarf_display_names {
                    db.add_symbol_mapped(global, name, Some(dtype.clone()), Address::new(address), *size);
                }
                if let Some((base, size)) = request.rodata_span {
                    if let Some(rng) = rugra::address::Range::new(
                        Address::new(base),
                        Address::new(base + size - 1),
                    ) {
                        db.set_property_range(
                            rugra::database::symbol_flags::READONLY,
                            rng,
                        );
                    }
                }
                eprintln!(
                    "[PREPASS] {} program-DB symbol graph: {} .rodata entries ({} string-typed) + {} global symbols ({} DWARF-typed) + readonly range",
                    target.name,
                    request.rodata_dat_entries.len(),
                    typed,
                    seeded_db_symbols,
                    dwarf_display_names.len()
                );
            }
            Some(db_arc)
        };
    // The loader-backed string manager source: the contiguous memory image
    // of the PT_LOAD segments (Ghidra's loader reads vaddr-keyed; .bss is
    // zero-filled NOBITS).
    let program_loader: Option<std::sync::Arc<dyn rugra::loadimage::LoadImage>> =
        Some(std::sync::Arc::new(worker_memory_load_image(elf, &request.binary_image)));
    let worker_arch =
        worker_architecture_with_program_db(program_db, program_loader)?;

    let debug_db = DebugPrototypeDatabase::parse_elf(&request.binary_image)
        .map_err(|error| format!("unable to import DWARF prototypes: {error}"))?;
    let mut sleigh = SleighLifter::new();
    sleigh
        .configure_x86_64(section_image, section.sh_addr)
        .map_err(|error| format!("failed to configure SLEIGH: {error}"))?;

    let proto_db: HashMap<u64, usize> = request.prototype_entries.iter().copied().collect();
    if proto_db.len() != request.prototype_entries.len() {
        return Err("duplicate address in external prototype snapshot".to_string());
    }
    let t0 = std::time::Instant::now();
    eprintln!("[STEP] {} START", target.name);

    let func_size =
        i32::try_from(target.size).map_err(|_| format!("function {} is too large", target.name))?;
    let mut fd = Funcdata::new(&target.name, Address::new(target.vaddr), func_size);
    // FUNCPROTO-MODEL-BIND-0001: attach the worker-local Architecture before
    // the DWARF/PLT prototype overlays below — the named-ctor model binding
    // (FuncProto::setScope -> setModel(defaultfp)) rides on it, so an overlay
    // can lock the prototype only after a model is in place.
    // B3-COREACTION-CONSTANTPTR-0001 (b): the architecture built above with
    // the Program-DB symbol graph + loader-backed StringManager.
    fd.set_arch(worker_arch);
    // FLOW-SHAREDRETURN-0001: the controller supplies the out-of-band
    // `<flowoverridelist>` projection for exactly this function. Seed it
    // before FlowInfo construction because Ghidra's constructor caches
    // Override::hasFlowOverride(); processInstruction performs the exact-site
    // query before lift and applies the rewrite after lift, before xref.
    for record in &request.flow_override_entries {
        if record.function_address != target.vaddr {
            return Err(format!(
                "flow override owner mismatch: target=0x{:x} owner=0x{:x} site=0x{:x}",
                target.vaddr, record.function_address, record.override_address
            ));
        }
        if record.flow_type == FlowOverride::None {
            return Err(format!(
                "NONE flow override supplied for 0x{:x}:0x{:x}",
                record.function_address, record.override_address
            ));
        }
        let address = Address::new(record.override_address);
        let previous = fd.localoverride.get_flow_override(address);
        if previous != FlowOverride::None && previous != record.flow_type {
            return Err(format!(
                "conflicting flow override at 0x{:x}: {:?} vs {:?}",
                record.override_address, previous, record.flow_type
            ));
        }
        fd.localoverride
            .insert_flow_override(address, record.flow_type);
    }
    // Seed the symbol table before prototype application so the PLT-import
    // boundary below can resolve the target's own address.
    for (address, name) in &request.symbol_entries {
        fd.add_symbol(*address, name.clone());
    }
    // MAINDIFF-GLOBAL-0001: the DWARF display-name overlay on the name
    // proxy — the same names the Program-DB layer carries (function-statics
    // in their function namespace), so print-side address-keyed lookups
    // agree with the symbol graph.
    for (&address, global) in debug_globals.iter() {
        let name = match &global.parent_function {
            Some(parent) => format!("{}::{}", parent, global.name),
            None => global.name.clone(),
        };
        fd.add_symbol(address, name);
    }
    for (address, value) in &request.string_entries {
        fd.add_string(*address, value.clone());
    }
    let libc_signatures = rugra::debugproto::LibcSignatureTable::default();
    // DWARF named-type index (Ghidra's program type-manager name resolution):
    // signature base spellings like `FILE` resolve to the binary's real type
    // graph so a locked libc `FILE *` return keeps SUB_PTR_STRUCT specificity
    // against inferred `char *` (parse_type_names, debugproto).
    let dwarf_type_names = rugra::debugproto::parse_type_names(&request.binary_image)
        .unwrap_or_default();
    let callspec_link_enabled = std::env::var("RUGRA_DISABLE_CALLSPEC_LINK").is_err();
    let mut dwarf_applied = false;
    match debug_db.apply(&mut fd) {
        Ok(true) => {
            dwarf_applied = true;
            eprintln!(
                "[PREPASS] {} applied locked DWARF prototype: {} params{}",
                target.name,
                fd.funcp.num_params(),
                if fd.funcp.is_varargs() {
                    " + varargs"
                } else {
                    ""
                }
            )
        }
        Ok(false) => {}
        Err(error) => eprintln!(
            "[PREPASS] {} DWARF prototype rejected: {}",
            target.name, error
        ),
    }
    // CALLSPEC-DRIVER-0001, PLT-stub target half: Ghidra's ELF importer marks
    // each PLT entry as a thunk of the EXTERNAL symbol, and the signature
    // data locks the thunk's prototype (locked oracle: 0x2320 renders as
    // `int puts(char *__s)` with the unknown-calling-convention warning —
    // exactly the locked-storage + unlocked-model combination the libc
    // table produces). Rugra applies the same locked ABI when the target's
    // own address is an import slot (address-exact: only PLT entries map to
    // import names) and DWARF did not already lock a prototype.
    if callspec_link_enabled && !dwarf_applied {
        if let Some(import_name) = fd.symbol_table.get(&target.vaddr).cloned() {
            let model_carrier = fd.funcp.clone();
            match libc_signatures.locked_proto(&import_name, &model_carrier, Some(&dwarf_type_names)) {
                Ok(Some(proto)) => {
                    eprintln!(
                        "[PREPASS] {} applied locked PLT-import signature: {} params",
                        target.name,
                        proto.num_params()
                    );
                    fd.funcp = proto;
                }
                Ok(None) => {}
                Err(error) => eprintln!(
                    "[PREPASS] {} PLT-import signature for {} rejected: {}",
                    target.name, import_name, error
                ),
            }
        }
    }
    // FLOW-NORETURN-DATA-0001, pre-flow function-attribute half (merge
    // adjudication, root c1598da follow-up): Ghidra's "Non-Returning
    // Functions - Known" analyzer marks the matched function's own DB
    // attribute BEFORE any decompilation runs — `functionAt.setNoReturn
    // (true)` on the (defined or thunk/external) function itself — and the
    // flow-time queryCall then reads that callee attribute and copies it
    // onto callers' call sites (flow.cc:663-664 copyFlowEffects, consumed
    // by checkForFlowModification's artificialHalt; CALLSPEC-NORETURN-WIRE
    // -0001 segment (b) on Rugra's side). This general marking subsumes the
    // former PLT-thunk-only half: any decompiled function whose primary
    // symbol matches the Known list carries the bit. Placement notes: (1)
    // AFTER the DWARF/PLT prototype overlays, because those replace
    // fd.funcp wholesale and would wipe an earlier bit; (2) applies
    // whether or not a locked signature was installed — the analyzer bit is
    // independent of the prototype model; (3) NOT gated by
    // RUGRA_DISABLE_CALLSPEC_LINK — the analyzer is a pre-decompile
    // platform pass, distinct from the callspec-link A/B gate; (4)
    // idempotent with the post-flow callsite marking in link_call_specs:
    // that sets the call-site proto's bit (queryCall's copy position),
    // this sets the function's own proto bit (the analyzer's DB attribute)
    // — two different objects, both faithful.
    let target_symbol_name = fd
        .symbol_table
        .get(&target.vaddr)
        .cloned()
        .unwrap_or_else(|| target.name.clone());
    if mark_known_no_return_function(&mut fd, &target_symbol_name) {
        eprintln!(
            "[PREPASS] {} marked known no-return ({} matches Non-Returning Functions - Known)",
            target.name, target_symbol_name
        );
    }
    fd.external_prototypes = proto_db;
    // Seed the DWARF global types: each address constant referencing a
    // global carries the C "&global" type (e.g. 0x17520 →
    // `Configurable *` from the DWARF `config` variable's struct with real
    // member types/offsets), which ActionInferTypes propagates onto
    // COPY/LOAD chains for `->field` rendering (DWARF-TYPE-IMPORT-0001).
    // Only `config` is wired today: A/B on the full corpus showed that
    // typing the other DWARF globals (glob_expand `URLGlob **` /
    // glob_buffer `char *` / save / beenhere) diverts printc's
    // symbol-name rendering into untyped locals (`extern long xVar69`
    // replaces `extern long glob_expand`) with no `URLGlob *`/`->size`
    // gain, because the LOAD-output → PTRSUB field-rendering chain and
    // Symbol-driven declarations are not in place (see
    // PRINTC-SYMBOL-DECL-0001 / FUNCDATA-LINKSYMBOL-TYPED-0001). The full
    // per-global map stays available via `address_pointer_map()`.
    fd.global_struct_ptrs = debug_globals
        .address_pointer_map()
        .into_iter()
        .filter(|(address, _)| *address == 0x17520)
        .collect();

    // FLOW-NORETURN-DATA-0001 segment (c): hand the flow-visible callee
    // table to flow. In Ghidra the "Non-Returning Functions - Known"
    // analyzer has already marked every matched function's DB attribute, and
    // queryCall (flow.cc:656-672) resolves those functions during flow —
    // copying their flow effects onto call sites (flow.cc:663-664) so
    // checkForFlowModification (flow.cc:636-651) inserts the noreturn
    // artificialHalt and emits the "Subroutine does not return" warning.
    // Rugra's Funcdata owns no per-callee Funcdata at flow time, so the
    // driver passes the callee `funcp` slices through the extended entry
    // point (empty table = the old behavior).
    let callee_protos = known_no_return_callee_protos(&fd.symbol_table);
    if !callee_protos.is_empty() {
        eprintln!(
            "[PREPASS] {} flow callee table: {} known no-return callees",
            target.name,
            callee_protos.len()
        );
    }
    rugra::flow::follow_flow_with_callee_protos(
        &mut fd,
        &mut sleigh,
        Address::new(target.vaddr),
        u64::MAX,
        &callee_protos,
    )
    .map_err(|error| format!("flow generation failed for {}: {error}", target.name))?;
    eprintln!(
        "[STEP] {} flow done {:?} raw_ops={} bblocks={}",
        target.name,
        t0.elapsed(),
        fd.obank.optree.len(),
        fd.bblocks.get_size()
    );
    // CALLSPEC-DRIVER-0001: resolve every CALL/CALLIND call specification
    // against the symbol/signature front-end (Ghidra's FlowInfo::queryCall
    // boundary, flow.cc:656-672). Ghidra queries the Program database here
    // (populated by the platform ELF/DWARF/signature analyzers); Rugra's
    // equivalent front-end state is the driver's symbol table plus the
    // locked libc ABI table. Unresolved targets stay unknown.
    // A/B measurement gate (same precedent as RUGRA_RULE_STATS): setting
    // RUGRA_DISABLE_CALLSPEC_LINK disables both halves of the wiring —
    // the call-spec resolution below and the PLT-import signature above —
    // so root can isolate this feature's corpus effect on the same tree.
    let mut named = 0usize;
    let mut signatures = 0usize;
    let mut dwarf_signatures = 0usize;
    let mut relinked = 0usize;
    let mut noreturn_marked = 0usize;
    if callspec_link_enabled {
        (named, signatures, dwarf_signatures, relinked, noreturn_marked) = link_call_specs(
            &mut fd,
            &libc_signatures,
            &debug_db,
            &target.name,
            &dwarf_type_names,
        );
    }
    eprintln!(
        "[PREPASS] {} call specs: {} callspecs, {} named, {} locked libc signatures, {} locked DWARF signatures, {} fspec targets relinked, {} known no-return callees marked",
        target.name,
        fd.callspecs.len(),
        named,
        signatures,
        dwarf_signatures,
        relinked,
        noreturn_marked
    );

    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc
        .write()
        .map_err(|_| "Funcdata write lock poisoned before analysis".to_string())?
        .set_self_ref(std::sync::Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();
    {
        let mut fd_write = fd_arc
            .write()
            .map_err(|_| "Funcdata write lock poisoned during analysis".to_string())?;
        // Ghidra's Action::perform aborts the whole pipeline on a negative
        // return; swallowing the error here made mid-pipeline aborts (e.g.
        // the RuleMultiCollapse def-loss) completely invisible in the
        // driver output (TYPED-DECL-GAP-0001 finding). Keep the
        // decompile-going-on semantics but surface the abort loudly.
        if let Err(err) = db.perform_action("decompile", &mut fd_write) {
            eprintln!("[DRIVER] {} pipeline ABORTED: {:?}", target.name, err);
        }

    }
    eprintln!("[STEP] {} action done {:?}", target.name, t0.elapsed());

    if let Ok(dump_fn) = std::env::var("RUGRA_DUMP_FUNC") {
        if dump_fn == target.name {
            let fd_read = fd_arc.read().unwrap();
            eprintln!("[DUMP] === basic blocks for {} ===", target.name);
            for i in 0..fd_read.bblocks.get_size() {
                let blk = match fd_read.bblocks.get_block(i) {
                    Some(b) => b,
                    None => continue,
                };
                let blk_rg = blk.read().unwrap();
                let ins: Vec<i32> =
                    (0..blk_rg.size_in()).map(|j| blk_rg.get_in(j).map(|e| e.point.read().unwrap().get_index()).unwrap_or(-1)).collect();
                let outs: Vec<i32> =
                    (0..blk_rg.size_out()).map(|j| blk_rg.get_out(j).map(|e| e.point.read().unwrap().get_index()).unwrap_or(-1)).collect();
                eprintln!("[DUMP] bb{} in={:?} out={:?}", blk_rg.get_index(), ins, outs);
                if let Some(bb) = blk_rg.as_any().downcast_ref::<rugra::block::BlockBasic>() {
                    let type_str = |v: &std::sync::Arc<std::sync::RwLock<rugra::varnode::Varnode>>| -> String {
                        let vr = v.read().unwrap();
                        let own = vr.v_type.as_ref().map(|t| format!("{:?}/{}", t.get_metatype(), t.get_name())).unwrap_or_else(|| "-".into());
                        let hi = vr.high.as_ref().map(|h| {
                            let hrg = h.read().unwrap();
                            format!("{:?}/{}", hrg.v_type.get().get_metatype(), hrg.v_type.get().get_name())
                        }).unwrap_or_else(|| "-".into());
                        format!("t={} h={}", own, hi)
                    };
                    for op in <rugra::block::BlockBasic as rugra::block::FlowBlock>::get_ops(bb) {
                        let op_rg = op.0.read().unwrap();
                        let out_s = op_rg.get_out().map(|v| {
                            let vr = v.read().unwrap();
                            format!("vn#{}(h={}:{}:{:x},{})", vr.create_index, vr.high.as_ref().map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_else(|| "?".into()), vr.get_space().name(), vr.get_offset(), type_str(v))
                        }).unwrap_or_default();
                        let in_s: Vec<String> = op_rg.inrefs.iter().map(|a| {
                            let vr = a.read().unwrap();
                            let extra = if vr.is_input() { ", INPUT" } else { "" };
                            format!("vn#{}(h={}{}:{}:{:x},{})", vr.create_index, vr.high.as_ref().map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_else(|| "?".into()), extra, vr.get_space().name(), vr.get_offset(), type_str(a))
                        }).collect();
                        let flag_s = format!("mk={} np={} nr={} outimpl={}", op_rg.is_marker(), (op_rg.flags & rugra::op::pcodeop_flags::NONPRINTING) != 0, (op_rg.flags & rugra::op::pcodeop_flags::NORETURN) != 0, op_rg.get_out().map(|o| o.read().unwrap().is_implied()).unwrap_or(false));
                        eprintln!("[DUMP]   op @0x{:x}/{} {:?} {} stopTP={} outStopUp={} {} = ({})", op_rg.start.addr.as_u64(), op_rg.start.order, op_rg.opcode, flag_s, op_rg.stops_type_propagation(), op_rg.get_out().map(|o| o.read().unwrap().stops_up_propagation()).unwrap_or(false), out_s, in_s.join(", "));
                    }
                }
            }
        }
    }
    // Ghidra: printlanguage.cc:69 PrintLanguage::PrintLanguage —
    // `emit = new EmitPrettyPrint()`; the decompiler always pretty-prints
    // through the Oppen token queue, so the driver mirrors that here.
    let mut printer = PrintC::new(Box::new(EmitPrettyPrint::new()));
    printer.set_rpn_enabled(true);
    let fd_read = fd_arc
        .read()
        .map_err(|_| "Funcdata read lock poisoned during printing".to_string())?;
    printer.doc_function(&fd_read);
    drop(fd_read);
    eprintln!("[STEP] {} print done {:?}", target.name, t0.elapsed());

    let output_buffer = printer
        .take_emit()
        .into_any()
        .downcast::<EmitPrettyPrint>()
        .map_err(|_| "PrintC returned an unexpected emitter type".to_string())?;
    let c_code = output_buffer.get_output();
    Ok((!c_code.trim().is_empty()).then_some(c_code))
}

// RUGRA-GLUE: bounded pipe drains prevent a verbose worker from blocking its controller.
fn read_pipe_limited<R: Read>(reader: R, limit: usize, stream: &str) -> io::Result<Vec<u8>> {
    let mut reader = reader;
    let mut output = Vec::new();
    let mut overflowed = false;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(output.len());
        let retained = remaining.min(count);
        output.extend_from_slice(&chunk[..retained]);
        overflowed |= retained != count;
    }
    if overflowed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{stream} exceeded {limit} bytes"),
        ));
    }
    Ok(output)
}

// RUGRA-GLUE: signal 0 probes the isolated group without changing worker state.
fn process_group_exists(process_group: i32) -> io::Result<bool> {
    let result = unsafe { kill(-process_group, 0) };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        Ok(false)
    } else {
        Err(error)
    }
}

// RUGRA-GLUE: sends a signal to every process in the per-function process group.
fn signal_process_group(process_group: i32, signal: i32) -> io::Result<()> {
    let result = unsafe { kill(-process_group, signal) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

// RUGRA-GLUE: verifies that no member of a terminated per-function group survives.
fn wait_for_process_group_exit(process_group: i32) -> io::Result<()> {
    for _ in 0..200 {
        if !process_group_exists(process_group)? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("process group {process_group} still exists after forced termination"),
    ))
}

// RUGRA-GLUE: hard-kills the whole worker group and synchronously reaps its direct child.
fn terminate_and_reap(child: &mut Child, process_group: i32) -> Result<ExitStatus, String> {
    let mut errors = Vec::new();
    if let Err(error) = signal_process_group(process_group, SIGKILL) {
        errors.push(format!("kill process group: {error}"));
    }
    if let Err(error) = child.kill() {
        if error.raw_os_error() != Some(ESRCH) && error.kind() != io::ErrorKind::InvalidInput {
            errors.push(format!("kill direct child: {error}"));
        }
    }
    let status = child
        .wait()
        .map_err(|error| format!("wait for killed worker: {error}"))?;
    if let Err(error) = wait_for_process_group_exit(process_group) {
        errors.push(error.to_string());
    }
    if errors.is_empty() {
        Ok(status)
    } else {
        Err(errors.join("; "))
    }
}

// RUGRA-GLUE: one self-exec child and process group form the cancellable unit for one function.
fn run_isolated_worker(
    job: &WorkerJob,
    timeout: Duration,
    monitor_mode: MonitorMode,
    request_mode: RequestMode,
    process_label: Option<&str>,
) -> WorkerRun {
    let encoded = if request_mode == RequestMode::MalformedProbe {
        b"not-a-valid-worker-request".to_vec()
    } else {
        match bincode::serialize(job) {
        Ok(encoded) if encoded.len() <= MAX_WORKER_REQUEST_BYTES => encoded,
        Ok(encoded) => {
            return WorkerRun {
                outcome: WorkerOutcome::SpawnFailed(format!(
                    "encoded request is too large: {} bytes",
                    encoded.len()
                )),
                stderr: Vec::new(),
            }
        }
        Err(error) => {
            return WorkerRun {
                outcome: WorkerOutcome::SpawnFailed(format!(
                    "unable to encode worker request: {error}"
                )),
                stderr: Vec::new(),
            }
        }
        }
    };
    if let Some(label) = process_label {
        if !valid_probe_token(label) {
            return WorkerRun {
                outcome: WorkerOutcome::SpawnFailed("invalid process label".to_string()),
                stderr: Vec::new(),
            };
        }
    }

    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            return WorkerRun {
                outcome: WorkerOutcome::SpawnFailed(format!(
                    "unable to resolve current executable: {error}"
                )),
                stderr: Vec::new(),
            }
        }
    };
    let mut command = Command::new(executable);
    command
        .arg(WORKER_MODE_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let controller_pid = match i32::try_from(std::process::id()) {
        Ok(pid) => pid,
        Err(_) => {
            return WorkerRun {
                outcome: WorkerOutcome::SpawnFailed(
                    "controller pid does not fit pid_t".to_string(),
                ),
                stderr: Vec::new(),
            }
        }
    };
    unsafe {
        command.pre_exec(move || {
            if prctl(PR_SET_PDEATHSIG, SIGKILL as usize, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if getppid() != controller_pid {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "controller exited while starting worker",
                ));
            }
            Ok(())
        });
    }
    if let Some(label) = process_label {
        command.arg(WORKER_LABEL_ARG).arg(label);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return WorkerRun {
                outcome: WorkerOutcome::SpawnFailed(format!("unable to spawn worker: {error}")),
                stderr: Vec::new(),
            }
        }
    };
    let process_group = match i32::try_from(child.id()) {
        Ok(process_group) => process_group,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return WorkerRun {
                outcome: WorkerOutcome::SpawnFailed("worker pid does not fit pid_t".to_string()),
                stderr: Vec::new(),
            };
        }
    };
    let observed_group = unsafe { getpgid(process_group) };
    if observed_group != process_group {
        let cleanup = terminate_and_reap(&mut child, process_group);
        return WorkerRun {
            outcome: WorkerOutcome::SpawnFailed(format!(
                "worker group isolation failed: pid={process_group}, pgid={observed_group}, cleanup={cleanup:?}"
            )),
            stderr: Vec::new(),
        };
    }

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let cleanup = terminate_and_reap(&mut child, process_group);
            return WorkerRun {
                outcome: WorkerOutcome::OutputDisconnected(format!(
                    "worker stdout pipe missing; cleanup={cleanup:?}"
                )),
                stderr: Vec::new(),
            };
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let cleanup = terminate_and_reap(&mut child, process_group);
            return WorkerRun {
                outcome: WorkerOutcome::OutputDisconnected(format!(
                    "worker stderr pipe missing; cleanup={cleanup:?}"
                )),
                stderr: Vec::new(),
            };
        }
    };
    let stdout_reader = match std::thread::Builder::new()
        .name("curl-worker-stdout".to_string())
        .spawn(move || read_pipe_limited(stdout, MAX_WORKER_STDOUT_BYTES, "worker stdout"))
    {
        Ok(reader) => reader,
        Err(error) => {
            let cleanup = terminate_and_reap(&mut child, process_group);
            return WorkerRun {
                outcome: WorkerOutcome::OutputDisconnected(format!(
                    "unable to start stdout reader: {error}; cleanup={cleanup:?}"
                )),
                stderr: Vec::new(),
            };
        }
    };
    let stderr_reader = match std::thread::Builder::new()
        .name("curl-worker-stderr".to_string())
        .spawn(move || read_pipe_limited(stderr, MAX_WORKER_STDERR_BYTES, "worker stderr"))
    {
        Ok(reader) => reader,
        Err(error) => {
            let cleanup = terminate_and_reap(&mut child, process_group);
            let _ = stdout_reader.join();
            return WorkerRun {
                outcome: WorkerOutcome::OutputDisconnected(format!(
                    "unable to start stderr reader: {error}; cleanup={cleanup:?}"
                )),
                stderr: Vec::new(),
            };
        }
    };

    let (deadline_sender, deadline_receiver) = mpsc::sync_channel(1);
    let (cancel_sender, cancel_receiver) = mpsc::sync_channel(1);
    let timer = match std::thread::Builder::new()
        .name("curl-worker-deadline".to_string())
        .spawn(move || {
            if monitor_mode == MonitorMode::DisconnectProbe {
                let _ = cancel_receiver.recv_timeout(timeout);
                return;
            }
            match cancel_receiver.recv_timeout(timeout) {
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let _ = deadline_sender.send(());
                }
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
            }
        }) {
        Ok(timer) => timer,
        Err(error) => {
            let cleanup = terminate_and_reap(&mut child, process_group);
            let _ = stdout_reader.join();
            let stderr = stderr_reader
                .join()
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
            return WorkerRun {
                outcome: WorkerOutcome::MonitorDisconnected,
                stderr: if cleanup.is_err() {
                    format!("timer spawn failed: {error}; cleanup={cleanup:?}\n").into_bytes()
                } else {
                    stderr
                },
            };
        }
    };
    let stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            let _ = cancel_sender.send(());
            let _ = timer.join();
            let cleanup = terminate_and_reap(&mut child, process_group);
            let _ = stdout_reader.join();
            let stderr = stderr_reader
                .join()
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
            return WorkerRun {
                outcome: WorkerOutcome::InputDisconnected(format!(
                    "worker stdin pipe missing; cleanup={cleanup:?}"
                )),
                stderr,
            };
        }
    };
    let input_writer = match std::thread::Builder::new()
        .name("curl-worker-stdin".to_string())
        .spawn(move || {
            let mut stdin = stdin;
            stdin.write_all(&encoded).and_then(|()| stdin.flush())
        }) {
        Ok(writer) => writer,
        Err(error) => {
            let _ = cancel_sender.send(());
            let _ = timer.join();
            let cleanup = terminate_and_reap(&mut child, process_group);
            let _ = stdout_reader.join();
            let stderr = stderr_reader
                .join()
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
            return WorkerRun {
                outcome: WorkerOutcome::InputDisconnected(format!(
                    "unable to start stdin writer: {error}; cleanup={cleanup:?}"
                )),
                stderr,
            };
        }
    };

    enum Completion {
        Exited(ExitStatus),
        TimedOut,
        MonitorDisconnected,
        WaitFailed(String),
    }
    let completion = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Completion::Exited(status),
            Ok(None) => {}
            Err(error) => break Completion::WaitFailed(error.to_string()),
        }
        match deadline_receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(()) => match child.try_wait() {
                Ok(Some(status)) => break Completion::Exited(status),
                Ok(None) => break Completion::TimedOut,
                Err(error) => break Completion::WaitFailed(error.to_string()),
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break Completion::MonitorDisconnected,
        }
    };
    let _ = cancel_sender.send(());
    let timer_panicked = timer.join().is_err();

    let mut cleanup_error = None;
    match &completion {
        Completion::Exited(_) => match process_group_exists(process_group) {
            Ok(false) => {}
            Ok(true) => {
                let mut errors = vec![
                    "worker leader exited while another process remained in its group".to_string(),
                ];
                if let Err(error) = signal_process_group(process_group, SIGKILL) {
                    errors.push(format!("kill remaining group members: {error}"));
                }
                if let Err(error) = wait_for_process_group_exit(process_group) {
                    errors.push(error.to_string());
                }
                cleanup_error = Some(errors.join("; "));
            }
            Err(error) => cleanup_error = Some(format!("probe worker process group: {error}")),
        },
        Completion::TimedOut | Completion::MonitorDisconnected | Completion::WaitFailed(_) => {
            match terminate_and_reap(&mut child, process_group) {
                Ok(_) => {}
                Err(error) => {
                    cleanup_error = Some(error);
                }
            }
        }
    }

    let input = match input_writer.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("stdin writer thread panicked".to_string()),
    };
    let stdout = match stdout_reader.join() {
        Ok(Ok(stdout)) => Ok(stdout),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("stdout reader thread panicked".to_string()),
    };
    let stderr_result = match stderr_reader.join() {
        Ok(Ok(stderr)) => Ok(stderr),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("stderr reader thread panicked".to_string()),
    };
    let stderr = stderr_result.as_ref().cloned().unwrap_or_else(|error| {
        format!("[WORKER-STDERR-ERROR] {error}\n").into_bytes()
    });

    if let Some(error) = cleanup_error {
        return WorkerRun {
            outcome: WorkerOutcome::CleanupFailed(error),
            stderr,
        };
    }
    if timer_panicked {
        return WorkerRun {
            outcome: WorkerOutcome::MonitorDisconnected,
            stderr,
        };
    }
    let outcome = match completion {
        Completion::TimedOut => WorkerOutcome::Timeout,
        Completion::MonitorDisconnected => WorkerOutcome::MonitorDisconnected,
        Completion::WaitFailed(error) => WorkerOutcome::WaitFailed(error),
        Completion::Exited(exit_status) => {
            if exit_status.success() {
                if let Err(error) = input {
                    WorkerOutcome::InputDisconnected(error)
                } else if let Err(error) = stderr_result {
                    WorkerOutcome::OutputDisconnected(error)
                } else {
                    match stdout {
                        Ok(stdout) => match bincode::deserialize::<WorkerPayload>(&stdout) {
                            Ok(payload) => WorkerOutcome::Success(payload),
                            Err(error) => WorkerOutcome::OutputDisconnected(format!(
                                "invalid worker response: {error}"
                            )),
                        },
                        Err(error) => WorkerOutcome::OutputDisconnected(error),
                    }
                }
            } else if exit_status.code() == Some(WORKER_PANIC_EXIT) {
                WorkerOutcome::Panic
            } else if exit_status.code() == Some(WORKER_INVALID_REQUEST_EXIT) {
                WorkerOutcome::InvalidRequest(exit_status.to_string())
            } else if exit_status.code() == Some(WORKER_OUTPUT_EXIT) {
                WorkerOutcome::OutputDisconnected(exit_status.to_string())
            } else {
                WorkerOutcome::NonZero(exit_status.to_string())
            }
        }
    };
    WorkerRun { outcome, stderr }
}

// RUGRA-GLUE: worker diagnostics are replayed before the controller emits that function's result.
fn replay_worker_stderr(stderr: &[u8]) -> io::Result<()> {
    if stderr.is_empty() {
        return Ok(());
    }
    let mut output = io::stderr().lock();
    output.write_all(stderr)?;
    output.flush()
}

const TYPEDEF_PREAMBLE: &str = "\ntypedef unsigned char byte;\ntypedef unsigned long undefined;\ntypedef unsigned short undefined2;\ntypedef unsigned long undefined4;\ntypedef unsigned long long undefined8;\ntypedef struct { char _anon[256]; } _struct;\n";

// RUGRA-GLUE: PrintC's process-wide typedef latch is reconstructed at the multi-process boundary.
fn normalize_worker_typedefs(
    document: String,
    typedefs_emitted: &mut bool,
) -> Result<String, String> {
    if !document.starts_with(TYPEDEF_PREAMBLE) {
        return Err("worker output is missing the expected typedef preamble".to_string());
    }
    if *typedefs_emitted {
        Ok(document[TYPEDEF_PREAMBLE.len()..].to_string())
    } else {
        *typedefs_emitted = true;
        Ok(document)
    }
}

// RUGRA-GLUE: direct comparison shares PrintC's in-process latch while isolated workers do not.
fn normalize_direct_typedefs(
    document: String,
    typedefs_emitted: &mut bool,
) -> Result<String, String> {
    if document.starts_with(TYPEDEF_PREAMBLE) {
        if *typedefs_emitted {
            return Err("direct output repeated the typedef preamble".to_string());
        }
        *typedefs_emitted = true;
        return Ok(document);
    }
    if *typedefs_emitted {
        Ok(document)
    } else {
        Err("first direct output is missing the expected typedef preamble".to_string())
    }
}

// RUGRA-GLUE: end-to-end fault probes exercise timeout, panic, nonzero, and monitor disconnect separately.
fn run_timeout_isolation_self_test(token: &str) -> Result<(), String> {
    let probe_job = |probe| WorkerJob::Probe {
        protocol_version: WORKER_PROTOCOL_VERSION,
        probe,
    };

    let timeout_token = format!("{token}.deadline");
    let disconnect_token = format!("{token}.disconnect");

    let timeout_run = run_isolated_worker(
        &probe_job(IsolationProbe::Hang {
            token: timeout_token.clone(),
        }),
        Duration::from_secs(2),
        MonitorMode::Deadline,
        RequestMode::Valid,
        Some(&timeout_token),
    );
    replay_worker_stderr(&timeout_run.stderr).map_err(|error| error.to_string())?;
    let ready_marker = format!("[TIMEOUT-PROBE] ready token={timeout_token}");
    if !String::from_utf8_lossy(&timeout_run.stderr).contains(&ready_marker) {
        return Err(format!(
            "hang probe timed out before worker and descendant were ready: {timeout_run:?}"
        ));
    }
    if !matches!(timeout_run.outcome, WorkerOutcome::Timeout) {
        return Err(format!(
            "hang probe was not classified as timeout: {timeout_run:?}"
        ));
    }
    println!("timeout-isolation probe: timeout=PASS");

    let success_run = run_isolated_worker(
        &probe_job(IsolationProbe::Success {
            token: token.to_string(),
        }),
        Duration::from_secs(2),
        MonitorMode::Deadline,
        RequestMode::Valid,
        Some(token),
    );
    replay_worker_stderr(&success_run.stderr).map_err(|error| error.to_string())?;
    match success_run.outcome {
        WorkerOutcome::Success(WorkerPayload::ProbeSuccess(ref value))
            if value == &format!("probe-success:{token}") => {}
        _ => {
            return Err(format!(
                "post-timeout success probe failed: {success_run:?}"
            ))
        }
    }
    println!("timeout-isolation probe: subsequent-worker=PASS");

    let panic_run = run_isolated_worker(
        &probe_job(IsolationProbe::Panic {
            token: token.to_string(),
        }),
        Duration::from_secs(2),
        MonitorMode::Deadline,
        RequestMode::Valid,
        Some(token),
    );
    replay_worker_stderr(&panic_run.stderr).map_err(|error| error.to_string())?;
    if !matches!(panic_run.outcome, WorkerOutcome::Panic) {
        return Err(format!("panic probe was misclassified: {panic_run:?}"));
    }
    println!("timeout-isolation probe: panic=PASS");

    let nonzero_run = run_isolated_worker(
        &probe_job(IsolationProbe::NonZero {
            token: token.to_string(),
        }),
        Duration::from_secs(2),
        MonitorMode::Deadline,
        RequestMode::Valid,
        Some(token),
    );
    replay_worker_stderr(&nonzero_run.stderr).map_err(|error| error.to_string())?;
    if !matches!(nonzero_run.outcome, WorkerOutcome::NonZero(_)) {
        return Err(format!("nonzero probe was misclassified: {nonzero_run:?}"));
    }
    println!("timeout-isolation probe: nonzero=PASS");

    let output_disconnect_run = run_isolated_worker(
        &probe_job(IsolationProbe::OutputDisconnect {
            token: token.to_string(),
        }),
        Duration::from_secs(2),
        MonitorMode::Deadline,
        RequestMode::Valid,
        Some(token),
    );
    replay_worker_stderr(&output_disconnect_run.stderr).map_err(|error| error.to_string())?;
    if !matches!(
        output_disconnect_run.outcome,
        WorkerOutcome::OutputDisconnected(_)
    ) {
        return Err(format!(
            "output disconnect probe was misclassified: {output_disconnect_run:?}"
        ));
    }
    println!("timeout-isolation probe: output-disconnect=PASS");

    let disconnect_run = run_isolated_worker(
        &probe_job(IsolationProbe::Hang {
            token: disconnect_token.clone(),
        }),
        Duration::from_secs(2),
        MonitorMode::DisconnectProbe,
        RequestMode::Valid,
        Some(&disconnect_token),
    );
    replay_worker_stderr(&disconnect_run.stderr).map_err(|error| error.to_string())?;
    let disconnect_ready_marker = format!("[TIMEOUT-PROBE] ready token={disconnect_token}");
    if !String::from_utf8_lossy(&disconnect_run.stderr).contains(&disconnect_ready_marker) {
        return Err(format!(
            "disconnect probe ended before worker and descendant were ready: {disconnect_run:?}"
        ));
    }
    if !matches!(disconnect_run.outcome, WorkerOutcome::MonitorDisconnected) {
        return Err(format!(
            "monitor disconnect probe was misclassified: {disconnect_run:?}"
        ));
    }
    println!("timeout-isolation probe: monitor-disconnect=PASS");

    let invalid_request_run = run_isolated_worker(
        &probe_job(IsolationProbe::Success {
            token: token.to_string(),
        }),
        Duration::from_secs(2),
        MonitorMode::Deadline,
        RequestMode::MalformedProbe,
        Some(token),
    );
    replay_worker_stderr(&invalid_request_run.stderr).map_err(|error| error.to_string())?;
    if !matches!(
        invalid_request_run.outcome,
        WorkerOutcome::InvalidRequest(_)
    ) {
        return Err(format!(
            "invalid request probe was misclassified: {invalid_request_run:?}"
        ));
    }
    println!("timeout-isolation probe: invalid-request=PASS");
    println!("timeout-isolation probe: zero-residual-groups=PASS");
    Ok(())
}

// RUGRA-GLUE: controller for the curl fixture; DriverMode only selects internal isolation verification.
fn run_main(mode: DriverMode) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Rugra End-to-End Decompilation: curl (all functions) ===\n");

    let buffer = match fs::read("examples/curl") {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: Could not read examples/curl: {}", e);
            return Ok(());
        }
    };

    let obj = Object::parse(&buffer)?;
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => {
            eprintln!("Unsupported binary format. Expected ELF.");
            return Ok(());
        }
    };

    // Ghidra imports DWARF into its Program database before constructing
    // Funcdata. Build the same known-prototype database once, then apply each
    // matching prototype before any Rugra Action runs.
    let debug_prototypes = DebugPrototypeDatabase::parse_elf(&buffer)?;
    eprintln!(
        "[PREPASS] Imported {} DWARF function prototypes",
        debug_prototypes.len()
    );

    // EXTERNAL-block imports (EXTERNAL-STUB-SUPPORT-0001): the undefined
    // .dynsym symbols Ghidra's ELF importer allocates artificial block
    // entries for, in slot order.
    let external_imports = collect_external_imports(elf);
    eprintln!(
        "[EXTERNAL] {} imports; EXTERNAL block base 0x{:x}",
        external_imports.len(),
        external_block_base(elf)
    );

    // Collect all functions and ELF metadata
    let mut functions: Vec<FuncInfo> = Vec::new();
    let mut elf_function_symbols: HashMap<u64, (String, usize)> = HashMap::new();
    let mut symbol_table: HashMap<u64, String> = HashMap::new();
    let mut string_table: HashMap<u64, String> = HashMap::new();
    // .rodata synthetic DAT labels reserved for the segment-(a1)
    // query_container channel (see scan_rodata_dat_entries); deliberately
    // NOT routed into symbol_entries in this slice.
    let mut rodata_dat_entries: BTreeMap<u64, String> = BTreeMap::new();
    // B3-COREACTION-CONSTANTPTR-0001 (b): `.rodata` extent for the readonly
    // property range (the a0 layer's reserved consumers).
    let mut rodata_span: Option<(u64, u64)> = None;
    let mut plt_symbols: HashMap<u64, String> = HashMap::new();
    // MAINDIFF-GLOBAL-0001: the Program-DB global symbol layer (address,
    // name, byte size) — ELF OBJECT symbols, GOT PTR_ labels and .data
    // PTR_DAT_ pointer labels (see the collection block below).
    let mut db_symbol_entries: Vec<(u64, String, i32, bool)> = Vec::new();

    {
        // Collect all function symbols
        for sym in elf.syms.iter() {
            if sym.st_value != 0 {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbol_table.insert(sym.st_value, name.to_string());
                        if sym.is_function() {
                            // Size-0 symbols (deregister_tm_clones etc.) are
                            // kept too: the golden corpus merge below prefers
                            // the ELF name and falls back to the ledger size.
                            elf_function_symbols.insert(
                                sym.st_value,
                                (name.to_string(), sym.st_size as usize),
                            );
                        }
                    }
                }
            }
        }

        // Dynamic symbols
        for sym in elf.dynsyms.iter() {
            if sym.st_value != 0 {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbol_table.insert(sym.st_value, name.to_string());
                    }
                }
            }
        }

        // PLT resolution
        {
            let mut plt_sec_base = 0u64;
            let mut plt_base = 0u64;
            for header in elf.section_headers.iter() {
                if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                    if name == ".plt" {
                        plt_base = header.sh_addr;
                    } else if name == ".plt.sec" {
                        plt_sec_base = header.sh_addr;
                    }
                }
            }
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
                                plt_symbols.insert(plt_addr, name.to_string());
                                symbol_table.insert(plt_addr, name.to_string());
                            }
                        }
                    }
                }
            }

            // .plt.got slots (CALLSPEC-DRIVER-0001): Ghidra's PLT analyzer
            // resolves these the same way as .plt.sec entries, but their GOT
            // slots are owned by R_X86_64_GLOB_DAT relocations in .rela.dyn
            // (not .rela.plt), so the loop above misses them. Each 8-byte
            // slot is `endbr64; bnd jmp *disp32(%rip)`: disp32 starts at
            // slot+7, rip after the jump is slot+11, and the GOT address it
            // jumps through names the imported symbol. Locked-oracle witness:
            // 0x22e0 -> __cxa_finalize (golden 0x1022e0 thunk + call site).
            for header in elf.section_headers.iter() {
                if elf.shdr_strtab.get_at(header.sh_name) != Some(".plt.got") {
                    continue;
                }
                let file_off = header.sh_offset as usize;
                let slot_vaddr = header.sh_addr;
                for slot in 0..(header.sh_size as usize / 8) {
                    let start = file_off + slot * 8;
                    let Some(insn) = buffer.get(start..start + 11) else {
                        continue;
                    };
                    // f2 ff 25 <disp32> at slot+4 (after endbr64).
                    if insn[4] != 0xf2 || insn[5] != 0xff || insn[6] != 0x25 {
                        continue;
                    }
                    let disp = i32::from_le_bytes([
                        insn[7], insn[8], insn[9], insn[10],
                    ]) as i64;
                    let got_addr = (slot_vaddr + slot as u64 + 11) as i64 + disp;
                    // x86-64 uses RELA dynamic relocations (.rela.dyn);
                    // fall back to the Rel form for completeness.
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
                        let plt_addr = slot_vaddr + slot as u64;
                        plt_symbols.insert(plt_addr, name.to_string());
                        symbol_table.insert(plt_addr, name.to_string());
                    }
                }
            }
        }

        // String table from .rodata, gated by the oracle's codepoint
        // validity chain (check_characters_utf8 above): invalid-UTF-8 runs
        // (0x7180/0x99a8/0xc1d8 hugehelp aliases) stay out so later Rule
        // folding cannot invert golden's `&DAT_*` classification.
        for header in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                if name == ".rodata" {
                    let start = header.sh_offset as usize;
                    let end = std::cmp::min(start + header.sh_size as usize, buffer.len());
                    let rodata = &buffer[start..end];
                    let base_vaddr = header.sh_addr;
                    string_table = scan_rodata_strings(rodata, base_vaddr);
                    // B3-COREACTION-CONSTANTPTR-0001 (b): the `.rodata`
                    // extent backs the readonly property range installed on
                    // the worker Database.
                    rodata_span = Some((base_vaddr, header.sh_size));
                    // Segment-(a0) Program-DB layer: synthetic .rodata DAT
                    // labels reserved for the (a1) query_container wiring.
                    rodata_dat_entries =
                        scan_rodata_dat_entries(rodata, base_vaddr, &symbol_table);
                    eprintln!(
                        "[PREPASS] .rodata DAT labels (B3 a0, reserved for query_container): {} entries [0x{:x}..0x{:x}]",
                        rodata_dat_entries.len(),
                        rodata_dat_entries.keys().next().copied().unwrap_or(0),
                        rodata_dat_entries.keys().next_back().copied().unwrap_or(0)
                    );
                    for witness in [0x7180u64, 0x99a8, 0xc1d8, 0xea40, 0x11270, 0x13ad0] {
                        eprintln!(
                            "[PREPASS]   hugehelp witness 0x{:x}: dat={} string={}",
                            witness,
                            rodata_dat_entries.contains_key(&witness),
                            string_table.contains_key(&witness)
                        );
                    }
                    break;
                }
            }
        }

        // Synthetic BSS/data variable names for addresses without ELF symbols
        // Scan .data and .bss sections and create DAT entries for
        // addresses that don't already have a symbol. Naming follows the
        // golden convention (synthetic_dat_name: DAT_ + 8-hex of the
        // analyzeHeadless image-base-0x100000 address, e.g. base-0 0x17020
        // -> DAT_00117020, matching golden :1678's PTR_DAT_00117020 /
        // :2537's DAT_001149b0 width and base).
        // Create synthetic names at every byte offset (sections are kept
        // manageable by the 0x10000 size cap below).
        for header in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                if name == ".data" || name == ".bss" {
                    let base = header.sh_addr;
                    let size = header.sh_size;
                    // Create synthetic names at every byte offset (sections are typically small)
                    if size <= 0x10000 {
                        // Only for reasonably sized sections
                        for off in 0..size {
                            let addr = base + off;
                            if !symbol_table.contains_key(&addr) {
                                symbol_table.insert(addr, synthetic_dat_name(addr));
                            }
                        }
                    }
                }
            }
        }

        // MAINDIFF-GLOBAL-0001: the Program-DB symbol layer over global
        // storage, mirroring what the locked 12.0.4 oracle's loaders and
        // analyzers had registered before decompilation (the state
        // Funcdata::mapGlobals queries through Scope::queryProperties,
        // database.cc:1263):
        //  - ELF symtab OBJECT symbols at their storage address, named the
        //    way Ghidra's ELF importer renders them: gcc `.NNN` static
        //    suffixes become `_` when no DWARF variable of the stripped
        //    name covers the address (locked witness: `completed.8061` ->
        //    `completed_8061`; DWARF-covered `save.5103`/`beenhere.3888`
        //    are overridden by the worker's DWARF merge with the
        //    function-namespace names `my_get_token::save` /
        //    `next_url::beenhere`).
        //  - GOT slot PTR_ labels: every 8-byte .got slot takes
        //    `PTR_<dynsym-name>_<image-based addr>` from the covering
        //    dynamic relocation (name stripped of its `@@GLIBC...`
        //    version), or bare `PTR_<addr>` when no relocation names it
        //    (witnesses: PTR___libc_start_main_00116fe0, PTR_00116e78).
        //  - .data pointer-relocation PTR_DAT_ labels for
        //    R_X86_64_RELATIVE slots pointing outside .data (witness:
        //    &PTR_DAT_00117020 -> .rodata 0x6004).
        // The entries ride `db_symbol_entries` into the worker's Database
        // global scope and (via symbol_table) the Funcdata name proxy.
        {
            // Relocation name lookup: r_offset -> version-stripped dynsym name.
            let reloc_name_at = |offset: u64| -> Option<String> {
                for reloc in elf.dynrelas.iter().chain(elf.dynrels.iter()) {
                    if reloc.r_offset != offset {
                        continue;
                    }
                    if reloc.r_sym == 0 {
                        return Some(String::new());
                    }
                    return elf
                        .dynsyms
                        .get(reloc.r_sym)
                        .and_then(|sym| elf.dynstrtab.get_at(sym.st_name))
                        .map(|n| n.split('@').next().unwrap_or(n).to_string());
                }
                None
            };
            // ELF symtab OBJECT layer (name + size for the DB entries).
            // `.NNN` gcc-static suffixes take the importer's `_` form when
            // no DWARF variable covers the address (worker DWARF merge
            // overrides the DWARF-covered spellings).
            let mut push_object_symbol = |raw: &str,
                                          st_value: u64,
                                          st_size: u64,
                                          symbol_table: &mut HashMap<u64, String>| {
                if raw.is_empty() || st_value == 0 || st_size == 0 {
                    return;
                }
                let name = raw.split('@').next().unwrap_or(raw).replace('.', "_");
                symbol_table.insert(st_value, name.clone());
                db_symbol_entries.push((st_value, name, st_size as i32, false));
            };
            for sym in elf.syms.iter() {
                if sym.st_info & 0xf != 1 /* STT_OBJECT */ {
                    continue;
                }
                if let Some(raw) = elf.strtab.get_at(sym.st_name) {
                    push_object_symbol(raw, sym.st_value, sym.st_size, &mut symbol_table);
                }
            }
            for sym in elf.dynsyms.iter() {
                if sym.st_info & 0xf != 1 /* STT_OBJECT */ {
                    continue;
                }
                if let Some(raw) = elf.dynstrtab.get_at(sym.st_name) {
                    push_object_symbol(raw, sym.st_value, sym.st_size, &mut symbol_table);
                }
            }
            // GOT PTR_ layer over every 8-byte slot.
            for header in elf.section_headers.iter() {
                if elf.shdr_strtab.get_at(header.sh_name) != Some(".got") {
                    continue;
                }
                for slot in (0..header.sh_size).step_by(8) {
                    let addr = header.sh_addr + slot;
                    // Oracle label form: `PTR_<name>_<image-based addr>`,
                    // collapsing to `PTR_<addr>` when no relocation names
                    // the slot (golden witness PTR_00116e78).
                    let sep_name = match reloc_name_at(addr) {
                        Some(name) if !name.is_empty() => format!("{name}_"),
                        _ => String::new(),
                    };
                    let label = format!(
                        "PTR_{}{:08x}",
                        sep_name,
                        ANALYZE_HEADLESS_IMAGE_BASE + addr
                    );
                    symbol_table.insert(addr, label.clone());
                    db_symbol_entries.push((addr, label, 8, true));
                }
            }
            // .data R_X86_64_RELATIVE pointer layer (PTR_DAT_).
            let data_span = elf.section_headers.iter().find_map(|header| {
                (elf.shdr_strtab.get_at(header.sh_name) == Some(".data"))
                    .then_some((header.sh_addr, header.sh_addr + header.sh_size))
            });
            if let Some((data_lo, data_hi)) = data_span {
                const R_X86_64_RELATIVE: u64 = 8;
                for reloc in elf.dynrelas.iter() {
                    if reloc.r_offset < data_lo
                        || reloc.r_offset >= data_hi
                        || reloc.r_sym != 0
                        || reloc.r_addend.unwrap_or(0) >= data_lo as i64
                    {
                        continue;
                    }
                    let label = format!(
                        "PTR_DAT_{:08x}",
                        ANALYZE_HEADLESS_IMAGE_BASE + reloc.r_offset
                    );
                    symbol_table.insert(reloc.r_offset, label.clone());
                    db_symbol_entries.push((reloc.r_offset, label, 8, true));
                }
            }
            eprintln!(
                "[PREPASS] Program-DB global symbol layer: {} entries (ELF OBJECT + GOT PTR_ + PTR_DAT_)",
                db_symbol_entries.len()
            );
        }
    }

    // Program source: Ghidra's Java Shared Return Calls analyzer writes
    // Instruction flow overrides into the Program database (captured by the
    // locked program_flow_metadata_1204 fixture). Standalone source: this
    // driver reconstructs its unique-owner direct-known-entry projection from
    // ELF STT_FUNC bodies, relocation-derived PLT functions, and iced direct
    // jump references. The wider contiguous-function discovery option is not
    // part of this slice.
    let flow_override_entries = if std::env::var("RUGRA_DISABLE_SHARED_RETURN").is_ok() {
        eprintln!("[PREPASS] Shared Return Calls disabled for A/B");
        Vec::new()
    } else {
        let records =
            collect_known_entry_shared_return_overrides(&buffer, elf, &plt_symbols)?;
        let function_count = records
            .iter()
            .map(|record| record.function_address)
            .collect::<BTreeSet<_>>()
            .len();
        eprintln!(
            "[PREPASS] Shared Return Calls unique-owner direct-known-entry metadata: {} sites in {} functions",
            records.len(), function_count
        );
        for record in &records {
            eprintln!(
                "[PREPASS] flow override owner=0x{:x} site=0x{:x} type={}",
                record.function_address,
                record.override_address,
                record.flow_type.to_string()
            );
        }
        records
    };

    // Build the decompilation corpus from the locked golden ledger (124
    // functions: ELF-named code, PLT stubs, `_init`/`_fini`, zero-sized
    // symtab functions, and the 48 EXTERNAL-space entries at 0x19000+ that
    // Ghidra synthesized for undefined imports). ELF symbols win for name
    // and size wherever they exist at the same address, so the previously
    // ELF-only subset keeps its exact former inputs (FULL-CORPUS-0001).
    let elf_function_file_offset = |vaddr: u64| -> u64 {
        let mut file_off = 0u64;
        for header in elf.section_headers.iter() {
            if vaddr >= header.sh_addr && vaddr < header.sh_addr + header.sh_size {
                file_off = header.sh_offset + (vaddr - header.sh_addr);
                break;
            }
        }
        file_off
    };
    for &(ledger_vaddr, ledger_name, ledger_size) in GOLDEN_CORPUS_LEDGER.iter() {
        let ledger_size = ledger_size as usize;
        let (name, size, origin) = match elf_function_symbols.get(&ledger_vaddr) {
            Some((elf_name, elf_size)) if *elf_size > 0 => {
                (elf_name.clone(), *elf_size, FunctionOrigin::ElfSymbol)
            }
            Some((elf_name, _)) => {
                // ELF symbol with st_size == 0: keep the ELF name (GCC
                // suffixes intact), size from the ledger.
                (elf_name.clone(), ledger_size, FunctionOrigin::LedgerEntry)
            }
            None => (ledger_name.to_string(), ledger_size, FunctionOrigin::LedgerEntry),
        };
        functions.push(FuncInfo {
            vaddr: ledger_vaddr,
            size,
            file_offset: elf_function_file_offset(ledger_vaddr),
            name,
            origin,
        });
    }
    functions.sort_by_key(|f| f.vaddr);

    println!(
        "Found {} golden-corpus functions ({} ELF-symbol backed), {} symbols, {} strings\n",
        functions.len(),
        functions
            .iter()
            .filter(|f| f.origin == FunctionOrigin::ElfSymbol)
            .count(),
        symbol_table.len(),
        string_table.len()
    );

    // Pre-pass: collect function prototypes for cross-function arg tracking.
    // Each function's detected param count is used by callers to trim CALL
    // args accurately. Mirrors Ghidra's ActionActiveParam multi-pass.
    // Only ELF-symbol-backed functions participate: PLT stubs and
    // EXTERNAL-space entries have no body to infer from (Ghidra gets import
    // prototypes from a signature database Rugra does not have), and
    // inferring on them would inject bogus CALL arg counts into callers.
    let mut prototype_db: std::collections::HashMap<u64, usize> = debug_prototypes
        .iter()
        .map(|(&address, prototype)| (address, prototype.parameters.len()))
        .collect();
    for func in &functions {
        if func.origin != FunctionOrigin::ElfSymbol
            || func.size < 5
            || func.name == "_start"
            || prototype_db.contains_key(&func.vaddr)
        {
            continue;
        }
        let job = WorkerJob::InferPrototype {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request: PrototypeRequest {
                binary_image: buffer.clone(),
                target: worker_target(func),
            },
        };
        let worker_run = run_isolated_worker(
            &job,
            function_timeout(),
            MonitorMode::Deadline,
            RequestMode::Valid,
            None,
        );
        replay_worker_stderr(&worker_run.stderr)?;
        match worker_run.outcome {
            WorkerOutcome::Success(WorkerPayload::Prototype(parameter_count)) => {
                prototype_db.insert(func.vaddr, parameter_count);
            }
            WorkerOutcome::Success(payload) => eprintln!(
                "[PREPASS-PROTOCOL] {} returned unexpected payload: {:?}",
                func.name, payload
            ),
            WorkerOutcome::Timeout => eprintln!(
                "[PREPASS-TIMEOUT] {} exceeded {:?} and was reaped",
                func.name, function_timeout()
            ),
            WorkerOutcome::Panic => {
                eprintln!("[PREPASS-PANIC] {} worker panicked", func.name)
            }
            WorkerOutcome::InvalidRequest(error) => {
                eprintln!("[PREPASS-PROTOCOL] {}: {error}", func.name)
            }
            WorkerOutcome::InputDisconnected(error) => {
                eprintln!("[PREPASS-INPUT-DISCONNECT] {}: {error}", func.name)
            }
            WorkerOutcome::OutputDisconnected(error) => {
                eprintln!("[PREPASS-OUTPUT-DISCONNECT] {}: {error}", func.name)
            }
            WorkerOutcome::MonitorDisconnected => {
                eprintln!("[PREPASS-MONITOR-DISCONNECT] {}", func.name)
            }
            WorkerOutcome::NonZero(error)
            | WorkerOutcome::WaitFailed(error)
            | WorkerOutcome::CleanupFailed(error)
            | WorkerOutcome::SpawnFailed(error) => {
                eprintln!("[PREPASS-ERROR] {}: {error}", func.name)
            }
        }
    }
    eprintln!("[PREPASS] Collected {} function prototypes:", prototype_db.len());
    for (&addr, &count) in prototype_db.iter().take(30) {
        let name = symbol_table.get(&addr).cloned().unwrap_or_else(|| format!("FUN_{:08x}", addr));
        eprintln!("[PREPASS]   {} @ 0x{:x}: {} params", name, addr, count);
    }

    // Decompile each function. Every golden-corpus entry is attempted
    // (including `_start`, tiny stubs and the EXTERNAL-space entries at
    // 0x19000+, which fail fast with no backing ELF section) so the
    // per-function timeout isolation and abort visibility cover the whole
    // 124-function corpus (FULL-CORPUS-0001).
    let mut stats = CorpusStats::default();
    let mut typedefs_emitted = false;
    let mut direct_typedefs_emitted = false;
    let selected_functions = match &mode {
        DriverMode::All => None,
        DriverMode::CompareFunctions(names) | DriverMode::SelectedFunctions(names) => {
            Some(names.as_slice())
        }
    };
    let mut selected_functions_seen = Vec::new();
    // Preserve the exact iteration order used by the former HashMap clones.
    let symbol_entries: Vec<(u64, String)> = symbol_table
        .iter()
        .map(|(&address, name)| (address, name.clone()))
        .collect();
    let string_entries: Vec<(u64, String)> = string_table
        .iter()
        .map(|(&address, value)| (address, value.clone()))
        .collect();
    let prototype_entries: Vec<(u64, usize)> = prototype_db
        .iter()
        .map(|(&address, &parameter_count)| (address, parameter_count))
        .collect();

    // EXTERNAL-block import slots (EXTERNAL-STUB-SUPPORT-0001): one 8-byte
    // slot per UND .dynsym symbol in symbol order, starting at the
    // linkage-aligned block base (see external_block_base). These are the
    // addresses Ghidra's ELF importer materializes for undefined imports and
    // where the oracle emits the halt_baddata() stub sections.
    let external_import_slots: HashMap<u64, &ExternalImport> = {
        let base = external_block_base(&elf);
        external_imports
            .iter()
            .enumerate()
            .map(|(index, import)| (base + 8 * index as u64, import))
            .collect()
    };

    for func in &functions {
        if let Some(names) = selected_functions {
            if !names.iter().any(|name| name == &func.name) {
                continue;
            }
            selected_functions_seen.push(func.name.clone());
        }

        // EXTERNAL-block target: no code exists to decompile (the oracle's
        // translate step fails as bad instruction data), so the driver
        // projects the stub section directly from the import's signature
        // instead of spawning a doomed worker.
        if let Some(import) = external_import_slots.get(&func.vaddr) {
            if import.name == func.name {
                println!(
                    "/* ---- 0x{:x}: {} ({} bytes) ---- */",
                    func.vaddr, func.name, func.size
                );
                println!("{}", external_stub_section(&func.name, import));
                stats.external_stub_decls += 1;
                continue;
            }
        }

        eprintln!(
            "[SYMS] {} entries; targets 0x2000-0x5000:",
            symbol_table.len()
        );
        for (&addr, name) in symbol_table.iter() {
            if addr >= 0x2000 && addr <= 0x5000 {
                eprintln!("[SYM] 0x{:x} = {}", addr, name);
            }
        }

        let job = WorkerJob::Decompile {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request: DecompileRequest {
                binary_image: buffer.clone(),
                target: worker_target(func),
                symbol_entries: symbol_entries.clone(),
                string_entries: string_entries.clone(),
                prototype_entries: prototype_entries.clone(),
                flow_override_entries: flow_override_entries
                    .iter()
                    .filter(|record| record.function_address == func.vaddr)
                    .copied()
                    .collect(),
                // B3-COREACTION-CONSTANTPTR-0001 (b): the a0 DAT layer rides
                // the request so the worker can install the Database symbol
                // graph ActionConstantPtr queries.
                rodata_dat_entries: rodata_dat_entries
                    .iter()
                    .map(|(&address, name)| (address, name.clone()))
                    .collect(),
                rodata_span,
                db_symbol_entries: db_symbol_entries.clone(),
            },
        };
        let direct_output = if matches!(mode, DriverMode::CompareFunctions(_)) {
            match run_worker_job(&job).map_err(|error| {
                let message = match error {
                    WorkerFailure::InvalidRequest(message) | WorkerFailure::Job(message) => message,
                };
                io::Error::new(io::ErrorKind::Other, message)
            })? {
                WorkerPayload::Decompile(output) => Some(output),
                WorkerPayload::Prototype(_) | WorkerPayload::ProbeSuccess(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "direct comparison returned a probe payload",
                    )
                    .into())
                }
            }
        } else {
            None
        };

        let worker_run = run_isolated_worker(
            &job,
            function_timeout(),
            MonitorMode::Deadline,
            RequestMode::Valid,
            None,
        );
        replay_worker_stderr(&worker_run.stderr)?;
        match worker_run.outcome {
            WorkerOutcome::Success(WorkerPayload::Decompile(c_code)) => {
                let c_code = match c_code
                    .map(|document| normalize_worker_typedefs(document, &mut typedefs_emitted))
                    .transpose()
                {
                    Ok(c_code) => c_code,
                    Err(error) => {
                        println!(
                            "/* ---- 0x{:x}: {} WORKER PROTOCOL ERROR: {} ---- */",
                            func.vaddr, func.name, error
                        );
                        stats.protocol_failures += 1;
                        continue;
                    }
                };
                if let Some(expected) = direct_output {
                    let expected = expected
                        .map(|document| {
                            normalize_direct_typedefs(document, &mut direct_typedefs_emitted)
                        })
                        .transpose()
                        .map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("direct output protocol error for {}: {error}", func.name),
                            )
                        })?;
                    if expected != c_code {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "isolated output changed for {} (direct {} bytes, isolated {} bytes)",
                                func.name,
                                expected.as_ref().map_or(0, String::len),
                                c_code.as_ref().map_or(0, String::len)
                            ),
                        )
                        .into());
                    }
                    eprintln!(
                        "[TIMEOUT-ISOLATION] normal output MATCH function={} bytes={}",
                        func.name,
                        c_code.as_ref().map_or(0, String::len)
                    );
                }
                match c_code {
                    Some(c_code) => {
                        println!(
                            "/* ---- 0x{:x}: {} ({} bytes) ---- */",
                            func.vaddr, func.name, func.size
                        );
                        println!("{}", c_code);
                        stats.decompiled += 1;
                    }
                    None => stats.empty_output += 1,
                }
            }
            WorkerOutcome::Success(WorkerPayload::Prototype(_))
            | WorkerOutcome::Success(WorkerPayload::ProbeSuccess(_)) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER PROTOCOL ERROR: unexpected probe payload ---- */",
                    func.vaddr, func.name
                );
                stats.protocol_failures += 1;
            }
            WorkerOutcome::Timeout => {
                println!(
                    "/* ---- 0x{:x}: {} TIMEOUT (>10s) ---- */",
                    func.vaddr, func.name
                );
                stats.timeouts += 1;
            }
            WorkerOutcome::Panic => {
                println!(
                    "/* ---- 0x{:x}: {} PANICKED: isolated worker panic ---- */",
                    func.vaddr, func.name
                );
                stats.panic += 1;
            }
            WorkerOutcome::NonZero(status) => {
                // EXTERNAL-space ledger entries (0x19000+) have no backing
                // ELF section, so a worker that still reaches this arm fails
                // fast with the section diagnostic. The projected-stub path
                // above normally intercepts them before the worker spawn;
                // this fallback keeps an honest bucket for any slot whose
                // ledger name disagrees with the .dynsym import.
                if is_external_stub_failure(&worker_run.stderr) {
                    println!(
                        "/* ---- 0x{:x}: {} EXTERNAL-STUB: no backing ELF section (Ghidra halt_baddata stub) ---- */",
                        func.vaddr, func.name
                    );
                    stats.external_stubs += 1;
                } else {
                    println!(
                        "/* ---- 0x{:x}: {} WORKER NONZERO: {} ---- */",
                        func.vaddr, func.name, status
                    );
                    stats.worker_failures += 1;
                }
            }
            WorkerOutcome::InputDisconnected(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER INPUT DISCONNECTED: {} ---- */",
                    func.vaddr, func.name, error
                );
                stats.worker_failures += 1;
            }
            WorkerOutcome::OutputDisconnected(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER OUTPUT DISCONNECTED: {} ---- */",
                    func.vaddr, func.name, error
                );
                stats.worker_failures += 1;
            }
            WorkerOutcome::MonitorDisconnected => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER MONITOR DISCONNECTED ---- */",
                    func.vaddr, func.name
                );
                stats.worker_failures += 1;
            }
            WorkerOutcome::WaitFailed(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER WAIT FAILED: {} ---- */",
                    func.vaddr, func.name, error
                );
                stats.worker_failures += 1;
            }
            WorkerOutcome::CleanupFailed(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER CLEANUP FAILED: {} ---- */",
                    func.vaddr, func.name, error
                );
                stats.worker_failures += 1;
            }
            WorkerOutcome::SpawnFailed(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER SPAWN FAILED: {} ---- */",
                    func.vaddr, func.name, error
                );
                stats.worker_failures += 1;
            }
            WorkerOutcome::InvalidRequest(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER INVALID REQUEST: {} ---- */",
                    func.vaddr, func.name, error
                );
                stats.protocol_failures += 1;
            }
        }
    }

    if let Some(names) = selected_functions {
        if let Some(missing) = names
            .iter()
            .find(|name| !selected_functions_seen.contains(name))
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("requested comparison function was not found: {missing}"),
            )
            .into());
        }
    }

    println!(
        "\n=== Summary: {}/{} golden-corpus functions processed: {} decompiled, {} empty-output, {} timeout, {} panic, {} external-stub(no ELF code), {} external-stub(import-signature declared), {} worker-failure, {} protocol-failure ===",
        stats.attempted(),
        GOLDEN_CORPUS_LEDGER.len(),
        stats.decompiled,
        stats.empty_output,
        stats.timeouts,
        stats.panic,
        stats.external_stubs,
        stats.external_stub_decls,
        stats.worker_failures,
        stats.protocol_failures
    );

    Ok(())
}

#[cfg(test)]
mod constantptr_driver_a0_tests {
    use super::*;

    /// Loads the locked curl fixture's .rodata (section bytes + base-0 vaddr).
    fn curl_rodata() -> (Vec<u8>, u64) {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/curl");
        let data = std::fs::read(path).expect("examples/curl fixture readable");
        let elf = match goblin::Object::parse(&data).expect("curl parses as ELF") {
            goblin::Object::Elf(elf) => elf,
            _ => panic!("curl fixture is not an ELF object"),
        };
        for header in elf.section_headers.iter() {
            if elf.shdr_strtab.get_at(header.sh_name) == Some(".rodata") {
                let start = header.sh_offset as usize;
                let end = (start + header.sh_size as usize).min(data.len());
                return (data[start..end].to_vec(), header.sh_addr);
            }
        }
        panic!("curl fixture has no .rodata section");
    }

    #[test]
    fn codepoint_gate_matches_oracle_prefix_chain() {
        // ASCII run with terminator (stringmanage.cc:329-336 happy path).
        assert!(check_characters_utf8(b"abc\0"));
        // Bare 0xAD continuation byte: fall-through return -1
        // (stringmanage.cc:391) — the hugehelp alias shape.
        assert!(!check_characters_utf8(b"opera\xad\ntion\0"));
        assert!(!check_characters_utf8(b"\x80lead\0"));
        // Valid multi-byte UTF-8 (e0/f0 prefix chains).
        assert!(check_characters_utf8(b"\xc3\xa9\0"));
        assert!(check_characters_utf8(b"\xf0\x9f\x98\x80\0"));
        // Truncated sequences (prefix at the end, NUL is not a continuation).
        assert!(!check_characters_utf8(b"\xc3\0"));
        assert!(!check_characters_utf8(b"\xf0\x9f\x98\0"));
        // Surrogate range and >0x10FFFF rejections (stringmanage.cc:392-397).
        assert!(!check_characters_utf8(b"\xed\xa0\x80\0"));
        assert!(!check_characters_utf8(b"\xf4\x90\x80\x80\0"));
        // Lead bytes outside every prefix chain.
        assert!(!check_characters_utf8(b"\xf8\x80\x80\x80\0"));
        // No terminator inside the section: DataUnavailError analog
        // (stringmanage.cc:463-465) leaves the negative cache.
        assert!(!check_characters_utf8(b"abc"));
        // Oracle quirk kept faithful: C0 80 is an overlong NUL — the
        // (val&0xe0)==0xc0 branch (stringmanage.cc:363-366) has no overlong
        // rejection, so it decodes to codepoint 0 and terminates the run.
        assert!(check_characters_utf8(b"\xc0\x80\0"));
    }

    #[test]
    fn six_hugehelp_addresses_classify_like_golden() {
        let (rodata, base_vaddr) = curl_rodata();
        let strings = scan_rodata_strings(&rodata, base_vaddr);
        // Fixture ELF symbols: only _IO_stdin_used sits inside .rodata.
        let mut fixture_symbols: HashMap<u64, String> = HashMap::new();
        fixture_symbols.insert(0x6000, "_IO_stdin_used".to_string());
        let dats = scan_rodata_dat_entries(&rodata, base_vaddr, &fixture_symbols);
        // Golden classification (B3 audit §1.2): the first three aliases
        // carry 0xAD bytes -> isString false -> `&DAT_*`; the last three are
        // pure ASCII -> string literals after Rule folding.
        for &rejected in &[0x7180u64, 0x99a8, 0xc1d8] {
            assert!(
                !strings.contains_key(&rejected),
                "0x{rejected:x} must be rejected by the UTF-8 gate"
            );
        }
        for &accepted in &[0xea40u64, 0x11270, 0x13ad0] {
            assert!(
                strings.contains_key(&accepted),
                "0x{accepted:x} must stay a valid string"
            );
        }
        // All six addresses get synthetic DAT labels for the (a1) channel.
        for &witness in &[0x7180u64, 0x99a8, 0xc1d8, 0xea40, 0x11270, 0x13ad0] {
            assert!(
                dats.contains_key(&witness),
                "0x{witness:x} must carry a .rodata DAT label"
            );
        }
        // Gate footprint on this fixture: the pre-gate driver admitted 136
        // strings; exactly the five invalid-UTF-8 runs drop (the three
        // hugehelp aliases plus 0x7094 and 0x149d4), nothing is added.
        for &also_rejected in &[0x7094u64, 0x149d4] {
            assert!(!strings.contains_key(&also_rejected));
        }
        assert_eq!(strings.len(), 131);
        // .rodata spans 0x6000..0x14a60; the only interior ELF symbol is
        // _IO_stdin_used@0x6000, so every other byte offset gets a DAT label.
        assert_eq!(dats.len(), 0xea60 - 1);
        assert!(!dats.contains_key(&0x6000));
        assert_eq!(dats[&0x7180], "DAT_00107180");
    }

    #[test]
    fn dat_names_match_golden_width() {
        assert_eq!(synthetic_dat_name(0x7180), "DAT_00107180");
        assert_eq!(synthetic_dat_name(0x61d9), "DAT_001061d9");
        assert_eq!(synthetic_dat_name(0x17020), "DAT_00117020");
        assert_eq!(synthetic_dat_name(0x175c0), "DAT_001175c0");
    }
}

#[cfg(test)]
mod flow_noreturn_data_tests {
    use super::*;

    /// Leading-underscore stripping mirrors the analyzer's `while (charAt ==
    /// '_') ++startIndex` loop: ALL leading underscores go, inner ones stay
    /// (`longjmp_chk`, `ZN10__cxxabiv111__terminateEPFvvE`).
    #[test]
    fn strips_all_leading_underscores() {
        assert_eq!(strip_leading_underscores("__stack_chk_fail"), "stack_chk_fail");
        assert_eq!(strip_leading_underscores("_exit"), "exit");
        assert_eq!(strip_leading_underscores("___pthread_exit"), "pthread_exit");
        assert_eq!(strip_leading_underscores("exit"), "exit");
        assert_eq!(strip_leading_underscores(""), "");
        // Inner underscores are not touched (Java substring from startIndex).
        assert_eq!(strip_leading_underscores("_longjmp_chk"), "longjmp_chk");
    }

    /// The matcher's accept set: underscore-stripped exact names from
    /// ElfFunctionsThatDoNotReturn, including the mangled C++ entries that
    /// only classify through stripping.
    #[test]
    fn accepts_known_no_return_names() {
        for name in [
            "exit",
            "__exit",      // -> exit
            "cexit",
            "c_exit",
            "abort",
            "reboot",
            "longjmp",
            "_longjmp", // glibc's setjmp-family alias form
            "longjmp_chk",
            "__longjmp_chk",
            "siglongjmp",
            "panic",
            "__stack_chk_fail",
            "__cxa_throw",
            "__cxa_terminate",
            "__cxa_call_unexpected",
            "__cxa_bad_cast",
            "_Unwind_Resume",
            "__assert_fail",
            "__assert_rtn",
            "__fortify_fail",
            "_ZSt9terminatev",
            "__ZN10__cxxabiv111__terminateEPFvvE",
            "pthread_exit",
        ] {
            assert!(is_known_no_return(name), "{name} must classify no-return");
        }
    }

    /// Exact-match boundary: case is significant (Java HashSet<String>
    /// containment), near-miss spellings and unlisted look-alikes stay
    /// returning, and mangled class methods never match (the analyzer's
    /// namespace guard analog for flat ELF names).
    #[test]
    fn rejects_non_members() {
        for name in [
            "Exit",               // case-sensitive list
            "STACK_CHK_FAIL",     // case-sensitive list
            "Unwind_resume",      // case-sensitive mangled entry
            "exits",              // not a prefix/equal match
            "exit2",
            "my_exit",            // inner underscore: strips to my_exit
            "aborting",
            "reboot_now",
            "longjmp2",
            "siglongjmp_chk",     // longjmp_chk is listed, sig- variant is not
            "panicky",
            "__cxa_atexit",       // cxa_atexit is NOT in the list
            "stack_chk",          // proper prefix of a listed name
            "__libc_start_main",  // curl import, returning
            "exit@GLIBC_2.2.5",   // version suffix is not stripped by the
                                  // analyzer (symbol.getName is the raw name)
            "_ZN5Menu5_exitEv",   // mangled method: Menu::_exit() — the
                                  // namespace guard's protected class
        ] {
            assert!(!is_known_no_return(name), "{name} must NOT classify no-return");
        }
    }

    /// Fixture witness: the locked curl binary's .dynsym imports classify
    /// exactly `exit` and `__stack_chk_fail` as known no-return (the two
    /// names the C1 audit symptom 2 chain rides on: __stack_chk_fail's
    /// 14-arg speculative call in my_get_line and exit calls in
    /// glob_word/glob_set). The full dynsym name set is the wide-readelf
    /// dump (52 entries).
    #[test]
    fn curl_dynsym_classifies_exit_and_stack_chk_fail_only() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/curl");
        let data = std::fs::read(path).expect("examples/curl fixture readable");
        let elf = match goblin::Object::parse(&data).expect("curl parses as ELF") {
            goblin::Object::Elf(elf) => elf,
            _ => panic!("curl fixture is not an ELF object"),
        };
        let mut matched: BTreeSet<String> = BTreeSet::new();
        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if is_known_no_return(name) {
                    matched.insert(name.to_string());
                }
            }
        }
        let expected: BTreeSet<String> =
            ["exit".to_string(), "__stack_chk_fail".to_string()].into_iter().collect();
        assert_eq!(matched, expected);
    }

    /// The list itself stays byte-faithful to the oracle data file: 21
    /// entries, no leading underscores, no wildcard tails (the loader would
    /// strip/warn and re-bucket those).
    #[test]
    fn list_stays_faithful_to_oracle_data_file() {
        assert_eq!(KNOWN_NO_RETURN_ELF_NAMES.len(), 21);
        for name in KNOWN_NO_RETURN_ELF_NAMES {
            assert!(!name.starts_with('_'), "{name} must not carry a leading '_'");
            assert!(!name.ends_with('*'), "{name} must not be a wildcard entry");
            assert_eq!(name, name.trim(), "{name} must be pre-trimmed");
        }
    }

    /// Pre-flow function-attribute marking (merge adjudication slice): a
    /// GENERAL callee — a locally defined function, not a PLT thunk — gets
    /// its own FuncProto's no_return bit set before flow runs, mirroring
    /// the analyzer's functionAt.setNoReturn(true) on the function itself.
    #[test]
    fn preflow_marking_sets_function_attribute_for_general_callee() {
        // A defined .text function named panic (no PLT/import involved).
        let mut fd = Funcdata::new("panic", Address::new(0x12000), 64);
        assert!(!fd.funcp.is_no_return());
        assert!(mark_known_no_return_function(&mut fd, "panic"));
        assert!(fd.funcp.is_no_return());
        // Underscored general callee form (glibc convention).
        let mut fd2 = Funcdata::new("__stack_chk_fail", Address::new(0x12100), 32);
        assert!(mark_known_no_return_function(&mut fd2, "__stack_chk_fail"));
        assert!(fd2.funcp.is_no_return());
    }

    /// Non-members are left untouched, and the marking never clears an
    /// existing bit (the analyzer only ever sets the flag on matches).
    #[test]
    fn preflow_marking_is_idempotent_and_never_clears() {
        let mut fd = Funcdata::new("glob_word", Address::new(0x12200), 128);
        // Non-member: no marking, bit stays clear.
        assert!(!mark_known_no_return_function(&mut fd, "glob_word"));
        assert!(!fd.funcp.is_no_return());
        // Member: marked; re-mark (idempotent) keeps it; a later non-member
        // pass on the same fd never unsets (analyzer has no clear path).
        assert!(mark_known_no_return_function(&mut fd, "exit"));
        assert!(mark_known_no_return_function(&mut fd, "exit"));
        assert!(!mark_known_no_return_function(&mut fd, "glob_word"));
        assert!(fd.funcp.is_no_return());
    }

    /// Flow-visible callee table (segment (c)): only Known-list members
    /// enter the table, keyed by symbol address; each entry is the minimal
    /// callee funcp slice — no_return set, everything else default (void
    /// return, no model, not inline) so queryCall's copy_flow_effects
    /// (flow.cc:663-664) reads exactly the analyzer's flag and nothing else.
    #[test]
    fn callee_table_contains_only_members_with_minimal_slice() {
        let mut symbols: HashMap<u64, String> = HashMap::new();
        symbols.insert(0x2380, "__stack_chk_fail".to_string());
        symbols.insert(0x2400, "exit".to_string());
        symbols.insert(0x2410, "exits".to_string()); // near-miss: excluded
        symbols.insert(0x2420, "Exit".to_string()); // case: excluded
        symbols.insert(0x2430, "fgets".to_string()); // ordinary import
        symbols.insert(0x2440, "_longjmp".to_string()); // member via strip
        let table = known_no_return_callee_protos(&symbols);
        assert_eq!(table.len(), 3);
        for &address in &[0x2380u64, 0x2400, 0x2440] {
            let proto = &table[&address];
            assert!(proto.is_no_return(), "entry 0x{address:x} must be no-return");
            assert!(!proto.is_inline());
            assert!(!proto.has_model());
            assert_eq!(proto.num_params(), 0);
        }
        // Names keep the raw symbol form (queryCall's set_funcdata uses the
        // symbol-table name for display; the proto name is the DB slice).
        assert_eq!(table[&0x2380].name, "__stack_chk_fail");
        assert_eq!(table[&0x2440].name, "_longjmp");
        // Empty symbol table: empty table (old follow_flow behavior).
        assert!(known_no_return_callee_protos(&HashMap::new()).is_empty());
    }
}
