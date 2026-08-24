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
use rugra::debugproto::{DebugGlobalDatabase, DebugPrototypeDatabase, X86_64GccStorage};
use rugra::disasm::sleigh_lift::SleighLifter;
use rugra::disasm::{Disassembler, X86Lifter, X86_64Disassembler};
use rugra::funcdata::Funcdata;
use rugra::override_rs::{FlowOverride, FlowOverrideRecord};
use rugra::prettyprint::EmitNoMarkup;
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
const FUNCTION_TIMEOUT: Duration = Duration::from_secs(10);
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

// callspec with a direct entry address: (1) set_funcdata with the symbol's
// display name, (2) when the symbol is a table import, install the locked
// signature proto on the call site, (3) refresh the CALL op's typed fspec
// annotation against the same stable callspec owner. Unresolved targets are
// left exactly as flow produced them (unknown). Returns (named, locked
// signatures, relinked call ops).
fn link_call_specs(
    fd: &mut rugra::funcdata::Funcdata,
    libc_signatures: &rugra::debugproto::LibcSignatureTable,
    storage: &rugra::debugproto::X86_64GccStorage,
    fn_name: &str,
) -> (usize, usize, usize) {
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
    let mut named = 0usize;
    let mut signatures = 0usize;
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
        // platform side's locked libc signature for the imported callee.
        match libc_signatures.locked_proto(&name, storage) {
            Ok(Some(proto)) => {
                owner.write().unwrap().prototype = proto;
                signatures += 1;
            }
            Ok(None) => {}
            Err(error) => eprintln!(
                "[PREPASS] {} callspec@0x{:x}: libc signature for {} rejected: {}",
                fn_name, op_addr, name, error
            ),
        }
    }
    // flow.cc:685 / fspec.cc:5450: opSetInput(op, newVarnodeCallSpecs(fc)).
    // Ghidra's fspec varnode is a pointer to the FuncCallSpecs. D0 preserves
    // that exact owner identity through a typed Weak carried by the temporary
    // Iop annotation; TypeOp/PrintC consumption remains a separate residual.
    let relinked = relink_call_spec_targets(fd);
    (named, signatures, relinked)
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

// RUGRA-GLUE: the EXTERNAL-block base in normalized (ELF-relative)
// coordinates: the 0x1000-aligned start of the range after the last
// allocatable section byte, mirroring ElfProgramBuilder.allocateLinkageBlock
// with ElfLoadAdapter.getLinkageBlockAlignment() == 0x1000
// (ElfLoadAdapter.java:445). For the locked curl input: .bss ends at
// 0x18680 -> base 0x19000.
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
    static CACHE: std::sync::OnceLock<
        Result<std::sync::Arc<rugra::arch::Architecture>, String>,
    > = std::sync::OnceLock::new();
    match CACHE.get_or_init(|| {
        let cspec_bytes = fs::read("sleigh_specs/x86-64-gcc.cspec")
            .map_err(|error| format!("unable to read compiler spec: {error}"))?;
        let sleigh = rugra::sleigh_ffi::SleighCtx::new()
            .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
        let mut registers = HashMap::new();
        for index in 0..sleigh.num_registers() {
            let Some((name, space, offset, size)) = sleigh.register_info(index) else {
                continue;
            };
            let Ok(space_id) = u8::try_from(space) else {
                continue;
            };
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
        Ok(Arc::new(arch))
    }) {
        Ok(arch) => Ok(arch.clone()),
        Err(message) => Err(message.clone()),
    }
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

    let debug_db = DebugPrototypeDatabase::parse_elf(&request.binary_image)
        .map_err(|error| format!("unable to import DWARF prototypes: {error}"))?;
    let debug_globals = DebugGlobalDatabase::parse_elf(&request.binary_image)
        .map_err(|error| format!("unable to import DWARF globals: {error}"))?;
    let register_context = rugra::sleigh_ffi::SleighCtx::new()
        .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
    let debug_storage = X86_64GccStorage::from_sleigh(&register_context)
        .map_err(|error| format!("unable to build compiler storage: {error}"))?;
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
    fd.set_arch(worker_architecture()?);
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
    for (address, value) in &request.string_entries {
        fd.add_string(*address, value.clone());
    }
    let libc_signatures = rugra::debugproto::LibcSignatureTable::default();
    let callspec_link_enabled = std::env::var("RUGRA_DISABLE_CALLSPEC_LINK").is_err();
    let mut dwarf_applied = false;
    match debug_db.apply(&mut fd, &debug_storage) {
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
            match libc_signatures.locked_proto(&import_name, &debug_storage) {
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

    rugra::flow::follow_flow(&mut fd, &mut sleigh, Address::new(target.vaddr), u64::MAX)
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
    let mut relinked = 0usize;
    if callspec_link_enabled {
        (named, signatures, relinked) = link_call_specs(
            &mut fd,
            &libc_signatures,
            &debug_storage,
            &target.name,
        );
    }
    eprintln!(
        "[PREPASS] {} call specs: {} callspecs, {} named, {} locked libc signatures, {} fspec targets relinked",
        target.name,
        fd.callspecs.len(),
        named,
        signatures,
        relinked
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

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
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
        .downcast::<EmitNoMarkup>()
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
    let register_context = rugra::sleigh_ffi::SleighCtx::new()
        .ok_or("unable to initialize SLEIGH register catalog")?;
    // Validate the same compiler-storage catalog that each isolated worker
    // reconstructs before applying a DWARF prototype.
    X86_64GccStorage::from_sleigh(&register_context)?;
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
    let mut plt_symbols: HashMap<u64, String> = HashMap::new();

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
            FUNCTION_TIMEOUT,
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
                func.name, FUNCTION_TIMEOUT
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
            FUNCTION_TIMEOUT,
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
