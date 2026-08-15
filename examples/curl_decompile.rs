//! End-to-end decompilation demo for the curl binary — ALL functions
//! Run with: cargo run --example curl_decompile

use goblin::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::panic::{self, AssertUnwindSafe};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use rugra::action::ActionDatabase;
use rugra::address::Address;
use rugra::debugproto::{DebugPrototypeDatabase, X86_64GccStorage};
use rugra::disasm::sleigh_lift::SleighLifter;
use rugra::disasm::{Disassembler, X86Lifter, X86_64Disassembler};
use rugra::funcdata::Funcdata;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printc::PrintC;
use rugra::printlanguage::PrintLanguage;
use rugra::type_system::datatype::{Datatype, TypeField};
use rugra::type_system::typefactory::TypeFactory;

/// Build the DWARF-derived struct types for the curl binary and return a map
/// from global-variable address → struct-pointer Datatype. The driver seeds
/// each per-function Funcdata's `global_struct_ptrs` with this map so that
/// `type_infer::propagate_types` stamps the struct-pointer types onto the
/// constant varnodes that reference these globals.
///
/// The struct layouts are extracted from the curl ELF's DWARF debug_info via
/// `tools/extract_dwarf_structs.py`. This stands in for the Architecture/
/// TypeFactory layer that Ghidra populates from .cspec/.specfile; Rugra's
/// driver has no Architecture layer, so we register the types here.
fn build_dwarf_struct_pointers() -> HashMap<u64, Arc<Datatype>> {
    let mut tf = TypeFactory::new(8);

    // Helper field type: a pointer-sized long (the DWARF extraction reports
    // every member as `long`, which is the pointer-sized slot). Using `long`
    // for char*/long/int members keeps field offsets accurate for PTRSUB
    // generation without needing the full DWARF type tree.
    let long8 = tf.get_base(8, rugra::type_system::datatype::TypeMetatype::Int)
        .expect("long base type");
    let field = |name: &str, off: usize| -> TypeField {
        TypeField { name: name.to_string(), offset: off, type_ptr: long8.clone() }
    };

    // struct Configurable { ... 304 bytes ... }  (DWARF DW_AT_byte_size: 304)
    // Global `::config` lives at 0x17520.
    tf.create_struct("Configurable");
    tf.set_fields("Configurable", vec![
        field("useragent", 0),
        field("cookie", 8),
        field("use_resume", 16),
        field("resume_from", 20),
        field("postfields", 24),
        field("referer", 32),
        field("timeout", 40),
        field("outfile", 48),
        field("headerfile", 56),
        field("remotefile", 64),
        field("ftpport", 72),
        field("porttouse", 80),
        field("range", 88),
        field("low_speed_limit", 96),
        field("low_speed_time", 100),
        field("showerror", 104),
        field("infile", 112),
        field("userpwd", 120),
        field("proxyuserpwd", 128),
        field("proxy", 136),
        field("configread", 144),
        field("conf", 152),
        field("cert", 168),
        field("cert_passwd", 176),
        field("crlf", 184),
        field("cookiefile", 192),
        field("customrequest", 200),
        field("progressmode", 208),
        field("nobuffer", 209),
        field("writeout", 216),
        field("errors", 224),
        field("quote", 232),
        field("postquote", 240),
        field("ssl_version", 248),
        field("timecond", 256),
        field("condtime", 264),
        field("headers", 272),
        field("httppost", 280),
        field("last_post", 288),
        field("httpreq", 296),
    ]);

    // struct OutStruct { char *filename; FILE *stream; }  (16 bytes)
    // Used as a local `OutStruct outs;` on the stack — no single global, but
    // we register the type so propagated pointers can resolve to it.
    tf.create_struct("OutStruct");
    tf.set_fields("OutStruct", vec![
        field("filename", 0),
        field("stream", 8),
    ]);

    // struct ProgressData { long total; long prev; long point; long width; }
    tf.create_struct("ProgressData");
    tf.set_fields("ProgressData", vec![
        field("total", 0),
        field("prev", 8),
        field("point", 16),
        field("width", 24),
    ]);

    // struct HttpPost { ... } — chain node used by multipart post handling.
    tf.create_struct("HttpPost");
    tf.set_fields("HttpPost", vec![
        field("next", 0),
        field("name", 8),
        field("contents", 16),
        field("contenttype", 24),
        field("more", 32),
        field("flags", 40),
    ]);

    // Build the struct and pointer types and the address→type map.
    let configurable = tf.find_by_name("Configurable").expect("Configurable struct");
    let configurable_ptr = tf.get_ptr(configurable.clone());
    let _outstruct = tf.find_by_name("OutStruct").expect("OutStruct struct");
    let _progressdata = tf.find_by_name("ProgressData").expect("ProgressData struct");
    let _httppost = tf.find_by_name("HttpPost").expect("HttpPost struct");

    let mut map: HashMap<u64, Arc<Datatype>> = HashMap::new();
    // ::config @ 0x17520 (from DWARF DW_AT_location DW_OP_addr: 0x17520).
    // The global is accessed via RIP-relative lea which puts the ADDRESS
    // (a Configurable*) into a register. So stamp the POINTER type on the
    // address constant, not the struct itself. This lets ActionInferTypes
    // propagate Configurable* through COPY/INT_ADD chains to reach the
    // STORE address base varnode, triggering ->field rendering.
    map.insert(0x17520, configurable_ptr.clone());
    // Also expose the struct-pointer type for code that takes `&::config`
    // (the IR surfaces this via RIP-relative lea into a register). The
    // pointer type is registered in the TypeFactory under "Configurable *"
    // so propagation consumers can find it; we don't map an address to it.
    let _ = configurable_ptr;
    map
}

/// Information about one function in the ELF
struct FuncInfo {
    vaddr: u64,
    size: usize,
    file_offset: u64,
    name: String,
}

// RUGRA-GLUE: copies immutable ELF symbol coordinates into the worker protocol.
fn worker_target(func: &FuncInfo) -> WorkerTarget {
    WorkerTarget {
        vaddr: func.vaddr,
        size: func.size,
        file_offset: func.file_offset,
        name: func.name.clone(),
    }
}

const WORKER_PROTOCOL_VERSION: u32 = 1;
const FUNCTION_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_MODE_ARG: &str = "--rugra-curl-function-worker";
const WORKER_LABEL_ARG: &str = "--probe-label";
const DESCENDANT_MODE_ARG: &str = "--rugra-timeout-descendant-probe";
const SELF_TEST_ARG: &str = "--rugra-timeout-isolation-self-test";
const COMPARE_FUNCTION_ARG: &str = "--rugra-timeout-isolation-compare-function";
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DecompileRequest {
    binary_image: Vec<u8>,
    target: WorkerTarget,
    symbol_entries: Vec<(u64, String)>,
    string_entries: Vec<(u64, String)>,
    prototype_entries: Vec<(u64, usize)>,
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

#[derive(Clone, Debug)]
enum DriverMode {
    All,
    CompareFunctions(Vec<String>),
}

unsafe extern "C" {
    fn getpgid(pid: i32) -> i32;
    fn getppid() -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
    fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
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
        _ => {
            eprintln!(
                "usage: {} [{} <function> ...]",
                args.first().map(String::as_str).unwrap_or("curl_decompile"),
                COMPARE_FUNCTION_ARG
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

// RUGRA-GLUE: reconstructs the original per-function prototype pre-pass inside the cancellable worker.
fn infer_prototype_request(request: &PrototypeRequest) -> Result<usize, String> {
    let obj = Object::parse(&request.binary_image)
        .map_err(|error| format!("unable to parse prototype worker ELF image: {error}"))?;
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => return Err("prototype worker input is not an ELF image".to_string()),
    };
    let target = &request.target;
    let symbol_matches = elf.syms.iter().any(|symbol| {
        symbol.st_value == target.vaddr
            && symbol.st_size as usize == target.size
            && elf.strtab.get_at(symbol.st_name) == Some(target.name.as_str())
    });
    if !symbol_matches {
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
    let symbol_matches = elf.syms.iter().any(|symbol| {
        symbol.st_value == target.vaddr
            && symbol.st_size as usize == target.size
            && elf.strtab.get_at(symbol.st_name) == Some(target.name.as_str())
    });
    if !symbol_matches {
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
    match debug_db.apply(&mut fd, &debug_storage) {
        Ok(true) => eprintln!(
            "[PREPASS] {} applied locked DWARF prototype: {} params{}",
            target.name,
            fd.funcp.num_params(),
            if fd.funcp.is_varargs() {
                " + varargs"
            } else {
                ""
            }
        ),
        Ok(false) => {}
        Err(error) => eprintln!(
            "[PREPASS] {} DWARF prototype rejected: {}",
            target.name, error
        ),
    }
    fd.external_prototypes = proto_db;
    fd.global_struct_ptrs = build_dwarf_struct_pointers();
    for (address, name) in &request.symbol_entries {
        fd.add_symbol(*address, name.clone());
    }
    for (address, value) in &request.string_entries {
        fd.add_string(*address, value.clone());
    }

    rugra::flow::follow_flow(&mut fd, &mut sleigh, Address::new(target.vaddr), u64::MAX);
    eprintln!(
        "[STEP] {} flow done {:?} raw_ops={} bblocks={}",
        target.name,
        t0.elapsed(),
        fd.obank.optree.len(),
        fd.bblocks.get_size()
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

const TYPEDEF_PREAMBLE: &str = "\ntypedef unsigned char byte;\ntypedef unsigned long undefined;\ntypedef unsigned long undefined4;\ntypedef unsigned long long undefined8;\ntypedef struct { char _anon[256]; } _struct;\n";

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

    // Collect all functions and ELF metadata
    let mut functions: Vec<FuncInfo> = Vec::new();
    let mut symbol_table: HashMap<u64, String> = HashMap::new();
    let mut string_table: HashMap<u64, String> = HashMap::new();
    let mut plt_symbols: HashMap<u64, String> = HashMap::new();

    {
        // Collect all function symbols
        for sym in elf.syms.iter() {
            if sym.st_value != 0 {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbol_table.insert(sym.st_value, name.to_string());
                    }
                    if sym.is_function() && sym.st_size > 0 {
                        // Find file offset
                        let mut file_off = 0u64;
                        for header in elf.section_headers.iter() {
                            if sym.st_value >= header.sh_addr
                                && sym.st_value < header.sh_addr + header.sh_size
                            {
                                file_off = header.sh_offset + (sym.st_value - header.sh_addr);
                                break;
                            }
                        }
                        if file_off > 0 {
                            functions.push(FuncInfo {
                                vaddr: sym.st_value,
                                size: sym.st_size as usize,
                                file_offset: file_off,
                                name: name.to_string(),
                            });
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
        }

        // String table from .rodata
        for header in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                if name == ".rodata" {
                    let start = header.sh_offset as usize;
                    let end = std::cmp::min(start + header.sh_size as usize, buffer.len());
                    let rodata = &buffer[start..end];
                    let base_vaddr = header.sh_addr;
                    let mut i = 0;
                    while i < rodata.len() {
                        if rodata[i].is_ascii_graphic()
                            || rodata[i] == b' '
                            || rodata[i] == b'\n'
                            || rodata[i] == b'\t'
                            || rodata[i] == b'\r'
                        {
                            let str_start = i;
                            while i < rodata.len() && rodata[i] != 0 {
                                i += 1;
                            }
                            let str_len = i - str_start;
                            let va = base_vaddr + str_start as u64;
                            if str_len >= 1 {
                                let s = String::from_utf8_lossy(
                                    &rodata[str_start..str_start + str_len],
                                );
                                if s.chars().all(|c| c.is_ascii() || c == '\u{FFFD}') {
                                    // Replace lossy replacement chars for clean display
                                    let clean: String =
                                        s.chars().filter(|c| c.is_ascii()).collect();
                                    if !clean.is_empty() {
                                        string_table.insert(va, clean);
                                    }
                                }
                            }
                        }
                        i += 1;
                    }
                    break;
                }
            }
        }

        // Synthetic BSS/data variable names for addresses without ELF symbols
        // Scan .data and .bss sections and create DAT_xxxxx entries for
        // addresses that don't already have a symbol.
        // We only create entries at 8-byte alignment to keep the table manageable.
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
                                symbol_table.insert(addr, format!("DAT_{:05x}", addr));
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort functions by address
    functions.sort_by_key(|f| f.vaddr);

    println!(
        "Found {} functions, {} symbols, {} strings\n",
        functions.len(),
        symbol_table.len(),
        string_table.len()
    );

    // Pre-pass: collect function prototypes for cross-function arg tracking.
    // Each function's detected param count is used by callers to trim CALL
    // args accurately. Mirrors Ghidra's ActionActiveParam multi-pass.
    let mut prototype_db: std::collections::HashMap<u64, usize> = debug_prototypes
        .iter()
        .map(|(&address, prototype)| (address, prototype.parameters.len()))
        .collect();
    for func in &functions {
        if func.size < 5 || func.name == "_start" || prototype_db.contains_key(&func.vaddr) {
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

    // Decompile each function
    let mut total_success = 0;
    let mut total_fail = 0;
    let mut typedefs_emitted = false;
    let mut direct_typedefs_emitted = false;
    let selected_functions = match &mode {
        DriverMode::All => None,
        DriverMode::CompareFunctions(names) => Some(names.as_slice()),
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

    for func in &functions {
        if let Some(names) = selected_functions {
            if !names.iter().any(|name| name == &func.name) {
                continue;
            }
            selected_functions_seen.push(func.name.clone());
        }
        // Skip very tiny functions (< 5 bytes) and _start
        if func.size < 5 || func.name == "_start" {
            continue;
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
                        total_fail += 1;
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
                        total_success += 1;
                    }
                    None => total_fail += 1,
                }
            }
            WorkerOutcome::Success(WorkerPayload::Prototype(_))
            | WorkerOutcome::Success(WorkerPayload::ProbeSuccess(_)) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER PROTOCOL ERROR: unexpected probe payload ---- */",
                    func.vaddr, func.name
                );
                total_fail += 1;
            }
            WorkerOutcome::Timeout => {
                println!(
                    "/* ---- 0x{:x}: {} TIMEOUT (>10s) ---- */",
                    func.vaddr, func.name
                );
                total_fail += 1;
            }
            WorkerOutcome::Panic => {
                println!(
                    "/* ---- 0x{:x}: {} PANICKED: isolated worker panic ---- */",
                    func.vaddr, func.name
                );
                total_fail += 1;
            }
            WorkerOutcome::NonZero(status) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER NONZERO: {} ---- */",
                    func.vaddr, func.name, status
                );
                total_fail += 1;
            }
            WorkerOutcome::InputDisconnected(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER INPUT DISCONNECTED: {} ---- */",
                    func.vaddr, func.name, error
                );
                total_fail += 1;
            }
            WorkerOutcome::OutputDisconnected(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER OUTPUT DISCONNECTED: {} ---- */",
                    func.vaddr, func.name, error
                );
                total_fail += 1;
            }
            WorkerOutcome::MonitorDisconnected => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER MONITOR DISCONNECTED ---- */",
                    func.vaddr, func.name
                );
                total_fail += 1;
            }
            WorkerOutcome::WaitFailed(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER WAIT FAILED: {} ---- */",
                    func.vaddr, func.name, error
                );
                total_fail += 1;
            }
            WorkerOutcome::CleanupFailed(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER CLEANUP FAILED: {} ---- */",
                    func.vaddr, func.name, error
                );
                total_fail += 1;
            }
            WorkerOutcome::SpawnFailed(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER SPAWN FAILED: {} ---- */",
                    func.vaddr, func.name, error
                );
                total_fail += 1;
            }
            WorkerOutcome::InvalidRequest(error) => {
                println!(
                    "/* ---- 0x{:x}: {} WORKER INVALID REQUEST: {} ---- */",
                    func.vaddr, func.name, error
                );
                total_fail += 1;
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
        "\n=== Summary: {} functions decompiled, {} skipped/failed ===",
        total_success, total_fail
    );

    Ok(())
}
