use std::fmt;
use std::sync::OnceLock;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VarnodeC {
    pub space: i32,
    pub offset: u64,
    pub size: u32,
    /// `-1` for an ordinary varnode; otherwise the normalized target space
    /// index for the space-id operand of LOAD/STORE.
    pub space_ref: i32,
    /// First-seen ID for the original varnode storage within one instruction.
    /// Equal IDs preserve cross-op aliasing (C++ `VarnodeData*` pool pointer,
    /// kuna pool slot address) without exposing addresses.
    pub identity: u64,
}

impl Default for VarnodeC {
    // RUGRA-GLUE: Rust DTO default used only for an absent engine PcodeEmit output
    fn default() -> Self {
        Self {
            space: 0,
            offset: 0,
            size: 0,
            space_ref: -1,
            identity: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcodeOpC {
    pub address_space: i32,
    pub address_offset: u64,
    pub opcode: i32,
    pub num_inputs: i32,
    pub has_output: i32,
    pub output: VarnodeC,
    pub inputs: Vec<VarnodeC>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedInstruction {
    /// Exact `Sleigh::oneInstruction` return value, including delay slots.
    pub step: i32,
    pub ops: Vec<PcodeOpC>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleighErrorKind {
    Unimplemented,
    BadData,
    DataUnavailable,
    Sleigh,
    Lowlevel,
    Decoder,
    StdException,
    UnknownException,
    InvalidArgument,
    InvalidState,
    OutOfMemory,
    Bridge,
}

impl SleighErrorKind {
    // RUGRA-GLUE: decode the fixed-width error discriminant used by the C ABI
    // and the Rust engine alike (sleigh_shim RugraSleighErrorKind values 1-11)
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Unimplemented),
            2 => Some(Self::BadData),
            3 => Some(Self::DataUnavailable),
            4 => Some(Self::Sleigh),
            5 => Some(Self::Lowlevel),
            6 => Some(Self::Decoder),
            7 => Some(Self::StdException),
            8 => Some(Self::UnknownException),
            9 => Some(Self::InvalidArgument),
            10 => Some(Self::InvalidState),
            11 => Some(Self::OutOfMemory),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SleighDecodeError {
    pub kind: SleighErrorKind,
    /// Exact bytes of the engine's explanatory string; presentation is lossy.
    pub message: Vec<u8>,
    /// Present only for `UnimplError`, including a meaningful value of zero.
    pub instruction_length: Option<i32>,
}

impl SleighDecodeError {
    // RUGRA-GLUE: construct a Rust-side validation failure at an engine boundary
    fn bridge(message: impl Into<Vec<u8>>) -> Self {
        Self {
            kind: SleighErrorKind::Bridge,
            message: message.into(),
            instruction_length: None,
        }
    }

    // RUGRA-GLUE: lossy display helper that preserves exact bytes in `message`
    pub fn message_lossy(&self) -> String {
        String::from_utf8_lossy(&self.message).into_owned()
    }
}

impl fmt::Display for SleighDecodeError {
    // RUGRA-GLUE: Rust Error presentation for a typed engine error record
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?}: {}",
            self.kind,
            String::from_utf8_lossy(&self.message)
        )?;
        if let Some(length) = self.instruction_length {
            write!(formatter, " (instruction_length={length})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SleighDecodeError {}

// ---------------------------------------------------------------------------
// Engine facade (post-retirement: the vendored kuna-sleigh runtime, Phase2
// of SLEIGH-RUSTIFY — the C++ FFI chain was retired after the gates in
// SLEIGH_PHASE2_SWAP_2026-09-26.md passed: op-for-op zero-diff over 698,605
// decodes / 5,550,599 ops, five-corpus E2E byte identity, cargo test --lib
// 1777P/0F, bank 391/391, perf same order with an -11% E2E wall win.)
// ---------------------------------------------------------------------------

// RUGRA-GLUE: process-wide Rust configuration for the default SLEIGH asset path
static SLA_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();

// RUGRA-GLUE: configure the default `.sla` location before the first context is made
pub fn set_sla_path(path: &str) {
    let _ = SLA_PATH.set(std::path::PathBuf::from(path));
}

// RUGRA-GLUE: resolve the configured `.sla` path for the engine constructor
fn resolve_sla_path() -> Option<std::path::PathBuf> {
    let default_path = std::path::PathBuf::from("sleigh_specs/x86-64.sla");
    let path = SLA_PATH.get().unwrap_or(&default_path);
    std::fs::canonicalize(path).ok()
}

/// Public SLEIGH decode-engine handle (the vendored `kuna-sleigh` runtime).
pub struct SleighCtx {
    backend: rust_backend::RustSleighEngine,
}

unsafe impl Send for SleighCtx {
    // RUGRA-GLUE: single-thread lifecycle contract inherited from the retired
    // C++ handle: a context is created, used, and dropped on one thread (the
    // C++ SLEIGH object graph was never thread-safe either). The kuna engine
    // holds `Rc` state with the identical constraint; no rugra caller moves a
    // lifter across threads (verified: rugra.rs/httpd_decompile create lifters
    // inside the thread that uses them).
}

impl SleighCtx {
    // RUGRA-GLUE: create the Rust SLEIGH engine from the configured .sla
    pub fn new() -> Option<Self> {
        let sla_path = resolve_sla_path()?;
        Some(Self {
            backend: rust_backend::RustSleighEngine::new(&sla_path)?,
        })
    }

    // RUGRA-GLUE: deep-copy an image into the engine before decoding starts
    pub fn try_set_image(&mut self, bytes: &[u8], base_addr: u64) -> Result<(), SleighDecodeError> {
        self.backend.try_set_image(bytes, base_addr)
    }

    // RUGRA-GLUE: compatibility wrapper retained for existing lifter callers until SLEIGH-0002D
    pub fn set_image(&mut self, bytes: &[u8], base_addr: u64) {
        let _ = self.try_set_image(bytes, base_addr);
    }

    // RUGRA-GLUE: set a context default before decoding starts, preserving typed failures
    pub fn try_set_context(&mut self, name: &str, value: i32) -> Result<(), SleighDecodeError> {
        self.backend.try_set_context(name, value)
    }

    // RUGRA-GLUE: compatibility wrapper retained for the temporary pspec scanner
    pub fn set_context(&mut self, name: &str, value: i32) {
        let _ = self.try_set_context(name, value);
    }

    // RUGRA-GLUE: temporary SLEIGH-0002C/MISMATCH pspec scanner; it does not model
    // ContextInternal ranges, masks, tracked registers, or child ordering.
    pub fn load_pspec(&mut self, pspec_path: &str) {
        let xml = match std::fs::read_to_string(pspec_path) {
            Ok(contents) => contents,
            Err(_) => return,
        };
        for tag in simple_xml_find(&xml, "set") {
            if let (Some(name), Some(value)) = (get_attr(&tag, "name"), get_attr(&tag, "val")) {
                if let Ok(value) = value.parse::<i32>() {
                    self.set_context(&name, value);
                }
            }
        }
    }

    // RUGRA-GLUE: safe oneInstruction boundary preserving step, zero-op success,
    // ordered dynamic operands, aliases, and typed engine exceptions
    pub fn one_instruction(
        &mut self,
        offset: u64,
    ) -> Result<DecodedInstruction, SleighDecodeError> {
        self.backend.one_instruction(offset)
    }

    // RUGRA-GLUE: compatibility bridge that still folds typed errors to an empty
    // vector for legacy lifter callers; SLEIGH-0002D removes this ambiguity
    pub fn decode(&mut self, offset: u64) -> Vec<PcodeOpC> {
        self.one_instruction(offset)
            .map(|instruction| instruction.ops)
            .unwrap_or_default()
    }

    // RUGRA-GLUE: SLEIGH printAssembly mnemonic probe (translate.hh:442).
    // Linear driver walks use this to drop no-effect padding ops by the
    // .sla's own constructor classification (see the backend mirror for
    // the full rationale).
    pub fn assembly_mnemonic(&self, offset: u64) -> Option<String> {
        self.backend.assembly_mnemonic(offset)
    }

    // RUGRA-GLUE: legacy length-only wrapper retained until callers consume the
    // atomic `one_instruction` result in SLEIGH-0002D; &mut because the engine
    // freezes image/context here (decode_started, mirroring the retired
    // rugra_sleigh.cpp:500 behavior)
    pub fn instruction_length(&mut self, offset: u64) -> Option<usize> {
        self.backend.instruction_length(offset)
    }

    // RUGRA-GLUE: query the number of address spaces exposed by the translator
    pub fn num_spaces(&self) -> usize {
        self.backend.num_spaces()
    }

    // RUGRA-GLUE: copy one space catalog entry from the translator
    pub fn space_info(&self, index: usize) -> Option<(i32, String)> {
        self.backend.space_info(index)
    }

    // RUGRA-GLUE: query the number of registers exposed by the translator
    pub fn num_registers(&self) -> usize {
        self.backend.num_registers()
    }

    // RUGRA-GLUE: copy one register catalog entry from the translator
    pub fn register_info(&self, index: usize) -> Option<(String, i32, u64, i32)> {
        self.backend.register_info(index)
    }
}

// ---------------------------------------------------------------------------
// Rust backend: vendored kuna-sleigh runtime (Phase2, SLEIGH-RUSTIFY-PHASE2-0001)
// ---------------------------------------------------------------------------

mod rust_backend {
    use super::{DecodedInstruction, PcodeOpC, SleighDecodeError, SleighErrorKind, VarnodeC};
    use kuna_base::address::Address;
    use kuna_base::error::{KunaError, KunaResult};
    use kuna_num::opcodes::OpCode;
    use kuna_num::pcoderaw::VarnodeData;
    use kuna_sleigh::globalcontext::ContextInternal;
    use kuna_sleigh::loadimage::LoadImage;
    use kuna_sleigh::sleigh::Sleigh;
    use kuna_sleigh::translate::PcodeEmit;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    // Shared mutable image state behind the engine's boxed LoadImage so
    // `try_set_image` can swap bytes in place without replacing the box
    // (the C++ shim mutates its own `RugraLoadImage` member the same way).
    struct SharedImageState {
        data: Vec<u8>,
        base_addr: u64,
    }

    // RUGRA-GLUE: `RugraLoadImage` equivalent (sleigh_shim/rugra_sleigh.cpp:88-137):
    // owns one contiguous byte image; `load_fill` mirrors its exact
    // wrap-subtraction bounds check, partial-copy, and zero-fill semantics.
    struct SharedLoadImage {
        shared: Rc<RefCell<SharedImageState>>,
    }

    impl LoadImage for SharedLoadImage {
        // RUGRA-GLUE: mirror of `RugraLoadImage::getArchType`'s sibling name accessor
        fn get_file_name(&self) -> &str {
            "rugra"
        }

        // RUGRA-GLUE: mirror of RugraLoadImage::loadFill (rugra_sleigh.cpp:108-133):
        // unsigned `start - base_addr` modulo wrap (RawLoadImage behavior the shim
        // preserves), DataUnavailError message text identical, `min(requested,
        // available)` copy then zero-fill of the remainder.
        fn load_fill(&mut self, ptr: &mut [u8], addr: &Address) -> KunaResult<()> {
            let state = self.shared.borrow();
            let start = addr.get_offset();
            let relative = start.wrapping_sub(state.base_addr);
            if relative >= state.data.len() as u64 {
                let mut message = format!("Unable to load {} bytes at ", ptr.len());
                message.push(addr.get_shortcut());
                addr.print_raw(&mut message)?;
                return Err(KunaError::DataUnavail { explain: message });
            }
            let requested = ptr.len();
            let relative = relative as usize;
            let available = state.data.len() - relative;
            let copied = requested.min(available);
            ptr[..copied].copy_from_slice(&state.data[relative..relative + copied]);
            for byte in &mut ptr[copied..] {
                *byte = 0;
            }
            Ok(())
        }

        // RUGRA-GLUE: mirror of RugraLoadImage::getArchType (rugra_sleigh.cpp:135)
        fn get_arch_type(&self) -> Vec<u8> {
            b"rugra".to_vec()
        }

        // RUGRA-GLUE: mirror of RugraLoadImage::adjustVma (rugra_sleigh.cpp:136 no-op)
        fn adjust_vma(&mut self, _adjust: i64) {}
    }

    // RUGRA-GLUE: kuna stores the manager index in the LOAD/STORE space-id
    // constant (kuna-sleigh sleigh.rs `spaceid_const`, LOSS-015) where the C++
    // runtime stored the `AddrSpace*` pointer value; both shims normalize the
    // wire value to the space index, so the wire bytes agree.
    const SIZEOF_SPACE: u32 = 8;

    // RUGRA-GLUE: `RugraPcodeEmit` equivalent (sleigh_shim/rugra_sleigh.cpp:154-244).
    // Identity is keyed by the address of each emitted varnode: the kuna engine
    // emits `&pool[range]` slices after the whole instruction is built
    // (one_instruction -> PcodeCacher::emit, mirroring sleigh.cc:776
    // `pcode_cache.emit` after `builder.build`), so pool slot addresses are
    // stable within one decode and equal addresses mean the same C++ pool
    // pointer — preserving the cross-op aliasing (e.g. the synthesized STORE's
    // input[2] aliasing the value op's output, sleigh.cc:265 `storevars+2`).
    struct RustPcodeCollector {
        ops: Vec<PcodeOpC>,
        identities: HashMap<usize, u64>,
        const_space_index: i32,
        num_spaces: i32,
        next_identity: u64,
        deferred: Option<SleighDecodeError>,
    }

    impl RustPcodeCollector {
        // RUGRA-GLUE: mirror of RugraPcodeEmit's constructor space table setup
        fn new(engine: &Sleigh) -> Self {
            let manager = engine.manager_rc();
            let const_space_index = manager
                .get_constant_space()
                .expect("constant space registered during .sla decode")
                .get_index();
            let num_spaces = manager.num_spaces();
            Self {
                ops: Vec::new(),
                identities: HashMap::new(),
                const_space_index,
                num_spaces,
                next_identity: 0,
                deferred: None,
            }
        }

        // RUGRA-GLUE: kuna PcodeEmit::dump cannot fail, so impossible-emission
        // failures (the C++ emitter threw LowlevelError out of oneInstruction)
        // park here and surface after the decode call returns.
        fn fail_lowlevel(&mut self, message: &str) {
            if self.deferred.is_none() {
                self.deferred = Some(SleighDecodeError {
                    kind: SleighErrorKind::Lowlevel,
                    message: message.as_bytes().to_vec(),
                    instruction_length: None,
                });
            }
        }

        // RUGRA-GLUE: mirror of RugraPcodeEmit::requireSpaceIndex; kuna's
        // `Option<Rc<AddrSpace>>` carries the manager index directly.
        fn require_space_index(&mut self, space: Option<&Rc<kuna_base::space::AddrSpace>>) -> i32 {
            match space {
                Some(space) => space.get_index(),
                None => {
                    self.fail_lowlevel("SLEIGH emitted a null address space");
                    -1
                }
            }
        }

        // RUGRA-GLUE: mirror of RugraPcodeEmit::identityFor over pool slot addresses
        fn identity_for(&mut self, varnode: &VarnodeData) -> u64 {
            let key = std::ptr::from_ref(varnode) as usize;
            if let Some(existing) = self.identities.get(&key) {
                return *existing;
            }
            let identity = self.next_identity;
            self.next_identity += 1;
            self.identities.insert(key, identity);
            identity
        }

        // RUGRA-GLUE: mirror of RugraPcodeEmit::copyVarnode (rugra_sleigh.cpp:181-205);
        // LOAD/STORE input 0 is normalized to the target space index on the wire.
        fn copy_varnode(
            &mut self,
            varnode: &VarnodeData,
            opcode: OpCode,
            input_slot: i32,
            is_input: bool,
        ) -> VarnodeC {
            let mut copied = VarnodeC {
                space: self.require_space_index(varnode.space.as_ref()),
                size: varnode.size,
                offset: varnode.offset,
                space_ref: -1,
                identity: self.identity_for(varnode),
            };
            if is_input
                && input_slot == 0
                && (opcode == OpCode::CPUI_LOAD || opcode == OpCode::CPUI_STORE)
            {
                if copied.space != self.const_space_index || copied.size != SIZEOF_SPACE {
                    self.fail_lowlevel("SLEIGH emitted an invalid LOAD/STORE space-id operand");
                    return copied;
                }
                // kuna LOSS-015: the stored offset already IS the target
                // space's manager index (the C++ stored the space pointer and
                // the shim remapped it via space_pointer_indices).
                let Ok(target) = i32::try_from(copied.offset) else {
                    self.fail_lowlevel(
                        "SLEIGH emitted an unknown LOAD/STORE address-space pointer",
                    );
                    return copied;
                };
                if target < 0 || target >= self.num_spaces {
                    self.fail_lowlevel(
                        "SLEIGH emitted an unknown LOAD/STORE address-space pointer",
                    );
                    return copied;
                }
                copied.offset = target as u64;
                copied.space_ref = target;
            }
            copied
        }

        // RUGRA-GLUE: consume the collected wire ops in emission order
        fn into_ops(self) -> Vec<PcodeOpC> {
            self.ops
        }
    }

    impl PcodeEmit for RustPcodeCollector {
        // RUGRA-GLUE: mirror of RugraPcodeEmit::dump (rugra_sleigh.cpp:222-243)
        fn dump(
            &mut self,
            addr: &Address,
            opc: OpCode,
            outvar: Option<&VarnodeData>,
            vars: &[VarnodeData],
        ) {
            if self.deferred.is_some() {
                return;
            }
            let address_space = self.require_space_index(addr.get_space());
            let output = outvar.map(|v| self.copy_varnode(v, opc, -1, false));
            let inputs = vars
                .iter()
                .enumerate()
                .map(|(index, varnode)| self.copy_varnode(varnode, opc, index as i32, true))
                .collect();
            self.ops.push(PcodeOpC {
                address_space,
                address_offset: addr.get_offset(),
                opcode: opc as i32,
                num_inputs: vars.len() as i32,
                has_output: output.is_some() as i32,
                output: output.unwrap_or_default(),
                inputs,
            });
        }
    }

    pub(crate) struct RustSleighEngine {
        sleigh: Sleigh,
        image: Rc<RefCell<SharedImageState>>,
        decode_started: bool,
    }

    impl RustSleighEngine {
        // RUGRA-GLUE: mirror of rugra_sleigh_create (rugra_sleigh.cpp:325-348):
        // construct Sleigh(loader, ContextInternal), then initialize from the
        // .sla file; any failure maps to None exactly like the C++ catch-all.
        pub(crate) fn new(sla_path: &std::path::Path) -> Option<Self> {
            let bytes = std::fs::read(sla_path).ok()?;
            let image = Rc::new(RefCell::new(SharedImageState {
                data: Vec::new(),
                base_addr: 0,
            }));
            let loader = SharedLoadImage { shared: Rc::clone(&image) };
            let mut sleigh = Sleigh::new(Box::new(loader), Box::new(ContextInternal::new()));
            sleigh.initialize_from_sla(&bytes).ok()?;
            Some(Self {
                sleigh,
                image,
                decode_started: false,
            })
        }

        // RUGRA-GLUE: mirror of rugra_sleigh_set_image (rugra_sleigh.cpp:350-372):
        // the decode_started guard is InvalidState; a zero-length image is the
        // same "empty vector" state the C++ setBytes produced.
        pub(crate) fn try_set_image(
            &mut self,
            bytes: &[u8],
            base_addr: u64,
        ) -> Result<(), SleighDecodeError> {
            if self.decode_started {
                return Err(SleighDecodeError {
                    kind: SleighErrorKind::InvalidState,
                    message: b"Cannot replace a SLEIGH image after decoding has started".to_vec(),
                    instruction_length: None,
                });
            }
            let mut state = self.image.borrow_mut();
            state.data = bytes.to_vec();
            state.base_addr = base_addr;
            Ok(())
        }

        // RUGRA-GLUE: mirror of rugra_sleigh_set_context (rugra_sleigh.cpp:374-396):
        // ContextInternal::setVariableDefault with the decode_started guard.
        pub(crate) fn try_set_context(
            &mut self,
            name: &str,
            value: i32,
        ) -> Result<(), SleighDecodeError> {
            if self.decode_started {
                return Err(SleighDecodeError {
                    kind: SleighErrorKind::InvalidState,
                    message: b"Cannot change SLEIGH context after decoding has started".to_vec(),
                    instruction_length: None,
                });
            }
            self.sleigh
                .with_context_db_mut(|db| db.set_variable_default(name.as_bytes(), value as u32))
                .map_err(map_kuna_error)
        }

        // RUGRA-GLUE: mirror of rugra_sleigh_decode (rugra_sleigh.cpp:398-417):
        // decode at Address(defaultCodeSpace, offset) through the collector,
        // surfacing a deferred emitter failure over a successful decode.
        pub(crate) fn one_instruction(
            &mut self,
            offset: u64,
        ) -> Result<DecodedInstruction, SleighDecodeError> {
            self.decode_started = true;
            let code_space = self
                .sleigh
                .manager_rc()
                .get_default_code_space()
                .expect("default code space registered during .sla decode")
                .clone();
            let address = Address::new(code_space, offset);
            let mut collector = RustPcodeCollector::new(&self.sleigh);
            match self.sleigh.one_instruction(&mut collector, &address) {
                Ok(step) => {
                    if let Some(deferred) = collector.deferred {
                        return Err(deferred);
                    }
                    Ok(DecodedInstruction {
                        step,
                        ops: collector.into_ops(),
                    })
                }
                Err(error) => Err(map_kuna_error(error)),
            }
        }

        // RUGRA-GLUE: SLEIGH printAssembly mnemonic probe (translate.hh:442
        // Translate::printAssembly / sleigh.cc:722 Sleigh::printAssembly).
        // The linear driver walks consume this to classify no-effect padding
        // by the .sla's own constructor table (the :NOP rm32 constructors of
        // ia.sinc:4136-4137 have empty templates but their rm operands carry
        // attached address-computation semantics, so the ENGINE emits the
        // operand pcode — both C++ SLEIGH and kuna do, Phase2 op-for-op
        // 698,605 decodes zero-diff). Ghidra's own pipeline never lifts
        // unreachable padding (followFlow is reachability-driven), so the
        // oracle IR never contains those ops; a LINEAR walk must filter them
        // by the oracle's own mnemonic classification to keep the same
        // effective IR.
        pub(crate) fn assembly_mnemonic(&self, offset: u64) -> Option<String> {
            let code_space = self
                .sleigh
                .manager_rc()
                .get_default_code_space()
                .expect("default code space registered during .sla decode")
                .clone();
            let address = Address::new(code_space, offset);
            let mut mnemonic = String::new();
            let mut body = String::new();
            self.sleigh
                .print_assembly_into(&address, &mut mnemonic, &mut body)
                .ok()?;
            Some(mnemonic)
        }

        // RUGRA-GLUE: mirror of rugra_sleigh_instruction_length (rugra_sleigh.cpp:496-507):
        // the C++ shim sets decode_started here too (the parse tree cache is
        // consulted), so a later set_image/set_context returns InvalidState;
        // any decode failure folds to None exactly like the C++ catch -> -1.
        pub(crate) fn instruction_length(&mut self, offset: u64) -> Option<usize> {
            self.decode_started = true;
            let code_space = self
                .sleigh
                .manager_rc()
                .get_default_code_space()
                .expect("default code space registered during .sla decode")
                .clone();
            let address = Address::new(code_space, offset);
            match self.sleigh.instruction_length(&address) {
                Ok(length) => (length > 0).then_some(length as usize),
                Err(_) => None,
            }
        }

        // RUGRA-GLUE: mirror of rugra_sleigh_num_spaces over the kuna manager
        pub(crate) fn num_spaces(&self) -> usize {
            usize::try_from(self.sleigh.manager_rc().num_spaces()).unwrap_or(0)
        }

        // RUGRA-GLUE: mirror of rugra_sleigh_space_info (spacetype ordinals
        // match space.hh IPTR_* on both sides)
        pub(crate) fn space_info(&self, index: usize) -> Option<(i32, String)> {
            let index = i32::try_from(index).ok()?;
            let manager = self.sleigh.manager_rc();
            let space = manager.get_space(index)?;
            Some((space.get_type() as i32, space.get_name().to_string()))
        }

        // RUGRA-GLUE: mirror of rugra_sleigh_num_registers over the kuna register
        // cross-reference (BTreeMap ordered by VarnodeData::operator< like the
        // C++ std::map the shim copied out of)
        pub(crate) fn num_registers(&self) -> usize {
            self.sleigh.base().get_all_registers().len()
        }

        // RUGRA-GLUE: mirror of rugra_sleigh_register_info (same map order)
        pub(crate) fn register_info(&self, index: usize) -> Option<(String, i32, u64, i32)> {
            let registers = self.sleigh.base().get_all_registers();
            let storage = registers.keys().nth(index)?;
            let name = registers.get(storage)?;
            let space = storage.space.as_ref()?;
            let size = i32::try_from(storage.size).ok()?;
            Some((
                String::from_utf8_lossy(name).into_owned(),
                space.get_index(),
                storage.offset,
                size,
            ))
        }
    }

    // RUGRA-GLUE: mirror of captureCurrentException (rugra_sleigh.cpp:296-319).
    // The C++ catch order maps: UnimplError(1) -> BadDataError(2) ->
    // DataUnavailError(3) -> SleighError(4) -> LowlevelError(5) ->
    // DecoderError(6) -> bad_alloc(11) -> std::exception(7) -> unknown(8).
    // KunaError variants Recov/Parse/Evaluation/ParamUnassigned/JumptableThunk/
    // Java all derive from LowlevelError upstream (error.hh:85/95,
    // opbehavior.hh:30, fspec.hh:64, jumptable.hh:42, ghidra_arch.hh:55) and
    // are caught by the LowlevelError arm, so they map to Lowlevel here.
    fn map_kuna_error(error: KunaError) -> SleighDecodeError {
        let (kind, message, instruction_length) = match error {
            KunaError::Unimpl {
                explain,
                instruction_length,
            } => (SleighErrorKind::Unimplemented, explain, Some(instruction_length)),
            KunaError::BadData { explain } => (SleighErrorKind::BadData, explain, None),
            KunaError::DataUnavail { explain } => {
                (SleighErrorKind::DataUnavailable, explain, None)
            }
            KunaError::Sleigh { explain } => (SleighErrorKind::Sleigh, explain, None),
            KunaError::Decoder { explain } => (SleighErrorKind::Decoder, explain, None),
            KunaError::Lowlevel { explain }
            | KunaError::Recov { explain }
            | KunaError::Parse { explain }
            | KunaError::Evaluation { explain }
            | KunaError::ParamUnassigned { explain }
            | KunaError::JumptableThunk { explain }
            | KunaError::Java {
                explain,
                ..
            } => (SleighErrorKind::Lowlevel, explain, None),
        };
        SleighDecodeError {
            kind,
            message: message.into_bytes(),
            instruction_length,
        }
    }
}


// RUGRA-GLUE: temporary SLEIGH-0002C/MISMATCH string scanner. Ghidra uses
// Document/Element plus ContextInternal::decodeFromSpec and preserves ranges,
// explicit masks, tracked registers, and child order; this helper does not.
fn simple_xml_find(xml: &str, tag: &str) -> Vec<String> {
    let opening = format!("<{tag}");
    let mut results = Vec::new();
    let mut position = 0;
    while let Some(relative_start) = xml[position..].find(&opening) {
        let start = position + relative_start;
        let Some(relative_end) = xml[start..].find('>') else {
            break;
        };
        let end = start + relative_end + 1;
        results.push(xml[start..end].to_string());
        position = end;
    }
    results
}

// RUGRA-GLUE: temporary SLEIGH-0002C/MISMATCH attribute scanner over a raw tag
fn get_attr(tag: &str, attribute: &str) -> Option<String> {
    let needle = format!("{attribute}=\"");
    let start = tag.find(&needle)? + needle.len();
    let remainder = &tag[start..];
    let end = remainder.find('"')?;
    Some(remainder[..end].to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn constructors_serialize_engine_init() {
        // Concurrent engine construction must be independently safe (the
        // retired C++ face exercised the XML parser's process globals; the
        // kuna engine has no shared global state).
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let constructors: Vec<_> = (0..2)
            .map(|_| {
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    super::SleighCtx::new().is_some()
                })
            })
            .collect();
        barrier.wait();
        for constructor in constructors {
            assert!(constructor.join().expect("constructor thread panicked"));
        }
    }

    #[test]
    fn rust_engine_decodes_mov_rax_rdi() {
        // Same smoke shape as examples/sleigh_test.rs, pinned to the Rust
        // engine by constructing the backend directly: MOV RAX,RDI must be a
        // 3-byte instruction in 64-bit context (addrsize=2) and emit p-code.
        let sla_path = std::path::Path::new("sleigh_specs/x86-64.sla");
        if !sla_path.exists() {
            return; // fixture tree unavailable (e.g. out-of-tree cargo test)
        }
        let mut engine = super::rust_backend::RustSleighEngine::new(sla_path)
            .expect("rust SLEIGH engine initializes");
        engine
            .try_set_context("addrsize", 2)
            .expect("addrsize default");
        engine.try_set_context("opsize", 1).expect("opsize default");
        engine
            .try_set_context("longMode", 1)
            .expect("longMode default");
        let code = [0x48, 0x89, 0xf8, 0xc3];
        engine.try_set_image(&code, 0).expect("image");
        let decoded = engine.one_instruction(0).expect("decode MOV RAX,RDI");
        assert_eq!(decoded.step, 3);
        assert!(!decoded.ops.is_empty());
    }
}
