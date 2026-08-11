use std::ffi::{c_char, c_void, CString};
use std::fmt;
use std::sync::OnceLock;

const SLEIGH_ABI_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VarnodeC {
    pub space: i32,
    pub offset: u64,
    pub size: u32,
    /// `-1` for an ordinary varnode; otherwise the normalized target space
    /// index for the space-id operand of LOAD/STORE.
    pub space_ref: i32,
    /// First-seen ID for the original `VarnodeData*` within one instruction.
    /// Equal IDs preserve cross-op pointer aliasing without exposing addresses.
    pub identity: u64,
}

impl Default for VarnodeC {
    // RUGRA-GLUE: Rust DTO default used only for an absent C++ PcodeEmit output
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
    /// Exact bytes of Ghidra's `std::string::explain`; presentation is lossy.
    pub message: Vec<u8>,
    /// Present only for `UnimplError`, including a meaningful value of zero.
    pub instruction_length: Option<i32>,
}

impl SleighDecodeError {
    // RUGRA-GLUE: construct a Rust-side validation failure at the C ABI boundary
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
    // RUGRA-GLUE: Rust Error presentation for a typed Ghidra/FFI error record
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

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RugraVarnodeWire {
    space: i32,
    size: u32,
    offset: u64,
    space_ref: i32,
    flags: u32,
    identity: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RugraPcodeOpWire {
    address_space: i32,
    has_output: u32,
    address_offset: u64,
    opcode: i32,
    num_inputs: i32,
    output: RugraVarnodeWire,
}

unsafe extern "C" {
    // RUGRA-GLUE: C ABI constructor for Ghidra's in-process C++ Sleigh object graph
    fn rugra_sleigh_create(sla_path: *const c_char) -> *mut c_void;
    // RUGRA-GLUE: owned-image C ABI adapter; the returned result is C++ owned
    fn rugra_sleigh_set_image(
        handle: *mut c_void,
        bytes: *const u8,
        len: u64,
        base_addr: u64,
    ) -> *mut c_void;
    // RUGRA-GLUE: context-default C ABI adapter used before decoding begins
    fn rugra_sleigh_set_context(
        handle: *mut c_void,
        name: *const c_char,
        value: i32,
    ) -> *mut c_void;
    // RUGRA-GLUE: atomic oneInstruction adapter returning an owned opaque result
    fn rugra_sleigh_decode(handle: *mut c_void, offset: u64) -> *mut c_void;
    // RUGRA-GLUE: fixed-width result accessors avoid exposing C++ containers
    fn rugra_sleigh_result_abi_version(result: *const c_void) -> u32;
    // RUGRA-GLUE: fixed-width result accessors avoid exposing C++ containers
    fn rugra_sleigh_result_error_kind(result: *const c_void) -> u32;
    // RUGRA-GLUE: fixed-width result accessors avoid exposing C++ containers
    fn rugra_sleigh_result_step(result: *const c_void) -> i32;
    // RUGRA-GLUE: fixed-width result accessors avoid exposing C++ containers
    fn rugra_sleigh_result_has_instruction_length(result: *const c_void) -> u32;
    // RUGRA-GLUE: fixed-width result accessors avoid exposing C++ containers
    fn rugra_sleigh_result_instruction_length(result: *const c_void) -> i32;
    // RUGRA-GLUE: borrowed result message bytes remain owned by the opaque result
    fn rugra_sleigh_result_message_data(result: *const c_void) -> *const u8;
    // RUGRA-GLUE: borrowed result message length excludes any terminator
    fn rugra_sleigh_result_message_len(result: *const c_void) -> u64;
    // RUGRA-GLUE: query the complete, dynamically sized emitted-op count
    fn rugra_sleigh_result_num_ops(result: *const c_void) -> u64;
    // RUGRA-GLUE: copy one fixed-width op header from the C++ owned result
    fn rugra_sleigh_result_op(
        result: *const c_void,
        index: u64,
        output: *mut RugraPcodeOpWire,
    ) -> i32;
    // RUGRA-GLUE: copy one ordered input from the C++ owned result
    fn rugra_sleigh_result_input(
        result: *const c_void,
        op_index: u64,
        input_index: u64,
        output: *mut RugraVarnodeWire,
    ) -> i32;
    // RUGRA-GLUE: destroy an opaque result with the same C++ allocator
    fn rugra_sleigh_result_destroy(result: *mut c_void);
    // RUGRA-GLUE: legacy length-only C ABI retained until SLEIGH-0002D
    fn rugra_sleigh_instruction_length(handle: *mut c_void, offset: u64) -> i32;
    // RUGRA-GLUE: C ABI metadata accessor
    fn rugra_sleigh_num_spaces(handle: *mut c_void) -> i32;
    // RUGRA-GLUE: C ABI metadata accessor
    fn rugra_sleigh_space_info(
        handle: *mut c_void,
        index: i32,
        out_type: *mut i32,
        out_name: *mut c_char,
        name_max: i32,
    ) -> i32;
    // RUGRA-GLUE: C ABI metadata accessor
    fn rugra_sleigh_num_registers(handle: *mut c_void) -> i32;
    // RUGRA-GLUE: C ABI metadata accessor
    fn rugra_sleigh_register_info(
        handle: *mut c_void,
        index: i32,
        out_name: *mut c_char,
        name_max: i32,
        out_space: *mut i32,
        out_offset: *mut u64,
        out_size: *mut i32,
    ) -> i32;
    // RUGRA-GLUE: C ABI destructor for the Ghidra C++ object graph
    fn rugra_sleigh_destroy(handle: *mut c_void);
}

struct SleighResultGuard(*mut c_void);

impl Drop for SleighResultGuard {
    // RUGRA-GLUE: RAII guard ensuring every C++ owned result uses its C++ destructor
    fn drop(&mut self) {
        unsafe { rugra_sleigh_result_destroy(self.0) }
    }
}

pub struct SleighCtx {
    handle: *mut c_void,
}

unsafe impl Send for SleighCtx {}

// RUGRA-GLUE: process-wide Rust configuration for the default SLEIGH asset path
static SLA_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();

// RUGRA-GLUE: configure the default `.sla` location before the first context is made
pub fn set_sla_path(path: &str) {
    let _ = SLA_PATH.set(std::path::PathBuf::from(path));
}

impl SleighCtx {
    // RUGRA-GLUE: create the Rust owner for a Ghidra C++ SLEIGH engine
    pub fn new() -> Option<Self> {
        let default_path = std::path::PathBuf::from("sleigh_specs/x86-64.sla");
        let path = SLA_PATH.get().unwrap_or(&default_path);
        let absolute = std::fs::canonicalize(path).ok()?;
        let c_path = CString::new(absolute.to_str()?).ok()?;
        let handle = unsafe { rugra_sleigh_create(c_path.as_ptr()) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }

    // RUGRA-GLUE: deep-copy a Rust image into the C++ owner before decoding starts
    pub fn try_set_image(&mut self, bytes: &[u8], base_addr: u64) -> Result<(), SleighDecodeError> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| SleighDecodeError::bridge(b"image length exceeds u64".to_vec()))?;
        let result =
            unsafe { rugra_sleigh_set_image(self.handle, bytes.as_ptr(), length, base_addr) };
        check_operation_result(result)
    }

    // RUGRA-GLUE: compatibility wrapper retained for existing lifter callers until SLEIGH-0002D
    pub fn set_image(&mut self, bytes: &[u8], base_addr: u64) {
        let _ = self.try_set_image(bytes, base_addr);
    }

    // RUGRA-GLUE: set a context default before decoding starts, preserving typed failures
    pub fn try_set_context(&mut self, name: &str, value: i32) -> Result<(), SleighDecodeError> {
        let c_name = CString::new(name)
            .map_err(|_| SleighDecodeError::bridge(b"context name contains NUL".to_vec()))?;
        let result = unsafe { rugra_sleigh_set_context(self.handle, c_name.as_ptr(), value) };
        check_operation_result(result)
    }

    // RUGRA-GLUE: compatibility wrapper retained for the temporary pspec scanner
    pub fn set_context(&mut self, name: &str, value: i32) {
        let _ = self.try_set_context(name, value);
    }

    // RUGRA-GLUE: temporary SLEIGH-0002C/MISMATCH pspec scanner; it does not model
    // ContextInternal ranges, masks, tracked registers, or child ordering
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
    // ordered dynamic operands, aliases, and typed Ghidra exceptions
    pub fn one_instruction(
        &mut self,
        offset: u64,
    ) -> Result<DecodedInstruction, SleighDecodeError> {
        let result = unsafe { rugra_sleigh_decode(self.handle, offset) };
        if result.is_null() {
            return Err(SleighDecodeError {
                kind: SleighErrorKind::OutOfMemory,
                message: b"C++ failed to allocate a SLEIGH result".to_vec(),
                instruction_length: None,
            });
        }
        let _guard = SleighResultGuard(result);
        check_result_abi(result)?;

        let raw_kind = unsafe { rugra_sleigh_result_error_kind(result) };
        if raw_kind != 0 {
            return Err(error_from_result(result, raw_kind));
        }

        let op_count = usize::try_from(unsafe { rugra_sleigh_result_num_ops(result) })
            .map_err(|_| SleighDecodeError::bridge(b"op count exceeds usize".to_vec()))?;
        let mut ops = Vec::with_capacity(op_count);
        for op_index in 0..op_count {
            let mut wire = RugraPcodeOpWire::default();
            let copied = unsafe { rugra_sleigh_result_op(result, op_index as u64, &mut wire) };
            if copied == 0 {
                return Err(SleighDecodeError::bridge(
                    format!("C++ omitted op {op_index}").into_bytes(),
                ));
            }
            if wire.num_inputs < 0 {
                return Err(SleighDecodeError::bridge(
                    format!("op {op_index} has a negative input count").into_bytes(),
                ));
            }
            if wire.has_output > 1 {
                return Err(SleighDecodeError::bridge(
                    format!("op {op_index} has an invalid output flag").into_bytes(),
                ));
            }

            let input_count = usize::try_from(wire.num_inputs)
                .map_err(|_| SleighDecodeError::bridge(b"input count exceeds usize".to_vec()))?;
            let mut inputs = Vec::with_capacity(input_count);
            for input_index in 0..input_count {
                let mut input = RugraVarnodeWire::default();
                let copied = unsafe {
                    rugra_sleigh_result_input(
                        result,
                        op_index as u64,
                        input_index as u64,
                        &mut input,
                    )
                };
                if copied == 0 {
                    return Err(SleighDecodeError::bridge(
                        format!("C++ omitted op {op_index} input {input_index}").into_bytes(),
                    ));
                }
                inputs.push(copy_varnode(input)?);
            }

            ops.push(PcodeOpC {
                address_space: wire.address_space,
                address_offset: wire.address_offset,
                opcode: wire.opcode,
                num_inputs: wire.num_inputs,
                has_output: wire.has_output as i32,
                output: if wire.has_output == 0 {
                    VarnodeC::default()
                } else {
                    copy_varnode(wire.output)?
                },
                inputs,
            });
        }

        Ok(DecodedInstruction {
            step: unsafe { rugra_sleigh_result_step(result) },
            ops,
        })
    }

    // RUGRA-GLUE: compatibility bridge that still folds typed errors to an empty
    // vector for legacy lifter callers; SLEIGH-0002D removes this ambiguity
    pub fn decode(&mut self, offset: u64) -> Vec<PcodeOpC> {
        self.one_instruction(offset)
            .map(|instruction| instruction.ops)
            .unwrap_or_default()
    }

    // RUGRA-GLUE: legacy length-only wrapper retained until callers consume the
    // atomic `one_instruction` result in SLEIGH-0002D
    pub fn instruction_length(&self, offset: u64) -> Option<usize> {
        let length = unsafe { rugra_sleigh_instruction_length(self.handle, offset) };
        (length > 0).then_some(length as usize)
    }

    // RUGRA-GLUE: query the number of address spaces exposed by the C++ translator
    pub fn num_spaces(&self) -> usize {
        let count = unsafe { rugra_sleigh_num_spaces(self.handle) };
        usize::try_from(count).unwrap_or(0)
    }

    // RUGRA-GLUE: copy one space catalog entry across the fixed-width C ABI
    pub fn space_info(&self, index: usize) -> Option<(i32, String)> {
        let index = i32::try_from(index).ok()?;
        let mut space_type = 0;
        let mut name_buffer = [0 as c_char; 64];
        let valid = unsafe {
            rugra_sleigh_space_info(
                self.handle,
                index,
                &mut space_type,
                name_buffer.as_mut_ptr(),
                name_buffer.len() as i32,
            )
        };
        if valid == 0 {
            return None;
        }
        Some((space_type, cstr_to_string(&name_buffer)?))
    }

    // RUGRA-GLUE: query the number of registers exposed by the C++ translator
    pub fn num_registers(&self) -> usize {
        let count = unsafe { rugra_sleigh_num_registers(self.handle) };
        usize::try_from(count).unwrap_or(0)
    }

    // RUGRA-GLUE: copy one register catalog entry across the fixed-width C ABI
    pub fn register_info(&self, index: usize) -> Option<(String, i32, u64, i32)> {
        let index = i32::try_from(index).ok()?;
        let mut name_buffer = [0 as c_char; 64];
        let mut space = 0;
        let mut offset = 0;
        let mut size = 0;
        let valid = unsafe {
            rugra_sleigh_register_info(
                self.handle,
                index,
                name_buffer.as_mut_ptr(),
                name_buffer.len() as i32,
                &mut space,
                &mut offset,
                &mut size,
            )
        };
        if valid == 0 {
            return None;
        }
        Some((cstr_to_string(&name_buffer)?, space, offset, size))
    }
}

impl Drop for SleighCtx {
    // RUGRA-GLUE: release the C++ engine through its own allocator
    fn drop(&mut self) {
        unsafe { rugra_sleigh_destroy(self.handle) }
    }
}

// RUGRA-GLUE: verify the versioned opaque result contract before reading fields
fn check_result_abi(result: *const c_void) -> Result<(), SleighDecodeError> {
    let version = unsafe { rugra_sleigh_result_abi_version(result) };
    if version != SLEIGH_ABI_VERSION {
        return Err(SleighDecodeError::bridge(
            format!("SLEIGH ABI version {version}, expected {SLEIGH_ABI_VERSION}").into_bytes(),
        ));
    }
    Ok(())
}

// RUGRA-GLUE: consume a C++ owned status-only result with RAII cleanup
fn check_operation_result(result: *mut c_void) -> Result<(), SleighDecodeError> {
    if result.is_null() {
        return Err(SleighDecodeError {
            kind: SleighErrorKind::OutOfMemory,
            message: b"C++ failed to allocate a SLEIGH operation result".to_vec(),
            instruction_length: None,
        });
    }
    let _guard = SleighResultGuard(result);
    check_result_abi(result)?;
    let raw_kind = unsafe { rugra_sleigh_result_error_kind(result) };
    if raw_kind == 0 {
        Ok(())
    } else {
        Err(error_from_result(result, raw_kind))
    }
}

// RUGRA-GLUE: copy exact error bytes and the optional Unimpl length from C++
fn error_from_result(result: *const c_void, raw_kind: u32) -> SleighDecodeError {
    let kind = SleighErrorKind::from_raw(raw_kind).unwrap_or(SleighErrorKind::Bridge);
    let op_count = unsafe { rugra_sleigh_result_num_ops(result) };
    let step = unsafe { rugra_sleigh_result_step(result) };
    let has_instruction_length = unsafe { rugra_sleigh_result_has_instruction_length(result) };
    if op_count != 0 || step != 0 {
        return SleighDecodeError::bridge(
            format!("C++ error result leaked step {step} or {op_count} operations").into_bytes(),
        );
    }
    if has_instruction_length > 1
        || (has_instruction_length != 0 && kind != SleighErrorKind::Unimplemented)
    {
        return SleighDecodeError::bridge(
            format!(
                "C++ error result has invalid instruction-length flag {has_instruction_length}"
            )
            .into_bytes(),
        );
    }
    let message = match copy_result_message(result) {
        Ok(message) => message,
        Err(error) => return error,
    };
    SleighDecodeError {
        kind,
        message,
        instruction_length: (has_instruction_length != 0)
            .then(|| unsafe { rugra_sleigh_result_instruction_length(result) }),
    }
}

// RUGRA-GLUE: copy a borrowed C++ string as bytes without assuming UTF-8
fn copy_result_message(result: *const c_void) -> Result<Vec<u8>, SleighDecodeError> {
    let length = usize::try_from(unsafe { rugra_sleigh_result_message_len(result) })
        .map_err(|_| SleighDecodeError::bridge(b"error message exceeds usize".to_vec()))?;
    if length == 0 {
        return Ok(Vec::new());
    }
    if length > isize::MAX as usize {
        return Err(SleighDecodeError::bridge(
            b"C++ error message exceeds Rust slice limits".to_vec(),
        ));
    }
    let data = unsafe { rugra_sleigh_result_message_data(result) };
    if data.is_null() {
        return Err(SleighDecodeError::bridge(
            b"non-empty C++ error message has a null pointer".to_vec(),
        ));
    }
    Ok(unsafe { std::slice::from_raw_parts(data, length) }.to_vec())
}

// RUGRA-GLUE: convert the fixed-width wire record to an owned Rust DTO
fn copy_varnode(wire: RugraVarnodeWire) -> Result<VarnodeC, SleighDecodeError> {
    if wire.flags != 0 {
        return Err(SleighDecodeError::bridge(
            format!("unknown varnode wire flags 0x{:x}", wire.flags).into_bytes(),
        ));
    }
    Ok(VarnodeC {
        space: wire.space,
        offset: wire.offset,
        size: wire.size,
        space_ref: wire.space_ref,
        identity: wire.identity,
    })
}

// RUGRA-GLUE: copy a fixed-size, NUL-terminated metadata buffer into Rust
fn cstr_to_string(buffer: &[c_char]) -> Option<String> {
    let bytes: Vec<u8> = buffer
        .iter()
        .take_while(|&&character| character != 0)
        .map(|&character| character as u8)
        .collect();
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
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
    use super::{RugraPcodeOpWire, RugraVarnodeWire, SleighCtx};
    use std::sync::{Arc, Barrier};

    #[test]
    fn wire_layout_matches_cpp_static_asserts() {
        assert_eq!(std::mem::size_of::<RugraVarnodeWire>(), 32);
        assert_eq!(std::mem::offset_of!(RugraVarnodeWire, offset), 8);
        assert_eq!(std::mem::offset_of!(RugraVarnodeWire, identity), 24);
        assert_eq!(std::mem::size_of::<RugraPcodeOpWire>(), 56);
        assert_eq!(std::mem::offset_of!(RugraPcodeOpWire, output), 24);
    }

    #[test]
    fn constructors_serialize_ghidra_xml_parser() {
        let barrier = Arc::new(Barrier::new(3));
        let constructors: Vec<_> = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    SleighCtx::new().is_some()
                })
            })
            .collect();
        barrier.wait();
        for constructor in constructors {
            assert!(constructor.join().expect("constructor thread panicked"));
        }
    }
}
