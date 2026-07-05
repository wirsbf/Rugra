use std::sync::OnceLock;

#[repr(C)]
pub struct VarnodeC {
    pub space: i32,
    pub offset: u64,
    pub size: i32,
}

#[repr(C)]
pub struct PcodeOpC {
    pub opcode: i32,
    pub num_inputs: i32,
    pub has_output: i32,
    pub output: VarnodeC,
    pub inputs: [VarnodeC; 16],
}

extern "C" {
    // RUGRA-GLUE: rugra_sleigh_create — FFI helper
    fn rugra_sleigh_create(sla_path: *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    // RUGRA-GLUE: rugra_sleigh_set_image — FFI helper
    fn rugra_sleigh_set_image(handle: *mut std::ffi::c_void, bytes: *const u8, len: u64, base_addr: u64);
    // RUGRA-GLUE: rugra_sleigh_decode — FFI helper
    fn rugra_sleigh_decode(
        handle: *mut std::ffi::c_void,
        offset: u64,
        ops: *mut PcodeOpC,
        max_ops: i32,
    ) -> i32;
    // RUGRA-GLUE: rugra_sleigh_instruction_length — FFI helper
    fn rugra_sleigh_instruction_length(handle: *mut std::ffi::c_void, offset: u64) -> i32;
    // RUGRA-GLUE: rugra_sleigh_num_spaces — FFI helper
    fn rugra_sleigh_num_spaces(handle: *mut std::ffi::c_void) -> i32;
    // RUGRA-GLUE: rugra_sleigh_space_info — FFI helper
    fn rugra_sleigh_space_info(
        handle: *mut std::ffi::c_void,
        index: i32,
        out_type: *mut i32,
        out_name: *mut std::os::raw::c_char,
        name_max: i32,
    );
    // RUGRA-GLUE: rugra_sleigh_num_registers — FFI helper
    fn rugra_sleigh_num_registers(handle: *mut std::ffi::c_void) -> i32;
    // RUGRA-GLUE: rugra_sleigh_register_info — FFI helper
    fn rugra_sleigh_register_info(
        handle: *mut std::ffi::c_void,
        index: i32,
        out_name: *mut std::os::raw::c_char,
        name_max: i32,
        out_space: *mut i32,
        out_offset: *mut u64,
        out_size: *mut i32,
    );
    // RUGRA-GLUE: rugra_sleigh_destroy — FFI helper
    fn rugra_sleigh_destroy(handle: *mut std::ffi::c_void);
}

pub struct SleighCtx {
    handle: *mut std::ffi::c_void,
}

unsafe impl Send for SleighCtx {}

// RUGRA-GLUE: SleighCtx — Rust wrapper for SLEIGH C++ engine via FFI
static SLA_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();

// RUGRA-GLUE: set_sla_path — configure .sla file location
pub fn set_sla_path(path: &str) {
    let _ = SLA_PATH.set(std::path::PathBuf::from(path));
}

impl SleighCtx {
    // RUGRA-GLUE: new — create SLEIGH context from .sla file
    pub fn new() -> Option<Self> {
        let default_path = std::path::PathBuf::from("sleigh_specs/x86-64.sla");
        let path = SLA_PATH.get().unwrap_or(&default_path);
        let abs = std::fs::canonicalize(path).ok()?;
        let c_path = std::ffi::CString::new(abs.to_str()?).ok()?;
        let handle = unsafe { rugra_sleigh_create(c_path.as_ptr()) };
        if handle.is_null() {
            eprintln!("[SLEIGH-FFI] create returned NULL: {:?}", abs);
            None
        } else {
            Some(Self { handle })
        }
    }

    // RUGRA-GLUE: set_image — set binary image bytes for SLEIGH decoding
    pub fn set_image(&mut self, bytes: &[u8], base_addr: u64) {
        unsafe { rugra_sleigh_set_image(self.handle, bytes.as_ptr(), bytes.len() as u64, base_addr) }
    }

    // RUGRA-GLUE: decode — decode instruction at address, return p-code ops
    pub fn decode(&mut self, offset: u64) -> Vec<PcodeOpC> {
        let mut buf: Vec<PcodeOpC> = Vec::with_capacity(64);
        unsafe {
            buf.set_len(64);
            let n = rugra_sleigh_decode(self.handle, offset, buf.as_mut_ptr(), 64);
            if n < 0 {
                return Vec::new();
            }
            buf.set_len(n as usize);
        }
        buf
    }

    // RUGRA-GLUE: instruction_length — FFI wrapper for SLEIGH C++ engine
    pub fn instruction_length(&self, offset: u64) -> Option<usize> {
        let n = unsafe { rugra_sleigh_instruction_length(self.handle, offset) };
        if n > 0 { Some(n as usize) } else { None }
    }

    // RUGRA-GLUE: num_spaces — FFI wrapper for SLEIGH C++ engine
    pub fn num_spaces(&self) -> usize {
        unsafe { rugra_sleigh_num_spaces(self.handle) as usize }
    }

    // RUGRA-GLUE: space_info — FFI wrapper for SLEIGH C++ engine
    pub fn space_info(&self, index: usize) -> Option<(i32, String)> {
        let mut ty: i32 = 0;
        let mut name_buf = [0i8; 64];
        unsafe {
            rugra_sleigh_space_info(
                self.handle, index as i32, &mut ty, name_buf.as_mut_ptr(), 64,
            );
        }
        let name = cstr_to_string(&name_buf)?;
        Some((ty, name))
    }

    // RUGRA-GLUE: num_registers — FFI wrapper for SLEIGH C++ engine
    pub fn num_registers(&self) -> usize {
        unsafe { rugra_sleigh_num_registers(self.handle) as usize }
    }

    // RUGRA-GLUE: register_info — FFI wrapper for SLEIGH C++ engine
    pub fn register_info(&self, index: usize) -> Option<(String, i32, u64, i32)> {
        let mut name_buf = [0i8; 64];
        let mut sp: i32 = 0;
        let mut off: u64 = 0;
        let mut sz: i32 = 0;
        unsafe {
            rugra_sleigh_register_info(
                self.handle, index as i32, name_buf.as_mut_ptr(), 64,
                &mut sp, &mut off, &mut sz,
            );
        }
        let name = cstr_to_string(&name_buf)?;
        Some((name, sp, off, sz))
    }
}

impl Drop for SleighCtx {
    // RUGRA-GLUE: drop — FFI helper
    fn drop(&mut self) {
        unsafe { rugra_sleigh_destroy(self.handle) }
    }
}

// RUGRA-GLUE: cstr_to_string — FFI helper
fn cstr_to_string(buf: &[i8]) -> Option<String> {
    let bytes: Vec<u8> = buf.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    if bytes.is_empty() { None } else { Some(String::from_utf8_lossy(&bytes).into_owned()) }
}
