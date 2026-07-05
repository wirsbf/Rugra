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
    // RUGRA-GLUE: rugra_sleigh_set_context — FFI helper
    fn rugra_sleigh_set_context(handle: *mut std::ffi::c_void, name: *const std::os::raw::c_char, val: i32);
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

    // RUGRA-GLUE: set_context — set context variable default
    pub fn set_context(&mut self, name: &str, val: i32) {
        let c_name = std::ffi::CString::new(name).unwrap();
        unsafe { rugra_sleigh_set_context(self.handle, c_name.as_ptr(), val) }
    }

    // RUGRA-GLUE: load_pspec — parse .pspec XML and set context defaults
    pub fn load_pspec(&mut self, pspec_path: &str) {
        let xml = match std::fs::read_to_string(pspec_path) {
            Ok(s) => s,
            Err(_) => return,
        };
        for cap in simple_xml_find(&xml, "set") {
            if let (Some(name), Some(val)) = (get_attr(&cap, "name"), get_attr(&cap, "val")) {
                if let Ok(v) = val.parse::<i32>() {
                    self.set_context(&name, v);
                }
            }
        }
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

// RUGRA-GLUE: simple_xml_find — Ghidra 的 Sleigh 编译器用 C++ 的 xml.cc
// (ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/xml.cc) 的
// `Element *Document::getRoot()` + `Element::getChild(string)` 解析 SLEIGH
// spec 输出。Rugra 在 sleigh_ffi 边界拿到的是 raw XML 字符串（Sleigh 编译器
// 以子进程方式运行），需自己解析。这个轻量字符串扫描替代 Ghidra 的
// Document/Element 树，只取所需 `<tag ...>` 起标签。无 1:1 对应。
fn simple_xml_find(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{}", tag);
    let mut results = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find(&open) {
        let abs = pos + start;
        if let Some(end) = xml[abs..].find('>') {
            results.push(xml[abs..abs+end+1].to_string());
            pos = abs + end + 1;
        } else { break; }
    }
    results
}

// RUGRA-GLUE: get_attr — 同上，对应 xml.cc `Element::getAttributeValue(name)`
// (`const string &Element::getAttributeValue(const string &nm) const`)。
// Ghidra 在 Element 树上查属性值；Rugra 在原始 tag 字符串里扫 `attr="..."`。
// 行为等价但 API 形态不同（Ghidra 树 vs Rugra 字符串扫描）。
fn get_attr(tag_str: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=\"", attr);
    let start = tag_str.find(&needle)? + needle.len();
    let rest = &tag_str[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
