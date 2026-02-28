//! API Knowledge Base for Rugra Decompiler
//!
//! This module provides information about standard library functions (libc, etc.)
//! to assist in type recovery and parameter mapping during decompilation.

use crate::types::DataType;
use std::collections::HashMap;

/// Represents a function prototype for an external API call
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPrototype {
    /// Function name (e.g., "printf")
    pub name: String,
    /// Return type
    pub return_type: DataType,
    /// Parameter types in order
    pub parameter_types: Vec<DataType>,
    /// Whether the function is variadic (like printf)
    pub is_variadic: bool,
}

impl ApiPrototype {
    /// Create a new API prototype
    pub fn new(name: &str, ret: DataType, params: Vec<DataType>) -> Self {
        ApiPrototype {
            name: name.to_string(),
            return_type: ret,
            parameter_types: params,
            is_variadic: false,
        }
    }

    /// Set variadic flag
    pub fn variadic(mut self) -> Self {
        self.is_variadic = true;
        self
    }
}

/// Registry of known API prototypes
#[derive(Debug, Clone)]
pub struct ApiRegistry {
    prototypes: HashMap<String, ApiPrototype>,
}

impl ApiRegistry {
    /// Create a new registry and populate it with common symbols
    pub fn new() -> Self {
        let mut registry = ApiRegistry {
            prototypes: HashMap::new(),
        };
        registry.populate_libc();
        registry
    }

    /// Find a prototype by function name
    pub fn get_prototype(&self, name: &str) -> Option<&ApiPrototype> {
        self.prototypes.get(name)
    }

    /// Register a new prototype
    pub fn register(&mut self, proto: ApiPrototype) {
        self.prototypes.insert(proto.name.clone(), proto);
    }

    /// Populate the registry with standard libc function prototypes
    fn populate_libc(&mut self) {
        // void* malloc(size_t size)
        self.register(ApiPrototype::new(
            "malloc",
            DataType::Pointer(Box::new(DataType::Unknown(1)), 8),
            vec![DataType::Int(8, false)],
        ));

        // void free(void* ptr)
        self.register(ApiPrototype::new(
            "free",
            DataType::Void,
            vec![DataType::Pointer(Box::new(DataType::Unknown(1)), 8)],
        ));

        // int printf(const char* format, ...)
        self.register(ApiPrototype::new(
            "printf",
            DataType::Int(4, true),
            vec![DataType::Pointer(Box::new(DataType::Int(1, true)), 8)],
        ).variadic());

        // size_t strlen(const char* s)
        self.register(ApiPrototype::new(
            "strlen",
            DataType::Int(8, false),
            vec![DataType::Pointer(Box::new(DataType::Int(1, true)), 8)],
        ));

        // char* strcpy(char* dest, const char* src)
        self.register(ApiPrototype::new(
            "strcpy",
            DataType::Pointer(Box::new(DataType::Int(1, true)), 8),
            vec![
                DataType::Pointer(Box::new(DataType::Int(1, true)), 8),
                DataType::Pointer(Box::new(DataType::Int(1, true)), 8),
            ],
        ));

        // void* memset(void* s, int c, size_t n)
        self.register(ApiPrototype::new(
            "memset",
            DataType::Pointer(Box::new(DataType::Unknown(1)), 8),
            vec![
                DataType::Pointer(Box::new(DataType::Unknown(1)), 8),
                DataType::Int(4, true),
                DataType::Int(8, false),
            ],
        ));

        // void* memcpy(void* dest, const void* src, size_t n)
        self.register(ApiPrototype::new(
            "memcpy",
            DataType::Pointer(Box::new(DataType::Unknown(1)), 8),
            vec![
                DataType::Pointer(Box::new(DataType::Unknown(1)), 8),
                DataType::Pointer(Box::new(DataType::Unknown(1)), 8),
                DataType::Int(8, false),
            ],
        ));

        // ssize_t read(int fd, void* buf, size_t count)
        self.register(ApiPrototype::new(
            "read",
            DataType::Int(8, true),
            vec![
                DataType::Int(4, true),
                DataType::Pointer(Box::new(DataType::Unknown(1)), 8),
                DataType::Int(8, false),
            ],
        ));

        // ssize_t write(int fd, const void* buf, size_t count)
        self.register(ApiPrototype::new(
            "write",
            DataType::Int(8, true),
            vec![
                DataType::Int(4, true),
                DataType::Pointer(Box::new(DataType::Unknown(1)), 8),
                DataType::Int(8, false),
            ],
        ));

        // void exit(int status)
        self.register(ApiPrototype::new(
            "exit",
            DataType::Void,
            vec![DataType::Int(4, true)],
        ));
    }
}

impl Default for ApiRegistry {
    fn default() -> Self {
        Self::new()
    }
}
