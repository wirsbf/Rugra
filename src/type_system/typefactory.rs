//! Type management and deduplication
//!
//! Corresponds to Ghidra's `TypeFactory` class in `type.hh`. This class is responsible
//! for the lifecycle of all `Datatype` objects, ensuring that identical types are
//! deduplicated and providing a central point for type lookup.

use std::collections::BTreeMap;
use std::sync::Arc;
use crate::type_system::datatype::*;

/// Managed container for all Datatype objects
pub struct TypeFactory {
    /// All types managed by this factory, keyed by their unique name
    types: BTreeMap<String, Arc<Datatype>>,

    /// Cache for core types (void, int, etc.) for quick access
    core_types: BTreeMap<String, Arc<Datatype>>,

    /// The default size of a pointer for this architecture
    ptr_size: usize,
}

impl TypeFactory {
    /// Create a new TypeFactory and initialize core types
    ///
    /// # Arguments
    /// * `ptr_size` - Default pointer size for the target architecture (e.g., 4 or 8)
    pub fn new(ptr_size: usize) -> Self {
        let mut factory = Self {
            types: BTreeMap::new(),
            core_types: BTreeMap::new(),
            ptr_size,
        };
        factory.init_core_types();
        factory
    }

    /// Initialize the fundamental core types
    fn init_core_types(&mut self) {
        // Void type
        let void_type = Arc::new(Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)));
        self.add_core_type(void_type);

        // Boolean type
        let bool_type = Arc::new(Datatype::Base(TypeBase::new("bool".to_string(), 1, TypeMetatype::Bool)));
        self.add_core_type(bool_type);

        // Standard integer types
        let int_sizes = [1, 2, 4, 8];
        for &size in &int_sizes {
            // Signed integers
            let s_name = if size == 4 { "int".to_string() } else { format!("int{}", size) };
            let s_type = Arc::new(Datatype::Base(TypeBase::new(s_name, size, TypeMetatype::Int)));
            self.add_core_type(s_type);

            // Unsigned integers
            let u_name = if size == 4 { "uint".to_string() } else { format!("uint{}", size) };
            let u_type = Arc::new(Datatype::Base(TypeBase::new(u_name, size, TypeMetatype::Uint)));
            self.add_core_type(u_type);
        }

        // Floating point types
        let f_type4 = Arc::new(Datatype::Base(TypeBase::new("float".to_string(), 4, TypeMetatype::Float)));
        self.add_core_type(f_type4);
        let f_type8 = Arc::new(Datatype::Base(TypeBase::new("double".to_string(), 8, TypeMetatype::Float)));
        self.add_core_type(f_type8);
    }

    /// Internal helper to register a core type
    fn add_core_type(&mut self, mut dt: Arc<Datatype>) {
        if let Some(dt_mut) = Arc::get_mut(&mut dt) {
            match dt_mut {
                Datatype::Void(b) | Datatype::Base(b) => b.flags |= type_flags::CORETYPE,
                _ => {}
            }
        }
        let name = dt.get_name().to_string();
        self.core_types.insert(name.clone(), dt.clone());
        self.types.insert(name, dt);
    }

    /// Find a type by name
    pub fn find_by_name(&self, name: &str) -> Option<Arc<Datatype>> {
        self.types.get(name).cloned()
    }

    /// Get a base scalar type of `size` bytes with metatype `m`. Faithful to
    /// `TypeFactory::getBase` (type.cc:3631-3660). For int/uint/float/bool,
    /// looks up the pre-generated core type by name; if not found, creates
    /// a new base type on the fly.
    pub fn get_base(&self, size: usize, m: TypeMetatype) -> Option<Arc<Datatype>> {
        use TypeMetatype::*;
        match m {
            Int => {
                let name = if size == 4 { "int".to_string() } else { format!("int{}", size) };
                self.find_by_name(&name).or_else(|| {
                    Some(Arc::new(Datatype::Base(TypeBase::new(name, size, Int))))
                })
            }
            Uint => {
                let name = if size == 4 { "uint".to_string() } else { format!("uint{}", size) };
                self.find_by_name(&name).or_else(|| {
                    Some(Arc::new(Datatype::Base(TypeBase::new(name, size, Uint))))
                })
            }
            Float => {
                let name = if size <= 4 { "float".to_string() } else { "double".to_string() };
                self.find_by_name(&name).or_else(|| {
                    Some(Arc::new(Datatype::Base(TypeBase::new(name, size, Float))))
                })
            }
            Bool => self.find_by_name("bool"),
            Void => self.find_by_name("void"),
            _ => None,
        }
    }

    /// Get or create a pointer type to the given base type
    pub fn get_ptr(&mut self, ptr_to: Arc<Datatype>) -> Arc<Datatype> {
        let name = format!("{} *", ptr_to.get_name());
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }

        let ptr_type = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new(name.clone(), self.ptr_size, TypeMetatype::Pointer),
            ptr_to,
            wordsize: 1,
        }));
        self.types.insert(name, ptr_type.clone());
        ptr_type
    }

    /// Get or create an array type
    pub fn get_array(&mut self, array_of: Arc<Datatype>, num_elements: usize) -> Arc<Datatype> {
        let name = format!("{}[{}]", array_of.get_name(), num_elements);
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }

        let size = array_of.get_size() * num_elements;
        let array_type = Arc::new(Datatype::Array(TypeArray {
            base: TypeBase::new(name.clone(), size, TypeMetatype::Array),
            array_of,
            num_elements,
        }));
        self.types.insert(name, array_type.clone());
        array_type
    }

    /// Create a new structure type
    pub fn create_struct(&mut self, name: &str) -> Arc<Datatype> {
        // Note: Ghidra allows multiple structs with same name in different scopes,
        // but for now we use a global flat namespace for the factory.
        let st_type = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new(name.to_string(), 0, TypeMetatype::Struct),
            fields: Vec::new(),
        }));
        self.types.insert(name.to_string(), st_type.clone());
        st_type
    }

    /// Set fields for an existing structure and update its size
    pub fn set_fields(&mut self, name: &str, fields: Vec<TypeField>) -> Option<Arc<Datatype>> {
        if let Some(dt) = self.types.get_mut(name) {
            if let Datatype::Struct(ref mut st) = Arc::make_mut(dt) {
                st.fields = fields;
                // Calculate size based on last field
                let mut max_size = 0;
                for field in &st.fields {
                    let field_end = field.offset + field.type_ptr.get_size();
                    if field_end > max_size {
                        max_size = field_end;
                    }
                }
                st.base.size = max_size;
                return Some(dt.clone());
            }
        }
        None
    }

    /// Get the number of types currently managed
    pub fn num_types(&self) -> usize {
        self.types.len()
    }

    /// Clear all non-core types
    pub fn clear_non_core(&mut self) {
        self.types = self.core_types.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_init() {
        let factory = TypeFactory::new(8);
        assert!(factory.find_by_name("void").is_some());
        assert!(factory.find_by_name("int").is_some());
        assert!(factory.find_by_name("uint").is_some());
        assert!(factory.find_by_name("bool").is_some());
    }

    #[test]
    fn test_pointer_deduplication() {
        let mut factory = TypeFactory::new(8);
        let int_type = factory.find_by_name("int").unwrap();

        let ptr1 = factory.get_ptr(int_type.clone());
        let ptr2 = factory.get_ptr(int_type.clone());

        assert_eq!(Arc::as_ptr(&ptr1), Arc::as_ptr(&ptr2));
        assert_eq!(ptr1.get_name(), "int *");
        assert_eq!(ptr1.get_size(), 8);
    }

    #[test]
    fn test_array_creation() {
        let mut factory = TypeFactory::new(8);
        let int_type = factory.find_by_name("int").unwrap();

        let array = factory.get_array(int_type, 10);
        assert_eq!(array.get_name(), "int[10]");
        assert_eq!(array.get_size(), 40);
    }
}
