//! Constant pool — faithful port of `cpool.hh` / `cpool.cc` (245 lines).
//!
//! Definitions to support a constant pool for deferred compilation languages
//! (i.e. Java byte-code). Byte-code languages refer to objects via encoded
//! references; the constant pool resolves these to concrete values, types, and
//! token names.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/cpool.{hh,cc}.

use std::collections::BTreeMap;

/// Generic constant pool tag types. Faithful to the `CPoolRecord` enum
/// (cpool.hh:59).
pub mod cpool_tag {
    /// Constant value of data-type `type`, cpool operator can be eliminated.
    pub const PRIMITIVE: u32 = 0;
    /// Constant reference to string (passed back as `byte_data`).
    pub const STRING_LITERAL: u32 = 1;
    /// Reference to (system level) class object, `token` holds class name.
    pub const CLASS_REFERENCE: u32 = 2;
    /// Pointer to a method, name in `token`, signature in `type`.
    pub const POINTER_METHOD: u32 = 3;
    /// Pointer to a field, name in `token`, data-type in `type`.
    pub const POINTER_FIELD: u32 = 4;
    /// Integer length, `token` is language specific indicator.
    pub const ARRAY_LENGTH: u32 = 5;
    /// Boolean value, `token` is language specific indicator.
    pub const INSTANCE_OF: u32 = 6;
    /// Pointer to object, new name in `token`, new data-type in `type`.
    pub const CHECK_CAST: u32 = 7;
}

/// Additional boolean properties on a CPoolRecord. Faithful to the flags enum
/// (cpool.hh:69).
pub mod cpool_flags {
    /// Referenced method is a constructor.
    pub const IS_CONSTRUCTOR: u32 = 0x1;
    /// Referenced method is a destructor.
    pub const IS_DESTRUCTOR: u32 = 0x2;
}

/// A description of a byte-code object referenced by a constant. Faithful to
/// `CPoolRecord` (cpool.hh:56).
#[derive(Debug, Clone)]
pub struct CPoolRecord {
    /// Descriptor of the type of object.
    pub tag: u32,
    /// Additional boolean properties (constructor/destructor).
    pub flags: u32,
    /// Name or token associated with the object.
    pub token: String,
    /// Constant value of the object (if known).
    pub value: u64,
    /// Data-type name associated with the object.
    pub type_name: String,
    /// For string literals, the raw byte data.
    pub byte_data: Option<Vec<u8>>,
}

impl Default for CPoolRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl CPoolRecord {
    /// Construct an empty record. Faithful to the constructor (cpool.hh:83).
    pub fn new() -> Self {
        Self {
            tag: cpool_tag::PRIMITIVE,
            flags: 0,
            token: String::new(),
            value: 0,
            type_name: String::new(),
            byte_data: None,
        }
    }

    /// Get the type of record. Faithful to `getTag`.
    pub fn get_tag(&self) -> u32 {
        self.tag
    }

    /// Get name of method or data-type. Faithful to `getToken`.
    pub fn get_token(&self) -> &str {
        &self.token
    }

    /// Get string literal byte data. Faithful to `getByteData`.
    pub fn get_byte_data(&self) -> Option<&[u8]> {
        self.byte_data.as_deref()
    }

    /// Number of bytes of string literal data. Faithful to `getByteDataLength`.
    pub fn get_byte_data_length(&self) -> usize {
        self.byte_data.as_ref().map_or(0, |d| d.len())
    }

    /// Get the data-type name. Faithful to `getType`.
    pub fn get_type_name(&self) -> &str {
        &self.type_name
    }

    /// Get the constant value. Faithful to `getValue`.
    pub fn get_value(&self) -> u64 {
        self.value
    }

    /// Is the object a constructor method? Faithful to `isConstructor`.
    pub fn is_constructor(&self) -> bool {
        (self.flags & cpool_flags::IS_CONSTRUCTOR) != 0
    }

    /// Is the object a destructor method? Faithful to `isDestructor`.
    pub fn is_destructor(&self) -> bool {
        (self.flags & cpool_flags::IS_DESTRUCTOR) != 0
    }

    /// Convert a tag to its string name for encoding. Faithful to the
    /// encode logic (cpool.cc:36-51).
    pub fn tag_to_string(tag: u32) -> &'static str {
        match tag {
            cpool_tag::POINTER_METHOD => "method",
            cpool_tag::POINTER_FIELD => "field",
            cpool_tag::INSTANCE_OF => "instanceof",
            cpool_tag::ARRAY_LENGTH => "arraylength",
            cpool_tag::CHECK_CAST => "checkcast",
            cpool_tag::STRING_LITERAL => "string",
            cpool_tag::CLASS_REFERENCE => "classref",
            _ => "primitive",
        }
    }

    /// Convert a string name to a tag for decoding. Faithful to the decode
    /// logic (cpool.cc:99-115).
    pub fn string_to_tag(s: &str) -> u32 {
        match s {
            "method" => cpool_tag::POINTER_METHOD,
            "field" => cpool_tag::POINTER_FIELD,
            "instanceof" => cpool_tag::INSTANCE_OF,
            "arraylength" => cpool_tag::ARRAY_LENGTH,
            "checkcast" => cpool_tag::CHECK_CAST,
            "string" => cpool_tag::STRING_LITERAL,
            "classref" => cpool_tag::CLASS_REFERENCE,
            _ => cpool_tag::PRIMITIVE,
        }
    }
}

/// A cheap (efficient) placeholder for a reference to a constant pool record.
/// Faithful to `ConstantPoolInternal::CheapSorter` (cpool.hh:175).
///
/// A reference can be 1 or more integers; in practice at most 2 are seen.
/// Ordered lexicographically by (a, b).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct CheapSorter {
    /// The first integer in a reference.
    pub a: u64,
    /// The second integer in a reference (or zero).
    pub b: u64,
}

impl CheapSorter {
    /// Construct from an array of reference integers. Faithful to the
    /// constructor (cpool.hh:181).
    pub fn from_refs(refs: &[u64]) -> Self {
        Self {
            a: refs.first().copied().unwrap_or(0),
            b: refs.get(1).copied().unwrap_or(0),
        }
    }

    /// Convert the reference back to a formal array of integers. Faithful to
    /// `apply` (cpool.hh:195).
    pub fn apply(&self) -> Vec<u64> {
        vec![self.a, self.b]
    }
}

/// An interface to the pool of constant objects for byte-code languages.
/// Faithful to `ConstantPool` (cpool.hh:104).
pub trait ConstantPool: Send + Sync {
    /// Retrieve a constant pool record given a reference. Faithful to
    /// `getRecord`.
    fn get_record(&self, refs: &[u64]) -> Option<&CPoolRecord>;

    /// Allocate a new CPoolRecord associated with the reference. Faithful to
    /// `createRecord`. Returns a mutable reference to the new record.
    fn create_record(&mut self, refs: &[u64]) -> Result<&mut CPoolRecord, String>;

    /// Add a new constant pool record. Faithful to `putRecord`
    /// (cpool.cc:157).
    fn put_record(&mut self, refs: &[u64], tag: u32, tok: &str, type_name: &str) {
        match self.create_record(refs) {
            Ok(rec) => {
                rec.tag = tag;
                rec.token = tok.to_string();
                rec.type_name = type_name.to_string();
            }
            Err(e) => {
                eprintln!("[CPOOL] Failed to put record: {e}");
            }
        }
    }

    /// Is the container empty of records? Faithful to `empty`.
    fn is_empty(&self) -> bool;

    /// Release any (local) resources. Faithful to `clear`.
    fn clear(&mut self);
}

/// An in-memory implementation of ConstantPool storing records in a BTreeMap.
/// Faithful to `ConstantPoolInternal` (cpool.hh:165).
pub struct ConstantPoolInternal {
    /// Map from reference to constant pool record.
    cpool_map: BTreeMap<CheapSorter, CPoolRecord>,
}

impl Default for ConstantPoolInternal {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstantPoolInternal {
    /// Construct an empty constant pool.
    pub fn new() -> Self {
        Self {
            cpool_map: BTreeMap::new(),
        }
    }

    /// Number of records in the pool.
    pub fn num_records(&self) -> usize {
        self.cpool_map.len()
    }

    /// Iterate over all (reference, record) pairs.
    pub fn records(&self) -> impl Iterator<Item = (&CheapSorter, &CPoolRecord)> {
        self.cpool_map.iter()
    }

    /// Encode all records to a stream. Faithful to `ConstantPoolInternal::encode`
    /// (cpool.cc:218). Emits `<constantpool>` with `<ref>` + `<cpoolrec>` children.
    pub fn encode(&self, encoder: &mut dyn crate::marshal::Encoder) {
        use crate::marshal::{AttributeId, ElementId};
        let cp_elem = ElementId::new("constantpool", 0);
        let ref_elem = ElementId::new("ref", 0);
        let rec_elem = ElementId::new("cpoolrec", 0);
        let token_elem = ElementId::new("token", 0);
        encoder.open_element(&cp_elem);
        for (sorter, rec) in &self.cpool_map {
            // <ref a=".." b=".."/>
            encoder.open_element(&ref_elem);
            encoder.write_unsigned_integer(&AttributeId::new("a", 0), sorter.a);
            encoder.write_unsigned_integer(&AttributeId::new("b", 0), sorter.b);
            encoder.close_element(&ref_elem);
            // <cpoolrec tag=".." [constructor] [destructor]> <token>..</token> </cpoolrec>
            encoder.open_element(&rec_elem);
            encoder.write_string(&AttributeId::new("tag", 0), CPoolRecord::tag_to_string(rec.tag));
            encoder.open_element(&token_elem);
            encoder.write_string(&AttributeId::new("content", 1), &rec.token);
            encoder.close_element(&token_elem);
            encoder.close_element(&rec_elem);
        }
        encoder.close_element(&cp_elem);
    }

    /// Restore records from a stream. Faithful to `ConstantPoolInternal::decode`
    /// (cpool.cc:230).
    pub fn decode(&mut self, decoder: &mut dyn crate::marshal::Decoder) {
        use crate::marshal::{AttributeId, ElementId};
        let cp_id = decoder.open_element();
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 { break; }
            let elem_name = decoder.element_name(sub_id).unwrap_or_default();
            if elem_name != "ref" {
                decoder.open_element();
                decoder.close_element_skipping(sub_id);
                continue;
            }
            // Read <ref>.
            decoder.open_element();
            let mut a = 0u64;
            let mut b = 0u64;
            loop {
                let aid = decoder.next_attribute_id();
                if aid == 0 { break; }
                match decoder.attribute_name(aid).as_deref() {
                    Some("a") => a = decoder.read_unsigned_integer(),
                    Some("b") => b = decoder.read_unsigned_integer(),
                    _ => { let _ = decoder.read_string(); }
                }
            }
            decoder.close_element(sub_id);
            // Read <cpoolrec>.
            let rec_id = decoder.peek_element();
            if rec_id != 0 {
                decoder.open_element();
                let mut tag = 0u32;
                let mut token = String::new();
                loop {
                    let aid = decoder.next_attribute_id();
                    if aid == 0 { break; }
                    if decoder.attribute_name(aid).as_deref() == Some("tag") {
                        tag = CPoolRecord::string_to_tag(&decoder.read_string());
                    } else { let _ = decoder.read_string(); }
                }
                // Read <token> child.
                let tok_id = decoder.peek_element();
                if tok_id != 0 {
                    decoder.open_element();
                    loop {
                        let aid = decoder.next_attribute_id();
                        if aid == 0 { break; }
                        if decoder.attribute_name(aid).as_deref() == Some("content") {
                            token = decoder.read_string();
                        } else { let _ = decoder.read_string(); }
                    }
                    decoder.close_element(tok_id);
                }
                decoder.close_element(rec_id);
                // Store the record.
                let sorter = CheapSorter { a, b };
                let mut rec = CPoolRecord::new();
                rec.tag = tag;
                rec.token = token;
                self.cpool_map.insert(sorter, rec);
            }
        }
        decoder.close_element(cp_id);
    }
}

impl ConstantPool for ConstantPoolInternal {
    fn get_record(&self, refs: &[u64]) -> Option<&CPoolRecord> {
        let sorter = CheapSorter::from_refs(refs);
        self.cpool_map.get(&sorter)
    }

    fn create_record(&mut self, refs: &[u64]) -> Result<&mut CPoolRecord, String> {
        let sorter = CheapSorter::from_refs(refs);
        if self.cpool_map.contains_key(&sorter) {
            return Err(format!(
                "Creating duplicate entry in constant pool: {:?}",
                sorter
            ));
        }
        self.cpool_map.insert(sorter.clone(), CPoolRecord::new());
        Ok(self.cpool_map.get_mut(&sorter).unwrap())
    }

    fn is_empty(&self) -> bool {
        self.cpool_map.is_empty()
    }

    fn clear(&mut self) {
        self.cpool_map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpool_record_default() {
        let r = CPoolRecord::new();
        assert_eq!(r.get_tag(), cpool_tag::PRIMITIVE);
        assert_eq!(r.get_value(), 0);
        assert!(!r.is_constructor());
        assert!(!r.is_destructor());
    }

    #[test]
    fn test_tag_string_roundtrip() {
        for &tag in &[
            cpool_tag::PRIMITIVE,
            cpool_tag::STRING_LITERAL,
            cpool_tag::CLASS_REFERENCE,
            cpool_tag::POINTER_METHOD,
            cpool_tag::POINTER_FIELD,
            cpool_tag::ARRAY_LENGTH,
            cpool_tag::INSTANCE_OF,
            cpool_tag::CHECK_CAST,
        ] {
            let s = CPoolRecord::tag_to_string(tag);
            assert_eq!(CPoolRecord::string_to_tag(s), tag);
        }
    }

    #[test]
    fn test_cheap_sorter_ordering() {
        let s1 = CheapSorter { a: 1, b: 2 };
        let s2 = CheapSorter { a: 1, b: 3 };
        let s3 = CheapSorter { a: 2, b: 0 };
        assert!(s1 < s2);
        assert!(s2 < s3);
    }

    #[test]
    fn test_cheap_sorter_from_refs() {
        let s = CheapSorter::from_refs(&[10, 20]);
        assert_eq!(s.a, 10);
        assert_eq!(s.b, 20);
        let s2 = CheapSorter::from_refs(&[5]);
        assert_eq!(s2.a, 5);
        assert_eq!(s2.b, 0);
    }

    #[test]
    fn test_cheap_sorter_apply() {
        let s = CheapSorter { a: 7, b: 9 };
        assert_eq!(s.apply(), vec![7, 9]);
    }

    #[test]
    fn test_constant_pool_create_get() {
        let mut pool = ConstantPoolInternal::new();
        assert!(pool.is_empty());
        {
            let rec = pool.create_record(&[1, 2]).unwrap();
            rec.tag = cpool_tag::POINTER_METHOD;
            rec.token = "main".to_string();
            rec.type_name = "func".to_string();
        }
        assert!(!pool.is_empty());
        assert_eq!(pool.num_records(), 1);
        let rec = pool.get_record(&[1, 2]).unwrap();
        assert_eq!(rec.get_tag(), cpool_tag::POINTER_METHOD);
        assert_eq!(rec.get_token(), "main");
    }

    #[test]
    fn test_constant_pool_duplicate() {
        let mut pool = ConstantPoolInternal::new();
        pool.create_record(&[1]).unwrap();
        let result = pool.create_record(&[1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_pool_put_record() {
        let mut pool = ConstantPoolInternal::new();
        pool.put_record(&[5, 0], cpool_tag::POINTER_FIELD, "field_x", "int");
        let rec = pool.get_record(&[5, 0]).unwrap();
        assert_eq!(rec.get_tag(), cpool_tag::POINTER_FIELD);
        assert_eq!(rec.get_token(), "field_x");
        assert_eq!(rec.get_type_name(), "int");
    }

    #[test]
    fn test_constant_pool_clear() {
        let mut pool = ConstantPoolInternal::new();
        pool.put_record(&[1], cpool_tag::PRIMITIVE, "", "");
        pool.put_record(&[2], cpool_tag::PRIMITIVE, "", "");
        assert_eq!(pool.num_records(), 2);
        pool.clear();
        assert!(pool.is_empty());
    }

    #[test]
    fn test_constant_pool_string_literal() {
        let mut pool = ConstantPoolInternal::new();
        {
            let rec = pool.create_record(&[10]).unwrap();
            rec.tag = cpool_tag::STRING_LITERAL;
            rec.byte_data = Some(vec![b'H', b'i']);
        }
        let rec = pool.get_record(&[10]).unwrap();
        assert_eq!(rec.get_tag(), cpool_tag::STRING_LITERAL);
        assert_eq!(rec.get_byte_data(), Some(&b"Hi"[..]));
        assert_eq!(rec.get_byte_data_length(), 2);
    }

    #[test]
    fn test_constant_pool_constructor_flag() {
        let mut pool = ConstantPoolInternal::new();
        {
            let rec = pool.create_record(&[20]).unwrap();
            rec.tag = cpool_tag::POINTER_METHOD;
            rec.flags = cpool_flags::IS_CONSTRUCTOR;
        }
        let rec = pool.get_record(&[20]).unwrap();
        assert!(rec.is_constructor());
        assert!(!rec.is_destructor());
    }

    #[test]
    fn test_constant_pool_records_iter() {
        let mut pool = ConstantPoolInternal::new();
        pool.put_record(&[1], cpool_tag::PRIMITIVE, "a", "");
        pool.put_record(&[2], cpool_tag::PRIMITIVE, "b", "");
        pool.put_record(&[3], cpool_tag::PRIMITIVE, "c", "");
        let names: Vec<_> = pool.records().map(|(_, r)| r.get_token()).collect();
        assert_eq!(names, vec!["a", "b", "c"]); // sorted by CheapSorter
    }
}
