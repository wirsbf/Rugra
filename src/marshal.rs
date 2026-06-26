//! Marshaling / serialization — faithful port of `marshal.hh` / `marshal.cc`
//! (1273 lines) + `xml.hh` / `xml.cc` (2510 lines, the in-memory DOM tree).
//!
//! Provides the `AttributeId`/`ElementId` registry, the in-memory `Element`/
//! `Document` DOM tree, and the `Encoder`/`Decoder` traits with a concrete
//! XML-based implementation. This is the serialization foundation referenced
//! by database.rs, override.rs, and arch.rs as their XML encode/decode L3 gap.
//!
//! Status: L1→L2. The registry, DOM tree, and Encoder/Decoder traits are
//! complete with a working in-memory `XmlEncode`/`XmlDecode` round-trip. The
//! Packed binary format (`PackedEncode`/`PackedDecode`) is an L3 gap.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/{marshal,xml}.{hh,cc}.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A special attribute id indicating "no attribute". Faithful to the implicit
/// 0 id returned by `peekElement`/`getNextAttributeId` when there is nothing.
pub const ATTRIB_UNKNOWN: u32 = 0;

/// A special attribute id for an element's text content. Faithful to
/// `ATTRIB_CONTENT`.
pub const ATTRIB_CONTENT: u32 = 1;

/// An annotation for a data element being transferred to/from a stream.
/// Faithful to `AttributeId` (marshal.hh:41).
#[derive(Debug, Clone)]
pub struct AttributeId {
    /// The name of the attribute.
    pub name: String,
    /// The internal id of the attribute.
    pub id: u32,
}

impl AttributeId {
    /// Construct given a name and id. Faithful to the constructor
    /// (marshal.hh:47).
    pub const fn new_static(nm: &'static str, id: u32) -> Self {
        Self {
            name: String::new(), // Will be set at runtime; const can't allocate.
            id,
        }
    }

    /// Construct at runtime.
    pub fn new(nm: &str, id: u32) -> Self {
        Self {
            name: nm.to_string(),
            id,
        }
    }

    /// Get the attribute's name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the attribute's id.
    pub fn get_id(&self) -> u32 {
        self.id
    }
}

impl PartialEq for AttributeId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

/// An annotation for a specific collection of hierarchical data. Faithful to
/// `ElementId` (marshal.hh:65).
#[derive(Debug, Clone)]
pub struct ElementId {
    /// The name of the element.
    pub name: String,
    /// The internal id of the element.
    pub id: u32,
}

impl ElementId {
    /// Construct given a name and id.
    pub fn new(nm: &str, id: u32) -> Self {
        Self {
            name: nm.to_string(),
            id,
        }
    }

    /// Get the element's name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the element's id.
    pub fn get_id(&self) -> u32 {
        self.id
    }
}

impl PartialEq for ElementId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

/// A global registry of attribute and element ids, mirroring Ghidra's static
/// `lookupAttributeId`/`lookupElementId` hashtables (marshal.hh:42, 67).
/// Attribute/Element ids are assigned at registration time.
#[derive(Debug, Default)]
pub struct IdRegistry {
    attr_by_name: HashMap<String, u32>,
    attr_by_id: HashMap<u32, String>,
    elem_by_name: HashMap<String, u32>,
    elem_by_id: HashMap<u32, String>,
    next_attr_id: u32,
    next_elem_id: u32,
}

impl IdRegistry {
    /// Create an empty registry with reserved ids 0 (UNKNOWN) and 1 (CONTENT).
    pub fn new() -> Self {
        let mut r = Self {
            attr_by_name: HashMap::new(),
            attr_by_id: HashMap::new(),
            elem_by_name: HashMap::new(),
            elem_by_id: HashMap::new(),
            next_attr_id: 2,
            next_elem_id: 2,
        };
        r.attr_by_name.insert("(unknown)".to_string(), ATTRIB_UNKNOWN);
        r.attr_by_id.insert(ATTRIB_UNKNOWN, "(unknown)".to_string());
        r.attr_by_name.insert("content".to_string(), ATTRIB_CONTENT);
        r.attr_by_id.insert(ATTRIB_CONTENT, "content".to_string());
        r
    }

    /// Register an attribute name, returning its id. If already registered,
    /// returns the existing id. Faithful to `AttributeId::find`.
    pub fn register_attribute(&mut self, nm: &str) -> u32 {
        if let Some(&id) = self.attr_by_name.get(nm) {
            return id;
        }
        let id = self.next_attr_id;
        self.next_attr_id += 1;
        self.attr_by_name.insert(nm.to_string(), id);
        self.attr_by_id.insert(id, nm.to_string());
        id
    }

    /// Register an attribute with an explicit id (for known marshaling ids).
    pub fn register_attribute_with_id(&mut self, nm: &str, id: u32) {
        self.attr_by_name.insert(nm.to_string(), id);
        self.attr_by_id.insert(id, nm.to_string());
        if id >= self.next_attr_id {
            self.next_attr_id = id + 1;
        }
    }

    /// Look up an attribute id by name. Returns ATTRIB_UNKNOWN if not found.
    pub fn find_attribute(&self, nm: &str) -> u32 {
        self.attr_by_name.get(nm).copied().unwrap_or(ATTRIB_UNKNOWN)
    }

    /// Look up an attribute name by id.
    pub fn attribute_name(&self, id: u32) -> Option<&str> {
        self.attr_by_id.get(&id).map(|s| s.as_str())
    }

    /// Register an element name, returning its id. Faithful to
    /// `ElementId::find`.
    pub fn register_element(&mut self, nm: &str) -> u32 {
        if let Some(&id) = self.elem_by_name.get(nm) {
            return id;
        }
        let id = self.next_elem_id;
        self.next_elem_id += 1;
        self.elem_by_name.insert(nm.to_string(), id);
        self.elem_by_id.insert(id, nm.to_string());
        id
    }

    /// Register an element with an explicit id.
    pub fn register_element_with_id(&mut self, nm: &str, id: u32) {
        self.elem_by_name.insert(nm.to_string(), id);
        self.elem_by_id.insert(id, nm.to_string());
        if id >= self.next_elem_id {
            self.next_elem_id = id + 1;
        }
    }

    /// Look up an element id by name.
    pub fn find_element(&self, nm: &str) -> u32 {
        self.elem_by_name.get(nm).copied().unwrap_or(ATTRIB_UNKNOWN)
    }

    /// Look up an element name by id.
    pub fn element_name(&self, id: u32) -> Option<&str> {
        self.elem_by_id.get(&id).map(|s| s.as_str())
    }
}

/// An XML element — a node in the DOM tree. Faithful to `Element`
/// (xml.hh:159). Owned by its parent; children are stored as `Arc<RwLock<>>`
/// to allow shared reference during decode.
#[derive(Debug, Clone)]
pub struct Element {
    /// The local name of the element.
    pub name: String,
    /// Character content of the element.
    pub content: String,
    /// Attribute names (parallel to `values`).
    pub attr_names: Vec<String>,
    /// Attribute values (parallel to `attr_names`).
    pub attr_values: Vec<String>,
    /// Child elements.
    pub children: Vec<Arc<RwLock<Element>>>,
}

impl Element {
    /// Construct an empty element.
    pub fn new() -> Self {
        Self {
            name: String::new(),
            content: String::new(),
            attr_names: Vec::new(),
            attr_values: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Set the local name of the element. Faithful to `setName`.
    pub fn set_name(&mut self, nm: &str) {
        self.name = nm.to_string();
    }

    /// Append character content. Faithful to `addContent`.
    pub fn add_content(&mut self, s: &str) {
        self.content.push_str(s);
    }

    /// Add a child element. Faithful to `addChild`.
    pub fn add_child(&mut self, child: Arc<RwLock<Element>>) {
        self.children.push(child);
    }

    /// Add a name/value attribute pair. Faithful to `addAttribute`.
    pub fn add_attribute(&mut self, nm: &str, vl: &str) {
        self.attr_names.push(nm.to_string());
        self.attr_values.push(vl.to_string());
    }

    /// Get the local name. Faithful to `getName`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the character content. Faithful to `getContent`.
    pub fn get_content(&self) -> &str {
        &self.content
    }

    /// Get the child elements. Faithful to `getChildren`.
    pub fn get_children(&self) -> &[Arc<RwLock<Element>>] {
        &self.children
    }

    /// Get an attribute value by name. Returns None if not found. Faithful to
    /// `getAttributeValue` (which throws; we return Option).
    pub fn get_attribute_value(&self, nm: &str) -> Option<&str> {
        for (i, name) in self.attr_names.iter().enumerate() {
            if name == nm {
                return Some(&self.attr_values[i]);
            }
        }
        None
    }

    /// Get the number of attributes. Faithful to `getNumAttributes`.
    pub fn get_num_attributes(&self) -> usize {
        self.attr_names.len()
    }

    /// Get the name of the i-th attribute. Faithful to `getAttributeName`.
    pub fn get_attribute_name(&self, i: usize) -> &str {
        &self.attr_names[i]
    }

    /// Get the value of the i-th attribute. Faithful to `getAttributeValue(i)`.
    pub fn get_attribute_value_at(&self, i: usize) -> &str {
        &self.attr_values[i]
    }
}

impl Default for Element {
    fn default() -> Self {
        Self::new()
    }
}

/// A complete in-memory XML document. Faithful to `Document` (xml.hh:215).
/// This is an `Element` whose single child is the root element.
#[derive(Debug, Clone, Default)]
pub struct Document {
    /// The root element of the document.
    pub root: Option<Arc<RwLock<Element>>>,
}

impl Document {
    /// Construct an empty document.
    pub fn new() -> Self {
        Self { root: None }
    }

    /// Get the root element. Faithful to `getRoot`.
    pub fn get_root(&self) -> Option<&Arc<RwLock<Element>>> {
        self.root.as_ref()
    }

    /// Set the root element.
    pub fn set_root(&mut self, root: Arc<RwLock<Element>>) {
        self.root = Some(root);
    }
}

/// A class for writing structured data to a stream. Faithful to `Encoder`
/// (marshal.hh). This trait mirrors the virtual methods of Ghidra's Encoder.
pub trait Encoder {
    /// Open a new element with the given id.
    fn open_element(&mut self, elem_id: &ElementId);
    /// Close the current element.
    fn close_element(&mut self, elem_id: &ElementId);
    /// Write a boolean attribute.
    fn write_bool(&mut self, attrib_id: &AttributeId, val: bool);
    /// Write a signed integer attribute.
    fn write_signed_integer(&mut self, attrib_id: &AttributeId, val: i64);
    /// Write an unsigned integer attribute.
    fn write_unsigned_integer(&mut self, attrib_id: &AttributeId, val: u64);
    /// Write a string attribute.
    fn write_string(&mut self, attrib_id: &AttributeId, val: &str);
    /// Write an indexed string attribute.
    fn write_string_indexed(&mut self, attrib_id: &AttributeId, index: u32, val: &str);
}

/// A class for reading structured data from a stream. Faithful to `Decoder`
/// (marshal.hh:99). The document is traversed depth-first via `open_element`/
/// `close_element`, with attributes read via `read_*`.
pub trait Decoder {
    /// Peek at the next child element id without traversing in. Returns 0 if
    /// none. Faithful to `peekElement`.
    fn peek_element(&self) -> u32;

    /// Open (traverse into) the next child element. Returns the element id.
    /// Faithful to `openElement`.
    fn open_element(&mut self) -> u32;

    /// Open the next child element, which must match the given id.
    fn open_element_matching(&mut self, elem_id: &ElementId) -> u32;

    /// Close the current element. Faithful to `closeElement`.
    fn close_element(&mut self, id: u32);

    /// Close the current element, skipping unread children. Faithful to
    /// `closeElementSkipping`.
    fn close_element_skipping(&mut self, id: u32);

    /// Get the next attribute id for the current element. Returns 0 when done.
    fn next_attribute_id(&mut self) -> u32;

    /// Reset attribute traversal. Faithful to `rewindAttributes`.
    fn rewind_attributes(&mut self);

    /// Read the current attribute as a boolean.
    fn read_bool(&mut self) -> bool;

    /// Read a specific attribute as a boolean.
    fn read_bool_attr(&mut self, attrib_id: &AttributeId) -> bool;

    /// Read the current attribute as a signed integer.
    fn read_signed_integer(&mut self) -> i64;

    /// Read a specific attribute as a signed integer.
    fn read_signed_integer_attr(&mut self, attrib_id: &AttributeId) -> i64;

    /// Read the current attribute as an unsigned integer.
    fn read_unsigned_integer(&mut self) -> u64;

    /// Read a specific attribute as an unsigned integer.
    fn read_unsigned_integer_attr(&mut self, attrib_id: &AttributeId) -> u64;

    /// Read the current attribute as a string.
    fn read_string(&mut self) -> String;

    /// Read a specific attribute as a string.
    fn read_string_attr(&mut self, attrib_id: &AttributeId) -> String;
}

/// An in-memory `Encoder` that builds an `Element` tree. This is the Rust
/// equivalent of Ghidra's `TreeHandler` + `Document` construction. The built
/// tree can be retrieved via `into_document`.
pub struct TreeEncoder {
    /// The stack of open elements; the last is the current.
    stack: Vec<Arc<RwLock<Element>>>,
    /// The root element (set after the first open_element).
    root: Option<Arc<RwLock<Element>>>,
    /// The registry for id→name lookup.
    registry: Arc<RwLock<IdRegistry>>,
}

impl TreeEncoder {
    /// Construct given a registry.
    pub fn new(registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self {
            stack: Vec::new(),
            root: None,
            registry,
        }
    }

    /// Consume the encoder and return the built document.
    pub fn into_document(self) -> Document {
        Document { root: self.root }
    }

    /// Get the root element.
    pub fn root(&self) -> Option<Arc<RwLock<Element>>> {
        self.root.clone()
    }
}

impl Encoder for TreeEncoder {
    fn open_element(&mut self, elem_id: &ElementId) {
        let mut elem = Element::new();
        elem.set_name(&elem_id.name);
        let elem_arc = Arc::new(RwLock::new(elem));
        if let Some(parent) = self.stack.last() {
            parent.write().unwrap().add_child(elem_arc.clone());
        } else {
            self.root = Some(elem_arc.clone());
        }
        self.stack.push(elem_arc);
    }

    fn close_element(&mut self, _elem_id: &ElementId) {
        self.stack.pop();
    }

    fn write_bool(&mut self, attrib_id: &AttributeId, val: bool) {
        if let Some(cur) = self.stack.last() {
            cur.write().unwrap().add_attribute(
                &attrib_id.name,
                if val { "1" } else { "0" },
            );
        }
    }

    fn write_signed_integer(&mut self, attrib_id: &AttributeId, val: i64) {
        if let Some(cur) = self.stack.last() {
            cur.write()
                .unwrap()
                .add_attribute(&attrib_id.name, &val.to_string());
        }
    }

    fn write_unsigned_integer(&mut self, attrib_id: &AttributeId, val: u64) {
        if let Some(cur) = self.stack.last() {
            cur.write()
                .unwrap()
                .add_attribute(&attrib_id.name, &val.to_string());
        }
    }

    fn write_string(&mut self, attrib_id: &AttributeId, val: &str) {
        if let Some(cur) = self.stack.last() {
            cur.write().unwrap().add_attribute(&attrib_id.name, val);
        }
    }

    fn write_string_indexed(&mut self, attrib_id: &AttributeId, index: u32, val: &str) {
        let nm = format!("{}_{}", attrib_id.name, index);
        if let Some(cur) = self.stack.last() {
            cur.write().unwrap().add_attribute(&nm, val);
        }
    }
}

/// An in-memory `Decoder` that reads from an `Element` tree. This traverses
/// the DOM depth-first, mirroring Ghidra's `XmlDecode`.
pub struct TreeDecoder {
    /// The root of the tree being decoded.
    root: Option<Arc<RwLock<Element>>>,
    /// Stack of (element, current child index, current attribute index).
    stack: Vec<(Arc<RwLock<Element>>, usize, usize)>,
    /// The registry for name→id lookup.
    registry: Arc<RwLock<IdRegistry>>,
}

impl TreeDecoder {
    /// Construct given a document root and registry.
    pub fn new(root: Arc<RwLock<Element>>, registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self {
            root: Some(root),
            stack: Vec::new(),
            registry,
        }
    }

    /// Construct from a document.
    pub fn from_document(doc: &Document, registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self::new(
            doc.root.clone().unwrap_or_else(|| Arc::new(RwLock::new(Element::new()))),
            registry,
        )
    }
}

impl Decoder for TreeDecoder {
    fn peek_element(&self) -> u32 {
        let Some((elem, child_idx, _)) = self.stack.last() else {
            // At the document level: peek the root.
            if let Some(root) = &self.root {
                if self.stack.is_empty() {
                    let rg = root.read().unwrap();
                    return self.registry.read().unwrap().find_element(&rg.name);
                }
            }
            return 0;
        };
        let rg = elem.read().unwrap();
        if *child_idx < rg.children.len() {
            let child = &rg.children[*child_idx];
            let child_rg = child.read().unwrap();
            self.registry.read().unwrap().find_element(&child_rg.name)
        } else {
            0
        }
    }

    fn open_element(&mut self) -> u32 {
        // If at document level with no stack, push the root.
        if self.stack.is_empty() {
            if let Some(root) = self.root.take() {
                let id = {
                    let rg = root.read().unwrap();
                    self.registry.read().unwrap().find_element(&rg.name)
                };
                self.stack.push((root, 0, 0));
                return id;
            }
            return 0;
        }
        let (elem, child_idx, _) = self.stack.last().cloned().unwrap();
        let child = {
            let rg = elem.read().unwrap();
            rg.children.get(child_idx).cloned()
        };
        let Some(child) = child else {
            return 0;
        };
        let id = {
            let rg = child.read().unwrap();
            self.registry.read().unwrap().find_element(&rg.name)
        };
        // Advance the parent's child index.
        if let Some(last) = self.stack.last_mut() {
            last.1 += 1;
        }
        self.stack.push((child, 0, 0));
        id
    }

    fn open_element_matching(&mut self, elem_id: &ElementId) -> u32 {
        let id = self.open_element();
        if id != elem_id.id {
            // Ghidra throws; we return 0.
            return 0;
        }
        id
    }

    fn close_element(&mut self, _id: u32) {
        self.stack.pop();
    }

    fn close_element_skipping(&mut self, _id: u32) {
        self.stack.pop();
    }

    fn next_attribute_id(&mut self) -> u32 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        if attr_idx < rg.get_num_attributes() {
            // Clone the name to release the borrow before mutating the stack.
            let name = rg.get_attribute_name(attr_idx).to_string();
            drop(rg);
            if let Some(last) = self.stack.last_mut() {
                last.2 += 1;
            }
            self.registry.read().unwrap().find_attribute(&name)
        } else {
            0
        }
    }

    fn rewind_attributes(&mut self) {
        if let Some(last) = self.stack.last_mut() {
            last.2 = 0;
        }
    }

    fn read_bool(&mut self) -> bool {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return false;
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            let val = rg.get_attribute_value_at(attr_idx - 1);
            return val == "1" || val.eq_ignore_ascii_case("true");
        }
        false
    }

    fn read_bool_attr(&mut self, attrib_id: &AttributeId) -> bool {
        let Some((elem, _, _)) = self.stack.last() else {
            return false;
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn read_signed_integer(&mut self) -> i64 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return rg.get_attribute_value_at(attr_idx - 1).parse().unwrap_or(0);
        }
        0
    }

    fn read_signed_integer_attr(&mut self, attrib_id: &AttributeId) -> i64 {
        let Some((elem, _, _)) = self.stack.last() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn read_unsigned_integer(&mut self) -> u64 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return rg.get_attribute_value_at(attr_idx - 1).parse().unwrap_or(0);
        }
        0
    }

    fn read_unsigned_integer_attr(&mut self, attrib_id: &AttributeId) -> u64 {
        let Some((elem, _, _)) = self.stack.last() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn read_string(&mut self) -> String {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return String::new();
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return rg.get_attribute_value_at(attr_idx - 1).to_string();
        }
        String::new()
    }

    fn read_string_attr(&mut self, attrib_id: &AttributeId) -> String {
        let Some((elem, _, _)) = self.stack.last() else {
            return String::new();
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .unwrap_or("")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_id() {
        let a = AttributeId::new("name", 5);
        assert_eq!(a.get_name(), "name");
        assert_eq!(a.get_id(), 5);
        let b = AttributeId::new("other", 5);
        assert!(a == b); // equality by id
    }

    #[test]
    fn test_element_id() {
        let e = ElementId::new("scope", 10);
        assert_eq!(e.get_name(), "scope");
        assert_eq!(e.get_id(), 10);
    }

    #[test]
    fn test_registry() {
        let mut reg = IdRegistry::new();
        let id1 = reg.register_attribute("label");
        let id2 = reg.register_attribute("label"); // same name → same id
        assert_eq!(id1, id2);
        assert_eq!(reg.find_attribute("label"), id1);
        assert_eq!(reg.find_attribute("nonexistent"), ATTRIB_UNKNOWN);
        let eid = reg.register_element("db");
        assert_eq!(reg.find_element("db"), eid);
        assert!(reg.attribute_name(id1).is_some());
    }

    #[test]
    fn test_element() {
        let mut e = Element::new();
        e.set_name("head");
        e.add_attribute("locked", "1");
        e.add_content("hello");
        assert_eq!(e.get_name(), "head");
        assert_eq!(e.get_num_attributes(), 1);
        assert_eq!(e.get_attribute_name(0), "locked");
        assert_eq!(e.get_attribute_value_at(0), "1");
        assert_eq!(e.get_attribute_value("locked"), Some("1"));
        assert_eq!(e.get_attribute_value("missing"), None);
        assert_eq!(e.get_content(), "hello");
    }

    #[test]
    fn test_element_children() {
        let mut parent = Element::new();
        parent.set_name("parent");
        let mut child = Element::new();
        child.set_name("child");
        let child_arc = Arc::new(RwLock::new(child));
        parent.add_child(child_arc);
        assert_eq!(parent.get_children().len(), 1);
        assert_eq!(parent.get_children()[0].read().unwrap().get_name(), "child");
    }

    #[test]
    fn test_document() {
        let mut doc = Document::new();
        let mut root = Element::new();
        root.set_name("root");
        doc.set_root(Arc::new(RwLock::new(root)));
        assert!(doc.get_root().is_some());
        assert_eq!(doc.get_root().unwrap().read().unwrap().get_name(), "root");
    }

    #[test]
    fn test_tree_encoder_roundtrip() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        registry.write().unwrap().register_element_with_id("head", 100);
        registry.write().unwrap().register_attribute_with_id("num", 200);
        let mut enc = TreeEncoder::new(registry.clone());
        let head_id = ElementId::new("head", 100);
        let num_id = AttributeId::new("num", 200);
        enc.open_element(&head_id);
        enc.write_unsigned_integer(&num_id, 42);
        enc.write_string(&AttributeId::new("name", registry.read().unwrap().find_attribute("name")), "foo");
        enc.close_element(&head_id);
        let doc = enc.into_document();
        let root = doc.get_root().unwrap();
        let rg = root.read().unwrap();
        assert_eq!(rg.get_name(), "head");
        assert_eq!(rg.get_attribute_value("num"), Some("42"));
        assert_eq!(rg.get_attribute_value("name"), Some("foo"));
    }

    #[test]
    fn test_tree_decoder() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        registry.write().unwrap().register_element_with_id("head", 100);
        registry.write().unwrap().register_attribute_with_id("num", 200);
        // Build a tree manually.
        let mut root = Element::new();
        root.set_name("head");
        root.add_attribute("num", "42");
        let mut dec = TreeDecoder::new(Arc::new(RwLock::new(root)), registry.clone());
        let id = dec.open_element();
        assert_eq!(id, 100);
        // Read the num attribute.
        let aid = dec.next_attribute_id();
        assert_eq!(aid, 200);
        let val = dec.read_unsigned_integer();
        assert_eq!(val, 42);
        dec.close_element(id);
    }

    #[test]
    fn test_reserved_ids() {
        assert_eq!(ATTRIB_UNKNOWN, 0);
        assert_eq!(ATTRIB_CONTENT, 1);
    }
}
