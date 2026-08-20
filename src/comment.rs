//! Comment database — faithful port of `comment.hh` / `comment.cc` (406 lines).
//!
//! A database interface for high-level language comments. Comments are
//! attached to a specific function and code address, with properties
//! (user1/user2/user3/header/warning/warningheader) controlling display.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/comment.{hh,cc}.

use crate::address::Address;
use crate::marshal::{AttributeId, Decoder, ElementId, Encoder};
use anyhow::{bail, Result};

/// Possible properties associated with a comment. Faithful to
/// `Comment::comment_type` (comment.hh:53).
pub mod comment_type {
    /// The first user defined property.
    pub const USER1: u32 = 1;
    /// The second user defined property.
    pub const USER2: u32 = 2;
    /// The third user defined property.
    pub const USER3: u32 = 4;
    /// The comment should be displayed in the function header.
    pub const HEADER: u32 = 8;
    /// The comment is auto-generated to alert the user.
    pub const WARNING: u32 = 16;
    /// The comment is auto-generated and should be in the header.
    pub const WARNINGHEADER: u32 = 32;
}

/// A comment attached to a specific function and code address. Faithful to
/// `Comment` (comment.hh:43).
#[derive(Debug, Clone)]
pub struct Comment {
    /// The properties associated with the comment.
    pub type_flags: u32,
    /// Sub-identifier for uniqueness.
    pub uniq: i32,
    /// Address of the function containing the comment.
    pub funcaddr: Address,
    /// Address associated with the comment.
    pub addr: Address,
    /// The body of the comment.
    pub text: String,
    /// True if this comment has already been emitted.
    pub emitted: bool,
}

impl Comment {
    // Ghidra: comment.cc:30 Comment::new
    /// Construct given properties, function address, comment address,
    /// uniqueness id, and text. Faithful to the constructor (comment.cc:30).
    pub fn new(tp: u32, fad: Address, ad: Address, uq: i32, txt: &str) -> Self {
        Self {
            type_flags: tp,
            uniq: uq,
            funcaddr: fad,
            addr: ad,
            text: txt.to_string(),
            emitted: false,
        }
    }

    // Ghidra: comment.cc:30 Comment::newEmpty
    /// Construct an empty comment for use with decode.
    pub fn new_empty() -> Self {
        Self {
            type_flags: 0,
            uniq: 0,
            funcaddr: Address::new(0),
            addr: Address::new(0),
            text: String::new(),
            emitted: false,
        }
    }

    // Ghidra: comment.cc:30 Comment::setEmitted
    /// Mark that this comment has been emitted. Faithful to `setEmitted`.
    pub fn set_emitted(&mut self, val: bool) {
        self.emitted = val;
    }

    // Ghidra: comment.cc:30 Comment::isEmitted
    /// Return true if this comment is already emitted.
    pub fn is_emitted(&self) -> bool {
        self.emitted
    }

    // Ghidra: comment.cc:30 Comment::getType
    /// Get the properties associated with the comment. Faithful to `getType`.
    pub fn get_type(&self) -> u32 {
        self.type_flags
    }

    // Ghidra: comment.cc:30 Comment::getFuncAddr
    /// Get the address of the function containing the comment.
    pub fn get_func_addr(&self) -> Address {
        self.funcaddr
    }

    // Ghidra: comment.cc:30 Comment::getAddr
    /// Get the address to which the instruction is attached.
    pub fn get_addr(&self) -> Address {
        self.addr
    }

    // Ghidra: comment.cc:30 Comment::getUniq
    /// Get the sub-sorting index. Faithful to `getUniq`.
    pub fn get_uniq(&self) -> i32 {
        self.uniq
    }

    // Ghidra: comment.cc:30 Comment::getText
    /// Get the body of the comment. Faithful to `getText`.
    pub fn get_text(&self) -> &str {
        &self.text
    }

    // Ghidra: comment.cc:37 Comment::encode
    /// Encode the comment to a stream. Faithful to `Comment::encode`
    /// (comment.cc:37).
    pub fn encode(&self, encoder: &mut dyn Encoder) -> Result<()> {
        let tpname = decode_comment_type(self.type_flags)?;
        let comment_elem = ElementId::new("comment", 0);
        let text_elem = ElementId::new("text", 0);
        encoder.open_element(&comment_elem);
        encoder.write_string(&AttributeId::new("type", 0), &tpname);
        encode_addr_child(encoder, self.funcaddr)?;
        encode_addr_child(encoder, self.addr)?;
        // Text content.
        encoder.open_element(&text_elem);
        encoder.write_string(&AttributeId::new("XMLcontent", 1), &self.text);
        encoder.close_element(&text_elem);
        encoder.close_element(&comment_elem);
        Ok(())
    }

    // Ghidra: comment.cc:57 Comment::decode
    /// Decode the comment from a stream. Faithful to `Comment::decode`
    /// (comment.cc:57).
    pub fn decode(&mut self, decoder: &mut dyn Decoder) -> Result<()> {
        self.emitted = false;
        self.type_flags = 0;
        let comment_id = decoder.open_element();
        // Read type attribute.
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            if decoder.attribute_name(aid).as_deref() == Some("type") {
                self.type_flags = encode_comment_type(&decoder.read_string())?;
            } else {
                // Ghidra's iterator advances independently of value reads.
            }
        }
        // Read two <addr> children (funcaddr, addr).
        self.funcaddr = read_addr_child(decoder)?;
        self.addr = read_addr_child(decoder)?;
        // Read <text> child if present.
        let sub_id = decoder.peek_element();
        if sub_id != 0 {
            decoder.open_element();
            self.text = decoder.read_string_attr(&AttributeId::new("XMLcontent", 1));
            decoder.close_element(sub_id);
        }
        decoder.close_element(comment_id);
        Ok(())
    }
}

// Ghidra: comment.cc:77 Comment::encodeCommentType
/// Convert a name string to a comment property. Faithful to
/// `encodeCommentType` (comment.cc:77). Unknown names are errors, matching
/// Ghidra's `LowlevelError` path.
pub fn encode_comment_type(name: &str) -> Result<u32> {
    Ok(match name {
        "user1" => comment_type::USER1,
        "user2" => comment_type::USER2,
        "user3" => comment_type::USER3,
        "header" => comment_type::HEADER,
        "warning" => comment_type::WARNING,
        "warningheader" => comment_type::WARNINGHEADER,
        _ => bail!("Unknown comment type: {name}"),
    })
}

// Ghidra: comment.cc:97 Comment::decodeCommentType
/// Convert a comment property to its string representation. Faithful to
/// `decodeCommentType` (comment.cc:97). Unknown values are errors, matching
/// Ghidra's `LowlevelError` path.
pub fn decode_comment_type(val: u32) -> Result<String> {
    Ok(match val {
        comment_type::USER1 => "user1".to_string(),
        comment_type::USER2 => "user2".to_string(),
        comment_type::USER3 => "user3".to_string(),
        comment_type::HEADER => "header".to_string(),
        comment_type::WARNING => "warning".to_string(),
        comment_type::WARNINGHEADER => "warningheader".to_string(),
        _ => bail!("Unknown comment type"),
    })
}

// Ghidra: space.cc:143 AddrSpace::encodeAttributes
/// Encode one `<addr>` child with distinct `space` and `offset` attributes.
fn encode_addr_child(encoder: &mut dyn Encoder, address: Address) -> Result<()> {
    let Some(space) = address.get_space() else {
        bail!("Cannot encode address without an address space");
    };
    let addr_elem = ElementId::new("addr", 0);
    encoder.open_element(&addr_elem);
    encoder.write_string(&AttributeId::new("space", 0), &space.get_name());
    encoder.write_unsigned_integer(&AttributeId::new("offset", 0), address.as_u64());
    encoder.close_element(&addr_elem);
    Ok(())
}

// Ghidra: address.cc:205 Address::decode
/// Read a single `<addr>` child and recover its required offset.
///
/// The current `Decoder` trait has no `AddrSpaceManager`, so this projection
/// validates and consumes the space name but returns the legacy offset-only
/// `Address`. Restoring the exact space handle remains an ADDRESS codec gap.
fn read_addr_child(decoder: &mut dyn Decoder) -> Result<Address> {
    let sub_id = decoder.peek_element();
    if sub_id == 0 {
        bail!("Address element is missing");
    }
    decoder.open_element();
    let mut saw_space = false;
    let mut offset = None;
    loop {
        let aid = decoder.next_attribute_id();
        if aid == 0 {
            break;
        }
        match decoder.attribute_name(aid).as_deref() {
            Some("space") => {
                saw_space = !decoder.read_string().is_empty();
            }
            Some("offset") => {
                offset = Some(decoder.read_unsigned_integer());
            }
            _ => {
                // Ghidra's AddrSpace::decodeAttributes ignores other attrs.
            }
        }
    }
    if !saw_space {
        bail!("Address is missing space");
    }
    let Some(offset) = offset else {
        bail!("Address is missing offset");
    };
    decoder.close_element(sub_id);
    Ok(Address::new(offset))
}

// Ghidra: comment.cc:30 Comment::commentSortKey
/// A sorting key for comments: (funcaddr, addr, uniq). Comments are ordered
/// first by function, then address, then the sub-sort index. Faithful to
/// `CommentOrder` (comment.hh:80).
fn comment_sort_key(c: &Comment) -> (u64, u64, i32) {
    (c.funcaddr.as_u64(), c.addr.as_u64(), c.uniq)
}

/// An in-memory implementation of the CommentDatabase API. Faithful to
/// `CommentDatabaseInternal` (comment.hh:161). All Comment objects are held in
/// memory in a sorted vector (by funcaddr, addr, uniq).
#[derive(Debug, Default, Clone)]
pub struct CommentDatabaseInternal {
    /// The sorted vector of Comments, keyed by (funcaddr, addr, uniq).
    comments: Vec<Comment>,
}

impl CommentDatabaseInternal {
    // Ghidra: comment.cc:134 CommentDatabaseInternal::new
    /// Construct an empty comment database.
    pub fn new() -> Self {
        Self::default()
    }

    // Ghidra: comment.cc:134 CommentDatabaseInternal::sort
    /// Keep the comments vector sorted by (funcaddr, addr, uniq).
    fn sort(&mut self) {
        self.comments
            .sort_by(|a, b| comment_sort_key(a).cmp(&comment_sort_key(b)));
    }

    // Ghidra: comment.cc:148 CommentDatabaseInternal::clear
    /// Clear all comments from this container. Faithful to `clear`
    /// (comment.cc:148).
    pub fn clear(&mut self) {
        self.comments.clear();
    }

    // Ghidra: comment.cc:158 CommentDatabaseInternal::clearType
    /// Clear all comments matching (one of) the indicated types, restricted to
    /// a specific function. Faithful to `clearType` (comment.cc:158).
    pub fn clear_type(&mut self, fad: Address, tp: u32) {
        self.comments
            .retain(|c| !(c.funcaddr == fad && (c.type_flags & tp) != 0));
    }

    // Ghidra: comment.cc:178 CommentDatabaseInternal::addComment
    /// Add a new comment to the container. Faithful to `addComment`
    /// (comment.cc:178). The uniqueness id is auto-assigned.
    pub fn add_comment(&mut self, tp: u32, fad: Address, ad: Address, txt: &str) {
        // Find the next uniq id for this (fad, ad) pair.
        let mut max_uniq = -1i32;
        for c in &self.comments {
            if c.funcaddr == fad && c.addr == ad {
                if c.uniq > max_uniq {
                    max_uniq = c.uniq;
                }
            }
        }
        let uniq = max_uniq + 1;
        let comment = Comment::new(tp, fad, ad, uniq, txt);
        self.comments.push(comment);
        self.sort();
    }

    // Ghidra: comment.cc:196 CommentDatabaseInternal::addCommentNoDuplicate
    /// Add a new comment, making sure there is no duplicate. Faithful to
    /// `addCommentNoDuplicate` (comment.cc:196). Returns true if a new Comment
    /// was created, false if there was a duplicate.
    pub fn add_comment_no_duplicate(
        &mut self,
        tp: u32,
        fad: Address,
        ad: Address,
        txt: &str,
    ) -> bool {
        // Check for an existing comment with the same text at this address.
        for c in &self.comments {
            if c.funcaddr == fad && c.addr == ad && c.text == txt {
                return false;
            }
        }
        self.add_comment(tp, fad, ad, txt);
        true
    }

    // Ghidra: comment.cc:134 CommentDatabaseInternal::numComments
    /// Number of comments in the database.
    pub fn num_comments(&self) -> usize {
        self.comments.len()
    }

    // Ghidra: comment.cc:134 CommentDatabaseInternal::commentsForFunction
    /// Iterate over all comments for a single function. Faithful to
    /// `beginComment`/`endComment`.
    pub fn comments_for_function(&self, fad: Address) -> impl Iterator<Item = &Comment> {
        self.comments.iter().filter(move |c| c.funcaddr == fad)
    }

    // Ghidra: comment.cc:134 CommentDatabaseInternal::allComments
    /// Iterate over all comments.
    pub fn all_comments(&self) -> impl Iterator<Item = &Comment> {
        self.comments.iter()
    }

    // Ghidra: comment.cc:242 CommentDatabaseInternal::encode
    /// Encode all comments to a stream. Faithful to `encode` (comment.cc:242).
    pub fn encode(&self, encoder: &mut dyn Encoder) -> Result<()> {
        let db_elem = ElementId::new("commentdb", 0);
        encoder.open_element(&db_elem);
        for c in &self.comments {
            c.encode(encoder)?;
        }
        encoder.close_element(&db_elem);
        Ok(())
    }

    // Ghidra: comment.cc:253 CommentDatabaseInternal::decode
    /// Decode all comments from a `<commentdb>` element. Faithful to `decode`
    /// (comment.cc:253).
    pub fn decode(&mut self, decoder: &mut dyn Decoder) -> Result<()> {
        let db_id = decoder.open_element();
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let mut com = Comment::new_empty();
            com.decode(decoder)?;
            self.add_comment(
                com.get_type(),
                com.get_func_addr(),
                com.get_addr(),
                com.get_text(),
            );
        }
        decoder.close_element(db_id);
        Ok(())
    }
}

/// Header comment type for the CommentSorter. Faithful to the enum in
/// CommentSorter (comment.hh:197).
pub mod header_type {
    /// Basic header comments.
    pub const HEADER_BASIC: u32 = 0;
    /// Comment that can't be placed in code flow.
    pub const HEADER_UNPLACED: u32 = 1;
}

/// The sorting key for placing a Comment within a specific basic block.
/// Faithful to `CommentSorter::Subsort` (comment.hh:203).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subsort {
    /// Either the basic block index or u32::MAX for a function header (-1 in
    /// Ghidra).
    pub index: u32,
    /// The order index within the basic block.
    pub order: u32,
    /// A final count to guarantee a unique sorting.
    pub pos: u32,
}

impl Subsort {
    // Ghidra: comment.hh:203 Subsort::setHeader
    /// Initialize a key for a header comment. Faithful to `setHeader`.
    pub fn set_header(header_type: u32) -> Self {
        Self {
            index: u32::MAX,
            order: header_type,
            pos: 0,
        }
    }

    // Ghidra: comment.hh:203 Subsort::setBlock
    /// Initialize a key for a basic block position. Faithful to `setBlock`.
    pub fn set_block(i: u32, ord: u32) -> Self {
        Self {
            index: i,
            order: ord,
            pos: 0,
        }
    }
}

/// A class for sorting comments into and within basic blocks. Faithful to
/// `CommentSorter` (comment.hh:195).
///
/// The decompiler maintains information about basic blocks that have been
/// entirely removed, in which case, the user can elect to not display the
/// corresponding comments.
#[derive(Debug, Default)]
pub struct CommentSorter {
    /// Comments for the current function, sorted by block.
    commmap: std::collections::BTreeMap<Subsort, usize>,
    /// The comments themselves (indexed by the commmap values).
    comments: Vec<Comment>,
    /// Display unplaced comments in the header.
    display_unplaced_comments: bool,
}

impl CommentSorter {
    // Ghidra: comment.hh:195 CommentSorter::new
    /// Construct an empty sorter.
    pub fn new() -> Self {
        Self::default()
    }

    // Ghidra: comment.cc:270 CommentSorter::findPosition
    /// Figure out the position of a Comment within the function's basic blocks.
    /// Faithful to `CommentSorter::findPosition` (comment.cc:270).
    ///
    /// Returns true if the comment can be positioned (placed in a block or
    /// header). Sets the subsort key accordingly.
    fn find_position(
        subsort: &mut Subsort,
        comm: &Comment,
        fd: &crate::funcdata::Funcdata,
        display_unplaced: bool,
    ) -> bool {
        if comm.get_type() == 0 {
            return false;
        }
        let fad = *fd.get_address();

        // Header comment at the function address.
        if (comm.get_type() & (comment_type::HEADER | comment_type::WARNINGHEADER)) != 0
            && comm.get_addr() == fad
        {
            *subsort = Subsort::set_header(header_type::HEADER_BASIC);
            return true;
        }

        // Try to find the op at the comment's address.
        let comm_addr = comm.get_addr();
        let mut found_block: Option<i32> = None;
        let mut found_order: u32 = 0;

        // Search through basic blocks for an op at this address.
        for i in 0..fd.bblocks.get_size() {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let bl_rg = bl.read().unwrap();
            if let Some(any) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                for op_ref in &any.ops {
                    let op_rg = op_ref.0.read().unwrap();
                    if op_rg.get_addr() == comm_addr {
                        found_block = Some(i as i32);
                        // Use the op's seq num order as the within-block order.
                        found_order = op_rg.get_seq_num().order;
                        break;
                    }
                }
                if found_block.is_some() {
                    break;
                }
            }
        }

        if let Some(block_idx) = found_block {
            *subsort = Subsort::set_block(block_idx as u32, found_order);
            return true;
        }

        // No op at this address — try to find the block containing it
        // by checking block start addresses.
        for i in 0..fd.bblocks.get_size() {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let bl_rg = bl.read().unwrap();
            if let Some(any) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                let start = any.start_addr.as_u64();
                if comm_addr.as_u64() >= start {
                    // Tentative match — this block starts before the comment.
                    *subsort = Subsort::set_block(i as u32, u32::MAX);
                    return true;
                }
            }
        }

        // Can't place the comment anywhere.
        if display_unplaced {
            *subsort = Subsort::set_header(header_type::HEADER_UNPLACED);
            return true;
        }
        false
    }

    // Ghidra: comment.cc:334 CommentSorter::setupFunctionList
    /// Collect and sort comments specific to the given function. Faithful to
    /// `setupFunctionList` (comment.cc:334).
    ///
    /// This implementation uses `findPosition` to associate comments with
    /// basic blocks by searching for ops at the comment's address.
    pub fn setup_function_list(
        &mut self,
        tp: u32,
        fd: &crate::funcdata::Funcdata,
        db: &CommentDatabaseInternal,
        display_unplaced: bool,
    ) {
        self.commmap.clear();
        self.comments.clear();
        self.display_unplaced_comments = display_unplaced;
        if tp == 0 {
            return;
        }
        let fd_addr = *fd.get_address();
        let mut pos = 0u32;

        for comm in db.comments_for_function(fd_addr) {
            if (comm.get_type() & tp) == 0 {
                continue;
            }
            let mut subsort = Subsort::default();
            if Self::find_position(&mut subsort, comm, fd, display_unplaced) {
                subsort.pos = pos;
                self.comments.push(comm.clone());
                self.commmap.insert(subsort, self.comments.len() - 1);
                pos += 1;
            }
        }
    }

    // Ghidra: comment.cc:379 CommentSorter::setupBlockList
    /// Prepare to walk comments from a single basic block. Faithful to
    /// `setupBlockList` (comment.cc:379). Returns the comments for the
    /// given block index.
    pub fn setup_block_list(&self, block_index: u32) -> Vec<&Comment> {
        self.commmap
            .iter()
            .filter(|(ss, _)| ss.index == block_index)
            .map(|(_, &idx)| &self.comments[idx])
            .collect()
    }

    // Ghidra: comment.cc:362 CommentSorter::setupOpList
    /// Prepare to walk comments up to a specific op landmark. Faithful to
    /// `setupOpList` (comment.cc:362).
    pub fn setup_op_list(&self, block_index: u32, op_order: u32) -> Vec<&Comment> {
        self.commmap
            .iter()
            .filter(|(ss, _)| ss.index == block_index && ss.order <= op_order)
            .map(|(_, &idx)| &self.comments[idx])
            .collect()
    }

    // Ghidra: comment.cc:394 CommentSorter::setupHeader
    /// Prepare to walk comments in the header. The full iterator mutation of
    /// `setupHeader` (comment.cc:394) is tracked by
    /// COMMENT-SORTER-ITERATORS-0001.
    pub fn setup_header(&self, _header_type: u32) {
        // TODO(COMMENT-SORTER-ITERATORS-0001): maintain start/opstop over the
        // exact (index=-1, order=header_type, pos) Subsort interval.
    }

    // Ghidra: comment.hh:195 CommentSorter::hasHeaderComments
    /// Return true if there are more comments to emit in the header.
    pub fn has_header_comments(&self) -> bool {
        self.commmap.keys().any(|k| k.index == u32::MAX)
    }

    // Ghidra: comment.hh:195 CommentSorter::headerComments
    /// Iterate over all header comments (basic + unplaced).
    pub fn header_comments(&self) -> impl Iterator<Item = &Comment> {
        self.commmap
            .iter()
            .filter(|(k, _)| k.index == u32::MAX)
            .map(|(_, &idx)| &self.comments[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::{IdRegistry, TreeDecoder, TreeEncoder};
    use crate::space::{space_flags, AddrSpace, SpaceType};

    fn ram_space() -> AddrSpace {
        AddrSpace::new_space(
            SpaceType::Processor,
            "ram",
            false,
            8,
            1,
            3,
            space_flags::HASPHYSICAL,
            0,
            0,
        )
    }

    #[test]
    fn test_comment_construction() {
        let c = Comment::new(
            comment_type::HEADER,
            Address::new(0x1000),
            Address::new(0x1000),
            0,
            "This is a header comment",
        );
        assert_eq!(c.get_type(), comment_type::HEADER);
        assert_eq!(c.get_func_addr().as_u64(), 0x1000);
        assert_eq!(c.get_addr().as_u64(), 0x1000);
        assert_eq!(c.get_uniq(), 0);
        assert_eq!(c.get_text(), "This is a header comment");
        assert!(!c.is_emitted());
    }

    #[test]
    fn test_comment_type_roundtrip() {
        for &tp in &[
            comment_type::USER1,
            comment_type::USER2,
            comment_type::USER3,
            comment_type::HEADER,
            comment_type::WARNING,
            comment_type::WARNINGHEADER,
        ] {
            let name = decode_comment_type(tp).unwrap();
            assert_eq!(encode_comment_type(&name).unwrap(), tp);
        }
        assert!(encode_comment_type("unknown").is_err());
        assert!(decode_comment_type(0).is_err());
    }

    #[test]
    fn test_database_add_comment() {
        let mut db = CommentDatabaseInternal::new();
        assert_eq!(db.num_comments(), 0);
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Warning!",
        );
        assert_eq!(db.num_comments(), 1);
    }

    #[test]
    fn test_database_add_no_duplicate() {
        let mut db = CommentDatabaseInternal::new();
        assert!(db.add_comment_no_duplicate(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Warning!"
        ));
        assert!(!db.add_comment_no_duplicate(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Warning!"
        ));
        assert_eq!(db.num_comments(), 1);
        // Different text → added.
        assert!(db.add_comment_no_duplicate(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Different"
        ));
        assert_eq!(db.num_comments(), 2);
    }

    #[test]
    fn test_database_clear_type() {
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "W",
        );
        db.add_comment(
            comment_type::HEADER,
            Address::new(0x1000),
            Address::new(0x3000),
            "H",
        );
        assert_eq!(db.num_comments(), 2);
        db.clear_type(Address::new(0x1000), comment_type::WARNING);
        assert_eq!(db.num_comments(), 1);
    }

    #[test]
    fn test_database_comments_for_function() {
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "A",
        );
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x3000),
            "B",
        );
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x5000),
            Address::new(0x6000),
            "C",
        );
        let func1: Vec<_> = db.comments_for_function(Address::new(0x1000)).collect();
        assert_eq!(func1.len(), 2);
        let func2: Vec<_> = db.comments_for_function(Address::new(0x5000)).collect();
        assert_eq!(func2.len(), 1);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        {
            let mut r = registry.write().unwrap();
            for nm in &["type", "space", "offset", "XMLcontent"] {
                r.register_attribute(nm);
            }
            for nm in &["comment", "commentdb", "addr", "text"] {
                r.register_element(nm);
            }
        }
        let ram = ram_space();
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::WARNING,
            Address::with_space(&ram, 0x1000),
            Address::with_space(&ram, 0x2000),
            "Test warning",
        );
        db.add_comment(
            comment_type::HEADER,
            Address::with_space(&ram, 0x1000),
            Address::with_space(&ram, 0x1000),
            "Header",
        );

        // Encode.
        let mut enc = TreeEncoder::new(registry.clone());
        db.encode(&mut enc).unwrap();
        let doc = enc.into_document();
        assert!(doc.get_root().is_some());

        // Decode into a fresh database.
        let root = doc.get_root().unwrap().clone();
        let mut db2 = CommentDatabaseInternal::new();
        let mut dec = TreeDecoder::new(root, registry.clone());
        db2.decode(&mut dec).unwrap();

        assert_eq!(db2.num_comments(), 2);
        let comments: Vec<_> = db2
            .comments_for_function(Address::new(0x1000))
            .map(|c| {
                (
                    c.get_type(),
                    c.get_addr().as_u64(),
                    c.get_text().to_string(),
                )
            })
            .collect();
        assert!(
            comments.iter().any(|(t, a, txt)| {
                *t == comment_type::WARNING && *a == 0x2000 && txt == "Test warning"
            }),
            "decoded comments: {comments:?}"
        );
        assert!(comments
            .iter()
            .any(|(t, a, txt)| { *t == comment_type::HEADER && *a == 0x1000 && txt == "Header" }));
    }

    #[test]
    fn test_decode_unknown_type_partial_state() {
        let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        {
            let mut r = registry.write().unwrap();
            r.register_attribute("type");
            r.register_element("comment");
        }
        let comment_elem = ElementId::new("comment", 0);
        let mut enc = TreeEncoder::new(registry.clone());
        enc.open_element(&comment_elem);
        enc.write_string(&AttributeId::new("type", 0), "bogus");
        enc.close_element(&comment_elem);
        let root = enc.into_document().get_root().unwrap().clone();

        let mut comment = Comment::new(
            comment_type::HEADER,
            Address::new(0xaaaa),
            Address::new(0xbbbb),
            7,
            "sentinel",
        );
        comment.set_emitted(true);
        let mut dec = TreeDecoder::new(root, registry);
        assert_eq!(
            comment.decode(&mut dec).unwrap_err().to_string(),
            "Unknown comment type: bogus"
        );
        assert_eq!(comment.get_type(), 0);
        assert!(!comment.is_emitted());
        assert_eq!(comment.get_func_addr().as_u64(), 0xaaaa);
        assert_eq!(comment.get_addr().as_u64(), 0xbbbb);
        assert_eq!(comment.get_uniq(), 7);
        assert_eq!(comment.get_text(), "sentinel");
    }

    #[test]
    fn test_decode_missing_offset_partial_state() {
        let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        {
            let mut r = registry.write().unwrap();
            for nm in &["type", "space", "offset", "XMLcontent"] {
                r.register_attribute(nm);
            }
            for nm in &["comment", "addr", "text"] {
                r.register_element(nm);
            }
        }
        let comment_elem = ElementId::new("comment", 0);
        let addr_elem = ElementId::new("addr", 0);
        let mut enc = TreeEncoder::new(registry.clone());
        enc.open_element(&comment_elem);
        enc.write_string(&AttributeId::new("type", 0), "warning");
        enc.open_element(&addr_elem);
        enc.write_string(&AttributeId::new("space", 0), "ram");
        enc.close_element(&addr_elem);
        enc.close_element(&comment_elem);
        let root = enc.into_document().get_root().unwrap().clone();

        let mut comment = Comment::new(
            comment_type::HEADER,
            Address::new(0xaaaa),
            Address::new(0xbbbb),
            7,
            "sentinel",
        );
        comment.set_emitted(true);
        let mut dec = TreeDecoder::new(root, registry);
        assert_eq!(
            comment.decode(&mut dec).unwrap_err().to_string(),
            "Address is missing offset"
        );
        assert_eq!(comment.get_type(), comment_type::WARNING);
        assert!(!comment.is_emitted());
        assert_eq!(comment.get_func_addr().as_u64(), 0xaaaa);
        assert_eq!(comment.get_addr().as_u64(), 0xbbbb);
        assert_eq!(comment.get_uniq(), 7);
        assert_eq!(comment.get_text(), "sentinel");
    }

    #[test]
    fn test_subsort_ordering() {
        let header = Subsort::set_header(header_type::HEADER_BASIC);
        let block0 = Subsort::set_block(0, 5);
        let block1 = Subsort::set_block(1, 0);
        // Header (index=u32::MAX) sorts after all blocks.
        assert!(block0 < block1);
        assert!(block1 < header);
    }

    #[test]
    fn test_comment_sorter_header() {
        let mut fd = crate::funcdata::Funcdata::new("test", Address::new(0x1000), 16);
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::HEADER,
            Address::new(0x1000),
            Address::new(0x1000),
            "Function header",
        );
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Inline warning",
        );
        let mut sorter = CommentSorter::new();
        sorter.setup_function_list(
            comment_type::HEADER | comment_type::WARNING,
            &fd,
            &db,
            false,
        );
        // Only the header comment should be placed (the warning is not at fd_addr).
        assert!(sorter.has_header_comments());
        let headers: Vec<_> = sorter.header_comments().collect();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].get_text(), "Function header");
    }
}
