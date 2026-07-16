//! Address space definitions
//!
//! This module corresponds to Ghidra's `space.hh` and defines the various
//! address spaces used in the decompiler.
//!
//! # Address Spaces
//!
//! Ghidra uses multiple address spaces to represent different types of storage:
//! - **RAM**: Normal memory
//! - **Register**: CPU registers
//! - **Unique**: Temporary/intermediate values (SSA temporaries)
//! - **Const**: Constant values
//! - **Stack**: Stack space
//! - **Other**: Custom/architecture-specific spaces

use serde::{Deserialize, Serialize};
use std::fmt;

/// Address space identifier
pub type SpaceId = u8;

// Space IDs matching SLEIGH .sla spec space indices (space.hh getIndex()).
// SLEIGH x86-64 spec: 0=const, 1=OTHER, 2=unique, 3=ram, 4=register.
// Rugra extends past index 4 for its own spaces (Stack, Join, Iop).
pub const SPACEID_CONST: SpaceId = 0;
pub const SPACEID_OTHER: SpaceId = 1;
pub const SPACEID_UNIQUE: SpaceId = 2;
pub const SPACEID_RAM: SpaceId = 3;
pub const SPACEID_REGISTER: SpaceId = 4;
pub const SPACEID_STACK: SpaceId = 5;
pub const SPACEID_JOIN: SpaceId = 6;
pub const SPACEID_IOP: SpaceId = 7;

/// Address space in which a varnode resides
///
/// Corresponds to Ghidra's AddrSpace hierarchy in `space.hh`
///
/// Ghidra uses multiple address spaces to represent different types of storage:
/// - RAM: Normal memory
/// - Register: CPU registers
/// - Unique: Temporary/intermediate values
/// - Const: Constant values
/// - Stack: Stack space
/// - Other: Custom address spaces
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub enum AddressSpace {
    /// Normal memory (RAM)
    Ram,
    /// CPU registers
    Register,
    /// Temporary/unique storage for intermediate values (SSA temporaries)
    Unique,
    /// Constant values
    Const,
    /// Stack space
    Stack,
    /// Join space (for combining multiple spaces)
    Join,
    /// Internal iop space — varnodes referencing a PcodeOp (Ghidra IPTR_IOP).
    Iop,
    /// Overlay space
    Overlay,
    /// Other/custom address space
    Other(SpaceId),
}

impl AddressSpace {
    // RUGRA-GLUE: space_id (no Ghidra counterpart found)
    /// Get the space ID
    pub fn space_id(&self) -> SpaceId {
        match self {
            AddressSpace::Ram => SPACEID_RAM,
            AddressSpace::Register => SPACEID_REGISTER,
            AddressSpace::Unique => SPACEID_UNIQUE,
            AddressSpace::Const => SPACEID_CONST,
            AddressSpace::Stack => SPACEID_STACK,
            AddressSpace::Join => SPACEID_JOIN,
            AddressSpace::Iop => SPACEID_IOP,
            AddressSpace::Overlay => SPACEID_OTHER,
            AddressSpace::Other(id) => *id,
        }
    }

    // Ghidra: space.hh:31 spacetype
    pub fn from_id(id: SpaceId) -> Self {
        match id {
            SPACEID_CONST => AddressSpace::Const,
            SPACEID_OTHER => AddressSpace::Other(id),
            SPACEID_UNIQUE => AddressSpace::Unique,
            SPACEID_RAM => AddressSpace::Ram,
            SPACEID_REGISTER => AddressSpace::Register,
            SPACEID_STACK => AddressSpace::Stack,
            SPACEID_JOIN => AddressSpace::Join,
            SPACEID_IOP => AddressSpace::Iop,
            id => AddressSpace::Other(id),
        }
    }

    // RUGRA-GLUE: is_register
    /// Check if this is a register space
    pub fn is_register(&self) -> bool {
        matches!(self, AddressSpace::Register)
    }

    // RUGRA-GLUE: is_unique (no Ghidra counterpart found)
    /// Check if this is a temporary/unique space
    pub fn is_unique(&self) -> bool {
        matches!(self, AddressSpace::Unique)
    }

    // RUGRA-GLUE: is_const (no Ghidra counterpart found)
    /// Check if this is a constant space
    pub fn is_const(&self) -> bool {
        matches!(self, AddressSpace::Const)
    }

    // RUGRA-GLUE: is_ram (no Ghidra counterpart found)
    /// Check if this is RAM space
    pub fn is_ram(&self) -> bool {
        matches!(self, AddressSpace::Ram)
    }

    // RUGRA-GLUE: is_stack (no Ghidra counterpart found)
    /// Check if this is stack space
    pub fn is_stack(&self) -> bool {
        matches!(self, AddressSpace::Stack)
    }

    // Ghidra: space.hh AddrSpace::getDelay
    /// Heritage delay for this space — number of heritage passes before
    /// this space's varnodes are first heritaged. Faithful to
    /// `AddrSpace::getDelay()` (space.hh). Ghidra reads this from the
    /// .sla spec (space.cc:325); Rugra's simplified enum model uses the
    /// Ghidra defaults: Stack=1 (so stack varnodes get a 2nd heritage pass
    /// after register/unique), all others=0.
    pub fn get_delay(&self) -> i32 {
        match self {
            AddressSpace::Stack => 1,
            _ => 0,
        }
    }

    // Ghidra: space.hh AddrSpace::getDeadcodeDelay
    /// Dead-code delay — number of heritage passes before dead-code removal
    /// is allowed on this space. Faithful to `AddrSpace::getDeadcodeDelay()`
    /// (space.hh). Ghidra defaults deadcodedelay = delay if not specified
    /// (space.cc:334-335).
    pub fn get_deadcode_delay(&self) -> i32 {
        self.get_delay()
    }

    // Ghidra: space.hh AddrSpace::isHeritaged
    /// Is this space heritaged (subject to SSA phi-placement)? Faithful to
    /// `AddrSpace::isHeritaged()` (space.hh). Ghidra's IPTR_CONSTANT,
    /// IPTR_FSPEC, IPTR_IOP, IPTR_JOIN are not heritaged; all others are.
    /// Rugra: Const/Iop/Join/Fspec(not modeled) are not heritaged.
    pub fn is_heritaged(&self) -> bool {
        !matches!(self, AddressSpace::Const | AddressSpace::Iop | AddressSpace::Join)
    }

    /// Check if this is the internal iop space (references a PcodeOp).
    /// Ghidra: `getSpaceType()==IPTR_IOP` (space.hh:35).
    pub fn is_iop(&self) -> bool {
        matches!(self, AddressSpace::Iop)
    }

    // RUGRA-GLUE: is_big_endian (no Ghidra counterpart found)
    /// Check if this is a big-endian space
    pub fn is_big_endian(&self) -> bool {
        // Default to false, can be overridden per architecture
        false
    }

    // RUGRA-GLUE: word_size (no Ghidra counterpart found)
    /// Get the word size for this space (in bytes)
    pub fn word_size(&self) -> usize {
        match self {
            AddressSpace::Register | AddressSpace::Ram | AddressSpace::Stack => 1,
            AddressSpace::Unique => 1,
            AddressSpace::Const => 1,
            AddressSpace::Join | AddressSpace::Iop | AddressSpace::Overlay | AddressSpace::Other(_) => 1,
        }
    }

    // RUGRA-GLUE: addr_size (no Ghidra counterpart found)
    /// Get the address size for this space (in bytes)
    pub fn addr_size(&self) -> usize {
        // Default to 8 bytes (64-bit), can be configured per architecture
        8
    }

    // RUGRA-GLUE: name (no Ghidra counterpart found)
    /// Get the name of this space
    pub fn name(&self) -> &'static str {
        match self {
            AddressSpace::Ram => "ram",
            AddressSpace::Register => "register",
            AddressSpace::Unique => "unique",
            AddressSpace::Const => "const",
            AddressSpace::Stack => "stack",
            AddressSpace::Join => "join",
            AddressSpace::Iop => "iop",
            AddressSpace::Overlay => "overlay",
            AddressSpace::Other(_) => "other",
        }
    }
}

impl fmt::Display for AddressSpace {
    // RUGRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressSpace::Ram => write!(f, "ram"),
            AddressSpace::Register => write!(f, "register"),
            AddressSpace::Unique => write!(f, "unique"),
            AddressSpace::Const => write!(f, "const"),
            AddressSpace::Stack => write!(f, "stack"),
            AddressSpace::Join => write!(f, "join"),
            AddressSpace::Iop => write!(f, "iop"),
            AddressSpace::Overlay => write!(f, "overlay"),
            AddressSpace::Other(id) => write!(f, "space{}", id),
        }
    }
}

/// Constant space (for constant values)
///
/// Corresponds to Ghidra's `ConstantSpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantSpace {
    /// Space ID
    pub id: SpaceId,
}

impl ConstantSpace {
    // Ghidra: space.cc:356 ConstantSpace::new
    /// Create a new constant space
    pub fn new() -> Self {
        ConstantSpace {
            id: SPACEID_CONST,
        }
    }

    // Ghidra: space.cc:356 ConstantSpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Const
    }

    // Ghidra: space.cc:380 ConstantSpace::decode
    /// Decode from string
    pub fn decode(s: &str) -> Option<Self> {
        let _id = s.parse::<SpaceId>().ok()?;
        Some(ConstantSpace::new())
    }

    // Ghidra: space.cc:364 ConstantSpace::overlapJoin
    /// Check if this overlaps with a join space
    pub fn overlap_join(&self, _offset: u64, _size: usize) -> bool {
        // Constant space doesn't overlap with joins
        false
    }

    // Ghidra: space.cc:372 ConstantSpace::printRaw
    /// Print raw representation
    pub fn print_raw(&self) -> String {
        format!("const_space[{}]", self.id)
    }
}

impl Default for ConstantSpace {
    // Ghidra: space.cc:356 ConstantSpace::default
    fn default() -> Self {
        Self::new()
    }
}

/// Unique space (for SSA temporaries)
///
/// Corresponds to Ghidra's `UniqueSpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueSpace {
    /// Space ID
    pub id: SpaceId,
    /// Next available unique offset
    next_offset: u64,
}

impl UniqueSpace {
    // Ghidra: space.cc:427 UniqueSpace::new
    /// Create a new unique space
    pub fn new() -> Self {
        UniqueSpace {
            id: SPACEID_UNIQUE,
            next_offset: 0,
        }
    }

    // Ghidra: space.cc:427 UniqueSpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Unique
    }

    // Ghidra: space.cc:427 UniqueSpace::allocate
    /// Allocate a new unique offset
    pub fn allocate(&mut self, size: usize) -> u64 {
        let offset = self.next_offset;
        self.next_offset += size as u64;
        offset
    }

    // Ghidra: space.cc:427 UniqueSpace::reset
    /// Reset the allocator
    pub fn reset(&mut self) {
        self.next_offset = 0;
    }
}

impl Default for UniqueSpace {
    // Ghidra: space.cc:427 UniqueSpace::default
    fn default() -> Self {
        Self::new()
    }
}

/// Other/custom address space
///
/// Corresponds to Ghidra's `OtherSpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherSpace {
    /// Space ID
    pub id: SpaceId,
    /// Space name
    pub name: String,
}

impl OtherSpace {
    // Ghidra: space.cc:396 OtherSpace::new
    /// Create a new other space
    pub fn new(id: SpaceId, name: String) -> Self {
        OtherSpace { id, name }
    }

    // Ghidra: space.cc:396 OtherSpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Other(self.id)
    }

    // Ghidra: space.cc:410 OtherSpace::printRaw
    /// Print raw representation
    pub fn print_raw(&self) -> String {
        format!("other_space[{}]:'{}'", self.id, self.name)
    }
}

// Ghidra: translate.hh:196 JoinRecord
/// A record describing how a join-space address maps to physical pieces.
#[derive(Debug, Clone)]
pub struct JoinRecord {
    pub pieces: Vec<VarnodeData>,
    pub unified: VarnodeData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarnodeData {
    pub space: AddressSpace,
    pub offset: u64,
    pub size: usize,
}

impl JoinRecord {
    // Ghidra: translate.hh:201 JoinRecord::numPieces
    pub fn num_pieces(&self) -> usize { self.pieces.len() }
    // Ghidra: translate.hh:202 JoinRecord::isFloatExtension
    pub fn is_float_extension(&self) -> bool { self.pieces.len() == 1 }
    // Ghidra: translate.hh:203 JoinRecord::getPiece
    pub fn get_piece(&self, i: usize) -> &VarnodeData { &self.pieces[i] }
    // Ghidra: translate.hh:204 JoinRecord::getUnified
    pub fn get_unified(&self) -> &VarnodeData { &self.unified }
}

#[derive(Clone)]
pub struct JoinDatabase {
    pub records: Vec<JoinRecord>,
}

impl JoinDatabase {
    // RUGRA-GLUE: Rust Default ctor (Ghidra uses AddrSpaceManager's vector)
    pub fn new() -> Self { Self { records: Vec::new() } }
    // Ghidra: translate.hh:232 AddrSpaceManager::findJoin
    pub fn find_join(&self, offset: u64) -> Option<&JoinRecord> {
        self.records.iter().find(|r| r.unified.offset == offset)
    }
    // Ghidra: translate.hh:234 AddrSpaceManager::addJoin
    pub fn add_join(&mut self, pieces: Vec<VarnodeData>) -> u64 {
        let offset = self.records.len() as u64;
        let total_size: usize = pieces.iter().map(|p| p.size).sum();
        let unified = VarnodeData { space: AddressSpace::Join, offset, size: total_size };
        self.records.push(JoinRecord { pieces, unified });
        offset
    }
}

/// Join space (for combining multiple spaces)
///
/// Corresponds to Ghidra's `JoinSpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinSpace {
    /// Space ID
    pub id: SpaceId,
    /// Pieces that make up the join
    pub pieces: Vec<JoinPiece>,
}

/// A piece of a join
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinPiece {
    /// Address space of this piece
    pub space: AddressSpace,
    /// Offset in the space
    pub offset: u64,
    /// Size of this piece
    pub size: usize,
}

impl JoinSpace {
    // Ghidra: space.cc:446 JoinSpace::new
    /// Create a new join space
    pub fn new(pieces: Vec<JoinPiece>) -> Self {
        JoinSpace {
            id: SPACEID_JOIN,
            pieces,
        }
    }

    // Ghidra: space.cc:446 JoinSpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Join
    }

    // Ghidra: space.cc:446 JoinSpace::size
    /// Get the total size of the join
    pub fn size(&self) -> usize {
        self.pieces.iter().map(|p| p.size).sum()
    }

    // Ghidra: space.cc:446 JoinSpace::numPieces
    /// Get the number of pieces
    pub fn num_pieces(&self) -> usize {
        self.pieces.len()
    }

    // Ghidra: space.cc:646 JoinSpace::decode
    /// Decode from string format
    pub fn decode(s: &str) -> Option<Self> {
        // Format: "piece1_space:offset:size,piece2_space:offset:size,..."
        let mut pieces = Vec::new();
        for piece_str in s.split(',') {
            let parts: Vec<&str> = piece_str.split(':').collect();
            if parts.len() != 3 {
                return None;
            }
            let space_id = parts[0].parse::<SpaceId>().ok()?;
            let offset = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).ok()?;
            let size = parts[2].parse().ok()?;
            pieces.push(JoinPiece {
                space: AddressSpace::from_id(space_id),
                offset,
                size,
            });
        }
        Some(JoinSpace::new(pieces))
    }

    // Ghidra: space.cc:539 JoinSpace::decodeAttributes
    /// Decode from attributes (XML-style)
    pub fn decode_attributes(attrs: &[(&str, &str)]) -> Option<Self> {
        let mut pieces = Vec::new();
        for (key, value) in attrs {
            if key.starts_with("piece") {
                let parts: Vec<&str> = value.split(':').collect();
                if parts.len() >= 3 {
                    if let (Ok(space_id), Ok(offset), Ok(size)) = (
                        parts[0].parse::<SpaceId>(),
                        u64::from_str_radix(parts[1].trim_start_matches("0x"), 16),
                        parts[2].parse(),
                    ) {
                        pieces.push(JoinPiece {
                            space: AddressSpace::from_id(space_id),
                            offset,
                            size,
                        });
                    }
                }
            }
        }
        if pieces.is_empty() {
            None
        } else {
            Some(JoinSpace::new(pieces))
        }
    }

    // Ghidra: space.cc:502 JoinSpace::encodeAttributes
    /// Encode to attributes (XML-style)
    pub fn encode_attributes(&self) -> Vec<(String, String)> {
        self.pieces
            .iter()
            .enumerate()
            .map(|(i, piece)| {
                (
                    format!("piece{}", i),
                    format!("{}:{:x}:{}", piece.space.space_id(), piece.offset, piece.size),
                )
            })
            .collect()
    }

    // Ghidra: space.cc:454 JoinSpace::overlapJoin
    /// Check if this overlaps with another join
    pub fn overlap_join(&self, offset: u64, size: usize) -> bool {
        let end = offset + size as u64;
        let self_size = self.size() as u64;
        offset < self_size && end > 0
    }

    // Ghidra: space.cc:590 JoinSpace::printRaw
    /// Print raw representation
    pub fn print_raw(&self) -> String {
        let pieces_str: Vec<String> = self
            .pieces
            .iter()
            .map(|p| format!("{}:{:x}:{}", p.space, p.offset, p.size))
            .collect();
        format!("join_space[{}]", pieces_str.join(","))
    }

    // Ghidra: space.cc:611 JoinSpace::read
    /// Read value from the joined pieces
    pub fn read(&self, _offset: u64, _size: usize) -> Vec<u8> {
        // Placeholder: would need actual memory context to read
        vec![0; _size]
    }
}

/// Overlay space (for overlaying another space)
///
/// Corresponds to Ghidra's `OverlaySpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlaySpace {
    /// Space ID
    pub id: SpaceId,
    /// Base space being overlaid
    pub base_space: AddressSpace,
    /// Name of the overlay
    pub name: String,
}

impl OverlaySpace {
    // Ghidra: space.cc:654 OverlaySpace::new
    /// Create a new overlay space
    pub fn new(id: SpaceId, base_space: AddressSpace, name: String) -> Self {
        OverlaySpace {
            id,
            base_space,
            name,
        }
    }

    // Ghidra: space.cc:654 OverlaySpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Overlay
    }

    // Ghidra: space.cc:654 OverlaySpace::base
    /// Get the base space
    pub fn base(&self) -> AddressSpace {
        self.base_space
    }

    // Ghidra: space.cc:661 OverlaySpace::decode
    /// Decode from string format "id:base_space_id:name"
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return None;
        }
        let id = parts[0].parse::<SpaceId>().ok()?;
        let base_space_id = parts[1].parse::<SpaceId>().ok()?;
        let name = parts[2].to_string();
        Some(OverlaySpace::new(
            id,
            AddressSpace::from_id(base_space_id),
            name,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_space_id() {
        assert_eq!(AddressSpace::Ram.space_id(), SPACEID_RAM);
        assert_eq!(AddressSpace::Register.space_id(), SPACEID_REGISTER);
        assert_eq!(AddressSpace::Unique.space_id(), SPACEID_UNIQUE);
        assert_eq!(AddressSpace::Const.space_id(), SPACEID_CONST);
    }

    #[test]
    fn test_address_space_from_id() {
        assert_eq!(AddressSpace::from_id(SPACEID_RAM), AddressSpace::Ram);
        assert_eq!(
            AddressSpace::from_id(SPACEID_REGISTER),
            AddressSpace::Register
        );
        assert_eq!(AddressSpace::from_id(SPACEID_UNIQUE), AddressSpace::Unique);
        assert_eq!(AddressSpace::from_id(SPACEID_CONST), AddressSpace::Const);
    }

    #[test]
    fn test_address_space_predicates() {
        assert!(AddressSpace::Register.is_register());
        assert!(AddressSpace::Unique.is_unique());
        assert!(AddressSpace::Const.is_const());
        assert!(AddressSpace::Ram.is_ram());
        assert!(AddressSpace::Stack.is_stack());

        assert!(!AddressSpace::Ram.is_register());
        assert!(!AddressSpace::Register.is_const());
    }

    #[test]
    fn test_address_space_display() {
        assert_eq!(AddressSpace::Ram.to_string(), "ram");
        assert_eq!(AddressSpace::Register.to_string(), "register");
        assert_eq!(AddressSpace::Unique.to_string(), "unique");
        assert_eq!(AddressSpace::Const.to_string(), "const");
    }

    #[test]
    fn test_unique_space_allocation() {
        let mut unique = UniqueSpace::new();

        let offset1 = unique.allocate(4);
        let offset2 = unique.allocate(8);
        let offset3 = unique.allocate(4);

        assert_eq!(offset1, 0);
        assert_eq!(offset2, 4);
        assert_eq!(offset3, 12);

        unique.reset();
        let offset4 = unique.allocate(4);
        assert_eq!(offset4, 0);
    }

    #[test]
    fn test_join_space() {
        let pieces = vec![
            JoinPiece {
                space: AddressSpace::Register,
                offset: 0,
                size: 4,
            },
            JoinPiece {
                space: AddressSpace::Register,
                offset: 4,
                size: 4,
            },
        ];

        let join = JoinSpace::new(pieces);
        assert_eq!(join.size(), 8);
        assert_eq!(join.num_pieces(), 2);
    }

    #[test]
    fn test_overlay_space() {
        let overlay = OverlaySpace::new(10, AddressSpace::Ram, "code_overlay".to_string());
        assert_eq!(overlay.base(), AddressSpace::Ram);
        assert_eq!(overlay.space(), AddressSpace::Overlay);
    }

    #[test]
    fn test_constant_space_methods() {
        let const_space = ConstantSpace::new();
        assert_eq!(const_space.print_raw(), "const_space[0]");
        assert!(!const_space.overlap_join(0, 100));
    }

    #[test]
    fn test_other_space_print_raw() {
        let other = OtherSpace::new(10, "custom".to_string());
        assert_eq!(other.print_raw(), "other_space[10]:'custom'");
    }

    #[test]
    fn test_join_space_decode_encode() {
        let pieces = vec![
            JoinPiece {
                space: AddressSpace::Register,
                offset: 0,
                size: 4,
            },
            JoinPiece {
                space: AddressSpace::Register,
                offset: 4,
                size: 4,
            },
        ];
        let join = JoinSpace::new(pieces);

        let attrs = join.encode_attributes();
        assert_eq!(attrs.len(), 2);

        assert!(join.overlap_join(0, 4));
        assert!(!join.overlap_join(100, 4));
    }

    #[test]
    fn test_overlay_space_decode() {
        let overlay = OverlaySpace::decode("10:3:test_overlay").unwrap();
        assert_eq!(overlay.id, 10);
        assert_eq!(overlay.base(), AddressSpace::Ram);
        assert_eq!(overlay.name, "test_overlay");
    }
}
