//! Type system module aligning with Ghidra's decompiler type management
//!
//! This module contains the representation of data types, type factories,
//! and casting strategies. Corresponds to `type.hh` and related files.

pub mod datatype;
pub mod typefactory;
pub mod cast;

pub use datatype::{Datatype, TypeBase, TypeField, TypeMetatype, type_flags};
pub use typefactory::TypeFactory;
pub use cast::{CastStrategy, CastStrategyC};

// Future alignment targets:
// - ConstantPool: Handling of constant values and their types
