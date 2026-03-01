//! Alignment verification for Block / CFG
//!
//! Corresponds to Ghidra's `block.hh`

#[cfg(test)]
mod tests {
    use crate::address::Address;
    use crate::block::{BlockBasic, BlockGraph, FlowBlock};

    #[test]
    fn verify_block_basic() {
        let mut bb = BlockBasic::new(0, Address::new(0x1000));
        assert_eq!(bb.get_index(), 0);
        assert_eq!(bb.get_start_addr(), Address::new(0x1000));

        // Flags
        assert_eq!(bb.get_flags(), 0);
        bb.set_flags(1);
        assert_eq!(bb.get_flags(), 1);
    }

    #[test]
    fn verify_block_graph() {
        let bg = BlockGraph::new();
        assert_eq!(bg.get_size(), 0);
    }
}
