//! Alignment verification for Heritage (SSA construction)
//!
//! Corresponds to Ghidra's `heritage.hh`

/*
#[cfg(test)]
mod tests {
    use crate::address::Address;
    use crate::heritage::{Heritage, HeritageInfo, LocationMap, PriorityQueue, SizePass};
    use crate::space::AddressSpace;

    // Testing specific Heritage components to ensure they exist and act structurally same.

    #[test]
    fn verify_size_pass() {
        let mut map = LocationMap::new();
        map.add(Address::new(0x1000), 4, 1);

        assert_eq!(map.find_pass(Address::new(0x1000)), 1);
        map.clear();
        // Since clear() is called, this should technically be not found, returning -1
        assert_eq!(map.find_pass(Address::new(0x1000)), -1);
    }

    #[test]
    fn verify_heritage_info() {
        let info = HeritageInfo::new(AddressSpace::Ram);
        assert_eq!(info.space, AddressSpace::Ram);
        assert_eq!(info.delay, 0);
        assert_eq!(info.deadcodedelay, 0);
        assert_eq!(info.deadremoved, -1);
    }

    #[test]
    fn verify_priority_queue() {
        let mut pq = PriorityQueue::new();
        assert!(pq.empty());
        pq.reset(5);
        assert!(pq.empty());
    }

    #[test]
    fn verify_heritage_struct() {
        let h = Heritage::new();
        assert!(h.fd.is_none());
        assert_eq!(h.maxdepth, -1);
        assert_eq!(h.pass, 0);
    }
}
*/
