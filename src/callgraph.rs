//! Call graph construction and analysis.
//!
//! Corresponds to Ghidra's `callgraph.hh` / `callgraph.cc` (596 lines).
//!
//! Builds and analyzes the call graph of a program: which functions call
//! which, detecting cycles, and iterating in leaf-first order.
//!
//! Key classes:
//! - `CallGraphEdge`: a directed edge (caller → callee)
//! - `CallGraphNode`: a function node with in/out edges
//! - `CallGraph`: the graph container with cycle detection and leaf walk

use std::collections::BTreeMap;

/// Edge flags.
pub mod edge_flags {
    pub const CYCLE: u32 = 1;
    pub const DONTFOLLOW: u32 = 2;
}

/// Node flags.
pub mod node_flags {
    pub const MARK: u32 = 1;
    pub const ONLY_CYCLE_IN: u32 = 2;
    pub const CURRENT_CYCLE: u32 = 4;
    pub const ENTRY_NODE: u32 = 8;
}

/// A directed edge in the call graph (caller → callee).
/// Corresponds to Ghidra's `CallGraphEdge` (callgraph.hh:32).
#[derive(Debug, Clone)]
pub struct CallGraphEdge {
    /// Address of the caller function
    pub from_addr: u64,
    /// Address of the callee function
    pub to_addr: u64,
    /// Address where the call instruction was made
    pub callsite_addr: u64,
    /// Edge flags
    pub flags: u32,
}

impl CallGraphEdge {
    pub fn new(from: u64, to: u64, callsite: u64) -> Self {
        Self { from_addr: from, to_addr: to, callsite_addr: callsite, flags: 0 }
    }
    pub fn is_cycle(&self) -> bool { self.flags & edge_flags::CYCLE != 0 }
}

/// A function node in the call graph.
/// Corresponds to Ghidra's `CallGraphNode` (callgraph.hh:54).
#[derive(Debug, Clone)]
pub struct CallGraphNode {
    /// Starting address of the function
    pub entry_addr: u64,
    /// Name of the function
    pub name: String,
    /// In-edges (callers)
    pub in_edges: Vec<CallGraphEdge>,
    /// Out-edges (callees)
    pub out_edges: Vec<CallGraphEdge>,
    /// Node flags
    pub flags: u32,
}

impl CallGraphNode {
    pub fn new(addr: u64, name: String) -> Self {
        Self { entry_addr: addr, name, in_edges: Vec::new(), out_edges: Vec::new(), flags: 0 }
    }

    pub fn num_in_edge(&self) -> usize { self.in_edges.len() }
    pub fn num_out_edge(&self) -> usize { self.out_edges.len() }
    pub fn is_mark(&self) -> bool { self.flags & node_flags::MARK != 0 }
    pub fn clear_mark(&mut self) { self.flags &= !node_flags::MARK; }
}

/// The call graph container.
/// Corresponds to Ghidra's `CallGraph` (callgraph.hh:96).
pub struct CallGraph {
    /// Nodes sorted by entry address
    pub nodes: BTreeMap<u64, CallGraphNode>,
    /// Seed nodes for cycle detection
    pub seeds: Vec<u64>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self { nodes: BTreeMap::new(), seeds: Vec::new() }
    }

    /// Add a node by address and name, returning the address.
    pub fn add_node(&mut self, addr: u64, name: String) -> u64 {
        self.nodes.entry(addr).or_insert_with(|| CallGraphNode::new(addr, name));
        addr
    }

    /// Find a node by address.
    pub fn find_node(&self, addr: u64) -> Option<&CallGraphNode> {
        self.nodes.get(&addr)
    }

    /// Find a mutable node by address.
    pub fn find_node_mut(&mut self, addr: u64) -> Option<&mut CallGraphNode> {
        self.nodes.get_mut(&addr)
    }

    /// Add an edge from one function to another.
    pub fn add_edge(&mut self, from: u64, to: u64, callsite: u64) {
        // Ensure both nodes exist.
        self.nodes.entry(from).or_insert_with(|| CallGraphNode::new(from, String::new()));
        self.nodes.entry(to).or_insert_with(|| CallGraphNode::new(to, String::new()));

        let edge = CallGraphEdge::new(from, to, callsite);
        if let Some(from_node) = self.nodes.get_mut(&from) {
            from_node.out_edges.push(edge.clone());
        }
        if let Some(to_node) = self.nodes.get_mut(&to) {
            to_node.in_edges.push(edge);
        }
    }

    /// Get the number of nodes.
    pub fn num_nodes(&self) -> usize { self.nodes.len() }

    /// Clear all marks on all nodes.
    pub fn clear_marks(&mut self) {
        for node in self.nodes.values_mut() {
            node.clear_mark();
        }
    }

    /// Initialize a leaf walk: find the first leaf (no out-Edges).
    pub fn init_leaf_walk(&self) -> Option<u64> {
        for (&addr, node) in &self.nodes {
            if node.out_edges.is_empty() {
                return Some(addr);
            }
        }
        None
    }

    /// Get the next leaf in a depth-first leaf walk from the given node.
    /// Corresponds to Ghidra's `CallGraph::nextLeaf`.
    /// Returns the next leaf address, or None if done.
    pub fn next_leaf(&self, _addr: u64) -> Option<u64> {
        // Simplified: just find the next unvisited leaf.
        for (&addr, node) in &self.nodes {
            if addr > _addr && node.out_edges.is_empty() {
                return Some(addr);
            }
        }
        None
    }

    /// Detect and snip cycles in the call graph using DFS.
    /// Corresponds to Ghidra's `CallGraph::snipCycles`.
    pub fn snip_cycles(&mut self) {
        // Collect all addresses for iteration.
        let addrs: Vec<u64> = self.nodes.keys().copied().collect();
        let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut in_stack: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for &start in &addrs {
            self.snip_cycles_dfs(start, &mut visited, &mut in_stack);
        }
    }

    fn snip_cycles_dfs(&mut self, addr: u64, visited: &mut std::collections::HashSet<u64>, in_stack: &mut std::collections::HashSet<u64>) {
        if visited.contains(&addr) { return; }
        visited.insert(addr);
        in_stack.insert(addr);

        // Collect out-edges (copy to avoid borrow issues).
        let out_addrs: Vec<u64> = self.nodes.get(&addr)
            .map(|n| n.out_edges.iter().map(|e| e.to_addr).collect())
            .unwrap_or_default();

        for to_addr in out_addrs {
            if in_stack.contains(&to_addr) {
                // Cycle detected: mark the edge as cycle.
                if let Some(from_node) = self.nodes.get_mut(&addr) {
                    for edge in &mut from_node.out_edges {
                        if edge.to_addr == to_addr {
                            edge.flags |= edge_flags::CYCLE;
                        }
                    }
                }
            } else if !visited.contains(&to_addr) {
                self.snip_cycles_dfs(to_addr, visited, in_stack);
            }
        }

        in_stack.remove(&addr);
    }

    /// Find all nodes that have no incoming edges (entry points).
    /// Corresponds to Ghidra's `CallGraph::findNoEntry`.
    pub fn find_no_entry(&self) -> Vec<u64> {
        self.nodes.iter()
            .filter(|(_, n)| n.in_edges.is_empty())
            .map(|(&addr, _)| addr)
            .collect()
    }

    /// Get all node addresses in sorted order.
    pub fn all_addrs(&self) -> Vec<u64> {
        self.nodes.keys().copied().collect()
    }

    /// Get all out-edges from a node.
    pub fn get_out_edges(&self, addr: u64) -> &[CallGraphEdge] {
        self.nodes.get(&addr).map(|n| n.out_edges.as_slice()).unwrap_or(&[])
    }

    /// Delete an in-edge from a node.
    pub fn delete_in_edge(&mut self, addr: u64, index: usize) {
        let from_addr = self.nodes.get(&addr).and_then(|n| n.in_edges.get(index)).map(|e| e.from_addr);
        if let Some(node) = self.nodes.get_mut(&addr) {
            if index < node.in_edges.len() {
                node.in_edges.remove(index);
            }
        }
        if let Some(fa) = from_addr {
            if let Some(from_node) = self.nodes.get_mut(&fa) {
                from_node.out_edges.retain(|e| e.to_addr != addr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callgraph_basic() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, "main".into());
        cg.add_node(0x2000, "helper".into());
        cg.add_edge(0x1000, 0x2000, 0x1050);

        assert_eq!(cg.num_nodes(), 2);
        let main = cg.find_node(0x1000).unwrap();
        assert_eq!(main.num_out_edge(), 1);
        assert_eq!(main.out_edges[0].to_addr, 0x2000);
        let helper = cg.find_node(0x2000).unwrap();
        assert_eq!(helper.num_in_edge(), 1);
    }

    #[test]
    fn test_leaf_walk() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, "a".into());
        cg.add_node(0x2000, "b".into());
        cg.add_edge(0x1000, 0x2000, 0x1050);
        let leaf = cg.init_leaf_walk().unwrap();
        assert_eq!(leaf, 0x2000);
    }

    #[test]
    fn test_edge() {
        let e = CallGraphEdge::new(0x1000, 0x2000, 0x1050);
        assert!(!e.is_cycle());
    }
}
