# `block.rs` API Reference

**源代码路径**: `src/block.rs`

## 模块说明 (Module Doc)

Basic blocks and control flow graph

Corresponds to Ghidra's `block.hh`

## 导出的公共 API (Public API)

### `pub enum BlockType`

Type of flow block (corresponds to Ghidra's BlockType)

### `pub const TERMINAL: u32 = 1 << 0`

*暂无代码注释*

### `pub const GOTO_TERMINAL: u32 = 1 << 1`

*暂无代码注释*

### `pub const RETURN_TERMINAL: u32 = 1 << 2`

*暂无代码注释*

### `pub const ENTRY_POINT: u32 = 1 << 3`

*暂无代码注释*

### `pub const DEAD: u32 = 1 << 4`

*暂无代码注释*

### `pub const MARK: u32 = 1 << 5`

*暂无代码注释*

### `pub trait FlowBlock: std::fmt::Debug + Send + Sync`

Common interface for all types of blocks (Basic, Graph, Condition, etc.)

Corresponds to Ghidra's `FlowBlock` base class

### `pub struct BlockBasic`

Represents a basic block of P-code operations

Corresponds to Ghidra's `BlockBasic` class

### `pub fn new(index: i32, start_addr: Address) -> Self`

*暂无代码注释*

### `pub fn add_op(&mut self, op: PcodeOpRef)`

Add an operation to the end of the block

### `pub fn last_op(&self) -> Option<PcodeOpRef>`

Get the last operation in the block

### `pub fn first_op(&self) -> Option<PcodeOpRef>`

Get the first operation in the block

### `pub struct BlockEdge`

Represents an edge between blocks in the control flow graph

Corresponds to Ghidra's `BlockEdge` class

### `pub fn new(point: Arc<RwLock<dyn FlowBlock + Send + Sync>>, reverse_index: i32) -> Self`

*暂无代码注释*

### `pub struct BlockRef(pub Arc<RwLock<dyn FlowBlock + Send + Sync>>)`

A reference to a block for use in collections

### `pub struct BlockGraph`

A graph of blocks, which is itself a block

Corresponds to Ghidra's `BlockGraph` class

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn add_block(&mut self, bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>)`

*暂无代码注释*

### `pub fn get_size(&self) -> usize`

*暂无代码注释*

### `pub fn get_block(&self, i: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>`

*暂无代码注释*

### `pub fn clear(&mut self)`

*暂无代码注释*

### `pub fn add_edge(`

*暂无代码注释*

### `pub fn build_dom_tree(&mut self)`

Build the dominator tree for the graph

Corresponds to Ghidra's `BlockGraph::buildDomTree`

### `pub fn build_dom_depth(&mut self)`

Build depth information based on the dominator tree

Corresponds to Ghidra's `BlockGraph::buildDomDepth`

### `pub fn build_dom_subtree(&mut self)`

Build the dominator sub-tree relationships

Corresponds to Ghidra's `BlockGraph::buildDomSubTree`

### `pub fn calc_dom_frontier(&mut self)`

Calculate dominance frontiers for all blocks

Corresponds to the algorithm in "A Simple, Fast Dominator Algorithm"

### `pub fn calc_rpo(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>`

Calculate Reverse Post-Order (RPO) of blocks

### `pub fn structure_loops(&mut self) -> bool`

Structure a loop

Corresponds to Ghidra's `BlockGraph::structureLoops`

### `pub fn add_loop_edge(`

Add a loop edge

Corresponds to Ghidra's `BlockGraph::addLoopEdge`

### `pub fn calc_loop(&mut self)`

Calculate loops in the graph

Corresponds to Ghidra's `BlockGraph::calcLoop`

### `pub struct BlockCopy`

Represents a copy of another block

Corresponds to Ghidra's `BlockCopy` class

### `pub struct BlockGoto`

Represents a goto statement

Corresponds to Ghidra's `BlockGoto` class

