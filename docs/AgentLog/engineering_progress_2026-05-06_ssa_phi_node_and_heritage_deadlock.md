# Engineering Progress Log: SSA Phi Node Validation & Heritage Deadlock Resolution

## Objective
The primary goal of this session was to advance the SSA verification pipeline by testing the generation of `MULTIEQUAL` (Phi) nodes during the `heritage` pass and resolving a known deadlock issue within `Funcdata`.

## Actions Taken
1. **Heritage Deadlock Resolution**:
   - The underlying issue was that `Heritage::heritage()` attempts to acquire a write lock on `Funcdata` through a weak pointer. If the caller (e.g., test or analysis pipeline) already held the lock, a deadlock occurred.
   - We resolved this architecturally by introducing the `Funcdata::run_heritage_direct(&mut self)` API. This method temporarily extracts `vbank` and `obank` from `Funcdata`, invokes the underlying direct algorithms (`place_multiequals_direct` and `rename_direct`), and safely bypasses the deadlock.

2. **SSA Dual-Block Phi Test (`test_ssa_dual_block_phi_alignment`)**:
   - Designed a specific assembly sequence with conditional branches to artificially create a multi-block control-flow merge:
     ```assembly
     cmp rdi, 0
     je +9          # jumps to block 2
     mov rax, 1     # block 1
     jmp +9         # merges to block 3
     mov rax, 2     # block 2
     jmp +0         # merges to block 3
     add rax, rsi   # block 3 (merge block)
     ret
     ```
   - Used this sequence to trigger the generation of a `MULTIEQUAL` (Phi) node for the `rax` register at the merge block (Block 3).
   - Validated that exactly one Phi node was generated, that it had 2 inputs, and that its output resided in `AddressSpace::Register` at offset `0x00`.

3. **Heritage AddressSpace Collision Bug Fix**:
   - During testing, we discovered a significant flaw in `Heritage::place_multiequals_direct`: definitions were being grouped solely by their `Address` (which in Rugra is just a `u64` offset) without distinguishing the `AddressSpace`.
   - Consequently, a `Ram` offset of `0x00` and a `Register` offset of `0x00` would collide, and `vbank.create(size, addr)` defaulted to creating Phi nodes in the `Ram` space.
   - We addressed this by modifying the data structure to group definitions by a composite key `(AddressSpace, Address)` and required `AddressSpace` to derive `Ord` and `PartialOrd`. We also updated `insert_multiequal_direct` to use `vbank.create_with_space()` to ensure accurate space assignments for generated Phi nodes.

## Next Steps
- Implement SSA renaming verification (checking that the variables are correctly renamed across the graph).
- Incorporate Ghidra-side automated exporting to feed real Ghidra snapshot datasets into `BatchSemanticCompareReport` for these SSA Phi cases.

## Review Status
- **Confidence**: High. The tests compile and pass smoothly, validating both the deadlock fix and the Phi generation logic.
- **Evidence Sources**: `src/funcdata.rs` (new test), `src/heritage.rs` (bug fixes), `src/space.rs` (derive trait additions).
