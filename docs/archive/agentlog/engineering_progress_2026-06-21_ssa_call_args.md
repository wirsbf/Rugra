# Engineering Progress: SSA-Based CALL Argument Tracking

**Date**: 2026-06-21 (continuation)
**Session Focus**: Replace ad-hoc arg tracking hacks with proper SSA-based architecture mirroring Ghidra's approach.
**Result**: 176/176 tests pass; `no_arg_calls` 15 → 1 real miss (2 are genuinely void). All via architecturally correct SSA-based tracking — no placeholder varnodes or unsafe cross-branch searches.

## Architectural Change

### Problem

CALL ops in Rugra's P-code only had the call target as input — arg registers (RDI, RSI, etc.) were implicit. This caused a cascade of problems:
- Heritage didn't create INPUT varnodes for arg registers (CALL didn't read them explicitly)
- ActionCallParams resorted to linear backwards search through alivelist
- The search stopped at CBRANCH/BRANCH boundaries, missing cross-block args
- Placeholder varnodes were created as a hack to produce correct-looking output without modeling data flow

### Root Cause

In `src/disasm/x86_lift.rs:538`, the lifter created CALL ops with only the target address:
```rust
let mut op = PcodeOpRaw::new(OpCode::CPUI_CALL as i32);
op.add_input(VarnodeRaw::new(AddressSpace::Ram, target_addr, 8));
```

In Ghidra, the lifter emits ALL potential arg registers as explicit CALL inputs. Heritage then naturally creates INPUT varnodes for unwritten registers, and the SSA graph tracks arg flow correctly.

### Fix

**1. Lifter change (`src/disasm/x86_lift.rs`):** Add the 6 SysV AMD64 arg registers (RDI, RSI, RDX, RCX, R8, R9) as explicit inputs to every CALL op. This mirrors Ghidra's P-code generation.

**2. ActionCallParams update (`src/coreaction.rs`):** Handle two CALL styles:
- **New-style** (`num_input > 1`): the lifter provided arg registers. Heritage processed them into proper SSA varnodes. Just trim to the callee's known param count — no backwards search needed.
- **Old-style** (`num_input == 1`): no lifter-provided args. Fall back to backwards search for backward compatibility.

**3. Void function trimming:** For `max_args == 0` (void functions), trim ALL arg register inputs from the CALL. Previously these were skipped, leaving 6 spurious args in the output.

**4. Reverted hacks:**
- Removed placeholder varnode creation (Fallback D from previous session). This was the "short-term faking" warned against — it produced `free(param_1)` without modeling actual data flow.
- Kept CBRANCH crossing in backwards search (for old-style CALLs) but it's now rarely needed since most CALLs use the new-style path.

## How It Works (Data Flow)

```
x86 instruction: call free
       ↓
Lifter: CALL(Ram:free_addr, Reg:RDI, Reg:RSI, Reg:RDX, Reg:RCX, Reg:R8, Reg:R9)
       ↓
inject_raw_ops: materializes Varnodes, adds to VarnodeBank
       ↓
Heritage: processes CALL's inrefs
  - RDI read before written → creates INPUT varnode for RDI
  - RSI read before written → creates INPUT varnode for RSI
  - etc.
       ↓
CopyPropagate: replaces arg register refs with actual values where possible
  - e.g., if t1 = COPY(param) before CALL, CALL's RDI ref → param
       ↓
ActionCallParams: sees CALL has 7 inputs (new-style)
  - known_param_count("free") = 1
  - trims to 1 + 1 = 2 inputs (target + 1 arg)
  - removes excess: RSI, RDX, RCX, R8, R9
       ↓
PrintC: emits free(arg1) where arg1 is the SSA-correct value
```

## Curl Metrics

| Metric | Before (placeholder hack) | After (SSA-based) |
|--------|---------------------------|-------------------|
| no_arg_calls | 4 (1 real miss) | 3 (1 real miss) |
| uVar | 126 | 133 (+7) |
| lVar | 212 | 196 (-16) |
| goto | 5 | 5 |
| empty_switch | 0 | 0 |

### Interpretation

- `no_arg_calls` stayed at 1 real miss. The SSA-based approach finds the same args as the placeholder hack, but architecturally correctly.
- `uVar` increased (+7) because the lifter now creates 6 arg register varnodes per CALL. These enter the SSA graph and some get uVar names. This is correct overhead — Ghidra also tracks all potential arg registers.
- `lVar` decreased (-16) because the SSA-based approach resolves more args to actual values (via CopyPropagate) rather than register-offset names. Net total variable references decreased: 126+212=338 → 133+196=329 (-9).

## Verification

- `cargo test`: 176/176 pass (0 regressions)
- `cargo build --release`: exit 0
- `lsp_diagnostics` on `coreaction.rs`, `x86_lift.rs`: zero errors
- `cargo run --release --example curl_decompile`: correct arg emission for `free(uVar_18)`, `puts("...")`, `strtol(local_588, 0, 0xa)`, `SetHTTPrequest_part_0(local_588, "r", ...)`. Void functions (`curl_version()`, `_init()`) correctly have 0 args.

## Long-Term Design Notes

This change establishes the foundation for proper parameter handling:
1. **The lifter is the single source of truth for CALL arg registers.** Future calling convention support (Windows x64, ARM AAPCS) just changes which registers the lifter emits.
2. **Heritage naturally handles INPUT varnode creation.** No special-casing needed in heritage for CALL args.
3. **ActionCallParams becomes a simple trimmer.** It no longer searches for arg register writes — it trusts the SSA graph and just trims to the callee's prototype.
4. **CopyPropagate naturally improves arg quality.** When a COPY feeds an arg register, CopyPropagate replaces the register ref with the actual value, producing cleaner output.

### What would make this even better (future work):
- **Callee prototype analysis:** Currently uses a hardcoded `known_param_count` table. A proper prototype analysis (like Ghidra's `ActionActiveParam` / `ParamActive`) would auto-detect param counts from the callee's SSA.
- **Arg type inference:** The arg register varnodes carry types from the caller's type propagation. Matching them to the callee's param types would enable better type checking.
- **Variadic function support:** Functions like `printf` take variable args. The current approach trims to a fixed count; variadic support would keep all provided args.

## Files Modified

- `src/disasm/x86_lift.rs` — CALL ops now include 6 SysV arg register inputs (+7 lines)
- `src/coreaction.rs` — ActionCallParams handles new-style CALLs (trim, not search); removed placeholder hack; void function trimming (-30 +40 lines, net +10)
