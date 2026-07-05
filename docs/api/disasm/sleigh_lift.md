# sleigh_lift.rs — SLEIGH-based P-code lifter

Uses jingle_sleigh to decode x86-64 instructions into P-code via Ghidra's
SLEIGH engine. Loads compiled .sla spec files from sleigh_specs/.

## Status
Experimental — produces correct P-code for basic instructions. Not yet
wired into the main pipeline (x86_lift.rs is still the default lifter).

## Components
- `SleighLifter` — main lifter struct
- `lift(addr, code)` — decode one instruction → Vec<PcodeOpRaw>
- `map_space` — jingle_sleigh SpaceType → Rugra AddressSpace
- `map_vn` — jingle_sleigh VarNode → Rugra VarnodeRaw
- `opc_from` — jingle_sleigh OpCode → Rugra OpCode (by variant name)

<!-- lift-instr: 1783181251.8037653 -->

<!-- sleigh-fix: 1783218732.6945384 -->
