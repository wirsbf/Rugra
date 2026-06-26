# override_rs.rs — Override commands API

Faithful port of Ghidra's `override.hh` / `override.cc` (435 lines).

**Status:** L1 → L2. Complete in-memory implementation; XML encode/decode is an
L3 gap pending the Encoder/Decoder infrastructure.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/override.{hh,cc}`.

## Enums

### `FlowOverride`
Flow-override type enumeration. Faithful to the `Override` enum
(override.hh:53).
- `None = 0`, `Branch = 1`, `Call = 2`, `CallReturn = 3`, `Return = 4`.
- `to_string(self) -> &'static str` — name (override.cc:405).
- `from_string(&str) -> Self` — parse (override.cc:421).

## Structs

### `Override`
A container of commands that override the decompiler's default behavior for a
single function. Faithful to `Override` (override.hh:50).

| Method | Description |
|---|---|
| `new()` | Empty override set. |
| `clear()` | Clear all overrides (override.cc:29). |
| `insert_force_goto(target, dest)` | Force-goto override (override.cc:66). |
| `insert_deadcode_delay(space_index, delay)` | Dead-code delay (override.cc:79). |
| `has_deadcode_delay(space_index, current_delay) -> bool` | Check (override.cc:92). |
| `insert_indirect_override(callpoint, directcall)` | Indirect→direct (override.cc:109). |
| `insert_proto_override(callpoint)` | Prototype override marker (override.cc:121). |
| `insert_multistage_jump(addr)` | Multistage flag (override.cc:137). |
| `insert_flow_override(addr, type)` | Flow override (override.cc:148). |
| `query_force_goto(target) -> Option<Address>` | Look up forced goto. |
| `force_gotos() -> impl Iterator` | All force-gotos. |
| `apply_indirect(callpoint) -> Option<Address>` | Indirect override (override.cc:177). |
| `apply_prototype(callpoint) -> bool` | Proto override (override.cc:160). |
| `query_multistage_jumptable(addr) -> bool` | Multistage check (override.cc:191). |
| `get_deadcode_delay(space_index) -> i32` | Delay or -1 (override.cc:217). |
| `deadcode_delays() -> impl Iterator` | (space_index, delay) pairs. |
| `has_flow_override() -> bool` | Any flow overrides (override.hh:84). |
| `get_flow_override(addr) -> FlowOverride` | Flow type (override.cc:233). |
| `flow_overrides() -> impl Iterator` | All flow overrides. |
| `is_empty() -> bool` | Any overrides at all. |
| `generate_deadcode_delay_message(space_name) -> String` | (override.cc:51). |
| `generate_override_messages(space_names) -> Vec<String>` | (override.cc:279). |
| `print_raw(space_names) -> Vec<String>` | Debug dump (override.cc:248). |

## L3 gaps
- XML `encode`/`decode` of the `<override>` element (override.cc:294, 356) —
  pending Encoder/Decoder infrastructure.
- FuncProto ownership in `insertProtoOverride` — pending fspec integration.
