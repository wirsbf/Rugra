// HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS: Rugra comparand for the locked
// Ghidra 12.0.4 oracle. Mirrors tests/oracle/heritage_tryoutput_1204.cc
// case for case:
//  - stack_output_contains_full: the production
//    Heritage::try_output_stack_guard output-contains branch
//    (src/heritage.rs, heritage.cc:1406-1430) driven directly on a real
//    Funcdata with one CALL op over the six trigger geometries. The
//    projection prints every op of the call block in insertion order with
//    the SUBPIECE in[1] constants — cc:1420, the fourth justifiedContain
//    touchpoint (LE start distances 0/2/4; BE end distances pinned by
//    case=cc1420_constant) — the created-vs-reused call output (cc:1411-
//    1416), the caller-perspective translation of the return storage
//    (cc:1407-1410: 0x1000 storage + 0x10 diff -> 0x1010), the write-list
//    entries with the vnFinal active-heritage flag (cc:1426-1429), and the
//    cc:1430 return value (true even for the no-op geometry 5).
//  - cc1420_constant: the exact cc:1420 call shape
//    retAddr.justifiedContain(retSize, addr, size, false) through
//    rugra::fspec::justified_contain_range on the caller-perspective
//    return storage in both endian routings — LE rows take the stack
//    space's endianness exactly as src/heritage.rs does, BE rows pass true
//    (helper-level big-endian pinning; the transitional enum space cannot
//    stage a BE stack, the same convention as
//    heritage_subpiece_const_1204).
//
// The cc:1407/cc:1410 fc->getOutput() reads are staged through the
// locked_output_storage parameter (Some((storage_address, ret_size))) —
// the same (Address, size) the C++ oracle derives from its locked
// ProtoParameter. Production passes None until the FSPEC-OUTPUT-STORAGE-
// 0001 residual is fixed; the outputCharacter classification (occ=) is
// staged with the same cc:4346 math via justified_contain_range because
// Rugra's FuncProto keeps no proto-store output storage either.

use std::sync::Arc;

use rugra::address::Address;
use rugra::block::{BlockBasic, FlowBlock};
use rugra::fspec::containment;
use rugra::fspec::{justified_contain_range, FuncCallSpecs, FuncProto};
use rugra::funcdata::Funcdata;
use rugra::heritage::Heritage;
use rugra::opcodes::OpCode;
use rugra::space::AddressSpace;
use rugra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<rugra::varnode::Varnode>>;

fn void_type() -> Arc<Datatype> {
    Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )))
}

// Varnode descriptor shared with the C++ oracle (see its file header):
//   constant -> c<size>(<value>); iop -> IOP;
//   other    -> <hexoffset>:<size>:<I|W|F>{ah}
// Space letters are not printed (the transitional new_varnode_out register
// space divergence is a registered projected-away residual).
fn vn_descriptor(vn: Option<&VnRef>) -> String {
    let Some(vn) = vn else {
        return "-".to_string();
    };
    let value = vn.read().unwrap();
    if value.is_constant() {
        return format!("c{}({})", value.size, value.get_offset());
    }
    if value.get_space() == AddressSpace::Iop {
        return "IOP".to_string();
    }
    let state = if value.is_input() {
        'I'
    } else if value.is_written() {
        'W'
    } else {
        'F'
    };
    let flags = if value.is_active_heritage() { "ah" } else { "" };
    format!("{:x}:{}:{}{{{}}}", value.get_offset(), value.size, state, flags)
}

// The guarded range lives at caller stack 0x101x; the callee perspective is
// 0x100x (stackoffset 0x10, the guardCalls cc:1466-1468 rebase shape), and
// the locked return storage sits at callee 0x1000 with 8 bytes — the
// caller perspective return storage is [0x1010, 0x1018).
const STACK_DIFF: u64 = 0x10;
const RET_STORAGE: u64 = 0x1000;

#[derive(Clone, Copy)]
struct ToGeom {
    addr: u64,
    size: i32,
    retsz: i32,
    pre_out: bool,
}

// The same six trigger geometries as the C++ oracle, in the same order.
const TO: [ToGeom; 6] = [
    ToGeom { addr: 0x1010, size: 4, retsz: 8, pre_out: false },
    ToGeom { addr: 0x1012, size: 4, retsz: 8, pre_out: false },
    ToGeom { addr: 0x1014, size: 4, retsz: 8, pre_out: false },
    ToGeom { addr: 0x1010, size: 8, retsz: 8, pre_out: false },
    ToGeom { addr: 0x1010, size: 4, retsz: 8, pre_out: true },
    ToGeom { addr: 0x1010, size: 8, retsz: 8, pre_out: true },
];

// Drive the production try_output_stack_guard on one geometry and print
// the full op projection of the call block plus the write entries.
fn run_try_case(index: usize, g: ToGeom) {
    let base = 0x6000 + 0x10 * index as u64;
    let mut fd = Funcdata::new("to", Address::new(base), 0x20);
    let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
        0,
        Address::new(base),
    )));
    fd.bblocks.add_block(block.clone());
    let call = fd.new_op(1, Address::new(base));
    fd.op_set_opcode(&call, OpCode::CPUI_CALL);
    // FuncCallSpecs::new_for_op reads the direct-call target from in(0).
    let target = fd.new_constant(8, 0x4000);
    fd.op_set_input(&call, target, 0);
    fd.op_insert_end(&call, &block);
    if g.pre_out {
        fd.new_varnode_out(g.retsz as usize, Address::new(RET_STORAGE + STACK_DIFF), &call);
    }

    // The FuncCallSpecs must be registered in the Funcdata because the Rust
    // signature indexes the call list (the C++ oracle passes fc directly).
    // The prototype content is irrelevant to the contains branch: the two
    // getOutput() reads are staged through locked_output_storage below.
    let fc = FuncCallSpecs::new_for_op(&call, FuncProto::new(String::new(), void_type()));
    let fc_idx = fd.add_call_specs(fc);

    // Staged outputCharacter: the cc:4346 locked-branch classification of
    // the callee-perspective range against the locked return storage
    // (0 -> CONTAINS_JUSTIFIED, >0 -> CONTAINS_UNJUSTIFIED). Every geometry
    // of this fixture is contained, mirroring the guardCalls cc:1489 gate
    // that only calls tryOutputStackGuard for non-no_containment ranges.
    let trans = g.addr - STACK_DIFF;
    let off = justified_contain_range(RET_STORAGE, g.retsz, trans, g.size, false, false);
    let occ = if off == 0 {
        containment::CONTAINS_JUSTIFIED
    } else {
        containment::CONTAINS_UNJUSTIFIED
    };

    let mut write: Vec<VnRef> = Vec::new();
    let mut heritage = Heritage::new();
    let res = heritage.try_output_stack_guard(
        &mut fd,
        fc_idx,
        AddressSpace::Stack,
        Address::new(g.addr),
        trans,
        g.size,
        occ,
        &mut write,
        Some((Address::new(RET_STORAGE), g.retsz)),
    );

    println!(
        "to geom={index} addr={:x} size={} ret={:x} retsz={} diff={} retc={:x} occ={} res={}",
        g.addr, g.size, RET_STORAGE, g.retsz, STACK_DIFF, RET_STORAGE + STACK_DIFF, occ,
        u8::from(res)
    );
    let ops = block.read().unwrap().get_ops();
    for (pos, op) in ops.iter().enumerate() {
        let o = op.0.read().unwrap();
        let mut inputs = String::new();
        for slot in 0..o.num_input() {
            if slot != 0 {
                inputs.push(',');
            }
            inputs.push_str(&vn_descriptor(o.get_in(slot)));
        }
        // Opcode number, not name (mirrors the C++ oracle: CALL=7,
        // SUBPIECE=63 are identical on both sides).
        println!(
            "  op{pos} {} in=[{inputs}] out={}",
            o.opcode as i32,
            vn_descriptor(o.output.as_ref())
        );
    }
    for (i, entry) in write.iter().enumerate() {
        println!("  write{i} {}", vn_descriptor(Some(entry)));
    }
}

fn main() {
    println!("schema=1|fixture=HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // ---- case 1: production try_output_stack_guard, output-contains ----
    println!("case=stack_output_contains_full");
    for (index, g) in TO.iter().enumerate() {
        run_try_case(index, *g);
    }

    // ---- case 2: cc:1420 constants in LE and BE routings ----------------
    println!("case=cc1420_constant");
    for (index, g) in TO.iter().enumerate() {
        let retc = RET_STORAGE + STACK_DIFF;
        // The exact cc:1420 call shape: container = the caller-perspective
        // return storage, contained = the guarded range, forceleft=false.
        // LE rows take the stack space's endianness exactly as the fixed
        // src/heritage.rs does, BE rows pass true.
        let amt = |be: bool| justified_contain_range(retc, g.retsz, g.addr, g.size, false, be);
        println!(
            "  sp geom={index} le={} be={}",
            amt(AddressSpace::Stack.is_big_endian()),
            amt(true),
        );
    }
}
