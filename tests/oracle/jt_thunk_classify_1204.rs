//! JT-THUNK-CLASSIFY-1204 (JUMPTABLE-THUNK-CLASSIFY-0001) Rugra comparand.
//!
//! Mirrors `tests/oracle/jt_thunk_classify_1204.cc` case for case against the
//! locked Ghidra 12.0.4 oracle.  The fixture observes the strict single-target
//! thunk boundary, override/reachability ordering, exact typed error text, and
//! all address/load/partial mutations visible at the error boundary.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, RwLock};

use rugra::address::Address;
use rugra::block::FlowBlock;
use rugra::funcdata::Funcdata;
use rugra::jumptable::{JumpModel, JumpTable, JumpTableRecoveryError, LoadTable, RecoveryMode};
use rugra::op::PcodeOp;
use rugra::opcodes::OpCode;
use rugra::space::{AddrSpace, SpaceType};
use rugra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

#[derive(Default)]
struct ModelState {
    recover_calls: AtomicI32,
    build_calls: AtomicI32,
    sanity_calls: AtomicI32,
}

struct FixtureModel {
    override_mode: bool,
    sanity_result: bool,
    mutate_on_reject: bool,
    reject_load_address: Address,
    build_targets: Vec<Address>,
    build_loads: Vec<LoadTable>,
    state: Arc<ModelState>,
}

impl JumpModel for FixtureModel {
    fn is_override(&self) -> bool {
        self.override_mode
    }

    fn get_table_size(&self) -> usize {
        self.build_targets.len()
    }

    fn recover_model(
        &mut self,
        _fd: &Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        _matchsize: u32,
        _maxtablesize: u32,
    ) -> bool {
        self.state.recover_calls.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn build_addresses(
        &self,
        _fd: &Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        loadpoints: Option<&mut Vec<LoadTable>>,
        loadcounts: Option<&mut Vec<i32>>,
    ) {
        self.state.build_calls.fetch_add(1, Ordering::Relaxed);
        *addresstable = self.build_targets.clone();

        let count = if let Some(loadpoints) = loadpoints {
            loadpoints.extend(self.build_loads.iter().cloned());
            loadpoints.len() as i32
        } else {
            0
        };
        if let Some(loadcounts) = loadcounts {
            loadcounts.extend(std::iter::repeat_n(count, self.build_targets.len()));
        }
    }

    fn find_unnormalized(&mut self, _maxaddsub: u32, _maxleftright: u32, _maxext: u32) {}

    fn build_labels(
        &self,
        _fd: &Funcdata,
        _addresstable: &[Address],
        _label: &mut Vec<u64>,
        _orig: &dyn JumpModel,
    ) {
    }

    fn fold_in_normalization(
        &mut self,
        _fd: &mut Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
    ) -> Option<Arc<RwLock<Varnode>>> {
        None
    }

    fn fold_in_guards(&mut self, _fd: &mut Funcdata, _jump: &mut JumpTable) -> bool {
        false
    }

    fn sanity_check(
        &mut self,
        _fd: &Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        loadpoints: &mut Vec<LoadTable>,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> bool {
        self.state.sanity_calls.fetch_add(1, Ordering::Relaxed);
        if self.mutate_on_reject {
            if addresstable.len() > 1 {
                addresstable.truncate(1);
            }
            loadpoints.push(LoadTable::single(self.reject_load_address, 4));
            if let Some(loadcounts) = loadcounts {
                loadcounts.push(7);
            }
        }
        self.sanity_result
    }

    fn clone_model(&self, _jt: Arc<RwLock<JumpTable>>) -> Box<dyn JumpModel> {
        Box::new(Self {
            override_mode: self.override_mode,
            sanity_result: self.sanity_result,
            mutate_on_reject: self.mutate_on_reject,
            reject_load_address: self.reject_load_address,
            build_targets: self.build_targets.clone(),
            build_loads: self.build_loads.clone(),
            state: self.state.clone(),
        })
    }
}

struct CaseConfig {
    id: &'static str,
    target_offsets: Vec<u64>,
    unreachable: bool,
    override_mode: bool,
    sanity_result: bool,
    mutate_on_reject: bool,
    drive_recover: bool,
}

fn addresses_text(addresses: &[Address]) -> String {
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn loads_text(loads: &[LoadTable]) -> String {
    loads
        .iter()
        .map(|load| format!("{}/{}/{}", load.addr, load.size, load.num))
        .collect::<Vec<_>>()
        .join(",")
}

fn counts_text(counts: &[i32]) -> String {
    counts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn build_indirect(
    fd: &mut Funcdata,
    code: &AddrSpace,
    unreachable: bool,
    op_offset: u64,
) -> rugra::op::PcodeOpRef {
    let switch_block: BlockRef = fd.create_new_block();
    if unreachable {
        let guard: BlockRef = fd.create_new_block();
        let other: BlockRef = fd.create_new_block();
        let cbranch = fd.new_op(2, Address::with_space(code, op_offset - 8));
        fd.op_set_opcode(&cbranch, OpCode::CPUI_CBRANCH);
        let target = fd.new_constant(8, op_offset + 0x40);
        let condition = fd.new_constant(1, 0);
        fd.op_set_input(&cbranch, target, 0);
        fd.op_set_input(&cbranch, condition, 1);
        fd.op_insert_end(&cbranch, &guard);
        fd.bblocks.add_edge(guard.clone(), other);
        fd.bblocks.add_edge(guard, switch_block.clone());
    }

    let indirect = fd.new_op(1, Address::with_space(code, op_offset));
    fd.op_set_opcode(&indirect, OpCode::CPUI_BRANCHIND);
    let destination = fd.new_constant(8, op_offset + 0x20);
    fd.op_set_input(&indirect, destination, 0);
    fd.op_insert_end(&indirect, &switch_block);
    indirect
}

fn run_case(code: &AddrSpace, config: CaseConfig) {
    const OP_OFFSET: u64 = 0x100000;
    let mut fd = Funcdata::new(config.id, Address::with_space(code, 0x90000), 0x20000);
    let indirect = build_indirect(&mut fd, code, config.unreachable, OP_OFFSET);

    let targets = config
        .target_offsets
        .iter()
        .map(|offset| Address::with_space(code, *offset))
        .collect::<Vec<_>>();
    let initial_loads = vec![
        LoadTable::single(Address::with_space(code, 0x3004), 4),
        LoadTable::single(Address::with_space(code, 0x3000), 4),
    ];
    let mut loadcounts = vec![1, 2];

    let mut table = JumpTable::new(Address::with_space(code, OP_OFFSET));
    table.set_indirect_op(indirect.0.clone());
    let state = Arc::new(ModelState::default());
    table.jmodel = Some(Box::new(FixtureModel {
        override_mode: config.override_mode,
        sanity_result: config.sanity_result,
        mutate_on_reject: config.mutate_on_reject,
        reject_load_address: Address::with_space(code, 0x3008),
        build_targets: targets.clone(),
        build_loads: initial_loads.clone(),
        state: state.clone(),
    }));
    table.addresstable = if config.drive_recover {
        Vec::new()
    } else {
        targets
    };
    table.loadpoints = if config.drive_recover {
        Vec::new()
    } else {
        initial_loads
    };
    table.collect_loads = config.drive_recover;

    let result = if config.drive_recover {
        table.recover_addresses_classified(&fd)
    } else {
        table.sanity_check(&fd, Some(&mut loadcounts))
    };
    let (kind, mode, message) = match result {
        Ok(()) => ("success", RecoveryMode::Success, "none".to_string()),
        Err(error @ JumpTableRecoveryError::Thunk { .. }) => {
            ("thunk", error.recovery_mode(), error.message().to_string())
        }
        Err(error @ JumpTableRecoveryError::Lowlevel { .. }) => (
            "lowlevel",
            error.recovery_mode(),
            error.message().to_string(),
        ),
    };

    println!(
        "case|id={}|path={}|kind={}|mode={}|msg={}|partial={}|override={}|recover_calls={}|build_calls={}|sanity_calls={}|addresses={}|loads={}|loadcounts={}",
        config.id,
        if config.drive_recover { "recover" } else { "sanity" },
        kind,
        mode as i32,
        message,
        i32::from(table.partial_table),
        i32::from(table.is_override()),
        state.recover_calls.load(Ordering::Relaxed),
        state.build_calls.load(Ordering::Relaxed),
        state.sanity_calls.load(Ordering::Relaxed),
        addresses_text(&table.addresstable),
        loads_text(&table.loadpoints),
        counts_text(&loadcounts),
    );
}

fn main() {
    let code = AddrSpace::new_space(SpaceType::Processor, "ram", false, 8, 1, 3, 0, 0, 0);
    const OP: u64 = 0x100000;
    let cases = vec![
        CaseConfig {
            id: "zero",
            target_offsets: vec![0],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_on_reject: false,
            drive_recover: false,
        },
        CaseConfig {
            id: "near",
            target_offsets: vec![OP + 0x20],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_on_reject: false,
            drive_recover: false,
        },
        CaseConfig {
            id: "cutoff",
            target_offsets: vec![OP + 0xffff],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_on_reject: false,
            drive_recover: false,
        },
        CaseConfig {
            id: "over",
            target_offsets: vec![OP + 0x10000],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_on_reject: false,
            drive_recover: false,
        },
        CaseConfig {
            id: "multi",
            target_offsets: vec![0, OP + 0x20000],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_on_reject: false,
            drive_recover: false,
        },
        CaseConfig {
            id: "partial",
            target_offsets: vec![0],
            unreachable: true,
            override_mode: false,
            sanity_result: true,
            mutate_on_reject: false,
            drive_recover: false,
        },
        CaseConfig {
            id: "override",
            target_offsets: vec![0],
            unreachable: true,
            override_mode: true,
            sanity_result: true,
            mutate_on_reject: false,
            drive_recover: true,
        },
        CaseConfig {
            id: "model_reject",
            target_offsets: vec![OP + 0x10, OP + 0x20],
            unreachable: false,
            override_mode: false,
            sanity_result: false,
            mutate_on_reject: true,
            drive_recover: false,
        },
    ];

    for config in cases {
        run_case(&code, config);
    }
}
