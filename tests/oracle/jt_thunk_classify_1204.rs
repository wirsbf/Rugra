//! JT-THUNK-CLASSIFY-1204 (JUMPTABLE-THUNK-CLASSIFY-0001) Rugra comparand.
//!
//! Mirrors `tests/oracle/jt_thunk_classify_1204.cc` case for case against the
//! locked Ghidra 12.0.4 oracle.  The fixture observes the strict single-target
//! thunk boundary, override/reachability ordering, exact typed error text, and
//! all address/load/partial mutations visible at the error boundary.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::block::FlowBlock;
use rugra::comment::CommentDatabaseInternal;
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
    observed_loadcounts: Mutex<Vec<i32>>,
    events: Mutex<Vec<&'static str>>,
}

struct FixtureModel {
    override_mode: bool,
    transient_override: bool,
    sanity_result: bool,
    mutate_during_sanity: bool,
    reject_load_address: Address,
    build_targets: Vec<Address>,
    build_loads: Vec<LoadTable>,
    state: Arc<ModelState>,
}

impl JumpModel for FixtureModel {
    fn is_override(&self) -> bool {
        self.override_mode
            || (self.transient_override && self.state.recover_calls.load(Ordering::Relaxed) == 0)
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
        self.state.events.lock().unwrap().push("recover");
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
        self.state.events.lock().unwrap().push("build");
        *addresstable = self.build_targets.clone();

        let count = if let Some(loadpoints) = loadpoints {
            loadpoints.extend(self.build_loads.iter().cloned());
            loadpoints.len() as i32
        } else {
            0
        };
        if let Some(loadcounts) = loadcounts {
            loadcounts.extend(std::iter::repeat_n(count, self.build_targets.len()));
            *self.state.observed_loadcounts.lock().unwrap() = loadcounts.clone();
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
        self.state.events.lock().unwrap().push("sanity");
        if self.mutate_during_sanity {
            if addresstable.len() > 1 {
                addresstable.truncate(1);
            }
            loadpoints.push(LoadTable::single(self.reject_load_address, 4));
            if let Some(loadcounts) = loadcounts {
                loadcounts.push(7);
                *self.state.observed_loadcounts.lock().unwrap() = loadcounts.clone();
            }
        } else if let Some(loadcounts) = loadcounts {
            *self.state.observed_loadcounts.lock().unwrap() = loadcounts.clone();
        }
        self.sanity_result
    }

    fn clone_model(&self, _jt: Arc<RwLock<JumpTable>>) -> Box<dyn JumpModel> {
        Box::new(Self {
            override_mode: self.override_mode,
            transient_override: self.transient_override,
            sanity_result: self.sanity_result,
            mutate_during_sanity: self.mutate_during_sanity,
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
    mutate_during_sanity: bool,
    drive_recover: bool,
    equal_address_loads: bool,
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

fn events_text(events: &[&str]) -> String {
    events.join(">")
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

fn run_case(
    code: &AddrSpace,
    architecture: &Arc<Architecture>,
    commentdb: &Arc<RwLock<CommentDatabaseInternal>>,
    config: CaseConfig,
) {
    const OP_OFFSET: u64 = 0x100000;
    commentdb.write().unwrap().clear();
    let mut fd = Funcdata::new(config.id, Address::with_space(code, 0x90000), 0x20000);
    fd.set_arch(architecture.clone());
    let indirect = build_indirect(&mut fd, code, config.unreachable, OP_OFFSET);

    let targets = config
        .target_offsets
        .iter()
        .map(|offset| Address::with_space(code, *offset))
        .collect::<Vec<_>>();
    let initial_loads = if config.equal_address_loads {
        vec![
            LoadTable::new(Address::with_space(code, 0x4000), 8, 2),
            LoadTable::new(Address::with_space(code, 0x4000), 4, 3),
            LoadTable::new(Address::with_space(code, 0x4010), 8, 1),
        ]
    } else {
        vec![
            LoadTable::single(Address::with_space(code, 0x3004), 4),
            LoadTable::single(Address::with_space(code, 0x3000), 4),
        ]
    };
    let mut loadcounts = vec![1, 2];

    let mut table = JumpTable::new(Address::with_space(code, OP_OFFSET));
    table.set_indirect_op(indirect.0.clone());
    let state = Arc::new(ModelState::default());
    table.jmodel = Some(Box::new(FixtureModel {
        override_mode: config.override_mode,
        transient_override: config.drive_recover && !config.override_mode,
        sanity_result: config.sanity_result,
        mutate_during_sanity: config.mutate_during_sanity,
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
    if config.drive_recover && result.is_ok() {
        state.events.lock().unwrap().push("collapse");
    }
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

    let observed_counts = if config.drive_recover {
        state.observed_loadcounts.lock().unwrap().clone()
    } else {
        loadcounts
    };
    let events = state.events.lock().unwrap().clone();
    let warning = {
        let database = commentdb.read().unwrap();
        let records = database
            .comments_for_function(*fd.get_address())
            .map(|comment| {
                format!(
                    "{}@{}:{}",
                    comment.get_type(),
                    comment.get_addr(),
                    comment.get_text()
                )
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            "none".to_string()
        } else {
            records.join(",")
        }
    };

    println!(
        "case|id={}|path={}|kind={}|mode={}|msg={}|partial={}|override={}|recover_calls={}|build_calls={}|sanity_calls={}|events={}|addresses={}|loads={}|loadcounts={}|warning={}",
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
        events_text(&events),
        addresses_text(&table.addresstable),
        loads_text(&table.loadpoints),
        counts_text(&observed_counts),
        warning,
    );
}

fn main() {
    let code = AddrSpace::new_space(SpaceType::Processor, "ram", false, 8, 1, 3, 0, 0, 0);
    let commentdb = Arc::new(RwLock::new(CommentDatabaseInternal::new()));
    let mut architecture = Architecture::new();
    architecture.commentdb = Some(commentdb.clone());
    let architecture = Arc::new(architecture);
    const OP: u64 = 0x100000;
    let cases = vec![
        CaseConfig {
            id: "zero",
            target_offsets: vec![0],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_during_sanity: false,
            drive_recover: false,
            equal_address_loads: false,
        },
        CaseConfig {
            id: "near",
            target_offsets: vec![OP + 0x20],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_during_sanity: false,
            drive_recover: false,
            equal_address_loads: false,
        },
        CaseConfig {
            id: "cutoff",
            target_offsets: vec![OP + 0xffff],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_during_sanity: false,
            drive_recover: false,
            equal_address_loads: false,
        },
        CaseConfig {
            id: "over",
            target_offsets: vec![OP + 0x10000],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_during_sanity: false,
            drive_recover: false,
            equal_address_loads: false,
        },
        CaseConfig {
            id: "multi",
            target_offsets: vec![0, OP + 0x20000],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_during_sanity: false,
            drive_recover: false,
            equal_address_loads: false,
        },
        CaseConfig {
            id: "partial",
            target_offsets: vec![0],
            unreachable: true,
            override_mode: false,
            sanity_result: true,
            mutate_during_sanity: false,
            drive_recover: false,
            equal_address_loads: false,
        },
        CaseConfig {
            id: "override",
            target_offsets: vec![0],
            unreachable: true,
            override_mode: true,
            sanity_result: true,
            mutate_during_sanity: false,
            drive_recover: true,
            equal_address_loads: false,
        },
        CaseConfig {
            id: "success_truncate",
            target_offsets: vec![OP + 0x10, OP + 0x20],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_during_sanity: true,
            drive_recover: true,
            equal_address_loads: false,
        },
        CaseConfig {
            id: "model_reject",
            target_offsets: vec![OP + 0x10, OP + 0x20],
            unreachable: false,
            override_mode: false,
            sanity_result: false,
            mutate_during_sanity: true,
            drive_recover: true,
            equal_address_loads: false,
        },
        CaseConfig {
            id: "sort_equal_addr",
            target_offsets: vec![OP + 0x10, OP + 0x20],
            unreachable: false,
            override_mode: false,
            sanity_result: true,
            mutate_during_sanity: false,
            drive_recover: true,
            equal_address_loads: true,
        },
    ];

    for config in cases {
        run_case(&code, &architecture, &commentdb, config);
    }
}
