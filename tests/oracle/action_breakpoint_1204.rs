//! ACTION-BREAKPOINT-RESUME-0001 Rust comparand: Action breakpoint and
//! resume over the real default action tree plus scripted probe trees.
//!
//! Mirrors the locked Ghidra 12.0.4 fixture observation line for line:
//! - name-path addressing (`get_sub_action`/`get_sub_rule`,
//!   action.cc:257/275/285/456/481/789) on the real `set_default_actions`
//!   tree, including ambiguous duplicates and rule paths (rule names are
//!   printed underscore-normalized: Rugra names rules in snake_case);
//! - `set_break_point`/`clear_break_points` return values and bit landings
//!   (action.cc:171-185/382/890);
//! - real-tree `break_start` stop/continue at the mainloop/stackstall heads
//!   driven through the resolved subtrees (probe2-validated flow);
//! - the scripted breakpoint matrix (leaf break_start with the
//!   count_tests-after-break-check ordering, tmpbreak one-shots, leaf
//!   break_action resume without reapply, group-level break_action stepping
//!   with `++state` resume, resume==single equality);
//! - a rule-level `break_action` inside a real `ActionPool` driven over two
//!   synthetic COPY ops, with behavioral per-rule test/application counts
//!   (the oracle's op_state/rule_index members are default-private and are
//!   observed through the same rule trace).

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::{Arc, RwLock};

use rugra::action::{
    break_flags, status_flags, Action, ActionDatabase, ActionGroup, ActionPool, ActionState, Rule,
};
use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::block::{BlockBasic, FlowBlock};
use rugra::funcdata::Funcdata;
use rugra::op::PcodeOp;
use rugra::opcodes::OpCode;

fn fixture_fd(name: &str, entry: u64) -> Funcdata {
    let mut fd = Funcdata::new(name, Address::new(entry), 0);
    let mut arch = Architecture::new();
    arch.archid = "fixture:LE:64:default".to_string();
    fd.set_arch(Arc::new(arch));
    fd
}

fn normalize_name(nm: &str) -> String {
    nm.chars().filter(|c| *c != '_').collect()
}

// ---------------------------------------------------------------------------
// Scripted probe classes (case C/D)
// ---------------------------------------------------------------------------

struct ScriptAction {
    name: String,
    script: Vec<i32>,
    cursor: usize,
    changes: Vec<i32>,
    apply_calls: u32,
    trace: Option<Rc<RefCell<Vec<String>>>>,
}

impl ScriptAction {
    fn new(
        name: &str,
        script: Vec<i32>,
        trace: Option<Rc<RefCell<Vec<String>>>>,
    ) -> Self {
        Self {
            name: name.to_string(),
            script,
            cursor: 0,
            changes: Vec::new(),
            apply_calls: 0,
            trace,
        }
    }
}

impl Action for ScriptAction {
    fn apply(&mut self, _fd: &mut Funcdata) -> rugra::Result<i32> {
        self.apply_calls += 1;
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push(self.name.clone());
        }
        let step = if self.cursor < self.script.len() {
            let value = self.script[self.cursor];
            self.cursor += 1;
            value
        } else {
            0
        };
        self.changes.push(step);
        Ok(0) // Ghidra ScriptedAction returns result; count is the member
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    // RUGRA-GLUE: externalizes the protected count increment (Ghidra's
    // ScriptedAction does `count += step.changes; return step.result;`).
    fn take_count_delta(&mut self) -> i32 {
        let delta: i32 = self.changes.drain(..).sum();
        delta
    }
}

/// Emit one perform() call observation in the fixture line format.
fn emit_leaf_call(tag: &str, ret: i32, state: &ActionState, apply_calls: u32) {
    println!(
        "{tag}|ret={ret}|status={}|count={}|lcount={}|tests={}|applies={}|breakpoint={}|apply_calls={apply_calls}",
        state.status, state.count, state.lcount, state.count_tests, state.count_apply,
        state.breakpoint
    );
}

fn emit_group_call(tag: &str, ret: i32, group: &ActionGroup, state: &ActionState, trace: &[String]) {
    println!(
        "{tag}|ret={ret}|status={}|count={}|state_index={}|trace={}",
        state.status,
        state.count,
        group.current_index(),
        trace.join(">")
    );
}

// ---------------------------------------------------------------------------
// Case D rule: applies (returns 1) exactly twice, records every attempt and
// application with the op address (behavioral op_state/rule_index view).
// ---------------------------------------------------------------------------

struct CountingRule {
    name: String,
    budget: Cell<i32>,
    tests: Cell<u32>,
    applies: Cell<u32>,
    applied_at: RefCell<Vec<u64>>,
}

impl CountingRule {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            budget: Cell::new(2),
            tests: Cell::new(0),
            applies: Cell::new(0),
            applied_at: RefCell::new(Vec::new()),
        }
    }

    fn report(&self) -> String {
        let addresses: Vec<String> = self
            .applied_at
            .borrow()
            .iter()
            .map(|offset| format!("0x{offset:x}"))
            .collect();
        addresses.join(">")
    }
}

impl Rule for CountingRule {
    fn apply_op(
        &self,
        op: &Arc<RwLock<PcodeOp>>,
        _fd: &mut Funcdata,
    ) -> rugra::Result<i32> {
        self.tests.set(self.tests.get() + 1);
        if self.budget.get() > 0 {
            self.budget.set(self.budget.get() - 1);
            self.applies.set(self.applies.get() + 1);
            let offset = op.read().unwrap().get_addr().as_u64();
            self.applied_at.borrow_mut().push(offset);
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_COPY]
    }
}

fn main() {
    println!("schema=1|fixture=ACTION-BREAKPOINT-RESUME-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    let mut allacts = ActionDatabase::new();
    allacts.set_default_actions();
    let root = allacts.get_action_mut("decompile").expect("decompile root");
    let mut root_state = ActionState::new(0);

    // --- Case A: addressing on the real tree -----------------------------
    let action_specs = [
        "universal",
        "universal:fullloop",
        "universal:fullloop:mainloop",
        "universal:fullloop:mainloop:stackstall",
        "universal:fullloop:mainloop:deadcode",
        "universal:fullloop:mainloop:unreachable",
        "universal:fullloop:deadcode",
        "universal:dynamicsymbols",
        "universal:nonexistent",
        "universal:cleanup",
    ];
    for spec in action_specs {
        match root.get_sub_action(spec) {
            Some(_) => {
                // Re-resolve through the tree walk to print the node name.
                let name = sub_action_name(root, spec).expect("resolved twice");
                println!("addr|spec={spec}|kind=action|name={name}");
            }
            None => println!("addr|spec={spec}|kind=action|match=NONE"),
        }
    }
    let rule_specs = [
        "universal:cleanup:mult_neg_one",
        "universal:fullloop:mainloop:stackstall:oppool1:early_removal",
        "universal:fullloop:mainloop",
    ];
    for spec in rule_specs {
        match root.get_sub_rule(spec) {
            Some((_, rule_index)) => {
                let (pool_name, rule_name) =
                    sub_rule_identity(root, spec, rule_index).expect("rule identity");
                println!(
                    "addr|spec={}|kind=rule|name={}|pool={pool_name}",
                    normalize_name(spec),
                    normalize_name(&rule_name)
                );
            }
            None => println!("addr|spec={}|kind=rule|match=NONE", normalize_name(spec)),
        }
    }
    println!(
        "addr|spec={}|kind=action|match={}",
        normalize_name("universal:cleanup:mult_neg_one"),
        match root.get_sub_action("universal:cleanup:mult_neg_one") {
            Some(_) => "SOME",
            None => "NONE",
        }
    );

    // set_break_point return values (action.cc:171-185).
    let root_group = root.as_action_group_mut().unwrap();
    println!(
        "setbp|spec=universal:fullloop:mainloop|tp=1|ok={}",
        u8::from(root_group.set_break_point(
            &mut root_state,
            break_flags::BREAK_START,
            "universal:fullloop:mainloop"
        ))
    );
    let root_group = root.as_action_group_mut().unwrap();
    println!(
        "setbp|spec=universal:fullloop:mainloop:unreachable|tp=1|ok={}",
        u8::from(root_group.set_break_point(
            &mut root_state,
            break_flags::BREAK_START,
            "universal:fullloop:mainloop:unreachable"
        ))
    );
    let root_group = root.as_action_group_mut().unwrap();
    println!(
        "setbp|spec=universal:cleanup:multnegone|tp=4|ok={}",
        u8::from(root_group.set_break_point(
            &mut root_state,
            break_flags::BREAK_ACTION,
            "universal:cleanup:mult_neg_one"
        ))
    );
    let root_group = root.as_action_group_mut().unwrap();
    println!(
        "setbp|spec=universal:cleanup:multnegone typo|tp=4|ok={}",
        u8::from(root_group.set_break_point(
            &mut root_state,
            break_flags::BREAK_ACTION,
            "universal:cleanup:mult_neg_one typo"
        ))
    );

    // Breakpoint bits land on the addressed nodes.
    {
        let mainloop_bits = {
            let group = root.as_action_group().unwrap();
            let path = root
                .get_sub_action("universal:fullloop:mainloop")
                .expect("mainloop path");
            let (&last, prefix) = path.split_last().unwrap();
            group
                .group_bits_view(prefix, last)
        };
        println!("bpbits|node=universal:fullloop:mainloop|bits={mainloop_bits}");
        let rule_bits = {
            let group = root.as_action_group().unwrap();
            let (path, rule_index) = root
                .get_sub_rule("universal:cleanup:mult_neg_one")
                .expect("rule path");
            group.rule_bits_view(&path, rule_index)
        };
        println!("bpbits|rule=universal:cleanup:multnegone|bits={rule_bits}");
        root.as_action_group_mut().unwrap().clear_break_points();
        let mainloop_bits = {
            let group = root.as_action_group().unwrap();
            let path = root
                .get_sub_action("universal:fullloop:mainloop")
                .expect("mainloop path");
            let (&last, prefix) = path.split_last().unwrap();
            group.group_bits_view(prefix, last)
        };
        println!("bpbits_clear|node=universal:fullloop:mainloop|bits={mainloop_bits}");
        let rule_bits = {
            let group = root.as_action_group().unwrap();
            let (path, rule_index) = root
                .get_sub_rule("universal:cleanup:mult_neg_one")
                .expect("rule path");
            group.rule_bits_view(&path, rule_index)
        };
        println!("bpbits_clear|rule=universal:cleanup:multnegone|bits={rule_bits}");
    }

    // --- Case B: real-tree break_start stop/continue ----------------------
    let mut fd = fixture_fd("fixture", 0x1000);

    let fullloop_path = root
        .get_sub_action("universal:fullloop")
        .expect("fullloop resolves");
    let fullloop_idx = fullloop_path[0];
    println!(
        "real|set_mainloop={}",
        u8::from(root.as_action_group_mut().unwrap().set_break_point(
            &mut root_state,
            break_flags::BREAK_START,
            "universal:fullloop:mainloop"
        ))
    );
    {
        let group = root.as_action_group_mut().unwrap();
        group.child_actions_mut()[fullloop_idx].reset(&mut fd);
    }
    {
        let group = root.as_action_group_mut().unwrap();
        let r1 = group.perform_child(fullloop_idx, &mut fd).expect("perform");
        let group_view = root.as_action_group().unwrap();
        let state = group_view.child_state(fullloop_idx).unwrap();
        let mut out = String::new();
        group_view.child_actions()[fullloop_idx].print_state(state, &mut out);
        let mainloop_status = {
            let path = root
                .get_sub_action("universal:fullloop:mainloop")
                .expect("mainloop");
            let (&last, prefix) = path.split_last().unwrap();
            let fullloop = group_view
                .child_actions()[prefix[0]]
                .as_action_group()
                .unwrap();
            fullloop.child_state(last).unwrap().status
        };
        println!("real|fullloop_perform1={r1}|state={out}|mainloop_status={mainloop_status}");
    }
    root.as_action_group_mut().unwrap().clear_break_points();

    let ss_path = root
        .get_sub_action("universal:fullloop:mainloop:stackstall")
        .expect("stackstall resolves");
    let mainloop_idx = ss_path[1];
    let ss_idx = ss_path[2];
    println!(
        "real|set_stackstall={}",
        u8::from(root.as_action_group_mut().unwrap().set_break_point(
            &mut root_state,
            break_flags::BREAK_START,
            "universal:fullloop:mainloop:stackstall"
        ))
    );
    {
        let group = root.as_action_group_mut().unwrap();
        let mainloop = group.child_actions_mut()[fullloop_idx]
            .as_action_group_mut()
            .unwrap()
            .child_actions_mut()[mainloop_idx]
            .as_action_group_mut()
            .unwrap();
        mainloop.child_actions_mut()[ss_idx].reset(&mut fd);
    }
    {
        let r1 = {
            let group = root.as_action_group_mut().unwrap();
            let mainloop = group.child_actions_mut()[fullloop_idx]
                .as_action_group_mut()
                .unwrap()
                .child_actions_mut()[mainloop_idx]
                .as_action_group_mut()
                .unwrap();
            mainloop.perform_child(ss_idx, &mut fd).expect("perform")
        };
        let out = {
            let group = root.as_action_group().unwrap();
            let mainloop = group.child_actions()[fullloop_idx]
                .as_action_group()
                .unwrap()
                .child_actions()[mainloop_idx]
                .as_action_group()
                .unwrap();
            let state = mainloop.child_state(ss_idx).unwrap();
            let mut buf = String::new();
            mainloop.child_actions()[ss_idx].print_state(state, &mut buf);
            buf
        };
        println!("real|ss_perform1={r1}|state1={out}");
    }
    {
        let r2 = {
            let group = root.as_action_group_mut().unwrap();
            let mainloop = group.child_actions_mut()[fullloop_idx]
                .as_action_group_mut()
                .unwrap()
                .child_actions_mut()[mainloop_idx]
                .as_action_group_mut()
                .unwrap();
            mainloop.perform_child(ss_idx, &mut fd).expect("perform")
        };
        let out = {
            let group = root.as_action_group().unwrap();
            let mainloop = group.child_actions()[fullloop_idx]
                .as_action_group()
                .unwrap()
                .child_actions()[mainloop_idx]
                .as_action_group()
                .unwrap();
            let state = mainloop.child_state(ss_idx).unwrap();
            let mut buf = String::new();
            mainloop.child_actions()[ss_idx].print_state(state, &mut buf);
            buf
        };
        println!("real|ss_perform2={r2}|state2={out}");
    }
    root.as_action_group_mut().unwrap().clear_break_points();
    {
        let group = root.as_action_group_mut().unwrap();
        let mainloop = group.child_actions_mut()[fullloop_idx]
            .as_action_group_mut()
            .unwrap()
            .child_actions_mut()[mainloop_idx]
            .as_action_group_mut()
            .unwrap();
        mainloop.child_actions_mut()[ss_idx].reset(&mut fd);
    }
    {
        let r3 = {
            let group = root.as_action_group_mut().unwrap();
            let mainloop = group.child_actions_mut()[fullloop_idx]
                .as_action_group_mut()
                .unwrap()
                .child_actions_mut()[mainloop_idx]
                .as_action_group_mut()
                .unwrap();
            mainloop.perform_child(ss_idx, &mut fd).expect("perform")
        };
        let out = {
            let group = root.as_action_group().unwrap();
            let mainloop = group.child_actions()[fullloop_idx]
                .as_action_group()
                .unwrap()
                .child_actions()[mainloop_idx]
                .as_action_group()
                .unwrap();
            let state = mainloop.child_state(ss_idx).unwrap();
            let mut buf = String::new();
            mainloop.child_actions()[ss_idx].print_state(state, &mut buf);
            buf
        };
        println!("real|ss_single={r3}|state3={out}");
    }

    // --- Case C: scripted breakpoint matrix -------------------------------
    {
        // c1: persistent break_start on a leaf.  Ghidra calls
        // a.setBreakPoint(break_start, "leaf1") on the leaf itself (self
        // match writes res->breakpoint, action.cc:174-176); the externalized
        // slot for a driven leaf is the fixture-held ActionState.
        let mut action = ScriptAction::new("leaf1", vec![3, 5], None);
        let mut state = ActionState::new(0);
        let mut fd = fixture_fd("c1", 0x4000);
        action.reset(&mut fd);
        state.breakpoint |= break_flags::BREAK_START;
        let mut r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c1_call1", r, &state, action.apply_calls);
        r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c1_call2", r, &state, action.apply_calls);
        r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c1_call3", r, &state, action.apply_calls);
        state.breakpoint = 0; // clearBreakPoints (action.cc:187)
        r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c1_call4", r, &state, action.apply_calls);
        r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c1_call5", r, &state, action.apply_calls);
    }
    {
        // c2: tmpbreak_start fires exactly once.
        let mut action = ScriptAction::new("leaf2", vec![2, 2], None);
        let mut state = ActionState::new(4); // rule_repeatapply
        let mut fd = fixture_fd("c2", 0x5000);
        action.reset(&mut fd);
        state.breakpoint |= break_flags::TMPBREAK_START;
        let mut r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c2_call1", r, &state, action.apply_calls);
        r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c2_call2", r, &state, action.apply_calls);
        r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c2_call3", r, &state, action.apply_calls);
    }
    {
        // c3: break_action fires after the change; resume from
        // status_actionbreak does not reapply.
        let mut action = ScriptAction::new("leaf3", vec![5], None);
        let mut state = ActionState::new(0);
        let mut fd = fixture_fd("c3", 0x6000);
        action.reset(&mut fd);
        state.breakpoint |= break_flags::BREAK_ACTION;
        let mut r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c3_call1", r, &state, action.apply_calls);
        r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c3_call2", r, &state, action.apply_calls);
        r = action.perform(&mut fd, &mut state).unwrap();
        emit_leaf_call("c3_call3", r, &state, action.apply_calls);
    }
    {
        // c4: group-level break_action stepping.
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut group = ActionGroup::with_flags("stepper", 0);
        group.add_action(Box::new(ScriptAction::new("c4_first", vec![1], Some(trace.clone()))));
        group.add_action(Box::new(ScriptAction::new("c4_mid", vec![2], Some(trace.clone()))));
        group.add_action(Box::new(ScriptAction::new("c4_last", vec![4], Some(trace.clone()))));
        let mut state = ActionState::new(0);
        let mut fd = fixture_fd("c4", 0x7000);
        group.reset(&mut fd);
        group
            .set_break_point(&mut state, break_flags::BREAK_ACTION, "stepper")
            .then_some(())
            .expect("group self set_break_point");
        for tag in ["c4_call1", "c4_call2", "c4_call3", "c4_call4", "c4_call5"] {
            let begin = trace.borrow().len();
            let r = group.perform(&mut fd, &mut state).unwrap();
            let slice: Vec<String> = trace.borrow()[begin..].to_vec();
            emit_group_call(tag, r, &group, &state, &slice);
        }
    }
    {
        // c5: tmpbreak_action on a group fires once.
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut group = ActionGroup::with_flags("tmpgroup", 0);
        group.add_action(Box::new(ScriptAction::new("c5_first", vec![1], Some(trace.clone()))));
        group.add_action(Box::new(ScriptAction::new("c5_last", vec![2], Some(trace.clone()))));
        let mut state = ActionState::new(0);
        let mut fd = fixture_fd("c5", 0x8000);
        group.reset(&mut fd);
        group
            .set_break_point(&mut state, break_flags::TMPBREAK_ACTION, "tmpgroup")
            .then_some(())
            .expect("group tmp set_break_point");
        for tag in ["c5_call1", "c5_call2"] {
            let begin = trace.borrow().len();
            let r = group.perform(&mut fd, &mut state).unwrap();
            let slice: Vec<String> = trace.borrow()[begin..].to_vec();
            emit_group_call(tag, r, &group, &state, &slice);
        }
    }
    {
        // c6: interrupted+resumed equals uninterrupted single run.
        let trace_single = Rc::new(RefCell::new(Vec::new()));
        let mut single = ActionGroup::with_flags("single", 0);
        single.add_action(Box::new(ScriptAction::new("s_first", vec![1], Some(trace_single.clone()))));
        single.add_action(Box::new(ScriptAction::new("s_mid", vec![2], Some(trace_single.clone()))));
        single.add_action(Box::new(ScriptAction::new("s_last", vec![4], Some(trace_single.clone()))));
        let mut single_state = ActionState::new(0);
        let mut fs = fixture_fd("c6s", 0x9000);
        single.reset(&mut fs);
        let rs = single.perform(&mut fs, &mut single_state).unwrap();
        let ts: Vec<String> = trace_single.borrow().clone();

        let trace_resume = Rc::new(RefCell::new(Vec::new()));
        let mut resumed = ActionGroup::with_flags("resumed", 0);
        resumed.add_action(Box::new(ScriptAction::new("s_first", vec![1], Some(trace_resume.clone()))));
        resumed.add_action(Box::new(ScriptAction::new("s_mid", vec![2], Some(trace_resume.clone()))));
        resumed.add_action(Box::new(ScriptAction::new("s_last", vec![4], Some(trace_resume.clone()))));
        let mut resumed_state = ActionState::new(0);
        let mut fr = fixture_fd("c6r", 0x9100);
        resumed.reset(&mut fr);
        resumed
            .set_break_point(&mut resumed_state, break_flags::TMPBREAK_ACTION, "resumed")
            .then_some(())
            .expect("resumed tmp set_break_point");
        let _rr1 = resumed.perform(&mut fr, &mut resumed_state).unwrap();
        let rr = resumed.perform(&mut fr, &mut resumed_state).unwrap();
        let tr: Vec<String> = trace_resume.borrow().clone();

        let equal = rs == rr
            && single_state.count == resumed_state.count
            && single_state.count_apply == resumed_state.count_apply
            && ts == tr;
        println!(
            "c6|single={rs}|resumed={rr}|single_count={}|resumed_count={}|single_applies={}|resumed_applies={}|trace={}|equal={}",
            single_state.count,
            resumed_state.count,
            single_state.count_apply,
            resumed_state.count_apply,
            if ts == tr { "same" } else { "diff" },
            u8::from(equal)
        );
    }

    // --- Case D: rule-level breakpoint inside a real ActionPool ----------
    {
        // Single uninterrupted run.
        let mut fs = fixture_fd("ds", 0xa000);
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0xa000))));
        fs.bblocks.add_block(block.clone());
        for slot in 0..2u64 {
            let op = fs.new_op(1, Address::new(0xa000 + slot * 2));
            fs.op_set_opcode(&op, OpCode::CPUI_COPY);
            fs.op_insert_end(&op, &block);
        }
        let mut single = ActionGroup::with_flags("proberoot", 0);
        let rule = Rc::new(CountingRule::new("counter"));
        let mut pool = ActionPool::new("countpool");
        pool.add_rule(Box::new(RuleAdapter(rule.clone())));
        single.add_action(Box::new(pool));
        let mut single_state = ActionState::new(0);
        single.reset(&mut fs);
        let rs = single.perform(&mut fs, &mut single_state).unwrap();
        let pool_state = single.child_state(0).unwrap();
        println!(
            "d_single|ret={rs}|group_count={}|pool_count={}|rule_tests={}|rule_applies={}|applied_at={}",
            single_state.count,
            pool_state.count,
            rule.tests.get(),
            rule.applies.get(),
            rule.report()
        );

        // Interrupted run.
        let mut fr = fixture_fd("dr", 0xb000);
        let block2: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0xb000))));
        fr.bblocks.add_block(block2.clone());
        for slot in 0..2u64 {
            let op = fr.new_op(1, Address::new(0xb000 + slot * 2));
            fr.op_set_opcode(&op, OpCode::CPUI_COPY);
            fr.op_insert_end(&op, &block2);
        }
        let mut resumed = ActionGroup::with_flags("proberoot", 0);
        let rule2 = Rc::new(CountingRule::new("counter"));
        let mut pool2 = ActionPool::new("countpool");
        pool2.add_rule(Box::new(RuleAdapter(rule2.clone())));
        resumed.add_action(Box::new(pool2));
        let mut resumed_state = ActionState::new(0);
        resumed.reset(&mut fr);
        resumed
            .set_break_point(&mut resumed_state, break_flags::BREAK_ACTION, "proberoot:countpool:counter")
            .then_some(())
            .expect("rule set_break_point");
        let r1 = resumed.perform(&mut fr, &mut resumed_state).unwrap();
        println!(
            "d_break1|ret={r1}|rule_tests={}|rule_applies={}|applied_at={}",
            rule2.tests.get(),
            rule2.applies.get(),
            rule2.report()
        );
        let r2 = resumed.perform(&mut fr, &mut resumed_state).unwrap();
        println!(
            "d_break2|ret={r2}|rule_tests={}|rule_applies={}|applied_at={}",
            rule2.tests.get(),
            rule2.applies.get(),
            rule2.report()
        );
        let r3 = resumed.perform(&mut fr, &mut resumed_state).unwrap();
        let pool2_state = resumed.child_state(0).unwrap();
        println!(
            "d_final|ret={r3}|group_count={}|pool_count={}|rule_tests={}|rule_applies={}|applied_at={}|resume_equals_single={}",
            resumed_state.count,
            pool2_state.count,
            rule2.tests.get(),
            rule2.applies.get(),
            rule2.report(),
            u8::from(
                resumed_state.count == single_state.count
                    && rule2.tests.get() == rule.tests.get()
                    && rule2.applies.get() == rule.applies.get()
            )
        );
    }
}

// ---------------------------------------------------------------------------
// Tree-walk helpers over the public views (the fixture cannot touch the
// container internals, mirroring the oracle's Action*/Rule* returns).
// ---------------------------------------------------------------------------

fn sub_action_name(root: &dyn Action, spec: &str) -> Option<String> {
    let path = root.get_sub_action(spec)?;
    if path.is_empty() {
        return Some(root.get_name().to_string());
    }
    let mut node = root
        .as_action_group()
        .expect("non-root path starts at a group") as &dyn Action;
    let mut iter = path.iter();
    while let Some(&index) = iter.next() {
        let group = node.as_action_group().expect("path traverses groups");
        if iter.len() == 0 {
            return Some(group.child_actions()[index].get_name().to_string());
        }
        node = group.child_actions()[index].as_ref();
    }
    None
}

fn sub_rule_identity(root: &dyn Action, spec: &str, rule_index: usize) -> Option<(String, String)> {
    let (path, _) = root.get_sub_rule(spec)?;
    let pool_name = spec.rsplit(':').nth(1)?.to_string();
    let mut node = root.as_action_group().expect("root group");
    for &index in &path[..path.len() - 1] {
        node = node.child_actions()[index]
            .as_action_group()
            .expect("rule path traverses groups");
    }
    let pool = node.child_actions()[path[path.len() - 1]]
        .as_action_pool()
        .expect("rule path ends at a pool");
    let rule_name = pool.rules()[rule_index].get_name().to_string();
    Some((pool_name, rule_name))
}

// RUGRA-GLUE: fixture-only view helpers reading the externalized breakpoint
// slots at an addressed node (Ghidra reads the protected member directly).
trait GroupBitsView {
    fn group_bits_view(&self, prefix: &[usize], last: usize) -> u32;
    fn rule_bits_view(&self, path: &[usize], rule_index: usize) -> u32;
}

impl GroupBitsView for ActionGroup {
    fn group_bits_view(&self, prefix: &[usize], last: usize) -> u32 {
        let mut node = self;
        for &index in prefix {
            node = node.child_actions()[index]
                .as_action_group()
                .expect("path traverses groups");
        }
        node.child_state(last).expect("child slot").breakpoint
    }

    fn rule_bits_view(&self, path: &[usize], rule_index: usize) -> u32 {
        let (&last, prefix) = path.split_last().expect("non-empty rule path");
        let mut node = self;
        for &index in prefix {
            node = node.child_actions()[index]
                .as_action_group()
                .expect("path traverses groups");
        }
        node.child_actions()[last]
            .as_action_pool()
            .expect("pool at path end")
            .rule_breakpoint(rule_index)
    }
}

// RUGRA-GLUE: Rc-shared rule adapter (Rugra's Rule is an owned Box<dyn Rule>;
// the fixture shares the counters through Rc).
struct RuleAdapter(Rc<CountingRule>);

impl Rule for RuleAdapter {
    fn apply_op(
        &self,
        op: &Arc<RwLock<PcodeOp>>,
        fd: &mut Funcdata,
    ) -> rugra::Result<i32> {
        self.0.apply_op(op, fd)
    }

    fn get_name(&self) -> &str {
        self.0.get_name()
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        self.0.get_opcodes()
    }
}
