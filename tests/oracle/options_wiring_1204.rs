//! OPTIONS-SPLITDATATYPE-WIRING-0002 Rust comparand.
//!
//! Drives the production `ActionDatabase::toggle_action` /
//! `add_to_group` / `remove_from_group` through the exact forwarding
//! sequence `OptionSplitDatatypes::apply` performs (options.cc:1007-1016),
//! with the configuration bits produced by the production option apply
//! (`rugra::options::OptionSplitDatatypes`) and the production toggle
//! pair (`rugra::options::split_action_toggles`). No hand-written expected
//! output is embedded.

use rugra::action::{Action, ActionDatabase, ActionGroup, ActionGroupList, ActionRestartGroup};
use rugra::arch::Architecture;
use rugra::options::ArchOption;

// The inherited flags word carries this leaf's construction ordinal (a
// monotonically increasing counter) solely as an allocator-independent
// identity channel: every clone is freshly constructed, so the ordinal
// changes exactly when the owning root was re-derived/replaced.
static NEXT_SCRIPT_ORDINAL: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(100);

struct ScriptAction {
    group: &'static str,
    name: &'static str,
    ordinal: u32,
}

impl ScriptAction {
    fn new(group: &'static str, name: &'static str) -> Self {
        Self {
            group,
            name,
            ordinal: NEXT_SCRIPT_ORDINAL
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        }
    }
}

impl Action for ScriptAction {
    fn apply(&mut self, _fd: &mut rugra::funcdata::Funcdata) -> rugra::Result<i32> {
        Ok(0)
    }
    fn get_name(&self) -> &str {
        self.name
    }
    fn get_flags(&self) -> u32 {
        self.ordinal
    }
    fn clone_for_groups(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        if !grouplist.contains(self.group) {
            return None;
        }
        Some(Box::new(Self::new(self.group, self.name)))
    }
}

fn render_group_children(group: &ActionGroup) -> String {
    group
        .child_actions()
        .iter()
        .enumerate()
        .map(|(index, child)| match child.as_action_group() {
            Some(sub) => format!("{}[{}]", sub.get_name_str(), render_group_children(sub)),
            None => format!("{}@{}", child.get_name(), group.child_group(index)),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn emit_state(arch: &Architecture, tag: &str) {
    let db = arch.allacts.as_ref().expect("allacts populated").read().expect("allacts read lock");
    let members = db
        .get_group("decompile")
        .expect("decompile grouplist exists")
        .member_names()
        .join(",");
    let tree = render_group_children(db.get_current().as_action_group().expect("current root is a group"));
    println!(
        "state={tag} config={} current={} mapsize={} members={members} tree={tree}",
        arch.split_datatype_config,
        db.get_current_name(),
        db.actionmap_size(),
    );
}

fn apply_case(arch: &mut Architecture, p1: &str, p2: &str, p3: &str) -> (bool, String) {
    // Production option apply (options.cc:1002-1005, 1017-1019): the
    // configuration bits, partial-assignment error ordering, and the return
    // string.
    let result = rugra::options::OptionSplitDatatypes.apply(arch, p1, p2, p3);
    let threw_message = result.strip_prefix("LowlevelError: ").map(str::to_string);
    match threw_message {
        Some(message) => (true, message),
        None => {
            // Production forwarding (options.cc:1007-1016): the wiring target
            // of OPTIONS-SPLITDATATYPE-WIRING-0002 — once options.rs owns its
            // allacts forwarding block, this fixture sequence is exactly what
            // the production apply performs internally.
            let (splitcopy_on, splitpointer_on) =
                rugra::options::split_action_toggles(arch.split_datatype_config);
            let mut db = arch
                .allacts
                .as_ref()
                .expect("allacts populated")
                .write()
                .expect("allacts write lock");
            let current = db.get_current_name().to_string();
            db.toggle_action(&current, "splitcopy", splitcopy_on);
            db.toggle_action(&current, "splitpointer", splitpointer_on);
            (false, result)
        }
    }
}

fn first_leaf_ordinal(action: Option<&dyn Action>) -> u32 {
    action
        .and_then(Action::as_action_group)
        .and_then(|group| group.child_actions().first())
        .map(|leaf| leaf.get_flags())
        .expect("root is a non-empty ActionGroup")
}

fn main() {
    let mut arch = Architecture::new();

    // Synthetic universal root: head leaves + nested body group holding the
    // split-relevant leaves at their registration slots (mirrors the oracle
    // fixture's universal construction).
    let mut universal = ActionRestartGroup::new("universal", rugra::action::action_flags::RULE_ONCEPERFUNC, 1);
    universal.add_action_in_group(Box::new(ScriptAction::new("base", "start")), "base");
    universal.add_action_in_group(Box::new(ScriptAction::new("base", "stop")), "base");
    let mut body = ActionGroup::new("body");
    body.add_action_in_group(Box::new(ScriptAction::new("splitcopy", "splitcopy")), "splitcopy");
    body.add_action_in_group(Box::new(ScriptAction::new("splitpointer", "splitpointer")), "splitpointer");
    body.add_action_in_group(Box::new(ScriptAction::new("merge", "merge")), "merge");
    universal.add_action(Box::new(body));

    let mut db = ActionDatabase::new();
    db.register_action(Box::new(universal));
    db.set_group("decompile", &["base", "splitcopy", "splitpointer", "merge"]);
    db.set_current("decompile");
    arch.allacts = Some(std::sync::Arc::new(std::sync::RwLock::new(db)));
    emit_state(&arch, "init");

    let cases: [(&str, &str, &str); 8] = [
        ("", "", ""),
        ("struct", "", ""),
        ("struct", "", "pointer"),
        ("array", "struct", "pointer"),
        ("array", "struct", "pointer"),
        ("bogus", "", ""),
        ("struct", "bogus", ""),
        ("", "array", ""),
    ];

    for (i, (p1, p2, p3)) in cases.iter().enumerate() {
        let db = arch.allacts.as_ref().expect("allacts populated").read().expect("allacts read lock");
        let universal_before = first_leaf_ordinal(db.get_action("universal"));
        let root_before = first_leaf_ordinal(Some(db.get_current()));
        drop(db);

        let (threw, result) = apply_case(&mut arch, p1, p2, p3);
        println!("apply={i} args={p1}|{p2}|{p3} threw={} result={result} config={}", u8::from(threw), arch.split_datatype_config);
        emit_state(&arch, &i.to_string());

        let db = arch.allacts.as_ref().expect("allacts populated").read().expect("allacts read lock");
        let universal_after = first_leaf_ordinal(db.get_action("universal"));
        let root_after = first_leaf_ordinal(Some(db.get_current()));
        println!(
            "identity={i} universal_changed={} root_changed={} universal_firstid={universal_after} root_firstid={root_after}",
            u8::from(universal_before != universal_after),
            u8::from(root_before != root_after),
        );
    }
}
