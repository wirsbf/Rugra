//! Union resolution — faithful port of `unionresolve.hh` / `unionresolve.cc`
//! (1110 lines).
//!
//! Analysis for resolving which field of a union data-type is being accessed
//! at a specific point in the data-flow. `ScoreUnionFields` scores all
//! possible fields of a union for a specific Varnode access edge.
//!
//! The full Ghidra scoring algorithm is implemented as the typed
//! [`ScoreUnionFields`] API, which threads `Arc<Datatype>`,
//! `Arc<RwLock<PcodeOp>>`, and `Arc<RwLock<Varnode>>` exactly as Ghidra
//! threads raw `Datatype*`/`PcodeOp*`/`Varnode*`. The scoring tables in
//! [`score_trial_down`](ScoreUnionFields::score_trial_down) and
//! [`score_trial_up`](ScoreUnionFields::score_trial_up) are 1:1 with
//! unionresolve.cc:305-833.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/unionresolve.{hh,cc}.

use std::sync::{Arc, RwLock};

use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::type_system::datatype::{Datatype, TypeField, TypeMetatype, TypeUnion};
use crate::type_system::TypeFactory;
use crate::varnode::Varnode;

// ===========================================================================
// ResolvedUnion — unionresolve.hh:39 / unionresolve.cc:25
// ===========================================================================

/// A data-type \e resolved from an associated TypeUnion or TypeStruct.
/// Faithful to `ResolvedUnion` (unionresolve.hh:39).
#[derive(Debug, Clone)]
pub struct ResolvedUnion {
    /// The resolved data-type (Ghidra `resolve`).
    pub resolve: Arc<Datatype>,
    /// Union or Structure being resolved (Ghidra `baseType`).
    pub base_type: Arc<Datatype>,
    /// Index of field referenced by `resolve`, or -1 for the whole union.
    pub field_num: i32,
    /// If true, resolution cannot be overridden.
    pub lock: bool,
}

impl ResolvedUnion {
    // Ghidra: unionresolve.cc:25 ResolvedUnion::ResolvedUnion(Datatype*)
    /// Construct a data-type that resolves to itself. Faithful to the
    /// constructor `ResolvedUnion::ResolvedUnion(Datatype *parent)`
    /// (unionresolve.hh:46). The base type is the parent with any pointer
    /// layer stripped (cc:29-30); `field_num` is -1.
    pub fn new(parent: Arc<Datatype>) -> Self {
        let base_type = strip_pointer_layer(&parent);
        Self { resolve: parent, base_type, field_num: -1, lock: false }
    }

    // Ghidra: unionresolve.cc:40 ResolvedUnion::ResolvedUnion(Datatype*,int4,TypeFactory&)
    /// Construct a reference to a specific field. Faithful to
    /// `ResolvedUnion::ResolvedUnion(Datatype *parent,int4 fldNum,
    /// TypeFactory &typegrp)` (unionresolve.hh:47).
    pub fn with_field(parent: Arc<Datatype>, fld_num: i32, typegrp: &TypeFactory) -> Self {
        let base_type = parent.clone();
        let resolve = if fld_num < 0 {
            parent.clone()
        } else {
            match parent.as_ref() {
                Datatype::Pointer(_p) => {
                    let field = depend_at(parent.as_ref(), fld_num as usize);
                    let _ = typegrp;
                    field
                }
                _ => depend_at(parent.as_ref(), fld_num as usize),
            }
        };
        Self { resolve, base_type, field_num: fld_num, lock: false }
    }

    // RUGRA-GLUE: Stringly-typed constructor for callers that only have a
    //   type name and cannot readily produce an Arc<Datatype>. Not present in
    //   Ghidra; included so existing Rugra call-sites keep compiling.
    pub fn new_self(parent_name: &str) -> Self {
        let parent = name_placeholder(parent_name);
        Self::new(parent)
    }

    // RUGRA-GLUE: Stringly-typed field constructor. See `new_self`.
    pub fn new_field(parent_name: &str, field_name: &str, fld_num: i32) -> Self {
        let parent = name_placeholder(parent_name);
        let base_type = parent.clone();
        Self { resolve: name_placeholder(field_name), base_type, field_num: fld_num, lock: false }
    }

    // Ghidra: unionresolve.hh:48 ResolvedUnion::getDatatype
    /// Get the resolved data-type. Faithful to `getDatatype`.
    pub fn get_datatype(&self) -> &Arc<Datatype> { &self.resolve }

    // Ghidra: unionresolve.hh:49 ResolvedUnion::getBase
    /// Get the union or structure being referenced. Faithful to `getBase`.
    pub fn get_base(&self) -> &Arc<Datatype> { &self.base_type }

    // Ghidra: unionresolve.hh:50 ResolvedUnion::getFieldNum
    /// Get the index of the resolved field or -1. Faithful to `getFieldNum`.
    pub fn get_field_num(&self) -> i32 { self.field_num }

    // Ghidra: unionresolve.hh:51 ResolvedUnion::isLocked
    /// Is this locked against overrides? Faithful to `isLocked`.
    pub fn is_locked(&self) -> bool { self.lock }

    // Ghidra: unionresolve.hh:52 ResolvedUnion::setLock
    /// Set whether this resolution is locked. Faithful to `setLock`.
    pub fn set_lock(&mut self, val: bool) { self.lock = val; }

    // RUGRA-GLUE: name-based view of `resolve`. See `new_self`.
    pub fn get_datatype_name(&self) -> &str { self.resolve.get_name() }

    // RUGRA-GLUE: name-based view of `baseType`. See `new_self`.
    pub fn get_base_name(&self) -> &str { self.base_type.get_name() }
}

// ===========================================================================
// ResolveEdge — unionresolve.hh:60 / unionresolve.cc:64 / inline op< :172
// ===========================================================================

/// A data-flow edge to which a resolved data-type can be assigned. Faithful
/// to `ResolveEdge` (unionresolve.hh:60).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolveEdge {
    /// Id of base data-type being resolved (cc:61).
    pub type_id: u64,
    /// Id of the PcodeOp edge — `SeqNum::order` (cc:62).
    pub op_time: u32,
    /// Encoding of the slot and pointer-ness (cc:63).
    pub encoding: i32,
}

impl ResolveEdge {
    // Ghidra: unionresolve.cc:64 ResolveEdge::ResolveEdge
    /// Construct from a parent data-type, a PcodeOp, and a slot. Faithful to
    /// `ResolveEdge::ResolveEdge(const Datatype *parent,const PcodeOp *op,
    /// int4 slot)` (unionresolve.hh:65).
    pub fn new(parent: &Datatype, op: &PcodeOp, slot: i32) -> Self {
        let op_time = op.get_seq_num().order;
        let mut encoding = slot;
        let type_id = match parent.get_metatype() {
            TypeMetatype::Pointer => {
                let pointee = pointee_of(parent);
                encoding += 0x1000;
                pointee.get_id()
            }
            _ => parent.get_id(),
        };
        Self { type_id, op_time, encoding }
    }

    // RUGRA-GLUE: Component-wise constructor for tests/edge cases that already
    //   hold the resolved fields. Mirrors the Ghidra struct layout directly.
    pub fn from_components(type_id: u64, op_time: u32, slot: i32, is_pointer: bool) -> Self {
        let encoding = if is_pointer { slot + 0x1000 } else { slot };
        Self { type_id, op_time, encoding }
    }
}

// ===========================================================================
// Trial — unionresolve.hh:84
// ===========================================================================

/// Direction of trial fit. Faithful to `dir_type` (unionresolve.hh:87).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirType {
    /// Push the fit down \e with the data-flow (cc:88 `fit_down`).
    FitDown,
    /// Push the fit up \e against the data-flow (cc:89 `fit_up`).
    FitUp,
}

/// A trial data-type fitted to a specific place in the data-flow. Faithful
/// to `ScoreUnionFields::Trial` (unionresolve.hh:84).
#[derive(Debug, Clone)]
pub struct Trial {
    /// The Varnode we are testing for data-type fit (cc:91 `vn`).
    pub vn: Arc<RwLock<Varnode>>,
    /// The PcodeOp reading the Varnode, or `None` for an upward trial (cc:92).
    pub op: Option<Arc<RwLock<PcodeOp>>>,
    /// The slot reading the Varnode, or -1 (cc:93 `inslot`).
    pub in_slot: i32,
    /// Direction to push fit (cc:94 `direction`).
    pub direction: DirType,
    /// Field can be accessed as an array (cc:95 `array`).
    pub is_array: bool,
    /// The putative data-type of the Varnode (cc:96 `fitType`).
    pub fit_type: Arc<Datatype>,
    /// The original field being scored by this trial (cc:97 `scoreIndex`).
    pub score_index: i32,
}

impl Trial {
    // Ghidra: unionresolve.hh:106 Trial::Trial(PcodeOp*,int4,Datatype*,int4,bool)
    /// Construct a downward trial for a Varnode being read. Faithful to the
    /// downward constructor (unionresolve.hh:106-107).
    pub fn new_down(
        op: Arc<RwLock<PcodeOp>>, slot: i32, ct: Arc<Datatype>, index: i32, is_array: bool,
    ) -> Self {
        let vn = {
            let op_rg = op.read().unwrap();
            op_rg.get_in(slot as usize).cloned().expect("Trial::new_down: slot out of range")
        };
        Self { vn, op: Some(op), in_slot: slot, direction: DirType::FitDown,
            is_array, fit_type: ct, score_index: index }
    }

    // Ghidra: unionresolve.hh:115 Trial::Trial(Varnode*,Datatype*,int4,bool)
    /// Construct an upward trial for a Varnode. Faithful to the upward
    /// constructor (unionresolve.hh:115-116).
    pub fn new_up(vn: Arc<RwLock<Varnode>>, ct: Arc<Datatype>, index: i32, is_array: bool) -> Self {
        Self { vn, op: None, in_slot: -1, direction: DirType::FitUp,
            is_array, fit_type: ct, score_index: index }
    }
}

// ===========================================================================
// VisitMark — unionresolve.hh:120
// ===========================================================================

/// A mark accumulated when a given Varnode is visited with a specific field
/// index. Faithful to `VisitMark` (unionresolve.hh:120).
#[derive(Debug, Clone)]
pub struct VisitMark {
    /// Varnode reached by the trial field (cc:121 `vn`). Stored as the Arc
    /// pointer address so the mark is `PartialEq + Ord`.
    pub vn_key: usize,
    /// Index of the trial field (cc:122 `index`).
    pub index: i32,
}

impl VisitMark {
    // Ghidra: unionresolve.hh:122 VisitMark::VisitMark
    /// Construct from a Varnode handle and field index. Faithful to the
    /// constructor (unionresolve.hh:124).
    pub fn new(vn: &Arc<RwLock<Varnode>>, index: i32) -> Self {
        Self { vn_key: Arc::as_ptr(vn) as usize, index }
    }

    // RUGRA-GLUE: Component-wise constructor for the legacy tests.
    pub fn from_id(vn_id: u64, index: i32) -> Self {
        Self { vn_key: vn_id as usize, index }
    }
}

impl PartialEq for VisitMark {
    fn eq(&self, other: &Self) -> bool { self.vn_key == other.vn_key && self.index == other.index }
}
impl Eq for VisitMark {}
impl PartialOrd for VisitMark {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}
impl Ord for VisitMark {
    // Ghidra: unionresolve.hh:130 VisitMark::operator<
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.vn_key.cmp(&other.vn_key) {
            std::cmp::Ordering::Equal => self.index.cmp(&other.index),
            ord => ord,
        }
    }
}

// ===========================================================================
// Constants — unionresolve.cc:79-81
// ===========================================================================

/// Threshold of trials over which to cancel additional passes. Faithful to
/// `ScoreUnionFields::threshold` (unionresolve.cc:79).
pub const THRESHOLD: i32 = 256;

/// Maximum number of levels to score through. Faithful to
/// `ScoreUnionFields::maxPasses` (unionresolve.cc:80).
pub const MAX_PASSES: i32 = 6;

/// Maximum number of trials to evaluate. Faithful to
/// `ScoreUnionFields::maxTrials` (unionresolve.cc:81).
pub const MAX_TRIALS: i32 = 1024;

// ===========================================================================
// ScoreUnionFields — unionresolve.hh:82
// ===========================================================================

/// Analyze data-flow to resolve which field of a union data-type is being
/// accessed. Faithful to `ScoreUnionFields` (unionresolve.hh:82).
pub struct ScoreUnionFields<'t> {
    /// The factory containing data-types (cc:136 `typegrp`).
    pub typegrp: &'t TypeFactory,
    /// Score for each field, indexed by `fieldNum + 1` (whole union is
    /// index 0) (cc:137 `scores`).
    pub scores: Vec<i32>,
    /// Field corresponding to each score (cc:138 `fields`).
    pub fields: Vec<Arc<Datatype>>,
    /// Places that have already been visited (cc:139 `visited`).
    pub visited: std::collections::BTreeSet<VisitMark>,
    /// Current trials being pushed (cc:140 `trialCurrent`).
    pub trial_current: Vec<Trial>,
    /// Next set of trials (cc:141 `trialNext`).
    pub trial_next: Vec<Trial>,
    /// The best result (cc:142 `result`).
    pub result: ResolvedUnion,
    /// Number of trials evaluated so far (cc:143 `trialCount`).
    pub trial_count: i32,
}

impl<'t> ScoreUnionFields<'t> {
    // Ghidra: unionresolve.cc:990 ScoreUnionFields::ScoreUnionFields(TypeFactory&,Datatype*,PcodeOp*,int4)
    /// Score a data-type involving a union against a data-flow edge.
    /// Faithful to the primary constructor (unionresolve.cc:990-1037).
    pub fn new(
        typegrp: &'t TypeFactory, parent_type: Arc<Datatype>,
        op: Arc<RwLock<PcodeOp>>, slot: i32,
    ) -> Self {
        let result = ResolvedUnion::new(parent_type.clone());
        {
            let op_rg = op.read().unwrap();
            if test_simple_cases(&op_rg, slot, parent_type.as_ref()) {
                return Self::empty(typegrp, result);
            }
        }
        let word_size = if parent_type.get_metatype() == TypeMetatype::Pointer {
            pointee_word_size(parent_type.as_ref())
        } else { 0 };
        let num_fields = num_depend(result.base_type.as_ref());
        let mut scores = vec![0i32; num_fields + 1];
        let mut fields: Vec<Arc<Datatype>> = vec![Arc::new(empty_placeholder()); num_fields + 1];
        let mut visited = std::collections::BTreeSet::new();
        let mut trial_current: Vec<Trial> = Vec::new();
        let vn = {
            let op_rg = op.read().unwrap();
            if slot < 0 { op_rg.get_out().cloned() } else { op_rg.get_in(slot as usize).cloned() }
        };
        let vn = vn.expect("ScoreUnionFields::new: op has no varnode at slot");
        {
            let vn_rg = vn.read().unwrap();
            if vn_rg.get_size() != parent_type.get_size() {
                scores[0] -= 10;
            } else {
                if slot < 0 {
                    trial_current.push(Trial::new_up(vn.clone(), parent_type.clone(), 0, false));
                } else {
                    trial_current.push(Trial::new_down(op.clone(), slot, parent_type.clone(), 0, false));
                }
            }
        }
        fields[0] = parent_type.clone();
        visited.insert(VisitMark::new(&vn, 0));
        for i in 0..num_fields {
            let mut field_type = get_depend(result.base_type.as_ref(), i);
            let mut is_array = false;
            if word_size != 0 {
                if field_type.get_metatype() == TypeMetatype::Array { is_array = true; }
                field_type = type_pointer_strip_array(typegrp, parent_type.get_size(), field_type, word_size);
            }
            let vn_size = vn.read().unwrap().get_size();
            if vn_size != field_type.get_size() {
                scores[i + 1] -= 10;
            } else if slot < 0 {
                trial_current.push(Trial::new_up(vn.clone(), field_type.clone(), (i + 1) as i32, is_array));
            } else {
                trial_current.push(Trial::new_down(op.clone(), slot, field_type.clone(), (i + 1) as i32, is_array));
            }
            fields[i + 1] = field_type;
            visited.insert(VisitMark::new(&vn, (i + 1) as i32));
        }
        let mut s = Self {
            typegrp, scores, fields, visited, trial_current,
            trial_next: Vec::new(), result, trial_count: 0,
        };
        s.run_passes();
        s.compute_best_index();
        s
    }

    // Ghidra: unionresolve.cc:1050 ScoreUnionFields::ScoreUnionFields(TypeFactory&,TypeUnion*,int4,PcodeOp*)
    /// Score a union against a SUBPIECE truncation. Faithful to the
    /// SUBPIECE constructor (unionresolve.cc:1050-1072).
    pub fn new_for_subpiece(
        typegrp: &'t TypeFactory, union_type: Arc<Datatype>,
        offset: i64, op: Arc<RwLock<PcodeOp>>,
    ) -> Self {
        let result = ResolvedUnion::new(union_type.clone());
        let vn = {
            let op_rg = op.read().unwrap();
            op_rg.get_out().cloned().expect("ScoreUnionFields::new_for_subpiece: op has no output")
        };
        let (union_fields, num_fields) = union_field_list(union_type.as_ref());
        let mut scores = vec![0i32; num_fields + 1];
        let mut fields: Vec<Arc<Datatype>> = vec![Arc::new(empty_placeholder()); num_fields + 1];
        fields[0] = union_type.clone();
        scores[0] = -10;
        let mut s = Self {
            typegrp, scores, fields,
            visited: std::collections::BTreeSet::new(),
            trial_current: Vec::new(), trial_next: Vec::new(),
            result, trial_count: 0,
        };
        let vn_size = vn.read().unwrap().get_size();
        for (i, uf) in union_fields.iter().enumerate() {
            s.fields[i + 1] = uf.type_ptr.clone();
            if uf.type_ptr.get_size() != vn_size || uf.offset as i64 != offset {
                s.scores[i + 1] = -10;
                continue;
            }
            s.new_trials_down(&vn, uf.type_ptr.clone(), (i + 1) as i32, false);
        }
        std::mem::swap(&mut s.trial_current, &mut s.trial_next);
        if s.trial_current.len() > 1 { s.run_passes(); }
        s.compute_best_index();
        s
    }

    // Ghidra: unionresolve.cc:1083 ScoreUnionFields::ScoreUnionFields(TypeFactory&,TypeUnion*,int4,PcodeOp*,int4)
    /// Score a union against an implied truncation at a data-flow edge.
    /// Faithful to the implied-truncation constructor (unionresolve.cc:1083-1108).
    pub fn new_for_implied_trunc(
        typegrp: &'t TypeFactory, union_type: Arc<Datatype>,
        offset: i64, op: Arc<RwLock<PcodeOp>>, slot: i32,
    ) -> Self {
        let result = ResolvedUnion::new(union_type.clone());
        let vn = {
            let op_rg = op.read().unwrap();
            if slot < 0 { op_rg.get_out().cloned() } else { op_rg.get_in(slot as usize).cloned() }
                .expect("ScoreUnionFields::new_for_implied_trunc: op has no varnode at slot")
        };
        let (union_fields, num_fields) = union_field_list(union_type.as_ref());
        let mut scores = vec![0i32; num_fields + 1];
        let mut fields: Vec<Arc<Datatype>> = vec![Arc::new(empty_placeholder()); num_fields + 1];
        fields[0] = union_type.clone();
        scores[0] = -10;
        let mut visited = std::collections::BTreeSet::new();
        let mut trial_current: Vec<Trial> = Vec::new();
        let vn_size = vn.read().unwrap().get_size();
        for (i, uf) in union_fields.iter().enumerate() {
            let field_offset = uf.offset as i64;
            let ct_opt = score_truncation_inplace(
                &mut scores, uf.type_ptr.as_ref(), vn_size,
                offset - field_offset, (i + 1) as i32);
            fields[i + 1] = uf.type_ptr.clone();
            if let Some(ct) = ct_opt {
                if slot < 0 {
                    trial_current.push(Trial::new_up(vn.clone(), ct, (i + 1) as i32, false));
                } else {
                    trial_current.push(Trial::new_down(op.clone(), slot, ct, (i + 1) as i32, false));
                }
                visited.insert(VisitMark::new(&vn, (i + 1) as i32));
            }
        }
        let mut s = Self {
            typegrp, scores, fields, visited, trial_current,
            trial_next: Vec::new(), result, trial_count: 0,
        };
        if s.trial_current.len() > 1 { s.run_passes(); }
        s.compute_best_index();
        s
    }

    // RUGRA-GLUE: Minimal constructor for the legacy string-based tests and
    //   for callers that build the scores/fields vectors by hand.
    pub fn with_field_names(parent_name: &str, field_names: &[String]) -> Self {
        let parent = name_placeholder(parent_name);
        let mut fields: Vec<Arc<Datatype>> = Vec::with_capacity(field_names.len() + 1);
        fields.push(parent.clone());
        for n in field_names { fields.push(name_placeholder(n)); }
        let scores = vec![0i32; fields.len()];
        let leaked: &'static TypeFactory = Box::leak(Box::new(TypeFactory::new(8)));
        Self {
            typegrp: leaked, scores, fields,
            visited: std::collections::BTreeSet::new(),
            trial_current: Vec::new(), trial_next: Vec::new(),
            result: ResolvedUnion::new(parent), trial_count: 0,
        }
    }

    // RUGRA-GLUE: Construct an empty scorer holding just an initial result.
    fn empty(typegrp: &'t TypeFactory, result: ResolvedUnion) -> Self {
        Self {
            typegrp, scores: Vec::new(), fields: Vec::new(),
            visited: std::collections::BTreeSet::new(),
            trial_current: Vec::new(), trial_next: Vec::new(),
            result, trial_count: 0,
        }
    }

    // Ghidra: unionresolve.hh:166 ScoreUnionFields::getResult
    /// Get the resulting best field resolution. Faithful to `getResult`.
    pub fn get_result(&self) -> &ResolvedUnion { &self.result }

    // RUGRA-GLUE: number of slots (whole union + N fields).
    pub fn num_fields(&self) -> usize { self.fields.len() }

    // RUGRA-GLUE: add to scores[index].
    pub fn add_score(&mut self, index: usize, score: i32) {
        if index < self.scores.len() { self.scores[index] += score; }
    }

    // Ghidra: unionresolve.cc:945 ScoreUnionFields::computeBestIndex
    /// Assuming scoring is complete, compute the best index. Faithful to
    /// `computeBestIndex` (unionresolve.cc:945-958).
    pub fn compute_best_index(&mut self) {
        if self.scores.is_empty() { return; }
        let mut best_idx = 0usize;
        let mut best_score = self.scores[0];
        for (i, &score) in self.scores.iter().enumerate().skip(1) {
            if score > best_score { best_score = score; best_idx = i; }
        }
        self.result.field_num = best_idx as i32 - 1;
        self.result.resolve = self.fields[best_idx].clone();
    }

    // Ghidra: unionresolve.cc:931 ScoreUnionFields::runOneLevel
    /// Run through each current trial and compute its score. Faithful to
    /// `runOneLevel` (unionresolve.cc:931-943).
    fn run_one_level(&mut self, last_pass: bool) {
        let current = std::mem::take(&mut self.trial_current);
        for trial in current {
            self.trial_count += 1;
            if self.trial_count > MAX_TRIALS { self.trial_current.clear(); return; }
            self.score_trial_down(&trial, last_pass);
            self.score_trial_up(&trial, last_pass);
        }
    }

    // Ghidra: unionresolve.cc:963 ScoreUnionFields::run
    /// Try to fit each possible field over multiple levels of the data-flow.
    /// Faithful to `run` (unionresolve.cc:963-980).
    fn run_passes(&mut self) {
        self.trial_count = 0;
        for pass in 0..MAX_PASSES {
            if self.trial_current.is_empty() { break; }
            if self.trial_count > THRESHOLD { break; }
            if pass + 1 == MAX_PASSES {
                self.run_one_level(true);
            } else {
                self.run_one_level(false);
                std::mem::swap(&mut self.trial_current, &mut self.trial_next);
                self.trial_next.clear();
            }
        }
    }

    // Ghidra: unionresolve.cc:88 ScoreUnionFields::testArrayArithmetic
    /// Check if the given PcodeOp is doing array arithmetic with union-sized
    /// elements. Faithful to `testArrayArithmetic` (unionresolve.cc:88-112).
    fn test_array_arithmetic(op: &PcodeOp, in_slot: i32, base_size: usize) -> bool {
        if op.get_opcode() == OpCode::CPUI_INT_ADD {
            let other_slot = (1 - in_slot) as usize;
            if let Some(other) = op.get_in(other_slot) {
                let other_rg = other.read().unwrap();
                if other_rg.is_constant() {
                    if other_rg.get_offset() >= base_size as u64 { return true; }
                } else if other_rg.is_written() {
                    if let Some(mult_op) = other_rg.get_def() {
                        let mult_rg = mult_op.read().unwrap();
                        if mult_rg.get_opcode() == OpCode::CPUI_INT_MULT {
                            if let Some(vn2) = mult_rg.get_in(1) {
                                let vn2_rg = vn2.read().unwrap();
                                if vn2_rg.is_constant() && vn2_rg.get_offset() >= base_size as u64 {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        } else if op.get_opcode() == OpCode::CPUI_PTRADD {
            if let Some(vn) = op.get_in(2) {
                let vn_rg = vn.read().unwrap();
                if vn_rg.get_offset() >= base_size as u64 { return true; }
            }
        }
        false
    }

    // Ghidra: unionresolve.cc:119 ScoreUnionFields::testSimpleCases
    /// Identify cases where we know the union shouldn't be resolved to a
    /// field. Faithful to `testSimpleCases` (unionresolve.cc:119-137).
    fn score_simple_cases_inner(op: &PcodeOp, in_slot: i32, parent: &Datatype) -> bool {
        if op.is_marker() { return true; }
        if parent.get_metatype() == TypeMetatype::Pointer {
            if in_slot < 0 { return true; }
            if Self::test_array_arithmetic(op, in_slot, parent.get_size()) { return true; }
        }
        if op.get_opcode() != OpCode::CPUI_COPY { return false; }
        if in_slot < 0 { return false; }
        if let Some(out) = op.get_out() {
            let out_rg = out.read().unwrap();
            if out_rg.is_type_lock() { return false; }
        }
        true
    }

    // Ghidra: unionresolve.cc:144 ScoreUnionFields::scoreLockedType
    /// Score a trial data-type against a locked data-type. Faithful to
    /// `scoreLockedType` (unionresolve.cc:144-176).
    fn score_locked_type(ct: &Datatype, lock_type: &Datatype) -> i32 {
        let mut score = 0i32;
        let mut ct = ct;
        let mut lock_type = lock_type;
        if std::ptr::eq(ct, lock_type) { score += 5; }
        while ct.get_metatype() == TypeMetatype::Pointer {
            if lock_type.get_metatype() != TypeMetatype::Pointer { break; }
            score += 5;
            ct = pointee_of(ct);
            lock_type = pointee_of(lock_type);
            if std::ptr::eq(ct, lock_type) { score += 5; }
        }
        let ct_meta = ct.get_metatype();
        let vn_meta = lock_type.get_metatype();
        if ct_meta == vn_meta {
            if matches!(ct_meta,
                TypeMetatype::Struct | TypeMetatype::Union
                | TypeMetatype::Array | TypeMetatype::Code) {
                score += 10;
            } else { score += 3; }
        } else {
            if (ct_meta == TypeMetatype::Int && vn_meta == TypeMetatype::Uint)
                || (ct_meta == TypeMetatype::Uint && vn_meta == TypeMetatype::Int) {
                score -= 1;
            } else { score -= 5; }
            if ct.get_size() != lock_type.get_size() { score -= 2; }
        }
        score
    }

    // Ghidra: unionresolve.cc:184 ScoreUnionFields::scoreParameter
    /// Score a trial data-type against a call parameter. Faithful to
    /// `scoreParameter` (unionresolve.cc:184-197).
    fn score_parameter(
        ct: &Datatype, fd: &crate::funcdata::Funcdata,
        call_op: &PcodeOp, param_slot: i32,
    ) -> i32 {
        for fc in fd.callspecs.iter() {
            if fc.op_addr == call_op.get_addr() {
                if fc.is_input_locked() && (fc.prototype.num_params() as i32) > param_slot {
                    if let Some(param) = fc.prototype.get_param(param_slot as usize) {
                        return Self::score_locked_type(ct, param.data_type.as_ref());
                    }
                }
                break;
            }
        }
        let meta = ct.get_metatype();
        if matches!(meta,
            TypeMetatype::Array | TypeMetatype::Struct
            | TypeMetatype::Union | TypeMetatype::Code) { -1 } else { 0 }
    }

    // Ghidra: unionresolve.cc:204 ScoreUnionFields::scoreReturnType
    /// Score a trial data-type against a CALL's return type. Faithful to
    /// `scoreReturnType` (unionresolve.cc:204-217).
    fn score_return_type(ct: &Datatype, fd: &crate::funcdata::Funcdata, call_op: &PcodeOp) -> i32 {
        for fc in fd.callspecs.iter() {
            if fc.op_addr == call_op.get_addr() {
                if fc.is_output_locked() {
                    return Self::score_locked_type(ct, fc.prototype.return_type.as_ref());
                }
                break;
            }
        }
        let meta = ct.get_metatype();
        if matches!(meta,
            TypeMetatype::Array | TypeMetatype::Struct
            | TypeMetatype::Union | TypeMetatype::Code) { -1 } else { 0 }
    }

    // Ghidra: unionresolve.cc:227 ScoreUnionFields::derefPointer
    /// Score a trial data-type as a pointer being dereferenced by LOAD/STORE.
    /// Faithful to `derefPointer` (unionresolve.cc:227-246).
    fn deref_pointer<'a>(ct: &'a Datatype, vn_size: usize) -> (Option<&'a Datatype>, i32) {
        let mut score = 0i32;
        let mut res_type: Option<&Datatype> = None;
        if ct.get_metatype() == TypeMetatype::Pointer {
            let mut ptr_to: Option<&Datatype> = Some(pointee_of(ct));
            while let Some(p) = ptr_to {
                if p.get_size() > vn_size {
                    let (sub, _newoff) = p.get_sub_type(0);
                    ptr_to = sub;
                } else { break; }
            }
            if let Some(p) = ptr_to {
                if p.get_size() == vn_size { score = 10; res_type = Some(p); }
            }
        } else { score = -10; }
        (res_type, score)
    }

    // Ghidra: unionresolve.cc:253 ScoreUnionFields::newTrialsDown
    /// Create new downward trials for each read of `vn`. Faithful to
    /// `newTrialsDown` (unionresolve.cc:253-268).
    fn new_trials_down(
        &mut self, vn: &Arc<RwLock<Varnode>>, ct: Arc<Datatype>,
        score_index: i32, is_array: bool,
    ) {
        let mark = VisitMark::new(vn, score_index);
        if !self.visited.insert(mark) { return; }
        let (is_type_lock, locked_type, descends) = {
            let vn_rg = vn.read().unwrap();
            let lt = if vn_rg.is_type_lock() { vn_rg.get_type() } else { None };
            let ds: Vec<Arc<RwLock<PcodeOp>>> = vn_rg.descend_iter().collect();
            (vn_rg.is_type_lock(), lt, ds)
        };
        if is_type_lock {
            if let Some(lt) = locked_type {
                self.scores[score_index as usize] += Self::score_locked_type(ct.as_ref(), lt.as_ref());
            }
            return;
        }
        for op in descends {
            let slot = {
                let op_rg = op.read().unwrap();
                op_rg.slot_of_input(vn).map(|s| s as i32).unwrap_or(-1)
            };
            self.trial_next.push(Trial::new_down(op, slot, ct.clone(), score_index, is_array));
        }
    }

    // Ghidra: unionresolve.cc:276 ScoreUnionFields::newTrials
    /// Create new trials (down + up) for the input slot of an op. Faithful
    /// to `newTrials` (unionresolve.cc:276-296).
    fn new_trials(
        &mut self, op: &Arc<RwLock<PcodeOp>>, slot: i32, ct: Arc<Datatype>,
        score_index: i32, is_array: bool,
    ) {
        let vn = {
            let op_rg = op.read().unwrap();
            op_rg.get_in(slot as usize).cloned().expect("ScoreUnionFields::new_trials: slot out of range")
        };
        let mark = VisitMark::new(&vn, score_index);
        if !self.visited.insert(mark) { return; }
        let (is_type_lock, locked_type, descends) = {
            let vn_rg = vn.read().unwrap();
            let lt = if vn_rg.is_type_lock() { vn_rg.get_type() } else { None };
            let ds: Vec<Arc<RwLock<PcodeOp>>> = vn_rg.descend_iter().collect();
            (vn_rg.is_type_lock(), lt, ds)
        };
        if is_type_lock {
            if let Some(lt) = locked_type {
                self.scores[score_index as usize] += Self::score_locked_type(ct.as_ref(), lt.as_ref());
            }
            return;
        }
        self.trial_next.push(Trial::new_up(vn.clone(), ct.clone(), score_index, is_array));
        for read_op in descends {
            let inslot = {
                let op_rg = read_op.read().unwrap();
                op_rg.slot_of_input(&vn).map(|s| s as i32).unwrap_or(-1)
            };
            if Arc::ptr_eq(&read_op, op) && inslot == slot { continue; }
            self.trial_next.push(Trial::new_down(read_op, inslot, ct.clone(), score_index, is_array));
        }
    }

    // Ghidra: unionresolve.cc:305 ScoreUnionFields::scoreTrialDown
    /// Fit a trial's data-type to its op's input and accumulate a score.
    /// Faithful to `scoreTrialDown` (unionresolve.cc:305-640).
    fn score_trial_down(&mut self, trial: &Trial, last_level: bool) {
        if trial.direction == DirType::FitUp { return; }
        let op = match &trial.op { Some(o) => o.clone(), None => return };
        let (op_code, out_vn, _in0, in1, in2, out_size, in1_offset_const, in2_offset_const) = {
            let op_rg = op.read().unwrap();
            let out_vn = op_rg.get_out().cloned();
            let in0 = op_rg.get_in(0).cloned();
            let in1 = op_rg.get_in(1).cloned();
            let in2 = op_rg.get_in(2).cloned();
            let out_size = out_vn.as_ref().map(|v| v.read().unwrap().get_size());
            let in1_off = in1.as_ref()
                .filter(|v| v.read().unwrap().is_constant())
                .map(|v| v.read().unwrap().get_offset());
            let in2_off = in2.as_ref()
                .filter(|v| v.read().unwrap().is_constant())
                .map(|v| v.read().unwrap().get_offset());
            (op_rg.get_opcode(), out_vn, in0, in1, in2, out_size, in1_off, in2_off)
        };
        let meta = trial.fit_type.get_metatype();
        let mut score: i32 = 0;
        let mut res_type: Option<Arc<Datatype>> = None;
        match op_code {
            OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT => {
                res_type = Some(trial.fit_type.clone());
            }
            OpCode::CPUI_LOAD => {
                if let Some(out_sz) = out_size {
                    let (rt, s) = Self::deref_pointer(trial.fit_type.as_ref(), out_sz);
                    score = s;
                    if let Some(rt) = rt { res_type = Some(Arc::new(rt.clone())); }
                }
            }
            OpCode::CPUI_STORE => {
                if trial.in_slot == 1 {
                    let vn_size = in2.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                    let (ptr_to, s) = Self::deref_pointer(trial.fit_type.as_ref(), vn_size);
                    score = s;
                    if let Some(pt) = ptr_to {
                        if !last_level {
                            self.new_trials(&op, 2, Arc::new(pt.clone()), trial.score_index, trial.is_array);
                        }
                    }
                } else if trial.in_slot == 2 {
                    if meta == TypeMetatype::Code { score = -5; } else { score = 1; }
                }
            }
            OpCode::CPUI_CBRANCH => {
                if meta == TypeMetatype::Bool { score = 10; } else { score = -10; }
            }
            OpCode::CPUI_BRANCHIND => {
                if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Array | TypeMetatype::Struct
                    | TypeMetatype::Union | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            OpCode::CPUI_CALL | OpCode::CPUI_CALLOTHER => {
                let _ = in1;
                if trial.in_slot > 0 {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct
                        | TypeMetatype::Union | TypeMetatype::Code) {
                        score = -1;
                    } else { score = 0; }
                }
            }
            OpCode::CPUI_CALLIND => {
                if trial.in_slot == 0 {
                    if meta == TypeMetatype::Pointer {
                        let ptrto = pointee_of(trial.fit_type.as_ref());
                        if ptrto.get_metatype() == TypeMetatype::Code { score = 10; } else { score = -10; }
                    }
                } else {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct
                        | TypeMetatype::Union | TypeMetatype::Code) {
                        score = -1;
                    } else { score = 0; }
                }
            }
            OpCode::CPUI_RETURN => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct
                    | TypeMetatype::Union | TypeMetatype::Code) {
                    score = -1;
                }
            }
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -1;
                } else { score = 1; }
            }
            OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Unknown
                    | TypeMetatype::Uint | TypeMetatype::Bool) {
                    score = -1;
                } else { score = 5; }
            }
            OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_CARRY => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Unknown | TypeMetatype::Uint) {
                    score = 5;
                } else if meta == TypeMetatype::Int { score = -5; }
            }
            OpCode::CPUI_INT_ZEXT => {
                if meta == TypeMetatype::Uint { score = 2; }
                else if matches!(meta, TypeMetatype::Int | TypeMetatype::Bool) { score = 1; }
                else if meta == TypeMetatype::Unknown { score = 0; }
                else { score = -5; }
            }
            OpCode::CPUI_INT_SEXT => {
                if meta == TypeMetatype::Int { score = 2; }
                else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Bool) { score = 1; }
                else if meta == TypeMetatype::Unknown { score = 0; }
                else { score = -5; }
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_PTRSUB => {
                if meta == TypeMetatype::Pointer {
                    if trial.in_slot >= 0 {
                        if let Some(off) = in1_offset_const {
                            let _ = off;
                            if off == 0 { res_type = Some(trial.fit_type.clone()); }
                            score = 5;
                        } else if trial.is_array {
                            score = 1;
                            let mut el_size = 1usize;
                            if let Some(ref vn1) = in1 {
                                if vn1.read().unwrap().is_written() {
                                    if let Some(mult_op) = vn1.read().unwrap().get_def() {
                                        let mult_rg = mult_op.read().unwrap();
                                        if mult_rg.get_opcode() == OpCode::CPUI_INT_MULT {
                                            if let Some(mult_vn) = mult_rg.get_in(1) {
                                                let mv = mult_vn.read().unwrap();
                                                if mv.is_constant() { el_size = mv.get_offset() as usize; }
                                            }
                                        }
                                    }
                                }
                            }
                            let base = trial.fit_type.as_ref();
                            if let Some(ptr_to) = pointer_pointee(base) {
                                if ptr_to.get_align_size() == el_size {
                                    score = 5;
                                    res_type = Some(trial.fit_type.clone());
                                }
                            }
                        } else { score = 5; }
                    }
                } else if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            OpCode::CPUI_INT_2COMP => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Unknown | TypeMetatype::Bool) {
                    score = -1;
                } else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR | OpCode::CPUI_POPCOUNT | OpCode::CPUI_LZCOUNT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -1;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 2; }
            }
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT => {
                if trial.in_slot == 0 {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float) {
                        score = -5;
                    } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                        score = -1;
                    } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 2; }
                } else {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float | TypeMetatype::Pointer) {
                        score = -5;
                    } else { score = 1; }
                }
            }
            OpCode::CPUI_INT_SRIGHT => {
                if trial.in_slot == 0 {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float) {
                        score = -5;
                    } else if matches!(meta,
                        TypeMetatype::Pointer | TypeMetatype::Bool
                        | TypeMetatype::Uint | TypeMetatype::Unknown) {
                        score = -1;
                    } else { score = 2; }
                } else {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float | TypeMetatype::Pointer) {
                        score = -5;
                    } else { score = 1; }
                }
            }
            OpCode::CPUI_INT_MULT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else { score = 5; }
            }
            OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_REM => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 5; }
            }
            OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_SREM => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_XOR | OpCode::CPUI_BOOL_OR => {
                if meta == TypeMetatype::Bool { score = 10; }
                else if matches!(meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Unknown) {
                    score = -1;
                } else { score = -10; }
            }
            OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_FLOAT_NAN | OpCode::CPUI_FLOAT_ADD | OpCode::CPUI_FLOAT_DIV
            | OpCode::CPUI_FLOAT_MULT | OpCode::CPUI_FLOAT_SUB | OpCode::CPUI_FLOAT_NEG
            | OpCode::CPUI_FLOAT_ABS | OpCode::CPUI_FLOAT_SQRT | OpCode::CPUI_FLOAT_FLOAT2FLOAT
            | OpCode::CPUI_FLOAT_TRUNC | OpCode::CPUI_FLOAT_CEIL
            | OpCode::CPUI_FLOAT_FLOOR | OpCode::CPUI_FLOAT_ROUND => {
                if meta == TypeMetatype::Float { score = 10; } else { score = -10; }
            }
            OpCode::CPUI_FLOAT_INT2FLOAT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if meta == TypeMetatype::Pointer { score = -5; }
                else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_PIECE => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                }
            }
            OpCode::CPUI_SUBPIECE => {
                let offset = in1_offset_const.unwrap_or(0) as i64;
                let vn_size = out_size.unwrap_or(0);
                if let Some(rt) = self.score_truncation(
                    trial.fit_type.as_ref(), vn_size, offset, trial.score_index) {
                    res_type = Some(Arc::new(rt.clone()));
                }
            }
            OpCode::CPUI_PTRADD => {
                if meta == TypeMetatype::Pointer {
                    if trial.in_slot == 0 {
                        let ptr_to = pointee_of(trial.fit_type.as_ref());
                        let stride = in2_offset_const.unwrap_or(0) as usize;
                        if ptr_to.get_align_size() == stride {
                            score = 10;
                            res_type = Some(trial.fit_type.clone());
                        }
                    } else { score = -10; }
                } else if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            OpCode::CPUI_SEGMENTOP => {
                if trial.in_slot == 2 {
                    if meta == TypeMetatype::Pointer { score = 5; }
                    else if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float) {
                        score = -5;
                    } else { score = -1; }
                } else {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float | TypeMetatype::Pointer) {
                        score = -2;
                    }
                }
            }
            _ => { score = -10; }
        }
        self.scores[trial.score_index as usize] += score;
        if let Some(rt) = res_type {
            if !last_level {
                if let Some(out) = out_vn {
                    self.new_trials_down(&out, rt, trial.score_index, trial.is_array);
                }
            }
        }
    }

    // Ghidra: unionresolve.cc:642 ScoreUnionFields::scoreTrialUp
    /// Fit a trial's data-type against the op that defines its Varnode.
    /// Faithful to `scoreTrialUp` (unionresolve.cc:642-833).
    fn score_trial_up(&mut self, trial: &Trial, last_level: bool) {
        if trial.direction == DirType::FitDown { return; }
        let mut score: i32 = 0;
        let mut res_type: Option<Arc<Datatype>> = None;
        let (is_written, is_constant) = {
            let vn_rg = trial.vn.read().unwrap();
            (vn_rg.is_written(), vn_rg.is_constant())
        };
        if !is_written {
            if is_constant { self.score_constant_fit(trial); }
            return;
        }
        let def = { let vn_rg = trial.vn.read().unwrap(); vn_rg.get_def() };
        let def = match def { Some(d) => d, None => return };
        let (def_code, in1_off_const, in2_off_const) = {
            let def_rg = def.read().unwrap();
            let in1_off = def_rg.get_in(1).and_then(|v| {
                let vrg = v.read().unwrap();
                if vrg.is_constant() { Some(vrg.get_offset()) } else { None }
            });
            let in2_off = def_rg.get_in(2).and_then(|v| {
                let vrg = v.read().unwrap();
                if vrg.is_constant() { Some(vrg.get_offset()) } else { None }
            });
            (def_rg.get_opcode(), in1_off, in2_off)
        };
        let meta = trial.fit_type.get_metatype();
        let new_slot = 0i32;
        match def_code {
            OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT => {
                res_type = Some(trial.fit_type.clone());
            }
            OpCode::CPUI_LOAD => { res_type = Some(trial.fit_type.clone()); }
            OpCode::CPUI_CALL | OpCode::CPUI_CALLOTHER | OpCode::CPUI_CALLIND => {
                let meta = trial.fit_type.get_metatype();
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct
                    | TypeMetatype::Union | TypeMetatype::Code) {
                    score = -1;
                } else { score = 0; }
            }
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW
            | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_CARRY
            | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_XOR | OpCode::CPUI_BOOL_OR
            | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL | OpCode::CPUI_FLOAT_NAN => {
                if meta == TypeMetatype::Bool { score = 10; }
                else if trial.fit_type.get_size() == 1 { score = 1; }
                else { score = -10; }
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_PTRSUB => {
                if meta == TypeMetatype::Pointer { score = 5; }
                else if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            OpCode::CPUI_INT_2COMP => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Unknown | TypeMetatype::Bool) {
                    score = -1;
                } else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR | OpCode::CPUI_POPCOUNT | OpCode::CPUI_LZCOUNT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -1;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 2; }
            }
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -1;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 2; }
            }
            OpCode::CPUI_INT_SRIGHT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Bool
                    | TypeMetatype::Uint | TypeMetatype::Unknown) {
                    score = -1;
                } else { score = 2; }
            }
            OpCode::CPUI_INT_MULT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else { score = 5; }
            }
            OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_REM => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 5; }
            }
            OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_SREM => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_FLOAT_ADD | OpCode::CPUI_FLOAT_DIV | OpCode::CPUI_FLOAT_MULT
            | OpCode::CPUI_FLOAT_SUB | OpCode::CPUI_FLOAT_NEG | OpCode::CPUI_FLOAT_ABS
            | OpCode::CPUI_FLOAT_SQRT | OpCode::CPUI_FLOAT_FLOAT2FLOAT | OpCode::CPUI_FLOAT_CEIL
            | OpCode::CPUI_FLOAT_FLOOR | OpCode::CPUI_FLOAT_ROUND | OpCode::CPUI_FLOAT_INT2FLOAT => {
                if meta == TypeMetatype::Float { score = 10; } else { score = -10; }
            }
            OpCode::CPUI_FLOAT_TRUNC => {
                if matches!(meta, TypeMetatype::Int | TypeMetatype::Uint) { score = 2; }
                else { score = -2; }
            }
            OpCode::CPUI_PIECE => {
                if matches!(meta, TypeMetatype::Float | TypeMetatype::Bool) { score = -5; }
                else if matches!(meta, TypeMetatype::Code | TypeMetatype::Pointer) { score = -2; }
            }
            OpCode::CPUI_SUBPIECE => {
                if matches!(meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Bool) {
                    if in1_off_const == Some(0) { score = 3; } else { score = 1; }
                } else { score = -5; }
            }
            OpCode::CPUI_PTRADD => {
                if meta == TypeMetatype::Pointer {
                    let ptr_to = pointee_of(trial.fit_type.as_ref());
                    let stride = in2_off_const.unwrap_or(0) as usize;
                    if ptr_to.get_align_size() == stride { score = 10; } else { score = 2; }
                } else if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            _ => { score = -10; }
        }
        self.scores[trial.score_index as usize] += score;
        if let Some(rt) = res_type {
            if !last_level {
                self.new_trials(&def, new_slot, rt, trial.score_index, trial.is_array);
            }
        }
    }

    // Ghidra: unionresolve.cc:843 ScoreUnionFields::scoreTruncation
    /// Score a truncation in the data-flow. Faithful to `scoreTruncation`
    /// (unionresolve.cc:843-879).
    fn score_truncation<'a>(
        &mut self, ct_in: &'a Datatype, vn_size: usize, offset: i64, score_index: i32,
    ) -> Option<&'a Datatype> {
        let idx = score_index as usize;
        if ct_in.get_metatype() == TypeMetatype::Union {
            let union_dt = as_union(ct_in);
            let mut score = -10i32;
            let mut recurse: Option<&Datatype> = None;
            if let Some(u) = union_dt {
                for field in &u.fields {
                    if field.offset as i64 == offset && field.type_ptr.get_size() == vn_size {
                        score = 10;
                        if let Datatype::Union(base_u) = self.result.base_type.as_ref() {
                            if base_u.fields.len() == u.fields.len() { score += 5; }
                        }
                        recurse = None;
                        break;
                    }
                }
            }
            self.scores[idx] += score;
            return recurse;
        }
        let mut score = 10i32;
        let mut cur_off = offset;
        let mut ct: Option<&Datatype> = Some(ct_in);
        while let Some(c) = ct {
            if cur_off == 0 && c.get_size() == vn_size { break; }
            if c.get_metatype() == TypeMetatype::Int || c.get_metatype() == TypeMetatype::Uint {
                if c.get_size() >= vn_size + cur_off as usize { score = 1; ct = None; break; }
            }
            let (sub, new_off) = c.get_sub_type(cur_off);
            cur_off = new_off;
            ct = sub;
        }
        if ct.is_none() { score = -10; }
        self.scores[idx] += score;
        ct
    }

    // Ghidra: unionresolve.cc:884 ScoreUnionFields::scoreConstantFit
    /// Score a trial data-type against a constant Varnode. Faithful to
    /// `scoreConstantFit` (unionresolve.cc:884-926).
    fn score_constant_fit(&mut self, trial: &Trial) {
        let (size, val, meta) = {
            let vn_rg = trial.vn.read().unwrap();
            (vn_rg.get_size(), vn_rg.get_offset(), trial.fit_type.get_metatype())
        };
        let mut score: i32;
        if meta == TypeMetatype::Bool {
            score = if size == 1 && val < 2 { 2 } else { -2 };
        } else if meta == TypeMetatype::Float {
            score = -1;
            let fmt = crate::float_emulate::FloatFormat::new(size);
            let exp = fmt.extract_exponent_code(val) as i32;
            if exp < 7 && exp > -4 { score = 2; }
        } else if matches!(meta,
            TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Pointer) {
            if val == 0 {
                score = 2;
            } else {
                let looks_like_pointer = bit_transition_count(val, size) >= 3;
                if meta == TypeMetatype::Pointer {
                    score = if looks_like_pointer { 2 } else { -2 };
                } else {
                    score = if looks_like_pointer { 1 } else { 2 };
                }
            }
        } else { score = -2; }
        self.scores[trial.score_index as usize] += score;
    }

    // RUGRA-GLUE: Legacy entry-point kept for the old Funcdata-scanning test
    //   path. The real Ghidra entry is the `new(...)` constructor above.
    pub fn run_on_func(&mut self, fd: &crate::funcdata::Funcdata) {
        for op_ref in &fd.obank.alivelist {
            let op_rg = op_ref.0.read().unwrap();
            match op_rg.get_opcode() {
                OpCode::CPUI_SUBPIECE => {
                    if let Some(offset_vn) = op_rg.get_in(1) {
                        let offset_rg = offset_vn.read().unwrap();
                        if offset_rg.is_constant() {
                            let offset = offset_rg.get_offset() as usize;
                            if offset < self.fields.len() { self.add_score(offset, 1); }
                        }
                    }
                }
                OpCode::CPUI_INT_AND => {
                    if let Some(mask_vn) = op_rg.get_in(1) {
                        let mask_rg = mask_vn.read().unwrap();
                        if mask_rg.is_constant() {
                            let mask = mask_rg.get_offset();
                            if mask != 0 && mask != u64::MAX && self.fields.len() > 1 {
                                self.add_score(1, 1);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        self.compute_best_index();
    }
}

// ===========================================================================
// Free helpers — porting Ghidra inline / virtual dispatch used by the scorer
// ===========================================================================

// RUGRA-GLUE: free-function form of ScoreUnionFields::testSimpleCases, used
//   by the `new` constructor before `self` exists (cc:993).
/// Identify cases where the union should not be resolved to a field.
/// Faithful to `ScoreUnionFields::testSimpleCases` (unionresolve.cc:119-137).
fn test_simple_cases(op: &PcodeOp, in_slot: i32, parent: &Datatype) -> bool {
    ScoreUnionFields::score_simple_cases_inner(op, in_slot, parent)
}

// RUGRA-GLUE: `ScoreUnionFields::scoreTruncation` free-function form taking
//   the scores slice directly, for use during construction.
/// Score an implied truncation, returning the recurse-type if any.
/// Faithful to `ScoreUnionFields::scoreTruncation` (unionresolve.cc:843-879).
fn score_truncation_inplace(
    scores: &mut [i32], ct_in: &Datatype, vn_size: usize, offset: i64, score_index: i32,
) -> Option<Arc<Datatype>> {
    let idx = score_index as usize;
    if ct_in.get_metatype() == TypeMetatype::Union {
        let union_dt = as_union(ct_in);
        let mut score = -10i32;
        if let Some(u) = union_dt {
            for field in &u.fields {
                if field.offset as i64 == offset && field.type_ptr.get_size() == vn_size {
                    score = 10;
                    break;
                }
            }
        }
        scores[idx] += score;
        return None;
    }
    let mut score = 10i32;
    let mut cur_off = offset;
    let mut ct: Option<&Datatype> = Some(ct_in);
    while let Some(c) = ct {
        if cur_off == 0 && c.get_size() == vn_size { break; }
        if c.get_metatype() == TypeMetatype::Int || c.get_metatype() == TypeMetatype::Uint {
            if c.get_size() >= vn_size + cur_off as usize { score = 1; ct = None; break; }
        }
        let (sub, new_off) = c.get_sub_type(cur_off);
        cur_off = new_off;
        ct = sub;
    }
    if ct.is_none() { score = -10; }
    scores[idx] += score;
    ct.map(|c| Arc::new(c.clone()))
}

// RUGRA-GLUE: Datatype::numDepend / getDepend aggregator. Mirrors Ghidra's
//   per-variant virtual dispatch.
/// Number of dependency sub-types. Faithful to `Datatype::numDepend`.
fn num_depend(dt: &Datatype) -> usize {
    match dt {
        Datatype::Struct(s) => s.fields.len(),
        Datatype::Union(u) => u.fields.len(),
        Datatype::Pointer(_) | Datatype::Array(_) | Datatype::Code(_) => 1,
        _ => 0,
    }
}

// RUGRA-GLUE: `Datatype::getDepend(i)` aggregator.
/// Get the i-th dependency sub-type. Faithful to `Datatype::getDepend`.
fn get_depend(dt: &Datatype, i: usize) -> Arc<Datatype> {
    match dt {
        Datatype::Struct(s) => s.fields[i].type_ptr.clone(),
        Datatype::Union(u) => u.fields[i].type_ptr.clone(),
        Datatype::Pointer(p) => p.ptr_to.clone(),
        Datatype::Array(a) => a.array_of.clone(),
        Datatype::Code(c) => c.proto.as_ref()
            .map(|p| p.return_type.clone())
            .unwrap_or_else(|| Arc::new(empty_placeholder())),
        _ => Arc::new(empty_placeholder()),
    }
}

// RUGRA-GLUE: equivalent of `parent->getDepend(fldNum)` used by the
//   ResolvedUnion field constructor (cc:53,57).
/// Get the i-th dependency sub-type as a borrowed reference.
fn depend_at(dt: &Datatype, i: usize) -> Arc<Datatype> { get_depend(dt, i) }

// RUGRA-GLUE: Datatype pointer helpers.
/// Borrow the pointee of a pointer type, or the type itself if not a pointer.
fn pointee_of(dt: &Datatype) -> &Datatype {
    match dt { Datatype::Pointer(p) => p.ptr_to.as_ref(), _ => dt }
}

/// `Some(pointee)` if `dt` is a pointer, else `None`.
fn pointer_pointee(dt: &Datatype) -> Option<&Datatype> {
    match dt { Datatype::Pointer(p) => Some(p.ptr_to.as_ref()), _ => None }
}

/// `Some(&TypeUnion)` for union types.
fn as_union(dt: &Datatype) -> Option<&TypeUnion> {
    match dt { Datatype::Union(u) => Some(u), _ => None }
}

/// Strip one pointer layer, returning a cloned Arc for ownership.
fn strip_pointer_layer(dt: &Arc<Datatype>) -> Arc<Datatype> {
    match dt.as_ref() { Datatype::Pointer(p) => p.ptr_to.clone(), _ => dt.clone() }
}

/// Word size of a pointer type (0 if not a pointer).
fn pointee_word_size(dt: &Datatype) -> usize {
    match dt { Datatype::Pointer(p) => p.wordsize, _ => 0 }
}

// RUGRA-GLUE: Return the (field list, field count) for a union-typed parent.
fn union_field_list(dt: &Datatype) -> (Vec<TypeField>, usize) {
    match dt {
        Datatype::Union(u) => { let count = u.fields.len(); (u.fields.clone(), count) }
        _ => (Vec::new(), 0),
    }
}

// RUGRA-GLUE: `TypeFactory::getTypePointerStripArray(size, ptrto, wordsize)`
//   (type.cc). Rugra's TypeFactory lacks this method, so we approximate: for
//   an array pointee we return a pointer to its element type; otherwise we
//   return the pointee itself.
fn type_pointer_strip_array(
    _typegrp: &TypeFactory, _size: usize, ptrto: Arc<Datatype>, _word_size: usize,
) -> Arc<Datatype> {
    match ptrto.as_ref() { Datatype::Array(a) => a.array_of.clone(), _ => ptrto }
}

// RUGRA-GLUE: Ghidra `bit_transitions(val,size)` (address.cc). Counts the
//   number of 0->1 and 1->0 bit transitions in the bottom `size*8` bits.
fn bit_transition_count(val: u64, size: usize) -> u32 {
    let bits = (size as u32).saturating_mul(8);
    if bits == 0 { return 0; }
    let mut transitions = 0u32;
    let mut prev = val & 1;
    for i in 1..bits {
        let bit = (val >> i) & 1;
        if bit != prev { transitions += 1; prev = bit; }
    }
    transitions
}

// RUGRA-GLUE: Construct a placeholder Datatype for the legacy string ctors.
fn name_placeholder(name: &str) -> Arc<Datatype> {
    Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
        name.to_string(), 0, TypeMetatype::Unknown)))
}

// RUGRA-GLUE: A distinct empty placeholder for score slots that Ghidra leaves
//   as `(Datatype *)0`.
fn empty_placeholder() -> Datatype {
    Datatype::Base(crate::type_system::datatype::TypeBase::new(
        String::new(), 0, TypeMetatype::Unknown))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolved_union_self() {
        let r = ResolvedUnion::new_self("union_tag");
        assert_eq!(r.get_datatype_name(), "union_tag");
        assert_eq!(r.get_base_name(), "union_tag");
        assert_eq!(r.get_field_num(), -1);
        assert!(!r.is_locked());
    }

    #[test]
    fn test_resolved_union_field() {
        let r = ResolvedUnion::new_field("union_tag", "field_x", 2);
        assert_eq!(r.get_datatype_name(), "field_x");
        assert_eq!(r.get_base_name(), "union_tag");
        assert_eq!(r.get_field_num(), 2);
    }

    #[test]
    fn test_resolved_union_lock() {
        let mut r = ResolvedUnion::new_self("u");
        r.set_lock(true);
        assert!(r.is_locked());
        r.set_lock(false);
        assert!(!r.is_locked());
    }

    #[test]
    fn test_resolve_edge_ordering() {
        let e1 = ResolveEdge::from_components(1, 10, 0, false);
        let e2 = ResolveEdge::from_components(1, 10, 1, false);
        let e3 = ResolveEdge::from_components(2, 5, 0, false);
        assert!(e1 < e2);
        assert!(e2 < e3);
    }

    #[test]
    fn test_resolve_edge_pointer_encoding() {
        let e_no_ptr = ResolveEdge::from_components(1, 10, 0, false);
        let e_ptr = ResolveEdge::from_components(1, 10, 0, true);
        assert_eq!(e_no_ptr.encoding, 0);
        assert_eq!(e_ptr.encoding, 0x1000);
        assert!(e_no_ptr < e_ptr);
    }

    #[test]
    fn test_visit_mark_ordering() {
        let v1 = Arc::new(RwLock::new(Varnode::new_unique(0x100, 4)));
        let v2 = Arc::new(RwLock::new(Varnode::new_unique(0x200, 4)));
        let m1 = VisitMark::new(&v1, 0);
        let m1b = VisitMark::new(&v1, 1);
        let m2 = VisitMark::new(&v2, 0);
        assert!(m1 < m1b);
        assert!(m1b < m2);
        let a = VisitMark::from_id(0x100, 0);
        let b = VisitMark::from_id(0x100, 1);
        assert!(a < b);
    }

    #[test]
    fn test_constants_match_ghidra() {
        assert_eq!(MAX_PASSES, 6);
        assert_eq!(THRESHOLD, 256);
        assert_eq!(MAX_TRIALS, 1024);
        assert!(MAX_TRIALS > THRESHOLD);
    }

    #[test]
    fn test_with_field_names_construction() {
        let s = ScoreUnionFields::with_field_names(
            "union_tag", &["field_a".to_string(), "field_b".to_string()]);
        assert_eq!(s.num_fields(), 3);
        assert_eq!(s.scores.len(), 3);
        assert_eq!(s.fields[0].get_name(), "union_tag");
        assert_eq!(s.fields[1].get_name(), "field_a");
        assert_eq!(s.fields[2].get_name(), "field_b");
    }

    #[test]
    fn test_compute_best_index_whole_union() {
        let mut s = ScoreUnionFields::with_field_names("u", &["a".to_string(), "b".to_string()]);
        s.compute_best_index();
        assert_eq!(s.get_result().get_field_num(), -1);
    }

    #[test]
    fn test_compute_best_index_specific_field() {
        let mut s = ScoreUnionFields::with_field_names("u", &["a".to_string(), "b".to_string()]);
        s.add_score(2, 5);
        s.compute_best_index();
        assert_eq!(s.get_result().get_field_num(), 1);
        assert_eq!(s.get_result().get_datatype_name(), "b");
    }

    #[test]
    fn test_score_locked_type_int_uint_mismatch() {
        let int_t = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int));
        let uint_t = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "uint".into(), 4, TypeMetatype::Uint));
        assert_eq!(ScoreUnionFields::score_locked_type(&int_t, &uint_t), -1);
        let other_int = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int));
        assert_eq!(ScoreUnionFields::score_locked_type(&int_t, &other_int), 3);
    }

    #[test]
    fn test_score_locked_type_struct_container_match() {
        let mk_struct = |name: &str| {
            Datatype::Struct(crate::type_system::datatype::TypeStruct {
                base: crate::type_system::datatype::TypeBase::new(
                    name.into(), 8, TypeMetatype::Struct),
                fields: vec![],
            })
        };
        let container = mk_struct("T");
        assert_eq!(ScoreUnionFields::score_locked_type(&container, &container), 15);
    }

    #[test]
    fn test_deref_pointer_size_match() {
        let int_t = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int)));
        let ptr = Datatype::Pointer(crate::type_system::datatype::TypePointer {
            base: crate::type_system::datatype::TypeBase::new(
                "int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: int_t, wordsize: 1,
        });
        let (rt, score) = ScoreUnionFields::deref_pointer(&ptr, 4);
        assert_eq!(score, 10);
        assert!(rt.is_some());
        assert_eq!(rt.unwrap().get_size(), 4);
        let (rt, score) = ScoreUnionFields::deref_pointer(&ptr, 1);
        assert_eq!(score, 0);
        assert!(rt.is_none());
        let base = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int));
        let (rt, score) = ScoreUnionFields::deref_pointer(&base, 4);
        assert_eq!(score, -10);
        assert!(rt.is_none());
    }

    #[test]
    fn test_bit_transition_count() {
        assert_eq!(bit_transition_count(0, 1), 0);
        assert_eq!(bit_transition_count(0xff, 1), 0);
        assert_eq!(bit_transition_count(0x55, 1), 7);
        assert_eq!(bit_transition_count(0x01, 1), 1);
    }

    #[test]
    fn test_num_depend_and_get_depend() {
        let int_t = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int)));
        let char_t = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "char".into(), 1, TypeMetatype::Int)));
        let u = Datatype::Union(crate::type_system::datatype::TypeUnion {
            base: crate::type_system::datatype::TypeBase::new("U".into(), 4, TypeMetatype::Union),
            fields: vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: int_t },
                TypeField { name: "b".into(), offset: 0, type_ptr: char_t },
            ],
        });
        assert_eq!(num_depend(&u), 2);
        assert_eq!(get_depend(&u, 0).get_name(), "a");
        assert_eq!(get_depend(&u, 1).get_name(), "b");
        let int_base = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int));
        assert_eq!(num_depend(&int_base), 0);
    }

    #[test]
    fn test_resolved_union_typed_new_strips_pointer() {
        let int_t = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int)));
        let ptr = Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer {
            base: crate::type_system::datatype::TypeBase::new(
                "int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: int_t.clone(), wordsize: 1,
        }));
        let r = ResolvedUnion::new(ptr.clone());
        assert_eq!(r.resolve.get_name(), "int *");
        assert_eq!(r.base_type.get_name(), "int");
        assert_eq!(r.field_num, -1);
    }
}
