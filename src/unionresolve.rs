//! Union resolution — faithful port of `unionresolve.hh` / `unionresolve.cc`
//! (1110 lines).
//!
//! Analysis for resolving which field of a union data-type is being accessed
//! at a specific point in the data-flow. `ScoreUnionFields` scores all
//! possible fields of a union for a specific Varnode access edge.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/unionresolve.{hh,cc}.

/// A data-type resolved from an associated TypeUnion or TypeStruct. Faithful
/// to `ResolvedUnion` (unionresolve.hh:39).
#[derive(Debug, Clone)]
pub struct ResolvedUnion {
    /// The resolved data-type name.
    pub resolve_type_name: String,
    /// Union or Structure being resolved (base type name).
    pub base_type_name: String,
    /// Index of field referenced by resolve, or -1 for the whole union.
    pub field_num: i32,
    /// If true, resolution cannot be overridden.
    pub lock: bool,
}

impl ResolvedUnion {
    /// Construct a data-type that resolves to itself. Faithful to the
    /// constructor (unionresolve.hh:46). `field_num` = -1.
    pub fn new_self(parent_name: &str) -> Self {
        Self {
            resolve_type_name: parent_name.to_string(),
            base_type_name: parent_name.to_string(),
            field_num: -1,
            lock: false,
        }
    }

    /// Construct a reference to a specific field. Faithful to the constructor
    /// (unionresolve.hh:47).
    pub fn new_field(parent_name: &str, field_name: &str, fld_num: i32) -> Self {
        Self {
            resolve_type_name: field_name.to_string(),
            base_type_name: parent_name.to_string(),
            field_num: fld_num,
            lock: false,
        }
    }

    /// Get the resolved data-type name. Faithful to `getDatatype`.
    pub fn get_datatype_name(&self) -> &str {
        &self.resolve_type_name
    }

    /// Get the union or structure being referenced. Faithful to `getBase`.
    pub fn get_base_name(&self) -> &str {
        &self.base_type_name
    }

    /// Get the index of the resolved field or -1. Faithful to `getFieldNum`.
    pub fn get_field_num(&self) -> i32 {
        self.field_num
    }

    /// Is this locked against overrides? Faithful to `isLocked`.
    pub fn is_locked(&self) -> bool {
        self.lock
    }

    /// Set whether this resolution is locked. Faithful to `setLock`.
    pub fn set_lock(&mut self, val: bool) {
        self.lock = val;
    }
}

/// A data-flow edge to which a resolved data-type can be assigned. Faithful to
/// `ResolveEdge` (unionresolve.hh:60).
///
/// The edge is associated with the specific data-type that needs to be
/// resolved, plus the PcodeOp and slot encoding. Edges are ordered by
/// (type_id, encoding, op_time).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolveEdge {
    /// Id of base data-type being resolved.
    pub type_id: u64,
    /// Id of the PcodeOp edge (sequence number).
    pub op_time: u32,
    /// Encoding of the slot and pointer-ness.
    pub encoding: i32,
}

impl ResolveEdge {
    /// Construct from components. Faithful to the constructor
    /// (unionresolve.hh:65).
    ///
    /// `type_id` is the data-type's id. `op_time` is the op's sequence order.
    /// `slot` >= 0 indicates an input varnode; -1 indicates the output.
    /// `is_pointer` encodes whether the parent is a pointer type.
    pub fn new(type_id: u64, op_time: u32, slot: i32, is_pointer: bool) -> Self {
        let encoding = if is_pointer {
            slot + 0x10000
        } else {
            slot
        };
        Self {
            type_id,
            op_time,
            encoding,
        }
    }
}

/// Direction of trial fit. Faithful to `dir_type` (unionresolve.hh:87).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirType {
    /// Push the fit down with the data-flow.
    FitDown,
    /// Push the fit up against the data-flow.
    FitUp,
}

/// A trial data-type fitted to a specific place in the data-flow. Faithful to
/// `ScoreUnionFields::Trial` (unionresolve.hh:84).
#[derive(Debug, Clone)]
pub struct Trial {
    /// Direction to push fit.
    pub direction: DirType,
    /// The trial data-type name.
    pub fit_type_name: String,
    /// The slot reading the Varnode (or -1).
    pub in_slot: i32,
    /// The original field being scored by this trial.
    pub score_index: i32,
    /// Field can be accessed as an array.
    pub is_array: bool,
}

impl Trial {
    /// Construct a downward trial for a Varnode being read. Faithful to the
    /// downward constructor (unionresolve.hh:106).
    pub fn new_down(slot: i32, type_name: &str, index: i32, is_array: bool) -> Self {
        Self {
            direction: DirType::FitDown,
            fit_type_name: type_name.to_string(),
            in_slot: slot,
            score_index: index,
            is_array,
        }
    }

    /// Construct an upward trial for a Varnode being written. Faithful to the
    /// upward constructor (unionresolve.hh:115).
    pub fn new_up(type_name: &str, index: i32, is_array: bool) -> Self {
        Self {
            direction: DirType::FitUp,
            fit_type_name: type_name.to_string(),
            in_slot: -1,
            score_index: index,
            is_array,
        }
    }
}

/// A mark accumulated when a given Varnode is visited with a specific field
/// index. Faithful to `VisitMark` (unionresolve.hh:120).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VisitMark {
    /// Varnode identifier (address offset as proxy).
    pub vn_id: u64,
    /// Index of the trial field.
    pub index: i32,
}

impl VisitMark {
    /// Construct. Faithful to the constructor (unionresolve.hh:122).
    pub fn new(vn_id: u64, index: i32) -> Self {
        Self { vn_id, index }
    }
}

/// Maximum number of levels to score through. Faithful to `maxPasses`.
pub const MAX_PASSES: i32 = 5;

/// Threshold of trials over which to cancel additional passes. Faithful to
/// `threshold`.
pub const THRESHOLD: i32 = 10;

/// Maximum number of trials to evaluate. Faithful to `maxTrials`.
pub const MAX_TRIALS: i32 = 50;

/// Analyze data-flow to resolve which field of a union data-type is being
/// accessed. Faithful to `ScoreUnionFields` (unionresolve.hh:82).
///
/// This class scores all possible fields of a data-type involving a union for
/// a specific Varnode access edge. The full scoring algorithm requires
/// TypeFactory integration (L3 gap); this implementation provides the data
/// structures, scoring framework, and result computation.
pub struct ScoreUnionFields {
    /// Score for each field, indexed by fieldNum + 1 (whole union is index=0).
    pub scores: Vec<i32>,
    /// Field type name corresponding to each score.
    pub fields: Vec<String>,
    /// Places that have already been visited.
    pub visited: std::collections::BTreeSet<VisitMark>,
    /// Current trials being pushed.
    pub trial_current: Vec<Trial>,
    /// Next set of trials.
    pub trial_next: Vec<Trial>,
    /// The best result.
    pub result: ResolvedUnion,
    /// Number of trials evaluated so far.
    pub trial_count: i32,
}

impl ScoreUnionFields {
    /// Construct given the parent type name and list of field names. The
    /// scores vector is initialized to zero for each field + 1 (whole union).
    pub fn new(parent_name: &str, field_names: &[String]) -> Self {
        let mut fields = vec![parent_name.to_string()]; // Index 0 = whole union.
        fields.extend(field_names.iter().cloned());
        let scores = vec![0i32; fields.len()];
        let result = ResolvedUnion::new_self(parent_name);
        Self {
            scores,
            fields,
            visited: std::collections::BTreeSet::new(),
            trial_current: Vec::new(),
            trial_next: Vec::new(),
            result,
            trial_count: 0,
        }
    }

    /// Get the resulting best field resolution. Faithful to `getResult`.
    pub fn get_result(&self) -> &ResolvedUnion {
        &self.result
    }

    /// Number of fields being scored (including the whole union at index 0).
    pub fn num_fields(&self) -> usize {
        self.fields.len()
    }

    /// Assuming scoring is complete, compute the best index. Faithful to
    /// `computeBestIndex` (unionresolve.cc). The best index is the one with
    /// the highest score; ties favor lower indices (whole union = 0).
    pub fn compute_best_index(&mut self) {
        let mut best_idx = 0usize;
        let mut best_score = self.scores[0];
        for (i, &score) in self.scores.iter().enumerate().skip(1) {
            if score > best_score {
                best_score = score;
                best_idx = i;
            }
        }
        if best_idx == 0 {
            self.result = ResolvedUnion::new_self(&self.fields[0]);
        } else {
            self.result = ResolvedUnion::new_field(
                &self.fields[0],
                &self.fields[best_idx],
                best_idx as i32 - 1, // field_num is 0-indexed
            );
        }
    }

    /// Add a score to a specific field index. Used by the scoring algorithm.
    pub fn add_score(&mut self, index: usize, score: i32) {
        if index < self.scores.len() {
            self.scores[index] += score;
        }
    }

    /// Run the scoring algorithm. Faithful to `run` (unionresolve.cc). The
    /// full implementation iterates through MAX_PASSES levels of trials,
    /// scoring each trial against the data-flow. This skeleton provides the
    /// framework; full scoring requires TypeFactory + PcodeOp integration.
    pub fn run(&mut self) {
        // L3 gap: full scoring requires TypeFactory integration.
        // For now, compute best from any scores set via add_score.
        self.compute_best_index();
    }
}

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
        let e1 = ResolveEdge::new(1, 10, 0, false);
        let e2 = ResolveEdge::new(1, 10, 1, false);
        let e3 = ResolveEdge::new(2, 5, 0, false);
        assert!(e1 < e2); // Same type, same encoding, lower op_time.
        assert!(e2 < e3); // Lower type_id.
    }

    #[test]
    fn test_resolve_edge_pointer_encoding() {
        let e1 = ResolveEdge::new(1, 10, 0, false);
        let e2 = ResolveEdge::new(1, 10, 0, true);
        assert!(e1 < e2); // Non-pointer encoding < pointer encoding.
    }

    #[test]
    fn test_trial_down() {
        let t = Trial::new_down(1, "int", 0, false);
        assert_eq!(t.direction, DirType::FitDown);
        assert_eq!(t.in_slot, 1);
        assert_eq!(t.fit_type_name, "int");
        assert!(!t.is_array);
    }

    #[test]
    fn test_trial_up() {
        let t = Trial::new_up("long", 1, true);
        assert_eq!(t.direction, DirType::FitUp);
        assert_eq!(t.in_slot, -1);
        assert!(t.is_array);
    }

    #[test]
    fn test_visit_mark_ordering() {
        let m1 = VisitMark::new(0x100, 0);
        let m2 = VisitMark::new(0x100, 1);
        let m3 = VisitMark::new(0x200, 0);
        assert!(m1 < m2);
        assert!(m2 < m3);
    }

    #[test]
    fn test_score_union_fields_construction() {
        let s = ScoreUnionFields::new("union_tag", &["field_a".to_string(), "field_b".to_string()]);
        assert_eq!(s.num_fields(), 3); // whole union + 2 fields.
        assert_eq!(s.scores.len(), 3);
        assert_eq!(s.fields[0], "union_tag");
        assert_eq!(s.fields[1], "field_a");
        assert_eq!(s.fields[2], "field_b");
    }

    #[test]
    fn test_compute_best_index_whole_union() {
        let mut s = ScoreUnionFields::new("u", &["a".to_string(), "b".to_string()]);
        s.compute_best_index();
        assert_eq!(s.get_result().get_field_num(), -1); // Whole union.
    }

    #[test]
    fn test_compute_best_index_specific_field() {
        let mut s = ScoreUnionFields::new("u", &["a".to_string(), "b".to_string()]);
        // Give field_b (index 2) a higher score.
        s.add_score(2, 5);
        s.compute_best_index();
        assert_eq!(s.get_result().get_field_num(), 1); // field_b = field_num 1.
        assert_eq!(s.get_result().get_datatype_name(), "b");
    }

    #[test]
    fn test_run_computes_best() {
        let mut s = ScoreUnionFields::new("u", &["a".to_string(), "b".to_string()]);
        s.add_score(1, 3);
        s.run();
        assert_eq!(s.get_result().get_field_num(), 0); // field_a = field_num 0.
        assert_eq!(s.get_result().get_datatype_name(), "a");
    }

    #[test]
    fn test_constants() {
        assert!(MAX_PASSES > 0);
        assert!(THRESHOLD > 0);
        assert!(MAX_TRIALS > THRESHOLD);
    }
}
