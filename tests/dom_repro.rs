//! Regression tests for `BlockGraph::build_dom_tree` (Cooper-Harvey-Kennedy).
//!
//! These exercise the idom-seeding fix for multi-root / disconnected CFGs.
//! See `src/block.rs:1765` (seed every CFG root, not just `rpo[0]`).

use rugra::address::Address;
use rugra::block::{BlockBasic, BlockGraph, FlowBlock};
use std::sync::{Arc, RwLock, Weak};

fn mk(i: i32) -> Arc<RwLock<BlockBasic>> {
    Arc::new(RwLock::new(BlockBasic::new(i, Address::new(i as u64))))
}

/// Compare a `Weak<dyn FlowBlock>` against an `Arc<BlockBasic>` by raw
/// allocation pointer (the trait object's data pointer is the `RwLock`).
fn weak_points_to(
    w: &Weak<RwLock<dyn FlowBlock + Send + Sync>>,
    arc: &Arc<RwLock<BlockBasic>>,
) -> bool {
    let upgraded: Arc<RwLock<dyn FlowBlock + Send + Sync>> = match w.upgrade() {
        Some(u) => u,
        None => return false,
    };
    let arc_dyn: Arc<RwLock<dyn FlowBlock + Send + Sync>> = arc.clone();
    // Arc::ptr_eq works on same-type Arcs; compare via the raw allocation.
    Arc::ptr_eq(&upgraded, &arc_dyn)
}

/// Returns (number of blocks with an idom set, number without).
fn idom_counts(g: &BlockGraph) -> (usize, usize) {
    let mut set = 0usize;
    let mut neg = 0usize;
    for b in &g.blocks {
        if b.read().unwrap().get_immed_dom().is_some() {
            set += 1;
        } else {
            neg += 1;
        }
    }
    (set, neg)
}

/// Every non-root block must end up with an immediate dominator. Roots
/// (size_in == 0) correctly have none. Returns the list of blocks that are
/// missing an idom despite having at least one predecessor.
fn blocks_missing_idom(g: &BlockGraph) -> Vec<i32> {
    let mut bad = Vec::new();
    for b in &g.blocks {
        let r = b.read().unwrap();
        if r.size_in() > 0 && r.get_immed_dom().is_none() {
            bad.push(r.get_index());
        }
    }
    bad
}

#[test]
fn dom_diamond() {
    let mut g = BlockGraph::new();
    let e = mk(0);
    let a = mk(1);
    let b = mk(2);
    let j = mk(3);
    g.add_block(e.clone());
    g.add_block(a.clone());
    g.add_block(b.clone());
    g.add_block(j.clone());
    g.add_edge(e.clone(), a.clone());
    g.add_edge(e.clone(), b.clone());
    g.add_edge(a.clone(), j.clone());
    g.add_edge(b.clone(), j.clone());
    g.build_dom_tree();

    // Exactly one root (entry e) has no idom; all others are set.
    let (set, neg) = idom_counts(&g);
    assert_eq!(set, 3);
    assert_eq!(neg, 1);
    assert!(j.read().unwrap().get_immed_dom().is_some());
    assert!(blocks_missing_idom(&g).is_empty());
}

#[test]
fn dom_chain_with_back_edge_reversed_vector_order() {
    // Vector order is the reverse of topological order, to confirm RPO is
    // independent of storage order. entry -> d -> c -> b -> a, plus a -> c.
    let mut g = BlockGraph::new();
    let entry = mk(0);
    let a = mk(1);
    let b = mk(2);
    let c = mk(3);
    let d = mk(4);
    g.add_block(entry.clone());
    g.add_block(a.clone());
    g.add_block(b.clone());
    g.add_block(c.clone());
    g.add_block(d.clone());
    g.add_edge(entry.clone(), d.clone());
    g.add_edge(d.clone(), c.clone());
    g.add_edge(c.clone(), b.clone());
    g.add_edge(b.clone(), a.clone());
    g.add_edge(a.clone(), c.clone()); // back edge
    g.build_dom_tree();

    assert!(blocks_missing_idom(&g).is_empty());
}

/// The core regression: a CFG with two `size_in == 0` roots (e.g. an
/// unreachable region survives in the graph). Before the fix, the second
/// root landed at RPO position > 0 with `idom = -1`, cascading -1 across
/// every reachable block in both regions (only 1 of 5 blocks got an idom).
#[test]
fn dom_two_roots_unreachable_region() {
    let mut g = BlockGraph::new();
    // Region 1: e(0) -> x(1) -> y(2)
    let e = mk(0);
    let x = mk(1);
    let y = mk(2);
    // Region 2 (unreachable from region 1): p(3) -> q(4), p has size_in == 0
    let p = mk(3);
    let q = mk(4);
    for b in [&e, &x, &y, &p, &q] {
        g.add_block(b.clone());
    }
    g.add_edge(e.clone(), x.clone());
    g.add_edge(x.clone(), y.clone());
    g.add_edge(p.clone(), q.clone());
    g.build_dom_tree();

    // Both roots (e, p) have no idom; x, y, q must all be set.
    let bad = blocks_missing_idom(&g);
    assert!(
        bad.is_empty(),
        "blocks with predecessors but no idom: {:?}",
        bad
    );
    let (set, neg) = idom_counts(&g);
    assert_eq!(set, 3, "expected x, y, q to have idom set");
    assert_eq!(neg, 2, "expected roots e, p to have no idom");

    // Dominator correctness checks.
    // x's idom is e; y's idom is x; q's idom is p.
    assert!(weak_points_to(
        &x.read().unwrap().get_immed_dom().unwrap(),
        &e
    ));
    assert!(weak_points_to(
        &y.read().unwrap().get_immed_dom().unwrap(),
        &x
    ));
    assert!(weak_points_to(
        &q.read().unwrap().get_immed_dom().unwrap(),
        &p
    ));
}

/// Three roots interleaved in vector order with reachable successors. This
/// is the shape that produced the reported 37/152 failure (many reachable
/// blocks stuck at idom = -1 because their root was not seeded).
#[test]
fn dom_many_roots_interleaved() {
    let mut g = BlockGraph::new();
    // 6 blocks: roots at 0, 2, 4; each root has one successor at 1, 3, 5.
    let blocks: Vec<_> = (0..6).map(mk).collect();
    for b in &blocks {
        g.add_block(b.clone());
    }
    g.add_edge(blocks[0].clone(), blocks[1].clone());
    g.add_edge(blocks[2].clone(), blocks[3].clone());
    g.add_edge(blocks[4].clone(), blocks[5].clone());
    g.build_dom_tree();

    let bad = blocks_missing_idom(&g);
    assert!(bad.is_empty(), "blocks missing idom: {:?}", bad);
    let (set, neg) = idom_counts(&g);
    assert_eq!(set, 3, "successors 1, 3, 5 should have idom");
    assert_eq!(neg, 3, "roots 0, 2, 4 should have no idom");
}
