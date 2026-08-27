# collapseAll phase archaeology (2026-08-28)

Oracle is Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`.

## Provenance

`git log -S collapse_all_5step --all -- src/blockaction.rs` identifies
`4fe8f0d74db2cfe3068d21492a2bb771ef935272` (2026-07-17) as the introduction.
Its stated motivation was to expose the literal oracle schedule behind the
then-default Rugra seven-phase driver: `orderLoopBodies`, `collapseConditions`,
`collapseInternal(NULL)`, then repeated `selectGoto` and targeted
`collapseInternal`. The implementation was initially flag-gated by
`RUGRA_5STEP=1`; the commit explicitly retained seven-phase because five
functions timed out.

The follow-up history records the causal hardening rather than an oracle
algorithm: `709d1c77` inserted `structure_loops_first` after the conditions
phase to stop loop-head spinning; `a00c3659` inserted a TraceDAG prepass;
`3c336f0f` temporarily made five-step default after reporting 24/24 curl
functions and 953/953 tests, while retaining seven-phase as `RUGRA_7PHASE=1`;
subsequent merges restored the seven-phase route as the safer baseline. The
later irreducible work (`4a4bd5c6`, `b9fcfc3a`, `2400ea65`, `f72d1dec`,
`751aef31`, and `4621a4db`) changes ownership/guards and does not establish
that the extra phases are oracle behavior.

## Oracle pass structure

`blockaction.cc:1768-1850` shows that `collapseInternal` is itself a nested
fixpoint: an outer `do` wraps an inner `do`/`while(change)`, each inner sweep
visits graph indices in ascending order and tries exactly
`Goto, Cat, ProperIf, IfElse, WhileDo, DoWhile, InfLoop, Switch`. Only after
that inner fixpoint does a second pass try `IfNoExit`, then `CaseFallthru`,
breaking after the first match; `fullchange` restarts the outer loop.

`blockaction.cc:1877-1893` then performs `finaltrace=false`,
`clearVisitCount`, `orderLoopBodies`, `collapseConditions`,
`collapseInternal(NULL)`, and `while (isolated_count < graph.getSize())`
`selectGoto()` followed by targeted `collapseInternal(targetbl)`. Thus the
oracle is not literally a fixed five-pass or seven-pass pipeline: it is a
looping state machine whose repeated rounds are inside `collapseInternal` and
whose goto loop continues until all blocks isolate. The oracle has no
`structure_loops_first`, batch goto cascade, deadline, or timeout fallback at
these lines. Any such mechanism must be treated as a Rugra compatibility
projection and independently justified, not as evidence of oracle pass order.
