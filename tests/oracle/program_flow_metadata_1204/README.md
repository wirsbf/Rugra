# Program flow metadata oracle (Ghidra 12.0.4)

This fixture captures the Java `Program` state that precedes the native
decompiler flow pipeline.  It runs only against the locked official Ghidra
12.0.4 release and never substitutes the C++/BFD loader for the Java producer.

Two fresh headless projects exercise mutually explicit option sets:

- `direct_only`: `Allow Conditional Jumps=false`; only the non-entry direct
  jump to `shared_ret` becomes `CALL_RETURN`.
- `conditional_enabled`: `Allow Conditional Jumps=true`; the direct and
  conditional jumps become `CALL_RETURN`.

Each lane records three independently observed states:

1. `pre_target_analyzers`: default analysis completed with **Shared Return
   Calls** and **Non-Returning Functions - Known** disabled by a pre-script.
2. `post_target_analyzers`: those exact analyzer classes were invoked in their
   priority order, before their Program changes were allowed to drain the
   remaining auto-analysis queue.
3. `analysis_queue_settled`: `AutoAnalysisManager.waitForAnalysis()` returned
   and Program events were flushed.

The snapshots preserve ordered function body ranges and instructions, native
and canonical-sorted references, raw and override-aware object p-code, raw and
override-aware packed p-code bytes, and ordered Program change records.  Event
records retain a single total delivery sequence; asynchronous dispatch-batch
boundaries are omitted because two fresh-project runs proved those boundaries
can coalesce differently without changing record order or Program state.  The
assembly makes `exit` return normally on purpose: its transition to no-return
is attributable to the name-driven analyzer, not instruction semantics.

Run from the repository root:

```bash
tools/run_program_flow_metadata_oracle.sh
```

The runner downloads the official GitHub release into a task-specific `/tmp`
cache if needed.  That persistent cache is required to contain only the
SHA-256-verified zip.  Every invocation extracts a fresh distribution beneath
its own `/var/tmp` directory, checks the application version, release name and
`application.revision.ghidra`, builds the ELF there, executes every lane twice,
and diffs the result against the checked-in oracle captures.  No release
archive, extracted distribution, object, ELF, or project database is tracked.

This fixture is deliberately `UNTESTED` globally until Rugra has the Program
metadata ingress and live Java-override consumer needed for a bilateral
comparison.  The captured analyzer-native projection is an exact oracle; the
API-seeded pointer/external, discontiguous-body, multi-flow-reference and
call-fixup lanes remain explicit residuals in the standard top-level
`tests/oracle/program_flow_metadata_1204.metadata.json` record.
