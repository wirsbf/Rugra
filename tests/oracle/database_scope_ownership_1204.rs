/*
 * Rugra capability projection for DATABASE-SCOPE-OWNERSHIP-FIXTURE-0001.
 *
 * This intentionally does not construct a parallel Scope/FunctionSymbol
 * shadow graph.  The pinned Rugra source has no concrete buildDatabase path,
 * FunctionSymbol does not own a Funcdata, Funcdata::new starts with no
 * Architecture or ScopeLocal, and Scope has neither Architecture nor Funcdata
 * back-references.  These are precisely the capabilities needed to express
 * the locked Ghidra oracle input.
 */

use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::funcdata::Funcdata;

fn main() {
    let architecture = Architecture::new();
    let function = Funcdata::new("fixture_function", Address::new(0x7e12_0400), 0);

    println!(
        "case=rugra_constructor_state|architecture_symboltab_present={}|funcdata_arch_present={}|funcdata_local_scope_present={}",
        u8::from(architecture.symboltab.is_some()),
        u8::from(function.arch.is_some()),
        u8::from(function.scope.is_some()),
    );
    println!(
        "case=missing_capability|build_database=missing_concrete_factory|functionsymbol_funcdata_owner=missing|scope_arch_backref=missing|scope_funcdata_backref=missing|explicit_scope_id_attach=missing|failure_ownership_contract=missing|destructor_cascade=missing"
    );
    println!("case=overall|status=MISMATCH");
}
