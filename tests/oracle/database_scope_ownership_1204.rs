/*
 * Rugra capability projection for DATABASE-SCOPE-OWNERSHIP-FIXTURE-0001.
 *
 * This intentionally does not construct a parallel Scope/FunctionSymbol
 * shadow graph.  It does exercise the real Database::find_create_scope API,
 * which supports explicit-id creation and repeat lookup.  The narrower gaps
 * are caller-owned Scope identity attachment and its exception ownership,
 * plus the absent concrete buildDatabase/FunctionSymbol/Funcdata ownership
 * chain.
 */

use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::database::Database;
use rugra::funcdata::Funcdata;

fn main() {
    let mut database = Database::new(true);
    let factory_id = 0x1204_0002;
    let created_id = database.find_create_scope(factory_id, "factory_ns", 0);
    let created_ptr = database
        .resolve_scope(created_id)
        .map(|scope| scope as *const _)
        .expect("find_create_scope did not register the created scope");
    let repeated_id = database.find_create_scope(factory_id, "ignored_name", 0);
    let repeated = database
        .resolve_scope(repeated_id)
        .expect("find_create_scope repeat did not resolve the scope");
    let repeated_ptr = repeated as *const _;
    let parent_child_alias = database
        .get_global_scope()
        .map(|scope| scope.children.contains(&factory_id))
        .unwrap_or(false);
    println!(
        "case=find_create_scope|id_matches={}|resolver_alias={}|repeat_alias={}|name_preserved={}|parent_id={}|parent_child_alias={}",
        u8::from(created_id == factory_id),
        u8::from(database.resolve_scope(factory_id).is_some()),
        u8::from(created_id == repeated_id && created_ptr == repeated_ptr),
        u8::from(repeated.get_name() == "factory_ns"),
        repeated.parent_id,
        u8::from(parent_child_alias),
    );

    let architecture = Architecture::new();
    let function = Funcdata::new("fixture_function", Address::new(0x7e12_0400), 0);

    println!(
        "case=rugra_constructor_state|architecture_symboltab_present={}|funcdata_arch_present={}|funcdata_local_scope_present={}",
        u8::from(architecture.symboltab.is_some()),
        u8::from(function.arch.is_some()),
        u8::from(function.scope.is_some()),
    );
    println!(
        "case=missing_capability|build_database=missing_concrete_factory|functionsymbol_funcdata_owner=missing|scope_arch_backref=missing|scope_funcdata_backref=missing|caller_owned_scope_identity_attach=missing|caller_owned_scope_failure_contract=missing|destructor_cascade=missing"
    );
    println!("case=overall|status=MISMATCH");
}
