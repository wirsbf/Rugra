// TYPEFACTORY-LOCALTYPE-CACHE-0001: Rust comparand for the locked Ghidra
// TypeFactory core-cache fixture. Record order and values mirror the C++
// fixture byte-for-byte; Arc pointer identity is the Rust observation of the
// factory-owned canonical Datatype pointer identity used by Ghidra.

use std::sync::Arc;

use rugra::type_system::datatype::{Datatype, TypeMetatype};
use rugra::type_system::typefactory::TypeFactory;

fn metatype_number(metatype: TypeMetatype) -> i32 {
    match metatype {
        TypeMetatype::Int => 14,
        TypeMetatype::Uint => 13,
        other => panic!("fixture received unsupported metatype: {other:?}"),
    }
}

fn emit_identity(key: &str, left: &Arc<Datatype>, right: &Arc<Datatype>) {
    println!("{key}={}", if Arc::ptr_eq(left, right) { 1 } else { 0 });
}

fn emit_type(key: &str, datatype: &Arc<Datatype>) {
    println!("{key}.name={}", datatype.get_name());
    println!("{key}.id={}", datatype.get_id());
    println!("{key}.size={}", datatype.get_size());
    println!("{key}.meta={}", metatype_number(datatype.get_metatype()));
    println!("{key}.core={}", if datatype.is_coretype() { 1 } else { 0 });
    println!(
        "{key}.char={}",
        if datatype.get_flags() & rugra::type_system::datatype::type_flags::CHARTYPE != 0 {
            1
        } else {
            0
        }
    );
}

fn base(factory: &TypeFactory, metatype: TypeMetatype) -> Arc<Datatype> {
    factory
        .get_base(1, metatype)
        .expect("fixture base type must exist")
}

fn nochar(factory: &TypeFactory) -> Arc<Datatype> {
    factory
        .get_base_no_char(1, TypeMetatype::Int)
        .expect("fixture nochar base type must exist")
}

fn named(factory: &TypeFactory, name: &str) -> Arc<Datatype> {
    factory
        .find_by_name(name)
        .unwrap_or_else(|| panic!("missing fixture type: {name}"))
}

fn main() {
    let mut factory = TypeFactory::new(8);
    factory.clear();
    factory.set_core_type("plain_high", 1, TypeMetatype::Int, false);
    factory.set_core_type("aaaaaaaa", 1, TypeMetatype::Int, false);
    factory.set_core_type("unsigned_custom_a", 1, TypeMetatype::Uint, false);
    factory.set_core_type("unsigned_custom_b", 1, TypeMetatype::Uint, false);
    factory.set_core_type("custom_ascii_glyph", 1, TypeMetatype::Int, true);
    factory.cache_core_types();

    let plain_high = named(&factory, "plain_high");
    let plain_a = named(&factory, "aaaaaaaa");
    let uint_a = named(&factory, "unsigned_custom_a");
    let uint_b = named(&factory, "unsigned_custom_b");
    let ascii = named(&factory, "custom_ascii_glyph");
    let preferred = base(&factory, TypeMetatype::Int);
    let initial_nochar = nochar(&factory);
    let preferred_uint = base(&factory, TypeMetatype::Uint);
    emit_type("initial.plain_high", &plain_high);
    emit_type("initial.aaaaaaaa", &plain_a);
    emit_type("initial.ascii", &ascii);
    emit_type("initial.uint_a", &uint_a);
    emit_type("initial.uint_b", &uint_b);
    emit_type("initial.preferred", &preferred);
    emit_type("initial.nochar", &initial_nochar);
    emit_type("initial.preferred_uint", &preferred_uint);
    emit_identity("initial.preferred_is_ascii", &preferred, &ascii);
    let expected_nochar = if plain_high.get_id() > plain_a.get_id() {
        &plain_high
    } else {
        &plain_a
    };
    emit_identity(
        "initial.nochar_is_tree_last",
        &initial_nochar,
        expected_nochar,
    );
    let expected_uint = if uint_a.get_id() < uint_b.get_id() {
        &uint_a
    } else {
        &uint_b
    };
    emit_identity("initial.uint_is_tree_first", &preferred_uint, expected_uint);
    let initial_char = factory.get_type_char(1);
    emit_identity("initial.charcache_is_ascii", &initial_char, &ascii);
    emit_identity(
        "initial.getbase_repeat",
        &preferred,
        &base(&factory, TypeMetatype::Int),
    );
    emit_identity("initial.nochar_repeat", &initial_nochar, &nochar(&factory));

    factory.cache_core_types();
    emit_identity(
        "repeat_cache.preferred",
        &preferred,
        &base(&factory, TypeMetatype::Int),
    );
    emit_identity("repeat_cache.nochar", &initial_nochar, &nochar(&factory));
    emit_identity(
        "repeat_cache.uint",
        &preferred_uint,
        &base(&factory, TypeMetatype::Uint),
    );

    factory.set_core_type("zzzzzzzz", 1, TypeMetatype::Int, false);
    let late_plain = named(&factory, "zzzzzzzz");
    factory.cache_core_types();
    let late_nochar = nochar(&factory);
    emit_type("late.plain", &late_plain);
    emit_type("late.nochar", &late_nochar);
    emit_identity("late.old_nochar_same", &initial_nochar, &late_nochar);
    emit_identity("late.new_nochar_is_late", &late_nochar, &late_plain);
    emit_identity(
        "late.preferred_still_ascii",
        &base(&factory, TypeMetatype::Int),
        &ascii,
    );

    factory.clear();
    factory.clear();
    println!(
        "clear.old_name_absent={}",
        if factory.find_by_name("custom_ascii_glyph").is_none() {
            1
        } else {
            0
        }
    );
    let empty_base = base(&factory, TypeMetatype::Int);
    emit_type("clear.empty_base", &empty_base);
    emit_identity(
        "clear.empty_nochar_falls_through",
        &empty_base,
        &nochar(&factory),
    );

    factory.clear();
    factory.set_core_type("post_clear_plain", 1, TypeMetatype::Int, false);
    factory.cache_core_types();
    let post_plain = named(&factory, "post_clear_plain");
    let post_preferred = base(&factory, TypeMetatype::Int);
    let post_nochar = nochar(&factory);
    emit_type("post.plain", &post_plain);
    emit_identity("post.preferred_is_plain", &post_preferred, &post_plain);
    emit_identity("post.nochar_is_plain", &post_nochar, &post_plain);
    factory.cache_core_types();
    emit_identity(
        "post.repeat_cache_preferred",
        &post_preferred,
        &base(&factory, TypeMetatype::Int),
    );
    emit_identity("post.repeat_cache_nochar", &post_nochar, &nochar(&factory));

    factory.set_core_type("post_clear_ascii", 1, TypeMetatype::Int, true);
    let post_ascii = named(&factory, "post_clear_ascii");
    factory.cache_core_types();
    emit_type("post.ascii", &post_ascii);
    emit_identity(
        "post.preferred_is_ascii",
        &base(&factory, TypeMetatype::Int),
        &post_ascii,
    );
    emit_identity("post.nochar_stays_plain", &nochar(&factory), &post_plain);
    let post_char = factory.get_type_char(1);
    emit_identity("post.charcache_is_ascii", &post_char, &post_ascii);
}
