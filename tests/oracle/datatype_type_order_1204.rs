//! DATATYPE-TYPEORDER-0001 Rugra comparand for locked Ghidra 12.0.4.

use rugra::fspec::ProtoModelFull;
use rugra::space::{AddrSpace, SpaceType};
use rugra::type_system::datatype::{
    type_flags, Datatype, TypeArray, TypeBase, TypeCode, TypeEnum, TypeField, TypeMetatype,
    TypePointer, TypeSpacebase, TypeStruct, TypeUnion,
};
use rugra::type_system::typefactory::TypeFactory;
use rugra::{Address, AddressSpace, FuncProto};
use std::collections::BTreeMap;
use std::sync::Arc;

fn signum(value: i32) -> i32 {
    value.signum()
}

fn base(name: &str, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        name.to_string(),
        size,
        metatype,
    )))
}

fn pointer(ptr_to: Arc<Datatype>) -> Datatype {
    Datatype::Pointer(TypePointer::new(8, ptr_to, 1))
}

fn structure(name: &str, size: usize, fields: Vec<TypeField>, incomplete: bool) -> Arc<Datatype> {
    let mut type_base = TypeBase::new(name.to_string(), size, TypeMetatype::Struct);
    if incomplete {
        type_base.flags |= type_flags::TYPE_INCOMPLETE;
    }
    if fields.len() == 1 && fields[0].type_ptr.get_size() == size {
        type_base.flags |= type_flags::NEEDS_RESOLUTION;
    }
    Arc::new(Datatype::Struct(TypeStruct {
        base: type_base,
        fields,
    }))
}

fn emit_order(key: &str, left: &Datatype, right: &Datatype) {
    println!("{key}={}", signum(left.type_order(right)));
}

fn emit_bool_order(key: &str, left: &Datatype, right: &Datatype) {
    println!("{key}={}", signum(left.type_order_bool(right)));
}

fn main() {
    let unknown4 = base("unknown4", 4, TypeMetatype::Unknown);
    let int4 = base("int4", 4, TypeMetatype::Int);
    let int4_alias = base("different_name_same_shape", 4, TypeMetatype::Int);
    let int8 = base("int8", 8, TypeMetatype::Int);
    let uint4 = base("uint4", 4, TypeMetatype::Uint);
    let bool1 = base("bool1", 1, TypeMetatype::Bool);
    let bool1_copy = base("bool1_copy", 1, TypeMetatype::Bool);

    let one_field = vec![TypeField {
        name: "a".to_string(),
        offset: 0,
        type_ptr: int4.clone(),
    }];
    let two_fields = vec![
        TypeField {
            name: "a".to_string(),
            offset: 0,
            type_ptr: int4.clone(),
        },
        TypeField {
            name: "b".to_string(),
            offset: 4,
            type_ptr: uint4.clone(),
        },
    ];
    let incomplete_struct = structure("Incomplete", 0, Vec::new(), true);
    let one_field_struct = structure("One", 4, one_field.clone(), false);
    let two_field_struct = structure("Two", 8, two_fields.clone(), false);

    let ptr_unknown = pointer(unknown4.clone());
    let ptr_int = pointer(int4.clone());
    let ptr_incomplete = pointer(incomplete_struct);
    let ptr_one_field = pointer(one_field_struct.clone());
    let ptr_two_field = pointer(two_field_struct);

    println!("identity.same={}", signum(int4.type_order(int4.as_ref())));
    println!(
        "submeta.unknown={}",
        Datatype::get_submeta(unknown4.as_ref()) as i32
    );
    println!(
        "submeta.int={}",
        Datatype::get_submeta(int4.as_ref()) as i32
    );
    println!(
        "submeta.uint={}",
        Datatype::get_submeta(uint4.as_ref()) as i32
    );
    println!(
        "submeta.bool={}",
        Datatype::get_submeta(bool1.as_ref()) as i32
    );
    println!(
        "submeta.ptr_unknown={}",
        Datatype::get_submeta(&ptr_unknown) as i32
    );
    println!(
        "submeta.ptr_incomplete_struct={}",
        Datatype::get_submeta(&ptr_incomplete) as i32
    );
    println!(
        "submeta.ptr_one_field_struct={}",
        Datatype::get_submeta(&ptr_one_field) as i32
    );
    println!(
        "submeta.ptr_one_field_needs_resolution={}",
        u8::from(ptr_one_field.needs_resolution())
    );
    println!(
        "submeta.ptr_two_field_struct={}",
        Datatype::get_submeta(&ptr_two_field) as i32
    );

    emit_order("order.ptr_unknown", &ptr_unknown, unknown4.as_ref());
    emit_order("order.int_unknown", int4.as_ref(), unknown4.as_ref());
    emit_order("order.uint_unknown", uint4.as_ref(), unknown4.as_ref());
    emit_order("order.bool_unknown", bool1.as_ref(), unknown4.as_ref());
    emit_order("order.int_uint", int4.as_ref(), uint4.as_ref());
    emit_order("order.int4_int8", int4.as_ref(), int8.as_ref());
    emit_order("order.name_ignored", int4.as_ref(), int4_alias.as_ref());
    emit_bool_order("bool_order.bool_int", bool1.as_ref(), int4.as_ref());
    emit_bool_order("bool_order.int_bool", int4.as_ref(), bool1.as_ref());
    emit_bool_order(
        "bool_order.distinct_bool",
        bool1.as_ref(),
        bool1_copy.as_ref(),
    );
    emit_bool_order("bool_order.same_bool", bool1.as_ref(), bool1.as_ref());

    let ptr_uint = pointer(uint4.clone());
    emit_order("recursive.ptr_int_uint", &ptr_int, &ptr_uint);
    let mut cutoff_left = match pointer(int4.clone()) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    let mut cutoff_right = match pointer(uint4.clone()) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    cutoff_left.base.id = 7;
    cutoff_right.base.id = 9;
    println!(
        "recursive.level0_id={}",
        signum(cutoff_left.compare(&cutoff_right, 0))
    );
    println!(
        "recursive.level1_target={}",
        signum(cutoff_left.compare(&cutoff_right, 1))
    );

    let struct_one = TypeStruct {
        base: TypeBase::new("S1".to_string(), 8, TypeMetatype::Struct),
        fields: one_field.clone(),
    };
    let struct_two = TypeStruct {
        base: TypeBase::new("S2".to_string(), 8, TypeMetatype::Struct),
        fields: two_fields,
    };
    println!(
        "tie.struct_more_fields={}",
        signum(struct_two.compare(&struct_one, 10))
    );
    let struct_name_b = TypeStruct {
        base: TypeBase::new("S3".to_string(), 8, TypeMetatype::Struct),
        fields: vec![TypeField {
            name: "b".to_string(),
            offset: 0,
            type_ptr: int4.clone(),
        }],
    };
    println!(
        "tie.struct_field_name={}",
        signum(struct_one.compare(&struct_name_b, 10))
    );
    let struct_unknown = TypeStruct {
        base: TypeBase::new("S4".to_string(), 8, TypeMetatype::Struct),
        fields: vec![TypeField {
            name: "a".to_string(),
            offset: 0,
            type_ptr: unknown4.clone(),
        }],
    };
    println!(
        "tie.struct_field_metatype={}",
        signum(struct_one.compare(&struct_unknown, 10))
    );

    let mut values_a = BTreeMap::new();
    values_a.insert(1, "A".to_string());
    let mut enum_a_base = TypeBase::new("EA".to_string(), 4, TypeMetatype::Int);
    enum_a_base.flags |= type_flags::ENUMTYPE;
    let enum_a = TypeEnum {
        base: enum_a_base,
        values: values_a,
    };
    let mut values_b = BTreeMap::new();
    values_b.insert(2, "A".to_string());
    let mut enum_b_base = TypeBase::new("EB".to_string(), 4, TypeMetatype::Int);
    enum_b_base.flags |= type_flags::ENUMTYPE;
    let enum_b = TypeEnum {
        base: enum_b_base,
        values: values_b,
    };
    println!("tie.enum_value={}", signum(enum_a.compare(&enum_b, 10)));

    let dep_same_a = match pointer(int4.clone()) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    let dep_same_b = match pointer(int4.clone()) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    let int4_copy = base("int4_copy", 4, TypeMetatype::Int);
    let dep_distinct = match pointer(int4_copy) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    let dep_forward = dep_same_a.compare_dependency(&dep_distinct);
    let dep_reverse = dep_distinct.compare_dependency(&dep_same_a);
    println!(
        "dependency.same_target={}",
        signum(dep_same_a.compare_dependency(&dep_same_b))
    );
    println!(
        "dependency.distinct_target_nonzero={}",
        u8::from(dep_forward != 0)
    );
    println!(
        "dependency.distinct_target_antisymmetric={}",
        u8::from(signum(dep_forward) == -signum(dep_reverse))
    );

    let ptr_uint_datatype = Datatype::Pointer(TypePointer::new(8, uint4.clone(), 1));
    let ptr_int_datatype = Datatype::Pointer(TypePointer::new(8, int4.clone(), 1));
    println!(
        "base_api.compare_pointer={}",
        signum(ptr_int_datatype.compare(&ptr_uint_datatype))
    );
    let dep_target_copy = base("dep_target_copy", 4, TypeMetatype::Int);
    let dep_pointer_copy = Datatype::Pointer(TypePointer::new(8, dep_target_copy, 1));
    let base_dep_forward = ptr_int_datatype.compare_dependency(&dep_pointer_copy);
    let base_dep_reverse = dep_pointer_copy.compare_dependency(&ptr_int_datatype);
    println!(
        "base_api.dependency_pointer_nonzero={}",
        u8::from(base_dep_forward != 0)
    );
    println!(
        "base_api.dependency_pointer_antisymmetric={}",
        u8::from(signum(base_dep_forward) == -signum(base_dep_reverse))
    );

    let mut array_base = TypeBase::new("A1".to_string(), 4, TypeMetatype::Array);
    array_base.flags |= type_flags::NEEDS_RESOLUTION;
    let array_one = Arc::new(Datatype::Array(TypeArray {
        base: array_base,
        array_of: int4.clone(),
        num_elements: 1,
    }));
    let array_pointer = Datatype::Pointer(TypePointer::new(8, array_one, 1));
    println!(
        "pointer_state.array_flag={}",
        u8::from(array_pointer.is_pointer_to_array())
    );
    println!(
        "pointer_state.array_needs_resolution={}",
        u8::from(array_pointer.needs_resolution())
    );
    let mut union_base = TypeBase::new("U".to_string(), 4, TypeMetatype::Union);
    union_base.flags |= type_flags::NEEDS_RESOLUTION;
    let union_type = Arc::new(Datatype::Union(TypeUnion {
        base: union_base,
        fields: vec![TypeField {
            name: "a".to_string(),
            offset: 0,
            type_ptr: int4.clone(),
        }],
    }));
    let union_pointer = Datatype::Pointer(TypePointer::new(8, union_type, 1));
    println!(
        "pointer_state.union_submeta={}",
        union_pointer.get_submeta() as i32
    );
    println!(
        "pointer_state.union_needs_resolution={}",
        u8::from(union_pointer.needs_resolution())
    );
    let pointer_to_union_pointer =
        Datatype::Pointer(TypePointer::new(8, Arc::new(union_pointer.clone()), 1));
    println!(
        "pointer_state.pointer_needs_resolution={}",
        u8::from(pointer_to_union_pointer.needs_resolution())
    );
    let mut core_int_base = TypeBase::new("core_int".to_string(), 4, TypeMetatype::Int);
    core_int_base.flags |= type_flags::CORETYPE;
    let core_int = Arc::new(Datatype::Base(core_int_base));
    let core_pointer = Datatype::Pointer(TypePointer::new(8, core_int, 1));
    println!(
        "pointer_state.core_inherited={}",
        u8::from(core_pointer.is_coretype())
    );

    let pointer_no_space = Datatype::Pointer(TypePointer::new(8, int4.clone(), 1));
    let pointer_ram =
        Datatype::Pointer(TypePointer::new_with_space(int4.clone(), AddressSpace::Ram));
    let pointer_register = Datatype::Pointer(TypePointer::new_with_space(
        int4.clone(),
        AddressSpace::Register,
    ));
    println!(
        "pointer_space.present_before_none={}",
        signum(pointer_ram.compare(&pointer_no_space))
    );
    println!(
        "pointer_space.ram_before_register={}",
        signum(pointer_ram.compare(&pointer_register))
    );
    println!(
        "pointer_space.dependency_ranking={}",
        signum(pointer_ram.compare_dependency(&pointer_register))
    );

    let rel_parent = one_field_struct.clone();
    let formal_rel = Datatype::Pointer(TypePointer::new_relative(
        8,
        unknown4.clone(),
        1,
        rel_parent.clone(),
        4,
    ));
    let mut ephemeral_pointer =
        TypePointer::new_relative(8, unknown4.clone(), 1, rel_parent.clone(), 4);
    let stripped = Arc::new(Datatype::Pointer(TypePointer::new(8, unknown4.clone(), 1)));
    ephemeral_pointer.mark_ephemeral(stripped.clone());
    let ephemeral_rel = Datatype::Pointer(ephemeral_pointer);
    println!(
        "pointer_rel.formal_submeta={}",
        formal_rel.get_submeta() as i32
    );
    println!(
        "pointer_rel.ephemeral_submeta={}",
        ephemeral_rel.get_submeta() as i32
    );
    println!(
        "pointer_rel.formal_has_stripped={}",
        u8::from((formal_rel.get_flags() & type_flags::HAS_STRIPPED) != 0)
    );
    println!(
        "pointer_rel.ephemeral_has_stripped={}",
        u8::from((ephemeral_rel.get_flags() & type_flags::HAS_STRIPPED) != 0)
    );
    let (formal_parent, formal_offset) = match &formal_rel {
        Datatype::Pointer(pointer) => (
            pointer.get_parent().expect("relative parent"),
            pointer.get_byte_offset().expect("relative offset"),
        ),
        _ => unreachable!(),
    };
    println!(
        "pointer_rel.parent_identity={}",
        u8::from(Arc::ptr_eq(formal_parent, &rel_parent))
    );
    println!("pointer_rel.parent_name={}", formal_parent.get_name());
    println!("pointer_rel.parent_size={}", formal_parent.get_size());
    println!(
        "pointer_rel.parent_needs_resolution={}",
        u8::from(formal_parent.needs_resolution())
    );
    println!("pointer_rel.byte_offset={formal_offset}");
    println!(
        "pointer_rel.stripped_identity={}",
        u8::from(match &ephemeral_rel {
            Datatype::Pointer(pointer) => pointer
                .get_stripped_pointer()
                .map(|candidate| Arc::ptr_eq(candidate, &stripped))
                .unwrap_or(false),
            _ => false,
        })
    );
    println!(
        "pointer_rel.formal_before_ephemeral={}",
        signum(formal_rel.compare(&ephemeral_rel))
    );
    let formal_int_rel = Datatype::Pointer(TypePointer::new_relative(
        8,
        int4.clone(),
        1,
        rel_parent.clone(),
        4,
    ));
    let mut ephemeral_int_pointer =
        TypePointer::new_relative(8, int4.clone(), 1, rel_parent.clone(), 4);
    ephemeral_int_pointer.mark_ephemeral(Arc::new(Datatype::Pointer(TypePointer::new(
        8,
        int4.clone(),
        1,
    ))));
    let ephemeral_int_rel = Datatype::Pointer(ephemeral_int_pointer);
    println!(
        "pointer_rel.stripped_tie={}",
        signum(formal_int_rel.compare(&ephemeral_int_rel))
    );
    let rel_offset_eight = Datatype::Pointer(TypePointer::new_relative(
        8,
        unknown4.clone(),
        1,
        rel_parent,
        8,
    ));
    println!(
        "pointer_rel.dependency_offset={}",
        signum(formal_rel.compare_dependency(&rel_offset_eight))
    );
    let other_rel_parent = structure("OtherRelParent", 4, one_field.clone(), false);
    let rel_other_parent = Datatype::Pointer(TypePointer::new_relative(
        8,
        unknown4.clone(),
        1,
        other_rel_parent,
        4,
    ));
    let rel_parent_forward = formal_rel.compare_dependency(&rel_other_parent);
    let rel_parent_reverse = rel_other_parent.compare_dependency(&formal_rel);
    println!(
        "pointer_rel.dependency_parent_nonzero={}",
        u8::from(rel_parent_forward != 0)
    );
    println!(
        "pointer_rel.dependency_parent_antisymmetric={}",
        u8::from(signum(rel_parent_forward) == -signum(rel_parent_reverse))
    );

    let unicode1 = Datatype::Base(TypeBase::new_unicode(
        "unicode1".to_string(),
        1,
        TypeMetatype::Int,
    ));
    let char1 = Datatype::Base(TypeBase::new_char("char1".to_string(), TypeMetatype::Int));
    println!("unicode.direct_submeta={}", unicode1.get_submeta() as i32);
    println!("unicode.char_submeta={}", char1.get_submeta() as i32);
    println!(
        "unicode.before_char={}",
        signum(unicode1.type_order(&char1))
    );

    let void_type = Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )));
    let mut model = ProtoModelFull::new(None, 8);
    model.name = "fixture_model".to_string();
    let model = Arc::new(model);
    let make_proto = |constructor: bool, destructor: bool, has_this: bool| {
        let mut proto = FuncProto::new(String::new(), void_type.clone());
        proto.set_model(Some(model.clone()));
        proto.set_constructor(constructor);
        proto.set_destructor(destructor);
        proto.set_has_thisptr(has_this);
        Arc::new(proto)
    };
    let code_plain = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(make_proto(false, false, false)),
    });
    let code_constructor = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(make_proto(true, false, false)),
    });
    let code_destructor = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(make_proto(false, true, false)),
    });
    let code_this = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(make_proto(false, false, true)),
    });
    let code_no_model = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(Arc::new(FuncProto::new(String::new(), void_type.clone()))),
    });
    println!(
        "code_model.absent_after_present={}",
        signum(code_no_model.compare(&code_plain))
    );
    println!(
        "code_flags.plain_constructor={}",
        signum(code_plain.compare(&code_constructor))
    );
    println!(
        "code_flags.constructor_destructor={}",
        signum(code_constructor.compare(&code_destructor))
    );
    println!(
        "code_flags.same_model_name={}",
        u8::from(match (&code_plain, &code_this) {
            (Datatype::Code(left), Datatype::Code(right)) => left
                .proto
                .as_ref()
                .zip(right.proto.as_ref())
                .map(|(left, right)| left.get_model_name() == right.get_model_name())
                .unwrap_or(false),
            _ => false,
        })
    );
    println!(
        "code_flags.plain_this={}",
        signum(code_plain.compare(&code_this))
    );

    let ram_handle = AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        AddressSpace::Ram.space_id() as i32,
        0,
        0,
        0,
    );
    let invalid_frame = Address::new(0);
    let valid_zero_frame = Address::with_space(&ram_handle, 0);
    let valid_one_frame = Address::with_space(&ram_handle, 1);
    let make_spacebase = |spaceid, frame| {
        Datatype::Spacebase(TypeSpacebase {
            base: TypeBase::new(String::new(), 0, TypeMetatype::Spacebase),
            address: frame,
            fd: None,
            spaceid,
            localframe: frame,
            scope: None,
        })
    };
    let spacebase_invalid = make_spacebase(Some(AddressSpace::Ram), invalid_frame);
    let spacebase_valid_zero = make_spacebase(Some(AddressSpace::Ram), valid_zero_frame);
    let spacebase_register = make_spacebase(Some(AddressSpace::Register), valid_zero_frame);
    let spacebase_valid_one = make_spacebase(Some(AddressSpace::Ram), valid_one_frame);
    println!(
        "spacebase.invalid_spaceless={}",
        u8::from(match &spacebase_invalid {
            Datatype::Spacebase(spacebase) => spacebase.is_invalid(),
            _ => false,
        })
    );
    println!(
        "spacebase.valid_zero={}",
        u8::from(match &spacebase_valid_zero {
            Datatype::Spacebase(spacebase) => !spacebase.is_invalid(),
            _ => false,
        })
    );
    let space_forward = spacebase_valid_zero.compare_dependency(&spacebase_register);
    let space_reverse = spacebase_register.compare_dependency(&spacebase_valid_zero);
    println!(
        "spacebase.space_identity_nonzero={}",
        u8::from(space_forward != 0)
    );
    println!(
        "spacebase.space_identity_antisymmetric={}",
        u8::from(signum(space_forward) == -signum(space_reverse))
    );
    println!(
        "spacebase.localframe_order={}",
        signum(spacebase_valid_zero.compare_dependency(&spacebase_valid_one))
    );
    println!(
        "spacebase.global_shortcut={}",
        signum(spacebase_invalid.compare_dependency(&spacebase_valid_zero))
    );

    let mut factory = TypeFactory::new(8);
    let factory_int = factory.get_base(4, TypeMetatype::Int).expect("factory int");
    let factory_plain_pointer = factory.get_type_pointer(4, factory_int.clone(), 2);
    println!(
        "factory_gap.ordinary_pointer_is_ptrrel={}",
        u8::from((factory_plain_pointer.get_flags() & type_flags::IS_PTRREL) != 0)
    );
    let factory_parent = one_field_struct;
    let factory_unknown = factory
        .get_base(4, TypeMetatype::Unknown)
        .expect("factory unknown");
    let factory_rel = factory.get_type_pointer_rel(factory_unknown, factory_parent, 4);
    println!(
        "factory_gap.ephemeral_rel_has_stripped={}",
        u8::from((factory_rel.get_flags() & type_flags::HAS_STRIPPED) != 0)
    );
    println!(
        "factory_gap.ephemeral_rel_submeta={}",
        factory_rel.get_submeta() as i32
    );
    let factory_array = factory.get_array(factory_int.clone(), 1);
    let factory_array_pointer = factory.get_ptr(factory_array);
    println!(
        "factory_gap.array_pointer_flag={}",
        u8::from(factory_array_pointer.is_pointer_to_array())
    );
    let factory_core_pointer = factory.get_ptr(factory_int);
    println!(
        "factory_gap.core_pointer_inherited={}",
        u8::from(factory_core_pointer.is_coretype())
    );
    let factory_unicode1 = factory.get_type_unicode(1);
    println!(
        "factory_gap.unicode1_submeta={}",
        factory_unicode1.get_submeta() as i32
    );
}
