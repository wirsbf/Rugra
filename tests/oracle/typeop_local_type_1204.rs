// TYPEOP-LOCALTYPE-DISPATCH-0001: current-Rugra comparand for the locked
// Ghidra TypeOpCall::getInputLocal fixture.
//
// This deliberately exercises the production TypeOpCall trait method.  The
// callspec is installed in Funcdata and represented by the same Iop/typed-Weak
// annotation that Funcdata::new_varnode_call_specs currently produces.  The
// output is expected to differ from Ghidra 12.0.4: TypeOpCall has no
// get_input_local override and the legacy Varnode address-space enum has no
// FSPEC variant.  The fixture therefore reports None; it does not emulate the
// missing behavior in test code.

use std::sync::{Arc, RwLock};

use rugra::address::Address;
use rugra::fspec::{protoparam_flags, FuncCallSpecs, FuncProto, ProtoParameter};
use rugra::funcdata::Funcdata;
use rugra::op::{PcodeOp, PcodeOpRef};
use rugra::opcodes::OpCode;
use rugra::space::SpaceType;
use rugra::type_system::datatype::{Datatype, TypeMetatype};
use rugra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rugra::typeop::{TypeOp, TypeOpCall};

fn emit_bool(key: &str, value: bool) {
    println!("{key}={}", if value { 1 } else { 0 });
}

fn option_identity(actual: Option<&Arc<Datatype>>, expected: &Arc<Datatype>) -> bool {
    actual.is_some_and(|datatype| Arc::ptr_eq(datatype, expected))
}

fn repeat_identity(left: Option<&Arc<Datatype>>, right: Option<&Arc<Datatype>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

fn emit_case(
    name: &str,
    typeop: &TypeOpCall,
    op: &PcodeOp,
    slot: usize,
    expected: &Arc<Datatype>,
    param: Option<&ProtoParameter>,
    fallback: &Arc<Datatype>,
) {
    let actual = typeop.get_input_local(op, slot);
    let repeat = typeop.get_input_local(op, slot);
    println!("case.{name}.slot={slot}");
    println!(
        "case.{name}.input_size={}",
        op.get_in(slot)
            .expect("fixture input slot")
            .read()
            .unwrap()
            .size
    );
    emit_bool(&format!("case.{name}.param_present"), param.is_some());
    emit_bool(
        &format!("case.{name}.param_locked"),
        param.is_some_and(ProtoParameter::is_type_locked),
    );
    emit_bool(
        &format!("case.{name}.param_this"),
        param.is_some_and(ProtoParameter::is_this_pointer),
    );
    match actual.as_ref() {
        Some(datatype) => {
            println!("case.{name}.result_type={}", datatype.print_raw());
            println!("case.{name}.result_meta={:?}", datatype.get_metatype());
            println!("case.{name}.result_size={}", datatype.get_size());
        }
        None => {
            println!("case.{name}.result_type=NONE");
            println!("case.{name}.result_meta=NONE");
            println!("case.{name}.result_size=NONE");
        }
    }
    emit_bool(
        &format!("case.{name}.expected_identity"),
        option_identity(actual.as_ref(), expected),
    );
    emit_bool(
        &format!("case.{name}.param_identity"),
        param.is_some_and(|parameter| option_identity(actual.as_ref(), &parameter.data_type)),
    );
    emit_bool(
        &format!("case.{name}.fallback_identity"),
        option_identity(actual.as_ref(), fallback),
    );
    emit_bool(
        &format!("case.{name}.repeat_identity"),
        repeat_identity(actual.as_ref(), repeat.as_ref()),
    );
}

fn callspec_identity(
    fd: &Funcdata,
    expected: &Arc<RwLock<FuncCallSpecs>>,
    op: &PcodeOpRef,
) -> bool {
    fd.get_call_specs_of_op(op)
        .is_some_and(|actual| Arc::ptr_eq(expected, &actual))
}

fn snapshot_param(
    fd: &Funcdata,
    callspec_index: usize,
    parameter_index: usize,
) -> Option<ProtoParameter> {
    fd.get_call_specs(callspec_index)
        .and_then(|callspec| callspec.prototype.get_param(parameter_index).cloned())
}

fn main() {
    let mut factory = TypeFactory::new(8);
    factory.setup_sizes(&SizeArchInputs {
        stack_spacebase_size: Some(8),
        default_data_space_addr_size: 8,
        default_size: 8,
        far_pointer: None,
    });

    let void_type = factory.get_type_void();
    let char_type = factory
        .get_type_char_named("char")
        .expect("canonical char type");
    let char_pointer = factory.get_type_pointer(8, char_type, 1);
    let int4_type = factory
        .get_base(4, TypeMetatype::Int)
        .expect("canonical int4 type");
    let uint8_type = factory
        .get_base(8, TypeMetatype::Uint)
        .expect("canonical uint8 type");
    let oversize_type = factory.get_array(uint8_type, 2);
    let object_type = factory.create_struct("typeop_call_fixture_object");
    let object_pointer = factory.get_type_pointer(8, object_type, 1);
    let plain_pointer = factory.get_type_pointer(8, int4_type.clone(), 1);

    let mut prototype = FuncProto::new("typeop_call_local_fixture".to_string(), void_type.clone());
    let mut locked_ptr = ProtoParameter::new(
        "locked_ptr".to_string(),
        char_pointer.clone(),
        Address::new(0x00),
    );
    locked_ptr.flags |= protoparam_flags::TYPE_LOCKED;
    prototype.add_parameter(locked_ptr);
    let mut locked_small = ProtoParameter::new(
        "locked_small".to_string(),
        int4_type.clone(),
        Address::new(0x08),
    );
    locked_small.flags |= protoparam_flags::TYPE_LOCKED;
    prototype.add_parameter(locked_small);
    prototype.add_parameter(ProtoParameter::new(
        "unlocked_int".to_string(),
        int4_type.clone(),
        Address::new(0x10),
    ));
    let mut locked_void = ProtoParameter::new(
        "locked_void".to_string(),
        void_type.clone(),
        Address::new(0x18),
    );
    locked_void.flags |= protoparam_flags::TYPE_LOCKED;
    prototype.add_parameter(locked_void);
    let mut locked_oversize = ProtoParameter::new(
        "locked_oversize".to_string(),
        oversize_type.clone(),
        Address::new(0x20),
    );
    locked_oversize.flags |= protoparam_flags::TYPE_LOCKED;
    prototype.add_parameter(locked_oversize);
    let mut this_struct = ProtoParameter::new(
        "this_struct".to_string(),
        object_pointer.clone(),
        Address::new(0x28),
    );
    this_struct.flags |= protoparam_flags::THIS_POINTER;
    prototype.add_parameter(this_struct);
    let mut this_plain =
        ProtoParameter::new("this_plain".to_string(), plain_pointer, Address::new(0x30));
    this_plain.flags |= protoparam_flags::THIS_POINTER;
    prototype.add_parameter(this_plain);

    let mut fd = Funcdata::new("typeop_call_local_fixture", Address::new(0x500000), 0x100);
    let call_target = fd.new_constant(8, 0x500080);
    let input1 = fd.new_constant(8, 0x7180);
    let input2 = fd.new_constant(8, 0x11223344);
    let input3 = fd.new_constant(4, 0x55667788);
    let input4 = fd.new_constant(8, 0);
    let input5 = fd.new_constant(8, 0x99a8);
    let input6 = fd.new_constant(8, 0xc1d8);
    let input7 = fd.new_constant(8, 0xea40);
    let input8 = fd.new_constant(1, 0x7f);

    let op = fd.new_op(9, Address::new(0x500010));
    fd.op_set_opcode(&op, OpCode::CPUI_CALL);
    fd.op_set_input(&op, call_target, 0);
    fd.op_set_input(&op, input1, 1);
    fd.op_set_input(&op, input2, 2);
    fd.op_set_input(&op, input3, 3);
    fd.op_set_input(&op, input4, 4);
    fd.op_set_input(&op, input5, 5);
    fd.op_set_input(&op, input6, 6);
    fd.op_set_input(&op, input7, 7);
    fd.op_set_input(&op, input8, 8);

    let callspec_index = fd.add_call_specs(FuncCallSpecs::new_for_op(&op, prototype));
    let callspec_owner = fd
        .get_call_specs_owner(callspec_index)
        .expect("fixture callspec owner");
    let fspec_primary = fd.new_varnode_call_specs(&callspec_owner);
    let fspec_alias = fd.new_varnode_call_specs(&callspec_owner);
    let callspec_bits = fspec_primary.read().unwrap().get_offset();
    let constant_mimic = fd.new_constant(std::mem::size_of::<usize>(), callspec_bits);
    let constant_mimic_has_no_handle = constant_mimic.read().unwrap().get_call_spec().is_none();
    let constant_mimic_op = fd.new_op(1, Address::new(0x500010));
    fd.op_set_opcode(&constant_mimic_op, OpCode::CPUI_CALL);
    fd.op_set_input(&constant_mimic_op, constant_mimic.clone(), 0);
    fd.op_set_input(&op, fspec_primary.clone(), 0);

    println!("fixture=TYPEOP-LOCALTYPE-DISPATCH-0001.call_input");
    println!("architecture=current-rust-size-configuration-only");
    println!("representation.fspec_name=iop");
    println!("representation.fspec_type={}", SpaceType::Iop as u32);
    println!(
        "representation.constant_type={}",
        SpaceType::Constant as u32
    );
    emit_bool(
        "representation.primary_roundtrip",
        callspec_identity(&fd, &callspec_owner, &op),
    );
    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = fspec_alias.clone();
    }
    emit_bool(
        "representation.alias_roundtrip",
        callspec_identity(&fd, &callspec_owner, &op),
    );
    emit_bool(
        "representation.alias_distinct_varnode",
        !Arc::ptr_eq(&fspec_primary, &fspec_alias),
    );
    let (primary_space, primary_offset) = {
        let primary = fspec_primary.read().unwrap();
        (primary.get_space(), primary.get_offset())
    };
    let (alias_space, alias_offset) = {
        let alias = fspec_alias.read().unwrap();
        (alias.get_space(), alias.get_offset())
    };
    let constant_offset = constant_mimic.read().unwrap().get_offset();
    emit_bool(
        "representation.alias_same_address",
        primary_space == alias_space && primary_offset == alias_offset,
    );
    emit_bool(
        "representation.constant_same_offset",
        constant_offset == primary_offset,
    );
    emit_bool(
        "representation.constant_not_fspec",
        constant_mimic_has_no_handle && fd.get_call_specs_of_op(&constant_mimic_op).is_none(),
    );
    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = fspec_primary.clone();
    }

    let typeop = TypeOpCall;
    let parameters = (0..7)
        .map(|index| snapshot_param(&fd, callspec_index, index))
        .collect::<Vec<_>>();
    {
        let call = op.0.read().unwrap();
        emit_case(
            "slot0_target",
            &typeop,
            &call,
            0,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            None,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "locked_ptr_equal",
            &typeop,
            &call,
            1,
            &char_pointer,
            parameters[0].as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "locked_small_fits",
            &typeop,
            &call,
            2,
            &int4_type,
            parameters[1].as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "unlocked_param",
            &typeop,
            &call,
            3,
            &factory.get_base(4, TypeMetatype::Unknown).unwrap(),
            parameters[2].as_ref(),
            &factory.get_base(4, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "locked_void",
            &typeop,
            &call,
            4,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            parameters[3].as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "locked_oversize",
            &typeop,
            &call,
            5,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            parameters[4].as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "unlocked_this_struct",
            &typeop,
            &call,
            6,
            &object_pointer,
            parameters[5].as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "unlocked_this_plain",
            &typeop,
            &call,
            7,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            parameters[6].as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "missing_param",
            &typeop,
            &call,
            8,
            &factory.get_base(1, TypeMetatype::Unknown).unwrap(),
            None,
            &factory.get_base(1, TypeMetatype::Unknown).unwrap(),
        );
    }

    fd.get_call_specs_mut(callspec_index)
        .unwrap()
        .prototype
        .parameters[0]
        .flags &= !protoparam_flags::TYPE_LOCKED;
    let unlocked_parameter = snapshot_param(&fd, callspec_index, 0);
    {
        let call = op.0.read().unwrap();
        emit_case(
            "locked_ptr_after_unlock",
            &typeop,
            &call,
            1,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            unlocked_parameter.as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
    }
    fd.get_call_specs_mut(callspec_index)
        .unwrap()
        .prototype
        .parameters[0]
        .flags |= protoparam_flags::TYPE_LOCKED;
    let relocked_parameter = snapshot_param(&fd, callspec_index, 0);
    {
        let call = op.0.read().unwrap();
        emit_case(
            "locked_ptr_after_relock",
            &typeop,
            &call,
            1,
            &char_pointer,
            relocked_parameter.as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
    }

    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = fspec_alias;
    }
    let alias_parameter = snapshot_param(&fd, callspec_index, 0);
    {
        let call = op.0.read().unwrap();
        emit_case(
            "fspec_alias",
            &typeop,
            &call,
            1,
            &char_pointer,
            alias_parameter.as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
    }
    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = constant_mimic;
    }
    let constant_parameter = snapshot_param(&fd, callspec_index, 0);
    {
        let call = op.0.read().unwrap();
        emit_case(
            "constant_same_offset",
            &typeop,
            &call,
            1,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            constant_parameter.as_ref(),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
    }
    println!("rugra.typeop_call_get_input_local.status=MISMATCH");
    println!("rugra.fspec_varnode_representation.status=MISMATCH");
}
