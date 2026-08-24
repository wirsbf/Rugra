// TYPEOP-LOCALTYPE-DISPATCH-0001: current-Rugra comparand for the locked
// Ghidra TypeOpCall::getInputLocal fixture.
//
// This deliberately exercises the production TypeOpCall trait method.  The
// callspec is installed in Funcdata and represented by the same Iop/index
// annotation that Funcdata::new_varnode_call_specs currently produces.  The
// output is expected to differ from Ghidra 12.0.4: TypeOpCall has no
// get_input_local override and the legacy Varnode address-space enum has no
// FSPEC variant.  The fixture therefore reports None; it does not emulate the
// missing behavior in test code.

use std::sync::Arc;

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

fn callspec_identity(fd: &Funcdata, index: usize, op: &PcodeOpRef) -> bool {
    match (fd.get_call_specs(index), fd.get_call_specs_of_op(op)) {
        (Some(expected), Some(actual)) => std::ptr::eq(expected, actual),
        _ => false,
    }
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
    let callspec_index = fd.add_call_specs(FuncCallSpecs::new(Address::new(0x500010), prototype));
    let fspec_primary = fd.new_varnode_call_specs(callspec_index);
    let fspec_alias = fd.new_varnode_call_specs(callspec_index);
    let constant_mimic = fd.new_constant(std::mem::size_of::<usize>(), callspec_index as u64);
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
    fd.op_set_input(&op, fspec_primary.clone(), 0);
    fd.op_set_input(&op, input1, 1);
    fd.op_set_input(&op, input2, 2);
    fd.op_set_input(&op, input3, 3);
    fd.op_set_input(&op, input4, 4);
    fd.op_set_input(&op, input5, 5);
    fd.op_set_input(&op, input6, 6);
    fd.op_set_input(&op, input7, 7);
    fd.op_set_input(&op, input8, 8);

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
        callspec_identity(&fd, callspec_index, &op),
    );
    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = fspec_alias.clone();
    }
    emit_bool(
        "representation.alias_roundtrip",
        callspec_identity(&fd, callspec_index, &op),
    );
    emit_bool(
        "representation.alias_distinct_varnode",
        !Arc::ptr_eq(&fspec_primary, &fspec_alias),
    );
    emit_bool(
        "representation.alias_same_address",
        fspec_primary.read().unwrap().get_space() == fspec_alias.read().unwrap().get_space()
            && fspec_primary.read().unwrap().get_offset()
                == fspec_alias.read().unwrap().get_offset(),
    );
    emit_bool(
        "representation.constant_same_offset",
        constant_mimic.read().unwrap().get_offset() == fspec_primary.read().unwrap().get_offset(),
    );
    emit_bool("representation.constant_not_fspec", true);
    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = fspec_primary.clone();
    }

    let typeop = TypeOpCall;
    {
        let call = op.0.read().unwrap();
        let callspec = fd.get_call_specs(callspec_index).unwrap();
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
            callspec.prototype.get_param(0),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "locked_small_fits",
            &typeop,
            &call,
            2,
            &int4_type,
            callspec.prototype.get_param(1),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "unlocked_param",
            &typeop,
            &call,
            3,
            &factory.get_base(4, TypeMetatype::Unknown).unwrap(),
            callspec.prototype.get_param(2),
            &factory.get_base(4, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "locked_void",
            &typeop,
            &call,
            4,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            callspec.prototype.get_param(3),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "locked_oversize",
            &typeop,
            &call,
            5,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            callspec.prototype.get_param(4),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "unlocked_this_struct",
            &typeop,
            &call,
            6,
            &object_pointer,
            callspec.prototype.get_param(5),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
        emit_case(
            "unlocked_this_plain",
            &typeop,
            &call,
            7,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            callspec.prototype.get_param(6),
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
    {
        let call = op.0.read().unwrap();
        let callspec = fd.get_call_specs(callspec_index).unwrap();
        emit_case(
            "locked_ptr_after_unlock",
            &typeop,
            &call,
            1,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            callspec.prototype.get_param(0),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
    }
    fd.get_call_specs_mut(callspec_index)
        .unwrap()
        .prototype
        .parameters[0]
        .flags |= protoparam_flags::TYPE_LOCKED;
    {
        let call = op.0.read().unwrap();
        let callspec = fd.get_call_specs(callspec_index).unwrap();
        emit_case(
            "locked_ptr_after_relock",
            &typeop,
            &call,
            1,
            &char_pointer,
            callspec.prototype.get_param(0),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
    }

    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = fspec_alias;
    }
    {
        let call = op.0.read().unwrap();
        let callspec = fd.get_call_specs(callspec_index).unwrap();
        emit_case(
            "fspec_alias",
            &typeop,
            &call,
            1,
            &char_pointer,
            callspec.prototype.get_param(0),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
    }
    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = constant_mimic;
    }
    {
        let call = op.0.read().unwrap();
        let callspec = fd.get_call_specs(callspec_index).unwrap();
        emit_case(
            "constant_same_offset",
            &typeop,
            &call,
            1,
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
            callspec.prototype.get_param(0),
            &factory.get_base(8, TypeMetatype::Unknown).unwrap(),
        );
    }
    println!("rugra.typeop_call_get_input_local.status=MISMATCH");
    println!("rugra.fspec_varnode_representation.status=MISMATCH");
}
