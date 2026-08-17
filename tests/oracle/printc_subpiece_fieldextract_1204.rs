// Locked Ghidra 12.0.4 oracle for PRINTC-SUBPIECE-FIELDEXTRACT-0001
// (Rust side). Mirrors tests/oracle/printc_subpiece_fieldextract_1204.cc
// record-for-record:
//   - piece.*     : Datatype::is_piece_structured sweep (type.hh:929).
//   - cast.*      : CastStrategyC::is_subpiece_cast partial arms + enum
//                   mapping + struct rejection (cast.cc:411-432).
//   - armA/armB   : the two printc.cc:846-871 bodies via the RPN dispatch
//                   (PrintC::op_subpiece_rpn — the twin of Ghidra's public
//                   virtual PrintC::opSubpiece, printc.hh:334):
//                     armA.field     -> "S.hi"   (pushPartialSymbol walk)
//                     armA.array     -> "S.arr[0]" (array getSubEntry walk)
//                     armA.synthetic -> "S._2_4_" (unnamedField, printlanguage.cc:719)
//                     armB.field     -> "S.lo"   (findTruncation/object_member)
//
// The object graph mirrors the C++ fixture: a register-space Varnode typed
// with the fixture struct, a HighVariable whose symbol "S" carries the
// struct type (symbol_offset -1 = perfect match), a SUBPIECE op with
// SPECIAL_PRINT set reading it, and a 4-byte output.

use std::sync::{Arc, RwLock};

use rugra::address::Address;
use rugra::database::Symbol;
use rugra::op::{op_addl_flags, PcodeOp};
use rugra::opcodes::OpCode;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printc::PrintC;
use rugra::space::AddressSpace;
use rugra::type_system::datatype::{
    Datatype, TypeArray, TypeBase, TypeMetatype, TypePartialEnum, TypePartialStruct,
    TypePartialUnion, TypePointer, TypeStruct, TypeUnion,
};
use rugra::variable::HighVariable;
use rugra::varnode::{varnode_flags, Varnode};

type VnRef = Arc<RwLock<Varnode>>;

fn int4() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)))
}

fn uint4() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new("uint".to_string(), 4, TypeMetatype::Uint)))
}

/// fixture_pair { int lo @0; int hi @4; } (same layout as the C++ fixture).
fn fixture_pair() -> Arc<Datatype> {
    Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("fixture_pair".to_string(), 8, TypeMetatype::Struct),
        fields: vec![
            rugra::type_system::datatype::TypeField {
                name: "lo".to_string(),
                offset: 0,
                type_ptr: int4(),
            },
            rugra::type_system::datatype::TypeField {
                name: "hi".to_string(),
                offset: 4,
                type_ptr: int4(),
            },
        ],
    }))
}

/// fixture_arr { int arr[2] @0; int tail @8; } — the tail field mirrors the
/// C++ fixture's guard against TypeStruct::setFields' needs_resolution flag
/// (type.cc:1569-1571: field[0] filling the whole struct).
fn fixture_arr() -> Arc<Datatype> {
    let arr2 = Arc::new(Datatype::Array(TypeArray {
        base: TypeBase::new("int[2]".to_string(), 8, TypeMetatype::Array),
        array_of: int4(),
        num_elements: 2,
    }));
    Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("fixture_arr".to_string(), 12, TypeMetatype::Struct),
        fields: vec![
            rugra::type_system::datatype::TypeField {
                name: "arr".to_string(),
                offset: 0,
                type_ptr: arr2,
            },
            rugra::type_system::datatype::TypeField {
                name: "tail".to_string(),
                offset: 8,
                type_ptr: int4(),
            },
        ],
    }))
}

fn fixture_union() -> Arc<Datatype> {
    Arc::new(Datatype::Union(TypeUnion {
        base: TypeBase::new("fixture_alt".to_string(), 4, TypeMetatype::Union),
        fields: vec![
            rugra::type_system::datatype::TypeField {
                name: "a".to_string(),
                offset: 0,
                type_ptr: int4(),
            },
            rugra::type_system::datatype::TypeField {
                name: "b".to_string(),
                offset: 0,
                type_ptr: uint4(),
            },
        ],
    }))
}

/// fixture_inner { long x } — single field fills the whole struct. The flag
/// is set MANUALLY here to mirror the REAL TypeFactory::setFields behaviour
/// (type.cc:1569-1871); Rugra's own TypeFactory::set_fields does not yet set
/// it (TYPEFACTORY-NEEDSRES-SINGLEFIELD-0001).
fn fixture_inner() -> Arc<Datatype> {
    let int8 = Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(),
        8,
        TypeMetatype::Int,
    )));
    let mut base = TypeBase::new("fixture_inner".to_string(), 8, TypeMetatype::Struct);
    base.flags |= rugra::type_system::datatype::type_flags::NEEDS_RESOLUTION;
    Arc::new(Datatype::Struct(TypeStruct {
        base,
        fields: vec![rugra::type_system::datatype::TypeField {
            name: "x".to_string(),
            offset: 0,
            type_ptr: int8,
        }],
    }))
}

/// fixture_outer { fixture_inner in @0; long tail @8 } — two fields, no
/// needs_resolution (mirrors the C++ fixture construction).
fn fixture_outer() -> Arc<Datatype> {
    let int8 = Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(),
        8,
        TypeMetatype::Int,
    )));
    Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("fixture_outer".to_string(), 16, TypeMetatype::Struct),
        fields: vec![
            rugra::type_system::datatype::TypeField {
                name: "in".to_string(),
                offset: 0,
                type_ptr: fixture_inner(),
            },
            rugra::type_system::datatype::TypeField {
                name: "tail".to_string(),
                offset: 8,
                type_ptr: int8,
            },
        ],
    }))
}

fn fixture_enum() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        "fixture_mode".to_string(),
        4,
        TypeMetatype::Enum,
    )))
}

/// Register-space struct-typed Varnode with a HighVariable whose symbol
/// (symbol_offset -1 = perfect whole-map match) carries the same struct
/// type. Mirrors the C++ fixture's type-locked ScopeLocal symbol
/// (addSymbol + setAttribute(typelock)) attached to the varnode via
/// Varnode::setSymbolProperties (varnode.cc:409-421).
fn struct_vn(
    container: Arc<Datatype>,
    symbol_name: &str,
    reg_offset: u64,
    size: usize,
    explicit: bool,
) -> VnRef {
    let mut vn = Varnode::new_with_space(size, AddressSpace::Register, reg_offset);
    vn.v_type = Some(container.clone());
    if explicit {
        vn.set_flags(varnode_flags::EXPLICIT);
    }
    let mut high = HighVariable::new(container.clone());
    high.name = symbol_name.to_string();
    let mut symbol = Symbol::new(0, symbol_name, "fixture_pair");
    symbol.set_dtype(container);
    symbol.display_name = symbol_name.to_string();
    high.symbol = Some(Arc::new(RwLock::new(symbol)));
    high.symbol_offset = -1;
    vn.high = Some(Arc::new(RwLock::new(high)));
    Arc::new(RwLock::new(vn))
}

/// SUBPIECE op: in(0) = struct vn, in(1) = constant lsb, out = `out_size`
/// bytes (optionally typed via `out_type`, which also feeds the output's
/// HighVariable — the allowCast arm reads the OUTPUT high type, printc.cc:859
/// + 2019), SPECIAL_PRINT set (Funcdata::opMarkSpecialPrint, funcdata.hh:483).
fn subpiece_op(
    vn: &VnRef,
    lsb: u64,
    out_size: usize,
    out_type: Option<Arc<Datatype>>,
    pc: u64,
) -> Arc<RwLock<PcodeOp>> {
    let constant = Arc::new(RwLock::new(Varnode::new_with_space(
        1,
        AddressSpace::Const,
        lsb,
    )));
    let mut out = Varnode::new_with_space(out_size, AddressSpace::Unique, pc);
    if let Some(ref ot) = out_type {
        out.v_type = Some(ot.clone());
    }
    let mut out_high = HighVariable::new(
        out_type.unwrap_or_else(|| {
            Arc::new(Datatype::Base(TypeBase::new(
                "undefined".to_string(),
                out_size,
                TypeMetatype::Unknown,
            )))
        }),
    );
    out_high.name = String::new();
    out.high = Some(Arc::new(RwLock::new(out_high)));
    let out = Arc::new(RwLock::new(out));
    let mut op = PcodeOp::new(rugra::address::SeqNum::new(Address::new(pc), 0), OpCode::CPUI_SUBPIECE);
    op.inrefs.push(vn.clone());
    op.inrefs.push(constant);
    op.output = Some(out);
    op.addlflags |= op_addl_flags::SPECIAL_PRINT;
    Arc::new(RwLock::new(op))
}

fn render(op_arc: &Arc<RwLock<PcodeOp>>) -> String {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.op_subpiece_rpn(op_arc);
    let emitter = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC fixture emitter type");
    emitter.get_output()
}

fn run_piece_sweep() {
    let pair = fixture_pair();
    let alt = fixture_union();
    let arr2 = Arc::new(Datatype::Array(TypeArray {
        base: TypeBase::new("int[2]".to_string(), 8, TypeMetatype::Array),
        array_of: int4(),
        num_elements: 2,
    }));
    let partial_struct = Arc::new(Datatype::PartialStruct(TypePartialStruct::new(
        pair.clone(),
        4,
        4,
        None,
    )));
    let partial_union = Arc::new(Datatype::PartialUnion(TypePartialUnion::new(
        alt.clone(),
        0,
        2,
        None,
    )));
    let en = fixture_enum();
    let partial_enum = Arc::new(Datatype::PartialEnum(TypePartialEnum::new(
        en.clone(),
        0,
        2,
        None,
    )));
    let ptr = Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
        ptr_to: int4(),
        wordsize: 1,
    }));

    println!("piece.struct={}", pair.is_piece_structured() as u8);
    println!("piece.union={}", alt.is_piece_structured() as u8);
    println!("piece.array={}", arr2.is_piece_structured() as u8);
    println!("piece.partialstruct={}", partial_struct.is_piece_structured() as u8);
    println!("piece.partialunion={}", partial_union.is_piece_structured() as u8);
    // Rugra keeps TypeMetatype::Enum on enum types where Ghidra's TypeEnum
    // ctor normalizes to TYPE_UINT/TYPE_INT (type.hh:489-494) — both sides
    // observe false for is_piece_structured.
    println!("piece.enum={}", en.is_piece_structured() as u8);
    println!("piece.partialenum={}", partial_enum.is_piece_structured() as u8);
    println!("piece.int={}", int4().is_piece_structured() as u8);
    println!("piece.uint={}", uint4().is_piece_structured() as u8);
    println!("piece.pointer={}", ptr.is_piece_structured() as u8);
}

fn run_cast_sweep() {
    let printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    let cs = &printer.cast_strategy;
    let int4 = int4();
    let int8 = Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(),
        8,
        TypeMetatype::Int,
    )));
    let pair = fixture_pair();
    let alt = fixture_union();
    let partial_struct = Arc::new(Datatype::PartialStruct(TypePartialStruct::new(
        pair.clone(),
        4,
        4,
        None,
    )));
    let partial_union = Arc::new(Datatype::PartialUnion(TypePartialUnion::new(
        alt.clone(),
        0,
        2,
        None,
    )));
    let en = fixture_enum();
    let partial_enum = Arc::new(Datatype::PartialEnum(TypePartialEnum::new(
        en.clone(),
        0,
        2,
        None,
    )));

    println!("cast.int_int_0={}", cs.is_subpiece_cast(&int4, &int8, 0) as u8);
    println!(
        "cast.int_partialstruct_0={}",
        cs.is_subpiece_cast(&int4, &partial_struct, 0) as u8
    );
    println!(
        "cast.int_partialunion_0={}",
        cs.is_subpiece_cast(&int4, &partial_union, 0) as u8
    );
    println!(
        "cast.int_partialstruct_2={}",
        cs.is_subpiece_cast(&int4, &partial_struct, 2) as u8
    );
    println!("cast.int_struct_0={}", cs.is_subpiece_cast(&int4, &pair, 0) as u8);
    println!("cast.int_enum_0={}", cs.is_subpiece_cast(&int4, &en, 0) as u8);
    println!("cast.enum_int8_0={}", cs.is_subpiece_cast(&en, &int8, 0) as u8);
    // TypePartialEnum delegates to the TypeEnum ctor (type.cc:2255-2262)
    // which normalizes the stored metatype to TYPE_UINT, so a Ghidra
    // partial-enum passes both whitelists like a plain enum.
    println!(
        "cast.int_partialenum_0={}",
        cs.is_subpiece_cast(&int4, &partial_enum, 0) as u8
    );
    println!(
        "cast.partialenum_out_0={}",
        cs.is_subpiece_cast(&partial_enum, &int8, 0) as u8
    );
    println!(
        "cast.partialstruct_out_0={}",
        cs.is_subpiece_cast(&partial_struct, &int8, 0) as u8
    );
}

fn run_subpiece_arms() {
    // armA.field: explicit vn, symbol S over fixture_pair, lsb=4 -> S.hi.
    {
        let vn = struct_vn(fixture_pair(), "S", 0x40, 8, true);
        let op = subpiece_op(&vn, 4, 4, None, 0x5010);
        println!("armA.field={}", render(&op));
    }
    // armA.array: explicit vn, symbol A over fixture_arr, lsb=0 -> A.arr[0].
    {
        let vn = struct_vn(fixture_arr(), "A", 0x48, 8, true);
        let op = subpiece_op(&vn, 0, 4, None, 0x6010);
        println!("armA.array={}", render(&op));
    }
    // armA.synthetic: explicit vn, symbol Y over fixture_pair, lsb=2,
    // outsize 4: findTruncation(2,4) spans past field lo (2+4>4) ->
    // synthetic unnamedField(2,4) -> Y._2_4_.
    {
        let vn = struct_vn(fixture_pair(), "Y", 0x50, 8, true);
        let op = subpiece_op(&vn, 2, 4, None, 0x7010);
        println!("armA.synthetic={}", render(&op));
    }
    // armB.field: NON-explicit vn (high still named/symbolled "B"), lsb=0,
    // outsize 4 -> findTruncation(0,4) -> field lo, offset==0 -> B.lo.
    {
        let vn = struct_vn(fixture_pair(), "B", 0x58, 8, false);
        let op = subpiece_op(&vn, 0, 4, None, 0x8010);
        println!("armB.field={}", render(&op));
    }
    // armA.nested: explicit vn, symbol N over fixture_outer (16 bytes),
    // lsb=0, outsize 8 -> descent .in, then the inner struct's
    // needsResolution findResolve arm: no cached resolution -> field[0].type
    // (long) != inner -> NO break (type.cc:1944-1951 / printc.cc:1969-1971)
    // -> findTruncation descends .x -> N.in.x.
    {
        let vn = struct_vn(fixture_outer(), "N", 0x60, 16, true);
        let op = subpiece_op(&vn, 0, 8, None, 0x9010);
        println!("armA.nested={}", render(&op));
    }
    // armA.allowcast: explicit vn, symbol C over fixture_pair, lsb=0,
    // outsize 2 typed uint2 ("uint2", Ghidra getBase(2,TYPE_UINT) display).
    // Walk: .lo descent, then at ct=int4 the allowCast arm reads outtype
    // from the OUTPUT high (printc.cc:859/2019) ->
    // isSubpieceCastEndian(uint2,int4,0,LE) true -> (uint2)C.lo.
    {
        let vn = struct_vn(fixture_pair(), "C", 0x68, 8, true);
        let uint2 = Arc::new(Datatype::Base(TypeBase::new(
            "uint2".to_string(),
            2,
            TypeMetatype::Uint,
        )));
        let op = subpiece_op(&vn, 0, 2, Some(uint2), 0xa010);
        println!("armA.allowcast={}", render(&op));
    }
}

fn main() {
    run_piece_sweep();
    run_cast_sweep();
    run_subpiece_arms();
}
