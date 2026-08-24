use std::sync::Arc;

use rugra::type_system::datatype::{Datatype, TypeMetatype, TypePointer};
use rugra::type_system::TypeBase;
use rugra::typeop::{TypeOp, TypeOpLoad, TypeOpStore};
use rugra::address::{Address, SeqNum};
use rugra::op::PcodeOp;
use rugra::opcodes::OpCode;
use rugra::varnode::Varnode;
use std::sync::RwLock;

fn pointer_to(pointee: Arc<Datatype>) -> Arc<Datatype> {
    Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(String::new(), 8, TypeMetatype::Pointer),
        ptr_to: pointee,
        wordsize: 1,
    }))
}

fn main() {
    let progress = Arc::new(Datatype::Base(TypeBase::new(
        "ProgressData".into(),
        32,
        TypeMetatype::Struct,
    )));
    let progress_ptr = pointer_to(progress.clone());
    let int4_type = Arc::new(Datatype::Base(TypeBase::new(
        "int4".into(),
        4,
        TypeMetatype::Int,
    )));
    let int4_ptr = pointer_to(int4_type.clone());

    let make_vn = |size, offset, datatype: Arc<Datatype>| {
        let mut varnode = Varnode::new(size, Address::new(offset));
        varnode.v_type = Some(datatype);
        Arc::new(RwLock::new(varnode))
    };
    let progress_source = make_vn(8, 0x100, progress_ptr.clone());
    let int4_source = make_vn(8, 0x108, int4_ptr.clone());
    let value16 = make_vn(16, 0x200, Arc::new(Datatype::Base(TypeBase::new(
        "value16".into(), 16, TypeMetatype::Unknown,
    ))));
    let value4 = make_vn(4, 0x210, Arc::new(Datatype::Base(TypeBase::new(
        "value4".into(), 4, TypeMetatype::Unknown,
    ))));
    let value32 = make_vn(32, 0x220, Arc::new(Datatype::Base(TypeBase::new(
        "value32".into(), 32, TypeMetatype::Unknown,
    ))));
    let mut load = PcodeOp::new(SeqNum::new(Address::new(0), 0), OpCode::CPUI_LOAD);
    load.inrefs.push(make_vn(8, 0, Arc::new(Datatype::Base(TypeBase::new(
        "space".into(), 8, TypeMetatype::Unknown,
    )))));
    load.inrefs.push(progress_source.clone());
    let mut load_result = |target: &Arc<RwLock<Varnode>>| {
        load.output = Some(target.clone());
        TypeOpLoad.propagate_type(&progress_ptr, &load, 1, -1)
    };
    let load16 = load_result(&value16);
    let load4 = load_result(&value4);
    let load32 = load_result(&value32);
    load.inrefs[1] = int4_source.clone();
    load.output = Some(value4.clone());
    let load_int4 = TypeOpLoad.propagate_type(&int4_ptr, &load, 1, -1);

    let store_result = |target: Arc<RwLock<Varnode>>| {
        let mut store = PcodeOp::new(SeqNum::new(Address::new(0), 0), OpCode::CPUI_STORE);
        store.inrefs.push(make_vn(8, 0, Arc::new(Datatype::Base(TypeBase::new(
            "space".into(), 8, TypeMetatype::Unknown,
        )))));
        store.inrefs.push(progress_source.clone());
        store.inrefs.push(target);
        TypeOpStore.propagate_type(&progress_ptr, &store, 1, 2)
    };
    let store16 = store_result(value16.clone());
    let store4 = store_result(value4.clone());
    let store32 = store_result(value32.clone());

    println!("fixture=TYPE-PTRWIDTH-PTRSUB-0001");
    println!("load_struct32_deref16_null={}", load16.is_none() as u8);
    println!("load_struct32_deref4_null={}", load4.is_none() as u8);
    println!(
        "load_struct32_deref32_identity={}",
        load32
            .as_ref()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &progress)) as u8
    );
    println!("store_struct32_deref16_null={}", store16.is_none() as u8);
    println!("store_struct32_deref4_null={}", store4.is_none() as u8);
    println!(
        "store_struct32_deref32_identity={}",
        store32
            .as_ref()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &progress)) as u8
    );
    println!(
        "load_int4_deref4_identity={}",
        load_int4
            .as_ref()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &int4_type)) as u8
    );
    println!(
        "source_type_alias={}",
        progress_source
            .read()
            .unwrap()
            .v_type
            .as_ref()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &progress_ptr)) as u8
    );
}
