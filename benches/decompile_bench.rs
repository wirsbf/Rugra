//! Benchmarks for Rugra decompiler
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rugra::{Address, Architecture, Decompiler};

fn benchmark_decompiler_creation(c: &mut Criterion) {
    c.bench_function("create_decompiler", |b| {
        b.iter(|| {
            black_box(Decompiler::new(Architecture::X86_64))
        });
    });
}

fn benchmark_address_creation(c: &mut Criterion) {
    c.bench_function("create_address", |b| {
        b.iter(|| {
            black_box(Address::new(0x1000))
        });
    });
}

fn benchmark_pcode_operations(c: &mut Criterion) {
    use rugra::pcode::{PcodeOp, Varnode};

    c.bench_function("create_varnode", |b| {
        b.iter(|| {
            black_box(Varnode::new_register(0, 4))
        });
    });

    c.bench_function("check_opcode_properties", |b| {
        b.iter(|| {
            let op = black_box(PcodeOp::IntAdd);
            black_box(op.is_arithmetic());
            black_box(op.is_commutative());
            black_box(op.input_count());
        });
    });
}

criterion_group!(
    benches,
    benchmark_decompiler_creation,
    benchmark_address_creation,
    benchmark_pcode_operations
);
criterion_main!(benches);
