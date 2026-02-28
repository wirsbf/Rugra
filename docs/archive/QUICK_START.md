# 🚀 Rugra Quick Start Guide

Welcome to **Rugra** - A Rust-based decompiler for C/C++ binaries!

## 📋 Prerequisites

- **Rust 1.70+** - [Install from rustup.rs](https://rustup.rs/)
- **Git** (optional) - For cloning the repository

## ⚡ 30-Second Quick Start

```bash
# Navigate to the project
cd rugra

# Build the project
cargo build --release

# Run tests (all 67 should pass!)
cargo test

# Run the CLI
cargo run --release -- version
```

## 🎯 What Works Now (Phase 0 Complete)

✅ **Binary Loading** - Load ELF, PE, and Mach-O files
✅ **P-code IR** - Complete intermediate representation (60+ operations)
✅ **Type System** - Full C/C++ type support
✅ **Architecture Support** - 10 CPU architectures defined
✅ **Analysis Framework** - Ready for CFG/DFA/SSA
✅ **CLI Tool** - Command-line interface

## 📚 Usage Examples

### 1. As a Library

```rust
use rugra::{Decompiler, Architecture};

fn main() -> anyhow::Result<()> {
    // Create decompiler
    let mut dec = Decompiler::new(Architecture::X86_64)?;
    
    // Load binary
    let data = std::fs::read("program.exe")?;
    dec.load_binary(&data)?;
    
    println!("✅ Binary loaded successfully!");
    println!("Architecture: {}", dec.architecture());
    
    // Get function list
    let functions = dec.get_functions()?;
    println!("Found {} functions", functions.len());
    
    Ok(())
}
```

### 2. Using P-code Directly

```rust
use rugra::pcode::{PcodeBuilder, PcodeOp, Varnode};
use rugra::Address;

fn main() {
    // Create a P-code program
    let mut builder = PcodeBuilder::new(Address::new(0x1000));
    
    // Add operation: temp = reg1 + reg2
    let temp = builder.new_unique(4);
    builder.add_op(
        PcodeOp::IntAdd,
        Some(temp.clone()),
        vec![
            Varnode::new_register(1, 4),
            Varnode::new_register(2, 4),
        ],
    );
    
    // Copy to output
    builder.add_op(
        PcodeOp::Copy,
        Some(Varnode::new_register(0, 4)),
        vec![temp],
    );
    
    let program = builder.build();
    println!("{}", program);
}
```

### 3. CLI Tool

```bash
# Show version
cargo run --release -- version

# Analyze a binary (placeholder output for now)
cargo run --release -- analyze /path/to/binary.exe

# Decompile a function (framework ready, implementation in progress)
cargo run --release -- decompile binary.exe --address 0x401000
```

## 🧪 Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_pcode_operations

# Run benchmarks
cargo bench
```

## 📖 Documentation

```bash
# Generate and open documentation
cargo doc --open

# Build docs without dependencies
cargo doc --no-deps
```

## 🏗️ Project Structure

```
rugra/
├── src/
│   ├── lib.rs          # Main library API
│   ├── types.rs        # Core types (Address, Architecture, etc.)
│   ├── error.rs        # Error handling
│   ├── utils.rs        # Utility functions
│   ├── binary/         # Binary parsing (ELF, PE, Mach-O)
│   ├── pcode/          # P-code IR
│   │   ├── ops.rs      # 60+ P-code operations
│   │   ├── varnode.rs  # Storage locations
│   │   └── program.rs  # Program structure
│   ├── analysis/       # Analysis framework
│   ├── codegen/        # C code generation
│   └── bin/
│       └── rugra.rs    # CLI tool
├── benches/            # Benchmarks
├── tests/              # Integration tests (coming soon)
└── examples/           # Examples (coming soon)
```

## 🎓 Key Concepts

### P-code Operations

Rugra uses P-code (inspired by Ghidra) as its intermediate representation:

```rust
// Example P-code for: eax = eax + ebx
$U10:4 = INT_ADD eax:4, ebx:4
eax:4 = COPY $U10:4
ZF:1 = INT_EQUAL $U10:4, 0:4
```

### Varnodes

Varnodes represent storage locations:

```rust
// Register
let eax = Varnode::new_register(0, 4);

// Memory
let mem = Varnode::new_ram(0x1000, 4);

// Temporary
let temp = Varnode::new_unique(10, 8);

// Constant
let const_42 = Varnode::new_constant(42, 4);
```

### Architectures

Supported architectures:

- x86 (32-bit)
- x86-64 (64-bit)
- ARM (32-bit)
- ARM64 (AArch64)
- MIPS (32/64-bit)
- RISC-V (32/64-bit)
- PowerPC (32/64-bit)

## 🔧 Development

### Adding Features

```bash
# Make changes
vim src/analysis/cfg.rs

# Format code
cargo fmt

# Check for issues
cargo clippy

# Run tests
cargo test

# Build release
cargo build --release
```

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📊 Current Status

**Phase**: 0 - Foundation ✅ COMPLETE

**What's Working**:
- ✅ Project compiles without errors
- ✅ All 67 tests passing
- ✅ Binary parsing (ELF, PE, Mach-O)
- ✅ Complete P-code IR
- ✅ Type system
- ✅ Analysis framework structure
- ✅ Code generation framework

**What's Next** (Phase 1 - 6-8 hours):
- [ ] x86-64 disassembly integration
- [ ] Instruction to P-code translation
- [ ] Basic CFG construction
- [ ] Simple C code output

## 🐛 Troubleshooting

### Build Issues

```bash
# Clean build
cargo clean
cargo build

# Update dependencies
cargo update

# Check Rust version
rustc --version  # Should be 1.70+
```

### Test Failures

```bash
# Run tests with backtrace
RUST_BACKTRACE=1 cargo test

# Run specific failing test
cargo test test_name -- --nocapture
```

## 📚 Learning Resources

- [Rugra Documentation](README.md) - Full project documentation
- [Ghidra P-code Reference](https://ghidra.re/courses/languages/html/pcoderef.html)
- [Rust Book](https://doc.rust-lang.org/book/)
- [Binary Analysis Course](https://binary.ninja/courses/)

## 🎉 Success Indicators

After following this guide, you should:

1. ✅ Have Rugra built successfully
2. ✅ See all 67 tests passing
3. ✅ Be able to run the CLI tool
4. ✅ Understand basic P-code concepts
5. ✅ Be ready to contribute or extend

## 💡 Examples to Try

### Example 1: Explore P-code

```bash
# Create a new Rust file
cat > examples/pcode_demo.rs << 'EOF'
use rugra::pcode::{PcodeOp, Varnode};

fn main() {
    println!("P-code Operations:");
    println!("  {}", PcodeOp::IntAdd);
    println!("  {}", PcodeOp::Store);
    println!("  {}", PcodeOp::Branch);
    
    let reg = Varnode::new_register(0, 4);
    println!("\nVarnode: {}", reg);
}
EOF

cargo run --example pcode_demo
```

### Example 2: Bit Manipulation

```bash
cat > examples/utils_demo.rs << 'EOF'
use rugra::utils::bits;

fn main() {
    let value = 0b11010110u64;
    println!("Extract bits [2:4]: {:04b}", bits::extract(value, 2, 4));
    println!("Popcount: {}", bits::popcount(value));
    println!("Leading zeros: {}", bits::leading_zeros(value));
}
EOF

cargo run --example utils_demo
```

## 🆘 Getting Help

- **Issues**: [GitHub Issues](https://github.com/yourusername/rugra/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/rugra/discussions)
- **Documentation**: `cargo doc --open`

## 🎯 Next Steps

1. **Explore the code**: Browse `src/` to understand the architecture
2. **Read STATUS.md**: See detailed progress and roadmap
3. **Check examples/**: More usage examples (coming soon)
4. **Join development**: Help implement Phase 1 features!

---

**Welcome aboard! Happy decompiling! 🦀**

*Last Updated: 2024*
*Version: 0.1.0-alpha*
*Status: Phase 0 Complete ✅*