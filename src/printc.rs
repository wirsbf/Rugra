//! C language printing implementation
//!
//! Corresponds to Ghidra's `printc.hh` and `printc.cc`

use crate::fspec::FuncProto;
use crate::funcdata::Funcdata;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::prettyprint::Emit;
use crate::printlanguage::PrintLanguage;
use crate::type_system::Datatype;
use crate::varnode::Varnode;
use std::sync::{Arc, RwLock};

/// Printer for the C programming language
///
/// Corresponds to Ghidra's `PrintC` class. This handles the conversion
/// of high-level IR (P-code and Control Flow) into valid C source code.
pub struct PrintC {
    emit: Box<dyn Emit>,
}

impl PrintC {
    /// Create a new PrintC instance
    pub fn new(emit: Box<dyn Emit>) -> Self {
        Self { emit }
    }
}

impl PrintLanguage for PrintC {
    fn get_emit(&mut self) -> &mut dyn Emit {
        self.emit.as_mut()
    }

    fn set_emit(&mut self, emit: Box<dyn Emit>) {
        self.emit = emit;
    }

    fn doc_function(&mut self, fd: &Funcdata) {
        // 1. Emit signature
        // For now, assume a proto is available in Funcdata (logic to be added)
        // self.doc_all_proto(&fd.proto);

        self.emit.print("void ");
        self.emit.tag_func_name(fd.get_name(), 0);
        self.emit.open_paren();
        self.emit.close_paren();

        // 2. Emit body
        self.emit.begin_block();

        // Emit statements from all basic blocks
        for block_arc in &fd.bblocks.blocks {
            let block = block_arc.read().unwrap();
            let ops = block.get_ops();
            for op_ref in &ops {
                let op = op_ref.0.read().unwrap();
                self.doc_statement(&op);
            }
        }

        self.emit.end_block();
    }

    fn doc_all_proto(&mut self, _proto: &FuncProto) {
        // TODO: Implement prototype emission
    }

    fn doc_variable_decl(&mut self, vn: &Varnode) {
        if let Some(dt) = &vn.v_type {
            self.push_type(dt);
            self.emit.print(" ");
        } else {
            self.emit.print("int "); // Fallback
        }
        self.push_varnode(vn, None);
        self.emit.print(";");
    }

    fn doc_statement(&mut self, op: &PcodeOp) {
        self.emit.tag_line(0);
        op.push(self); // This will call the appropriate op_xxx method
        self.emit.print(";");
    }

    // --- P-code Op-code specific emission ---

    fn op_copy(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.emit.tag_op(" = ");
            if let Some(in0) = op.get_in(0) {
                self.push_varnode(&in0.read().unwrap(), Some(op));
            }
        }
    }

    fn op_load(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.emit.tag_op(" = ");
            self.emit.tag_op("*");
            if let Some(in1) = op.get_in(1) {
                self.push_varnode(&in1.read().unwrap(), Some(op));
            }
        }
    }

    fn op_store(&mut self, op: &PcodeOp) {
        self.emit.tag_op("*");
        if let Some(in1) = op.get_in(1) {
            self.push_varnode(&in1.read().unwrap(), Some(op));
        }
        self.emit.tag_op(" = ");
        if let Some(in2) = op.get_in(2) {
            self.push_varnode(&in2.read().unwrap(), Some(op));
        }
    }

    fn op_binary(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.emit.tag_op(" = ");
            if let Some(in0) = op.get_in(0) {
                self.push_varnode(&in0.read().unwrap(), Some(op));
            }

            let op_sym = match op.opcode {
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_FLOAT_EQUAL => " == ",
                OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_FLOAT_NOTEQUAL => " != ",
                OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS | OpCode::CPUI_FLOAT_LESS => " < ",
                OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_FLOAT_LESSEQUAL => " <= ",
                OpCode::CPUI_INT_ADD | OpCode::CPUI_FLOAT_ADD => " + ",
                OpCode::CPUI_INT_SUB | OpCode::CPUI_FLOAT_SUB => " - ",
                OpCode::CPUI_INT_MULT | OpCode::CPUI_FLOAT_MULT => " * ",
                OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_FLOAT_DIV => " / ",
                OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM => " % ",
                OpCode::CPUI_INT_AND => " & ",
                OpCode::CPUI_INT_OR => " | ",
                OpCode::CPUI_INT_XOR => " ^ ",
                OpCode::CPUI_INT_LEFT => " << ",
                OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => " >> ",
                OpCode::CPUI_BOOL_AND => " && ",
                OpCode::CPUI_BOOL_OR => " || ",
                OpCode::CPUI_BOOL_XOR => " ^ ",
                _ => " op ",
            };

            self.emit.print(op_sym);
            if let Some(in1) = op.get_in(1) {
                self.push_varnode(&in1.read().unwrap(), Some(op));
            }
        }
    }

    fn op_unary(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.emit.tag_op(" = ");

            let op_sym = match op.opcode {
                OpCode::CPUI_INT_NOT => "~",
                OpCode::CPUI_INT_NEG => "-",
                OpCode::CPUI_BOOL_NOT => "!",
                OpCode::CPUI_FLOAT_NEG => "-",
                _ => "op",
            };
            self.emit.print(op_sym);

            if let Some(in0) = op.get_in(0) {
                self.push_varnode(&in0.read().unwrap(), Some(op));
            }
        }
    }

    fn op_multiequal(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.emit.tag_op(" = ");
            self.emit.print("phi");
            self.emit.open_paren();
            for i in 0..op.num_input() {
                if i > 0 {
                    self.emit.print(", ");
                }
                if let Some(vn) = op.get_in(i) {
                    self.push_varnode(&vn.read().unwrap(), Some(op));
                }
            }
            self.emit.close_paren();
        }
    }

    fn op_indirect(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.emit.tag_op(" = ");
            if let Some(in0) = op.get_in(0) {
                self.push_varnode(&in0.read().unwrap(), Some(op));
            }
            self.emit.print(" (indirect)");
        }
    }

    fn op_call(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.emit.tag_op(" = ");
        }
        if let Some(in0) = op.get_in(0) {
            self.push_varnode(&in0.read().unwrap(), Some(op));
        }
        self.emit.open_paren();
        for i in 1..op.num_input() {
            if i > 1 {
                self.emit.print(", ");
            }
            if let Some(vn) = op.get_in(i) {
                self.push_varnode(&vn.read().unwrap(), Some(op));
            }
        }
        self.emit.close_paren();
    }

    fn op_return(&mut self, op: &PcodeOp) {
        self.emit.print("return");
        if op.num_input() > 1 {
            self.emit.print(" ");
            if let Some(in1) = op.get_in(1) {
                self.push_varnode(&in1.read().unwrap(), Some(op));
            }
        }
    }

    fn push_type(&mut self, dt: &Datatype) {
        self.emit.tag_type(dt.get_name(), dt.get_id());
    }

    fn push_varnode(&mut self, vn: &Varnode, _op: Option<&PcodeOp>) {
        // In real Ghidra, this looks up the HighVariable/Symbol
        // For now, use address as name
        let name = format!("v_{}_{:x}", vn.get_size(), vn.get_offset());
        self.emit.tag_variable(&name, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::opcodes::OpCode;
    use crate::prettyprint::EmitNoMarkup;

    #[test]
    fn test_print_c_copy() {
        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);

        let mut vbank = crate::varnode::VarnodeBank::new();
        let out_vn = vbank.create(4, Address::new(0x1000));
        let in_vn = vbank.create(4, Address::new(0x2000));

        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x100), 0),
            OpCode::CPUI_COPY,
        );
        op.output = Some(out_vn);
        op.inrefs.push(in_vn);

        printer.op_copy(&op);
        // Verify emission doesn't panic
    }

    #[test]
    fn test_doc_function_stub() {
        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);
        let fd = Funcdata::new("test_func", Address::new(0x1000), 0x100);

        printer.doc_function(&fd);
    }
}
