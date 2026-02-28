//! Pretty printing and token emission
//!
//! Corresponds to Ghidra's `prettyprint.hh`

/// Trait for emitting decompilation tokens
///
/// This provides a generic interface for "printing" decompiled code,
/// allowing for different output formats (plain text, XML, HTML with markup, etc.)
pub trait Emit {
    /// Emit raw text
    fn print(&mut self, text: &str);

    /// Start a new block (e.g., '{')
    fn begin_block(&mut self);
    /// End a block (e.g., '}')
    fn end_block(&mut self);

    /// Emit an open parenthesis '('
    fn open_paren(&mut self);
    /// Emit a close parenthesis ')'
    fn close_paren(&mut self);

    /// Start a function definition
    fn begin_function(&mut self);
    /// End a function definition
    fn end_function(&mut self);

    /// Tag a type name for markup
    fn tag_type(&mut self, text: &str, _id: u64);
    /// Tag a variable name for markup
    fn tag_variable(&mut self, text: &str, _id: u64);
    /// Tag an operator for markup
    fn tag_op(&mut self, text: &str);
    /// Tag a field name for markup
    fn tag_field(&mut self, text: &str, _id: u64);
    /// Tag a function name for markup
    fn tag_func_name(&mut self, text: &str, _id: u64);
    /// Tag a comment for markup
    fn tag_comment(&mut self, text: &str);
    /// Tag a label for markup
    fn tag_label(&mut self, text: &str);
    /// Tag a case label for markup
    fn tag_case_label(&mut self, text: &str);

    /// Tag a statement line
    fn tag_line(&mut self, _indent: i32) {}

    /// Check if this emitter supports markup
    fn emits_markup(&self) -> bool { false }
}

/// Simple emitter that produces plain text with no markup
pub struct EmitNoMarkup {
    output: String,
    indent: i32,
}

impl Default for EmitNoMarkup {
    fn default() -> Self {
        Self::new()
    }
}

impl EmitNoMarkup {
    pub fn new() -> Self {
        Self {
            output: String::new(),
            indent: 0,
        }
    }

    pub fn get_output(self) -> String {
        self.output
    }

    fn do_indent(&mut self) {
        for _ in 0..self.indent {
            self.output.push_str("  ");
        }
    }
}

impl Emit for EmitNoMarkup {
    fn print(&mut self, text: &str) {
        self.output.push_str(text);
    }

    fn begin_block(&mut self) {
        self.output.push_str(" {\n");
        self.indent += 1;
        self.do_indent();
    }

    fn end_block(&mut self) {
        self.indent -= 1;
        self.output.push('\n');
        self.do_indent();
        self.output.push('}');
    }

    fn open_paren(&mut self) {
        self.output.push('(');
    }

    fn close_paren(&mut self) {
        self.output.push(')');
    }

    fn begin_function(&mut self) {
        // No-op for plain text
    }

    fn end_function(&mut self) {
        self.output.push('\n');
    }

    fn tag_type(&mut self, text: &str, _id: u64) { self.print(text); }
    fn tag_variable(&mut self, text: &str, _id: u64) { self.print(text); }
    fn tag_op(&mut self, text: &str) { self.print(text); }
    fn tag_field(&mut self, text: &str, _id: u64) { self.print(text); }
    fn tag_func_name(&mut self, text: &str, _id: u64) { self.print(text); }
    fn tag_comment(&mut self, text: &str) { self.print(text); }
    fn tag_label(&mut self, text: &str) { self.print(text); }
    fn tag_case_label(&mut self, text: &str) { self.print(text); }
}
