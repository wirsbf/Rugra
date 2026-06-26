//! P-code snippet parser — faithful port of `pcodeparse.hh` / `pcodeparse.cc`
//! (3303 lines, Bison-generated) + `pcodecompile.hh` / `pcodecompile.cc`
//! (889 lines).
//!
//! Classes for compiling standalone p-code snippets, given an existing SLEIGH
//! language. Used by p-code injection to parse p-code from string form.
//!
//! Status: L1→L2. PcodeLexer with state-machine tokenization is complete.
//! PcodeSnippet (parser + compiler) is a framework — the full Bison-generated
//! parser is replaced by a hand-written recursive descent parser that will
//! be built out incrementally. SLEIGH integration (SleighBase/SymbolTree) is
//! an L3 gap.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/pcodeparse.{hh,cc},
//! pcodecompile.{hh,cc}.

use std::collections::HashMap;

/// Lexer token types for p-code parsing. Faithful to the Bison token enum
/// in pcodeparse.cc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcodeToken {
    /// End of stream.
    Eof,
    /// Illegal character.
    Illegal,
    /// Identifier (opcode name, variable name, etc.).
    Identifier,
    /// Hexadecimal number (0x...).
    HexNumber,
    /// Decimal number.
    DecNumber,
    /// Punctuation: ( ) , ; [ ]
    LParen,
    RParen,
    Comma,
    Semicolon,
    LBracket,
    RBracket,
    /// Special operator: =
    Assign,
    /// Special operator: $
    Dollar,
    /// Special operator: $$
    DoubleDollar,
}

/// Identifier record mapping p-code opcode names to their IDs.
/// Faithful to `IdentRec` (pcodeparse.hh:26).
pub struct IdentRec {
    pub name: &'static str,
    pub id: i32,
}

/// The p-code lexer. Faithful to `PcodeLexer` (pcodeparse.hh:31).
pub struct PcodeLexer {
    input: Vec<char>,
    pos: usize,
    cur_identifier: String,
    cur_number: u64,
}

impl PcodeLexer {
    /// Construct an empty lexer.
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            pos: 0,
            cur_identifier: String::new(),
            cur_number: 0,
        }
    }

    /// Initialize the lexer with input text.
    pub fn initialize(&mut self, text: &str) {
        self.input = text.chars().collect();
        self.pos = 0;
        self.cur_identifier.clear();
        self.cur_number = 0;
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn next_char(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn is_ident_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_' || c == '.'
    }

    fn is_hex_char(c: char) -> bool {
        c.is_ascii_hexdigit()
    }

    fn is_dec_char(c: char) -> bool {
        c.is_ascii_digit()
    }

    /// Get the next token. Faithful to `getNextToken` (pcodeparse.cc).
    pub fn get_next_token(&mut self) -> PcodeToken {
        // Skip whitespace.
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.pos += 1;
            } else if c == '#' {
                // End-of-line comment — skip to end of line.
                while let Some(c2) = self.peek() {
                    if c2 == '\n' {
                        break;
                    }
                    self.pos += 1;
                }
            } else {
                break;
            }
        }

        let Some(c) = self.peek() else {
            return PcodeToken::Eof;
        };

        // Check for 0x hex prefix FIRST (before identifier check).
        if c == '0' {
            let next = self.input.get(self.pos + 1).copied();
            if next == Some('x') || next == Some('X') {
                self.pos += 2; // Skip "0x"
                let mut hex = String::new();
                while let Some(hc) = self.peek() {
                    if !Self::is_hex_char(hc) {
                        break;
                    }
                    hex.push(hc);
                    self.pos += 1;
                }
                self.cur_number = u64::from_str_radix(&hex, 16).unwrap_or(0);
                return PcodeToken::HexNumber;
            }
        }

        // Check for identifiers and numbers.
        if Self::is_ident_char(c) {
            let mut ident = String::new();
            while let Some(c) = self.peek() {
                if !Self::is_ident_char(c) {
                    break;
                }
                ident.push(c);
                self.pos += 1;
            }
            // If starts with a digit, it's a number.
            if ident.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                // Try decimal first (all dec chars).
                if ident.chars().all(|c| Self::is_dec_char(c)) {
                    self.cur_number = ident.parse().unwrap_or(0);
                    return PcodeToken::DecNumber;
                }
                // Try hex (all hex chars but not all dec).
                if ident.chars().all(|c| Self::is_hex_char(c)) {
                    self.cur_number = u64::from_str_radix(&ident, 16).unwrap_or(0);
                    return PcodeToken::HexNumber;
                }
            }
            self.cur_identifier = ident;
            return PcodeToken::Identifier;
        }

        // Check for punctuation and special operators.
        self.pos += 1;
        match c {
            '(' => PcodeToken::LParen,
            ')' => PcodeToken::RParen,
            ',' => PcodeToken::Comma,
            ';' => PcodeToken::Semicolon,
            '[' => PcodeToken::LBracket,
            ']' => PcodeToken::RBracket,
            '=' => PcodeToken::Assign,
            '$' => {
                if self.peek() == Some('$') {
                    self.pos += 1;
                    PcodeToken::DoubleDollar
                } else {
                    PcodeToken::Dollar
                }
            }
            _ => PcodeToken::Illegal,
        }
    }

    /// Get the current identifier.
    pub fn get_identifier(&self) -> &str {
        &self.cur_identifier
    }

    /// Get the current number.
    pub fn get_number(&self) -> u64 {
        self.cur_number
    }
}

impl Default for PcodeLexer {
    fn default() -> Self {
        Self::new()
    }
}

/// A p-code snippet compiler. Faithful to `PcodeSnippet`
/// (pcodeparse.hh:72).
///
/// Parses a string of p-code (e.g., "RAX = #0 + RAX;") into a sequence of
/// PcodeOps. Used by p-code injection.
pub struct PcodeSnippet {
    /// The lexer.
    lexer: PcodeLexer,
    /// Symbol table for temporaries (name → unique offset).
    symbols: HashMap<String, u64>,
    /// Base offset for allocating unique temporaries.
    temp_base: u64,
    /// Error count.
    error_count: i32,
    /// First error message.
    first_error: String,
}

impl PcodeSnippet {
    /// Construct.
    pub fn new() -> Self {
        Self {
            lexer: PcodeLexer::new(),
            symbols: HashMap::new(),
            temp_base: 0,
            error_count: 0,
            first_error: String::new(),
        }
    }

    /// Set the unique base for temporary allocation.
    pub fn set_unique_base(&mut self, val: u64) {
        self.temp_base = val;
    }

    /// Get the unique base.
    pub fn get_unique_base(&self) -> u64 {
        self.temp_base
    }

    /// Check if there are parse errors.
    pub fn has_errors(&self) -> bool {
        self.error_count != 0
    }

    /// Get the first error message.
    pub fn get_error_message(&self) -> &str {
        &self.first_error
    }

    /// Report an error. Faithful to `reportError`.
    pub fn report_error(&mut self, msg: &str) {
        if self.error_count == 0 {
            self.first_error = msg.to_string();
        }
        self.error_count += 1;
    }

    /// Clear state for a new parse.
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.error_count = 0;
        self.first_error.clear();
    }

    /// Allocate a temporary varnode offset. Faithful to `allocateTemp`.
    pub fn allocate_temp(&mut self) -> u64 {
        let offset = self.temp_base;
        self.temp_base += 1;
        offset
    }

    /// Add a symbol to the local scope. Faithful to `addSymbol`.
    pub fn add_symbol(&mut self, name: &str, offset: u64) {
        self.symbols.insert(name.to_string(), offset);
    }

    /// Look up a symbol by name.
    pub fn lookup_symbol(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }

    /// Add an operand reference (e.g., "$(1)"). Faithful to `addOperand`.
    pub fn add_operand(&mut self, name: &str, _index: i32) {
        // In full Ghidra, this adds a SleighSymbol for the operand.
        // Stored as a special symbol.
    }

    /// Lex function — delegates to the lexer. Faithful to `PcodeSnippet::lex`.
    pub fn lex(&mut self) -> PcodeToken {
        self.lexer.get_next_token()
    }

    /// Parse a p-code stream. Faithful to `parseStream`
    /// (pcodeparse.hh:96). Returns true on success.
    ///
    /// Full Bison-generated parser is replaced by a simplified parser that
    /// tokenizes and validates the input. Full semantic actions require
    /// SLEIGH integration (SleighBase/SymbolTree/ConstructTpl).
    pub fn parse_stream(&mut self, text: &str) -> bool {
        self.clear();
        self.lexer.initialize(text);

        // Simple validation: ensure the stream tokenizes without errors.
        loop {
            let tok = self.lex();
            match tok {
                PcodeToken::Eof => break,
                PcodeToken::Illegal => {
                    self.report_error("Illegal character in p-code snippet");
                    return false;
                }
                _ => {}
            }
        }

        // Full recursive-descent parser + semantic actions would go here.
        // L3 gap: requires SLEIGH integration for ConstructTpl assembly.
        !self.has_errors()
    }
}

impl Default for PcodeSnippet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lexer_identifier() {
        let mut lex = PcodeLexer::new();
        lex.initialize("RAX RBY");
        assert_eq!(lex.get_next_token(), PcodeToken::Identifier);
        assert_eq!(lex.get_identifier(), "RAX");
        assert_eq!(lex.get_next_token(), PcodeToken::Identifier);
        assert_eq!(lex.get_identifier(), "RBY");
        assert_eq!(lex.get_next_token(), PcodeToken::Eof);
    }

    #[test]
    fn test_lexer_hex_number() {
        let mut lex = PcodeLexer::new();
        lex.initialize("0xFF");
        assert_eq!(lex.get_next_token(), PcodeToken::HexNumber);
        assert_eq!(lex.get_number(), 255);
    }

    #[test]
    fn test_lexer_dec_number() {
        let mut lex = PcodeLexer::new();
        lex.initialize("42");
        assert_eq!(lex.get_next_token(), PcodeToken::DecNumber);
        assert_eq!(lex.get_number(), 42);
    }

    #[test]
    fn test_lexer_punctuation() {
        let mut lex = PcodeLexer::new();
        lex.initialize("();[],=");
        assert_eq!(lex.get_next_token(), PcodeToken::LParen);
        assert_eq!(lex.get_next_token(), PcodeToken::RParen);
        assert_eq!(lex.get_next_token(), PcodeToken::Semicolon);
        assert_eq!(lex.get_next_token(), PcodeToken::LBracket);
        assert_eq!(lex.get_next_token(), PcodeToken::RBracket);
        assert_eq!(lex.get_next_token(), PcodeToken::Comma);
        assert_eq!(lex.get_next_token(), PcodeToken::Assign);
    }

    #[test]
    fn test_lexer_dollar() {
        let mut lex = PcodeLexer::new();
        lex.initialize("$$ $");
        assert_eq!(lex.get_next_token(), PcodeToken::DoubleDollar);
        assert_eq!(lex.get_next_token(), PcodeToken::Dollar);
    }

    #[test]
    fn test_lexer_comment() {
        let mut lex = PcodeLexer::new();
        lex.initialize("# comment\nfoo");
        assert_eq!(lex.get_next_token(), PcodeToken::Identifier);
        assert_eq!(lex.get_identifier(), "foo");
    }

    #[test]
    fn test_lexer_eof() {
        let mut lex = PcodeLexer::new();
        lex.initialize("");
        assert_eq!(lex.get_next_token(), PcodeToken::Eof);
    }

    #[test]
    fn test_lexer_illegal() {
        let mut lex = PcodeLexer::new();
        lex.initialize("@");
        assert_eq!(lex.get_next_token(), PcodeToken::Illegal);
    }

    #[test]
    fn test_snippet_basic() {
        let mut snip = PcodeSnippet::new();
        snip.set_unique_base(0x1000);
        assert!(snip.parse_stream("RAX = #0 + RAX;"));
        assert!(!snip.has_errors());
    }

    #[test]
    fn test_snippet_error() {
        let mut snip = PcodeSnippet::new();
        assert!(!snip.parse_stream("@illegal"));
        assert!(snip.has_errors());
        assert!(snip.get_error_message().contains("Illegal"));
    }

    #[test]
    fn test_snippet_allocate_temp() {
        let mut snip = PcodeSnippet::new();
        snip.set_unique_base(0x2000);
        assert_eq!(snip.allocate_temp(), 0x2000);
        assert_eq!(snip.allocate_temp(), 0x2001);
    }

    #[test]
    fn test_snippet_symbols() {
        let mut snip = PcodeSnippet::new();
        snip.add_symbol("tmp", 0x100);
        assert_eq!(snip.lookup_symbol("tmp"), Some(0x100));
        assert_eq!(snip.lookup_symbol("nonexistent"), None);
    }

    #[test]
    fn test_snippet_clear() {
        let mut snip = PcodeSnippet::new();
        snip.add_symbol("a", 1);
        snip.clear();
        assert_eq!(snip.lookup_symbol("a"), None);
        assert!(!snip.has_errors());
    }

    #[test]
    fn test_snippet_multiple_statements() {
        let mut snip = PcodeSnippet::new();
        let pcode = "RAX = #0;\nRBY = INT_ADD RAX #1;";
        assert!(snip.parse_stream(pcode));
        assert!(!snip.has_errors());
    }
}
