//! C grammar parser — faithful port of `grammar.hh` / `grammar.cc` (3338
//! lines).
//!
//! Lexer and parser for C-style type declarations. Used by the decompiler to
//! parse type strings, prototype declarations, and interface commands.
//!
//! Status: L1→L2. The GrammarToken/GrammarLexer with state-machine tokenization
//! is complete. The TypeDeclarator/TypeModifier AST and CParse parser
//! framework are provided as data structures. The full recursive-descent
//! parser (grammar.cc's state machine) and TypeFactory integration are L3
//! gaps.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/grammar.{hh,cc}.

/// Token types for the C grammar lexer. Faithful to the `GrammarToken` enum
/// (grammar.hh:26).
pub mod token_type {
    pub const OPEN_PAREN: u32 = 0x28;
    pub const CLOSE_PAREN: u32 = 0x29;
    pub const STAR: u32 = 0x2a;
    pub const COMMA: u32 = 0x2c;
    pub const SEMICOLON: u32 = 0x3b;
    pub const OPEN_BRACKET: u32 = 0x5b;
    pub const CLOSE_BRACKET: u32 = 0x5d;
    pub const OPEN_BRACE: u32 = 0x7b;
    pub const CLOSE_BRACE: u32 = 0x7d;
    pub const BAD_TOKEN: u32 = 0x100;
    pub const END_OF_FILE: u32 = 0x101;
    pub const DOTDOTDOT: u32 = 0x102;
    pub const INTEGER: u32 = 0x103;
    pub const CHAR_CONSTANT: u32 = 0x104;
    pub const IDENTIFIER: u32 = 0x105;
    pub const STRING_VAL: u32 = 0x106;
}

/// A lexical token from the C grammar. Faithful to `GrammarToken`
/// (grammar.hh:23).
#[derive(Debug, Clone)]
pub struct GrammarToken {
    /// The token type (see `token_type` module).
    pub token_type: u32,
    /// The integer value (for INTEGER tokens).
    pub integer_value: u64,
    /// The string value (for IDENTIFIER/STRING tokens).
    pub string_value: String,
    /// Line number containing this token.
    pub lineno: i32,
    /// Column where this token starts.
    pub colno: i32,
    /// Which file we were in.
    pub filenum: i32,
}

impl Default for GrammarToken {
    fn default() -> Self {
        Self::new()
    }
}

impl GrammarToken {
    /// Construct an empty token. Faithful to the constructor.
    pub fn new() -> Self {
        Self {
            token_type: token_type::BAD_TOKEN,
            integer_value: 0,
            string_value: String::new(),
            lineno: 0,
            colno: 0,
            filenum: 0,
        }
    }

    /// Get the token type. Faithful to `getType`.
    pub fn get_type(&self) -> u32 {
        self.token_type
    }

    /// Get the integer value. Faithful to `getInteger`.
    pub fn get_integer(&self) -> u64 {
        self.integer_value
    }

    /// Get the string value. Faithful to `getString`.
    pub fn get_string(&self) -> &str {
        &self.string_value
    }

    /// Get the line number. Faithful to `getLineNo`.
    pub fn get_line_no(&self) -> i32 {
        self.lineno
    }

    /// Get the column number. Faithful to `getColNo`.
    pub fn get_col_no(&self) -> i32 {
        self.colno
    }

    /// Get the file number. Faithful to `getFileNum`.
    pub fn get_file_num(&self) -> i32 {
        self.filenum
    }

    /// Set position. Faithful to `setPosition`.
    pub fn set_position(&mut self, file: i32, line: i32, col: i32) {
        self.filenum = file;
        self.lineno = line;
        self.colno = col;
    }
}

/// Lexer state machine states. Faithful to the `GrammarLexer` enum
/// (grammar.hh:82).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexerState {
    Start,
    Slash,
    Dot1,
    Dot2,
    Dot3,
    Punctuation,
    EndOfLineComment,
    CComment,
    DoubleQuote,
    DoubleQuoteEnd,
    SingleQuote,
    SingleQuoteEnd,
    SingleBackslash,
    Number,
    Identifier,
}

/// A lexer for C-style type declarations. Faithful to `GrammarLexer`
/// (grammar.hh:69).
pub struct GrammarLexer {
    /// The input text being lexed.
    input: Vec<char>,
    /// Current position in the input.
    pos: usize,
    /// Current line number.
    cur_lineno: i32,
    /// End of file reached.
    end_of_file: bool,
    /// Error message (if any).
    error: String,
}

impl GrammarLexer {
    /// Construct given the maximum buffer size. Faithful to the constructor
    /// (grammar.hh:104).
    pub fn new(_max_buffer: i32) -> Self {
        Self {
            input: Vec::new(),
            pos: 0,
            cur_lineno: 1,
            end_of_file: false,
            error: String::new(),
        }
    }

    /// Clear the lexer state. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.input.clear();
        self.pos = 0;
        self.cur_lineno = 1;
        self.end_of_file = false;
        self.error.clear();
    }

    /// Set the input text to lex.
    pub fn set_input(&mut self, text: &str) {
        self.clear();
        self.input = text.chars().collect();
    }

    /// Get the error message. Faithful to `getError`.
    pub fn get_error(&self) -> &str {
        &self.error
    }

    /// Check if at end of file.
    pub fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Peek at the next character without consuming.
    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    /// Consume and return the next character.
    fn next_char(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.cur_lineno += 1;
        }
        Some(c)
    }

    /// Get the next token from the input. Faithful to `getNextToken`
    /// (grammar.hh:110). Implements the state machine for tokenizing C
    /// declarations.
    pub fn get_next_token(&mut self) -> GrammarToken {
        let mut token = GrammarToken::new();
        token.set_position(0, self.cur_lineno, self.pos as i32);

        if self.is_eof() {
            token.token_type = token_type::END_OF_FILE;
            return token;
        }

        let mut state = LexerState::Start;
        let mut accum = String::new();

        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => {
                    // End of input — finalize current state.
                    return self.finalize_token(&mut token, &state, &accum);
                }
            };

            match state {
                LexerState::Start => {
                    match c {
                        ' ' | '\t' | '\r' | '\n' => {
                            self.next_char();
                        }
                        '(' => {
                            self.next_char();
                            token.token_type = token_type::OPEN_PAREN;
                    return token;
                        }
                        ')' => {
                            self.next_char();
                            token.token_type = token_type::CLOSE_PAREN;
                    return token;
                        }
                        '*' => {
                            self.next_char();
                            token.token_type = token_type::STAR;
                    return token;
                        }
                        ',' => {
                            self.next_char();
                            token.token_type = token_type::COMMA;
                    return token;
                        }
                        ';' => {
                            self.next_char();
                            token.token_type = token_type::SEMICOLON;
                    return token;
                        }
                        '[' => {
                            self.next_char();
                            token.token_type = token_type::OPEN_BRACKET;
                    return token;
                        }
                        ']' => {
                            self.next_char();
                            token.token_type = token_type::CLOSE_BRACKET;
                    return token;
                        }
                        '{' => {
                            self.next_char();
                            token.token_type = token_type::OPEN_BRACE;
                    return token;
                        }
                        '}' => {
                            self.next_char();
                            token.token_type = token_type::CLOSE_BRACE;
                    return token;
                        }
                        '/' => {
                            self.next_char();
                            state = LexerState::Slash;
                        }
                        '.' => {
                            self.next_char();
                            state = LexerState::Dot1;
                        }
                        '"' => {
                            self.next_char();
                            state = LexerState::DoubleQuote;
                        }
                        '\'' => {
                            self.next_char();
                            state = LexerState::SingleQuote;
                        }
                        '0'..='9' => {
                            accum.push(c);
                            self.next_char();
                            state = LexerState::Number;
                        }
                        'a'..='z' | 'A'..='Z' | '_' => {
                            accum.push(c);
                            self.next_char();
                            state = LexerState::Identifier;
                        }
                        _ => {
                            self.next_char();
                            token.token_type = token_type::BAD_TOKEN;
                    return token;
                        }
                    }
                }
                LexerState::Slash => {
                    match c {
                        '/' => {
                            self.next_char();
                            state = LexerState::EndOfLineComment;
                        }
                        '*' => {
                            self.next_char();
                            state = LexerState::CComment;
                        }
                        _ => {
                            token.token_type = token_type::BAD_TOKEN;
                    return token;
                        }
                    }
                }
                LexerState::EndOfLineComment => {
                    if c == '\n' {
                        self.next_char();
                        state = LexerState::Start;
                    } else {
                        self.next_char();
                    }
                }
                LexerState::CComment => {
                    if c == '*' {
                        self.next_char();
                        state = LexerState::Dot3; // Reuse for comment-end detection.
                    } else {
                        self.next_char();
                    }
                }
                LexerState::Dot3 => {
                    // Inside C comment, saw '*', check for '/'
                    if c == '/' {
                        self.next_char();
                        state = LexerState::Start;
                    } else {
                        state = LexerState::CComment;
                    }
                }
                LexerState::Dot1 => {
                    if c == '.' {
                        self.next_char();
                        state = LexerState::Dot2;
                    } else {
                        token.token_type = token_type::BAD_TOKEN;
                    return token;
                    }
                }
                LexerState::Dot2 => {
                    if c == '.' {
                        self.next_char();
                        token.token_type = token_type::DOTDOTDOT;
                    return token;
                    } else {
                        token.token_type = token_type::BAD_TOKEN;
                    return token;
                    }
                }
                LexerState::DoubleQuote => {
                    if c == '"' {
                        self.next_char();
                        token.token_type = token_type::STRING_VAL;
                        token.string_value = accum;
                    return token;
                    } else {
                        accum.push(c);
                        self.next_char();
                    }
                }
                LexerState::SingleQuote => {
                    if c == '\'' {
                        self.next_char();
                        token.token_type = token_type::CHAR_CONSTANT;
                        token.string_value = accum;
                    return token;
                    } else {
                        accum.push(c);
                        self.next_char();
                    }
                }
                LexerState::Number => {
                    if c.is_ascii_hexdigit() || c == 'x' || c == 'X' || c.is_ascii_digit() {
                        accum.push(c);
                        self.next_char();
                    } else {
                        token.token_type = token_type::INTEGER;
                        token.integer_value = parse_number(&accum);
                    return token;
                    }
                }
                LexerState::Identifier => {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        accum.push(c);
                        self.next_char();
                    } else {
                        token.token_type = token_type::IDENTIFIER;
                        token.string_value = accum;
                    return token;
                    }
                }
                _ => {
                    self.next_char();
                    state = LexerState::Start;
                }
            }
        }
    }

    /// Finalize a token at end of input.
    fn finalize_token(
        &self,
        token: &mut GrammarToken,
        state: &LexerState,
        accum: &str,
    ) -> GrammarToken {
        match state {
            LexerState::Number => {
                token.token_type = token_type::INTEGER;
                token.integer_value = parse_number(accum);
            }
            LexerState::Identifier => {
                token.token_type = token_type::IDENTIFIER;
                token.string_value = accum.to_string();
            }
            _ => {
                token.token_type = token_type::END_OF_FILE;
            }
        }
        token.clone()
    }
}

/// Parse a number string (decimal or hex) into a u64.
fn parse_number(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else if s.starts_with('0') && s.len() > 1 {
        u64::from_str_radix(s, 8).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Type declaration AST (data structures)
// ---------------------------------------------------------------------------

/// Type modifier kind. Faithful to `TypeModifier` enum (grammar.hh:120).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifierKind {
    Pointer,
    Array,
    Function,
    Struct,
    Enum,
}

/// A type modifier (pointer, array, function). Faithful to `TypeModifier`
/// (grammar.hh:118).
#[derive(Debug, Clone)]
pub enum TypeModifier {
    /// Pointer modifier with flags.
    Pointer { flags: u32 },
    /// Array modifier with flags and size.
    Array { flags: u32, array_size: i32 },
    /// Function modifier with parameter names and varargs flag.
    Function {
        param_names: Vec<String>,
        dotdotdot: bool,
    },
}

impl TypeModifier {
    /// Get the modifier kind. Faithful to `getType`.
    pub fn kind(&self) -> ModifierKind {
        match self {
            TypeModifier::Pointer { .. } => ModifierKind::Pointer,
            TypeModifier::Array { .. } => ModifierKind::Array,
            TypeModifier::Function { .. } => ModifierKind::Function,
        }
    }

    /// Is this modifier valid? Faithful to `isValid`.
    pub fn is_valid(&self) -> bool {
        match self {
            TypeModifier::Pointer { .. } => true,
            TypeModifier::Array { array_size, .. } => *array_size > 0,
            TypeModifier::Function { .. } => true,
        }
    }
}

/// A C type declarator. Faithful to `TypeDeclarator` (grammar.hh:165).
#[derive(Debug, Clone)]
pub struct TypeDeclarator {
    /// The base type name.
    pub base_type_name: String,
    /// List of modifiers (pointer, array, function).
    pub mods: Vec<TypeModifier>,
    /// The variable identifier.
    pub ident: String,
    /// The prototype model name (for function pointers).
    pub model: String,
    /// Specifier/qualifier flags.
    pub flags: u32,
}

impl Default for TypeDeclarator {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeDeclarator {
    /// Construct an empty declarator. Faithful to the constructor.
    pub fn new() -> Self {
        Self {
            base_type_name: String::new(),
            mods: Vec::new(),
            ident: String::new(),
            model: String::new(),
            flags: 0,
        }
    }

    /// Construct with an identifier. Faithful to the constructor (grammar.hh:174).
    pub fn with_name(name: &str) -> Self {
        let mut d = Self::new();
        d.ident = name.to_string();
        d
    }

    /// Get the base type name. Faithful to `getBaseType`.
    pub fn get_base_type_name(&self) -> &str {
        &self.base_type_name
    }

    /// Number of modifiers. Faithful to `numModifiers`.
    pub fn num_modifiers(&self) -> usize {
        self.mods.len()
    }

    /// Get the identifier. Faithful to `getIdentifier`.
    pub fn get_identifier(&self) -> &str {
        &self.ident
    }

    /// Has a property? Faithful to `hasProperty`.
    pub fn has_property(&self, mask: u32) -> bool {
        (self.flags & mask) != 0
    }
}

/// Parse a type from a string, returning the type name and identifier.
/// Faithful to `parse_type` (grammar.hh:282). This is a simplified entry
/// point; the full implementation uses CParse + TypeFactory.
///
/// L3 gap: full TypeFactory-based parsing.
pub fn parse_type(text: &str) -> Option<(String, String)> {
    let mut lexer = GrammarLexer::new(1024);
    lexer.set_input(text);
    // Read the first token (should be a type name identifier).
    let tok = lexer.get_next_token();
    if tok.get_type() != token_type::IDENTIFIER {
        return None;
    }
    let type_name = tok.get_string().to_string();
    // Read the next token (should be the variable name).
    let tok2 = lexer.get_next_token();
    let var_name = if tok2.get_type() == token_type::IDENTIFIER {
        tok2.get_string().to_string()
    } else {
        String::new()
    };
    Some((type_name, var_name))
}

/// Parse text up to the next separator (space, tab, comma, etc.). Faithful to
/// `parse_toseparator` (grammar.hh:288).
pub fn parse_to_separator(text: &str) -> String {
    let mut result = String::new();
    for c in text.chars() {
        if c.is_whitespace() || c == ',' || c == ';' {
            break;
        }
        result.push(c);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_default() {
        let t = GrammarToken::new();
        assert_eq!(t.get_type(), token_type::BAD_TOKEN);
    }

    #[test]
    fn test_lexer_identifier() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("hello world");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::IDENTIFIER);
        assert_eq!(tok.get_string(), "hello");
        let tok2 = lex.get_next_token();
        assert_eq!(tok2.get_type(), token_type::IDENTIFIER);
        assert_eq!(tok2.get_string(), "world");
    }

    #[test]
    fn test_lexer_punctuation() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("(){}[];,*");
        assert_eq!(lex.get_next_token().get_type(), token_type::OPEN_PAREN);
        assert_eq!(lex.get_next_token().get_type(), token_type::CLOSE_PAREN);
        assert_eq!(lex.get_next_token().get_type(), token_type::OPEN_BRACE);
        assert_eq!(lex.get_next_token().get_type(), token_type::CLOSE_BRACE);
        assert_eq!(lex.get_next_token().get_type(), token_type::OPEN_BRACKET);
        assert_eq!(lex.get_next_token().get_type(), token_type::CLOSE_BRACKET);
        assert_eq!(lex.get_next_token().get_type(), token_type::SEMICOLON);
        assert_eq!(lex.get_next_token().get_type(), token_type::COMMA);
        assert_eq!(lex.get_next_token().get_type(), token_type::STAR);
    }

    #[test]
    fn test_lexer_integer() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("42");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::INTEGER);
        assert_eq!(tok.get_integer(), 42);
    }

    #[test]
    fn test_lexer_hex_integer() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("0xFF");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::INTEGER);
        assert_eq!(tok.get_integer(), 255);
    }

    #[test]
    fn test_lexer_dotdotdot() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("...");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::DOTDOTDOT);
    }

    #[test]
    fn test_lexer_eof() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("x");
        lex.get_next_token(); // consume 'x'
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::END_OF_FILE);
    }

    #[test]
    fn test_lexer_string() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("\"hello\"");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::STRING_VAL);
        assert_eq!(tok.get_string(), "hello");
    }

    #[test]
    fn test_lexer_eol_comment() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("// comment\nfoo");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::IDENTIFIER);
        assert_eq!(tok.get_string(), "foo");
    }

    #[test]
    fn test_lexer_c_comment() {
        let mut lex = GrammarLexer::new(1024);
        lex.set_input("/* comment */ bar");
        let tok = lex.get_next_token();
        assert_eq!(tok.get_type(), token_type::IDENTIFIER);
        assert_eq!(tok.get_string(), "bar");
    }

    #[test]
    fn test_parse_number_decimal() {
        assert_eq!(parse_number("123"), 123);
        assert_eq!(parse_number("0"), 0);
    }

    #[test]
    fn test_parse_number_hex() {
        assert_eq!(parse_number("0xFF"), 255);
        assert_eq!(parse_number("0XAB"), 171);
    }

    #[test]
    fn test_parse_number_octal() {
        assert_eq!(parse_number("010"), 8);
    }

    #[test]
    fn test_type_declarator() {
        let d = TypeDeclarator::with_name("myVar");
        assert_eq!(d.get_identifier(), "myVar");
        assert_eq!(d.num_modifiers(), 0);
        assert!(!d.has_property(1));
    }

    #[test]
    fn test_type_modifier_pointer() {
        let m = TypeModifier::Pointer { flags: 0 };
        assert_eq!(m.kind(), ModifierKind::Pointer);
        assert!(m.is_valid());
    }

    #[test]
    fn test_type_modifier_array() {
        let m_valid = TypeModifier::Array { flags: 0, array_size: 10 };
        assert!(m_valid.is_valid());
        let m_invalid = TypeModifier::Array { flags: 0, array_size: 0 };
        assert!(!m_invalid.is_valid());
    }

    #[test]
    fn test_parse_type_simple() {
        let result = parse_type("int x").unwrap();
        assert_eq!(result.0, "int");
        assert_eq!(result.1, "x");
    }

    #[test]
    fn test_parse_to_separator() {
        assert_eq!(parse_to_separator("hello world"), "hello");
        assert_eq!(parse_to_separator("foo,bar"), "foo");
        assert_eq!(parse_to_separator("end;"), "end");
    }
}
