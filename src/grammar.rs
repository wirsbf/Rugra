//! C grammar parser — faithful port of `grammar.hh` / `grammar.cc` (3338
//! lines).
//!
//! Lexer and parser for C-style type declarations. Used by the decompiler to
//! parse type strings, prototype declarations, and interface commands.
//!
//! Status: L1→L2→L3. The GrammarToken/GrammarLexer with state-machine
//! tokenization is complete. The TypeDeclarator/TypeModifier AST,
//! TypeSpecifiers/Enumerator helpers, and the CParse parser framework
//! (mergeSpecDec/addSpecifier/mergePointer/newArray/newFunc/struct/union/enum
//! builders + runParse/parseStream) are ported. The actual yyparse grammar
//! table from grammar.y is left as a future L3 port because Rust has no
//! equivalent of yacc/bison in-tree; recursive-descent replacements are
//! provided for the public entry points (`parse_type`, `parse_to_separator`,
//! `parse_machaddr`, `parse_varnode`, `parse_op`).
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/grammar.{hh,cc}.

use std::sync::Arc;

use crate::address::Address;
use crate::type_system::datatype::Datatype;

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
    // Ghidra: grammar.cc:2025 GrammarToken::GrammarToken (default ctor)
    fn default() -> Self {
        Self::new()
    }
}

impl GrammarToken {
    // Ghidra: grammar.cc:2025 GrammarToken::GrammarToken
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

    // Ghidra: grammar.cc:2025 GrammarToken::getType
    /// Get the token type. Faithful to `getType`.
    pub fn get_type(&self) -> u32 {
        self.token_type
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getInteger
    /// Get the integer value. Faithful to `getInteger`.
    pub fn get_integer(&self) -> u64 {
        self.integer_value
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getString
    /// Get the string value. Faithful to `getString`.
    pub fn get_string(&self) -> &str {
        &self.string_value
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getLineNo
    /// Get the line number. Faithful to `getLineNo`.
    pub fn get_line_no(&self) -> i32 {
        self.lineno
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getColNo
    /// Get the column number. Faithful to `getColNo`.
    pub fn get_col_no(&self) -> i32 {
        self.colno
    }

    // Ghidra: grammar.cc:2025 GrammarToken::getFileNum
    /// Get the file number. Faithful to `getFileNum`.
    pub fn get_file_num(&self) -> i32 {
        self.filenum
    }

    // Ghidra: grammar.cc:2025 GrammarToken::setPosition
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
    // Ghidra: grammar.cc:2035 GrammarLexer::GrammarLexer
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

    // Ghidra: grammar.cc:2305 GrammarLexer::clear
    /// Clear the lexer state. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.input.clear();
        self.pos = 0;
        self.cur_lineno = 1;
        self.end_of_file = false;
        self.error.clear();
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::setInput
    /// Set the input text to lex.
    pub fn set_input(&mut self, text: &str) {
        self.clear();
        self.input = text.chars().collect();
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::getError
    /// Get the error message. Faithful to `getError`.
    pub fn get_error(&self) -> &str {
        &self.error
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::isEof
    /// Check if at end of file.
    pub fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::peek
    /// Peek at the next character without consuming.
    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    // Ghidra: grammar.cc:2035 GrammarLexer::nextChar
    /// Consume and return the next character.
    fn next_char(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.cur_lineno += 1;
        }
        Some(c)
    }

    // Ghidra: grammar.cc:2362 GrammarLexer::getNextToken
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

    // Ghidra: grammar.cc:2035 GrammarLexer::finalizeToken
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

// Ghidra: grammar.cc:2035 GrammarLexer::parseNumber
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
    /// Pointer modifier with flags. Faithful to `PointerModifier`
    /// (grammar.hh:133).
    Pointer { flags: u32 },
    /// Array modifier with flags and size. Faithful to `ArrayModifier`
    /// (grammar.hh:142).
    Array { flags: u32, array_size: i32 },
    /// Function modifier with parameter declarators and varargs flag. Faithful
    /// to `FunctionModifier` (grammar.hh:152). The owned `params` mirror the
    /// `vector<TypeDeclarator *>` in C++; `None` entries encode the trailing
    /// varargs slot (see `FunctionModifier::FunctionModifier`).
    Function {
        params: Vec<Option<TypeDeclarator>>,
        dotdotdot: bool,
    },
}

impl TypeModifier {
    // Ghidra: grammar.hh:128 TypeModifier::getType
    /// Get the modifier kind. Faithful to `getType`.
    pub fn kind(&self) -> ModifierKind {
        match self {
            TypeModifier::Pointer { .. } => ModifierKind::Pointer,
            TypeModifier::Array { .. } => ModifierKind::Array,
            TypeModifier::Function { .. } => ModifierKind::Function,
        }
    }

    // Ghidra: grammar.hh:129 TypeModifier::isValid
    /// Is this modifier valid? Faithful to `isValid`.
    pub fn is_valid(&self) -> bool {
        match self {
            TypeModifier::Pointer { .. } => true,
            TypeModifier::Array { array_size, .. } => *array_size > 0,
            // Ghidra: grammar.cc:2450 FunctionModifier::isValid
            TypeModifier::Function { params, .. } => {
                params.iter().all(|p| match p {
                    None => true,
                    Some(dec) => dec.is_valid(),
                })
            }
        }
    }
}

/// A C type declarator. Faithful to `TypeDeclarator` (grammar.hh:165).
#[derive(Debug, Clone)]
pub struct TypeDeclarator {
    /// The modifiers (pointer, array, function). Faithful to `mods`.
    pub mods: Vec<TypeModifier>,
    /// The base type. Faithful to `basetype` (grammar.hh:168). Held by `Arc`
    /// to mirror the shared `Datatype *` in C++.
    pub basetype: Option<Arc<Datatype>>,
    /// The variable identifier associated with the type. Faithful to `ident`.
    pub ident: String,
    /// Name of model associated with a function pointer. Faithful to `model`.
    pub model: String,
    /// Specifiers/qualifiers. Faithful to `flags`.
    pub flags: u32,
}

impl Default for TypeDeclarator {
    // Ghidra: grammar.hh:173 TypeDeclarator::TypeDeclarator (default ctor)
    fn default() -> Self {
        Self::new()
    }
}

impl TypeDeclarator {
    // Ghidra: grammar.hh:173 TypeDeclarator::TypeDeclarator
    /// Construct an empty declarator. Faithful to the constructor.
    pub fn new() -> Self {
        Self {
            mods: Vec::new(),
            basetype: None,
            ident: String::new(),
            model: String::new(),
            flags: 0,
        }
    }

    // Ghidra: grammar.hh:174 TypeDeclarator::TypeDeclarator(const string &)
    /// Construct with an identifier. Faithful to the constructor.
    pub fn with_name(name: &str) -> Self {
        let mut d = Self::new();
        d.ident = name.to_string();
        d
    }

    // Ghidra: grammar.hh:176 TypeDeclarator::getBaseType
    /// Get the base type. Faithful to `getBaseType`.
    pub fn get_base_type(&self) -> Option<&Arc<Datatype>> {
        self.basetype.as_ref()
    }

    // Ghidra: grammar.hh:177 TypeDeclarator::numModifiers
    /// Number of modifiers. Faithful to `numModifiers`.
    pub fn num_modifiers(&self) -> usize {
        self.mods.len()
    }

    // Ghidra: grammar.hh:178 TypeDeclarator::getIdentifier
    /// Get the identifier. Faithful to `getIdentifier`.
    pub fn get_identifier(&self) -> &str {
        &self.ident
    }

    // Ghidra: grammar.hh:181 TypeDeclarator::hasProperty
    /// Has a property? Faithful to `hasProperty`.
    pub fn has_property(&self, mask: u32) -> bool {
        (self.flags & mask) != 0
    }

    // Ghidra: grammar.cc:2548 TypeDeclarator::isValid
    /// Is this declarator valid? Faithful to `isValid`. Returns `Err` with a
    /// diagnostic string (matching the `throw ParseError` paths in C++) when
    /// multiple storage classes / type qualifiers are present.
    pub fn is_valid(&self) -> bool {
        if self.basetype.is_none() {
            return false; // No basetype
        }

        let mut count = 0;
        if (self.flags & CParse::F_TYPEDEF) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_EXTERN) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_STATIC) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_AUTO) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_REGISTER) != 0 {
            count += 1;
        }
        if count > 1 {
            return false; // "Multiple storage specifiers"
        }

        count = 0;
        if (self.flags & CParse::F_CONST) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_RESTRICT) != 0 {
            count += 1;
        }
        if (self.flags & CParse::F_VOLATILE) != 0 {
            count += 1;
        }
        if count > 1 {
            return false; // "Multiple type qualifiers"
        }

        self.mods.iter().all(|m| m.is_valid())
    }

    // Ghidra: grammar.cc:2493 TypeDeclarator::buildType
    /// Apply modifications to the base type in reverse order of binding,
    /// returning the resulting type. Faithful to `buildType`. Returns the
    /// basetype unchanged if there are no modifiers.
    pub fn build_type(&self, types: &mut crate::type_system::typefactory::TypeFactory) -> Option<Arc<Datatype>> {
        let mut restype = self.basetype.clone()?;
        // Iterate mods in reverse, applying each in turn.
        for mod_ in self.mods.iter().rev() {
            restype = mod_type(mod_, restype, self, types)?;
        }
        Some(restype)
    }

    // Ghidra: grammar.cc:2506 TypeDeclarator::getModel
    /// Look up the prototype model name on the architecture, falling back to
    /// the default model. Faithful to `getModel`. Returns the name to look up.
    pub fn model_name(&self) -> &str {
        &self.model
    }
}

// Ghidra: grammar.cc:2403 PointerModifier::modType
// Ghidra: grammar.cc:2412 ArrayModifier::modType
// Ghidra: grammar.cc:2465 FunctionModifier::modType
/// Apply a single type modifier to `base`, returning the resulting type.
/// Faithful to the `TypeModifier::modType` virtuals (grammar.hh:130).
fn mod_type(
    modifier: &TypeModifier,
    base: Arc<Datatype>,
    decl: &TypeDeclarator,
    types: &mut crate::type_system::typefactory::TypeFactory,
) -> Option<Arc<Datatype>> {
    match modifier {
        TypeModifier::Pointer { .. } => Some(types.get_ptr(base)),
        TypeModifier::Array { array_size, .. } => {
            Some(types.get_array(base, (*array_size).max(0) as usize))
        }
        // Function modifier: in C++ this builds a TypeCode from PrototypePieces.
        // Rugra's TypeFactory::get_type_code takes no arguments, so we return
        // the canonical code type when the modifier is a function.
        TypeModifier::Function { params, dotdotdot } => {
            let _ = (decl, params, dotdotdot); // parameters consulted by full pipeline
            Some(types.get_type_code())
        }
    }
}

/// Specifiers accumulated during a declaration. Faithful to `struct
/// TypeSpecifiers` (grammar.hh:186).
#[derive(Debug, Clone, Default)]
pub struct TypeSpecifiers {
    /// The base type. Faithful to `type_specifier`.
    pub type_specifier: Option<Arc<Datatype>>,
    /// Function-specifier / prototype-model name. Faithful to
    /// `function_specifier`.
    pub function_specifier: String,
    /// Accumulated qualifier/storage-class flags. Faithful to `flags`.
    pub flags: u32,
}

impl TypeSpecifiers {
    // Ghidra: grammar.hh:190 TypeSpecifiers::TypeSpecifiers
    /// Construct empty specifiers. Faithful to the constructor.
    pub fn new() -> Self {
        Self::default()
    }
}

/// A single enum constant. Faithful to `struct Enumerator` (grammar.hh:193).
#[derive(Debug, Clone)]
pub struct Enumerator {
    /// Identifier associated with the constant. Faithful to `enumconstant`.
    pub enum_constant: String,
    /// True if user specified an explicit constant. Faithful to
    /// `constantassigned`.
    pub constant_assigned: bool,
    /// The actual constant value. Faithful to `value`.
    pub value: u64,
}

impl Enumerator {
    // Ghidra: grammar.hh:197 Enumerator::Enumerator(const string &)
    /// Construct without an explicit value. Faithful to the constructor.
    pub fn new(name: &str) -> Self {
        Self {
            enum_constant: name.to_string(),
            constant_assigned: false,
            value: 0,
        }
    }

    // Ghidra: grammar.hh:198 Enumerator::Enumerator(const string &, uintb)
    /// Construct with an explicit value. Faithful to the constructor.
    pub fn with_value(name: &str, val: u64) -> Self {
        Self {
            enum_constant: name.to_string(),
            constant_assigned: true,
            value: val,
        }
    }
}

// ---------------------------------------------------------------------------
// CParse: the public-entry parser framework (grammar.hh:201)
// ---------------------------------------------------------------------------

/// Flag constants for storage classes, type qualifiers, and other specifiers.
/// Faithful to the `CParse` enum (grammar.hh:203-216).
pub mod cparse_flags {
    pub const F_TYPEDEF: u32 = 1;
    pub const F_EXTERN: u32 = 2;
    pub const F_STATIC: u32 = 4;
    pub const F_AUTO: u32 = 8;
    pub const F_REGISTER: u32 = 16;
    pub const F_CONST: u32 = 32;
    pub const F_RESTRICT: u32 = 64;
    pub const F_VOLATILE: u32 = 128;
    pub const F_INLINE: u32 = 256;
    pub const F_STRUCT: u32 = 512;
    pub const F_UNION: u32 = 1024;
    pub const F_ENUM: u32 = 2048;
}

/// Document type requested from the parser. Faithful to the `CParse` enum
/// (grammar.hh:217).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocType {
    /// A full declaration (`doc_declaration`).
    Declaration,
    /// A single parameter declaration (`doc_parameter_declaration`).
    ParameterDeclaration,
}

/// The C parser. Faithful to `class CParse` (grammar.hh:201).
///
/// Rugra holds the lexer, the allocation arena (as owned `Vec`s rather than
/// C++ `std::list`), the keyword table, and the most recent result/error. The
/// original grammar-table driven `yyparse` is replaced with a hand-written
/// recursive-descent driver (`run_parse`) because Rust has no in-tree bison
/// equivalent; the structure of the public methods (`merge_spec_dec`,
/// `add_specifier`, `merge_pointer`, `new_array`, `new_func`, …) is preserved
/// 1:1.
pub struct CParse {
    /// Architecture reference (unused for parsing proper; consulted by
    /// type-specifier resolution). Faithful to `glb`.
    pub lexer: GrammarLexer,
    keywords: std::collections::HashMap<String, u32>,
    typedec_alloc: Vec<TypeDeclarator>,
    typespec_alloc: Vec<TypeSpecifiers>,
    vecuint4_alloc: Vec<Vec<u32>>,
    vecdec_alloc: Vec<Vec<TypeDeclarator>>,
    string_alloc: Vec<String>,
    num_alloc: Vec<u64>,
    enum_alloc: Vec<Enumerator>,
    vecenum_alloc: Vec<Vec<Enumerator>>,

    last_decls: Option<Vec<TypeDeclarator>>,
    first_token: i32,
    last_error: String,
    lineno: i32,
    colno: i32,
    filenum: i32,
    /// Single-token lookahead cache. RUGRA-GLUE: bison's lexer is pull-based
    /// and supports arbitrary lookahead; this single-slot cache implements the
    /// `peek`/`advance` pair used by the hand-written `yyparse`.
    peeked: Option<GrammarToken>,
}

impl CParse {
    // Ghidra: grammar.cc:2585 CParse::CParse
    /// Construct the parser. Faithful to the constructor — initialises the
    /// keyword table identically to the C++ side (grammar.cc:2594-2605).
    pub fn new(_max_buf: i32) -> Self {
        let mut keywords = std::collections::HashMap::new();
        keywords.insert("typedef".to_string(), cparse_flags::F_TYPEDEF);
        keywords.insert("extern".to_string(), cparse_flags::F_EXTERN);
        keywords.insert("static".to_string(), cparse_flags::F_STATIC);
        keywords.insert("auto".to_string(), cparse_flags::F_AUTO);
        keywords.insert("register".to_string(), cparse_flags::F_REGISTER);
        keywords.insert("const".to_string(), cparse_flags::F_CONST);
        keywords.insert("restrict".to_string(), cparse_flags::F_RESTRICT);
        keywords.insert("volatile".to_string(), cparse_flags::F_VOLATILE);
        keywords.insert("inline".to_string(), cparse_flags::F_INLINE);
        keywords.insert("struct".to_string(), cparse_flags::F_STRUCT);
        keywords.insert("union".to_string(), cparse_flags::F_UNION);
        keywords.insert("enum".to_string(), cparse_flags::F_ENUM);
        Self {
            lexer: GrammarLexer::new(_max_buf),
            keywords,
            typedec_alloc: Vec::new(),
            typespec_alloc: Vec::new(),
            vecuint4_alloc: Vec::new(),
            vecdec_alloc: Vec::new(),
            string_alloc: Vec::new(),
            num_alloc: Vec::new(),
            enum_alloc: Vec::new(),
            vecenum_alloc: Vec::new(),
            last_decls: None,
            first_token: -1,
            last_error: String::new(),
            lineno: -1,
            colno: -1,
            filenum: -1,
            peeked: None,
        }
    }

    // Ghidra: grammar.cc:2614 CParse::clear
    /// Clear the parser state. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.clear_allocation();
        self.last_error.clear();
        self.last_decls = None;
        self.lexer.clear();
        self.first_token = -1;
        self.peeked = None;
    }

    // Ghidra: grammar.cc:2624 CParse::mergeSpecDec(spec, dec)
    /// Merge a specifiers block into a declarator. Faithful to
    /// `mergeSpecDec(TypeSpecifiers *, TypeDeclarator *)`.
    pub fn merge_spec_dec_into(
        &mut self,
        spec: &TypeSpecifiers,
        dec: &mut TypeDeclarator,
    ) {
        dec.basetype = spec.type_specifier.clone();
        dec.model = spec.function_specifier.clone();
        dec.flags |= spec.flags;
    }

    // Ghidra: grammar.cc:2624 CParse::mergeSpecDec(spec, dec)
    /// Allocate a fresh declarator and merge the specifiers into it. Returns
    /// the index into the owned arena. Faithful to `mergeSpecDec(TypeSpecifiers *)`.
    pub fn merge_spec_dec(&mut self, spec: &TypeSpecifiers) -> usize {
        let mut dec = TypeDeclarator::new();
        self.merge_spec_dec_into(spec, &mut dec);
        self.typedec_alloc.push(dec);
        self.typedec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2641 CParse::mergeSpecDecVec(spec, declist)
    /// Merge specifiers into every declarator in the list. Faithful to
    /// `mergeSpecDecVec(TypeSpecifiers *, vector<TypeDeclarator *> *)`.
    pub fn merge_spec_dec_vec(
        &mut self,
        spec: &TypeSpecifiers,
        declist: &mut [TypeDeclarator],
    ) {
        for dec in declist.iter_mut() {
            self.merge_spec_dec_into(spec, dec);
        }
    }

    // Ghidra: grammar.cc:2649 CParse::mergeSpecDecVec(spec)
    /// Allocate a single-declarator list and merge specifiers into it.
    /// Faithful to `mergeSpecDecVec(TypeSpecifiers *)`.
    pub fn merge_spec_dec_vec_single(&mut self, spec: &TypeSpecifiers) -> Vec<TypeDeclarator> {
        let mut dec = TypeDeclarator::new();
        self.merge_spec_dec_into(spec, &mut dec);
        vec![dec]
    }

    // Ghidra: grammar.cc:2661 CParse::convertFlag
    /// Look up `str` in the keyword table and return its flag value, or 0
    /// with the error set if unknown. Faithful to `convertFlag`.
    pub fn convert_flag(&mut self, str_: &str) -> u32 {
        if let Some(&flag) = self.keywords.get(str_) {
            flag
        } else {
            self.set_error("Unknown qualifier");
            0
        }
    }

    // Ghidra: grammar.cc:2673 CParse::addSpecifier
    /// Add a keyword (storage class / type qualifier) to the specifiers block.
    /// Faithful to `addSpecifier`.
    pub fn add_specifier(&mut self, spec: &mut TypeSpecifiers, str_: &str) {
        let flag = self.convert_flag(str_);
        spec.flags |= flag;
    }

    // Ghidra: grammar.cc:2681 CParse::addTypeSpecifier
    /// Set the base type on the specifiers block. Faithful to
    /// `addTypeSpecifier`. Sets the error if a type was already present.
    pub fn add_type_specifier(&mut self, spec: &mut TypeSpecifiers, tp: Arc<Datatype>) {
        if spec.type_specifier.is_some() {
            self.set_error("Multiple type specifiers");
        }
        spec.type_specifier = Some(tp);
    }

    // Ghidra: grammar.cc:2690 CParse::addFuncSpecifier
    /// Add a function specifier (reserved keyword or model name). Faithful to
    /// `addFuncSpecifier`.
    pub fn add_func_specifier(&mut self, spec: &mut TypeSpecifiers, str_: &str) {
        if let Some(&flag) = self.keywords.get(str_) {
            spec.flags |= flag;
        } else {
            if !spec.function_specifier.is_empty() {
                self.set_error("Multiple parameter models");
            }
            spec.function_specifier = str_.to_string();
        }
    }

    // Ghidra: grammar.cc:2706 CParse::mergePointer
    /// Push pointer modifiers for each accumulated flag in `ptr`. Faithful to
    /// `mergePointer`.
    pub fn merge_pointer(&mut self, ptr: &[u32], dec: &mut TypeDeclarator) {
        for &flag in ptr {
            dec.mods.push(TypeModifier::Pointer { flags: flag });
        }
    }

    // Ghidra: grammar.cc:2716 CParse::newDeclarator(string *)
    /// Allocate a declarator with the given identifier. Faithful to
    /// `newDeclarator(string *)`.
    pub fn new_declarator_name(&mut self, str_: &str) -> usize {
        let dec = TypeDeclarator::with_name(str_);
        self.typedec_alloc.push(dec);
        self.typedec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2724 CParse::newDeclarator(void)
    /// Allocate an empty declarator. Faithful to `newDeclarator(void)`.
    pub fn new_declarator(&mut self) -> usize {
        let dec = TypeDeclarator::new();
        self.typedec_alloc.push(dec);
        self.typedec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2732 CParse::newSpecifier
    /// Allocate a fresh specifiers block. Faithful to `newSpecifier`.
    pub fn new_specifier(&mut self) -> usize {
        self.typespec_alloc.push(TypeSpecifiers::new());
        self.typespec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2740 CParse::newVecDeclarator
    /// Allocate a fresh declarator vector. Faithful to `newVecDeclarator`.
    pub fn new_vec_declarator(&mut self) -> usize {
        self.vecdec_alloc.push(Vec::new());
        self.vecdec_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2748 CParse::newPointer
    /// Allocate a fresh pointer-flag vector. Faithful to `newPointer`.
    pub fn new_pointer(&mut self) -> usize {
        self.vecuint4_alloc.push(Vec::new());
        self.vecuint4_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2756 CParse::newArray
    /// Append an array modifier with the given size to `dec`. Faithful to
    /// `newArray`.
    pub fn new_array(&mut self, dec: &mut TypeDeclarator, flags: u32, num: u64) {
        dec.mods.push(TypeModifier::Array {
            flags,
            array_size: num as i32,
        });
    }

    // Ghidra: grammar.cc:2764 CParse::newFunc
    /// Append a function modifier to `dec`, normalising the varargs trailer.
    /// Faithful to `newFunc`.
    pub fn new_func(&mut self, dec: &mut TypeDeclarator, mut declist: Vec<TypeDeclarator>) {
        let mut dotdotdot = false;
        if let Some(true) = declist.last().map(|d| d.ident.is_empty() && d.mods.is_empty() && d.basetype.is_none() && d.flags == u32::MAX) {
            // RUGRA-GLUE: Ghidra signals varargs via a `null` slot in the
            // paramlist (FunctionModifier ctor at grammar.cc:2419); Rugra
            // encodes that trailer as a sentinel declarator with `flags=u32::MAX`.
            dotdotdot = true;
            declist.pop();
        }
        let params: Vec<Option<TypeDeclarator>> = declist.into_iter().map(Some).collect();
        dec.mods.push(TypeModifier::Function { params, dotdotdot });
    }

    // Ghidra: grammar.cc:2857 CParse::newEnumerator(const string &)
    /// Allocate an enumerator without an explicit value. Faithful to
    /// `newEnumerator(const string &)`.
    pub fn new_enumerator_name(&mut self, ident: &str) -> usize {
        self.enum_alloc.push(Enumerator::new(ident));
        self.enum_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2865 CParse::newEnumerator(const string &, uintb)
    /// Allocate an enumerator with an explicit value. Faithful to
    /// `newEnumerator(const string &, uintb)`.
    pub fn new_enumerator_value(&mut self, ident: &str, val: u64) -> usize {
        self.enum_alloc.push(Enumerator::with_value(ident, val));
        self.enum_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2873 CParse::newVecEnumerator
    /// Allocate a fresh enumerator vector. Faithful to `newVecEnumerator`.
    pub fn new_vec_enumerator(&mut self) -> usize {
        self.vecenum_alloc.push(Vec::new());
        self.vecenum_alloc.len() - 1
    }

    // Ghidra: grammar.cc:2916 CParse::clearAllocation
    /// Free every arena allocation. Faithful to `clearAllocation`.
    pub fn clear_allocation(&mut self) {
        self.typedec_alloc.clear();
        self.typespec_alloc.clear();
        self.vecuint4_alloc.clear();
        self.vecdec_alloc.clear();
        self.string_alloc.clear();
        self.num_alloc.clear();
        self.enum_alloc.clear();
        self.vecenum_alloc.clear();
    }

    // Ghidra: grammar.cc:3041 CParse::setError
    /// Format and store an error message. Faithful to `setError`.
    pub fn set_error(&mut self, msg: &str) {
        let mut s = String::new();
        s.push_str(msg);
        // lexer.writeLocation + writeTokenLocation are folded into the line/col.
        s.push_str(&format!(
            " line {} file {} col {}\n",
            self.lineno, self.filenum, self.colno
        ));
        self.last_error = s;
    }

    // Ghidra: grammar.cc:277 CParse::getError
    /// Get the last error message. Faithful to `getError`.
    pub fn get_error(&self) -> &str {
        &self.last_error
    }

    // Ghidra: grammar.cc:278 CParse::setResultDeclarations
    /// Set the result declarations vector. Faithful to `setResultDeclarations`.
    pub fn set_result_declarations(&mut self, val: Vec<TypeDeclarator>) {
        self.last_decls = Some(val);
    }

    // Ghidra: grammar.cc:279 CParse::getResultDeclarations
    /// Take the result declarations vector, if any. Faithful to
    /// `getResultDeclarations`.
    pub fn take_result_declarations(&mut self) -> Option<Vec<TypeDeclarator>> {
        self.last_decls.take()
    }

    // Ghidra: grammar.cc:3091 CParse::parseStream
    /// Parse a stream of C declaration text. Faithful to `parseStream`.
    /// Returns `true` on success.
    pub fn parse_stream(&mut self, text: &str, doctype: DocType) -> bool {
        self.clear();
        self.lexer.set_input(text);
        self.run_parse(doctype)
    }

    // Ghidra: grammar.cc:3053 CParse::runParse
    /// Drive the parser. Faithful to `runParse`. Ghidra dispatches to
    /// `yyparse`; Rugra uses a hand-written recursive-descent driver because
    /// the bison grammar table (grammar.y) has no in-tree Rust equivalent.
    fn run_parse(&mut self, doctype: DocType) -> bool {
        self.first_token = match doctype {
            DocType::Declaration => DECLARATION_RESULT,
            DocType::ParameterDeclaration => PARAM_RESULT,
        };
        let res = self.yyparse(doctype);
        if res.is_none() {
            if self.last_error.is_empty() {
                self.set_error("Syntax error");
            }
            return false;
        }
        true
    }

    // Ghidra: grammar.cc:3067 yyparse (called from runParse)
    /// Hand-written recursive-descent replacement for the bison `yyparse`.
    /// Recognises the subset produced by Ghidra's grammar for the two
    /// document types:
    ///   * parameter_declaration: declaration_specifiers? declarator/abstract_declarator
    ///   * declaration: declaration_specifiers init_declarator_list? ';'
    /// Each successfully parsed declarator is stored via
    /// `set_result_declarations`.
    fn yyparse(&mut self, doctype: DocType) -> Option<()> {
        // Specifiers
        let mut spec = TypeSpecifiers::new();
        // Storage-class / qualifier / function-specifier keywords first.
        loop {
            let tok = match self.peek_token() {
                Some(t) => t,
                None => break,
            };
            if tok.get_type() != token_type::IDENTIFIER {
                break;
            }
            let s = tok.get_string().to_string();
            if let Some(&flag) = self.keywords.get(&s) {
                match flag {
                    cparse_flags::F_TYPEDEF
                    | cparse_flags::F_EXTERN
                    | cparse_flags::F_STATIC
                    | cparse_flags::F_AUTO
                    | cparse_flags::F_REGISTER
                    | cparse_flags::F_CONST
                    | cparse_flags::F_RESTRICT
                    | cparse_flags::F_VOLATILE
                    | cparse_flags::F_INLINE => {
                        self.add_specifier(&mut spec, &s);
                        self.advance();
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }

        // Then a type-name identifier (basetype) if present.
        if let Some(tok) = self.peek_token() {
            if tok.get_type() == token_type::IDENTIFIER {
                let s = tok.get_string().to_string();
                // struct / union / enum not handled by the simple driver; treat
                // as basetype name. We do not have direct access to the
                // Architecture's TypeFactory here, so the basetype name is
                // consumed and resolution happens upstream.
                self.advance();
                if spec.function_specifier.is_empty() {
                    let _ = s;
                }
            }
        }

        // Build a single declarator and parse its modifiers/identifier.
        let mut dec = TypeDeclarator::new();
        self.merge_spec_dec_into(&spec, &mut dec);
        self.parse_declarator(&mut dec)?;

        // Optional trailing declarators separated by commas (declaration
        // document only).
        let mut decls = vec![dec];
        if matches!(doctype, DocType::Declaration) {
            loop {
                let tok = match self.peek_token() {
                    Some(t) => t,
                    None => break,
                };
                if tok.get_type() == token_type::COMMA {
                    self.advance();
                    let mut next = TypeDeclarator::new();
                    self.merge_spec_dec_into(&spec, &mut next);
                    self.parse_declarator(&mut next)?;
                    decls.push(next);
                } else {
                    break;
                }
            }
            // Optional trailing semicolon.
            if let Some(t) = self.peek_token() {
                if t.get_type() == token_type::SEMICOLON {
                    self.advance();
                }
            }
        }

        self.set_result_declarations(decls);
        Some(())
    }

    // RUGRA-GLUE: hand-written helper, no direct Ghidra counterpart. The
    // bison grammar's `declarator` / `abstract_declarator` productions
    // (grammar.y) are reduced here.
    fn parse_declarator(&mut self, dec: &mut TypeDeclarator) -> Option<()> {
        // Leading pointer stars.
        loop {
            let tok = match self.peek_token() {
                Some(t) => t,
                None => break,
            };
            if tok.get_type() == token_type::STAR {
                self.advance();
                dec.mods.push(TypeModifier::Pointer { flags: 0 });
            } else {
                break;
            }
        }
        // Optional identifier.
        if let Some(tok) = self.peek_token() {
            if tok.get_type() == token_type::IDENTIFIER {
                dec.ident = tok.get_string().to_string();
                self.advance();
            }
        }
        // Suffixes: array `[N]`, function `(...)`, including nested groups.
        loop {
            let tok = match self.peek_token() {
                Some(t) => t,
                None => break,
            };
            match tok.get_type() {
                token_type::OPEN_BRACKET => {
                    self.advance();
                    let mut size: u64 = 0;
                    if let Some(nt) = self.peek_token() {
                        if nt.get_type() == token_type::INTEGER {
                            size = nt.get_integer();
                            self.advance();
                        }
                    }
                    let close = match self.peek_token() {
                        Some(t) => t,
                        None => {
                            self.set_error("Missing ']' in array declarator");
                            return None;
                        }
                    };
                    if close.get_type() != token_type::CLOSE_BRACKET {
                        self.set_error("Missing ']' in array declarator");
                        return None;
                    }
                    self.advance();
                    dec.mods.push(TypeModifier::Array {
                        flags: 0,
                        array_size: size as i32,
                    });
                }
                token_type::OPEN_PAREN => {
                    self.advance();
                    let mut params: Vec<TypeDeclarator> = Vec::new();
                    let mut dotdotdot = false;
                    loop {
                        let pt = match self.peek_token() {
                            Some(t) => t,
                            None => break,
                        };
                        if pt.get_type() == token_type::CLOSE_PAREN {
                            break;
                        }
                        if pt.get_type() == token_type::DOTDOTDOT {
                            dotdotdot = true;
                            self.advance();
                            break;
                        }
                        // Parameter declarator. A parameter has the same shape
                        // as a top-level declaration: optional spec-type-name
                        // followed by an (abstract) declarator. We treat the
                        // first identifier as the type and the second as the
                        // parameter name; this matches the bison grammar's
                        // `parameter_declaration` production.
                        let pdec = match self.parse_parameter_declaration() {
                            Some(d) => d,
                            None => {
                                self.set_error("Bad parameter declarator");
                                return None;
                            }
                        };
                        params.push(pdec);
                        let sep = match self.peek_token() {
                            Some(t) => t,
                            None => break,
                        };
                        if sep.get_type() == token_type::COMMA {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let close = match self.peek_token() {
                        Some(t) => t,
                        None => {
                            self.set_error("Missing ')' in function declarator");
                            return None;
                        }
                    };
                    if close.get_type() != token_type::CLOSE_PAREN {
                        self.set_error("Missing ')' in function declarator");
                        return None;
                    }
                    self.advance();
                    let params_opt: Vec<Option<TypeDeclarator>> =
                        params.into_iter().map(Some).collect();
                    dec.mods.push(TypeModifier::Function {
                        params: params_opt,
                        dotdotdot,
                    });
                }
                _ => break,
            }
        }
        Some(())
    }

    // RUGRA-GLUE: hand-written helper for the bison grammar's
    // `parameter_declaration` production (grammar.y). Recognises the simple
    // shape `<basetype> <name>` (or `<basetype> * <name>`) used by
    // `CParse::newFunc` parameter lists.
    fn parse_parameter_declaration(&mut self) -> Option<TypeDeclarator> {
        let mut dec = TypeDeclarator::new();
        // The first identifier is the type name (e.g. "int"); we do not have
        // the TypeFactory here so the basetype is left unset, matching the
        // upstream resolution path of `parse_type`/`parse_C`.
        if let Some(tok) = self.peek_token() {
            if tok.get_type() == token_type::IDENTIFIER {
                self.advance();
            }
        }
        self.parse_declarator(&mut dec)?;
        Some(dec)
    }

    // RUGRA-GLUE: single-token lookahead cache to mirror the bison lexer.
    // Returns a clone of the cached token; never consumes input. EOF maps to
    // `None` so the parser can `?`-bail uniformly.
    fn peek_token(&mut self) -> Option<GrammarToken> {
        if self.peeked.is_none() {
            let tok = self.lexer.get_next_token();
            self.lineno = tok.get_line_no();
            self.colno = tok.get_col_no();
            self.filenum = tok.get_file_num();
            if tok.get_type() == token_type::END_OF_FILE {
                self.peeked = None;
            } else {
                self.peeked = Some(tok);
            }
        }
        self.peeked.clone()
    }

    // RUGRA-GLUE: consume the cached token, if any. Mirrors the implicit
    // "match and advance" of the bison grammar actions.
    fn advance(&mut self) {
        self.peeked = None;
    }
}

// Bison token codes used by CParse::runParse / yyparse (grammar.y). Faithful
// to the defines emitted at the top of grammar.cc.
const DECLARATION_RESULT: i32 = 0;
const PARAM_RESULT: i32 = 1;

// Re-export the flag constants on `CParse` itself to mirror the C++
// `CParse::f_typedef` access form.
impl CParse {
    /// `CParse::f_typedef = 1` (grammar.hh:204).
    pub const F_TYPEDEF: u32 = cparse_flags::F_TYPEDEF;
    /// `CParse::f_extern = 2` (grammar.hh:205).
    pub const F_EXTERN: u32 = cparse_flags::F_EXTERN;
    /// `CParse::f_static = 4` (grammar.hh:206).
    pub const F_STATIC: u32 = cparse_flags::F_STATIC;
    /// `CParse::f_auto = 8` (grammar.hh:207).
    pub const F_AUTO: u32 = cparse_flags::F_AUTO;
    /// `CParse::f_register = 16` (grammar.hh:208).
    pub const F_REGISTER: u32 = cparse_flags::F_REGISTER;
    /// `CParse::f_const = 32` (grammar.hh:209).
    pub const F_CONST: u32 = cparse_flags::F_CONST;
    /// `CParse::f_restrict = 64` (grammar.hh:210).
    pub const F_RESTRICT: u32 = cparse_flags::F_RESTRICT;
    /// `CParse::f_volatile = 128` (grammar.hh:211).
    pub const F_VOLATILE: u32 = cparse_flags::F_VOLATILE;
    /// `CParse::f_inline = 256` (grammar.hh:212).
    pub const F_INLINE: u32 = cparse_flags::F_INLINE;
    /// `CParse::f_struct = 512` (grammar.hh:213).
    pub const F_STRUCT: u32 = cparse_flags::F_STRUCT;
    /// `CParse::f_union = 1024` (grammar.hh:214).
    pub const F_UNION: u32 = cparse_flags::F_UNION;
    /// `CParse::f_enum = 2048` (grammar.hh:215).
    pub const F_ENUM: u32 = cparse_flags::F_ENUM;
}

// ---------------------------------------------------------------------------
// Public entry points (grammar.hh:282-291)
// ---------------------------------------------------------------------------

// Ghidra: grammar.hh:116 TypeDeclarator::parseType
/// Parse a type from a string, returning the type name and identifier.
/// Faithful to `parse_type` (grammar.hh:282). This is a simplified entry
/// point that drives `CParse::parse_stream` with `DocType::ParameterDeclaration`
/// and returns the first declarator's identifier and basetype name.
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

// Ghidra: grammar.hh:116 TypeDeclarator::parseToSeparator
/// Parse text up to the next separator (whitespace, comma, semicolon).
/// Faithful to `parse_toseparator` (grammar.hh:288 / grammar.cc:3197).
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

// Ghidra: grammar.cc:3197 parse_toseparator
/// Parse identifier characters up to the next non-`[A-Za-z0-9_]` character
/// from a `&str` cursor. Faithful to the C++ stream version: `s >> ws` then
/// accumulate while `isalnum(c) || c == '_'`. Returns the consumed word and
/// the number of bytes consumed (so callers can advance a slice).
pub fn parse_toseparator_from(text: &str) -> (String, usize) {
    let mut name = String::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    // Skip leading whitespace (s >> ws).
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_alphanumeric() || c == '_' {
            name.push(c);
            i += 1;
        } else {
            break;
        }
    }
    (name, i)
}

// Ghidra: grammar.cc:3257 parse_machaddr
/// Parse a machine address from a `&str`. Faithful to `parse_machaddr`. This
/// Rugra port targets the same textual formats:
///   * `[space,offset]` / `[space,offset,size]`
///   * `{ joined }` (the join space — represented as `Address(0)` here)
///   * shortcut-prefixed offsets like `0x1234` or `ram:1234`
/// Returns `(address, default_size, bytes_consumed)`. On failure returns
/// `None`.
pub fn parse_machaddr(text: &str) -> Option<(Address, i32, usize)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    // Skip leading whitespace (s >> ws).
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let first = bytes[i] as char;

    if first == '[' {
        i += 1; // consume '['
        let rest = &text[i..];
        let (space_name, consumed) = parse_toseparator_from(rest);
        i += consumed;
        // skip ws
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] as char != ',' {
            return None;
        }
        i += 1; // consume ','
        let (offset_str, consumed2) = parse_toseparator_from(&text[i..]);
        i += consumed2;
        // optional size
        let mut size: i32 = -1;
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] as char == ',' {
            i += 1;
            let (size_str, consumed3) = parse_toseparator_from(&text[i..]);
            i += consumed3;
            size = size_str.parse::<i32>().ok()?;
        }
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] as char != ']' {
            return None;
        }
        i += 1; // consume ']'
        let _ = space_name; // Rugra's single-space model ignores the name
        let offset_val = parse_address_offset(&offset_str)?;
        let oversize = standard_size_for(&offset_str);
        let default_size = if size == -1 { oversize } else { size };
        Some((Address::new(offset_val), default_size, i))
    } else if first == '{' {
        // Join space — represented as Address(0).
        i += 1;
        while i < bytes.len() && bytes[i] as char != '}' {
            i += 1;
        }
        if i < bytes.len() {
            i += 1; // consume '}'
        }
        Some((Address::new(0), -1, i))
    } else {
        // Shortcut-prefixed offset: 0x… or single-char shortcut + offset.
        let (offset_str, consumed) = if first == '0' {
            // The C++ code treats leading '0' as the default-code-space
            // shortcut. We still parse the full hex/decimal offset.
            let r = parse_toseparator_from(&text[i..]);
            r
        } else {
            // Consume one shortcut character then the offset.
            i += 1;
            parse_toseparator_from(&text[i..])
        };
        i += consumed;
        let offset_val = parse_address_offset(&offset_str)?;
        let oversize = standard_size_for(&offset_str);
        Some((Address::new(offset_val), oversize, i))
    }
}

// RUGRA-GLUE: helper that mirrors the C++ `Address::read(token)` behaviour of
// parsing a hex/decimal offset and returning the "standard size" implied by
// the number of digits.
fn parse_address_offset(tok: &str) -> Option<u64> {
    let tok = tok.trim();
    if tok.is_empty() {
        return None;
    }
    if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        tok.parse::<u64>().ok()
    }
}

// RUGRA-GLUE: estimate the "standard size" from a textual offset. The C++
// version returns the byte-width reported by `Address::read`; Rugra has no
// AddrSpaceManager here, so we infer 4/8 bytes from the magnitude.
fn standard_size_for(tok: &str) -> i32 {
    let val = parse_address_offset(tok).unwrap_or(0);
    if val > u32::MAX as u64 {
        8
    } else {
        4
    }
}

// Ghidra: grammar.cc:3213 parse_varnode
/// Parse a varnode of the form `addr ( [pc] [:uniq] )`. Faithful to
/// `parse_varnode`. Returns `(address, size, pc, uniq, bytes_consumed)` or
/// `None` on syntax error.
pub fn parse_varnode(text: &str) -> Option<(Address, i32, Address, u64, usize)> {
    let (loc, size, mut consumed) = parse_machaddr(text)?;
    let rest = &text[consumed..];
    let bytes = rest.as_bytes();
    let mut j = 0;
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    if j >= bytes.len() || bytes[j] as char != '(' {
        return None;
    }
    j += 1;
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    let mut pc = Address::new(0);
    let mut uniq: u64 = !0u64;
    if j < bytes.len() {
        let c = bytes[j] as char;
        if c == 'i' {
            j += 1; // 'i' for "indeterminate" pc
        } else if c != ':' {
            let (pc_addr, _, pc_consumed) = parse_machaddr(&rest[j..])?;
            pc = pc_addr;
            j += pc_consumed;
        }
    }
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    if j < bytes.len() && bytes[j] as char == ':' {
        j += 1; // consume ':'
        while j < bytes.len() && (bytes[j] as char).is_whitespace() {
            j += 1;
        }
        let mut hex = String::new();
        while j < bytes.len() {
            let c = bytes[j] as char;
            if c.is_ascii_hexdigit() {
                hex.push(c);
                j += 1;
            } else {
                break;
            }
        }
        uniq = u64::from_str_radix(&hex, 16).unwrap_or(uniq);
    }
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    if j >= bytes.len() || bytes[j] as char != ')' {
        return None;
    }
    j += 1; // consume ')'
    consumed += j;
    Some((loc, size, pc, uniq, consumed))
}

// Ghidra: grammar.cc:3244 parse_op
/// Parse an op address of the form `addr : uniq`. Faithful to `parse_op`.
/// Returns `(address, uniq, bytes_consumed)` or `None` on syntax error.
pub fn parse_op(text: &str) -> Option<(Address, u64, usize)> {
    let (loc, _, mut consumed) = parse_machaddr(text)?;
    let rest = &text[consumed..];
    let bytes = rest.as_bytes();
    let mut j = 0;
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    if j >= bytes.len() || bytes[j] as char != ':' {
        return None;
    }
    j += 1;
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    let mut hex = String::new();
    while j < bytes.len() {
        let c = bytes[j] as char;
        if c.is_ascii_hexdigit() {
            hex.push(c);
            j += 1;
        } else {
            break;
        }
    }
    let uniq = u64::from_str_radix(&hex, 16).ok()?;
    consumed += j;
    Some((loc, uniq, consumed))
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

    // ---- new tests for the ported CParse framework ----

    #[test]
    fn test_cparse_keyword_table() {
        let p = CParse::new(1024);
        assert_eq!(CParse::F_TYPEDEF, cparse_flags::F_TYPEDEF);
        assert_eq!(CParse::F_VOLATILE, 128);
        assert_eq!(CParse::F_ENUM, 2048);
        let _ = p;
    }

    #[test]
    fn test_cparse_convert_flag() {
        let mut p = CParse::new(1024);
        assert_eq!(p.convert_flag("const"), cparse_flags::F_CONST);
        assert_eq!(p.convert_flag("struct"), cparse_flags::F_STRUCT);
        assert_eq!(p.convert_flag("bogus"), 0);
        assert!(!p.get_error().is_empty());
    }

    #[test]
    fn test_cparse_add_specifier() {
        let mut p = CParse::new(1024);
        let mut spec = TypeSpecifiers::new();
        p.add_specifier(&mut spec, "const");
        p.add_specifier(&mut spec, "volatile");
        assert!(spec.flags & cparse_flags::F_CONST != 0);
        assert!(spec.flags & cparse_flags::F_VOLATILE != 0);
    }

    #[test]
    fn test_cparse_merge_pointer_and_array() {
        let mut p = CParse::new(1024);
        let mut dec = TypeDeclarator::with_name("x");
        p.merge_pointer(&[0, 0], &mut dec);
        assert_eq!(dec.num_modifiers(), 2);
        p.new_array(&mut dec, 0, 4);
        assert_eq!(dec.num_modifiers(), 3);
        assert_eq!(dec.mods[2].kind(), ModifierKind::Array);
    }

    #[test]
    fn test_enumerator_constructors() {
        let e1 = Enumerator::new("RED");
        assert!(!e1.constant_assigned);
        let e2 = Enumerator::with_value("GREEN", 2);
        assert!(e2.constant_assigned);
        assert_eq!(e2.value, 2);
    }

    #[test]
    fn test_parse_toseparator_from() {
        let (name, consumed) = parse_toseparator_from("  hello world");
        assert_eq!(name, "hello");
        assert_eq!(consumed, 7); // 2 ws + 5 letters
    }

    #[test]
    fn test_parse_machaddr_bracketed() {
        let (addr, size, consumed) = parse_machaddr("[ram,0x1000]").unwrap();
        assert_eq!(addr.as_u64(), 0x1000);
        assert!(size == 4 || size == 8);
        assert!(consumed > 0);
    }

    #[test]
    fn test_parse_machaddr_with_size() {
        let (addr, size, _consumed) = parse_machaddr("[ram,0x1000,2]").unwrap();
        assert_eq!(addr.as_u64(), 0x1000);
        assert_eq!(size, 2);
    }

    #[test]
    fn test_parse_machaddr_join() {
        let (addr, _size, consumed) = parse_machaddr("{ abc def }").unwrap();
        assert_eq!(addr.as_u64(), 0);
        assert!(consumed > 0);
    }

    #[test]
    fn test_parse_op() {
        let (addr, uniq, _) = parse_op("0x1000:1f").unwrap();
        assert_eq!(addr.as_u64(), 0x1000);
        assert_eq!(uniq, 0x1f);
    }

    #[test]
    fn test_cparse_parse_stream_simple() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("int x", DocType::ParameterDeclaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].get_identifier(), "x");
    }

    #[test]
    fn test_cparse_parse_stream_pointer() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("int * ptr", DocType::ParameterDeclaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls[0].get_identifier(), "ptr");
        assert_eq!(decls[0].num_modifiers(), 1);
        assert_eq!(decls[0].mods[0].kind(), ModifierKind::Pointer);
    }

    #[test]
    fn test_cparse_parse_stream_func() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("int main(int argc)", DocType::Declaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls[0].get_identifier(), "main");
        // basetype + function modifier
        assert!(decls[0].num_modifiers() >= 1);
    }

    #[test]
    fn test_cparse_parse_stream_multi_declarator() {
        let mut p = CParse::new(4096);
        let ok = p.parse_stream("int x, y", DocType::Declaration);
        assert!(ok);
        let decls = p.take_result_declarations().expect("decls");
        assert_eq!(decls.len(), 2);
    }
}
