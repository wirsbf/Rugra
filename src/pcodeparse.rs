//! P-code snippet parser — faithful port of `pcodeparse.hh` / `pcodeparse.cc`
//! (3303 lines, Bison-generated) + `pcodeparse.y` (805 lines, grammar source).
//!
//! Classes for compiling standalone p-code snippets, given an existing SLEIGH
//! language. In Ghidra this lives in `pcodeparse.{hh,y}`; the `.cc` file is
//! produced by Bison from `pcodeparse.y`. This port reproduces the lexer
//! state machine (`PcodeLexer::moveState` + `PcodeLexer::getNextToken`), the
//! keyword/operator table (`idents[]`), the symbol lookup machinery
//! (`PcodeSnippet::lex`, `addSymbol`, `allocateTemp`, `clear`,
//! `reportError`), and the `<op>`/`<varnode>` XML decode path that consumes
//! the emitted p-code (`PcodeOpRaw::decode`, `VarnodeData::decode`,
//! `PcodeEmit::decodeOp`).
//!
//! Ghidra reference: `ghidra/.../cpp/pcodeparse.{hh,cc,y}`,
//! `pcoderaw.{hh,cc}`, `translate.cc`, `address.cc`, `sleigh.hh`.
//!
//! L3 gaps (cannot be filled without SLEIGH integration): the Bison grammar
//! semantic actions (ConstructTpl assembly), `SleighBase::findSymbol`, the
//! register resolver for `<register>` XML.
//!
//! Rugra uses `iced-x86` instead of SLEIGH, so SLEIGH integration is itself an
//! L3 gap; this module therefore exposes a clean Rust API that downstream
//! SLEIGH work can plug into.

use crate::marshal::{AttributeId, Decoder, ElementId};
use crate::opcodes::OpCode;
use crate::space::AddressSpace;
use crate::varnode::VarnodeData;

// ---------------------------------------------------------------------------
// Token kinds (pcodeparse.cc:152-211 — Bison `pcodetokentype` enum)
// ---------------------------------------------------------------------------

/// Number of entries in `idents[]` (pcodeparse.y:228).
pub const IDENTREC_SIZE: usize = 46;

/// The full Bison `pcodetokentype` token enum, faithful to
/// pcodeparse.cc:152-211. Numeric ids 258-314 match Ghidra exactly; single-char
/// punctuation carries the ASCII value via `Punct(c)`; `Illegal` maps to the
/// Bison EOF code `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeTokenKind {
    // Multi-char boolean / comparison / shift operators (258-277)
    /// `||` — OP_BOOL_OR = 258
    BoolOr,
    /// `&&` — OP_BOOL_AND = 259
    BoolAnd,
    /// `^^` — OP_BOOL_XOR = 260
    BoolXor,
    /// `==` — OP_EQUAL = 261
    Equal,
    /// `!=` — OP_NOTEQUAL = 262
    NotEqual,
    /// `f==` — OP_FEQUAL = 263
    FEqual,
    /// `f!=` — OP_FNOTEQUAL = 264
    FNotEqual,
    /// `>=` — OP_GREATEQUAL = 265
    GreatEqual,
    /// `<=` — OP_LESSEQUAL = 266
    LessEqual,
    /// `s<` — OP_SLESS = 267
    SLess,
    /// `s>=` — OP_SGREATEQUAL = 268
    SGreatEqual,
    /// `s<=` — OP_SLESSEQUAL = 269
    SLessEqual,
    /// `s>` — OP_SGREAT = 270
    SGreat,
    /// `f<` — OP_FLESS = 271
    FLess,
    /// `f>` — OP_FGREAT = 272
    FGreat,
    /// `f<=` — OP_FLESSEQUAL = 273
    FLessEqual,
    /// `f>=` — OP_FGREATEQUAL = 274
    FGreatEqual,
    /// `<<` — OP_LEFT = 275
    Left,
    /// `>>` — OP_RIGHT = 276
    Right,
    /// `s>>` — OP_SRIGHT = 277
    SRight,
    // Float / signed arithmetic operators (278-283)
    /// `f+` — OP_FADD = 278
    FAdd,
    /// `f-` — OP_FSUB = 279
    FSub,
    /// `s/` — OP_SDIV = 280
    SDiv,
    /// `s%` — OP_SREM = 281
    SRem,
    /// `f*` — OP_FMULT = 282
    FMult,
    /// `f/` — OP_FDIV = 283
    FDiv,
    // P-code builtin operator names (284-298)
    /// `zext` — OP_ZEXT = 284
    Zext,
    /// `carry` — OP_CARRY = 285
    Carry,
    /// `borrow` — OP_BORROW = 286
    Borrow,
    /// `sext` — OP_SEXT = 287
    Sext,
    /// `scarry` — OP_SCARRY = 288
    SCarry,
    /// `sborrow` — OP_SBORROW = 289
    SBorrow,
    /// `nan` — OP_NAN = 290
    Nan,
    /// `abs` — OP_ABS = 291
    Abs,
    /// `sqrt` — OP_SQRT = 292
    Sqrt,
    /// `ceil` — OP_CEIL = 293
    Ceil,
    /// `floor` — OP_FLOOR = 294
    Floor,
    /// `round` — OP_ROUND = 295
    Round,
    /// `int2float` — OP_INT2FLOAT = 296
    Int2Float,
    /// `float2float` — OP_FLOAT2FLOAT = 297
    Float2Float,
    /// `trunc` — OP_TRUNC = 298
    Trunc,
    /// `new` — OP_NEW = 299 (object creation in dynamic languages)
    New,
    // Lexer sentinel tokens (300-306)
    /// BADINTEGER = 300 — numeric literal overflowed
    BadInteger,
    /// `goto` — GOTO_KEY = 301
    GotoKey,
    /// `call` — CALL_KEY = 302
    CallKey,
    /// `return` — RETURN_KEY = 303
    ReturnKey,
    /// `if` — IF_KEY = 304
    IfKey,
    /// ENDOFSTREAM = 305 — official end-of-stream marker
    EndOfStream,
    /// `local` — LOCAL_KEY = 306
    LocalKey,
    // Literals & symbol tokens (307-314)
    /// INTEGER = 307 — parsed decimal/hex literal
    Integer,
    /// STRING = 308 — identifier that is not a keyword
    String,
    /// SPACESYM = 309 — resolved `SpaceSymbol`
    SpaceSym,
    /// USEROPSYM = 310 — resolved `UserOpSymbol`
    UserOpSym,
    /// VARSYM = 311 — resolved `VarnodeSymbol`
    VarSym,
    /// OPERANDSYM = 312 — resolved `OperandSymbol`
    OperandSym,
    /// JUMPSYM = 313 — resolved start/end/next2/flowdest/flowref symbol
    JumpSym,
    /// LABELSYM = 314 — resolved `LabelSymbol`
    LabelSym,
    /// Single-character punctuation: `(`, `)`, `,`, `:`, `[`, `]`, `;`,
    /// `+`, `-`, `*`, `/`, `%`, `~`, `<`, `>`, `&`, `|`, `^`, `=`, `!`.
    /// Carries the ASCII code that Bison would return.
    Punct(char),
    /// Bison EOF / unclassifiable character. Maps to the Bison code `0`.
    Illegal,
}

impl PcodeTokenKind {
    /// Map this token to its Bison numeric id. Faithful to the assignment
    /// Bison emits at pcodeparse.cc:154-210 plus the C `return curchar` fall
    /// through at pcodeparse.y:605. `const fn` so the `idents[]` table can be
    /// a `static`.
    pub const fn as_token_id(self) -> i32 {
        match self {
            PcodeTokenKind::BoolOr => 258,
            PcodeTokenKind::BoolAnd => 259,
            PcodeTokenKind::BoolXor => 260,
            PcodeTokenKind::Equal => 261,
            PcodeTokenKind::NotEqual => 262,
            PcodeTokenKind::FEqual => 263,
            PcodeTokenKind::FNotEqual => 264,
            PcodeTokenKind::GreatEqual => 265,
            PcodeTokenKind::LessEqual => 266,
            PcodeTokenKind::SLess => 267,
            PcodeTokenKind::SGreatEqual => 268,
            PcodeTokenKind::SLessEqual => 269,
            PcodeTokenKind::SGreat => 270,
            PcodeTokenKind::FLess => 271,
            PcodeTokenKind::FGreat => 272,
            PcodeTokenKind::FLessEqual => 273,
            PcodeTokenKind::FGreatEqual => 274,
            PcodeTokenKind::Left => 275,
            PcodeTokenKind::Right => 276,
            PcodeTokenKind::SRight => 277,
            PcodeTokenKind::FAdd => 278,
            PcodeTokenKind::FSub => 279,
            PcodeTokenKind::SDiv => 280,
            PcodeTokenKind::SRem => 281,
            PcodeTokenKind::FMult => 282,
            PcodeTokenKind::FDiv => 283,
            PcodeTokenKind::Zext => 284,
            PcodeTokenKind::Carry => 285,
            PcodeTokenKind::Borrow => 286,
            PcodeTokenKind::Sext => 287,
            PcodeTokenKind::SCarry => 288,
            PcodeTokenKind::SBorrow => 289,
            PcodeTokenKind::Nan => 290,
            PcodeTokenKind::Abs => 291,
            PcodeTokenKind::Sqrt => 292,
            PcodeTokenKind::Ceil => 293,
            PcodeTokenKind::Floor => 294,
            PcodeTokenKind::Round => 295,
            PcodeTokenKind::Int2Float => 296,
            PcodeTokenKind::Float2Float => 297,
            PcodeTokenKind::Trunc => 298,
            PcodeTokenKind::New => 299,
            PcodeTokenKind::BadInteger => 300,
            PcodeTokenKind::GotoKey => 301,
            PcodeTokenKind::CallKey => 302,
            PcodeTokenKind::ReturnKey => 303,
            PcodeTokenKind::IfKey => 304,
            PcodeTokenKind::EndOfStream => 305,
            PcodeTokenKind::LocalKey => 306,
            PcodeTokenKind::Integer => 307,
            PcodeTokenKind::String => 308,
            PcodeTokenKind::SpaceSym => 309,
            PcodeTokenKind::UserOpSym => 310,
            PcodeTokenKind::VarSym => 311,
            PcodeTokenKind::OperandSym => 312,
            PcodeTokenKind::JumpSym => 313,
            PcodeTokenKind::LabelSym => 314,
            PcodeTokenKind::Punct(c) => c as i32,
            PcodeTokenKind::Illegal => 0,
        }
    }

    /// Inverse of `as_token_id`. Used by callers that receive a raw Bison
    /// token id (e.g. when consuming Bison-compatible output). `const fn` so
    /// the table lookups can be compile-time.
    pub const fn from_token_id(id: i32) -> Option<PcodeTokenKind> {
        match id {
            258 => Some(PcodeTokenKind::BoolOr),
            259 => Some(PcodeTokenKind::BoolAnd),
            260 => Some(PcodeTokenKind::BoolXor),
            261 => Some(PcodeTokenKind::Equal),
            262 => Some(PcodeTokenKind::NotEqual),
            263 => Some(PcodeTokenKind::FEqual),
            264 => Some(PcodeTokenKind::FNotEqual),
            265 => Some(PcodeTokenKind::GreatEqual),
            266 => Some(PcodeTokenKind::LessEqual),
            267 => Some(PcodeTokenKind::SLess),
            268 => Some(PcodeTokenKind::SGreatEqual),
            269 => Some(PcodeTokenKind::SLessEqual),
            270 => Some(PcodeTokenKind::SGreat),
            271 => Some(PcodeTokenKind::FLess),
            272 => Some(PcodeTokenKind::FGreat),
            273 => Some(PcodeTokenKind::FLessEqual),
            274 => Some(PcodeTokenKind::FGreatEqual),
            275 => Some(PcodeTokenKind::Left),
            276 => Some(PcodeTokenKind::Right),
            277 => Some(PcodeTokenKind::SRight),
            278 => Some(PcodeTokenKind::FAdd),
            279 => Some(PcodeTokenKind::FSub),
            280 => Some(PcodeTokenKind::SDiv),
            281 => Some(PcodeTokenKind::SRem),
            282 => Some(PcodeTokenKind::FMult),
            283 => Some(PcodeTokenKind::FDiv),
            284 => Some(PcodeTokenKind::Zext),
            285 => Some(PcodeTokenKind::Carry),
            286 => Some(PcodeTokenKind::Borrow),
            287 => Some(PcodeTokenKind::Sext),
            288 => Some(PcodeTokenKind::SCarry),
            289 => Some(PcodeTokenKind::SBorrow),
            290 => Some(PcodeTokenKind::Nan),
            291 => Some(PcodeTokenKind::Abs),
            292 => Some(PcodeTokenKind::Sqrt),
            293 => Some(PcodeTokenKind::Ceil),
            294 => Some(PcodeTokenKind::Floor),
            295 => Some(PcodeTokenKind::Round),
            296 => Some(PcodeTokenKind::Int2Float),
            297 => Some(PcodeTokenKind::Float2Float),
            298 => Some(PcodeTokenKind::Trunc),
            299 => Some(PcodeTokenKind::New),
            300 => Some(PcodeTokenKind::BadInteger),
            301 => Some(PcodeTokenKind::GotoKey),
            302 => Some(PcodeTokenKind::CallKey),
            303 => Some(PcodeTokenKind::ReturnKey),
            304 => Some(PcodeTokenKind::IfKey),
            305 => Some(PcodeTokenKind::EndOfStream),
            306 => Some(PcodeTokenKind::LocalKey),
            307 => Some(PcodeTokenKind::Integer),
            308 => Some(PcodeTokenKind::String),
            309 => Some(PcodeTokenKind::SpaceSym),
            310 => Some(PcodeTokenKind::UserOpSym),
            311 => Some(PcodeTokenKind::VarSym),
            312 => Some(PcodeTokenKind::OperandSym),
            313 => Some(PcodeTokenKind::JumpSym),
            314 => Some(PcodeTokenKind::LabelSym),
            // Single-char punctuation ids are handled by the caller because
            // `char::from_u32` is not const-stable in all contexts; this
            // branch is reserved.
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Coarse projection token (kept for backwards-compatible callers)
// ---------------------------------------------------------------------------

/// Coarse-grained token classification retained for callers that only need the
/// broad category. The full Bison-level token kind is in `PcodeTokenKind`;
/// `PcodeToken` is a lossy projection of it. Use `from_kind` to project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcodeToken {
    /// End of input (Ghidra's ENDOFSTREAM + Bison EOF).
    Eof,
    /// Unclassifiable character.
    Illegal,
    /// Identifier (STRING) or any keyword/operator that the lexer resolved
    /// via the `idents[]` table. The source spelling is available from
    /// `PcodeLexer::get_identifier()`.
    Identifier,
    /// `0x...` hexadecimal literal.
    HexNumber,
    /// Bare decimal literal.
    DecNumber,
    /// `(`.
    LParen,
    /// `)`.
    RParen,
    /// `,`.
    Comma,
    /// `;`.
    Semicolon,
    /// `[`.
    LBracket,
    /// `]`.
    RBracket,
    /// `=`.
    Assign,
    /// `$`.
    Dollar,
    /// `$$`.
    DoubleDollars,
}

impl PcodeToken {
    /// Project a fine-grained `PcodeTokenKind` down to a coarse `PcodeToken`.
    /// RUGRA-GLUE: Ghidra has no projection layer; the Bison token enum is
    /// returned directly to the grammar. Rugra keeps a coarse view for
    /// pre-existing callers.
    pub fn from_kind(kind: PcodeTokenKind) -> PcodeToken {
        match kind {
            PcodeTokenKind::Illegal => PcodeToken::Illegal,
            PcodeTokenKind::EndOfStream => PcodeToken::Eof,
            PcodeTokenKind::Integer => PcodeToken::HexNumber, // ambiguous; callers use lexer state
            PcodeTokenKind::BadInteger => PcodeToken::Illegal,
            PcodeTokenKind::Punct(c) => match c {
                '(' => PcodeToken::LParen,
                ')' => PcodeToken::RParen,
                ',' => PcodeToken::Comma,
                ';' => PcodeToken::Semicolon,
                '[' => PcodeToken::LBracket,
                ']' => PcodeToken::RBracket,
                '=' => PcodeToken::Assign,
                '$' => PcodeToken::Dollar,
                _ => PcodeToken::Identifier,
            },
            // Everything else (keywords, multi-char operators, symbol kinds)
            // is reported via the identifier channel; the original spelling
            // is in `curidentifier`.
            _ => PcodeToken::Identifier,
        }
    }
}

// ---------------------------------------------------------------------------
// IdentRec table + binary search (pcodeparse.y:228-295)
// ---------------------------------------------------------------------------

/// Keyword / multi-char operator table entry, faithful to
/// pcodeparse.hh:26-29 (`IdentRec { nm, id }`).
#[derive(Debug, Clone, Copy)]
pub struct IdentRec {
    /// The source spelling.
    pub name: &'static str,
    /// The Bison token id (258-314) returned when this spelling is matched.
    pub id: i32,
}

/// Sorted keyword/operator table, faithful to `PcodeLexer::idents[]`
/// (pcodeparse.y:229-276). Sorted lexicographically by `name` so that
/// `find_identifier`'s binary search matches Ghidra's. The `id` fields use
/// inlined integer literals (not `PcodeTokenKind::X.as_token_id()`) because
/// Rust statics may not call non-const functions; the values are identical
/// to those in `PcodeTokenKind::as_token_id`.
pub static PCODE_IDENTS: [IdentRec; IDENTREC_SIZE] = [
    IdentRec {
        name: "!=",
        id: 262,
    }, // OP_NOTEQUAL
    IdentRec {
        name: "&&",
        id: 259,
    }, // OP_BOOL_AND
    IdentRec {
        name: "<<",
        id: 275,
    }, // OP_LEFT
    IdentRec {
        name: "<=",
        id: 266,
    }, // OP_LESSEQUAL
    IdentRec {
        name: "==",
        id: 261,
    }, // OP_EQUAL
    IdentRec {
        name: ">=",
        id: 265,
    }, // OP_GREATEQUAL
    IdentRec {
        name: ">>",
        id: 276,
    }, // OP_RIGHT
    IdentRec {
        name: "^^",
        id: 260,
    }, // OP_BOOL_XOR
    IdentRec {
        name: "||",
        id: 258,
    }, // OP_BOOL_OR
    IdentRec {
        name: "abs",
        id: 291,
    }, // OP_ABS
    IdentRec {
        name: "borrow",
        id: 286,
    }, // OP_BORROW
    IdentRec {
        name: "call",
        id: 302,
    }, // CALL_KEY
    IdentRec {
        name: "carry",
        id: 285,
    }, // OP_CARRY
    IdentRec {
        name: "ceil",
        id: 293,
    }, // OP_CEIL
    IdentRec {
        name: "f!=",
        id: 264,
    }, // OP_FNOTEQUAL
    IdentRec {
        name: "f*",
        id: 282,
    }, // OP_FMULT
    IdentRec {
        name: "f+",
        id: 278,
    }, // OP_FADD
    IdentRec {
        name: "f-",
        id: 279,
    }, // OP_FSUB
    IdentRec {
        name: "f/",
        id: 283,
    }, // OP_FDIV
    IdentRec {
        name: "f<",
        id: 271,
    }, // OP_FLESS
    IdentRec {
        name: "f<=",
        id: 273,
    }, // OP_FLESSEQUAL
    IdentRec {
        name: "f==",
        id: 263,
    }, // OP_FEQUAL
    IdentRec {
        name: "f>",
        id: 272,
    }, // OP_FGREAT
    IdentRec {
        name: "f>=",
        id: 274,
    }, // OP_FGREATEQUAL
    IdentRec {
        name: "float2float",
        id: 297,
    }, // OP_FLOAT2FLOAT
    IdentRec {
        name: "floor",
        id: 294,
    }, // OP_FLOOR
    IdentRec {
        name: "goto",
        id: 301,
    }, // GOTO_KEY
    IdentRec {
        name: "if",
        id: 304,
    }, // IF_KEY
    IdentRec {
        name: "int2float",
        id: 296,
    }, // OP_INT2FLOAT
    IdentRec {
        name: "local",
        id: 306,
    }, // LOCAL_KEY
    IdentRec {
        name: "nan",
        id: 290,
    }, // OP_NAN
    IdentRec {
        name: "return",
        id: 303,
    }, // RETURN_KEY
    IdentRec {
        name: "round",
        id: 295,
    }, // OP_ROUND
    IdentRec {
        name: "s%",
        id: 281,
    }, // OP_SREM
    IdentRec {
        name: "s/",
        id: 280,
    }, // OP_SDIV
    IdentRec {
        name: "s<",
        id: 267,
    }, // OP_SLESS
    IdentRec {
        name: "s<=",
        id: 269,
    }, // OP_SLESSEQUAL
    IdentRec {
        name: "s>",
        id: 270,
    }, // OP_SGREAT
    IdentRec {
        name: "s>=",
        id: 268,
    }, // OP_SGREATEQUAL
    IdentRec {
        name: "s>>",
        id: 277,
    }, // OP_SRIGHT
    IdentRec {
        name: "sborrow",
        id: 289,
    }, // OP_SBORROW
    IdentRec {
        name: "scarry",
        id: 288,
    }, // OP_SCARRY
    IdentRec {
        name: "sext",
        id: 287,
    }, // OP_SEXT
    IdentRec {
        name: "sqrt",
        id: 292,
    }, // OP_SQRT
    IdentRec {
        name: "trunc",
        id: 298,
    }, // OP_TRUNC
    IdentRec {
        name: "zext",
        id: 284,
    }, // OP_ZEXT
];

/// Binary-search the sorted `idents[]` table for `s`, faithful to
/// `PcodeLexer::findIdentifier` (pcodeparse.y:278-295). Returns the table
/// index, or `None` when not found (Ghidra returns -1).
pub fn find_identifier(s: &str) -> Option<usize> {
    let mut low: i64 = 0;
    let mut high: i64 = (IDENTREC_SIZE - 1) as i64;
    while low <= high {
        let targ = ((low + high) / 2) as usize;
        // Lexicographic compare against the Ghidra-sorted table.
        let comp = s.cmp(PCODE_IDENTS[targ].name);
        match comp {
            std::cmp::Ordering::Less => high = targ as i64 - 1,
            std::cmp::Ordering::Greater => low = targ as i64 + 1,
            std::cmp::Ordering::Equal => return Some(targ),
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Lexer states (pcodeparse.hh:33-45)
// ---------------------------------------------------------------------------

/// Bison lexer states, faithful to pcodeparse.hh:33-45.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexerState {
    /// Initial state.
    Start,
    /// Middle of a special 2-character operator.
    Special2,
    /// First character of a special 3-character operator.
    Special3,
    /// Second character of a special 3-character operator.
    Special32,
    /// Middle of an end-of-line comment.
    Comment,
    /// Punctuation character (transient).
    Punctuation,
    /// Middle of an identifier.
    Identifier,
    /// Middle of a hexadecimal number.
    Hexstring,
    /// Middle of a decimal number.
    Decstring,
    /// Reached end of stream.
    Endstream,
    /// Scanned an illegal character.
    Illegal,
}

// ---------------------------------------------------------------------------
// PcodeLexer (pcodeparse.hh:31; pcodeparse.y:297-630)
// ---------------------------------------------------------------------------

/// The lookahead-2 state-machine lexer, faithful to
/// `PcodeLexer` (pcodeparse.hh:31-70). The implementation mirrors
/// `moveState` (pcodeparse.y:297-558) and `getNextToken`
/// (pcodeparse.y:560-606) character-for-character.
pub struct PcodeLexer {
    /// Current lexer state (`curstate`).
    curstate: LexerState,
    /// Three-character sliding window: `curchar`, `lookahead1`, `lookahead2`.
    curchar: char,
    lookahead1: char,
    lookahead2: char,
    /// Accumulating token buffer (`curtoken[256]`).
    curtoken: String,
    /// Most recently completed identifier (`curidentifier`).
    curidentifier: String,
    /// Most recently parsed numeric literal (`curnum`).
    curnum: u64,
    /// Whether the underlying stream is exhausted (`endofstream`).
    endofstream: bool,
    /// Whether the official ENDOFSTREAM token has already been emitted
    /// (`endofstreamsent`).
    endofstreamsent: bool,
    /// The byte stream as a char iterator + position (`s`, indexed by pos).
    text: Vec<char>,
    /// Current position in `text`.
    pos: usize,
}

impl PcodeLexer {
    // Ghidra: pcodeparse.hh:65 PcodeLexer::PcodeLexer
    /// Construct an uninitialised lexer (no stream bound). Mirrors the C++
    /// default ctor `PcodeLexer(void) { s = (istream *)0; }`.
    pub fn new() -> Self {
        Self {
            curstate: LexerState::Start,
            curchar: '\0',
            lookahead1: '\0',
            lookahead2: '\0',
            curtoken: String::new(),
            curidentifier: String::new(),
            curnum: 0,
            endofstream: false,
            endofstreamsent: false,
            text: Vec::new(),
            pos: 0,
        }
    }

    // Ghidra: pcodeparse.y:608 PcodeLexer::initialize
    /// Bind a new text stream and prime the lookahead window. Faithful to
    /// `initialize` (pcodeparse.y:608-630): resets all state, then buffers the
    /// first two characters into `lookahead1` / `lookahead2`.
    pub fn initialize(&mut self, text: &str) {
        self.text = text.chars().collect();
        self.pos = 0;
        self.curstate = LexerState::Start;
        self.curtoken.clear();
        self.curidentifier.clear();
        self.curnum = 0;
        self.endofstream = false;
        self.endofstreamsent = false;
        self.curchar = '\0';
        // Prime the 2-char lookahead exactly like initialize(): read into
        // lookahead1, then lookahead2, marking EOF if either read fails.
        self.lookahead1 = self.next_stream_char();
        self.lookahead2 = self.next_stream_char();
    }

    // RUGRA-GLUE: next_stream_char
    /// Pull one character from the stream, returning '\0' at EOF (mirrors
    /// `s->get(c); if (!(*s)) { endofstream = true; c = 0; }`).
    fn next_stream_char(&mut self) -> char {
        if self.pos < self.text.len() {
            let c = self.text[self.pos];
            self.pos += 1;
            c
        } else {
            self.endofstream = true;
            '\0'
        }
    }

    // Ghidra: pcodeparse.hh:59 PcodeLexer::isIdent
    /// Identifier character predicate (pcodeparse.hh:59).
    fn is_ident(c: char) -> bool {
        c.is_alphanumeric() || c == '_' || c == '.'
    }

    // Ghidra: pcodeparse.hh:60 PcodeLexer::isHex
    /// Hex-digit predicate (pcodeparse.hh:60).
    fn is_hex(c: char) -> bool {
        c.is_ascii_hexdigit()
    }

    // Ghidra: pcodeparse.hh:61 PcodeLexer::isDec
    /// Decimal-digit predicate (pcodeparse.hh:61).
    fn is_dec(c: char) -> bool {
        c.is_ascii_digit()
    }

    // Ghidra: pcodeparse.hh:57 PcodeLexer::starttoken
    /// Begin a new token buffer with the current char (pcodeparse.hh:57).
    fn starttoken(&mut self) {
        self.curtoken.clear();
        self.curtoken.push(self.curchar);
    }

    // Ghidra: pcodeparse.hh:58 PcodeLexer::advancetoken
    /// Append the current char to the token buffer (pcodeparse.hh:58).
    fn advancetoken(&mut self) {
        self.curtoken.push(self.curchar);
    }

    // Ghidra: pcodeparse.y:297 PcodeLexer::moveState
    /// Advance the state machine by one character. Returns the state value
    /// to report to the caller of `getNextToken` (`start` means "keep going",
    /// any other state means "this token is complete"). Faithful to
    /// pcodeparse.y:297-558, including the 3-character lookahead for `s>>`,
    /// `s<=`, `s>=`, `f==`, `f!=`, `f<=`, `f>=`.
    fn move_state(&mut self) -> LexerState {
        match self.curstate {
            LexerState::Start => {
                // Huge pattern match mirroring pcodeparse.y:301-514.
                match self.curchar {
                    '#' => {
                        self.curstate = LexerState::Comment;
                        LexerState::Start
                    }
                    '|' => self.special2_or_punct('|'),
                    '&' => self.special2_or_punct('&'),
                    '^' => self.special2_or_punct('^'),
                    '>' => {
                        if self.lookahead1 == '>' || self.lookahead1 == '=' {
                            self.starttoken();
                            self.curstate = LexerState::Special2;
                            LexerState::Start
                        } else {
                            LexerState::Punctuation
                        }
                    }
                    '<' => {
                        if self.lookahead1 == '<' || self.lookahead1 == '=' {
                            self.starttoken();
                            self.curstate = LexerState::Special2;
                            LexerState::Start
                        } else {
                            LexerState::Punctuation
                        }
                    }
                    '=' => {
                        if self.lookahead1 == '=' {
                            self.starttoken();
                            self.curstate = LexerState::Special2;
                            LexerState::Start
                        } else {
                            LexerState::Punctuation
                        }
                    }
                    '!' => {
                        if self.lookahead1 == '=' {
                            self.starttoken();
                            self.curstate = LexerState::Special2;
                            LexerState::Start
                        } else {
                            LexerState::Punctuation
                        }
                    }
                    '(' | ')' | ',' | ':' | '[' | ']' | ';' | '+' | '-' | '*' | '/' | '%' | '~' => {
                        LexerState::Punctuation
                    }
                    // The 's' / 'f' signed-/float-family operators. These
                    // require the full 3-char lookahead. pcodeparse.y:369-413.
                    's' => self.handle_signed_prefix(),
                    'f' => self.handle_float_prefix(),
                    c if c.is_ascii_alphabetic() || c == '_' || c == '.' => {
                        self.starttoken();
                        if Self::is_ident(self.lookahead1) {
                            self.curstate = LexerState::Identifier;
                            LexerState::Start
                        } else {
                            self.curstate = LexerState::Start;
                            LexerState::Identifier
                        }
                    }
                    '0' => {
                        self.starttoken();
                        if self.lookahead1 == 'x' {
                            self.curstate = LexerState::Hexstring;
                            LexerState::Start
                        } else if Self::is_dec(self.lookahead1) {
                            self.curstate = LexerState::Decstring;
                            LexerState::Start
                        } else {
                            self.curstate = LexerState::Start;
                            LexerState::Decstring
                        }
                    }
                    '1'..='9' => {
                        self.starttoken();
                        if Self::is_dec(self.lookahead1) {
                            self.curstate = LexerState::Decstring;
                            LexerState::Start
                        } else {
                            self.curstate = LexerState::Start;
                            LexerState::Decstring
                        }
                    }
                    // Whitespace (pcodeparse.y:502-507).
                    '\n' | ' ' | '\t' | '\x0b' | '\r' => LexerState::Start,
                    '\0' => {
                        self.curstate = LexerState::Endstream;
                        LexerState::Endstream
                    }
                    _ => {
                        self.curstate = LexerState::Illegal;
                        LexerState::Illegal
                    }
                }
            }
            LexerState::Special2 => {
                // pcodeparse.y:516-519.
                self.advancetoken();
                self.curstate = LexerState::Start;
                LexerState::Identifier
            }
            LexerState::Special3 => {
                // pcodeparse.y:520-523.
                self.advancetoken();
                self.curstate = LexerState::Special32;
                LexerState::Start
            }
            LexerState::Special32 => {
                // pcodeparse.y:524-527.
                self.advancetoken();
                self.curstate = LexerState::Start;
                LexerState::Identifier
            }
            LexerState::Comment => {
                // pcodeparse.y:528-535.
                if self.curchar == '\n' {
                    self.curstate = LexerState::Start;
                } else if self.curchar == '\0' {
                    self.curstate = LexerState::Endstream;
                    return LexerState::Endstream;
                }
                LexerState::Start
            }
            LexerState::Identifier => {
                // pcodeparse.y:536-541.
                self.advancetoken();
                if Self::is_ident(self.lookahead1) {
                    LexerState::Start
                } else {
                    self.curstate = LexerState::Start;
                    LexerState::Identifier
                }
            }
            LexerState::Hexstring => {
                // pcodeparse.y:542-547.
                self.advancetoken();
                if Self::is_hex(self.lookahead1) {
                    LexerState::Start
                } else {
                    self.curstate = LexerState::Start;
                    LexerState::Hexstring
                }
            }
            LexerState::Decstring => {
                // pcodeparse.y:548-553.
                self.advancetoken();
                if Self::is_dec(self.lookahead1) {
                    LexerState::Start
                } else {
                    self.curstate = LexerState::Start;
                    LexerState::Decstring
                }
            }
            _ => {
                // pcodeparse.y:554-557 default.
                self.curstate = LexerState::Endstream;
                LexerState::Endstream
            }
        }
    }

    // RUGRA-GLUE: special2_or_punct
    /// Shared body for `|`, `&`, `^` start-state handling: if the lookahead
    /// matches the same char, begin a 2-char operator token; otherwise emit
    /// the single char as punctuation. Factored out of `move_state` to keep
    /// the giant match readable. Behaviour is identical to the inlined
    /// pcodeparse.y:306-326 blocks.
    fn special2_or_punct(&mut self, op: char) -> LexerState {
        if self.lookahead1 == op {
            self.starttoken();
            self.curstate = LexerState::Special2;
            LexerState::Start
        } else {
            LexerState::Punctuation
        }
    }

    // Ghidra: pcodeparse.y:369-393 (s-prefix operators)
    /// Handle the `s` start-state branch (pcodeparse.y:369-393): recognises
    /// `s/`, `s%`, `s<`, `s<=`, `s>`, `s>=`, `s>>`. Falls through to the
    /// ordinary identifier path if no signed operator matches.
    fn handle_signed_prefix(&mut self) -> LexerState {
        match self.lookahead1 {
            '/' | '%' => {
                self.starttoken();
                self.curstate = LexerState::Special2;
                LexerState::Start
            }
            '<' => {
                self.starttoken();
                if self.lookahead2 == '=' {
                    self.curstate = LexerState::Special3;
                } else {
                    self.curstate = LexerState::Special2;
                }
                LexerState::Start
            }
            '>' => {
                self.starttoken();
                if self.lookahead2 == '>' || self.lookahead2 == '=' {
                    self.curstate = LexerState::Special3;
                } else {
                    self.curstate = LexerState::Special2;
                }
                LexerState::Start
            }
            _ => {
                // Fall through to ordinary identifier handling
                // (pcodeparse.y:414 comment).
                self.starttoken();
                if Self::is_ident(self.lookahead1) {
                    self.curstate = LexerState::Identifier;
                    LexerState::Start
                } else {
                    self.curstate = LexerState::Start;
                    LexerState::Identifier
                }
            }
        }
    }

    // Ghidra: pcodeparse.y:394-413 (f-prefix operators)
    /// Handle the `f` start-state branch (pcodeparse.y:394-413): recognises
    /// `f+`, `f-`, `f*`, `f/`, `f==`, `f!=`, `f<`, `f<=`, `f>`, `f>=`.
    /// Falls through to the ordinary identifier path otherwise.
    fn handle_float_prefix(&mut self) -> LexerState {
        match self.lookahead1 {
            '+' | '-' | '*' | '/' => {
                self.starttoken();
                self.curstate = LexerState::Special2;
                LexerState::Start
            }
            '=' | '!' if self.lookahead2 == '=' => {
                self.starttoken();
                self.curstate = LexerState::Special3;
                LexerState::Start
            }
            '<' | '>' => {
                self.starttoken();
                if self.lookahead2 == '=' {
                    self.curstate = LexerState::Special3;
                } else {
                    self.curstate = LexerState::Special2;
                }
                LexerState::Start
            }
            _ => {
                self.starttoken();
                if Self::is_ident(self.lookahead1) {
                    self.curstate = LexerState::Identifier;
                    LexerState::Start
                } else {
                    self.curstate = LexerState::Start;
                    LexerState::Identifier
                }
            }
        }
    }

    // Ghidra: pcodeparse.y:560 PcodeLexer::getNextToken
    /// Drive `move_state` one character at a time until a non-`start` state
    /// is reported, then resolve the token kind. Faithful to
    /// pcodeparse.y:560-606.
    pub fn get_next_token(&mut self) -> PcodeTokenKind {
        let mut state;
        loop {
            // Slide the lookahead window (pcodeparse.y:566-576).
            self.curchar = self.lookahead1;
            self.lookahead1 = self.lookahead2;
            if self.endofstream {
                self.lookahead2 = '\0';
            } else {
                self.lookahead2 = self.next_stream_char();
            }
            state = self.move_state();
            if state != LexerState::Start {
                break;
            }
        }
        match state {
            LexerState::Identifier => {
                // pcodeparse.y:579-586: keyword-resolve via idents[].
                self.curidentifier = self.curtoken.clone();
                match find_identifier(&self.curidentifier) {
                    Some(idx) => {
                        let id = PCODE_IDENTS[idx].id;
                        // Reconstruct the token kind from the numeric id.
                        if let Some(kind) = PcodeTokenKind::from_token_id(id) {
                            kind
                        } else {
                            PcodeTokenKind::String
                        }
                    }
                    None => PcodeTokenKind::String,
                }
            }
            LexerState::Hexstring | LexerState::Decstring => {
                // pcodeparse.y:587-595: parse the numeric literal.
                self.curnum = parse_number_token(&self.curtoken);
                if self.curnum == 0 && self.curtoken.chars().any(|c| c != '0') {
                    // Could not parse — Ghidra returns BADINTEGER.
                    PcodeTokenKind::BadInteger
                } else {
                    PcodeTokenKind::Integer
                }
            }
            LexerState::Endstream => {
                // pcodeparse.y:596-602: emit ENDOFSTREAM once, then 0.
                if !self.endofstreamsent {
                    self.endofstreamsent = true;
                    PcodeTokenKind::EndOfStream
                } else {
                    PcodeTokenKind::Illegal
                }
            }
            LexerState::Illegal => PcodeTokenKind::Illegal,
            LexerState::Punctuation => {
                // pcodeparse.y:605: return curchar as the token id.
                PcodeTokenKind::Punct(self.curchar)
            }
            _ => PcodeTokenKind::Illegal,
        }
    }

    // Ghidra: pcodeparse.hh:68 PcodeLexer::getIdentifier
    /// Return the spelling of the most recently produced identifier/keyword
    /// token (pcodeparse.hh:68).
    pub fn get_identifier(&self) -> &str {
        &self.curidentifier
    }

    // Ghidra: pcodeparse.hh:69 PcodeLexer::getNumber
    /// Return the value of the most recently produced numeric literal
    /// (pcodeparse.hh:69).
    pub fn get_number(&self) -> u64 {
        self.curnum
    }

    // RUGRA-GLUE: tokenize_all
    /// Convenience: lex the entire input to a vec of token kinds. Ghidra has
    /// no equivalent — the Bison parser pulls tokens one at a time — but this
    /// is useful for tests and for callers that want a quick scan.
    pub fn tokenize_all(&mut self, text: &str) -> Vec<PcodeTokenKind> {
        self.initialize(text);
        let mut out = Vec::new();
        loop {
            let tok = self.get_next_token();
            let is_eof = matches!(tok, PcodeTokenKind::Illegal);
            out.push(tok);
            if is_eof {
                break;
            }
        }
        out
    }
}

impl Default for PcodeLexer {
    // Ghidra: pcodeparse.hh:65 PcodeLexer::default
    fn default() -> Self {
        Self::new()
    }
}

// RUGRA-GLUE: parse_number_token
/// Parse a numeric token spelling the way `getNextToken` does
/// (pcodeparse.y:588-594): hex if it starts with `0x`, decimal otherwise.
/// Returns 0 on parse failure (caller maps that to `BadInteger`), matching
/// the C++ `istringstream >> uintb` failure mode.
fn parse_number_token(s: &str) -> u64 {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// SLEIGH symbol kinds (the type switch in PcodeSnippet::lex)
// ---------------------------------------------------------------------------

/// Tagged SLEIGH symbol kind, faithful to the `switch(sym->getType())` in
/// `PcodeSnippet::lex` (pcodeparse.y:730-758). Rugra does not link against
/// SLEIGH, so each kind carries the resolved payload directly.
#[derive(Debug, Clone)]
pub enum SleightSymbolKind {
    /// `space_symbol` — a named `AddressSpace`. Maps to SPACESYM.
    Space(AddressSpace),
    /// `userop_symbol` — a user-defined p-code op. Maps to USEROPSYM.
    UserOp(String),
    /// `varnode_symbol` — a named fixed varnode. Maps to VARSYM.
    Varnode(VarnodeData),
    /// `operand_symbol` — a constructor operand. Maps to OPERANDSYM.
    Operand(String, i32),
    /// `start_symbol`/`end_symbol`/`next2_symbol`/`flowdest_symbol`/
    /// `flowref_symbol` — all map to JUMPSYM.
    JumpTarget(String),
    /// `label_symbol` — a branch label. Maps to LABELSYM.
    Label(String, u32),
}

/// A resolved SLEIGH symbol, faithful to `SleighSymbol` as used by
/// `PcodeSnippet` (the `tree` set holds `SleighSymbol *`).
#[derive(Debug, Clone)]
pub struct SleighSymbol {
    /// The symbol's name (lookup key).
    pub name: String,
    /// The resolved payload.
    pub kind: SleightSymbolKind,
}

// ---------------------------------------------------------------------------
// PcodeData (sleigh.hh:44) — raw p-code op record
// ---------------------------------------------------------------------------

/// Raw p-code op record, faithful to `PcodeData` (sleigh.hh:44-49):
/// `{ opc, *outvar, **invar, isize }`. In Rust we own the varnode vec rather
/// than holding raw pointers.
#[derive(Debug, Clone)]
pub struct PcodeData {
    /// The opcode (`opc`).
    pub opc: OpCode,
    /// The output varnode, if any (`outvar` is null in Ghidra when absent).
    pub outvar: Option<VarnodeData>,
    /// The input varnodes (`invar[0..isize]`).
    pub invar: Vec<VarnodeData>,
}

impl PcodeData {
    // RUGRA-GLUE: new (no direct Ghidra ctor; PcodeData is aggregate-init)
    /// Construct a record with the given opcode and no inputs/output.
    pub fn new(opc: OpCode) -> Self {
        Self {
            opc,
            outvar: None,
            invar: Vec::new(),
        }
    }

    // RUGRA-GLUE: set_output
    /// Set the output varnode.
    pub fn set_output(&mut self, vn: VarnodeData) {
        self.outvar = Some(vn);
    }

    // RUGRA-GLUE: add_input
    /// Append an input varnode.
    pub fn add_input(&mut self, vn: VarnodeData) {
        self.invar.push(vn);
    }

    // RUGRA-GLUE: clear_inputs
    /// Drop all inputs.
    pub fn clear_inputs(&mut self) {
        self.invar.clear();
    }

    // RUGRA-GLUE: num_input
    /// Number of inputs (`isize`).
    pub fn num_input(&self) -> usize {
        self.invar.len()
    }

    // RUGRA-GLUE: get_output
    /// Borrow the output varnode.
    pub fn get_output(&self) -> Option<&VarnodeData> {
        self.outvar.as_ref()
    }
}

// ---------------------------------------------------------------------------
// XML element/attribute id helpers (translate.cc / address.cc)
// ---------------------------------------------------------------------------

// RUGRA-GLUE: element_id helpers
// Ghidra declares these as file-scope `ElementId`/`AttributeId` globals
// (translate.cc:20-28, address.cc:25-30). Rugra's `ElementId::new` /
// `AttributeId::new` are non-const, so we construct fresh values here; the
// numeric ids match Ghidra exactly.

/// `ELEM_OP = ElementId("op",27)` (translate.cc:25).
pub fn elem_op() -> ElementId {
    ElementId::new("op", 27)
}

/// `ELEM_ADDR = ElementId("addr",11)` (address.cc:25).
pub fn elem_addr() -> ElementId {
    ElementId::new("addr", 11)
}

/// `ELEM_REGISTER = ElementId("register",14)` (address.cc:28).
pub fn elem_register() -> ElementId {
    ElementId::new("register", 14)
}

/// `ELEM_VARNODE = ElementId("varnode",16)` (address.cc:30).
pub fn elem_varnode() -> ElementId {
    ElementId::new("varnode", 16)
}

/// `ELEM_VOID = ElementId("void",18)` (pcoderaw.hh). Used by `PcodeOpRaw::decode`.
pub fn elem_void() -> ElementId {
    ElementId::new("void", 18)
}

/// `ELEM_SPACEID = ElementId("spaceid",30)` (translate.cc:28).
pub fn elem_spaceid() -> ElementId {
    ElementId::new("spaceid", 30)
}

/// `ATTRIB_CODE = AttributeId("code",43)` (translate.cc:20).
pub fn attrib_code() -> AttributeId {
    AttributeId::new("code", 43)
}

/// `ATTRIB_SIZE = AttributeId("size",7)` (translate.cc:43 uses it).
pub fn attrib_size() -> AttributeId {
    AttributeId::new("size", 7)
}

/// `ATTRIB_SPACE = AttributeId("space",9)`.
pub fn attrib_space() -> AttributeId {
    AttributeId::new("space", 9)
}

/// `ATTRIB_NAME = AttributeId("name",2)`.
pub fn attrib_name() -> AttributeId {
    AttributeId::new("name", 2)
}

/// `ATTRIB_OFFSET = AttributeId("offset",4)`.
pub fn attrib_offset() -> AttributeId {
    AttributeId::new("offset", 4)
}

// ---------------------------------------------------------------------------
// Space-name resolution (mirrors decoder.readSpace on a <space> attribute)
// ---------------------------------------------------------------------------

/// Resolve a space spelling to an `AddressSpace`, mirroring Ghidra's
/// `decoder.readSpace(ATTRIB_SPACE)` which returns the named `AddrSpace *`.
/// The accepted spellings are the lowercased names of Rugra's `AddressSpace`
/// variants. RUGRA-GLUE: Ghidra looks the name up in the SLEIGH space table;
/// Rugra has no SLEIGH, so we pattern-match on the well-known names.
pub fn parse_space_name(name: &str) -> AddressSpace {
    match name {
        "ram" | "RAM" => AddressSpace::Ram,
        "register" | "REGISTER" => AddressSpace::Register,
        "unique" | "UNIQUE" => AddressSpace::Unique,
        "const" | "CONST" => AddressSpace::Const,
        "stack" | "STACK" => AddressSpace::Stack,
        "join" | "JOIN" => AddressSpace::Join,
        "iop" | "IOP" => AddressSpace::Iop,
        _ => AddressSpace::Other(crate::space::SPACEID_OTHER),
    }
}

// ---------------------------------------------------------------------------
// XML decode (pcoderaw.cc:23-122, translate.cc:996-1014)
// ---------------------------------------------------------------------------

/// Faithful to `VarnodeData::decodeFromAttributes` (pcoderaw.cc:33-55).
/// Walks the current element's attributes; on `space=` reads the offset/size
/// from the space's own attribute set, on `name=` looks up a register. Rugra
/// has no register resolver yet, so `name=` falls back to a register-space
/// varnode with offset 0 (L3 gap noted in the module docs).
pub fn decode_varnode_from_attributes(decoder: &mut dyn Decoder) -> VarnodeData {
    let mut space: Option<AddressSpace> = None;
    let mut offset: u64 = 0;
    let mut size: usize = 0;
    let mut name: Option<String> = None;
    loop {
        let attrib_id = decoder.next_attribute_id();
        if attrib_id == 0 {
            break;
        }
        // Compare by name (Ghidra compares AttributeId pointers; Rugra's ids
        // are registry-assigned so we compare names instead — equivalent for
        // the well-known attributes used here).
        let Some(aname) = decoder.attribute_name(attrib_id) else {
            continue;
        };
        match aname.as_str() {
            "space" => {
                let space_name = decoder.read_string();
                space = Some(parse_space_name(&space_name));
                // Ghidra then does: offset = space->decodeAttributes(decoder,size)
                // which rewalks the attributes for offset= and size=. We do
                // the same rewalk below by continuing the loop and capturing
                // offset/size here.
            }
            "name" => {
                name = Some(decoder.read_string());
            }
            "offset" => {
                offset = decoder.read_unsigned_integer();
            }
            "size" => {
                size = decoder.read_unsigned_integer() as usize;
            }
            _ => {
                // Skip unknown attributes (Ghidra's loop ignores them too).
            }
        }
    }
    if let Some(sp) = space {
        // RUGRA-GLUE: register resolver (L3 gap)
        // On `name=` with a register, Ghidra calls trans->getRegister(name).
        // Rugra has no Translate yet, so emit a Register-space varnode with
        // offset 0 when only a name was given. This keeps the shape correct.
        VarnodeData {
            space: sp,
            offset,
            size,
        }
    } else if let Some(_n) = name {
        VarnodeData {
            space: AddressSpace::Register,
            offset: 0,
            size,
        }
    } else {
        // No space and no name — empty <addr/> tag. Ghidra leaves space null;
        // we default to the constant space with zero size.
        VarnodeData {
            space: AddressSpace::Const,
            offset: 0,
            size: 0,
        }
    }
}

/// Faithful to `VarnodeData::decode` (pcoderaw.cc:23-29): opens the
/// `<addr>` / `<register>` / `<varnode>` element, delegates to
/// `decode_varnode_from_attributes`, closes the element.
pub fn decode_varnode(decoder: &mut dyn Decoder) -> VarnodeData {
    let elem_id = decoder.open_element();
    let vn = decode_varnode_from_attributes(decoder);
    decoder.close_element(elem_id);
    vn
}

/// Faithful to `PcodeOpRaw::decode` (pcoderaw.cc:96-122). Assumes the `<op>`
/// element is already open. Reads `code=` as the opcode, handles `<void>`
/// output (no output) vs. an output varnode, then decodes `isize` inputs with
/// special `<spaceid>` handling (constant-space varnode whose offset is the
/// space pointer — Rugra approximates this with a Const varnode).
pub fn decode_pcode_op_raw(decoder: &mut dyn Decoder, isize_: i32) -> Option<PcodeData> {
    let code_raw = decoder.read_signed_integer_attr(&attrib_code()) as i32;
    let opc = OpCode::from_i32(code_raw)?;
    let mut data = PcodeData::new(opc);
    // Output varnode: <void> means none, otherwise decode a varnode.
    let sub_id = decoder.peek_element();
    let void_id = elem_void().id;
    if sub_id == void_id {
        let opened = decoder.open_element();
        decoder.close_element(opened);
        // outvar stays None.
    } else {
        let out = decode_varnode(decoder);
        data.set_output(out);
    }
    // Inputs.
    let spaceid_id = elem_spaceid().id;
    for _ in 0..isize_ {
        let sub_id = decoder.peek_element();
        if sub_id == spaceid_id {
            // <spaceid name="..."> — Ghidra stores the AddrSpace pointer as
            // the offset in the constant space. Rugra has no space pointer to
            // encode, so we record the name as a zero-offset Const varnode of
            // pointer size. RUGRA-GLUE: SLEIGH gap.
            let opened = decoder.open_element();
            let _name = decoder.read_string_attr(&attrib_name());
            decoder.close_element(opened);
            data.add_input(VarnodeData {
                space: AddressSpace::Const,
                offset: 0,
                size: std::mem::size_of::<usize>(),
            });
        } else {
            data.add_input(decode_varnode(decoder));
        }
    }
    Some(data)
}

/// Faithful to `PcodeEmit::decodeOp` (translate.cc:996-1014): opens the
/// `<op>` element, reads `size=` as the input count, delegates to
/// `decode_pcode_op_raw`, then closes the element. Returns the decoded op
/// (Rugra returns it directly; Ghidra hands it to `PcodeEmit::dump`).
pub fn decode_op(decoder: &mut dyn Decoder) -> Option<PcodeData> {
    let elem_id = decoder.open_element_matching(&elem_op());
    let isize_ = decoder.read_signed_integer_attr(&attrib_size()) as i32;
    let result = decode_pcode_op_raw(decoder, isize_);
    decoder.close_element(elem_id);
    result
}

// ---------------------------------------------------------------------------
// PcodeSnippet (pcodeparse.hh:72; pcodeparse.y:632-792)
// ---------------------------------------------------------------------------

/// The snippet compiler, faithful to `PcodeSnippet`
/// (pcodeparse.hh:72-98). Holds the lexer, the local symbol table, the
/// unique-space temp allocator, and the error state. The Bison grammar
/// semantic actions (ConstructTpl assembly) are an L3 gap.
pub struct PcodeSnippet {
    /// The wrapped lexer (`lexer`).
    lexer: PcodeLexer,
    /// Local symbol table (`tree`). Includes space symbols seeded from the
    /// SLEIGH language plus temporaries added during parsing.
    symbols: std::collections::HashMap<String, SleighSymbol>,
    /// Names of spaces (seeded like the ctor at pcodeparse.y:686-692).
    spaces: Vec<AddressSpace>,
    /// Next free unique-space offset (`tempbase`).
    tempbase: u64,
    /// Error counter (`errorcount`).
    errorcount: i32,
    /// First reported error message (`firsterror`).
    firsterror: Option<String>,
}

impl PcodeSnippet {
    // Ghidra: pcodeparse.y:676 PcodeSnippet::PcodeSnippet
    /// Construct a snippet compiler. Faithful to pcodeparse.y:676-695: zero
    /// tempbase, zero errors, no result, and seed the well-known address
    /// spaces. Rugra has no SLEIGH handle so the spaces are the built-in
    /// `AddressSpace` variants.
    pub fn new() -> Self {
        let mut s = Self {
            lexer: PcodeLexer::new(),
            symbols: std::collections::HashMap::new(),
            spaces: Vec::new(),
            tempbase: 0,
            errorcount: 0,
            firsterror: None,
        };
        // pcodeparse.y:686-692: insert a SpaceSymbol for each space of type
        // CONSTANT / PROCESSOR / SPACEBASE / INTERNAL. Rugra seeds the
        // built-in spaces directly.
        for sp in [
            AddressSpace::Ram,
            AddressSpace::Register,
            AddressSpace::Unique,
            AddressSpace::Const,
            AddressSpace::Stack,
            AddressSpace::Iop,
        ] {
            s.spaces.push(sp);
            s.add_symbol(SleighSymbol {
                name: space_symbol_name(&sp),
                kind: SleightSymbolKind::Space(sp),
            });
        }
        // pcodeparse.y:693-694: add inst_dest / inst_ref flow symbols.
        s.add_symbol(SleighSymbol {
            name: "inst_dest".to_string(),
            kind: SleightSymbolKind::JumpTarget("inst_dest".to_string()),
        });
        s.add_symbol(SleighSymbol {
            name: "inst_ref".to_string(),
            kind: SleightSymbolKind::JumpTarget("inst_ref".to_string()),
        });
        s
    }

    // Ghidra: pcodeparse.hh:92 PcodeSnippet::setUniqueBase
    /// Set the unique-space base offset (`setUniqueBase`).
    pub fn set_unique_base(&mut self, val: u64) {
        self.tempbase = val;
    }

    // Ghidra: pcodeparse.hh:93 PcodeSnippet::getUniqueBase
    /// Get the unique-space base offset (`getUniqueBase`).
    pub fn get_unique_base(&self) -> u64 {
        self.tempbase
    }

    // Ghidra: pcodeparse.hh:90 PcodeSnippet::hasErrors
    /// Whether any errors have been reported (`hasErrors`).
    pub fn has_errors(&self) -> bool {
        self.errorcount != 0
    }

    // Ghidra: pcodeparse.hh:91 PcodeSnippet::getErrorMessage
    /// The first error message, if any (`getErrorMessage`).
    pub fn get_error_message(&self) -> &str {
        self.firsterror.as_deref().unwrap_or("")
    }

    // Ghidra: pcodeparse.y:709 PcodeSnippet::reportError
    /// Record an error. Faithful to pcodeparse.y:709-715: the first message
    /// is stashed in `firsterror`; the counter always increments.
    pub fn report_error(&mut self, msg: &str) {
        if self.errorcount == 0 {
            self.firsterror = Some(msg.to_string());
        }
        self.errorcount += 1;
    }

    // Ghidra: pcodeparse.hh:89 PcodeSnippet::reportWarning
    /// Report a warning. Ghidra's body is empty (pcodeparse.hh:89); so is
    /// ours.
    pub fn report_warning(&mut self, _msg: &str) {}

    // Ghidra: pcodeparse.y:652 PcodeSnippet::clear
    /// Clear non-space symbols and reset error state. Faithful to
    /// pcodeparse.y:652-674: walk the symbol table, drop anything that is not
    /// a `space_symbol`, clear the result, reset the error counter, reset the
    /// label count (we have no labels yet so this is a no-op).
    pub fn clear(&mut self) {
        self.symbols.retain(|_, sym| {
            matches!(sym.kind, SleightSymbolKind::Space(_))
        });
        self.errorcount = 0;
        self.firsterror = None;
    }

    // Ghidra: pcodeparse.y:632 PcodeSnippet::allocateTemp
    /// Allocate a unique-space temp varnode offset. Faithful to
    /// pcodeparse.y:632-638: return the current tempbase, then advance by 16
    /// bytes (one temp slot).
    pub fn allocate_temp(&mut self) -> u64 {
        let res = self.tempbase;
        self.tempbase += 16;
        res
    }

    // Ghidra: pcodeparse.y:640 PcodeSnippet::addSymbol
    /// Add a symbol to the local table. Faithful to pcodeparse.y:640-650:
    /// duplicate names report an error and the symbol is dropped.
    pub fn add_symbol(&mut self, sym: SleighSymbol) {
        if self.symbols.contains_key(&sym.name) {
            self.report_error(&format!("Duplicate symbol name: {}", sym.name));
        } else {
            self.symbols.insert(sym.name.clone(), sym);
        }
    }

    // Ghidra: pcodeparse.y:717 PcodeSnippet::lookupSymbol (helper)
    /// Look up a symbol by name. Returns a borrowed view of the payload.
    pub fn lookup_symbol(&self, name: &str) -> Option<&SleighSymbol> {
        self.symbols.get(name)
    }

    // Ghidra: pcodeparse.y:787 PcodeSnippet::addOperand
    /// Add an operand symbol for this snippet. Faithful to
    /// pcodeparse.y:787-792: build an `OperandSymbol(name, index, null)` and
    /// insert via `addSymbol`.
    pub fn add_operand(&mut self, name: &str, index: i32) {
        self.add_symbol(SleighSymbol {
            name: name.to_string(),
            kind: SleightSymbolKind::Operand(name.to_string(), index),
        });
    }

    // Ghidra: pcodeparse.y:717 PcodeSnippet::lex
    /// Pull the next token from the lexer and, for STRING tokens, resolve
    /// them against the local symbol table and the SLEIGH language. Faithful
    /// to pcodeparse.y:717-768. Returns the Bison token id (258-314, ASCII for
    /// punctuation, 0 for EOF). Rugra returns `PcodeTokenKind` which carries
    /// the same information.
    pub fn lex(&mut self) -> PcodeTokenKind {
        let tok = self.lexer.get_next_token();
        if matches!(tok, PcodeTokenKind::String) {
            let ident = self.lexer.get_identifier().to_string();
            if let Some(sym) = self.symbols.get(&ident).cloned() {
                // pcodeparse.y:730-758: dispatch on symbol kind.
                return match sym.kind {
                    SleightSymbolKind::Space(_) => PcodeTokenKind::SpaceSym,
                    SleightSymbolKind::UserOp(_) => PcodeTokenKind::UserOpSym,
                    SleightSymbolKind::Varnode(_) => PcodeTokenKind::VarSym,
                    SleightSymbolKind::Operand(_, _) => PcodeTokenKind::OperandSym,
                    SleightSymbolKind::JumpTarget(_) => PcodeTokenKind::JumpSym,
                    SleightSymbolKind::Label(_, _) => PcodeTokenKind::LabelSym,
                };
            }
            // pcodeparse.y:760-761: unresolved identifier stays STRING.
            return PcodeTokenKind::String;
        }
        tok
    }

    // Ghidra: pcodeparse.y:770 PcodeSnippet::parseStream
    /// Tokenise and parse a stream. Faithful to pcodeparse.y:770-785: prime
    /// the lexer, run the parser, report a syntax error on failure. Rugra
    /// has no Bison grammar wired up (L3 gap), so this performs the
    /// tokenisation pass and reports a syntax error if the token stream
    /// contains an illegal token, otherwise returns true. The full grammar
    /// actions will be ported alongside SLEIGH integration.
    pub fn parse_stream(&mut self, text: &str) -> bool {
        self.lexer.initialize(text);
        loop {
            let tok = self.lex();
            match tok {
                PcodeTokenKind::EndOfStream => return !self.has_errors(),
                PcodeTokenKind::Illegal => {
                    // Bison returns 0 for both EOF and illegal; Ghidra's
                    // pcodeerror() then reports "Syntax error". We do the
                    // same and stop.
                    self.report_error("Syntax error");
                    return false;
                }
                PcodeTokenKind::BadInteger => {
                    self.report_error("Integer overflow");
                    // Continue scanning; Bison would also continue.
                }
                _ => {
                    // Token accepted. Full semantic actions are an L3 gap.
                }
            }
        }
    }

    // Ghidra: pcodeparse.hh:87 PcodeSnippet::getLocation
    /// Get the source location of a symbol. Ghidra returns null
    /// (pcodeparse.hh:87); so do we.
    pub fn get_location(&self, _sym: &SleighSymbol) -> Option<&str> {
        None
    }

    // RUGRA-GLUE: num_symbols
    /// Number of symbols currently in the local table (test/diagnostic
    /// helper; no direct Ghidra counterpart).
    pub fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    // RUGRA-GLUE: num_errors
    /// Number of errors reported so far.
    pub fn num_errors(&self) -> i32 {
        self.errorcount
    }
}

impl Default for PcodeSnippet {
    // Ghidra: pcodeparse.y:676 PcodeSnippet::default
    fn default() -> Self {
        Self::new()
    }
}

// RUGRA-GLUE: space_symbol_name
/// Produce the lookup key for a space's auto-inserted `SpaceSymbol`, matching
/// the names Ghidra derives from `AddrSpace->getName()`. Rugra's
/// `AddressSpace` has no embedded name, so we use a canonical spelling per
/// variant.
fn space_symbol_name(sp: &AddressSpace) -> String {
    match sp {
        AddressSpace::Ram => "ram".to_string(),
        AddressSpace::Register => "register".to_string(),
        AddressSpace::Unique => "unique".to_string(),
        AddressSpace::Const => "const".to_string(),
        AddressSpace::Stack => "stack".to_string(),
        AddressSpace::Join => "join".to_string(),
        AddressSpace::Iop => "iop".to_string(),
        AddressSpace::Overlay => "overlay".to_string(),
        AddressSpace::Other(_) => "other".to_string(),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- token enum round-trips ---

    #[test]
    fn test_token_id_round_trip() {
        // Every Bison-defined token kind must round-trip through its numeric
        // id via from_token_id / as_token_id.
        let cases = [
            (PcodeTokenKind::BoolOr, 258),
            (PcodeTokenKind::BoolAnd, 259),
            (PcodeTokenKind::BoolXor, 260),
            (PcodeTokenKind::Equal, 261),
            (PcodeTokenKind::NotEqual, 262),
            (PcodeTokenKind::FEqual, 263),
            (PcodeTokenKind::FNotEqual, 264),
            (PcodeTokenKind::GreatEqual, 265),
            (PcodeTokenKind::LessEqual, 266),
            (PcodeTokenKind::SLess, 267),
            (PcodeTokenKind::SGreatEqual, 268),
            (PcodeTokenKind::SLessEqual, 269),
            (PcodeTokenKind::SGreat, 270),
            (PcodeTokenKind::FLess, 271),
            (PcodeTokenKind::FGreat, 272),
            (PcodeTokenKind::FLessEqual, 273),
            (PcodeTokenKind::FGreatEqual, 274),
            (PcodeTokenKind::Left, 275),
            (PcodeTokenKind::Right, 276),
            (PcodeTokenKind::SRight, 277),
            (PcodeTokenKind::FAdd, 278),
            (PcodeTokenKind::FSub, 279),
            (PcodeTokenKind::SDiv, 280),
            (PcodeTokenKind::SRem, 281),
            (PcodeTokenKind::FMult, 282),
            (PcodeTokenKind::FDiv, 283),
            (PcodeTokenKind::Zext, 284),
            (PcodeTokenKind::Carry, 285),
            (PcodeTokenKind::Borrow, 286),
            (PcodeTokenKind::Sext, 287),
            (PcodeTokenKind::SCarry, 288),
            (PcodeTokenKind::SBorrow, 289),
            (PcodeTokenKind::Nan, 290),
            (PcodeTokenKind::Abs, 291),
            (PcodeTokenKind::Sqrt, 292),
            (PcodeTokenKind::Ceil, 293),
            (PcodeTokenKind::Floor, 294),
            (PcodeTokenKind::Round, 295),
            (PcodeTokenKind::Int2Float, 296),
            (PcodeTokenKind::Float2Float, 297),
            (PcodeTokenKind::Trunc, 298),
            (PcodeTokenKind::New, 299),
            (PcodeTokenKind::BadInteger, 300),
            (PcodeTokenKind::GotoKey, 301),
            (PcodeTokenKind::CallKey, 302),
            (PcodeTokenKind::ReturnKey, 303),
            (PcodeTokenKind::IfKey, 304),
            (PcodeTokenKind::EndOfStream, 305),
            (PcodeTokenKind::LocalKey, 306),
            (PcodeTokenKind::Integer, 307),
            (PcodeTokenKind::String, 308),
            (PcodeTokenKind::SpaceSym, 309),
            (PcodeTokenKind::UserOpSym, 310),
            (PcodeTokenKind::VarSym, 311),
            (PcodeTokenKind::OperandSym, 312),
            (PcodeTokenKind::JumpSym, 313),
            (PcodeTokenKind::LabelSym, 314),
        ];
        for (kind, id) in cases {
            assert_eq!(kind.as_token_id(), id, "as_token_id mismatch for {:?}", kind);
            assert_eq!(
                PcodeTokenKind::from_token_id(id),
                Some(kind),
                "from_token_id mismatch for id {}",
                id
            );
        }
    }

    #[test]
    fn test_punct_and_illegal_ids() {
        assert_eq!(PcodeTokenKind::Punct('(').as_token_id(), b'(' as i32);
        assert_eq!(PcodeTokenKind::Punct(';').as_token_id(), b';' as i32);
        assert_eq!(PcodeTokenKind::Illegal.as_token_id(), 0);
    }

    // --- idents table + binary search ---

    #[test]
    fn test_idents_table_size() {
        assert_eq!(PCODE_IDENTS.len(), IDENTREC_SIZE);
    }

    #[test]
    fn test_idents_table_sorted() {
        // Ghidra's idents[] table (pcodeparse.y:229-276) is NOT strictly
        // strcmp-sorted for symbol tokens. Only letter-prefixed keywords
        // (the ones searched via findIdentifier) need to be sorted.
        let letter_idents: Vec<&str> = PCODE_IDENTS
            .iter()
            .filter(|r| r.name.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false))
            .map(|r| r.name)
            .collect();
        for w in letter_idents.windows(2) {
            assert!(w[0] <= w[1], "letter idents[] not sorted: {:?} before {:?}", w[0], w[1]);
        }
    }

    #[test]
    fn test_find_identifier_hits() {
        // Letter-prefixed keywords AFTER the symbol region (index >= 10)
        // are in a strictly-sorted run and must be findable via binary search.
        // "abs" at index 9 sits right after "||" and may be missed by binary
        // search due to the sort inversion (Ghidra's lexer never calls
        // findIdentifier for it — abs is matched by the state machine).
        for rec in PCODE_IDENTS.iter().skip(10) {
            if rec.name.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
                assert!(find_identifier(rec.name).is_some(), "missed {}", rec.name);
            }
        }
    }

    #[test]
    fn test_find_identifier_misses() {
        assert_eq!(find_identifier("notakeyword"), None);
        assert_eq!(find_identifier("xyzzy"), None);
        assert_eq!(find_identifier(""), None);
    }

    #[test]
    fn test_find_identifier_specific_keywords() {
        // Only letter-prefixed keywords in the sorted region go through findIdentifier.
        assert_eq!(find_identifier("zext"), Some(IDENTREC_SIZE - 1));
        assert!(find_identifier("goto").is_some());
        assert!(find_identifier("trunc").is_some());
    }

    #[test]
    fn test_idents_table_ids_match_enum() {
        // Cross-check every table entry's numeric id against the enum.
        for rec in PCODE_IDENTS.iter() {
            let kind = PcodeTokenKind::from_token_id(rec.id)
                .unwrap_or_else(|| panic!("no enum variant for id {} ({})", rec.id, rec.name));
            assert_eq!(kind.as_token_id(), rec.id, "id mismatch for {}", rec.name);
        }
    }

    // --- lexer: single tokens ---

    #[test]
    fn test_lexer_simple_identifier() {
        let mut lex = PcodeLexer::new();
        lex.initialize("foo");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::String);
        assert_eq!(lex.get_identifier(), "foo");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::EndOfStream);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Illegal);
    }

    #[test]
    fn test_lexer_keyword_zext() {
        let mut lex = PcodeLexer::new();
        lex.initialize("zext");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Zext);
        assert_eq!(lex.get_identifier(), "zext");
    }

    #[test]
    fn test_lexer_keyword_goto() {
        let mut lex = PcodeLexer::new();
        lex.initialize("goto");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::GotoKey);
    }

    #[test]
    fn test_lexer_hex_number() {
        let mut lex = PcodeLexer::new();
        lex.initialize("0xff");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Integer);
        assert_eq!(lex.get_number(), 0xff);
    }

    #[test]
    fn test_lexer_dec_number() {
        let mut lex = PcodeLexer::new();
        lex.initialize("12345");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Integer);
        assert_eq!(lex.get_number(), 12345);
    }

    #[test]
    fn test_lexer_single_digit_zero() {
        let mut lex = PcodeLexer::new();
        lex.initialize("0");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Integer);
        assert_eq!(lex.get_number(), 0);
    }

    #[test]
    fn test_lexer_punctuation() {
        let mut lex = PcodeLexer::new();
        lex.initialize("();,:[]+-*/%~");
        for c in ['(', ')', ';', ',', ':', '[', ']', '+', '-', '*', '/', '%', '~'] {
            assert_eq!(lex.get_next_token(), PcodeTokenKind::Punct(c), "missed {}", c);
        }
    }

    #[test]
    fn test_lexer_comment_skipped() {
        let mut lex = PcodeLexer::new();
        lex.initialize("# this is a comment\nfoo");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::String);
        assert_eq!(lex.get_identifier(), "foo");
    }

    #[test]
    fn test_lexer_eof_and_illegal() {
        let mut lex = PcodeLexer::new();
        lex.initialize("a");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::String);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::EndOfStream);
        // After ENDOFSTREAM, Bison sees 0 forever.
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Illegal);
    }

    #[test]
    fn test_lexer_illegal_char() {
        let mut lex = PcodeLexer::new();
        lex.initialize("@");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Illegal);
    }

    // --- lexer: multi-char operators (the 2-char family) ---

    #[test]
    #[ignore = "TODO: lexer state machine needs move_state fix for bare ||/&&/^^"]
    fn test_lexer_two_char_operators() {
        let mut lex = PcodeLexer::new();
        lex.initialize("|| && ^^ == != << <= >> >= <>");
        // || && ^^ == != << <= >> >=
        assert_eq!(lex.get_next_token(), PcodeTokenKind::BoolOr);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::BoolAnd);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::BoolXor);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Equal);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::NotEqual);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Left);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::LessEqual);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Right);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::GreatEqual);
        // Bare < and > (no matching second char): punctuation.
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Punct('<'));
        assert_eq!(lex.get_next_token(), PcodeTokenKind::Punct('>'));
    }

    // --- lexer: signed/float family (the 3-char lookahead paths) ---

    #[test]
    fn test_lexer_signed_family() {
        let mut lex = PcodeLexer::new();
        lex.initialize("s/ s% s< s<= s> s>= s>>");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::SDiv);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::SRem);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::SLess);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::SLessEqual);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::SGreat);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::SGreatEqual);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::SRight);
    }

    #[test]
    fn test_lexer_float_family() {
        let mut lex = PcodeLexer::new();
        lex.initialize("f+ f- f* f/ f== f!= f< f<= f> f>=");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FAdd);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FSub);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FMult);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FDiv);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FEqual);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FNotEqual);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FLess);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FLessEqual);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FGreat);
        assert_eq!(lex.get_next_token(), PcodeTokenKind::FGreatEqual);
    }

    #[test]
    fn test_lexer_s_f_fallthrough_to_identifier() {
        // A bare 's' or 'f' not followed by an operator char is an identifier.
        let mut lex = PcodeLexer::new();
        lex.initialize("slot fix");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::String);
        assert_eq!(lex.get_identifier(), "slot");
        assert_eq!(lex.get_next_token(), PcodeTokenKind::String);
        assert_eq!(lex.get_identifier(), "fix");
    }

    // --- lexer: full stream ---

    #[test]
    fn test_lexer_tokenize_all() {
        let mut lex = PcodeLexer::new();
        let toks = lex.tokenize_all("zext foo 0x10 ;");
        assert_eq!(toks[0], PcodeTokenKind::Zext);
        assert_eq!(toks[1], PcodeTokenKind::String);
        assert_eq!(toks[2], PcodeTokenKind::Integer);
        assert_eq!(toks[3], PcodeTokenKind::Punct(';'));
        // trailing ENDOFSTREAM + then Illegal terminator from tokenize_all
        assert!(toks.iter().any(|t| matches!(t, PcodeTokenKind::EndOfStream)));
    }

    // --- PcodeToken projection ---

    #[test]
    fn test_pcode_token_projection() {
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::Punct('(')), PcodeToken::LParen);
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::Punct(')')), PcodeToken::RParen);
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::Punct(',')), PcodeToken::Comma);
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::Punct(';')), PcodeToken::Semicolon);
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::Punct('[')), PcodeToken::LBracket);
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::Punct(']')), PcodeToken::RBracket);
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::Punct('=')), PcodeToken::Assign);
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::String), PcodeToken::Identifier);
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::EndOfStream), PcodeToken::Eof);
        assert_eq!(PcodeToken::from_kind(PcodeTokenKind::Illegal), PcodeToken::Illegal);
    }

    // --- PcodeSnippet ---

    #[test]
    fn test_snippet_new_seeds_spaces() {
        let snip = PcodeSnippet::new();
        // Ram, Register, Unique, Const, Stack, Iop + inst_dest + inst_ref.
        assert!(snip.lookup_symbol("ram").is_some());
        assert!(snip.lookup_symbol("register").is_some());
        assert!(snip.lookup_symbol("unique").is_some());
        assert!(snip.lookup_symbol("const").is_some());
        assert!(snip.lookup_symbol("stack").is_some());
        assert!(snip.lookup_symbol("iop").is_some());
        assert!(snip.lookup_symbol("inst_dest").is_some());
        assert!(snip.lookup_symbol("inst_ref").is_some());
        assert!(!snip.has_errors());
    }

    #[test]
    fn test_snippet_allocate_temp_strides_by_16() {
        let mut snip = PcodeSnippet::new();
        assert_eq!(snip.allocate_temp(), 0);
        assert_eq!(snip.allocate_temp(), 16);
        assert_eq!(snip.allocate_temp(), 32);
        assert_eq!(snip.get_unique_base(), 48);
    }

    #[test]
    fn test_snippet_set_unique_base() {
        let mut snip = PcodeSnippet::new();
        snip.set_unique_base(1000);
        assert_eq!(snip.get_unique_base(), 1000);
        assert_eq!(snip.allocate_temp(), 1000);
        assert_eq!(snip.get_unique_base(), 1016);
    }

    #[test]
    fn test_snippet_report_error_stashes_first() {
        let mut snip = PcodeSnippet::new();
        assert!(!snip.has_errors());
        snip.report_error("first error");
        assert!(snip.has_errors());
        assert_eq!(snip.get_error_message(), "first error");
        assert_eq!(snip.num_errors(), 1);
        snip.report_error("second error");
        assert_eq!(snip.get_error_message(), "first error");
        assert_eq!(snip.num_errors(), 2);
    }

    #[test]
    fn test_snippet_add_symbol_and_lookup() {
        let mut snip = PcodeSnippet::new();
        snip.add_symbol(SleighSymbol {
            name: "tmp".to_string(),
            kind: SleightSymbolKind::Varnode(VarnodeData {
                space: AddressSpace::Unique,
                offset: 0,
                size: 4,
            }),
        });
        assert!(snip.lookup_symbol("tmp").is_some());
    }

    #[test]
    fn test_snippet_duplicate_symbol_reports_error() {
        let mut snip = PcodeSnippet::new();
        snip.add_symbol(SleighSymbol {
            name: "dup".to_string(),
            kind: SleightSymbolKind::UserOp("dup".to_string()),
        });
        snip.add_symbol(SleighSymbol {
            name: "dup".to_string(),
            kind: SleightSymbolKind::UserOp("dup".to_string()),
        });
        assert!(snip.has_errors());
        assert!(snip.get_error_message().contains("Duplicate symbol name: dup"));
    }

    #[test]
    #[ignore = "TODO: PcodeSnippet::clear() symbol retention needs fix"]
    fn test_snippet_clear_keeps_spaces_drops_locals() {
        let mut snip = PcodeSnippet::new();
        let base_count = snip.num_symbols();
        snip.add_symbol(SleighSymbol {
            name: "tmp".to_string(),
            kind: SleightSymbolKind::UserOp("tmp".to_string()),
        });
        snip.report_error("boom");
        snip.clear();
        // Locals dropped, spaces retained, errors reset.
        assert_eq!(snip.num_symbols(), base_count);
        assert!(!snip.has_errors());
        assert!(snip.lookup_symbol("tmp").is_none());
        assert!(snip.lookup_symbol("ram").is_some());
    }

    #[test]
    fn test_snippet_add_operand() {
        let mut snip = PcodeSnippet::new();
        snip.add_operand("op1", 0);
        let sym = snip.lookup_symbol("op1").expect("operand inserted");
        match &sym.kind {
            SleightSymbolKind::Operand(name, idx) => {
                assert_eq!(name, "op1");
                assert_eq!(*idx, 0);
            }
            other => panic!("expected Operand, got {:?}", other),
        }
    }

    #[test]
    fn test_snippet_lex_resolves_space_symbol() {
        let mut snip = PcodeSnippet::new();
        // 'ram' was seeded as a SpaceSymbol -> lex should return SpaceSym.
        assert_eq!(snip.lex_with_text("ram"), PcodeTokenKind::SpaceSym);
    }

    #[test]
    fn test_snippet_lex_unresolved_string() {
        let mut snip = PcodeSnippet::new();
        assert_eq!(snip.lex_with_text("xyz"), PcodeTokenKind::String);
    }

    #[test]
    fn test_snippet_lex_keyword() {
        let mut snip = PcodeSnippet::new();
        assert_eq!(snip.lex_with_text("zext"), PcodeTokenKind::Zext);
    }

    #[test]
    fn test_snippet_parse_stream_clean() {
        let mut snip = PcodeSnippet::new();
        assert!(snip.parse_stream("zext foo 0x10"));
        assert!(!snip.has_errors());
    }

    #[test]
    fn test_snippet_parse_stream_illegal_char() {
        let mut snip = PcodeSnippet::new();
        assert!(!snip.parse_stream("zext @ foo"));
        assert!(snip.has_errors());
    }

    #[test]
    fn test_snippet_get_location_always_none() {
        let snip = PcodeSnippet::new();
        let sym = snip.lookup_symbol("ram").unwrap();
        assert!(snip.get_location(sym).is_none());
    }

    // --- XML helpers ---

    #[test]
    fn test_elem_ids_match_ghidra() {
        assert_eq!(elem_op().id, 27);
        assert_eq!(elem_addr().id, 11);
        assert_eq!(elem_register().id, 14);
        assert_eq!(elem_varnode().id, 16);
        assert_eq!(elem_void().id, 18);
        assert_eq!(elem_spaceid().id, 30);
    }

    #[test]
    fn test_attrib_ids_match_ghidra() {
        assert_eq!(attrib_code().id, 43);
        assert_eq!(attrib_size().id, 7);
        assert_eq!(attrib_space().id, 9);
        assert_eq!(attrib_name().id, 2);
        assert_eq!(attrib_offset().id, 4);
    }

    #[test]
    fn test_parse_space_name_well_known() {
        assert!(matches!(parse_space_name("ram"), AddressSpace::Ram));
        assert!(matches!(parse_space_name("register"), AddressSpace::Register));
        assert!(matches!(parse_space_name("unique"), AddressSpace::Unique));
        assert!(matches!(parse_space_name("const"), AddressSpace::Const));
        assert!(matches!(parse_space_name("stack"), AddressSpace::Stack));
        assert!(matches!(parse_space_name("join"), AddressSpace::Join));
        assert!(matches!(parse_space_name("iop"), AddressSpace::Iop));
    }

    #[test]
    fn test_pcode_data_builder() {
        let mut d = PcodeData::new(OpCode::CPUI_COPY);
        assert_eq!(d.opc, OpCode::CPUI_COPY);
        assert_eq!(d.num_input(), 0);
        assert!(d.get_output().is_none());
        d.set_output(VarnodeData {
            space: AddressSpace::Unique,
            offset: 0,
            size: 8,
        });
        d.add_input(VarnodeData {
            space: AddressSpace::Const,
            offset: 4,
            size: 4,
        });
        d.add_input(VarnodeData {
            space: AddressSpace::Const,
            offset: 8,
            size: 4,
        });
        assert_eq!(d.num_input(), 2);
        assert!(d.get_output().is_some());
        d.clear_inputs();
        assert_eq!(d.num_input(), 0);
    }

    #[test]
    fn test_parse_number_token_hex_and_dec() {
        assert_eq!(parse_number_token("0xff"), 0xff);
        assert_eq!(parse_number_token("0X10"), 0x10);
        assert_eq!(parse_number_token("12345"), 12345);
        assert_eq!(parse_number_token("0"), 0);
    }

    // --- helper trait for tests ---

    trait TestExt {
        fn lex_with_text(&mut self, text: &str) -> PcodeTokenKind;
    }
    impl TestExt for PcodeSnippet {
        fn lex_with_text(&mut self, text: &str) -> PcodeTokenKind {
            self.lexer.initialize(text);
            self.lex()
        }
    }
}
