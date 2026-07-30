//! Tokenizer for the Firebase Security Rules language.
//!
//! Path literals (`/users/$(uid)` in expression position) are handled by the
//! parser calling back into `lex_path_segment` — `/` is ambiguous with
//! division and only the parser knows which position it's in.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    Float(f64),
    // punctuation / operators
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Semi,
    Colon,
    Question,
    Dot,
    Slash,
    Star,
    Percent,
    Plus,
    Minus,
    Eq,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    Not,
    Assign,
    Eof,
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tok::Ident(s) => write!(f, "{s}"),
            Tok::Str(_) => write!(f, "string literal"),
            Tok::Int(i) => write!(f, "{i}"),
            Tok::Float(x) => write!(f, "{x}"),
            other => write!(f, "{other:?}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub line: u32,
    pub col: u32,
    /// Byte offset in source — used by the parser for path-literal lexing.
    pub offset: usize,
}

#[derive(Debug, Clone)]
pub struct LexError {
    pub message: String,
    pub line: u32,
    pub col: u32,
}

pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    col: u32,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self { src: src.as_bytes(), pos: 0, line: 1, col: 1 }
    }

    fn bump(&mut self) -> u8 {
        let b = self.src[self.pos];
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        b
    }

    fn peek(&self) -> u8 {
        *self.src.get(self.pos).unwrap_or(&0)
    }
    fn peek2(&self) -> u8 {
        *self.src.get(self.pos + 1).unwrap_or(&0)
    }

    fn err(&self, message: impl Into<String>) -> LexError {
        LexError { message: message.into(), line: self.line, col: self.col }
    }

    fn skip_trivia(&mut self) -> Result<(), LexError> {
        loop {
            match self.peek() {
                b' ' | b'\t' | b'\r' | b'\n' => {
                    self.bump();
                }
                b'/' if self.peek2() == b'/' => {
                    while self.pos < self.src.len() && self.peek() != b'\n' {
                        self.bump();
                    }
                }
                b'/' if self.peek2() == b'*' => {
                    self.bump();
                    self.bump();
                    loop {
                        if self.pos >= self.src.len() {
                            return Err(self.err("unterminated block comment"));
                        }
                        if self.peek() == b'*' && self.peek2() == b'/' {
                            self.bump();
                            self.bump();
                            break;
                        }
                        self.bump();
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    pub fn tokenize(mut self) -> Result<Vec<Token>, LexError> {
        let mut out = Vec::new();
        loop {
            self.skip_trivia()?;
            let (line, col, offset) = (self.line, self.col, self.pos);
            if self.pos >= self.src.len() {
                out.push(Token { tok: Tok::Eof, line, col, offset });
                return Ok(out);
            }
            let tok = self.next_token()?;
            out.push(Token { tok, line, col, offset });
        }
    }

    fn next_token(&mut self) -> Result<Tok, LexError> {
        let b = self.bump();
        Ok(match b {
            b'(' => Tok::LParen,
            b')' => Tok::RParen,
            b'{' => Tok::LBrace,
            b'}' => Tok::RBrace,
            b'[' => Tok::LBracket,
            b']' => Tok::RBracket,
            b',' => Tok::Comma,
            b';' => Tok::Semi,
            b':' => Tok::Colon,
            b'?' => Tok::Question,
            b'.' => Tok::Dot,
            b'/' => Tok::Slash,
            b'*' => Tok::Star,
            b'%' => Tok::Percent,
            b'+' => Tok::Plus,
            b'-' => Tok::Minus,
            b'=' => {
                if self.peek() == b'=' {
                    self.bump();
                    Tok::EqEq
                } else {
                    Tok::Assign
                }
            }
            b'!' => {
                if self.peek() == b'=' {
                    self.bump();
                    Tok::NotEq
                } else {
                    Tok::Not
                }
            }
            b'<' => {
                if self.peek() == b'=' {
                    self.bump();
                    Tok::Le
                } else {
                    Tok::Lt
                }
            }
            b'>' => {
                if self.peek() == b'=' {
                    self.bump();
                    Tok::Ge
                } else {
                    Tok::Gt
                }
            }
            b'&' => {
                if self.peek() == b'&' {
                    self.bump();
                    Tok::AndAnd
                } else {
                    return Err(self.err("expected '&&'"));
                }
            }
            b'|' => {
                if self.peek() == b'|' {
                    self.bump();
                    Tok::OrOr
                } else {
                    return Err(self.err("expected '||'"));
                }
            }
            b'\'' | b'"' => self.string(b)?,
            b'0'..=b'9' => self.number(b)?,
            b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'$' => self.ident(b),
            other => return Err(self.err(format!("unexpected character {:?}", other as char))),
        })
    }

    fn string(&mut self, quote: u8) -> Result<Tok, LexError> {
        let mut out = String::new();
        loop {
            if self.pos >= self.src.len() {
                return Err(self.err("unterminated string"));
            }
            let b = self.bump();
            if b == quote {
                return Ok(Tok::Str(out));
            }
            if b == b'\\' {
                let e = self.bump();
                match e {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'\\' => out.push('\\'),
                    b'\'' => out.push('\''),
                    b'"' => out.push('"'),
                    b'/' => out.push('/'),
                    b'u' => {
                        let mut code = 0u32;
                        for _ in 0..4 {
                            let h = self.bump();
                            code = code * 16
                                + (h as char)
                                    .to_digit(16)
                                    .ok_or_else(|| self.err("invalid \\u escape"))?;
                        }
                        out.push(
                            char::from_u32(code).ok_or_else(|| self.err("invalid \\u escape"))?,
                        );
                    }
                    other => {
                        return Err(self.err(format!("invalid escape \\{}", other as char)));
                    }
                }
            } else {
                // Collect the full UTF-8 sequence.
                let start = self.pos - 1;
                let len = utf8_len(b);
                for _ in 1..len {
                    self.bump();
                }
                out.push_str(
                    std::str::from_utf8(&self.src[start..start + len])
                        .map_err(|_| self.err("invalid UTF-8"))?,
                );
            }
        }
    }

    fn number(&mut self, first: u8) -> Result<Tok, LexError> {
        let mut text = String::new();
        text.push(first as char);
        while self.peek().is_ascii_digit() {
            text.push(self.bump() as char);
        }
        // A float needs `digit . digit`; a bare `1.foo` is member access.
        if self.peek() == b'.' && self.peek2().is_ascii_digit() {
            text.push(self.bump() as char);
            while self.peek().is_ascii_digit() {
                text.push(self.bump() as char);
            }
            return Ok(Tok::Float(text.parse().map_err(|_| self.err("invalid float literal"))?));
        }
        match text.parse::<i64>() {
            Ok(i) => Ok(Tok::Int(i)),
            Err(_) => Err(self.err("integer literal out of range")),
        }
    }

    fn ident(&mut self, first: u8) -> Tok {
        let mut out = String::new();
        out.push(first as char);
        while matches!(self.peek(), b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'$') {
            out.push(self.bump() as char);
        }
        Tok::Ident(out)
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}
