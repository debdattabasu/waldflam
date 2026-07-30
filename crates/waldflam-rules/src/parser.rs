//! Recursive-descent parser: structural grammar (service/match/allow/
//! function) + Pratt expressions with CEL precedence, + the path-literal
//! scanner (paths re-lex raw source and resync by byte offset).

use crate::ast::*;
use crate::lexer::{Lexer, Tok, Token};

#[derive(Debug, Clone)]
pub struct Issue {
    pub message: String,
    pub line: u32,
    pub col: u32,
}

const MAX_EXPR_DEPTH: u32 = 100;
const MAX_MATCH_DEPTH: u32 = 10;

pub fn parse(source: &str) -> Result<Ruleset, Issue> {
    let tokens = Lexer::new(source)
        .tokenize()
        .map_err(|e| Issue { message: e.message, line: e.line, col: e.col })?;
    let mut parser = Parser { source, tokens, pos: 0, depth: 0 };
    parser.ruleset()
}

struct Parser<'a> {
    source: &'a str,
    tokens: Vec<Token>,
    pos: usize,
    depth: u32,
}

impl<'a> Parser<'a> {
    fn cur(&self) -> &Token {
        &self.tokens[self.pos.min(self.tokens.len() - 1)]
    }

    fn err(&self, message: impl Into<String>) -> Issue {
        let t = self.cur();
        Issue { message: message.into(), line: t.line, col: t.col }
    }

    fn bump(&mut self) -> Token {
        let t = self.cur().clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, tok: &Tok) -> bool {
        if &self.cur().tok == tok {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, tok: &Tok) -> Result<(), Issue> {
        if self.eat(tok) {
            Ok(())
        } else {
            Err(self.err(format!("expected {tok}, found {}", self.cur().tok)))
        }
    }

    fn eat_ident(&mut self, kw: &str) -> bool {
        if matches!(&self.cur().tok, Tok::Ident(s) if s == kw) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect_ident(&mut self) -> Result<String, Issue> {
        match self.cur().tok.clone() {
            Tok::Ident(s) => {
                self.bump();
                Ok(s)
            }
            other => Err(self.err(format!("expected identifier, found {other}"))),
        }
    }

    fn ruleset(&mut self) -> Result<Ruleset, Issue> {
        let mut version = Version::V1;
        if self.eat_ident("rules_version") {
            self.expect(&Tok::Assign)?;
            match self.bump().tok {
                Tok::Str(v) if v == "1" => version = Version::V1,
                Tok::Str(v) if v == "2" => version = Version::V2,
                _ => return Err(self.err("unsupported rules_version")),
            }
            self.expect(&Tok::Semi)?;
        }
        let mut services = Vec::new();
        while !matches!(self.cur().tok, Tok::Eof) {
            if !self.eat_ident("service") {
                return Err(self.err("expected 'service'"));
            }
            // Service name is dotted: cloud.firestore
            let mut name = self.expect_ident()?;
            while self.eat(&Tok::Dot) {
                name.push('.');
                name.push_str(&self.expect_ident()?);
            }
            self.expect(&Tok::LBrace)?;
            let mut functions = Vec::new();
            let mut matches = Vec::new();
            while !self.eat(&Tok::RBrace) {
                if matches!(&self.cur().tok, Tok::Ident(s) if s == "function") {
                    functions.push(self.function()?);
                } else if matches!(&self.cur().tok, Tok::Ident(s) if s == "match") {
                    matches.push(self.match_rule(version, 1)?);
                } else {
                    return Err(self.err("expected 'match' or 'function'"));
                }
            }
            services.push(Service { name, functions, matches });
        }
        Ok(Ruleset { version, services })
    }

    fn match_rule(&mut self, version: Version, depth: u32) -> Result<MatchRule, Issue> {
        if depth > MAX_MATCH_DEPTH {
            return Err(self.err("match statements nested too deeply"));
        }
        self.bump(); // 'match'
        let path = self.match_path(version)?;
        self.expect(&Tok::LBrace)?;
        let mut functions = Vec::new();
        let mut allows = Vec::new();
        let mut children = Vec::new();
        while !self.eat(&Tok::RBrace) {
            match &self.cur().tok {
                Tok::Ident(s) if s == "function" => functions.push(self.function()?),
                Tok::Ident(s) if s == "match" => {
                    children.push(self.match_rule(version, depth + 1)?)
                }
                Tok::Ident(s) if s == "allow" => allows.push(self.allow()?),
                _ => return Err(self.err("expected 'allow', 'match' or 'function'")),
            }
        }
        Ok(MatchRule { path, functions, allows, children })
    }

    fn match_path(&mut self, version: Version) -> Result<Vec<MatchSeg>, Issue> {
        let raw = self.scan_raw_path()?;
        let mut segments = Vec::new();
        let mut glob_seen = false;
        for (i, seg) in raw.iter().enumerate() {
            let parsed = if let Some(inner) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                if let Some(name) = inner.strip_suffix("=**") {
                    if glob_seen {
                        return Err(self.err("only one recursive wildcard is permitted"));
                    }
                    glob_seen = true;
                    if version == Version::V1 && i != raw.len() - 1 {
                        return Err(self.err(
                            "recursive wildcards must be the last path segment in rules_version 1",
                        ));
                    }
                    MatchSeg::Glob(name.to_owned())
                } else {
                    MatchSeg::Capture(inner.to_owned())
                }
            } else {
                MatchSeg::Literal(seg.clone())
            };
            segments.push(parsed);
        }
        if segments.is_empty() {
            return Err(self.err("empty match path"));
        }
        Ok(segments)
    }

    /// Scans a `/`-led path from raw source starting at the current token
    /// (which must be `/`), returning raw segment strings and resyncing the
    /// token cursor past the path.
    fn scan_raw_path(&mut self) -> Result<Vec<String>, Issue> {
        if self.cur().tok != Tok::Slash {
            return Err(self.err("expected '/'"));
        }
        let start = self.cur().offset;
        let bytes = self.source.as_bytes();
        let mut i = start;
        let mut depth = 0i32;
        while i < bytes.len() {
            let b = bytes[i];
            let stop = match b {
                b' ' | b'\t' | b'\r' | b'\n' | b',' | b';' => depth == 0,
                b'(' | b'{' => {
                    depth += 1;
                    false
                }
                b')' | b'}' => {
                    if depth == 0 {
                        true
                    } else {
                        depth -= 1;
                        false
                    }
                }
                b']' => depth == 0,
                _ => false,
            };
            if stop {
                break;
            }
            i += 1;
        }
        let text = &self.source[start..i];
        // Resync tokens past the scanned range.
        while self.cur().offset < i && self.cur().tok != Tok::Eof {
            self.bump();
        }
        let mut segments = Vec::new();
        for seg in text.split('/').skip(1) {
            if seg.is_empty() {
                return Err(self.err("empty path segment"));
            }
            segments.push(seg.to_owned());
        }
        Ok(segments)
    }

    /// Path literal in expression position: segments are static text or
    /// `$(expr)` splices (parsed recursively from the captured text).
    fn path_literal(&mut self) -> Result<Expr, Issue> {
        let (line, col) = (self.cur().line, self.cur().col);
        let raw = self.scan_raw_path()?;
        let mut parts = Vec::new();
        for seg in raw {
            if let Some(inner) = seg.strip_prefix("$(").and_then(|s| s.strip_suffix(')')) {
                let sub = parse_expression(inner).map_err(|mut e| {
                    e.line = line;
                    e.col = col;
                    e
                })?;
                parts.push(PathPart::Splice(Box::new(sub)));
            } else {
                parts.push(PathPart::Static(seg));
            }
        }
        Ok(Expr::Path(parts))
    }

    fn allow(&mut self) -> Result<Allow, Issue> {
        let line = self.cur().line;
        self.bump(); // 'allow'
        let mut methods = vec![self.expect_ident()?];
        while self.eat(&Tok::Comma) {
            methods.push(self.expect_ident()?);
        }
        for m in &methods {
            if !matches!(
                m.as_str(),
                "read" | "write" | "get" | "list" | "create" | "update" | "delete"
            ) {
                return Err(self.err(format!("unknown operation {m:?}")));
            }
        }
        let condition = if self.eat(&Tok::Colon) {
            if !self.eat_ident("if") {
                return Err(self.err("expected 'if'"));
            }
            self.expr(0)?
        } else {
            Expr::Bool(true)
        };
        self.expect(&Tok::Semi)?;
        Ok(Allow { methods, condition, line })
    }

    fn function(&mut self) -> Result<FunctionDecl, Issue> {
        self.bump(); // 'function'
        let name = self.expect_ident()?;
        self.expect(&Tok::LParen)?;
        let mut params = Vec::new();
        if !self.eat(&Tok::RParen) {
            loop {
                params.push(self.expect_ident()?);
                if !self.eat(&Tok::Comma) {
                    self.expect(&Tok::RParen)?;
                    break;
                }
            }
        }
        self.expect(&Tok::LBrace)?;
        let mut lets = Vec::new();
        while self.eat_ident("let") {
            let name = self.expect_ident()?;
            self.expect(&Tok::Assign)?;
            let value = self.expr(0)?;
            self.expect(&Tok::Semi)?;
            lets.push((name, value));
        }
        if !self.eat_ident("return") {
            return Err(self.err("expected 'return'"));
        }
        let body = self.expr(0)?;
        self.expect(&Tok::Semi)?;
        self.expect(&Tok::RBrace)?;
        Ok(FunctionDecl { name, params, lets, body })
    }

    // ---- expressions (Pratt) ----

    fn expr(&mut self, min_bp: u8) -> Result<Expr, Issue> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            return Err(self.err("expression too complex"));
        }
        let result = self.expr_inner(min_bp);
        self.depth -= 1;
        result
    }

    fn expr_inner(&mut self, min_bp: u8) -> Result<Expr, Issue> {
        let mut lhs = self.prefix()?;
        loop {
            let (op_bp, op) = match &self.cur().tok {
                Tok::Question => (1, None),
                Tok::OrOr => (2, Some(BinOp::Or)),
                Tok::AndAnd => (3, Some(BinOp::And)),
                Tok::EqEq => (4, Some(BinOp::Eq)),
                Tok::NotEq => (4, Some(BinOp::Ne)),
                Tok::Lt => (5, Some(BinOp::Lt)),
                Tok::Le => (5, Some(BinOp::Le)),
                Tok::Gt => (5, Some(BinOp::Gt)),
                Tok::Ge => (5, Some(BinOp::Ge)),
                Tok::Ident(s) if s == "in" => (5, Some(BinOp::In)),
                Tok::Ident(s) if s == "is" => (5, None),
                Tok::Plus => (6, Some(BinOp::Add)),
                Tok::Minus => (6, Some(BinOp::Sub)),
                Tok::Star => (7, Some(BinOp::Mul)),
                Tok::Slash => (7, Some(BinOp::Div)),
                Tok::Percent => (7, Some(BinOp::Mod)),
                _ => break,
            };
            if op_bp < min_bp {
                break;
            }
            match op {
                Some(binop) => {
                    self.bump();
                    let rhs = self.expr(op_bp + 1)?;
                    lhs = Expr::Binary(binop, Box::new(lhs), Box::new(rhs));
                }
                None if self.cur().tok == Tok::Question => {
                    self.bump();
                    let then = self.expr(0)?;
                    self.expect(&Tok::Colon)?;
                    let otherwise = self.expr(1)?;
                    lhs = Expr::Ternary(Box::new(lhs), Box::new(then), Box::new(otherwise));
                }
                None => {
                    // `is`
                    self.bump();
                    let ty = self.expect_ident()?;
                    lhs = Expr::Is(Box::new(lhs), ty);
                }
            }
        }
        Ok(lhs)
    }

    fn prefix(&mut self) -> Result<Expr, Issue> {
        let expr = match self.cur().tok.clone() {
            Tok::Not => {
                self.bump();
                let inner = self.expr(8)?;
                Expr::Unary(UnOp::Not, Box::new(inner))
            }
            Tok::Minus => {
                self.bump();
                let inner = self.expr(8)?;
                Expr::Unary(UnOp::Neg, Box::new(inner))
            }
            Tok::Slash => self.path_literal()?,
            Tok::Int(i) => {
                self.bump();
                Expr::Int(i)
            }
            Tok::Float(x) => {
                self.bump();
                Expr::Float(x)
            }
            Tok::Str(s) => {
                self.bump();
                Expr::Str(s)
            }
            Tok::LParen => {
                self.bump();
                let inner = self.expr(0)?;
                self.expect(&Tok::RParen)?;
                inner
            }
            Tok::LBracket => {
                self.bump();
                let mut items = Vec::new();
                if !self.eat(&Tok::RBracket) {
                    loop {
                        items.push(self.expr(0)?);
                        if !self.eat(&Tok::Comma) {
                            self.expect(&Tok::RBracket)?;
                            break;
                        }
                    }
                }
                Expr::List(items)
            }
            Tok::LBrace => {
                self.bump();
                let mut entries = Vec::new();
                if !self.eat(&Tok::RBrace) {
                    loop {
                        let key = match self.bump().tok {
                            Tok::Str(s) => s,
                            Tok::Ident(s) => s,
                            other => {
                                return Err(self.err(format!("expected map key, found {other}")));
                            }
                        };
                        self.expect(&Tok::Colon)?;
                        entries.push((key, self.expr(0)?));
                        if !self.eat(&Tok::Comma) {
                            self.expect(&Tok::RBrace)?;
                            break;
                        }
                    }
                }
                Expr::Map(entries)
            }
            Tok::Ident(name) => {
                self.bump();
                match name.as_str() {
                    "true" => Expr::Bool(true),
                    "false" => Expr::Bool(false),
                    "null" => Expr::Null,
                    _ if self.cur().tok == Tok::LParen => {
                        self.bump();
                        let args = self.call_args()?;
                        Expr::Call { target: None, name, args }
                    }
                    _ => Expr::Ident(name),
                }
            }
            other => return Err(self.err(format!("unexpected {other}"))),
        };
        self.postfix(expr)
    }

    fn postfix(&mut self, mut expr: Expr) -> Result<Expr, Issue> {
        loop {
            if self.eat(&Tok::Dot) {
                let name = self.expect_ident()?;
                if self.eat(&Tok::LParen) {
                    let args = self.call_args()?;
                    expr = Expr::Call { target: Some(Box::new(expr)), name, args };
                } else {
                    expr = Expr::Member(Box::new(expr), name);
                }
            } else if self.eat(&Tok::LBracket) {
                // index or range: a[i], a[i:j], a[:j], a[i:]
                if self.eat(&Tok::Colon) {
                    let hi = if self.cur().tok == Tok::RBracket {
                        None
                    } else {
                        Some(Box::new(self.expr(0)?))
                    };
                    self.expect(&Tok::RBracket)?;
                    expr = Expr::Range(Box::new(expr), None, hi);
                } else {
                    let first = self.expr(0)?;
                    if self.eat(&Tok::Colon) {
                        let hi = if self.cur().tok == Tok::RBracket {
                            None
                        } else {
                            Some(Box::new(self.expr(0)?))
                        };
                        self.expect(&Tok::RBracket)?;
                        expr = Expr::Range(Box::new(expr), Some(Box::new(first)), hi);
                    } else {
                        self.expect(&Tok::RBracket)?;
                        expr = Expr::Index(Box::new(expr), Box::new(first));
                    }
                }
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn call_args(&mut self) -> Result<Vec<Expr>, Issue> {
        let mut args = Vec::new();
        if !self.eat(&Tok::RParen) {
            loop {
                args.push(self.expr(0)?);
                if !self.eat(&Tok::Comma) {
                    self.expect(&Tok::RParen)?;
                    break;
                }
            }
        }
        Ok(args)
    }
}

/// Parses a standalone expression (used for `$(…)` path splices).
pub fn parse_expression(source: &str) -> Result<Expr, Issue> {
    let tokens = Lexer::new(source)
        .tokenize()
        .map_err(|e| Issue { message: e.message, line: e.line, col: e.col })?;
    let mut parser = Parser { source, tokens, pos: 0, depth: 0 };
    let expr = parser.expr(0)?;
    if parser.cur().tok != Tok::Eof {
        return Err(parser.err("trailing input after expression"));
    }
    Ok(expr)
}
