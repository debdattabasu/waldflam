//! AST for the rules language.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

#[derive(Debug)]
pub struct Ruleset {
    pub version: Version,
    pub services: Vec<Service>,
}

#[derive(Debug)]
pub struct Service {
    pub name: String,
    pub functions: Vec<FunctionDecl>,
    pub matches: Vec<MatchRule>,
}

#[derive(Debug)]
pub struct MatchRule {
    pub path: Vec<MatchSeg>,
    pub functions: Vec<FunctionDecl>,
    pub allows: Vec<Allow>,
    pub children: Vec<MatchRule>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MatchSeg {
    Literal(String),
    Capture(String),
    /// `{name=**}` — recursive wildcard.
    Glob(String),
}

#[derive(Debug)]
pub struct Allow {
    pub methods: Vec<String>,
    pub condition: Expr,
    pub line: u32,
}

#[derive(Debug)]
pub struct FunctionDecl {
    pub name: String,
    pub params: Vec<String>,
    pub lets: Vec<(String, Expr)>,
    pub body: Expr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    In,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Expr>),
    Map(Vec<(String, Expr)>),
    /// Path literal: `/databases/$(db)/documents/users/$(uid)`.
    Path(Vec<PathPart>),
    Ident(String),
    Member(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Range(Box<Expr>, Option<Box<Expr>>, Option<Box<Expr>>),
    /// `target.name(args)` or bare `name(args)`.
    Call {
        target: Option<Box<Expr>>,
        name: String,
        args: Vec<Expr>,
    },
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    /// `x is int`.
    Is(Box<Expr>, String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Not,
    Neg,
}

#[derive(Debug, Clone)]
pub enum PathPart {
    Static(String),
    Splice(Box<Expr>),
}
