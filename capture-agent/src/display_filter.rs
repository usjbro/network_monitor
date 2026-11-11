//! Display-filter language, ported from `lib/display-filter.ts` (JAM-18).
//!
//! The agent evaluates IO-graph series filters on every frame, before the
//! packet-event rate limiter, so its counts must use exactly the semantics
//! the browser filters with. This module is a structural port of the
//! TypeScript: the same tokenizer, the same recursive-descent parser (errors
//! surface lazily, when the parser reaches the offending token), the same
//! limits and the same evaluation rules. The shared corpus in
//! `testdata/display-filter-conformance.json` is run against both
//! implementations; change them together.
//!
//! Positions and the source-length limit are UTF-16 code units, as JS string
//! indices are. One known divergence: an unexpected astral (non-BMP)
//! character is reported with the whole character as its `token`, where JS
//! reports only its high surrogate (which cannot be held in a Rust `String`).
//! The position is the same.

use crate::fields::{Field, FieldType, FieldValue};

pub const MAX_SOURCE_LENGTH: usize = 2048;
pub const MAX_TOKENS: usize = 512;
pub const MAX_NESTING: usize = 64;
pub const MAX_SET_SIZE: usize = 128;

/// Mirrors the TypeScript `DisplayFilterError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub message: String,
    pub token: String,
    /// UTF-16 code-unit offset into the source.
    pub position: usize,
}

fn error(message: &str, token: &str, position: usize) -> Error {
    Error { message: message.to_string(), token: token.to_string(), position }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Word,
    Number,
    Str,
    Symbol,
    Error,
    End,
}

#[derive(Debug, Clone)]
struct Token {
    kind: Kind,
    text: String,
    position: usize,
    /// Unescaped content, for string tokens.
    value: String,
    /// Error message, for error tokens.
    message: String,
}

impl Token {
    fn new(kind: Kind, text: String, position: usize) -> Self {
        Token { kind, text, position, value: String::new(), message: String::new() }
    }
}

/// JavaScript's `\s`: WhiteSpace plus LineTerminator. It differs from
/// `char::is_whitespace`: it includes U+FEFF and excludes U+0085.
fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}'
            | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

fn tokenize(source: &str) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    // UTF-16 position of each char index, plus one past the end.
    let mut pos = Vec::with_capacity(chars.len() + 1);
    let mut p = 0;
    for c in &chars {
        pos.push(p);
        p += c.len_utf16();
    }
    pos.push(p);
    let end_position = p;

    let mut tokens: Vec<Token> = Vec::new();
    let fail = |mut tokens: Vec<Token>, message: &str, text: &str, position: usize| -> Vec<Token> {
        let mut t = Token::new(Kind::Error, text.to_string(), position);
        t.message = message.to_string();
        tokens.push(t);
        tokens.push(Token::new(Kind::End, "<end>".to_string(), end_position));
        tokens
    };

    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if is_js_whitespace(c) {
            i += 1;
            continue;
        }
        if tokens.len() == MAX_TOKENS {
            return fail(tokens, "Token limit exceeded", "<token-limit>", pos[i]);
        }
        let start = i;
        if c.is_ascii_alphabetic() || c == '_' {
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '.') {
                i += 1;
            }
            tokens.push(Token::new(Kind::Word, chars[start..i].iter().collect(), pos[start]));
            continue;
        }
        if c.is_ascii_digit() {
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            tokens.push(Token::new(Kind::Number, chars[start..i].iter().collect(), pos[start]));
            continue;
        }
        if c == '"' {
            i += 1;
            let mut value = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                    if i >= chars.len() {
                        return fail(tokens, "Invalid string escape", "<end>", pos[i]);
                    }
                    if chars[i] != '\\' && chars[i] != '"' {
                        return fail(tokens, "Invalid string escape", &chars[i].to_string(), pos[i]);
                    }
                }
                value.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                return fail(tokens, "Unterminated string", "<end>", pos[i]);
            }
            i += 1;
            let mut t = Token::new(Kind::Str, chars[start..i].iter().collect(), pos[start]);
            t.value = value;
            tokens.push(t);
            continue;
        }
        let next = chars.get(i + 1).copied();
        let two = matches!((c, next), ('=', Some('=')) | ('!', Some('=')) | ('>', Some('=')) | ('<', Some('=')));
        if two {
            i += 2;
            tokens.push(Token::new(Kind::Symbol, chars[start..i].iter().collect(), pos[start]));
            continue;
        }
        if matches!(c, '>' | '<' | '(' | ')' | ',' | '{' | '}') {
            i += 1;
            tokens.push(Token::new(Kind::Symbol, c.to_string(), pos[start]));
            continue;
        }
        return fail(tokens, "Unexpected token", &c.to_string(), pos[i]);
    }
    tokens.push(Token::new(Kind::End, "<end>".to_string(), end_position));
    tokens
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

#[derive(Debug, Clone)]
enum Literal {
    /// Exact integer value, saturated at `u128::MAX`. Field values are
    /// `u64`, so saturation never changes a comparison's result.
    Number(u128),
    /// Already lower-cased.
    Str(String),
    Bool(bool),
}

#[derive(Debug, Clone)]
enum Node {
    /// Matches every frame: an empty IO-graph series filter (spec D3).
    All,
    Or(Vec<Node>),
    And(Vec<Node>),
    Not(Box<Node>),
    Compare { path: String, op: Op, literal: Literal },
    Contains { path: String, literal: Literal },
    In { path: String, numbers: Vec<u128>, booleans: Vec<bool>, strings: Vec<String> },
    Present { path: String },
}

/// A compiled filter.
#[derive(Debug, Clone)]
pub struct Compiled {
    root: Node,
    /// Every field path the filter names (lower-cased), with its position,
    /// in source order.
    paths: Vec<(String, usize)>,
}

enum Value<'a> {
    Number(u64),
    Bool(bool),
    Str(&'a str),
    Addr(&'a str),
    Group,
}

fn path_matches(field_path: &str, path: &str) -> bool {
    if field_path.is_ascii() {
        field_path.eq_ignore_ascii_case(path)
    } else {
        field_path.to_lowercase() == path
    }
}

/// The value an IO graph aggregate reads (spec D10): the first field
/// whose path matches (the same lookup a filter uses), if it is a uint.
/// A uint past 2^53 - 1 is held as a decimal string in the field tree and
/// is parsed back here. `path` is lower-case.
pub fn uint_value(fields: &[Field], frame_len: u32, path: &str) -> Option<u64> {
    if path == "frame.len" {
        return Some(u64::from(frame_len));
    }
    let field = fields.iter().find(|f| path_matches(&f.path, path))?;
    match (field.field_type, &field.value) {
        (FieldType::Uint, Some(FieldValue::Uint(n))) => Some(*n),
        (FieldType::Uint, Some(FieldValue::Str(s))) => s.parse().ok(),
        _ => None,
    }
}

/// `valueAt` from the TypeScript, for packet records. `path` is lower-case.
fn value_at<'a>(fields: &'a [Field], frame_len: u32, path: &str) -> Option<Value<'a>> {
    if path == "frame.len" {
        return Some(Value::Number(u64::from(frame_len)));
    }
    let field = fields.iter().find(|f| path_matches(&f.path, path))?;
    Some(match (field.field_type, &field.value) {
        (FieldType::Group, _) => Value::Group,
        (FieldType::Uint, Some(FieldValue::Uint(n))) => Value::Number(*n),
        (FieldType::Bool, Some(FieldValue::Bool(b))) => Value::Bool(*b),
        (FieldType::Str, Some(FieldValue::Str(s))) => Value::Str(s),
        (FieldType::Addr, Some(FieldValue::Str(s))) => Value::Addr(s),
        _ => Value::Group,
    })
}

fn compare(value: Option<Value<'_>>, op: Op, literal: &Literal) -> bool {
    match (value, literal) {
        (None | Some(Value::Group), _) => false,
        (Some(Value::Str(s) | Value::Addr(s)), Literal::Str(right)) => match op {
            Op::Eq => s.to_lowercase() == *right,
            Op::Ne => s.to_lowercase() != *right,
            _ => false,
        },
        (Some(Value::Number(n)), Literal::Number(right)) => {
            let left = u128::from(n);
            match op {
                Op::Eq => left == *right,
                Op::Ne => left != *right,
                Op::Gt => left > *right,
                Op::Lt => left < *right,
                Op::Ge => left >= *right,
                Op::Le => left <= *right,
            }
        }
        (Some(Value::Bool(b)), Literal::Bool(right)) => match op {
            Op::Eq => b == *right,
            Op::Ne => b != *right,
            _ => false,
        },
        // Mismatched types: false for every operator, `!=` included.
        _ => false,
    }
}

impl Node {
    fn eval(&self, fields: &[Field], frame_len: u32) -> bool {
        match self {
            Node::All => true,
            Node::Or(children) => children.iter().any(|c| c.eval(fields, frame_len)),
            Node::And(children) => children.iter().all(|c| c.eval(fields, frame_len)),
            Node::Not(child) => !child.eval(fields, frame_len),
            Node::Compare { path, op, literal } => compare(value_at(fields, frame_len, path), *op, literal),
            Node::Contains { path, literal } => match (value_at(fields, frame_len, path), literal) {
                (Some(Value::Str(s) | Value::Addr(s)), Literal::Str(needle)) => s.to_lowercase().contains(needle.as_str()),
                _ => false,
            },
            Node::In { path, numbers, booleans, strings } => match value_at(fields, frame_len, path) {
                Some(Value::Number(n)) => numbers.contains(&u128::from(n)),
                Some(Value::Bool(b)) => booleans.contains(&b),
                Some(Value::Str(s) | Value::Addr(s)) => {
                    let lower = s.to_lowercase();
                    strings.contains(&lower)
                }
                Some(Value::Group) | None => false,
            },
            Node::Present { path } => value_at(fields, frame_len, path).is_some(),
        }
    }
}

impl Compiled {
    /// Evaluates the filter against one packet's field tree. `frame_len` is
    /// the captured length, which is what `frame.len` means in the browser.
    pub fn matches(&self, fields: &[Field], frame_len: u32) -> bool {
        self.root.eval(fields, frame_len)
    }
}

fn is_reserved(word: &str) -> bool {
    ["and", "or", "not", "in", "contains", "true", "false"].iter().any(|r| word.eq_ignore_ascii_case(r))
}

fn parse_number(text: &str) -> u128 {
    text.bytes().fold(0u128, |acc, d| acc.saturating_mul(10).saturating_add(u128::from(d - b'0')))
}

struct Parser {
    tokens: Vec<Token>,
    index: usize,
    paths: Vec<(String, usize)>,
}

impl Parser {
    fn peek(&self) -> Result<&Token, Error> {
        let token = &self.tokens[self.index];
        if token.kind == Kind::Error {
            return Err(error(&token.message, &token.text, token.position));
        }
        Ok(token)
    }
    fn take(&mut self) -> Result<Token, Error> {
        let token = self.peek()?.clone();
        self.index += 1;
        Ok(token)
    }
    fn unexpected(token: &Token) -> Error {
        error("Unexpected token", &token.text, token.position)
    }
    fn fail_here<T>(&self) -> Result<T, Error> {
        Err(Self::unexpected(self.peek()?))
    }
    fn keyword(&self, word: &str) -> Result<bool, Error> {
        let t = self.peek()?;
        Ok(t.kind == Kind::Word && t.text.eq_ignore_ascii_case(word))
    }
    fn symbol(&self, symbol: &str) -> Result<bool, Error> {
        let t = self.peek()?;
        Ok(t.kind == Kind::Symbol && t.text == symbol)
    }
    fn expect_symbol(&mut self, symbol: &str) -> Result<(), Error> {
        if !self.symbol(symbol)? {
            return self.fail_here();
        }
        self.take()?;
        Ok(())
    }
    fn literal(&mut self) -> Result<Literal, Error> {
        let token = self.take()?;
        match token.kind {
            Kind::Number => Ok(Literal::Number(parse_number(&token.text))),
            Kind::Str => Ok(Literal::Str(token.value.to_lowercase())),
            Kind::Word if token.text.eq_ignore_ascii_case("true") => Ok(Literal::Bool(true)),
            Kind::Word if token.text.eq_ignore_ascii_case("false") => Ok(Literal::Bool(false)),
            _ => Err(Self::unexpected(&token)),
        }
    }
    fn parse(mut self) -> Result<Compiled, Error> {
        let root = self.or(0)?;
        if self.peek()?.kind != Kind::End {
            return self.fail_here();
        }
        Ok(Compiled { root, paths: self.paths })
    }
    fn or(&mut self, depth: usize) -> Result<Node, Error> {
        let mut children = vec![self.and(depth)?];
        while self.keyword("or")? {
            self.take()?;
            children.push(self.and(depth)?);
        }
        Ok(if children.len() == 1 { children.pop().unwrap() } else { Node::Or(children) })
    }
    fn and(&mut self, depth: usize) -> Result<Node, Error> {
        let mut children = vec![self.not(depth)?];
        while self.keyword("and")? {
            self.take()?;
            children.push(self.not(depth)?);
        }
        Ok(if children.len() == 1 { children.pop().unwrap() } else { Node::And(children) })
    }
    fn nesting_check(&self, depth: usize) -> Result<(), Error> {
        if depth == MAX_NESTING {
            return Err(error("Nesting limit exceeded", "<nesting-limit>", self.peek()?.position));
        }
        Ok(())
    }
    fn not(&mut self, depth: usize) -> Result<Node, Error> {
        if self.keyword("not")? {
            self.nesting_check(depth)?;
            self.take()?;
            return Ok(Node::Not(Box::new(self.not(depth + 1)?)));
        }
        if self.symbol("(")? {
            self.nesting_check(depth)?;
            self.take()?;
            let child = self.or(depth + 1)?;
            self.expect_symbol(")")?;
            return Ok(child);
        }
        self.atom()
    }
    fn atom(&mut self) -> Result<Node, Error> {
        let path_token = self.take()?;
        if path_token.kind != Kind::Word || is_reserved(&path_token.text) {
            return Err(Self::unexpected(&path_token));
        }
        let path = path_token.text.to_lowercase();
        self.paths.push((path.clone(), path_token.position));
        let op = self.peek()?.clone();
        let op = if op.kind == Kind::Symbol {
            match op.text.as_str() {
                "==" => Some(Op::Eq),
                "!=" => Some(Op::Ne),
                ">=" => Some(Op::Ge),
                "<=" => Some(Op::Le),
                ">" => Some(Op::Gt),
                "<" => Some(Op::Lt),
                _ => None,
            }
        } else {
            None
        };
        if let Some(op) = op {
            self.take()?;
            let literal = self.literal()?;
            return Ok(Node::Compare { path, op, literal });
        }
        if self.keyword("contains")? {
            self.take()?;
            let literal = self.literal()?;
            return Ok(Node::Contains { path, literal });
        }
        if self.keyword("in")? {
            self.take()?;
            self.expect_symbol("{")?;
            let mut literals = vec![self.literal()?];
            while self.symbol(",")? {
                self.take()?;
                if literals.len() == MAX_SET_SIZE {
                    return Err(error("Set size limit exceeded", "<set-limit>", self.peek()?.position));
                }
                literals.push(self.literal()?);
            }
            self.expect_symbol("}")?;
            let (mut numbers, mut booleans, mut strings) = (Vec::new(), Vec::new(), Vec::new());
            for literal in literals {
                match literal {
                    Literal::Number(n) => numbers.push(n),
                    Literal::Bool(b) => booleans.push(b),
                    Literal::Str(s) => strings.push(s),
                }
            }
            return Ok(Node::In { path, numbers, booleans, strings });
        }
        Ok(Node::Present { path })
    }
}

/// Compiles a display filter with the browser's semantics.
pub fn compile(source: &str) -> Result<Compiled, Error> {
    if utf16_len(source) > MAX_SOURCE_LENGTH {
        return Err(error("Source length limit exceeded", "<source-limit>", MAX_SOURCE_LENGTH));
    }
    Parser { tokens: tokenize(source), index: 0, paths: Vec::new() }.parse()
}

/// Compiles a filter for an IO-graph series (spec D2). On top of `compile`,
/// it rejects paths whose values a per-frame count cannot honestly use:
/// `connection.*` (always absent on a packet record) and `*.response_to`
/// (present only when the request was itself sent to the browser, so it
/// depends on the packet-event rate limiter).
///
/// An empty or whitespace-only source means "every parsed frame" (spec D3),
/// where the browser's `compile` treats it as a syntax error; the browser
/// treats an empty display filter as "no filter", which is the same thing.
pub fn compile_for_series(source: &str) -> Result<Compiled, Error> {
    if utf16_len(source) <= MAX_SOURCE_LENGTH && source.chars().all(is_js_whitespace) {
        return Ok(Compiled { root: Node::All, paths: Vec::new() });
    }
    let compiled = compile(source)?;
    for (path, position) in &compiled.paths {
        if path.starts_with("connection.") {
            return Err(error("connection fields are not available in IO graph series", path, *position));
        }
        if path.ends_with(".response_to") {
            return Err(error(
                "response_to depends on which packets were sent to the browser and cannot be counted",
                path,
                *position,
            ));
        }
    }
    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::ByteRegion;

    fn uint(path: &str, n: u64) -> Field {
        Field {
            path: path.into(),
            label: path.into(),
            group: None,
            field_type: FieldType::Uint,
            value: Some(FieldValue::Uint(n)),
            region: ByteRegion::Header,
            offset: 0,
            len: 0,
        }
    }

    #[test]
    fn series_rejects_connection_fields_with_their_position() {
        let e = compile_for_series("tcp and connection.remote_port == 443").unwrap_err();
        assert_eq!(e.message, "connection fields are not available in IO graph series");
        assert_eq!((e.token.as_str(), e.position), ("connection.remote_port", 8));
        // The browser filter accepts it (it is valid for connection records).
        assert!(compile("tcp and connection.remote_port == 443").is_ok());
    }

    #[test]
    fn series_rejects_response_to_but_keeps_time_us() {
        let e = compile_for_series("DNS.Response_To").unwrap_err();
        assert!(e.message.starts_with("response_to depends on"));
        assert_eq!((e.token.as_str(), e.position), ("dns.response_to", 0));
        assert!(compile_for_series("dns.time_us > 1000 or http.time_us > 1000").is_ok());
    }

    #[test]
    fn series_reports_compile_errors_before_path_rejections() {
        let e = compile_for_series("connection.process ==").unwrap_err();
        assert_eq!(e.message, "Unexpected token");
    }

    #[test]
    fn an_empty_series_filter_matches_every_frame() {
        for source in ["", "  \t\u{FEFF}"] {
            let all = compile_for_series(source).unwrap();
            assert!(all.matches(&[], 0));
            assert!(all.matches(&[uint("x", 1)], 1500));
        }
        // The browser grammar itself still rejects an empty source.
        assert_eq!(compile("").unwrap_err().message, "Unexpected token");
        assert!(compile_for_series("\u{85}").is_err());
    }

    #[test]
    fn whitespace_follows_javascript_not_rust() {
        assert!(compile("tcp\u{FEFF}").is_ok());
        assert_eq!(compile("\u{85}tcp").unwrap_err().message, "Unexpected token");
    }

    #[test]
    fn long_or_chains_evaluate_without_deep_recursion() {
        let source = format!("x == 1{}", " or x == 1".repeat(120));
        let compiled = compile(&source).unwrap();
        assert!(compiled.matches(&[uint("x", 1)], 0));
        assert!(!compiled.matches(&[uint("x", 2)], 0));
    }
}
