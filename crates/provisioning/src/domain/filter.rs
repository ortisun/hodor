//! The filters of SCIM lists, read by a bounded parser.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Filters".
//! Reading is a pure function: text in, a tree of conditions or a refusal
//! out. The length is checked before anything is read, and the nesting
//! and the number of comparisons while reading, so no text costs more
//! than one at the bounds.
//!
//! Reading happens in two steps. The first reads the grammar of RFC 7644,
//! section 3.4.2.2, into a tree that still names attributes as written,
//! and keeps the bounds. The second gives each name its attribute of one
//! resource type and checks that the operators and values fit its type.

use crate::domain::attribute::{Attribute, AttributeType, fold_case, without_schema};
use hodor_kernel::Timestamp;
use std::fmt;
use time::format_description::well_known::Rfc3339;

/// The most characters a filter may hold.
pub const MAX_FILTER_CHARACTERS: usize = 1000;
/// The most levels of nesting: each pair of parentheses, with or without
/// `not` before it, and each value path's brackets, is one.
pub const MAX_FILTER_DEPTH: usize = 10;
/// The most comparisons, presence tests included.
pub const MAX_FILTER_COMPARISONS: usize = 20;

/// How a comparison compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operator {
    /// `eq`: equal.
    Equal,
    /// `ne`: not equal.
    NotEqual,
    /// `co`: contains.
    Contains,
    /// `sw`: starts with.
    StartsWith,
    /// `ew`: ends with.
    EndsWith,
    /// `gt`: greater than.
    Greater,
    /// `ge`: greater than or equal.
    GreaterOrEqual,
    /// `lt`: less than.
    Less,
    /// `le`: less than or equal.
    LessOrEqual,
}

impl Operator {
    /// How the operator is written.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "eq",
            Self::NotEqual => "ne",
            Self::Contains => "co",
            Self::StartsWith => "sw",
            Self::EndsWith => "ew",
            Self::Greater => "gt",
            Self::GreaterOrEqual => "ge",
            Self::Less => "lt",
            Self::LessOrEqual => "le",
        }
    }

    fn named(word: &str) -> Option<Self> {
        Some(match word.to_ascii_lowercase().as_str() {
            "eq" => Self::Equal,
            "ne" => Self::NotEqual,
            "co" => Self::Contains,
            "sw" => Self::StartsWith,
            "ew" => Self::EndsWith,
            "gt" => Self::Greater,
            "ge" => Self::GreaterOrEqual,
            "lt" => Self::Less,
            "le" => Self::LessOrEqual,
            _ => return None,
        })
    }

    /// Whether the operator orders values: `gt`, `ge`, `lt`, `le`.
    #[must_use]
    pub const fn orders(self) -> bool {
        matches!(
            self,
            Self::Greater | Self::GreaterOrEqual | Self::Less | Self::LessOrEqual
        )
    }

    const fn allowed_for(self, value_type: AttributeType) -> bool {
        match value_type {
            AttributeType::Text { .. } => true,
            AttributeType::Boolean => matches!(self, Self::Equal | Self::NotEqual),
            AttributeType::DateTime => {
                !matches!(self, Self::Contains | Self::StartsWith | Self::EndsWith)
            }
        }
    }
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A value a comparison compares with, of its attribute's type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Text. For an attribute compared without regard to case, the
    /// letters `A` to `Z` are already `a` to `z`.
    Text(String),
    /// `true` or `false`.
    Boolean(bool),
    /// A date and time.
    DateTime(Timestamp),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => f.write_str(&serde_json::to_string(text).map_err(|_| fmt::Error)?),
            Self::Boolean(value) => write!(f, "{value}"),
            Self::DateTime(at) => {
                write!(f, "\"{}\"", at.format(&Rfc3339).map_err(|_| fmt::Error)?)
            }
        }
    }
}

/// A condition on the resources of one type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter<A> {
    /// A single-valued attribute compared with a value.
    Compare(A, Operator, Value),
    /// A single-valued attribute has a value.
    Present(A),
    /// One value of a multi-valued attribute satisfies the condition.
    Any(A, Box<ValueFilter>),
    /// Both hold.
    And(Box<Self>, Box<Self>),
    /// Either holds.
    Or(Box<Self>, Box<Self>),
    /// It does not hold.
    Not(Box<Self>),
}

/// A condition on one value of a multi-valued attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFilter {
    /// The value compared with another.
    Compare(Operator, Value),
    /// The value is there. Always true of a value that exists.
    Present,
    /// Both hold.
    And(Box<Self>, Box<Self>),
    /// Either holds.
    Or(Box<Self>, Box<Self>),
    /// It does not hold.
    Not(Box<Self>),
}

/// Why a filter is refused. Each is answered with `invalidFilter` and its
/// own detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterRefusal {
    /// More than [`MAX_FILTER_CHARACTERS`].
    TooLong,
    /// More than [`MAX_FILTER_DEPTH`] levels.
    TooDeep,
    /// More than [`MAX_FILTER_COMPARISONS`].
    TooManyComparisons,
    /// Not the grammar of RFC 7644; says where it goes wrong.
    Unreadable(&'static str),
    /// An attribute that cannot be filtered on, as it was written.
    NotFilterable(String),
    /// An operator the attribute's type does not take.
    OperatorNotAllowed {
        /// The attribute.
        attribute: &'static str,
        /// The operator.
        operator: Operator,
    },
    /// A value the attribute's type does not take.
    ValueNotAllowed {
        /// The attribute.
        attribute: &'static str,
        /// What it takes.
        expected: &'static str,
    },
    /// `null` with an operator other than `eq` and `ne`.
    NullNotAllowed,
}

impl fmt::Display for FilterRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(
                f,
                "a filter holds at most {MAX_FILTER_CHARACTERS} characters"
            ),
            Self::TooDeep => write!(f, "a filter nests at most {MAX_FILTER_DEPTH} levels deep"),
            Self::TooManyComparisons => write!(
                f,
                "a filter holds at most {MAX_FILTER_COMPARISONS} comparisons"
            ),
            Self::Unreadable(why) => write!(f, "the filter cannot be read: {why}"),
            Self::NotFilterable(path) => write!(f, "{path} cannot be filtered on"),
            Self::OperatorNotAllowed {
                attribute,
                operator,
            } => write!(f, "{attribute} cannot be compared with {operator}"),
            Self::ValueNotAllowed {
                attribute,
                expected,
            } => write!(f, "{attribute} is compared with {expected}"),
            Self::NullNotAllowed => f.write_str("null is compared only with eq or ne"),
        }
    }
}

/// Reads a filter on the resources whose attributes are `A`.
///
/// # Errors
///
/// The refusal, when the filter passes a bound, is not the grammar of RFC
/// 7644, names an attribute that cannot be filtered on, or compares one
/// in a way its type does not allow.
pub fn parse<A: Attribute>(text: &str) -> Result<Filter<A>, FilterRefusal> {
    if text.chars().count() > MAX_FILTER_CHARACTERS {
        return Err(FilterRefusal::TooLong);
    }
    let tokens = tokens(text)?;
    let mut parser = Parser {
        tokens,
        at: 0,
        comparisons: 0,
    };
    if parser.tokens.is_empty() {
        return Err(FilterRefusal::Unreadable("the filter is empty"));
    }
    let raw = parser.or(0, false)?;
    if parser.at < parser.tokens.len() {
        return Err(FilterRefusal::Unreadable(
            "there is more after the end of the filter",
        ));
    }
    resolve(&raw)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Open,
    Close,
    OpenBracket,
    CloseBracket,
    Word(String),
    Text(String),
    Number,
}

fn is_word_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '$' || character == '_'
}

fn is_word_part(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':' | '$')
}

fn tokens(text: &str) -> Result<Vec<Token>, FilterRefusal> {
    let mut found = Vec::new();
    let mut characters = text.char_indices().peekable();
    while let Some((start, character)) = characters.next() {
        match character {
            ' ' | '\t' | '\r' | '\n' => {}
            '(' => found.push(Token::Open),
            ')' => found.push(Token::Close),
            '[' => found.push(Token::OpenBracket),
            ']' => found.push(Token::CloseBracket),
            '"' => {
                let mut end = None;
                while let Some((at, inside)) = characters.next() {
                    match inside {
                        '\\' => {
                            characters.next();
                        }
                        '"' => {
                            end = Some(at);
                            break;
                        }
                        _ => {}
                    }
                }
                let end = end.ok_or(FilterRefusal::Unreadable("a string is not closed"))?;
                let decoded: String = serde_json::from_str(&text[start..=end])
                    .map_err(|_| FilterRefusal::Unreadable("a string is not valid JSON"))?;
                found.push(Token::Text(decoded));
            }
            '-' | '0'..='9' => {
                let mut end = start + character.len_utf8();
                while let Some(&(at, next)) = characters.peek() {
                    if next.is_ascii_digit() || matches!(next, '.' | 'e' | 'E' | '+' | '-') {
                        end = at + next.len_utf8();
                        characters.next();
                    } else {
                        break;
                    }
                }
                serde_json::from_str::<serde_json::Number>(&text[start..end])
                    .map_err(|_| FilterRefusal::Unreadable("a number cannot be read"))?;
                found.push(Token::Number);
            }
            character if is_word_start(character) => {
                let mut end = start + character.len_utf8();
                while let Some(&(at, next)) = characters.peek() {
                    if is_word_part(next) {
                        end = at + next.len_utf8();
                        characters.next();
                    } else {
                        break;
                    }
                }
                found.push(Token::Word(text[start..end].to_owned()));
            }
            _ => {
                return Err(FilterRefusal::Unreadable(
                    "it holds a character that is not part of a filter",
                ));
            }
        }
    }
    Ok(found)
}

/// A literal as written, before its attribute's type is known.
#[derive(Debug, Clone, PartialEq)]
enum Literal {
    Text(String),
    Number,
    True,
    False,
    Null,
}

/// A filter as written, with attributes named as written.
#[derive(Debug, Clone, PartialEq)]
enum Raw {
    Compare(String, Operator, Literal),
    Present(String),
    ValuePath(String, Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    comparisons: usize,
}

fn is_keyword(word: &str, keyword: &str) -> bool {
    word.eq_ignore_ascii_case(keyword)
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        if token.is_some() {
            self.at += 1;
        }
        token
    }

    fn peek_keyword(&self, keyword: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(word)) if is_keyword(word, keyword))
    }

    fn deeper(depth: usize) -> Result<usize, FilterRefusal> {
        let deeper = depth + 1;
        if deeper > MAX_FILTER_DEPTH {
            return Err(FilterRefusal::TooDeep);
        }
        Ok(deeper)
    }

    fn counted(&mut self) -> Result<(), FilterRefusal> {
        self.comparisons += 1;
        if self.comparisons > MAX_FILTER_COMPARISONS {
            return Err(FilterRefusal::TooManyComparisons);
        }
        Ok(())
    }

    fn or(&mut self, depth: usize, in_value_path: bool) -> Result<Raw, FilterRefusal> {
        let mut left = self.and(depth, in_value_path)?;
        while self.peek_keyword("or") {
            self.at += 1;
            let right = self.and(depth, in_value_path)?;
            left = Raw::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self, depth: usize, in_value_path: bool) -> Result<Raw, FilterRefusal> {
        let mut left = self.term(depth, in_value_path)?;
        while self.peek_keyword("and") {
            self.at += 1;
            let right = self.term(depth, in_value_path)?;
            left = Raw::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn close(&mut self, closing: &Token) -> Result<(), FilterRefusal> {
        if self.next().as_ref() == Some(closing) {
            Ok(())
        } else if *closing == Token::Close {
            Err(FilterRefusal::Unreadable("a parenthesis is not closed"))
        } else {
            Err(FilterRefusal::Unreadable(
                "a value path's bracket is not closed",
            ))
        }
    }

    fn term(&mut self, depth: usize, in_value_path: bool) -> Result<Raw, FilterRefusal> {
        match self.next() {
            Some(Token::Open) => {
                let depth = Self::deeper(depth)?;
                let inner = self.or(depth, in_value_path)?;
                self.close(&Token::Close)?;
                Ok(inner)
            }
            Some(Token::Word(word)) if is_keyword(&word, "not") => {
                if self.next() != Some(Token::Open) {
                    return Err(FilterRefusal::Unreadable(
                        "not is followed by a parenthesis",
                    ));
                }
                let depth = Self::deeper(depth)?;
                let inner = self.or(depth, in_value_path)?;
                self.close(&Token::Close)?;
                Ok(Raw::Not(Box::new(inner)))
            }
            Some(Token::Word(word)) if is_keyword(&word, "and") || is_keyword(&word, "or") => Err(
                FilterRefusal::Unreadable("an attribute is expected before and and or"),
            ),
            Some(Token::Word(path)) => self.attribute_expression(path, depth, in_value_path),
            None => Err(FilterRefusal::Unreadable("the filter ends too early")),
            Some(_) => Err(FilterRefusal::Unreadable(
                "an attribute, a parenthesis or not is expected",
            )),
        }
    }

    fn attribute_expression(
        &mut self,
        path: String,
        depth: usize,
        in_value_path: bool,
    ) -> Result<Raw, FilterRefusal> {
        match self.next() {
            Some(Token::OpenBracket) => {
                if in_value_path {
                    return Err(FilterRefusal::Unreadable(
                        "a value path cannot hold another",
                    ));
                }
                let depth = Self::deeper(depth)?;
                let inner = self.or(depth, true)?;
                self.close(&Token::CloseBracket)?;
                Ok(Raw::ValuePath(path, Box::new(inner)))
            }
            Some(Token::Word(word)) if is_keyword(&word, "pr") => {
                self.counted()?;
                Ok(Raw::Present(path))
            }
            Some(Token::Word(word)) => {
                let operator = Operator::named(&word).ok_or(FilterRefusal::Unreadable(
                    "an operator is not one SCIM defines",
                ))?;
                self.counted()?;
                let literal = match self.next() {
                    Some(Token::Text(text)) => Literal::Text(text),
                    Some(Token::Number) => Literal::Number,
                    Some(Token::Word(word)) if is_keyword(&word, "true") => Literal::True,
                    Some(Token::Word(word)) if is_keyword(&word, "false") => Literal::False,
                    Some(Token::Word(word)) if is_keyword(&word, "null") => Literal::Null,
                    _ => {
                        return Err(FilterRefusal::Unreadable(
                            "a value is expected after an operator",
                        ));
                    }
                };
                Ok(Raw::Compare(path, operator, literal))
            }
            _ => Err(FilterRefusal::Unreadable(
                "an operator is expected after an attribute",
            )),
        }
    }
}

/// A value filter of a `PATCH` path, such as the `type eq "work"` of
/// `emails[type eq "work"].value`: a condition on the sub-attributes of one
/// value of a multi-valued attribute, any of them. It keeps the grammar and
/// the bounds of filters, and compares text without regard to case.
#[derive(Debug, Clone, PartialEq)]
pub struct ElementFilter(Raw);

/// Reads the value filter of a `PATCH` path, the text between its
/// brackets.
///
/// # Errors
///
/// The refusal, when the filter passes a bound or is not the grammar of
/// RFC 7644. A value path inside it is refused too.
pub fn parse_element_filter(text: &str) -> Result<ElementFilter, FilterRefusal> {
    if text.chars().count() > MAX_FILTER_CHARACTERS {
        return Err(FilterRefusal::TooLong);
    }
    let mut parser = Parser {
        tokens: tokens(text)?,
        at: 0,
        comparisons: 0,
    };
    if parser.tokens.is_empty() {
        return Err(FilterRefusal::Unreadable("the filter is empty"));
    }
    let raw = parser.or(0, true)?;
    if parser.at < parser.tokens.len() {
        return Err(FilterRefusal::Unreadable(
            "there is more after the end of the filter",
        ));
    }
    Ok(ElementFilter(raw))
}

fn element_field<'a>(
    element: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a serde_json::Value> {
    element
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
        .filter(|value| !value.is_null())
}

fn raw_matches(raw: &Raw, element: &serde_json::Map<String, serde_json::Value>) -> bool {
    use serde_json::Value as Json;
    match raw {
        Raw::And(left, right) => raw_matches(left, element) && raw_matches(right, element),
        Raw::Or(left, right) => raw_matches(left, element) || raw_matches(right, element),
        Raw::Not(inner) => !raw_matches(inner, element),
        Raw::Present(path) => element_field(element, path).is_some(),
        Raw::ValuePath(..) => false,
        Raw::Compare(path, operator, literal) => {
            let found = element_field(element, path);
            match (found, literal) {
                (None, Literal::Null) => *operator == Operator::Equal,
                (Some(_), Literal::Null) => *operator == Operator::NotEqual,
                (Some(Json::String(found)), Literal::Text(text)) => {
                    let (found, text) = (fold_case(found), fold_case(text));
                    match operator {
                        Operator::Contains => found.contains(&text),
                        Operator::StartsWith => found.starts_with(&text),
                        Operator::EndsWith => found.ends_with(&text),
                        Operator::Equal => found == text,
                        Operator::NotEqual => found != text,
                        Operator::Greater => found > text,
                        Operator::GreaterOrEqual => found >= text,
                        Operator::Less => found < text,
                        Operator::LessOrEqual => found <= text,
                    }
                }
                (Some(Json::Bool(found)), Literal::True | Literal::False) => {
                    let wanted = *literal == Literal::True;
                    match operator {
                        Operator::Equal => *found == wanted,
                        Operator::NotEqual => *found != wanted,
                        _ => false,
                    }
                }
                _ => false,
            }
        }
    }
}

fn raw_equalities(raw: &Raw, found: &mut Vec<(String, serde_json::Value)>) -> bool {
    match raw {
        Raw::And(left, right) => raw_equalities(left, found) && raw_equalities(right, found),
        Raw::Compare(path, Operator::Equal, Literal::Text(text)) => {
            found.push((path.clone(), serde_json::Value::String(text.clone())));
            true
        }
        Raw::Compare(path, Operator::Equal, Literal::True) => {
            found.push((path.clone(), serde_json::Value::Bool(true)));
            true
        }
        Raw::Compare(path, Operator::Equal, Literal::False) => {
            found.push((path.clone(), serde_json::Value::Bool(false)));
            true
        }
        _ => false,
    }
}

impl ElementFilter {
    /// Whether one value of a multi-valued attribute satisfies the filter.
    #[must_use]
    pub fn matches(&self, element: &serde_json::Map<String, serde_json::Value>) -> bool {
        raw_matches(&self.0, element)
    }

    /// The sub-attributes a new value must have to satisfy the filter,
    /// when it is made only of `eq` comparisons joined by `and`; `None`
    /// otherwise.
    #[must_use]
    pub fn equalities(&self) -> Option<Vec<(String, serde_json::Value)>> {
        let mut found = Vec::new();
        raw_equalities(&self.0, &mut found).then_some(found)
    }
}

/// The attribute a path names, as written in a filter.
fn attribute<A: Attribute>(path: &str) -> Result<A, FilterRefusal> {
    let lowered = path.to_ascii_lowercase();
    without_schema(&lowered, A::SCHEMA)
        .and_then(A::named)
        .ok_or_else(|| FilterRefusal::NotFilterable(path.to_owned()))
}

fn value_of(
    attribute: &'static str,
    value_type: AttributeType,
    literal: &Literal,
) -> Result<Value, FilterRefusal> {
    match (value_type, literal) {
        (AttributeType::Text { exact }, Literal::Text(text)) => Ok(Value::Text(if exact {
            text.clone()
        } else {
            fold_case(text)
        })),
        (AttributeType::Text { .. }, _) => Err(FilterRefusal::ValueNotAllowed {
            attribute,
            expected: "a string",
        }),
        (AttributeType::Boolean, Literal::True) => Ok(Value::Boolean(true)),
        (AttributeType::Boolean, Literal::False) => Ok(Value::Boolean(false)),
        (AttributeType::Boolean, _) => Err(FilterRefusal::ValueNotAllowed {
            attribute,
            expected: "true or false",
        }),
        (AttributeType::DateTime, Literal::Text(text)) => Timestamp::parse(text, &Rfc3339)
            .map(Value::DateTime)
            .map_err(|_| FilterRefusal::ValueNotAllowed {
                attribute,
                expected: "a date and time of RFC 3339",
            }),
        (AttributeType::DateTime, _) => Err(FilterRefusal::ValueNotAllowed {
            attribute,
            expected: "a date and time of RFC 3339",
        }),
    }
}

/// What a comparison of an attribute of `value_type` with `literal` is:
/// a comparison, or, for `null`, whether the attribute has a value.
enum Compared {
    Compare(Operator, Value),
    Present,
    Absent,
}

fn compared(
    attribute: &'static str,
    value_type: AttributeType,
    operator: Operator,
    literal: &Literal,
) -> Result<Compared, FilterRefusal> {
    if *literal == Literal::Null {
        return match operator {
            Operator::Equal => Ok(Compared::Absent),
            Operator::NotEqual => Ok(Compared::Present),
            _ => Err(FilterRefusal::NullNotAllowed),
        };
    }
    if !operator.allowed_for(value_type) {
        return Err(FilterRefusal::OperatorNotAllowed {
            attribute,
            operator,
        });
    }
    Ok(Compared::Compare(
        operator,
        value_of(attribute, value_type, literal)?,
    ))
}

fn resolve<A: Attribute>(raw: &Raw) -> Result<Filter<A>, FilterRefusal> {
    Ok(match raw {
        Raw::And(left, right) => Filter::And(Box::new(resolve(left)?), Box::new(resolve(right)?)),
        Raw::Or(left, right) => Filter::Or(Box::new(resolve(left)?), Box::new(resolve(right)?)),
        Raw::Not(inner) => Filter::Not(Box::new(resolve(inner)?)),
        Raw::Present(path) => {
            let attribute = attribute::<A>(path)?;
            if attribute.multi_valued() {
                Filter::Any(attribute, Box::new(ValueFilter::Present))
            } else {
                Filter::Present(attribute)
            }
        }
        Raw::Compare(path, operator, literal) => {
            let attribute = attribute::<A>(path)?;
            let compared = compared(attribute.name(), attribute.value_type(), *operator, literal)?;
            match (attribute.multi_valued(), compared) {
                (false, Compared::Compare(operator, value)) => {
                    Filter::Compare(attribute, operator, value)
                }
                (false, Compared::Present) => Filter::Present(attribute),
                (false, Compared::Absent) => Filter::Not(Box::new(Filter::Present(attribute))),
                (true, Compared::Compare(operator, value)) => {
                    Filter::Any(attribute, Box::new(ValueFilter::Compare(operator, value)))
                }
                (true, Compared::Present) => Filter::Any(attribute, Box::new(ValueFilter::Present)),
                (true, Compared::Absent) => Filter::Not(Box::new(Filter::Any(
                    attribute,
                    Box::new(ValueFilter::Present),
                ))),
            }
        }
        Raw::ValuePath(path, inner) => {
            let attribute = attribute::<A>(path)?;
            if !attribute.multi_valued() {
                return Err(FilterRefusal::Unreadable(
                    "only a multi-valued attribute takes a value path",
                ));
            }
            Filter::Any(attribute, Box::new(resolve_value(attribute, path, inner)?))
        }
    })
}

fn resolve_value<A: Attribute>(
    attribute: A,
    parent: &str,
    raw: &Raw,
) -> Result<ValueFilter, FilterRefusal> {
    let sub = |path: &str| -> Result<(), FilterRefusal> {
        if path.eq_ignore_ascii_case("value") {
            Ok(())
        } else {
            Err(FilterRefusal::NotFilterable(format!("{parent}.{path}")))
        }
    };
    Ok(match raw {
        Raw::And(left, right) => ValueFilter::And(
            Box::new(resolve_value(attribute, parent, left)?),
            Box::new(resolve_value(attribute, parent, right)?),
        ),
        Raw::Or(left, right) => ValueFilter::Or(
            Box::new(resolve_value(attribute, parent, left)?),
            Box::new(resolve_value(attribute, parent, right)?),
        ),
        Raw::Not(inner) => ValueFilter::Not(Box::new(resolve_value(attribute, parent, inner)?)),
        Raw::Present(path) => {
            sub(path)?;
            ValueFilter::Present
        }
        Raw::Compare(path, operator, literal) => {
            sub(path)?;
            match compared(attribute.name(), attribute.value_type(), *operator, literal)? {
                Compared::Compare(operator, value) => ValueFilter::Compare(operator, value),
                Compared::Present => ValueFilter::Present,
                Compared::Absent => ValueFilter::Not(Box::new(ValueFilter::Present)),
            }
        }
        // The grammar never puts a value path inside another.
        Raw::ValuePath(..) => {
            return Err(FilterRefusal::Unreadable(
                "a value path cannot hold another",
            ));
        }
    })
}

/// The part of a multi-valued attribute's name before its sub-attribute:
/// `emails` of `emails.value`.
fn parent_name(name: &'static str) -> &'static str {
    name.split_once('.').map_or(name, |(parent, _)| parent)
}

fn write_operand<A: Attribute>(
    f: &mut fmt::Formatter<'_>,
    filter: &Filter<A>,
    grouped: bool,
) -> fmt::Result {
    if grouped {
        write!(f, "({filter})")
    } else {
        write!(f, "{filter}")
    }
}

/// Writes the filter so that reading it gives the same tree.
impl<A: Attribute> fmt::Display for Filter<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compare(attribute, operator, value) => {
                write!(f, "{} {operator} {value}", attribute.name())
            }
            Self::Present(attribute) => write!(f, "{} pr", attribute.name()),
            Self::Any(attribute, condition) => {
                write!(f, "{}[{condition}]", parent_name(attribute.name()))
            }
            Self::Not(inner) => write!(f, "not ({inner})"),
            Self::And(left, right) => {
                write_operand(f, left, matches!(**left, Self::Or(..)))?;
                f.write_str(" and ")?;
                write_operand(f, right, matches!(**right, Self::Or(..) | Self::And(..)))
            }
            Self::Or(left, right) => {
                write_operand(f, left, false)?;
                f.write_str(" or ")?;
                write_operand(f, right, matches!(**right, Self::Or(..)))
            }
        }
    }
}

impl fmt::Display for ValueFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operand = |f: &mut fmt::Formatter<'_>, inner: &Self, grouped: bool| {
            if grouped {
                write!(f, "({inner})")
            } else {
                write!(f, "{inner}")
            }
        };
        match self {
            Self::Compare(operator, value) => write!(f, "value {operator} {value}"),
            Self::Present => f.write_str("value pr"),
            Self::Not(inner) => write!(f, "not ({inner})"),
            Self::And(left, right) => {
                operand(f, left, matches!(**left, Self::Or(..)))?;
                f.write_str(" and ")?;
                operand(f, right, matches!(**right, Self::Or(..) | Self::And(..)))
            }
            Self::Or(left, right) => {
                operand(f, left, false)?;
                f.write_str(" or ")?;
                operand(f, right, matches!(**right, Self::Or(..)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::attribute::{GroupAttribute, UserAttribute};

    fn user(text: &str) -> Result<Filter<UserAttribute>, FilterRefusal> {
        parse(text)
    }

    #[test]
    fn and_binds_tighter_than_or() {
        let read = user(r#"userName eq "a" or userName eq "b" and active eq true"#).expect("read");
        let Filter::Or(_, right) = read else {
            panic!("an or at the top: {read:?}");
        };
        assert!(matches!(*right, Filter::And(..)));
    }

    #[test]
    fn words_and_operators_are_read_without_regard_to_case() {
        assert_eq!(
            user(r#"USERNAME EQ "Bjensen" AND Active Eq TRUE"#).expect("read"),
            Filter::And(
                Box::new(Filter::Compare(
                    UserAttribute::UserName,
                    Operator::Equal,
                    Value::Text("bjensen".to_owned())
                )),
                Box::new(Filter::Compare(
                    UserAttribute::Active,
                    Operator::Equal,
                    Value::Boolean(true)
                )),
            )
        );
    }

    #[test]
    fn a_value_compared_exactly_keeps_its_case() {
        assert_eq!(
            user(r#"externalId eq "AbC""#).expect("read"),
            Filter::Compare(
                UserAttribute::ExternalId,
                Operator::Equal,
                Value::Text("AbC".to_owned())
            )
        );
    }

    #[test]
    fn null_is_absence_and_presence() {
        assert_eq!(
            user("externalId eq null").expect("read"),
            Filter::Not(Box::new(Filter::Present(UserAttribute::ExternalId)))
        );
        assert_eq!(
            user("externalId ne null").expect("read"),
            Filter::Present(UserAttribute::ExternalId)
        );
        assert_eq!(
            user("externalId gt null"),
            Err(FilterRefusal::NullNotAllowed)
        );
    }

    #[test]
    fn a_multi_valued_attribute_is_compared_through_one_of_its_values() {
        let plain = user(r#"emails co "example.com""#).expect("read");
        let bracketed = user(r#"emails[value co "example.com"]"#).expect("read");
        assert_eq!(plain, bracketed);
        assert_eq!(
            parse::<GroupAttribute>("members pr").expect("read"),
            Filter::Any(GroupAttribute::Members, Box::new(ValueFilter::Present))
        );
    }

    #[test]
    fn the_bounds_are_kept() {
        let long = format!(r#"userName eq "{}""#, "a".repeat(990));
        assert_eq!(user(&long), Err(FilterRefusal::TooLong));
        let deep = format!(
            "{}userName pr{}",
            "(".repeat(MAX_FILTER_DEPTH + 1),
            ")".repeat(MAX_FILTER_DEPTH + 1)
        );
        assert_eq!(user(&deep), Err(FilterRefusal::TooDeep));
        let at_the_bound = format!(
            "{}userName pr{}",
            "(".repeat(MAX_FILTER_DEPTH),
            ")".repeat(MAX_FILTER_DEPTH)
        );
        assert!(user(&at_the_bound).is_ok());
        let many = vec!["userName pr"; MAX_FILTER_COMPARISONS + 1].join(" or ");
        assert_eq!(user(&many), Err(FilterRefusal::TooManyComparisons));
        let enough = vec!["userName pr"; MAX_FILTER_COMPARISONS].join(" or ");
        assert!(user(&enough).is_ok());
    }

    #[test]
    fn an_element_filter_compares_any_sub_attribute_without_regard_to_case() {
        let element = |value: serde_json::Value| value.as_object().cloned().expect("an object");
        let work = element(
            serde_json::json!({ "value": "Ana@Example.com", "type": "Work", "primary": true }),
        );
        let home = element(serde_json::json!({ "value": "ana@home.org", "type": "home" }));
        let filter = parse_element_filter(r#"type eq "work" and primary eq true"#).expect("read");
        assert!(filter.matches(&work));
        assert!(!filter.matches(&home));
        assert!(
            parse_element_filter(r#"value ew ".ORG""#)
                .expect("read")
                .matches(&home)
        );
        assert!(
            parse_element_filter("display eq null")
                .expect("read")
                .matches(&home)
        );
        assert_eq!(
            parse_element_filter(r#"type eq "work""#)
                .expect("read")
                .equalities(),
            Some(vec![("type".to_owned(), serde_json::json!("work"))])
        );
        assert_eq!(
            parse_element_filter(r#"type eq "work" or type eq "home""#)
                .expect("read")
                .equalities(),
            None
        );
        assert!(parse_element_filter(r#"value[type eq "x"]"#).is_err());
    }

    #[test]
    fn a_written_filter_reads_back_the_same() {
        for text in [
            r#"userName eq "bjensen""#,
            r#"(userName eq "a" or userName eq "b") and not (active eq false)"#,
            r#"emails[value sw "ana" and value ew ".org"] or externalId pr"#,
            r#"meta.created gt "2026-11-24T10:00:00Z""#,
        ] {
            let read = user(text).expect("read");
            assert_eq!(user(&read.to_string()).expect("again"), read, "{text}");
        }
    }
}
