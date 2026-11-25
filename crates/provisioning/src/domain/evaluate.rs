//! Whether a resource satisfies a filter, worked out from the values it
//! has: what the in-memory store does, and what the SQL of the PostgreSQL
//! store must agree with.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`,
//! "Comparisons".

use crate::domain::attribute::{Attribute, AttributeType, fold_case};
use crate::domain::filter::{Filter, Operator, Value, ValueFilter};
use hodor_kernel::Timestamp;
use std::cmp::Ordering;

/// One value of an attribute of a resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact {
    /// Text, as it is kept.
    Text(String),
    /// `true` or `false`.
    Boolean(bool),
    /// A date and time.
    DateTime(Timestamp),
}

/// The values a resource has for the attributes a filter may name.
pub trait Facts<A: Attribute> {
    /// The value of a single-valued attribute, if it has one.
    fn value(&self, attribute: A) -> Option<Fact>;
    /// Every value of a multi-valued attribute.
    fn values(&self, attribute: A) -> Vec<Fact>;
}

/// Whether the resource whose values are `facts` satisfies `filter`.
pub fn matches<A: Attribute>(filter: &Filter<A>, facts: &dyn Facts<A>) -> bool {
    match filter {
        Filter::Compare(attribute, operator, value) => facts
            .value(*attribute)
            .is_some_and(|fact| compare(&fact, *operator, value, attribute.value_type())),
        Filter::Present(attribute) => facts.value(*attribute).is_some(),
        Filter::Any(attribute, condition) => facts
            .values(*attribute)
            .iter()
            .any(|fact| satisfies(condition, fact, attribute.value_type())),
        Filter::And(left, right) => matches(left, facts) && matches(right, facts),
        Filter::Or(left, right) => matches(left, facts) || matches(right, facts),
        Filter::Not(inner) => !matches(inner, facts),
    }
}

fn satisfies(condition: &ValueFilter, fact: &Fact, value_type: AttributeType) -> bool {
    match condition {
        ValueFilter::Compare(operator, value) => compare(fact, *operator, value, value_type),
        ValueFilter::Present => true,
        ValueFilter::And(left, right) => {
            satisfies(left, fact, value_type) && satisfies(right, fact, value_type)
        }
        ValueFilter::Or(left, right) => {
            satisfies(left, fact, value_type) || satisfies(right, fact, value_type)
        }
        ValueFilter::Not(inner) => !satisfies(inner, fact, value_type),
    }
}

fn ordered(ordering: Ordering, operator: Operator) -> bool {
    match operator {
        Operator::Equal => ordering == Ordering::Equal,
        Operator::NotEqual => ordering != Ordering::Equal,
        Operator::Greater => ordering == Ordering::Greater,
        Operator::GreaterOrEqual => ordering != Ordering::Less,
        Operator::Less => ordering == Ordering::Less,
        Operator::LessOrEqual => ordering != Ordering::Greater,
        Operator::Contains | Operator::StartsWith | Operator::EndsWith => false,
    }
}

/// Compares a value a resource has with the value of a comparison. The
/// comparison's text is already folded when its attribute is compared
/// without regard to case.
fn compare(fact: &Fact, operator: Operator, value: &Value, value_type: AttributeType) -> bool {
    match (fact, value) {
        (Fact::Text(fact), Value::Text(value)) => {
            let fact = match value_type {
                AttributeType::Text { exact: false } => fold_case(fact),
                _ => fact.clone(),
            };
            match operator {
                Operator::Contains => fact.contains(value.as_str()),
                Operator::StartsWith => fact.starts_with(value.as_str()),
                Operator::EndsWith => fact.ends_with(value.as_str()),
                _ => ordered(fact.as_str().cmp(value.as_str()), operator),
            }
        }
        (Fact::Boolean(fact), Value::Boolean(value)) => ordered(fact.cmp(value), operator),
        (Fact::DateTime(fact), Value::DateTime(value)) => ordered(fact.cmp(value), operator),
        _ => false,
    }
}

/// How two values of an attribute a list is sorted by compare, the way
/// the attribute is compared. A missing value sorts after every value.
#[must_use]
pub fn sort_order(
    left: Option<&Fact>,
    right: Option<&Fact>,
    value_type: AttributeType,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(Fact::Text(left)), Some(Fact::Text(right))) => match value_type {
            AttributeType::Text { exact: false } => fold_case(left).cmp(&fold_case(right)),
            _ => left.cmp(right),
        },
        (Some(Fact::Boolean(left)), Some(Fact::Boolean(right))) => left.cmp(right),
        (Some(Fact::DateTime(left)), Some(Fact::DateTime(right))) => left.cmp(right),
        _ => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::attribute::UserAttribute;
    use crate::domain::filter::parse;

    struct Person {
        user_name: &'static str,
        emails: Vec<&'static str>,
        external_id: Option<&'static str>,
    }

    impl Facts<UserAttribute> for Person {
        fn value(&self, attribute: UserAttribute) -> Option<Fact> {
            match attribute {
                UserAttribute::UserName => Some(Fact::Text(self.user_name.to_owned())),
                UserAttribute::ExternalId => self.external_id.map(|id| Fact::Text(id.to_owned())),
                UserAttribute::Active => Some(Fact::Boolean(true)),
                _ => None,
            }
        }

        fn values(&self, attribute: UserAttribute) -> Vec<Fact> {
            match attribute {
                UserAttribute::Emails => self
                    .emails
                    .iter()
                    .map(|email| Fact::Text((*email).to_owned()))
                    .collect(),
                _ => Vec::new(),
            }
        }
    }

    fn holds(text: &str, person: &Person) -> bool {
        matches(&parse::<UserAttribute>(text).expect("a filter"), person)
    }

    #[test]
    fn comparisons_follow_the_rules_of_the_page() {
        let ana = Person {
            user_name: "ana.silva",
            emails: vec!["ana@example.com", "ana@home.org"],
            external_id: None,
        };
        assert!(holds(r#"userName eq "ANA.SILVA""#, &ana));
        assert!(holds(r#"emails.value ne "ana@example.com""#, &ana));
        assert!(!holds(
            r#"emails[value sw "ana@e" and value ew ".org"]"#,
            &ana
        ));
        assert!(holds(
            r#"emails.value sw "ana@e" and emails.value ew ".org""#,
            &ana
        ));
        // A comparison with a missing value is false, whatever the operator.
        assert!(!holds(r#"externalId ne "x""#, &ana));
        assert!(holds(r#"not (externalId eq "x")"#, &ana));
        assert!(holds("externalId eq null", &ana));
        assert!(holds(r#"userName gt "ana" and userName lt "anb""#, &ana));
    }

    #[test]
    fn a_missing_value_sorts_last() {
        let text = |value: &str| Fact::Text(value.to_owned());
        let case = AttributeType::Text { exact: false };
        assert_eq!(
            sort_order(Some(&text("B")), Some(&text("a")), case),
            Ordering::Greater
        );
        assert_eq!(sort_order(None, Some(&text("a")), case), Ordering::Greater);
    }
}
