//! The filter parser against the corpus, and over any text.
//!
//! The acceptance of Issue-90: every filter of the corpus is answered or
//! refused for its own reason. What each answered filter finds is checked
//! by the contract, against every store.

use hodor_kernel::UserId;
use hodor_provisioning::api::{
    Filter, FilterRefusal, GroupAttribute, MAX_FILTER_CHARACTERS, MAX_FILTER_COMPARISONS,
    MAX_FILTER_DEPTH, Operator, UserAttribute, Value, ValueFilter, parse,
};
use hodor_provisioning::testing::{Expected, group_corpus, user_corpus};
use proptest::prelude::*;

fn concrete(filter: &str) -> String {
    let mut text = filter.to_owned();
    for name in ["bjensen", "jsmith", "finance", "payables"] {
        text = text.replace(&format!("{{{name}}}"), &UserId::generate().to_string());
    }
    text
}

#[test]
fn every_filter_on_users_is_answered_or_refused_for_its_own_reason() {
    for case in user_corpus() {
        let read = parse::<UserAttribute>(&concrete(&case.filter));
        match case.expected {
            Expected::Finds(_) => assert!(read.is_ok(), "{}: {read:?}", case.filter),
            Expected::Refused(refusal) => {
                assert_eq!(read, Err(refusal), "{}", case.filter);
            }
        }
    }
}

#[test]
fn every_filter_on_groups_is_answered_or_refused_for_its_own_reason() {
    for case in group_corpus() {
        let read = parse::<GroupAttribute>(&concrete(&case.filter));
        match case.expected {
            Expected::Finds(_) => assert!(read.is_ok(), "{}: {read:?}", case.filter),
            Expected::Refused(refusal) => {
                assert_eq!(read, Err(refusal), "{}", case.filter);
            }
        }
    }
}

#[test]
fn every_reason_says_which_bound_or_rule() {
    let detail = |text: &str| {
        parse::<UserAttribute>(text)
            .expect_err("refused")
            .to_string()
    };
    assert_eq!(
        detail(&"a".repeat(MAX_FILTER_CHARACTERS + 1)),
        "a filter holds at most 1000 characters"
    );
    assert_eq!(
        detail(&format!("{}userName pr{}", "(".repeat(11), ")".repeat(11))),
        "a filter nests at most 10 levels deep"
    );
    assert_eq!(
        detail(&vec!["userName pr"; 21].join(" or ")),
        "a filter holds at most 20 comparisons"
    );
    assert_eq!(detail("title pr"), "title cannot be filtered on");
    assert_eq!(
        detail("active gt true"),
        "active cannot be compared with gt"
    );
}

/// A filter on users within the bounds, as a tree.
fn user_filter() -> impl Strategy<Value = Filter<UserAttribute>> {
    let text = "[a-zA-Z0-9 @._'\"\\\\é-]{0,12}";
    let leaf = prop_oneof![
        (
            prop_oneof![
                Just(UserAttribute::Id),
                Just(UserAttribute::ExternalId),
                Just(UserAttribute::UserName),
                Just(UserAttribute::DisplayName),
                Just(UserAttribute::GivenName),
                Just(UserAttribute::FamilyName),
            ],
            prop_oneof![
                Just(Operator::Equal),
                Just(Operator::NotEqual),
                Just(Operator::Contains),
                Just(Operator::StartsWith),
                Just(Operator::EndsWith),
                Just(Operator::Greater),
                Just(Operator::LessOrEqual),
            ],
            text,
        )
            .prop_map(|(attribute, operator, value)| {
                let value = match attribute {
                    UserAttribute::Id | UserAttribute::ExternalId => value,
                    _ => value.to_ascii_lowercase(),
                };
                Filter::Compare(attribute, operator, Value::Text(value))
            }),
        any::<bool>().prop_map(|active| Filter::Compare(
            UserAttribute::Active,
            Operator::Equal,
            Value::Boolean(active)
        )),
        Just(Filter::Present(UserAttribute::ExternalId)),
        text.prop_map(|value| Filter::Any(
            UserAttribute::Emails,
            Box::new(ValueFilter::Compare(
                Operator::Contains,
                Value::Text(value.to_ascii_lowercase())
            ))
        )),
        Just(Filter::Any(
            UserAttribute::Emails,
            Box::new(ValueFilter::Present)
        )),
    ];
    leaf.prop_recursive(3, 12, 2, |inner| {
        prop_oneof![
            (inner.clone(), inner.clone())
                .prop_map(|(left, right)| Filter::And(Box::new(left), Box::new(right))),
            (inner.clone(), inner.clone())
                .prop_map(|(left, right)| Filter::Or(Box::new(left), Box::new(right))),
            inner.prop_map(|inner| Filter::Not(Box::new(inner))),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any text is answered with a tree or a refusal; nothing fails.
    #[test]
    fn any_text_is_read_or_refused(text in "\\PC{0,1200}") {
        let read = parse::<UserAttribute>(&text);
        if text.chars().count() > MAX_FILTER_CHARACTERS {
            prop_assert_eq!(read, Err(FilterRefusal::TooLong));
        }
    }

    /// Text made of the filter's own characters reaches deeper into the
    /// parser, and is still read or refused.
    #[test]
    fn any_text_of_filter_words_is_read_or_refused(
        words in proptest::collection::vec(
            prop_oneof![
                Just("("), Just(")"), Just("["), Just("]"), Just("not"), Just("and"),
                Just("or"), Just("eq"), Just("pr"), Just("co"), Just("userName"),
                Just("emails"), Just("value"), Just("\"a\""), Just("true"), Just("null"),
                Just("12"), Just("meta.created"), Just("\"2026-11-24T10:00:00Z\""),
            ],
            0..80,
        )
    ) {
        let _ = parse::<UserAttribute>(&words.join(" "));
        let _ = parse::<GroupAttribute>(&words.join(" "));
    }

    /// Past a bound of nesting or comparisons, the bound is the reason.
    #[test]
    fn past_a_bound_the_bound_is_the_reason(depth in 0_usize..20, comparisons in 1_usize..30) {
        let nested = format!("{}userName pr{}", "(".repeat(depth), ")".repeat(depth));
        let read = parse::<UserAttribute>(&nested);
        prop_assert_eq!(read.is_err(), depth > MAX_FILTER_DEPTH);
        let many = vec!["userName pr"; comparisons].join(" or ");
        let read = parse::<UserAttribute>(&many);
        if comparisons > MAX_FILTER_COMPARISONS {
            prop_assert_eq!(read, Err(FilterRefusal::TooManyComparisons));
        } else {
            prop_assert!(read.is_ok());
        }
    }

    /// A filter written out reads back as the same tree.
    #[test]
    fn a_written_filter_reads_back_the_same(filter in user_filter()) {
        let text = filter.to_string();
        prop_assume!(text.chars().count() <= MAX_FILTER_CHARACTERS);
        prop_assert_eq!(parse::<UserAttribute>(&text), Ok(filter), "{}", text);
    }
}
