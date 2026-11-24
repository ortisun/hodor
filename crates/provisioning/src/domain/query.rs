//! What a list asks for: a filter, an order and a page.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Lists".

use crate::domain::attribute::Attribute;
use crate::domain::error::{invalid_filter, invalid_value};
use crate::domain::filter::{Filter, parse};
use hodor_kernel::DomainError;

/// How many resources a page holds when the request does not say.
pub const DEFAULT_COUNT: u32 = 100;
/// The most resources a page holds.
pub const MAX_COUNT: u32 = 200;

/// Which way a list is sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    /// Smallest first; a resource without a value last.
    Ascending,
    /// Largest first; a resource without a value first.
    Descending,
}

/// A list's query parameters, as the request wrote them.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListParameters<'a> {
    /// `filter`.
    pub filter: Option<&'a str>,
    /// `sortBy`.
    pub sort_by: Option<&'a str>,
    /// `sortOrder`.
    pub sort_order: Option<&'a str>,
    /// `startIndex`.
    pub start_index: Option<&'a str>,
    /// `count`.
    pub count: Option<&'a str>,
}

/// What a list asks for, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListQuery<A> {
    /// Which resources; every one without a filter.
    pub filter: Option<Filter<A>>,
    /// The attribute to sort by and which way; the order of creation
    /// without one.
    pub sort: Option<(A, SortOrder)>,
    /// Where the page starts, the first resource being 1.
    pub start_index: u64,
    /// How many the page holds, at most [`MAX_COUNT`]; 0 for none.
    pub count: u32,
}

impl<A: Attribute> Default for ListQuery<A> {
    fn default() -> Self {
        Self {
            filter: None,
            sort: None,
            start_index: 1,
            count: DEFAULT_COUNT,
        }
    }
}

fn number(name: &str, text: &str) -> Result<i64, DomainError> {
    text.trim()
        .parse::<i64>()
        .map_err(|_| invalid_value(format!("{name} is a whole number")))
}

impl<A: Attribute> ListQuery<A> {
    /// Reads the query parameters of a list.
    ///
    /// # Errors
    ///
    /// `Invalid` with code `provisioning.invalid_filter` for a filter that
    /// is refused, and `provisioning.invalid_value` for a `sortBy` that
    /// cannot be sorted by, a `sortOrder` that is neither `ascending` nor
    /// `descending`, or a `startIndex` or `count` that is not a number.
    pub fn read(parameters: &ListParameters<'_>) -> Result<Self, DomainError> {
        let filter = parameters
            .filter
            .map(|text| parse::<A>(text).map_err(|refusal| invalid_filter(&refusal)))
            .transpose()?;
        let order = match parameters.sort_order {
            None => SortOrder::Ascending,
            Some(order) if order.eq_ignore_ascii_case("ascending") => SortOrder::Ascending,
            Some(order) if order.eq_ignore_ascii_case("descending") => SortOrder::Descending,
            Some(_) => {
                return Err(invalid_value(
                    "sortOrder is ascending or descending".to_owned(),
                ));
            }
        };
        let sort = parameters
            .sort_by
            .map(|name| {
                A::sort_named(name)
                    .map(|attribute| (attribute, order))
                    .ok_or_else(|| invalid_value(format!("a list cannot be sorted by {name}")))
            })
            .transpose()?;
        let start_index = parameters
            .start_index
            .map(|text| number("startIndex", text))
            .transpose()?
            .map_or(1, |index| u64::try_from(index.max(1)).unwrap_or(1));
        let count = parameters
            .count
            .map(|text| number("count", text))
            .transpose()?
            .map_or(DEFAULT_COUNT, |count| {
                u32::try_from(count.clamp(0, i64::from(MAX_COUNT))).unwrap_or(MAX_COUNT)
            });
        Ok(Self {
            filter,
            sort,
            start_index,
            count,
        })
    }

    /// How many resources come before the page.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.start_index.saturating_sub(1)
    }
}

/// What a store found: how many match, and the identifiers on the page,
/// in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found<I> {
    /// How many resources match the filter, whatever the page.
    pub total: u64,
    /// The identifiers of the resources on the page.
    pub ids: Vec<I>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::attribute::{GroupAttribute, UserAttribute};

    #[test]
    fn pages_are_bounded_and_counted_from_one() {
        let read = |start_index: &str, count: &str| {
            ListQuery::<UserAttribute>::read(&ListParameters {
                start_index: Some(start_index),
                count: Some(count),
                ..ListParameters::default()
            })
            .expect("read")
        };
        let query = read("0", "500");
        assert_eq!((query.start_index, query.count), (1, MAX_COUNT));
        let query = read("-4", "-1");
        assert_eq!((query.start_index, query.count), (1, 0));
        let query = read("11", "5");
        assert_eq!((query.offset(), query.count), (10, 5));
        let query = ListQuery::<UserAttribute>::read(&ListParameters::default()).expect("read");
        assert_eq!((query.start_index, query.count), (1, DEFAULT_COUNT));
    }

    #[test]
    fn only_the_sortable_attributes_sort() {
        let sorted = |sort_by: &str, sort_order: Option<&str>| {
            ListQuery::<GroupAttribute>::read(&ListParameters {
                sort_by: Some(sort_by),
                sort_order,
                ..ListParameters::default()
            })
        };
        assert_eq!(
            sorted("displayName", Some("Descending"))
                .expect("sorted")
                .sort,
            Some((GroupAttribute::DisplayName, SortOrder::Descending))
        );
        assert_eq!(
            sorted("members.value", None).expect_err("refused").code(),
            "provisioning.invalid_value"
        );
        assert_eq!(
            sorted("displayName", Some("sideways"))
                .expect_err("refused")
                .code(),
            "provisioning.invalid_value"
        );
        assert!(
            ListQuery::<UserAttribute>::read(&ListParameters {
                count: Some("many"),
                ..ListParameters::default()
            })
            .is_err()
        );
    }
}
