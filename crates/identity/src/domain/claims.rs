//! A person's standard claims: the names, addresses of pages, birth date,
//! time zone, telephone number and postal address OpenID Connect Core,
//! section 5.1, names.
//!
//! Specified in `docs/architecture/contexts/identity.md`, "Standard
//! claims", and Decision 0065. Every rule is checked here, on values; the
//! messages of a refusal name the claim and never its value, which is
//! personal data.

use hodor_kernel::{DomainError, Timestamp};
use time::{Date, Month};

/// The longest name: given, family, middle name and nickname.
pub const LONGEST_NAME: usize = 200;
/// The longest address of a page: `profile`, `picture`, `website`.
pub const LONGEST_PAGE_ADDRESS: usize = 1024;
/// The longest gender.
pub const LONGEST_GENDER: usize = 50;
/// The longest time zone name.
pub const LONGEST_ZONEINFO: usize = 64;
/// The longest telephone number as it is kept: `+`, 15 digits, `;ext=`
/// and 10 digits.
pub const LONGEST_PHONE_NUMBER: usize = 31;
/// The longest birth date as it is kept.
pub const LONGEST_BIRTHDATE: usize = 10;
/// The longest formatted address.
pub const LONGEST_FORMATTED_ADDRESS: usize = 300;
/// The longest street address.
pub const LONGEST_STREET_ADDRESS: usize = 200;
/// The longest locality, region and country.
pub const LONGEST_ADDRESS_PART: usize = 100;
/// The longest postal code.
pub const LONGEST_POSTAL_CODE: usize = 20;

/// A postal address, in the parts OpenID Connect names. It exists when one
/// part has a value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PostalAddress {
    /// The whole address as it would be written on a letter.
    pub formatted: Option<String>,
    /// The street, house number and anything else of that line.
    pub street_address: Option<String>,
    /// The city or locality.
    pub locality: Option<String>,
    /// The state, province or region.
    pub region: Option<String>,
    /// The postal code.
    pub postal_code: Option<String>,
    /// The country.
    pub country: Option<String>,
}

impl PostalAddress {
    /// Whether no part has a value.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Each part with its name as OpenID Connect writes it, in order.
    #[must_use]
    pub fn parts(&self) -> [(&'static str, Option<&str>); 6] {
        [
            ("formatted", self.formatted.as_deref()),
            ("street_address", self.street_address.as_deref()),
            ("locality", self.locality.as_deref()),
            ("region", self.region.as_deref()),
            ("postal_code", self.postal_code.as_deref()),
            ("country", self.country.as_deref()),
        ]
    }
}

/// A person's standard claims. Every one is optional; together they are one
/// value, replaced as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StandardClaims {
    /// `given_name`.
    pub given_name: Option<String>,
    /// `family_name`.
    pub family_name: Option<String>,
    /// `middle_name`.
    pub middle_name: Option<String>,
    /// `nickname`.
    pub nickname: Option<String>,
    /// `profile`: the address of the person's page elsewhere.
    pub profile: Option<String>,
    /// `picture`: the address of a picture of the person.
    pub picture: Option<String>,
    /// `website`: the address of the person's site.
    pub website: Option<String>,
    /// `gender`.
    pub gender: Option<String>,
    /// `birthdate`: `YYYY-MM-DD`, `0000-MM-DD` or `YYYY`.
    pub birthdate: Option<String>,
    /// `zoneinfo`: a name of the time zone database.
    pub zoneinfo: Option<String>,
    /// `phone_number`, in E.164 with an optional extension.
    pub phone_number: Option<String>,
    /// `phone_number_verified`: whether someone vouched for the number.
    pub phone_number_verified: bool,
    /// `address`.
    pub address: Option<PostalAddress>,
}

/// One claim, or one part of the address, as a value of text: what an
/// interface sets one at a time and what a provider maps an attribute to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimField {
    /// `given_name`.
    GivenName,
    /// `family_name`.
    FamilyName,
    /// `middle_name`.
    MiddleName,
    /// `nickname`.
    Nickname,
    /// `profile`.
    Profile,
    /// `picture`.
    Picture,
    /// `website`.
    Website,
    /// `gender`.
    Gender,
    /// `birthdate`.
    Birthdate,
    /// `zoneinfo`.
    Zoneinfo,
    /// `phone_number`.
    PhoneNumber,
    /// `address.formatted`.
    AddressFormatted,
    /// `address.street_address`.
    AddressStreetAddress,
    /// `address.locality`.
    AddressLocality,
    /// `address.region`.
    AddressRegion,
    /// `address.postal_code`.
    AddressPostalCode,
    /// `address.country`.
    AddressCountry,
}

impl ClaimField {
    /// Every field, in the order of the claims.
    pub const ALL: [Self; 17] = [
        Self::GivenName,
        Self::FamilyName,
        Self::MiddleName,
        Self::Nickname,
        Self::Profile,
        Self::Picture,
        Self::Website,
        Self::Gender,
        Self::Birthdate,
        Self::Zoneinfo,
        Self::PhoneNumber,
        Self::AddressFormatted,
        Self::AddressStreetAddress,
        Self::AddressLocality,
        Self::AddressRegion,
        Self::AddressPostalCode,
        Self::AddressCountry,
    ];

    /// Its name: the claim's, or `address.` and the part's.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GivenName => "given_name",
            Self::FamilyName => "family_name",
            Self::MiddleName => "middle_name",
            Self::Nickname => "nickname",
            Self::Profile => "profile",
            Self::Picture => "picture",
            Self::Website => "website",
            Self::Gender => "gender",
            Self::Birthdate => "birthdate",
            Self::Zoneinfo => "zoneinfo",
            Self::PhoneNumber => "phone_number",
            Self::AddressFormatted => "address.formatted",
            Self::AddressStreetAddress => "address.street_address",
            Self::AddressLocality => "address.locality",
            Self::AddressRegion => "address.region",
            Self::AddressPostalCode => "address.postal_code",
            Self::AddressCountry => "address.country",
        }
    }

    /// The field of a name, if it is one.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.as_str() == name)
    }

    /// The rule a value breaks, as a refusal says it.
    const fn rule(self) -> &'static str {
        match self {
            Self::GivenName | Self::FamilyName | Self::MiddleName | Self::Nickname => {
                "is 1 to 200 characters without control characters"
            }
            Self::Profile | Self::Picture | Self::Website => {
                "is an absolute https or http address with a host, at most 1024 printable ASCII \
                 characters without spaces, double quotes or backslashes"
            }
            Self::Gender => "is 1 to 50 characters without control characters",
            Self::Birthdate => {
                "is YYYY-MM-DD, 0000-MM-DD or YYYY, a day of the calendar not after today"
            }
            Self::Zoneinfo => {
                "is a name of the time zone database such as Europe/Paris, at most 64 characters"
            }
            Self::PhoneNumber => {
                "is + and 4 to 15 digits, with an optional ;ext= and 1 to 10 digits"
            }
            Self::AddressFormatted => {
                "is at most 300 characters, without control characters but line breaks"
            }
            Self::AddressStreetAddress => {
                "is at most 200 characters, without control characters but line breaks"
            }
            Self::AddressLocality | Self::AddressRegion | Self::AddressCountry => {
                "is at most 100 characters without control characters"
            }
            Self::AddressPostalCode => "is at most 20 characters without control characters",
        }
    }

    /// The value written as it is kept, `None` for no value, or `Err` if it
    /// breaks the rule.
    fn normalized(self, value: &str, today: Date) -> Result<Option<String>, ()> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        let good = match self {
            Self::GivenName | Self::FamilyName | Self::MiddleName | Self::Nickname => {
                plain(value, LONGEST_NAME, false)
            }
            Self::Profile | Self::Picture | Self::Website => is_page_address(value),
            Self::Gender => plain(value, LONGEST_GENDER, false),
            Self::Birthdate => is_birthdate(value, today),
            Self::Zoneinfo => is_zoneinfo(value),
            Self::PhoneNumber => return phone_number(value).map(Some).ok_or(()),
            Self::AddressFormatted => plain(value, LONGEST_FORMATTED_ADDRESS, true),
            Self::AddressStreetAddress => plain(value, LONGEST_STREET_ADDRESS, true),
            Self::AddressLocality | Self::AddressRegion | Self::AddressCountry => {
                plain(value, LONGEST_ADDRESS_PART, false)
            }
            Self::AddressPostalCode => plain(value, LONGEST_POSTAL_CODE, false),
        };
        if good {
            Ok(Some(value.to_owned()))
        } else {
            Err(())
        }
    }
}

/// Text of 1 to `longest` characters without control characters, but line
/// breaks where `lines` allows them.
fn plain(value: &str, longest: usize, lines: bool) -> bool {
    value.chars().count() <= longest
        && !value
            .chars()
            .any(|c| c.is_control() && !(lines && matches!(c, '\n' | '\r')))
}

/// An absolute `https` or `http` address with a host, at most 1024 printable
/// ASCII characters other than a double quote and a backslash.
fn is_page_address(value: &str) -> bool {
    if value.len() > LONGEST_PAGE_ADDRESS
        || !value
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\'))
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
    else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !host.is_empty() && !host.contains('@')
}

/// `YYYY-MM-DD`, `0000-MM-DD` or `YYYY`: a day that exists, or a year,
/// not after `today`.
fn is_birthdate(value: &str, today: Date) -> bool {
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    let number = |text: &str| text.parse::<i32>().ok();
    match value.split('-').collect::<Vec<_>>().as_slice() {
        [year] if year.len() == 4 && digits(year) => {
            number(year).is_some_and(|year| year >= 1 && year <= today.year())
        }
        [year, month, day]
            if year.len() == 4
                && month.len() == 2
                && day.len() == 2
                && digits(year)
                && digits(month)
                && digits(day) =>
        {
            let (Some(year), Some(month), Some(day)) = (number(year), number(month), number(day))
            else {
                return false;
            };
            let Some(month) = u8::try_from(month)
                .ok()
                .and_then(|month| Month::try_from(month).ok())
            else {
                return false;
            };
            let Ok(day) = u8::try_from(day) else {
                return false;
            };
            if year == 0 {
                // The year is not told: any day that exists in some year,
                // the 29th of February included.
                return Date::from_calendar_date(2000, month, day).is_ok();
            }
            Date::from_calendar_date(year, month, day).is_ok_and(|date| date <= today)
        }
        _ => false,
    }
}

/// A name of the time zone database: parts separated by `/`, each starting
/// with a letter and made of letters, digits, `_`, `-` and `+`.
fn is_zoneinfo(value: &str) -> bool {
    value.len() <= LONGEST_ZONEINFO
        && value.split('/').all(|part| {
            part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+'))
        })
}

/// A telephone number in E.164, with what separates its digits taken out:
/// `+` and 4 to 15 digits, then optionally `;ext=` and 1 to 10 digits.
fn phone_number(value: &str) -> Option<String> {
    let kept: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')'))
        .collect();
    let (number, extension) = match kept.split_once(";ext=") {
        Some((number, extension)) => (number, Some(extension)),
        None => (kept.as_str(), None),
    };
    let digits = number.strip_prefix('+')?;
    let good = (4..=15).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
        && extension.is_none_or(|extension| {
            (1..=10).contains(&extension.len()) && extension.bytes().all(|b| b.is_ascii_digit())
        });
    good.then_some(kept)
}

impl StandardClaims {
    /// Whether the person has none of them.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The value of one field.
    #[must_use]
    pub fn get(&self, field: ClaimField) -> Option<&str> {
        let address = self.address.as_ref();
        let part = |of: fn(&PostalAddress) -> &Option<String>| {
            address.and_then(|address| of(address).as_deref())
        };
        match field {
            ClaimField::GivenName => self.given_name.as_deref(),
            ClaimField::FamilyName => self.family_name.as_deref(),
            ClaimField::MiddleName => self.middle_name.as_deref(),
            ClaimField::Nickname => self.nickname.as_deref(),
            ClaimField::Profile => self.profile.as_deref(),
            ClaimField::Picture => self.picture.as_deref(),
            ClaimField::Website => self.website.as_deref(),
            ClaimField::Gender => self.gender.as_deref(),
            ClaimField::Birthdate => self.birthdate.as_deref(),
            ClaimField::Zoneinfo => self.zoneinfo.as_deref(),
            ClaimField::PhoneNumber => self.phone_number.as_deref(),
            ClaimField::AddressFormatted => part(|a| &a.formatted),
            ClaimField::AddressStreetAddress => part(|a| &a.street_address),
            ClaimField::AddressLocality => part(|a| &a.locality),
            ClaimField::AddressRegion => part(|a| &a.region),
            ClaimField::AddressPostalCode => part(|a| &a.postal_code),
            ClaimField::AddressCountry => part(|a| &a.country),
        }
    }

    /// Sets one field, as given: nothing is checked until
    /// [`StandardClaims::checked`]. The address exists while one of its
    /// parts has a value.
    pub fn set(&mut self, field: ClaimField, value: Option<String>) {
        let slot = match field {
            ClaimField::GivenName => &mut self.given_name,
            ClaimField::FamilyName => &mut self.family_name,
            ClaimField::MiddleName => &mut self.middle_name,
            ClaimField::Nickname => &mut self.nickname,
            ClaimField::Profile => &mut self.profile,
            ClaimField::Picture => &mut self.picture,
            ClaimField::Website => &mut self.website,
            ClaimField::Gender => &mut self.gender,
            ClaimField::Birthdate => &mut self.birthdate,
            ClaimField::Zoneinfo => &mut self.zoneinfo,
            ClaimField::PhoneNumber => &mut self.phone_number,
            part => {
                let address = self.address.get_or_insert_with(PostalAddress::default);
                let slot = match part {
                    ClaimField::AddressFormatted => &mut address.formatted,
                    ClaimField::AddressStreetAddress => &mut address.street_address,
                    ClaimField::AddressLocality => &mut address.locality,
                    ClaimField::AddressRegion => &mut address.region,
                    ClaimField::AddressPostalCode => &mut address.postal_code,
                    _ => &mut address.country,
                };
                *slot = value;
                if address.is_empty() {
                    self.address = None;
                }
                return;
            }
        };
        *slot = value;
    }

    /// The claims as they are kept: every text trimmed, an empty one no
    /// value, the telephone number without what separates its digits, no
    /// address without a part, and no verified number without a number.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` with code `identity.claim_invalid` for the first
    /// field that breaks its rule. The message names the field, never the
    /// value.
    pub fn checked(self, now: Timestamp) -> Result<Self, DomainError> {
        self.normalized(now, |field| {
            Err(DomainError::invalid(
                "identity.claim_invalid",
                format!("{} {}", field.as_str(), field.rule()),
            ))
        })
    }

    /// As [`StandardClaims::checked`], but a field that breaks its rule is
    /// left out and the others are kept: for what an identity provider
    /// says, which nobody can correct before the person signs in.
    #[must_use]
    pub fn lenient(self, now: Timestamp) -> Self {
        self.normalized(now, |_| Ok(None)).unwrap_or_default()
    }

    fn normalized(
        self,
        now: Timestamp,
        broken: impl Fn(ClaimField) -> Result<Option<String>, DomainError>,
    ) -> Result<Self, DomainError> {
        let today = now.date();
        let mut kept = Self::default();
        for field in ClaimField::ALL {
            let value = match self.get(field) {
                Some(value) => match field.normalized(value, today) {
                    Ok(value) => value,
                    Err(()) => broken(field)?,
                },
                None => None,
            };
            kept.set(field, value);
        }
        kept.phone_number_verified = self.phone_number_verified && kept.phone_number.is_some();
        Ok(kept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{OffsetDateTime, Time};

    /// Noon of 2026-11-25.
    fn now() -> Timestamp {
        let day = Date::from_calendar_date(2026, Month::November, 25).expect("a day");
        OffsetDateTime::new_utc(day, Time::from_hms(12, 0, 0).expect("noon"))
    }

    fn with(field: ClaimField, value: &str) -> StandardClaims {
        let mut claims = StandardClaims::default();
        claims.set(field, Some(value.to_owned()));
        claims
    }

    fn accepted(field: ClaimField, value: &str) -> Option<String> {
        with(field, value)
            .checked(now())
            .unwrap_or_else(|error| panic!("{} {value:?}: {error}", field.as_str()))
            .get(field)
            .map(str::to_owned)
    }

    fn refused(field: ClaimField, value: &str) {
        let error = with(field, value)
            .checked(now())
            .expect_err(&format!("{} {value:?} is refused", field.as_str()));
        assert_eq!(error.code(), "identity.claim_invalid");
        assert!(error.message().starts_with(field.as_str()));
    }

    #[test]
    fn every_field_has_a_name_that_reads_back() {
        for field in ClaimField::ALL {
            assert_eq!(ClaimField::parse(field.as_str()), Some(field));
        }
        assert_eq!(ClaimField::parse("address"), None);
        assert_eq!(ClaimField::parse("name"), None);
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(
            accepted(ClaimField::GivenName, "  Ana  ").as_deref(),
            Some("Ana")
        );
        assert_eq!(accepted(ClaimField::FamilyName, "   "), None);
        assert!(accepted(ClaimField::Nickname, &"é".repeat(200)).is_some());
        refused(ClaimField::MiddleName, &"a".repeat(201));
        refused(ClaimField::GivenName, "Ana\u{0}");
        refused(ClaimField::GivenName, "Ana\nMaria");
        assert!(accepted(ClaimField::Gender, "non-binary").is_some());
        refused(ClaimField::Gender, &"g".repeat(51));
    }

    #[test]
    fn addresses_of_pages_are_absolute_and_plain() {
        for good in [
            "https://example.com",
            "http://example.com/ana?x=1#y",
            "HTTPS://Example.com/Ana",
        ] {
            assert_eq!(accepted(ClaimField::Picture, good).as_deref(), Some(good));
        }
        for bad in [
            "example.com",
            "ftp://example.com",
            "https://",
            "https:///path",
            "https://user@example.com",
            "https://example.com/a b",
            "https://example.com/\"",
            "https://example.com/é",
            &format!("https://example.com/{}", "a".repeat(1010)),
        ] {
            refused(ClaimField::Website, bad);
        }
    }

    #[test]
    fn a_birth_date_is_a_day_a_year_or_a_day_without_its_year() {
        for good in [
            "1990-04-12",
            "0000-02-29",
            "1990",
            "2026-11-25",
            "2024-02-29",
        ] {
            assert_eq!(accepted(ClaimField::Birthdate, good).as_deref(), Some(good));
        }
        for bad in [
            "2026-11-26",
            "2027",
            "0000",
            "1990-13-01",
            "1990-02-30",
            "2023-02-29",
            "1990-4-12",
            "12/04/1990",
            "1990-04-12T00:00",
            "+990-04-12",
        ] {
            refused(ClaimField::Birthdate, bad);
        }
    }

    #[test]
    fn a_time_zone_has_the_shape_of_the_database() {
        for good in [
            "Europe/Paris",
            "America/Argentina/Buenos_Aires",
            "UTC",
            "Etc/GMT+3",
            "America/Port-au-Prince",
        ] {
            assert_eq!(accepted(ClaimField::Zoneinfo, good).as_deref(), Some(good));
        }
        for bad in [
            "Europe/",
            "/Paris",
            "Europe//Paris",
            "3/Paris",
            "Europe/Pa ris",
            &"A".repeat(65),
        ] {
            refused(ClaimField::Zoneinfo, bad);
        }
    }

    #[test]
    fn a_telephone_number_is_kept_in_e164() {
        assert_eq!(
            accepted(ClaimField::PhoneNumber, "+1 (604) 555-1234").as_deref(),
            Some("+16045551234")
        );
        assert_eq!(
            accepted(ClaimField::PhoneNumber, "+1.604.555.1234;ext=5678").as_deref(),
            Some("+16045551234;ext=5678")
        );
        for bad in [
            "6045551234",
            "+123",
            "+1234567890123456",
            "+1604555123a",
            "+16045551234;ext=",
            "+16045551234;ext=12345678901",
            "+16045551234 ext 5",
        ] {
            refused(ClaimField::PhoneNumber, bad);
        }
    }

    #[test]
    fn an_address_exists_while_one_part_has_a_value() {
        let mut claims = StandardClaims::default();
        claims.set(ClaimField::AddressLocality, Some("São Paulo".to_owned()));
        claims.set(
            ClaimField::AddressStreetAddress,
            Some("Rua A, 1\nApto 2".to_owned()),
        );
        let kept = claims.clone().checked(now()).expect("good");
        assert_eq!(kept.get(ClaimField::AddressLocality), Some("São Paulo"));
        assert_eq!(
            kept.get(ClaimField::AddressStreetAddress),
            Some("Rua A, 1\nApto 2")
        );
        claims.set(ClaimField::AddressLocality, None);
        claims.set(ClaimField::AddressStreetAddress, Some("  ".to_owned()));
        assert_eq!(claims.checked(now()).expect("good").address, None);
        refused(ClaimField::AddressPostalCode, &"1".repeat(21));
        refused(ClaimField::AddressCountry, "B\tR");
        refused(ClaimField::AddressFormatted, &"a".repeat(301));
        assert!(accepted(ClaimField::AddressFormatted, "a\r\nb").is_some());
    }

    #[test]
    fn a_number_is_verified_only_when_there_is_one() {
        let claims = StandardClaims {
            phone_number_verified: true,
            ..StandardClaims::default()
        };
        assert!(!claims.checked(now()).expect("good").phone_number_verified);
        let claims = StandardClaims {
            phone_number: Some("+5511912345678".to_owned()),
            phone_number_verified: true,
            ..StandardClaims::default()
        };
        assert!(claims.checked(now()).expect("good").phone_number_verified);
    }

    #[test]
    fn a_refusal_names_the_claim_and_never_the_value() {
        let error = with(ClaimField::Birthdate, "31/12/1999")
            .checked(now())
            .expect_err("refused");
        assert!(error.message().contains("birthdate"));
        assert!(!error.message().contains("1999"));
    }

    #[test]
    fn leniently_a_broken_claim_is_left_out_and_the_others_kept() {
        let mut claims = with(ClaimField::GivenName, "Ana");
        claims.set(ClaimField::PhoneNumber, Some("not a number".to_owned()));
        claims.set(ClaimField::AddressCountry, Some("BR".to_owned()));
        claims.phone_number_verified = true;
        let kept = claims.lenient(now());
        assert_eq!(kept.given_name.as_deref(), Some("Ana"));
        assert_eq!(kept.phone_number, None);
        assert!(!kept.phone_number_verified);
        assert_eq!(kept.get(ClaimField::AddressCountry), Some("BR"));
    }
}
