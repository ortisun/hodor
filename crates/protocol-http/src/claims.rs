//! A person's standard claims as the administration interface and the
//! interaction interface write them.
//!
//! Specified in `docs/api/admin-api.md`, "A user's standard claims", and
//! `docs/api/interaction-api.md`, "The person's profile". No `Debug`
//! prints a value: the claims are personal data.

use hodor_identity::api::{PostalAddress, StandardClaims};
use serde::{Deserialize, Serialize};

/// The parts of a postal address.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    formatted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    street_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    locality: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    postal_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    country: Option<String>,
}

/// A person's standard claims. In an answer, those with a value and
/// `phone_number_verified`; in a request, every member optional.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimsBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    given_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    family_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    middle_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nickname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    picture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    website: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gender: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    birthdate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    zoneinfo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone_number_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<AddressBody>,
}

impl ClaimsBody {
    /// The claims of a person, as an answer writes them; none for a
    /// workload, which has none.
    pub(crate) fn of(claims: &StandardClaims, person: bool) -> Self {
        if !person {
            return Self::default();
        }
        Self {
            given_name: claims.given_name.clone(),
            family_name: claims.family_name.clone(),
            middle_name: claims.middle_name.clone(),
            nickname: claims.nickname.clone(),
            profile: claims.profile.clone(),
            picture: claims.picture.clone(),
            website: claims.website.clone(),
            gender: claims.gender.clone(),
            birthdate: claims.birthdate.clone(),
            zoneinfo: claims.zoneinfo.clone(),
            phone_number: claims.phone_number.clone(),
            phone_number_verified: Some(claims.phone_number_verified),
            address: claims.address.as_ref().map(|address| AddressBody {
                formatted: address.formatted.clone(),
                street_address: address.street_address.clone(),
                locality: address.locality.clone(),
                region: address.region.clone(),
                postal_code: address.postal_code.clone(),
                country: address.country.clone(),
            }),
        }
    }

    /// The claims a request gives, unchecked: the identity context checks
    /// them. `phone_number_verified` is false unless given.
    pub(crate) fn into_claims(self) -> StandardClaims {
        StandardClaims {
            given_name: self.given_name,
            family_name: self.family_name,
            middle_name: self.middle_name,
            nickname: self.nickname,
            profile: self.profile,
            picture: self.picture,
            website: self.website,
            gender: self.gender,
            birthdate: self.birthdate,
            zoneinfo: self.zoneinfo,
            phone_number: self.phone_number,
            phone_number_verified: self.phone_number_verified.unwrap_or(false),
            address: self.address.map(|address| PostalAddress {
                formatted: address.formatted,
                street_address: address.street_address,
                locality: address.locality,
                region: address.region,
                postal_code: address.postal_code,
                country: address.country,
            }),
        }
    }
}

impl std::fmt::Debug for ClaimsBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Personal data: never printed.
        f.debug_struct("ClaimsBody").finish_non_exhaustive()
    }
}
