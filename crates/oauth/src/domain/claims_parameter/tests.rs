//! The `claims` parameter, read, resolved against consent, and added to an
//! ID token within its bound.

use super::*;
use hodor_identity::api::{PostalAddress, StandardClaims};
use serde_json::json;

fn scopes(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn names(list: &[&str]) -> Vec<String> {
    scopes(list)
}

#[test]
fn only_the_person_s_claims_are_kept_in_a_fixed_order_and_unknown_names_are_ignored() {
    let read = read_claims(
        r#"{
            "id_token": {"phone_number": null, "email": {"essential": true}, "name#fr": null,
                         "auth_time": {"essential": true}, "groups": null, "shoe_size": null},
            "userinfo": {"address": null, "given_name": {"essential": false}, "acr": null},
            "something_else": {"name": null}
        }"#,
    )
    .expect("read");
    assert_eq!(read.request.id_token, names(&["email", "phone_number"]));
    assert_eq!(read.request.userinfo, names(&["given_name", "address"]));
    assert_eq!(read.request.subject, None);
    assert_eq!(read.essential_acr, None);
    assert!(!read.acr_with_values);
}

#[test]
fn an_essential_acr_gives_its_values_and_one_without_essential_gives_none() {
    let essential = read_claims(
        r#"{"id_token":{"acr":{"essential":true,"values":["urn:a","urn:b"],"value":"urn:c"}}}"#,
    )
    .expect("read");
    assert_eq!(
        essential.essential_acr.as_deref(),
        Some("urn:c urn:a urn:b")
    );
    assert!(essential.acr_with_values);
    let preferred = read_claims(r#"{"id_token":{"acr":{"values":["urn:a"]}}}"#).expect("read");
    assert_eq!(preferred.essential_acr, None);
    assert!(preferred.acr_with_values);
    let bare = read_claims(r#"{"id_token":{"acr":{"essential":true}}}"#).expect("read");
    assert_eq!(bare.essential_acr, None);
    assert!(!bare.acr_with_values);
    // A level is a name without a space.
    assert!(read_claims(r#"{"id_token":{"acr":{"essential":true,"value":"a b"}}}"#).is_err());
}

#[test]
fn a_sub_with_a_value_names_the_person_expected() {
    let read =
        read_claims(r#"{"userinfo":{"sub":{"value":"ana"}},"id_token":{"sub":{"value":"ana"}}}"#)
            .expect("read");
    assert_eq!(read.request.subject.as_deref(), Some("ana"));
    let without = read_claims(r#"{"id_token":{"sub":{"essential":true}}}"#).expect("read");
    assert_eq!(without.request.subject, None);
}

#[test]
fn the_bounds_of_the_parameter_hold() {
    let sixty_four: String = format!(
        "{{\"id_token\":{{{}}},\"userinfo\":{{{}}}}}",
        (0..32)
            .map(|index| format!("\"a{index}\":null"))
            .collect::<Vec<_>>()
            .join(","),
        (0..32)
            .map(|index| format!("\"b{index}\":null"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(read_claims(&sixty_four).is_ok());
    let sixty_five = sixty_four.replacen("\"a0\":null", "\"a0\":null,\"a64\":null", 1);
    assert_eq!(
        read_claims(&sixty_five),
        Err("claims names at most 64 claims")
    );
    let padding = " ".repeat(MAX_CLAIMS_BYTES - 2);
    assert!(read_claims(&format!("{{{padding}}}")).is_ok());
    assert_eq!(
        read_claims(&format!("{{{padding} }}")),
        Err("claims holds at most 4096 bytes")
    );
}

#[test]
fn a_grant_gives_only_the_claims_a_consented_scope_covers() {
    let request = ClaimsRequest {
        id_token: names(&["name", "email", "phone_number"]),
        userinfo: names(&["name", "address"]),
        subject: None,
    };
    let given = request.given(
        &scopes(&["openid"]),
        &scopes(&["openid", "profile", "email"]),
    );
    assert_eq!(given.id_token, names(&["name", "email"]));
    assert_eq!(given.userinfo, names(&["name"]));
    // Nothing without `openid`.
    let given = request.given(
        &scopes(&["read"]),
        &scopes(&["profile", "email", "address"]),
    );
    assert_eq!(given, GrantClaims::default());
}

fn person() -> PersonClaims {
    PersonClaims {
        name: Some("Ana Silva".to_owned()),
        preferred_username: Some("ana".to_owned()),
        email: Some(("ana@example.com".to_owned(), true)),
        claims: StandardClaims {
            given_name: Some("Ana".to_owned()),
            phone_number: Some("+5511999990000".to_owned()),
            phone_number_verified: false,
            address: Some(PostalAddress {
                locality: Some("São Paulo".to_owned()),
                country: Some("BR".to_owned()),
                ..PostalAddress::default()
            }),
            ..StandardClaims::default()
        },
        ..PersonClaims::default()
    }
}

#[test]
fn asked_claims_are_added_under_their_own_names_when_the_person_has_them() {
    let mut claims = json!({"sub": "ana", "acr": "urn:hodor:acr:mfa"});
    add_asked_claims(
        &mut claims,
        &names(&[
            "name",
            "email_verified",
            "address",
            "phone_number_verified",
            "nickname",
        ]),
        &person(),
        &Map::new(),
    );
    assert_eq!(claims["name"], "Ana Silva");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(
        claims["address"],
        json!({"locality": "São Paulo", "country": "BR"})
    );
    assert_eq!(claims["phone_number_verified"], false);
    assert!(claims.get("nickname").is_none(), "the person has none");
    assert_eq!(claims["acr"], "urn:hodor:acr:mfa");
}

#[test]
fn a_claim_that_would_cross_the_bound_is_left_out_whole_and_mappers_count_first() {
    let mut person = person();
    // 200 characters of four bytes each, the longest a given name has.
    person.claims.given_name = Some("𝔄".repeat(200));
    person.name = Some("Ana".to_owned());
    // The mappers' claims leave 500 bytes.
    let filler = "x".repeat(MOST_MAPPED_BYTES - 500 - "filler".len() - 6);
    let mut mapped = Map::new();
    mapped.insert("filler".to_owned(), json!(filler));
    assert_eq!(cost("filler", &mapped["filler"]), MOST_MAPPED_BYTES - 500);

    let mut claims = json!({"sub": "ana"});
    add_asked_claims(
        &mut claims,
        &names(&["given_name", "name", "email"]),
        &person,
        &mapped,
    );
    // `name` comes first and fits, 13 bytes; the given name, 816 bytes
    // with its name and value, would cross the 487 left and is left out
    // whole; `email`, 26 bytes after it, still fits.
    assert_eq!(claims["name"], "Ana");
    assert!(claims.get("given_name").is_none());
    assert_eq!(claims["email"], "ana@example.com");

    // With no mapper, the same given name fits.
    let mut claims = json!({"sub": "ana"});
    add_asked_claims(&mut claims, &names(&["given_name"]), &person, &Map::new());
    assert_eq!(claims["given_name"], json!("𝔄".repeat(200)));
}
