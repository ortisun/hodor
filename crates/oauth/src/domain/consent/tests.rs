//! The rules of consent, case by case.

use super::*;

const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;
const AUDIENCE: &str = "https://api.example.com";

fn request(scopes: &[&str], first_party: bool) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: ClientId::generate(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        audiences: vec![AUDIENCE.to_owned()],
        code_challenge: None,
        state: None,
        nonce: None,
        prompt: Vec::new(),
        max_age: None,
        login_hint: None,
        ui_locales: None,
        acr_values: None,
        first_party,
        organization: None,
        response_mode: crate::domain::response::ResponseMode::Query,
        id_token_hint: None,
        given_hint: None,
        claims: crate::domain::claims_parameter::ClaimsRequest::default(),
        claims_locales: None,
    }
}

fn given(request: &AuthorizationRequest) -> Consent {
    Consent::give(
        None,
        UserId::generate(),
        request,
        DEFAULT_CONSENT_LIFETIME,
        MOMENT,
    )
}

#[test]
fn a_first_party_client_is_not_asked_unless_prompt_says_so() {
    let mut asked = request(&["openid", "read"], true);
    assert!(!must_ask(&asked, None, MOMENT));
    asked.scopes.push(OFFLINE_ACCESS.to_owned());
    assert!(
        !must_ask(&asked, None, MOMENT),
        "the tenant runs a first-party application, offline access included"
    );
    asked.prompt = vec!["consent".to_owned()];
    assert!(must_ask(&asked, None, MOMENT));
}

#[test]
fn a_third_party_client_is_asked_until_a_consent_covers_the_request() {
    let asked = request(&["openid", "read"], false);
    assert!(must_ask(&asked, None, MOMENT));
    let consent = given(&asked);
    assert!(!must_ask(&asked, Some(&consent), MOMENT));

    let mut more = asked.clone();
    more.scopes.push("write".to_owned());
    assert!(
        must_ask(&more, Some(&consent), MOMENT),
        "a scope not agreed"
    );

    let mut elsewhere = asked.clone();
    elsewhere.audiences = vec!["urn:example:other".to_owned()];
    assert!(
        must_ask(&elsewhere, Some(&consent), MOMENT),
        "an audience not agreed"
    );

    let mut again = asked;
    again.prompt = vec!["consent".to_owned()];
    assert!(must_ask(&again, Some(&consent), MOMENT));
}

#[test]
fn offline_access_is_asked_every_time_and_never_kept() {
    let asked = request(&["openid", OFFLINE_ACCESS], false);
    let consent = given(&asked);
    assert_eq!(consent.scopes, ["openid"]);
    assert!(must_ask(&asked, Some(&consent), MOMENT));
}

#[test]
fn a_consent_runs_out_and_can_be_withdrawn_once() {
    let asked = request(&["read"], false);
    let mut consent = given(&asked);
    let before_the_end = MOMENT + DEFAULT_CONSENT_LIFETIME - Duration::seconds(1);
    assert!(consent.covers(&asked, before_the_end));
    assert!(!consent.covers(&asked, MOMENT + DEFAULT_CONSENT_LIFETIME));

    let event = consent.withdraw(ConsentActor::Administrator, MOMENT);
    assert!(matches!(
        event,
        Some(OauthEvent::ConsentWithdrawn {
            by: "administrator",
            ..
        })
    ));
    assert!(!consent.covers(&asked, MOMENT));
    assert_eq!(consent.withdraw(ConsentActor::Person, MOMENT), None);
}

#[test]
fn agreeing_again_adds_to_a_consent_that_stands_and_starts_over_one_that_does_not() {
    let first = request(&["read"], false);
    let consent = given(&first);
    let mut second = first.clone();
    second.scopes = vec!["write".to_owned()];
    let later = MOMENT + Duration::days(10);
    let grown = Consent::give(
        Some(&consent),
        consent.user_id,
        &second,
        DEFAULT_CONSENT_LIFETIME,
        later,
    );
    assert_eq!(grown.scopes, ["read", "write"]);
    assert_eq!(grown.expires_at, later + DEFAULT_CONSENT_LIFETIME);

    let mut withdrawn = consent;
    withdrawn.withdraw(ConsentActor::Person, MOMENT);
    let fresh = Consent::give(
        Some(&withdrawn),
        withdrawn.user_id,
        &second,
        DEFAULT_CONSENT_LIFETIME,
        later,
    );
    assert_eq!(fresh.scopes, ["write"]);
    assert_eq!(fresh.withdrawn_at, None);
}

#[test]
fn stored_values_are_read_back_and_unknown_ones_refused() {
    for answer in [ConsentAnswer::Agreed, ConsentAnswer::Refused] {
        assert_eq!(
            ConsentAnswer::from_stored(answer.as_str()).ok(),
            Some(answer)
        );
    }
    for actor in [ConsentActor::Person, ConsentActor::Administrator] {
        assert_eq!(ConsentActor::from_stored(actor.as_str()).ok(), Some(actor));
    }
    assert!(ConsentAnswer::from_stored("maybe").is_err());
    assert!(ConsentActor::from_stored("someone").is_err());
}

#[test]
fn the_scopes_consented_to_are_the_client_s_for_a_first_party_one_and_the_person_s_otherwise() {
    let allowed = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ];
    let first = request(&["openid"], true);
    assert_eq!(
        consented_scopes(&first, None, &allowed, MOMENT),
        ["openid", "profile", "email"]
    );

    let third = request(&["openid"], false);
    assert_eq!(consented_scopes(&third, None, &allowed, MOMENT), ["openid"]);
    let mut earlier = given(&request(&["openid", "profile"], false));
    assert_eq!(
        consented_scopes(&third, Some(&earlier), &[], MOMENT),
        ["openid", "profile"]
    );
    // A consent that no longer stands counts for nothing.
    assert_eq!(
        consented_scopes(
            &third,
            Some(&earlier),
            &[],
            MOMENT + DEFAULT_CONSENT_LIFETIME
        ),
        ["openid"]
    );
    earlier.withdraw(ConsentActor::Person, MOMENT);
    assert_eq!(
        consented_scopes(&third, Some(&earlier), &[], MOMENT),
        ["openid"]
    );
}
