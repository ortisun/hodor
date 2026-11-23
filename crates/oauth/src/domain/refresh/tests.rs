use super::*;
use crate::domain::authorization::CodeHash;
use crate::testing::DistinctRandom;
use hodor_kernel::random::testing::FakeDigest;

fn now() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn code(scopes: &[&str]) -> AuthorizationCode {
    AuthorizationCode {
        hash: CodeHash::from_stored([1; 32]),
        grant_id: GrantId::generate(),
        client_id: ClientId::generate(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        audiences: vec![
            "https://api.example.com".to_owned(),
            "urn:example:billing".to_owned(),
        ],
        code_challenge: None,
        nonce: None,
        session_id: SessionId::generate(),
        user_id: UserId::generate(),
        signed_in_at: now() - Duration::minutes(2),
        methods: vec!["password".to_owned()],
        acr: Some("urn:hodor:acr:mfa".to_owned()),
        issued_at: now(),
        expires_at: now() + Duration::seconds(60),
        redeemed_at: Some(now()),
    }
}

fn family(scopes: &[&str]) -> (RefreshFamily, RefreshTokenValue) {
    RefreshFamily::start(
        &code(scopes),
        &TokenPolicy::default(),
        SealedSecret::from_stored(vec![9; 40]),
        now(),
        &DistinctRandom,
        &FakeDigest,
    )
}

/// The family after one move at `at`, asked for `asked`.
fn moved(mut family: RefreshFamily, asked: RefreshAsk, at: Timestamp) -> RefreshFamily {
    family.generation += 1;
    family.current_hash = RefreshTokenHash::from_stored([7; 32]);
    family.moved_at = Some(at);
    family.moved_for = asked;
    family.last_used_at = at;
    family
}

#[test]
fn a_family_starts_with_the_code_and_the_policy() {
    let (family, first) = family(&["openid", "read"]);
    let policy = TokenPolicy::default();
    assert_eq!(family.generation, 1);
    assert_eq!(family.current_hash, first.hash(&FakeDigest));
    assert_eq!(family.expires_at, now() + policy.refresh_token);
    assert_eq!(family.idle, policy.refresh_idle);
    assert!(!family.offline, "no offline_access");
    assert_eq!(first.expose().len(), 43);
    assert_eq!(
        RefreshTokenHash::of_presented(first.expose(), &FakeDigest),
        Some(family.current_hash)
    );
    let (offline, _) = self::family(&["openid", OFFLINE_ACCESS]);
    assert!(offline.offline);
}

#[test]
fn only_a_value_shaped_like_a_token_is_hashed() {
    for value in [
        "",
        "short",
        &"a".repeat(44),
        &format!("{}=", "a".repeat(42)),
    ] {
        assert!(RefreshTokenHash::of_presented(value, &FakeDigest).is_none());
    }
}

#[test]
fn the_next_token_depends_on_the_secret_and_the_token_before() {
    let one = FamilySecret::from_opened(Secret::from(vec![1; 32]));
    let two = FamilySecret::from_opened(Secret::from(vec![2; 32]));
    let token = "A".repeat(43);
    let next = one.next_after(&token, &FakeDigest);
    assert_eq!(next.expose().len(), 43);
    assert_eq!(
        next.expose(),
        one.next_after(&token, &FakeDigest).expose(),
        "the same token always leads to the same next one"
    );
    assert_ne!(next.expose(), two.next_after(&token, &FakeDigest).expose());
    assert_ne!(
        next.expose(),
        one.next_after(&"B".repeat(43), &FakeDigest).expose()
    );
    assert!(RefreshTokenHash::of_presented(next.expose(), &FakeDigest).is_some());
}

#[test]
fn the_newest_token_moves_the_family_and_may_narrow_the_scopes() {
    let (family, _) = family(&["openid", "read", "invoices"]);
    let client = family.client_id;
    assert_eq!(
        family.decide(1, client, None, None, now(), DEFAULT_RETRY_WINDOW),
        Ok(RefreshDecision::Move(RefreshAsk::default()))
    );
    assert_eq!(
        family.decide(
            1,
            client,
            Some("invoices read read"),
            Some("urn:example:billing"),
            now(),
            DEFAULT_RETRY_WINDOW
        ),
        Ok(RefreshDecision::Move(RefreshAsk {
            scopes: vec!["read".to_owned(), "invoices".to_owned()],
            resource: Some("urn:example:billing".to_owned()),
        })),
        "kept in the order of the family"
    );
    assert_eq!(
        family.decide(
            1,
            client,
            Some("read write"),
            None,
            now(),
            DEFAULT_RETRY_WINDOW
        ),
        Err(RefreshRefusal::ScopeNotGranted),
        "never widened"
    );
    assert_eq!(
        family.decide(
            1,
            client,
            None,
            Some("https://other.example.com"),
            now(),
            DEFAULT_RETRY_WINDOW
        ),
        Err(RefreshRefusal::ResourceNotGranted)
    );
}

#[test]
fn another_client_is_refused_and_named_a_leak() {
    let (family, _) = family(&["read"]);
    let refusal = family
        .decide(
            1,
            ClientId::generate(),
            None,
            None,
            now(),
            DEFAULT_RETRY_WINDOW,
        )
        .expect_err("refused");
    assert_eq!(refusal, RefreshRefusal::OtherClient);
    assert!(refusal.revokes_the_family() && !refusal.revokes_the_grant());
}

#[test]
fn a_token_used_before_is_reuse_outside_a_retry() {
    let (family, _) = family(&["openid", "read"]);
    let client = family.client_id;
    let asked = RefreshAsk::default();
    let family = moved(family, asked, now());
    let later = now() + Duration::seconds(3);

    // Within the window, for the same request: a retry.
    assert_eq!(
        family.decide(1, client, None, None, later, DEFAULT_RETRY_WINDOW),
        Ok(RefreshDecision::Retry(RefreshAsk::default()))
    );
    // Other scopes, outside the window, a window of zero: reuse.
    for (scope, at, window) in [
        (Some("read"), later, DEFAULT_RETRY_WINDOW),
        (None, now() + DEFAULT_RETRY_WINDOW, DEFAULT_RETRY_WINDOW),
        (None, later, Duration::ZERO),
    ] {
        let refusal = family
            .decide(1, client, scope, None, at, window)
            .expect_err("reuse");
        assert_eq!(refusal, RefreshRefusal::Reused);
        assert!(refusal.revokes_the_family() && refusal.revokes_the_grant());
    }
    // Two generations old: reuse even within the window.
    let family = moved(family, RefreshAsk::default(), later);
    assert_eq!(
        family.decide(1, client, None, None, later, DEFAULT_RETRY_WINDOW),
        Err(RefreshRefusal::Reused)
    );
}

#[test]
fn a_family_ends_with_its_lifetimes_and_its_revocation() {
    let (mut family, _) = family(&["read"]);
    let client = family.client_id;
    let policy = TokenPolicy::default();
    assert_eq!(
        family.decide(
            1,
            client,
            None,
            None,
            now() + policy.refresh_idle,
            DEFAULT_RETRY_WINDOW
        ),
        Err(RefreshRefusal::Idle)
    );
    assert_eq!(
        family.decide(
            1,
            client,
            None,
            None,
            now() + policy.refresh_token,
            DEFAULT_RETRY_WINDOW
        ),
        Err(RefreshRefusal::Expired)
    );
    let event = family
        .revoke(RefreshRefusal::Reused.as_str(), now())
        .expect("revoked");
    assert!(matches!(
        event,
        OauthEvent::RefreshTokenFamilyRevoked {
            reason: "refresh_token_reused",
            ..
        }
    ));
    assert!(family.revoke("again", now()).is_none(), "once");
    assert_eq!(
        family.decide(1, client, None, None, now(), DEFAULT_RETRY_WINDOW),
        Err(RefreshRefusal::Revoked)
    );
}

#[test]
fn a_retry_is_answered_only_while_the_family_has_not_moved_again() {
    let secret = FamilySecret::from_opened(Secret::from(vec![3; 32]));
    let (mut family, first) = family(&["read"]);
    let next = secret.next_after(first.expose(), &FakeDigest);
    family.current_hash = next.hash(&FakeDigest);
    assert!(family.is_newest(&secret.next_after(first.expose(), &FakeDigest), &FakeDigest));
    family.current_hash = RefreshTokenHash::from_stored([0; 32]);
    assert!(!family.is_newest(&next, &FakeDigest));
}
