use super::*;
use crate::domain::authorization::{AuthorizationCode, CodeHash, GrantId};
use crate::domain::backchannel::{LogoutTokenSubject, logout_token_claims};
use crate::domain::client::IdTokenAlgorithm;
use crate::domain::openid::{IdTokenNames, PersonClaims, id_token_claims, userinfo_claims};
use crate::domain::token::{TokenSubject, claims_for};
use crate::testing::DistinctRandom;
use hodor_kernel::UserId;
use hodor_kernel::random::testing::FakeDigest;
use hodor_session::api::SessionId;
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";

fn now() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn scopes(list: &[&str]) -> Vec<String> {
    list.iter().map(|scope| (*scope).to_owned()).collect()
}

fn settings(claim: &str, targets: &[ClaimTarget], source: ClaimSource) -> ClaimMapperSettings {
    ClaimMapperSettings {
        claim: claim.to_owned(),
        targets: targets.to_vec(),
        scope: None,
        source,
    }
}

fn mapper(claim: &str, targets: &[ClaimTarget], source: ClaimSource) -> ClaimMapper {
    ClaimMapper::create(
        ClientId::generate(),
        settings(claim, targets, source),
        &scopes(&["openid", "profile"]),
        now(),
    )
    .expect("a mapper")
    .0
}

fn refusal(settings: ClaimMapperSettings) -> String {
    settings
        .checked(&scopes(&["openid", "profile"]))
        .expect_err("refused")
        .code()
        .to_owned()
}

#[test]
fn a_mapper_that_names_sub_iss_or_acr_is_refused() {
    for name in [
        "sub", "iss", "acr", "SUB", "Acr", "groups", "org_id", "email", "act", "cnf",
    ] {
        assert_eq!(
            refusal(settings(name, &[ClaimTarget::IdToken], ClaimSource::Groups)),
            "oauth.claim_mapper_name_reserved",
            "{name}"
        );
    }
    for name in [
        "department",
        "roles",
        "given_name",
        "https://example.com/claims/team",
    ] {
        assert!(
            settings(name, &[ClaimTarget::IdToken], ClaimSource::Groups)
                .checked(&[])
                .is_ok(),
            "{name}"
        );
    }
}

/// Every claim Hodor writes in any token or answer, with every optional
/// claim present, is a reserved name: a claim Hodor starts writing cannot
/// be forgotten in the list.
#[test]
fn every_claim_hodor_writes_is_reserved() {
    let code = AuthorizationCode {
        hash: CodeHash::from_stored([1; 32]),
        grant_id: GrantId::generate(),
        client_id: ClientId::generate(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scopes: scopes(&["openid", "email", "groups"]),
        audiences: vec!["https://api.example.com".to_owned()],
        code_challenge: None,
        nonce: Some("nonce".to_owned()),
        session_id: SessionId::generate(),
        user_id: UserId::generate(),
        signed_in_at: now(),
        methods: scopes(&["password", "totp"]),
        acr: Some("urn:hodor:acr:mfa".to_owned()),
        issued_at: now(),
        expires_at: now() + Duration::seconds(60),
        redeemed_at: Some(now()),
    };
    let id_token = id_token_claims(
        ISSUER,
        &code,
        IdTokenNames {
            subject: "a-pairwise-subject",
            session: "a-pairwise-session",
        },
        Some(OrganizationId::generate()),
        ClientId::generate(),
        Duration::minutes(5),
        now(),
        "token",
        IdTokenAlgorithm::Es256,
        &FakeDigest,
    );
    let mut subject = TokenSubject::of_code(&code);
    subject.organization = Some(OrganizationId::generate());
    subject.groups = Some(vec![GroupId::generate()]);
    subject.principal_kind = Some("agent".to_owned());
    subject.act = Some(json!({"sub": "agent"}));
    let access_token = claims_for(
        ISSUER,
        &subject,
        ClientId::generate(),
        Duration::minutes(5),
        now(),
        &DistinctRandom,
    )
    .claims;
    let person = PersonClaims {
        name: Some("Ana".to_owned()),
        preferred_username: Some("ana".to_owned()),
        locale: Some("pt-BR".to_owned()),
        updated_at: Some(now()),
        email: Some(("ana@example.com".to_owned(), true)),
        groups: vec![GroupId::generate()],
    };
    let userinfo = userinfo_claims(
        "a-pairwise-subject",
        &scopes(&["openid", "profile", "email", "groups"]),
        &person,
    );
    let logout_token = logout_token_claims(
        LogoutTokenSubject {
            issuer: ISSUER,
            client_id: ClientId::generate(),
            subject: "a-pairwise-subject",
            session: "a-pairwise-session",
        },
        now(),
        "token-identifier",
    );
    for claims in [id_token, access_token, userinfo, logout_token] {
        for name in claims.as_object().expect("an object").keys() {
            assert!(
                is_reserved(name),
                "`{name}` is written by Hodor and not reserved"
            );
        }
    }
}

#[test]
fn a_mapper_keeps_to_its_own_rules() {
    let groups = || ClaimSource::Groups;
    assert_eq!(
        refusal(settings("", &[ClaimTarget::IdToken], groups())),
        "oauth.claim_mapper_name_invalid"
    );
    assert_eq!(
        refusal(settings("two words", &[ClaimTarget::IdToken], groups())),
        "oauth.claim_mapper_name_invalid"
    );
    assert_eq!(
        refusal(settings(
            &"x".repeat(129),
            &[ClaimTarget::IdToken],
            groups()
        )),
        "oauth.claim_mapper_name_invalid"
    );
    assert_eq!(
        refusal(settings("team", &[], groups())),
        "oauth.claim_mapper_targets_invalid"
    );
    assert_eq!(
        refusal(settings(
            "team",
            &[ClaimTarget::IdToken, ClaimTarget::IdToken],
            groups()
        )),
        "oauth.claim_mapper_targets_invalid"
    );
    let mut scoped = settings("team", &[ClaimTarget::IdToken], groups());
    scoped.scope = Some("invoices:read".to_owned());
    assert_eq!(refusal(scoped), "oauth.claim_mapper_scope_not_allowed");
    assert_eq!(
        refusal(settings(
            "plan",
            &[ClaimTarget::AccessToken],
            ClaimSource::Constant(Value::Null)
        )),
        "oauth.claim_mapper_source_invalid"
    );
    assert_eq!(
        refusal(settings(
            "plan",
            &[ClaimTarget::AccessToken],
            ClaimSource::Constant(json!("x".repeat(1023)))
        )),
        "oauth.claim_mapper_source_invalid",
        "1025 bytes with its quotes"
    );
    assert!(
        settings(
            "plan",
            &[ClaimTarget::AccessToken],
            ClaimSource::Constant(json!("x".repeat(1022)))
        )
        .checked(&[])
        .is_ok(),
        "1024 bytes"
    );
    let ordered = settings(
        "team",
        &[ClaimTarget::UserInfo, ClaimTarget::IdToken],
        groups(),
    )
    .checked(&[])
    .expect("valid");
    assert_eq!(
        ordered.targets,
        [ClaimTarget::IdToken, ClaimTarget::UserInfo]
    );
}

#[test]
fn a_source_is_read_as_the_interface_writes_it() {
    let group = GroupId::generate();
    for source in [
        ClaimSource::Attribute(PersonAttribute::DisplayName),
        ClaimSource::Attribute(PersonAttribute::EmailVerified),
        ClaimSource::Groups,
        ClaimSource::GroupMember(group),
        ClaimSource::Organization(OrganizationAttribute::Name),
        ClaimSource::Constant(json!({"tier": "gold", "seats": 5})),
    ] {
        assert_eq!(
            ClaimSource::from_json(&source.to_json()),
            Ok(source.clone())
        );
    }
    for bad in [
        json!("groups"),
        json!({"kind": "role"}),
        json!({"kind": "attribute", "attribute": "password"}),
        json!({"kind": "attribute"}),
        json!({"kind": "groups", "group_id": group.to_string()}),
        json!({"kind": "group_member", "group_id": "finance"}),
        json!({"kind": "organization", "attribute": "description"}),
    ] {
        assert_eq!(
            ClaimSource::from_json(&bad).expect_err("refused").code(),
            "oauth.claim_mapper_source_invalid",
            "{bad}"
        );
    }
}

#[test]
fn each_source_has_a_largest_value() {
    let worst = |source: ClaimSource| settings("c", &[ClaimTarget::IdToken], source).worst_case();
    // A name of one character, its quotes, the colon and a comma.
    let around = 5;
    assert_eq!(
        worst(ClaimSource::Attribute(PersonAttribute::DisplayName)),
        802 + around
    );
    assert_eq!(
        worst(ClaimSource::Attribute(PersonAttribute::Username)),
        258 + around
    );
    assert_eq!(
        worst(ClaimSource::Attribute(PersonAttribute::Email)),
        1018 + around
    );
    assert_eq!(
        worst(ClaimSource::Attribute(PersonAttribute::EmailVerified)),
        5 + around
    );
    assert_eq!(
        worst(ClaimSource::Attribute(PersonAttribute::Locale)),
        142 + around
    );
    assert_eq!(worst(ClaimSource::Groups), 3901 + around);
    assert_eq!(
        worst(ClaimSource::GroupMember(GroupId::generate())),
        5 + around
    );
    assert_eq!(
        worst(ClaimSource::Organization(OrganizationAttribute::Id)),
        38 + around
    );
    assert_eq!(
        worst(ClaimSource::Organization(OrganizationAttribute::Name)),
        402 + around
    );
    assert_eq!(worst(ClaimSource::Constant(json!([1, 2]))), 5 + around);

    // The worst case of the groups is what a hundred of them write.
    let facts = PersonFacts {
        groups: (0..100).map(|_| GroupId::generate()).collect(),
        ..PersonFacts::default()
    };
    let written = mapped_claims(
        &[mapper("c", &[ClaimTarget::IdToken], ClaimSource::Groups)],
        ClaimTarget::IdToken,
        &[],
        &facts,
    );
    assert_eq!(written["c"].to_string().len(), 3901);
}

#[test]
fn a_token_past_the_bound_is_refused_when_the_mapper_is_saved() {
    let groups = settings(
        "team",
        &[ClaimTarget::IdToken, ClaimTarget::AccessToken],
        ClaimSource::Groups,
    );
    let name = settings(
        "full_name",
        &[ClaimTarget::IdToken],
        ClaimSource::Attribute(PersonAttribute::DisplayName),
    );
    let elsewhere = settings(
        "full_name",
        &[ClaimTarget::UserInfo],
        ClaimSource::Attribute(PersonAttribute::DisplayName),
    );
    assert!(
        check_together(&[&groups]).is_ok(),
        "one mapper of the groups fits"
    );
    let refused = check_together(&[&groups, &name]).expect_err("refused");
    assert_eq!(refused.code(), "oauth.claim_mapper_token_too_large");
    assert!(
        refused.message().contains("id_token"),
        "says the target: {}",
        refused.message()
    );
    assert!(
        check_together(&[&groups, &elsewhere]).is_ok(),
        "the bound is per target"
    );

    // Exactly at the bound, and one byte past it.
    let constant = |claim: &str, bytes: usize| {
        settings(
            claim,
            &[ClaimTarget::AccessToken],
            ClaimSource::Constant(json!("x".repeat(bytes - 2))),
        )
    };
    let quarters: Vec<ClaimMapperSettings> = (0..4)
        .map(|index| constant(&format!("c{index}"), 1024))
        .collect();
    // Four of 1024 bytes and their names of two characters: 4 × 1030.
    assert!(check_together(&quarters.iter().collect::<Vec<_>>()).is_err());
    let fitting: Vec<ClaimMapperSettings> = (0..4)
        .map(|index| constant(&format!("c{index}"), 1018))
        .collect();
    assert_eq!(
        fitting
            .iter()
            .map(ClaimMapperSettings::worst_case)
            .sum::<usize>(),
        4096
    );
    assert!(check_together(&fitting.iter().collect::<Vec<_>>()).is_ok());
}

#[test]
fn one_mapper_per_claim_and_at_most_twenty() {
    let one = settings(
        "Team",
        &[ClaimTarget::IdToken],
        ClaimSource::GroupMember(GroupId::generate()),
    );
    let other = settings(
        "team",
        &[ClaimTarget::UserInfo],
        ClaimSource::GroupMember(GroupId::generate()),
    );
    assert_eq!(
        check_together(&[&one, &other]).expect_err("refused").code(),
        "oauth.claim_mapper_name_taken",
        "without regard to case, whatever the targets"
    );
    let many: Vec<ClaimMapperSettings> = (0..21)
        .map(|index| {
            settings(
                &format!("c{index}"),
                &[ClaimTarget::UserInfo],
                ClaimSource::GroupMember(GroupId::generate()),
            )
        })
        .collect();
    assert_eq!(
        check_together(&many.iter().collect::<Vec<_>>())
            .expect_err("refused")
            .code(),
        "oauth.claim_mappers_too_many"
    );
    assert!(check_together(&many[..20].iter().collect::<Vec<_>>()).is_ok());
}

#[test]
fn each_source_writes_what_the_person_has_and_leaves_out_what_they_do_not() {
    let finance = GroupId::generate();
    let organization = OrganizationId::generate();
    let target = [ClaimTarget::IdToken];
    let mappers = [
        mapper(
            "full_name",
            &target,
            ClaimSource::Attribute(PersonAttribute::DisplayName),
        ),
        mapper(
            "login",
            &target,
            ClaimSource::Attribute(PersonAttribute::Username),
        ),
        mapper(
            "mail",
            &target,
            ClaimSource::Attribute(PersonAttribute::Email),
        ),
        mapper(
            "mail_checked",
            &target,
            ClaimSource::Attribute(PersonAttribute::EmailVerified),
        ),
        mapper(
            "language",
            &target,
            ClaimSource::Attribute(PersonAttribute::Locale),
        ),
        mapper("teams", &target, ClaimSource::Groups),
        mapper("in_finance", &target, ClaimSource::GroupMember(finance)),
        mapper(
            "company",
            &target,
            ClaimSource::Organization(OrganizationAttribute::Id),
        ),
        mapper(
            "company_name",
            &target,
            ClaimSource::Organization(OrganizationAttribute::Name),
        ),
        mapper(
            "plan",
            &target,
            ClaimSource::Constant(json!({"tier": "gold"})),
        ),
    ];
    let other = GroupId::generate();
    let facts = PersonFacts {
        attributes: PersonAttributes {
            display_name: Some("Ana Silva".to_owned()),
            username: Some("ana".to_owned()),
            email: Some(("ana@example.com".to_owned(), false)),
            locale: Some("pt-BR".to_owned()),
        },
        groups: vec![finance, other],
        organization: Some(organization),
        organization_name: Some("Acme Brasil".to_owned()),
    };
    let claims = mapped_claims(&mappers, ClaimTarget::IdToken, &[], &facts);
    assert_eq!(claims["full_name"], "Ana Silva");
    assert_eq!(claims["login"], "ana");
    assert_eq!(claims["mail"], "ana@example.com");
    assert_eq!(claims["mail_checked"], false);
    assert_eq!(claims["language"], "pt-BR");
    assert_eq!(
        claims["teams"],
        json!([finance.to_string(), other.to_string()])
    );
    assert_eq!(claims["in_finance"], true);
    assert_eq!(claims["company"], organization.to_string());
    assert_eq!(claims["company_name"], "Acme Brasil");
    assert_eq!(claims["plan"], json!({"tier": "gold"}));
    let names: Vec<&String> = claims.keys().collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "by claim name");

    let nothing = mapped_claims(&mappers, ClaimTarget::IdToken, &[], &PersonFacts::default());
    assert_eq!(nothing["teams"], json!([]));
    assert_eq!(nothing["in_finance"], false);
    assert_eq!(nothing["plan"], json!({"tier": "gold"}));
    for absent in [
        "full_name",
        "login",
        "mail",
        "mail_checked",
        "language",
        "company",
        "company_name",
    ] {
        assert!(nothing.get(absent).is_none(), "{absent}");
    }
    assert!(
        mapped_claims(&mappers, ClaimTarget::UserInfo, &[], &facts).is_empty(),
        "only the targets a mapper names"
    );
}

#[test]
fn a_value_larger_than_its_bound_and_too_many_groups_leave_the_claim_out() {
    let target = [ClaimTarget::AccessToken];
    let mappers = [
        mapper(
            "language",
            &target,
            ClaimSource::Attribute(PersonAttribute::Locale),
        ),
        mapper("teams", &target, ClaimSource::Groups),
        mapper(
            "in_first",
            &target,
            ClaimSource::GroupMember(GroupId::generate()),
        ),
    ];
    let facts = PersonFacts {
        attributes: PersonAttributes {
            locale: Some(format!("en-{}", "abcdefgh-".repeat(4))),
            ..PersonAttributes::default()
        },
        groups: (0..101).map(|_| GroupId::generate()).collect(),
        ..PersonFacts::default()
    };
    let claims = mapped_claims(&mappers, ClaimTarget::AccessToken, &[], &facts);
    assert_eq!(
        claims.get("language"),
        None,
        "a locale of more than 35 characters"
    );
    assert_eq!(
        claims.get("teams"),
        None,
        "a person in more than 100 groups"
    );
    assert_eq!(claims["in_first"], false, "the boolean is still answered");
}

#[test]
fn a_mapper_with_a_scope_applies_only_when_the_token_holds_it() {
    let mut scoped = settings(
        "full_name",
        &[ClaimTarget::AccessToken],
        ClaimSource::Attribute(PersonAttribute::DisplayName),
    );
    scoped.scope = Some("profile".to_owned());
    let (mapper, _) =
        ClaimMapper::create(ClientId::generate(), scoped, &scopes(&["profile"]), now())
            .expect("valid");
    let facts = PersonFacts {
        attributes: PersonAttributes {
            display_name: Some("Ana".to_owned()),
            ..PersonAttributes::default()
        },
        ..PersonFacts::default()
    };
    let mappers = [mapper];
    assert!(
        mapped_claims(
            &mappers,
            ClaimTarget::AccessToken,
            &scopes(&["openid"]),
            &facts
        )
        .is_empty()
    );
    assert_eq!(
        mapped_claims(
            &mappers,
            ClaimTarget::AccessToken,
            &scopes(&["openid", "profile"]),
            &facts
        )["full_name"],
        "Ana"
    );
    assert_eq!(
        needs(&mappers, &[ClaimTarget::AccessToken], &scopes(&["openid"])),
        Needs::default(),
        "nothing is read for a mapper that does not apply"
    );
    assert!(needs(&mappers, &[ClaimTarget::AccessToken], &scopes(&["profile"])).attributes);
}

#[test]
fn only_what_the_mappers_read_is_read() {
    let mappers = [
        mapper(
            "in_finance",
            &[ClaimTarget::IdToken],
            ClaimSource::GroupMember(GroupId::generate()),
        ),
        mapper(
            "company",
            &[ClaimTarget::UserInfo],
            ClaimSource::Organization(OrganizationAttribute::Name),
        ),
    ];
    assert_eq!(
        needs(
            &mappers,
            &[ClaimTarget::IdToken, ClaimTarget::AccessToken],
            &[]
        ),
        Needs {
            groups: true,
            ..Needs::default()
        }
    );
    assert_eq!(
        needs(&mappers, &[ClaimTarget::UserInfo], &[]),
        Needs {
            organization_name: true,
            ..Needs::default()
        }
    );
}

#[test]
fn mapped_claims_come_after_hodors_own_and_never_replace_one() {
    let mut claims = json!({"iss": ISSUER, "sub": "someone"});
    let mut mapped = Map::new();
    mapped.insert("team".to_owned(), json!("blue"));
    mapped.insert("sub".to_owned(), json!("someone else"));
    mapped.insert("Sub".to_owned(), json!("someone else"));
    add_mapped_claims(&mut claims, &mapped);
    assert_eq!(
        claims,
        json!({"iss": ISSUER, "sub": "someone", "team": "blue"})
    );
}

#[test]
fn creating_replacing_and_deleting_say_so_without_a_constant_value() {
    let client = ClientId::generate();
    let (mut mapper, created) = ClaimMapper::create(
        client,
        settings(
            "plan",
            &[ClaimTarget::UserInfo, ClaimTarget::IdToken],
            ClaimSource::Constant(json!("secret plan")),
        ),
        &[],
        now(),
    )
    .expect("valid");
    assert_eq!(
        created,
        OauthEvent::ClaimMapperCreated {
            claim_mapper_id: mapper.id(),
            client_id: client,
            claim: "plan".to_owned(),
            targets: vec!["id_token", "userinfo"],
            source: "constant",
        }
    );
    assert!(
        !serde_json::to_string(&created)
            .expect("json")
            .contains("secret plan")
    );
    let later = now() + Duration::minutes(1);
    let changed = mapper
        .replace(
            settings("tier", &[ClaimTarget::AccessToken], ClaimSource::Groups),
            &[],
            later,
        )
        .expect("valid");
    assert!(matches!(changed, OauthEvent::ClaimMapperChanged { ref claim, .. } if claim == "tier"));
    assert_eq!(mapper.snapshot().updated_at, later);
    assert_eq!(mapper.client_id(), client, "the client never changes");
    assert!(
        mapper
            .replace(
                settings("sub", &[ClaimTarget::AccessToken], ClaimSource::Groups),
                &[],
                later
            )
            .is_err()
    );
    assert_eq!(
        mapper.settings().claim,
        "tier",
        "a refused replacement changes nothing"
    );
    assert!(matches!(
        mapper.deleted(),
        OauthEvent::ClaimMapperDeleted { .. }
    ));
}
