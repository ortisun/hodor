//! The rules of request objects at a client's address, case by case.

use super::*;
use crate::domain::application::{Application, ApplicationSettings};
use crate::domain::client::{ClientSettings, ClientType, GrantType};
use crate::domain::secret::ClientSecret;
use hodor_kernel::Timestamp;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

const REDIRECT: &str = "https://payroll.example.com/callback";
const REGISTERED: &str = "https://payroll.example.com/requests/";
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;

fn settings(request_uris: &[&str]) -> ClientSettings {
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.request_uris = request_uris.iter().map(|uri| (*uri).to_owned()).collect();
    settings
}

fn client(request_uris: &[&str]) -> Client {
    let application = Application::create(
        ApplicationSettings {
            name: "Payroll".to_owned(),
            first_party: true,
        },
        MOMENT,
    )
    .expect("application");
    Client::create(
        application.id(),
        ClientType::Confidential,
        settings(request_uris),
        ClientSecret::DEFAULT_LIFETIME,
        MOMENT,
        &CountingRandom::default(),
        &FakeDigest,
    )
    .expect("client")
    .0
}

fn parameters(given: &[(&str, &str)]) -> AuthorizationParameters {
    AuthorizationParameters::from_pairs(
        given
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    )
}

fn redirected(refusal: AuthorizationRefusal) -> (&'static str, &'static str, Option<String>) {
    match refusal {
        AuthorizationRefusal::Redirect(error) => {
            assert_eq!(error.redirect_uri, REDIRECT);
            (error.error, error.description, error.state)
        }
        AuthorizationRefusal::NotRedirectable(page) => panic!("a page: {page}"),
    }
}

#[test]
fn a_registered_address_is_https_with_a_host_and_a_path() {
    for accepted in [
        "https://payroll.example.com/",
        "https://payroll.example.com/requests/",
        "https://payroll.example.com:8443/requests?tenant=acme",
        "https://[2001:db8::1]/requests/",
        // The development exception decides whether plain HTTP is called.
        "http://127.0.0.1:9600/requests/",
    ] {
        check_request_uri(accepted).unwrap_or_else(|error| panic!("{accepted}: {error:?}"));
    }
    for refused in [
        "https://payroll.example.com",
        "https://payroll.example.com?query",
        "https://payroll.example.com/requests#hash",
        "https://user:password@payroll.example.com/",
        "ftp://payroll.example.com/",
        "https:///requests/",
        "https://payroll.example.com/with space",
        "https://payroll.example.com/\u{e9}",
        "",
    ] {
        assert_eq!(
            check_request_uri(refused).expect_err(refused).code(),
            "oauth.client_request_uri_invalid",
            "{refused}"
        );
    }
    let long = format!("https://payroll.example.com/{}", "a".repeat(2000));
    assert!(check_request_uri(&long).is_err(), "longer than 2000");
}

#[test]
fn a_client_has_at_most_ten_and_only_with_the_authorization_code() {
    let ten: Vec<String> = (0..10)
        .map(|index| format!("https://payroll.example.com/{index}/"))
        .collect();
    let mut many = settings(&[]);
    many.request_uris.clone_from(&ten);
    let checked = many.checked(ClientType::Confidential).expect("ten");
    assert_eq!(checked.request_uris, ten);

    let mut eleven = settings(&[]);
    eleven.request_uris = (0..11)
        .map(|index| format!("https://payroll.example.com/{index}/"))
        .collect();
    assert_eq!(
        eleven
            .checked(ClientType::Confidential)
            .expect_err("eleven")
            .code(),
        "oauth.client_request_uri_invalid"
    );

    // Kept once, in the order given.
    let repeated = settings(&[REGISTERED, "https://payroll.example.com/", REGISTERED]);
    assert_eq!(
        repeated
            .checked(ClientType::Confidential)
            .expect("valid")
            .request_uris,
        [REGISTERED, "https://payroll.example.com/"]
    );

    let mut workload = ClientSettings::new(
        "Payroll job",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    workload.request_uris = vec![REGISTERED.to_owned()];
    assert_eq!(
        workload
            .checked(ClientType::Confidential)
            .expect_err("no code")
            .code(),
        "oauth.client_request_uri_invalid"
    );
}

#[test]
fn only_an_address_that_starts_with_a_registered_one_is_registered() {
    let client = client(&[REGISTERED, "https://other.example.net/object.jwt"]);
    for registered in [
        REGISTERED,
        "https://payroll.example.com/requests/abc",
        "https://payroll.example.com/requests/abc#hash",
        "https://other.example.net/object.jwt",
        "https://other.example.net/object.jwt?version=2",
    ] {
        assert!(is_registered(registered, &client), "{registered}");
    }
    for unregistered in [
        "https://payroll.example.com/",
        "https://payroll.example.com/request",
        "https://payroll.example.com/Requests/abc",
        "http://payroll.example.com/requests/abc",
        "https://payroll.example.com.example.org/requests/abc",
        "https://payroll.example.com/requests/with space",
        // The fragment is not part of what is compared.
        "https://payroll.example.com/request#s/",
    ] {
        assert!(!is_registered(unregistered, &client), "{unregistered}");
    }
    let long = format!("{REGISTERED}{}", "a".repeat(2000));
    assert!(!is_registered(&long, &client), "longer than 2000");
    assert!(
        !is_registered(REGISTERED, &self::client(&[])),
        "a client without addresses has none registered"
    );
}

#[test]
fn an_address_is_fetched_only_once_every_other_check_has_passed() {
    let client = client(&[REGISTERED]);
    let id = client.id().to_string();
    let address = format!("{REGISTERED}abc#hash");
    let outside = |extra: &[(&str, &str)]| {
        let mut given = vec![
            ("client_id", id.as_str()),
            ("request_uri", address.as_str()),
            ("redirect_uri", REDIRECT),
            ("state", "outside"),
        ];
        given.extend_from_slice(extra);
        parameters(&given)
    };

    let given = outside(&[]);
    let to_fetch = address_to_fetch(&given, &client, false).expect("fetched");
    assert_eq!(
        to_fetch,
        AddressToFetch {
            url: "https://payroll.example.com/requests/abc",
            fragment: Some("hash"),
        }
    );
    let plain = parameters(&[("client_id", &id), ("request_uri", REGISTERED)]);
    assert_eq!(
        address_to_fetch(&plain, &client, false).expect("fetched"),
        AddressToFetch {
            url: REGISTERED,
            fragment: None,
        }
    );

    let (error, _, state) = redirected(
        address_to_fetch(&outside(&[("request", "eyJ.eyJ.")]), &client, false)
            .expect_err("request beside it"),
    );
    assert_eq!(error, "invalid_request");
    assert_eq!(state.as_deref(), Some("outside"));
    let (error, description, _) =
        redirected(address_to_fetch(&given, &client, true).expect_err("must push"));
    assert_eq!(error, "invalid_request");
    assert_eq!(
        description,
        "this client must push its authorization requests"
    );

    let unregistered = parameters(&[
        ("client_id", &id),
        ("request_uri", "https://attacker.example.org/requests/abc"),
        ("redirect_uri", REDIRECT),
    ]);
    let (error, _, _) =
        redirected(address_to_fetch(&unregistered, &client, false).expect_err("unregistered"));
    assert_eq!(error, "invalid_request_uri");

    // Without a redirect address of the client's outside, Hodor's own page.
    let nowhere = parameters(&[
        ("client_id", &id),
        ("request_uri", "https://attacker.example.org/requests/abc"),
    ]);
    assert_eq!(
        address_to_fetch(&nowhere, &client, false).expect_err("unregistered"),
        AuthorizationRefusal::NotRedirectable("oauth.authorization_request_uri_invalid")
    );
}

#[test]
fn what_was_fetched_must_be_small_text_with_the_hash_of_its_fragment() {
    let object = b"eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCJ9.\n";
    let hash = URL_SAFE_NO_PAD.encode(FakeDigest.sha256(object));
    let with = |fragment| AddressToFetch {
        url: REGISTERED,
        fragment,
    };
    assert_eq!(
        fetched_object(200, object, &with(None), &FakeDigest),
        Ok("eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCJ9.".to_owned()),
        "the line end around it is not part of it"
    );
    assert_eq!(
        fetched_object(200, object, &with(Some(&hash)), &FakeDigest).map(|text| text.len()),
        Ok(object.len() - 1),
        "the hash of the content exactly as it was received"
    );
    let padded = format!("{hash}=");
    for wrong in ["", "AAAA", &hash[1..], &padded] {
        assert_eq!(
            fetched_object(200, object, &with(Some(wrong)), &FakeDigest),
            Err(FetchRefusal::HashMismatch),
            "{wrong}"
        );
    }
    for status in [301, 302, 304, 400, 404, 500] {
        assert_eq!(
            fetched_object(status, object, &with(None), &FakeDigest),
            Err(FetchRefusal::Status),
            "{status}"
        );
    }
    let largest = vec![b'a'; MAX_REQUEST_OBJECT_BYTES];
    assert!(fetched_object(200, &largest, &with(None), &FakeDigest).is_ok());
    let larger = vec![b'a'; MAX_REQUEST_OBJECT_BYTES + 1];
    assert_eq!(
        fetched_object(200, &larger, &with(None), &FakeDigest),
        Err(FetchRefusal::TooLarge)
    );
    for not_text in [&b"\xff\xfe"[..], b"", b" \r\n"] {
        assert_eq!(
            fetched_object(200, not_text, &with(None), &FakeDigest),
            Err(FetchRefusal::NotText)
        );
    }
}

#[test]
fn a_refused_fetch_never_names_the_address() {
    let client = client(&[REGISTERED]);
    let id = client.id().to_string();
    let given = parameters(&[
        ("client_id", &id),
        ("request_uri", "https://payroll.example.com/requests/abc"),
        ("redirect_uri", REDIRECT),
        ("state", "outside"),
    ]);
    for refusal in [
        FetchRefusal::Unreachable,
        FetchRefusal::Status,
        FetchRefusal::TooLarge,
        FetchRefusal::HashMismatch,
        FetchRefusal::NotText,
    ] {
        let (error, description, state) = redirected(refused_fetch(&given, &client, refusal));
        assert_eq!(error, "invalid_request_uri");
        assert!(!description.contains("payroll"), "{description}");
        assert_eq!(state.as_deref(), Some("outside"));
    }
}

#[test]
fn what_was_fetched_takes_the_place_of_the_reference() {
    let given = parameters(&[
        ("client_id", "abc"),
        ("request_uri", REGISTERED),
        ("scope", "openid"),
    ]);
    let read = with_fetched_object(&given, "eyJ.eyJ.".to_owned());
    assert_eq!(read.once("request"), Some("eyJ.eyJ."));
    assert_eq!(read.once("request_uri"), None);
    assert_eq!(read.once("client_id"), Some("abc"));
    assert_eq!(read.once("scope"), Some("openid"));
}
