//! The LDAP adapter against a real OpenLDAP in a container.

use hodor_adapters_ldap::LdapDirectoryClient;
use hodor_adapters_ldap::testing::{BASE, BIND_NAME, BIND_PASSWORD, Person, TestDirectory};
use hodor_federation::api::{DirectoryAnswer, DirectoryClient as _, DirectoryQuery};
use hodor_kernel::Secret;

const ANA: Person<'static> = Person {
    uid: "ana",
    name: "Ana Example",
    email: "ana@example.com",
    password: "correct horse battery staple",
};

fn query(directory: &TestDirectory, filter: &str) -> DirectoryQuery {
    DirectoryQuery {
        address: directory.address.clone(),
        bind_name: BIND_NAME.to_owned(),
        bind_password: Secret::from(BIND_PASSWORD.to_owned()),
        base: BASE.to_owned(),
        filter: filter.to_owned(),
        attributes: vec!["entryUUID".to_owned(), "mail".to_owned(), "cn".to_owned()],
    }
}

fn password(value: &str) -> Secret<String> {
    Secret::from(value.to_owned())
}

#[tokio::test]
async fn a_directory_answers_who_a_person_is_only_for_the_right_password() {
    let directory = TestDirectory::start().await;
    directory.add(&ANA).await;
    directory
        .add(&Person {
            uid: "bia",
            name: "Bia Example",
            email: "bia@example.com",
            password: "another long passphrase",
        })
        .await;
    let client = LdapDirectoryClient::new(std::slice::from_ref(&directory.host));

    let answer = client
        .verify(&query(&directory, "(uid=ana)"), &password(ANA.password))
        .await
        .expect("asked");
    let DirectoryAnswer::Verified(entry) = answer else {
        panic!("expected a verified entry: {answer:?}");
    };
    assert_eq!(entry.name, format!("uid=ana,{BASE}"));
    let uuid = std::str::from_utf8(entry.first("entryUUID").expect("entryUUID")).expect("text");
    assert_eq!(uuid.len(), 36, "{uuid}");
    assert_eq!(entry.first("mail"), Some(b"ana@example.com".as_slice()));
    assert_eq!(
        entry.first("CN"),
        Some(b"Ana Example".as_slice()),
        "names in any case"
    );

    // The same person asked again is the same entry.
    let again = client
        .verify(&query(&directory, "(uid=ana)"), &password(ANA.password))
        .await
        .expect("asked");
    assert_eq!(again, DirectoryAnswer::Verified(entry));

    for (filter, typed, reason) in [
        ("(uid=ana)", "a wrong password", "wrong_password"),
        // Bia's password is not Ana's.
        ("(uid=ana)", "another long passphrase", "wrong_password"),
        ("(uid=nobody)", ANA.password, "not_found"),
        // Two people match: nobody is signed in.
        ("(mail=*@example.com)", ANA.password, "ambiguous"),
        ("(uid=ana)", "", "empty_password"),
    ] {
        let answer = client
            .verify(&query(&directory, filter), &password(typed))
            .await
            .expect("asked");
        assert_eq!(
            answer,
            DirectoryAnswer::Refused(reason),
            "{filter} {typed:?}"
        );
    }
}

#[tokio::test]
async fn a_directory_that_is_not_on_the_list_is_never_connected_to() {
    let directory = TestDirectory::start().await;
    directory.add(&ANA).await;

    for allowed in [
        Vec::new(),
        vec!["127.0.0.1:1".to_owned()],
        vec![format!(
            "localhost:{}",
            directory.host.split(':').nth(1).expect("port")
        )],
    ] {
        let client = LdapDirectoryClient::new(&allowed);
        let error = client
            .verify(&query(&directory, "(uid=ana)"), &password(ANA.password))
            .await
            .expect_err("not allowed");
        assert_eq!(
            error.code(),
            "federation.directory_not_allowed",
            "{allowed:?}"
        );
    }
}

#[tokio::test]
async fn a_directory_that_refuses_hodor_or_does_not_answer_is_unavailable() {
    let directory = TestDirectory::start().await;
    let client = LdapDirectoryClient::new(&[directory.host.clone(), "127.0.0.1:9".to_owned()]);

    let mut wrong = query(&directory, "(uid=ana)");
    wrong.bind_password = Secret::from("not the password".to_owned());
    let error = client
        .verify(&wrong, &password("x"))
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "federation.provider_unavailable");
    assert!(!format!("{error:?}").contains("not the password"));

    let mut nowhere = query(&directory, "(uid=ana)");
    nowhere.address = "ldap://127.0.0.1:9".to_owned();
    let error = client
        .verify(&nowhere, &password("x"))
        .await
        .expect_err("nothing there");
    assert_eq!(error.code(), "federation.provider_unavailable");
}
