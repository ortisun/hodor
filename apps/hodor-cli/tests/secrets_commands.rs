//! The secrets command, run as the real binary. It needs no database.

use hodor_adapters_crypto::SecretKeys;
use hodor_kernel::{Secret, SecretBox as _, TenantContext, TenantId};
use std::process::Command;

fn generate() -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(["secrets", "generate-key"])
        .env_remove("HODOR_DATABASE_URL")
        .output()
        .expect("the command-line tool should run");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout)
        .expect("text")
        .trim()
        .to_owned()
}

#[test]
fn a_generated_key_is_one_the_server_accepts() {
    let key = generate();
    assert_ne!(key, generate(), "every run prints another key");

    let keys = SecretKeys::parse(&Secret::new(format!("2026-11:{key}"))).expect("a usable key");
    let tenant = TenantContext::assume(TenantId::generate());
    let secret = Secret::new(b"a secret".to_vec());
    let sealed = keys.seal(&tenant, "a.purpose", &secret).expect("seal");
    let opened = keys.open(&tenant, "a.purpose", &sealed).expect("open");
    assert_eq!(opened.expose(), secret.expose());
}
