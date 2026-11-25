//! HMAC-SHA-1, for the codes of authenticator applications, and
//! HMAC-SHA256, for the signatures of webhooks and the pairwise subject
//! identifiers of OAuth.

use aws_lc_rs::hmac;
use hodor_credential::api::HmacSha1;
use hodor_oauth::api::HmacSha256 as PairwiseHmac;
use hodor_webhooks::api::HmacSha256;

/// [`HmacSha1`] on `aws-lc-rs`.
///
/// SHA-1 is offered by the library for old uses only; HMAC-SHA-1 is what
/// RFC 6238 and every authenticator application use, and it is still
/// sound inside an HMAC. See `docs/architecture/contexts/credential.md`,
/// "Authenticator applications".
#[derive(Debug, Clone, Copy, Default)]
pub struct AwsLcHmacSha1;

impl HmacSha1 for AwsLcHmacSha1 {
    fn mac(&self, key: &[u8], message: &[u8]) -> [u8; 20] {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        let tag = hmac::sign(&key, message);
        let mut out = [0_u8; 20];
        out.copy_from_slice(tag.as_ref());
        out
    }
}

/// [`HmacSha256`] on `aws-lc-rs`, for the signatures of webhooks (see
/// `docs/architecture/contexts/webhooks.md`, "How it is signed"), and the
/// pairwise subject identifiers of OAuth (see
/// `docs/architecture/contexts/oauth.md`, "The identifier").
#[derive(Debug, Clone, Copy, Default)]
pub struct AwsLcHmacSha256;

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, message);
    let mut out = [0_u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

impl HmacSha256 for AwsLcHmacSha256 {
    fn mac(&self, key: &[u8], message: &[u8]) -> [u8; 32] {
        hmac_sha256(key, message)
    }
}

impl PairwiseHmac for AwsLcHmacSha256 {
    fn mac(&self, key: &[u8], message: &[u8]) -> [u8; 32] {
        hmac_sha256(key, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_credential::api::totp_code_at;
    use hodor_kernel::Timestamp;

    /// RFC 2202, test case 2.
    #[test]
    fn it_matches_the_published_hmac_vector() {
        let mac = AwsLcHmacSha1.mac(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    /// RFC 4231, test case 2.
    #[test]
    fn it_matches_the_published_hmac_sha256_vector() {
        let mac = HmacSha256::mac(&AwsLcHmacSha256, b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// The same vector through the trait of the OAuth context.
    #[test]
    fn the_oauth_hmac_is_hmac_sha256() {
        let mac = PairwiseHmac::mac(&AwsLcHmacSha256, b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// The pairwise identifier of a fixed secret, tenant, sector and person
    /// never changes: a change of the algorithm would change every
    /// identifier every client was given.
    #[test]
    fn a_pairwise_identifier_is_what_it_always_was() {
        use hodor_kernel::{Secret, TenantId};
        use hodor_oauth::api::PairwiseSecret;
        let secret = PairwiseSecret::from_opened(Secret::new((0_u8..32).collect())).expect("32");
        let tenant = TenantId::from_uuid(
            "0193f1c2-0000-7000-8000-000000000001"
                .parse()
                .expect("a tenant"),
        );
        let person = [0x11_u8; 16];
        let sub = secret.subject(&AwsLcHmacSha256, tenant, "app.example.com", &person);
        let sid = secret.session(&AwsLcHmacSha256, tenant, "app.example.com", &person);
        assert_eq!(sub.len(), 43);
        assert_ne!(sub, sid);
        assert_eq!(sub, PINNED_SUB);
        assert_eq!(sid, PINNED_SID);
    }

    /// Computed apart from this code, by HMAC-SHA-256 of the message the
    /// OAuth context's page writes, with Python's `hmac` module.
    const PINNED_SUB: &str = "MAl1mMDFvWYGczw4sY-iz_CbH_AHQJ2b72F4h84e-u4";
    const PINNED_SID: &str = "xTh9BRGF7vBEr9pPCFlZr2igTwaH7QD16VNSQkNA2uU";

    /// RFC 6238, appendix B, the SHA-1 cases: the last six of the eight
    /// digits given there.
    #[test]
    fn it_gives_the_codes_of_rfc_6238() {
        let secret = b"12345678901234567890";
        for (seconds, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            let moment = Timestamp::from_unix_timestamp(seconds).expect("moment");
            assert_eq!(
                totp_code_at(&AwsLcHmacSha1, secret, moment),
                code,
                "{seconds}"
            );
        }
    }
}
