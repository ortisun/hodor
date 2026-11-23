//! HMAC-SHA-1, for the codes of authenticator applications.

use aws_lc_rs::hmac;
use hodor_credential::api::HmacSha1;

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
