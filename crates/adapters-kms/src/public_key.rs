//! The public keys OpenBao answers, read into the numbers the keys context
//! keeps: PEM documents of a SubjectPublicKeyInfo (RFC 5280, section 4.1)
//! for ECDSA and RSA, and the key's own 32 bytes in base64 for Ed25519.
//! Only the three shapes Hodor makes are accepted: a P-256 point, an RSA
//! key of 2048 bits, and an Ed25519 key.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_kernel::PublicKey;

/// `id-ecPublicKey` (RFC 5480).
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `secp256r1`, the curve P-256 (RFC 5480).
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `rsaEncryption` (RFC 8017).
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const NULL: u8 = 0x05;
const OBJECT_IDENTIFIER: u8 = 0x06;

/// Reads one element of DER: its tag, its content and what follows it.
fn element(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&length, rest) = rest.split_first()?;
            (usize::from(length), rest)
        }
        0x82 => {
            let (pair, rest) = rest.split_at_checked(2)?;
            (usize::from(u16::from_be_bytes([pair[0], pair[1]])), rest)
        }
        _ => return None,
    };
    let (content, rest) = rest.split_at_checked(length)?;
    Some((tag, content, rest))
}

/// Reads exactly one element of `tag` and nothing after it.
fn only(bytes: &[u8], tag: u8) -> Option<&[u8]> {
    match element(bytes)? {
        (found, content, []) if found == tag => Some(content),
        _ => None,
    }
}

/// A positive integer, without the zero DER puts before a high bit.
fn unsigned(content: &[u8]) -> Option<Vec<u8>> {
    if content.first()? & 0x80 != 0 {
        return None;
    }
    let start = content.iter().position(|&byte| byte != 0)?;
    Some(content[start..].to_vec())
}

/// The DER inside a PEM document labelled `PUBLIC KEY`.
fn pem(text: &str) -> Option<Vec<u8>> {
    let body = text
        .trim()
        .strip_prefix("-----BEGIN PUBLIC KEY-----")?
        .strip_suffix("-----END PUBLIC KEY-----")?;
    let joined: String = body.split_whitespace().collect();
    STANDARD.decode(joined).ok()
}

/// The shape of a public key Hodor asks OpenBao for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// A point on P-256, in PEM.
    P256,
    /// An RSA key of 2048 bits, in PEM.
    Rsa,
    /// An Ed25519 key: its 32 bytes in base64, which is how OpenBao
    /// answers the public key of a key of type `ed25519`.
    Ed25519,
}

/// Reads a public key OpenBao answered, of the shape asked. `None` for
/// anything else, a key of another shape included.
pub(crate) fn read(text: &str, shape: Shape) -> Option<PublicKey> {
    if shape == Shape::Ed25519 {
        let key = STANDARD.decode(text.trim()).ok()?;
        return (key.len() == 32).then_some(PublicKey::Ed25519 { x: key });
    }
    let rsa = shape == Shape::Rsa;
    let der = pem(text)?;
    let info = only(&der, SEQUENCE)?;
    let (tag, algorithm, rest) = element(info)?;
    if tag != SEQUENCE {
        return None;
    }
    let key = only(rest, BIT_STRING)?;
    let (unused_bits, key) = key.split_first()?;
    if *unused_bits != 0 {
        return None;
    }
    let (tag, identifier, parameters) = element(algorithm)?;
    if tag != OBJECT_IDENTIFIER {
        return None;
    }
    if rsa {
        if identifier != RSA_ENCRYPTION || !only(parameters, NULL)?.is_empty() {
            return None;
        }
        let numbers = only(key, SEQUENCE)?;
        let (tag, modulus, rest) = element(numbers)?;
        if tag != INTEGER {
            return None;
        }
        let exponent = unsigned(only(rest, INTEGER)?)?;
        let modulus = unsigned(modulus)?;
        (modulus.len() == 256).then_some(PublicKey::Rsa { modulus, exponent })
    } else {
        if identifier != EC_PUBLIC_KEY || only(parameters, OBJECT_IDENTIFIER)? != P256 {
            return None;
        }
        match key {
            [0x04, point @ ..] if point.len() == 64 => Some(PublicKey::P256 {
                x: point[..32].to_vec(),
                y: point[32..].to_vec(),
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A P-256 key as OpenBao 2.7.2 answered it.
    const P256_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8efidbiTVXrY8W1Llo73XJNXo54E\n9gPSKSjGjqHr10uPnRJg6DzbPfHl+1Y8CYOLpxnW4LWB+eOdS1WTdrjKiA==\n-----END PUBLIC KEY-----\n";

    fn rsa_key(modulus_bytes: usize) -> String {
        // SEQUENCE { SEQUENCE { rsaEncryption, NULL }, BIT STRING {
        // SEQUENCE { INTEGER modulus, INTEGER 65537 } } }
        let mut modulus = vec![0x00, 0xc0];
        modulus.extend(std::iter::repeat_n(0x11, modulus_bytes - 1));
        let wrap = |tag: u8, content: &[u8]| {
            let mut out = vec![tag];
            let length = content.len();
            if length < 0x80 {
                out.push(u8::try_from(length).expect("short"));
            } else if length < 0x100 {
                out.extend([0x81, u8::try_from(length).expect("one byte")]);
            } else {
                out.push(0x82);
                out.extend(u16::try_from(length).expect("two bytes").to_be_bytes());
            }
            out.extend_from_slice(content);
            out
        };
        let mut numbers = wrap(INTEGER, &modulus);
        numbers.extend(wrap(INTEGER, &[0x01, 0x00, 0x01]));
        let mut bits = vec![0];
        bits.extend(wrap(SEQUENCE, &numbers));
        let mut algorithm = wrap(OBJECT_IDENTIFIER, RSA_ENCRYPTION);
        algorithm.extend([NULL, 0]);
        let mut info = wrap(SEQUENCE, &algorithm);
        info.extend(wrap(BIT_STRING, &bits));
        let der = wrap(SEQUENCE, &info);
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(der)
        )
    }

    #[test]
    fn a_p256_key_is_read_into_its_point() {
        let Some(PublicKey::P256 { x, y }) = read(P256_KEY, Shape::P256) else {
            panic!("a P-256 key");
        };
        assert_eq!((x.len(), y.len()), (32, 32));
        assert_eq!(x[..4], [0xf1, 0xe7, 0xe2, 0x75]);
        assert_eq!(read(P256_KEY, Shape::Rsa), None, "not an RSA key");
        assert_eq!(read(P256_KEY, Shape::Ed25519), None, "not an Ed25519 key");
    }

    #[test]
    fn an_rsa_key_of_2048_bits_is_read_into_its_numbers() {
        let Some(PublicKey::Rsa { modulus, exponent }) = read(&rsa_key(256), Shape::Rsa) else {
            panic!("an RSA key");
        };
        assert_eq!(modulus.len(), 256);
        assert_eq!(modulus[0], 0xc0);
        assert_eq!(exponent, [1, 0, 1]);
        assert_eq!(read(&rsa_key(256), Shape::P256), None, "not a P-256 key");
        assert_eq!(read(&rsa_key(128), Shape::Rsa), None, "1024 bits");
        assert_eq!(read(&rsa_key(384), Shape::Rsa), None, "3072 bits");
    }

    /// An Ed25519 key as OpenBao 2.7.2 answered it.
    const ED25519_KEY: &str = "ZkHsesCL3A/mWHHe+o/lYfBnk0D4cJDl3RbyALxrQoQ=";

    #[test]
    fn an_ed25519_key_is_read_from_its_32_bytes_in_base64() {
        let Some(PublicKey::Ed25519 { x }) = read(ED25519_KEY, Shape::Ed25519) else {
            panic!("an Ed25519 key");
        };
        assert_eq!(x.len(), 32);
        assert_eq!(x[..4], [0x66, 0x41, 0xec, 0x7a]);
        assert_eq!(read(ED25519_KEY, Shape::P256), None, "not a PEM document");
        assert_eq!(read(P256_KEY, Shape::Ed25519), None, "a PEM document");
        for bad in [
            "",
            "ZkHsesCL3A/mWHHe+o/lYfBnk0D4cJDl3RbyALxrQo==",
            "not base64!",
        ] {
            assert_eq!(read(bad, Shape::Ed25519), None, "{bad}");
        }
    }

    #[test]
    fn anything_else_is_refused() {
        let cut = P256_KEY.replacen("==", "", 1);
        for bad in [
            "",
            "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----",
            &P256_KEY.replace("PUBLIC KEY", "PRIVATE KEY"),
            &P256_KEY.replace("MFkw", "MFow"),
            &cut,
        ] {
            assert_eq!(read(bad, Shape::P256), None, "{bad}");
        }
    }
}
