//! A narrow reader of CBOR: the subset that WebAuthn authenticators write.
//!
//! Integers, byte strings, text strings, arrays and maps of definite
//! length, and the simple values true, false and null, nested at most
//! eight deep. Everything else is refused: indefinite lengths, tags,
//! floating-point numbers, other simple values, and a length longer than
//! what is left of the input. See Decision 0024.

/// The deepest nesting accepted.
const MAX_DEPTH: usize = 8;

/// One value, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    /// An integer, unsigned or negative, in the range CBOR can carry.
    Integer(i128),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A text string.
    Text(String),
    /// An array.
    Array(Vec<Value>),
    /// A map, its pairs in the order they were written.
    Map(Vec<(Value, Value)>),
    /// True or false.
    Bool(bool),
    /// Null.
    Null,
}

impl Value {
    /// The value for a key of a map, if this is a map holding it.
    pub(crate) fn get(&self, key: &Self) -> Option<&Self> {
        match self {
            Self::Map(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value for a text key of a map.
    pub(crate) fn get_text(&self, key: &str) -> Option<&Self> {
        self.get(&Self::Text(key.to_owned()))
    }

    /// The value for an integer key of a map.
    pub(crate) fn get_integer(&self, key: i128) -> Option<&Self> {
        self.get(&Self::Integer(key))
    }

    /// The bytes, if this is a byte string.
    pub(crate) fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// The integer, if this is one.
    pub(crate) const fn as_integer(&self) -> Option<i128> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }
}

/// Why the input could not be read. Never shown to anyone: a reason for a
/// test to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CborError {
    /// The input ended in the middle of a value.
    Truncated,
    /// A kind of value outside the subset.
    Unsupported,
    /// Nested deeper than allowed.
    TooDeep,
    /// A text string that is not UTF-8.
    NotText,
    /// A map with the same key twice.
    DuplicateKey,
}

/// Reads one value from the start of `input` and says how many bytes it
/// took. What follows is left to the caller.
///
/// # Errors
///
/// Returns why the value could not be read.
pub(crate) fn read(input: &[u8]) -> Result<(Value, usize), CborError> {
    let mut reader = Reader { input, position: 0 };
    let value = reader.value(0)?;
    Ok((value, reader.position))
}

/// Reads one value that must take the whole of `input`.
///
/// # Errors
///
/// Returns why the value could not be read; `Unsupported` if anything is
/// left over.
pub(crate) fn read_exactly(input: &[u8]) -> Result<Value, CborError> {
    let (value, used) = read(input)?;
    if used == input.len() {
        Ok(value)
    } else {
        Err(CborError::Unsupported)
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], CborError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.input.len())
            .ok_or(CborError::Truncated)?;
        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        Ok(self.take(1)?[0])
    }

    /// The argument that follows an initial byte: the value itself, or a
    /// length.
    fn argument(&mut self, additional: u8) -> Result<u64, CborError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => Ok(u64::from(self.byte()?)),
            25 => Ok(u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().map_err(|_| CborError::Truncated)?,
            ))),
            26 => Ok(u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().map_err(|_| CborError::Truncated)?,
            ))),
            27 => Ok(u64::from_be_bytes(
                self.take(8)?.try_into().map_err(|_| CborError::Truncated)?,
            )),
            // 28 to 30 are reserved; 31 is an indefinite length.
            _ => Err(CborError::Unsupported),
        }
    }

    /// A length, which can never be more than what is left: every item
    /// takes at least one byte.
    fn length(&mut self, additional: u8) -> Result<usize, CborError> {
        let length = self.argument(additional)?;
        let left = self.input.len() - self.position;
        usize::try_from(length)
            .ok()
            .filter(|length| *length <= left)
            .ok_or(CborError::Truncated)
    }

    fn value(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let initial = self.byte()?;
        let (major, additional) = (initial >> 5, initial & 0x1f);
        match major {
            0 => Ok(Value::Integer(i128::from(self.argument(additional)?))),
            1 => Ok(Value::Integer(-1 - i128::from(self.argument(additional)?))),
            2 => {
                let length = self.length(additional)?;
                Ok(Value::Bytes(self.take(length)?.to_vec()))
            }
            3 => {
                let length = self.length(additional)?;
                let bytes = self.take(length)?.to_vec();
                String::from_utf8(bytes)
                    .map(Value::Text)
                    .map_err(|_| CborError::NotText)
            }
            4 => {
                let count = self.length(additional)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let count = self.length(additional)?;
                let mut pairs: Vec<(Value, Value)> = Vec::with_capacity(count);
                for _ in 0..count {
                    let key = self.value(depth + 1)?;
                    if pairs.iter().any(|(existing, _)| *existing == key) {
                        return Err(CborError::DuplicateKey);
                    }
                    let value = self.value(depth + 1)?;
                    pairs.push((key, value));
                }
                Ok(Value::Map(pairs))
            }
            7 => match additional {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(CborError::Unsupported),
            },
            // Major type 6 is a tag.
            _ => Err(CborError::Unsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CborError, Value, read, read_exactly};
    use proptest::prelude::*;

    #[test]
    fn reads_the_subset() {
        // {1: 2, 3: -7, -1: 1, -2: h'0102', "fmt": "none", "a": [true, false, null]}
        let input = [
            0xa6, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x42, 0x01, 0x02, 0x63, b'f', b'm',
            b't', 0x64, b'n', b'o', b'n', b'e', 0x61, b'a', 0x83, 0xf5, 0xf4, 0xf6,
        ];
        let value = read_exactly(&input).expect("read");
        assert_eq!(value.get_integer(1), Some(&Value::Integer(2)));
        assert_eq!(value.get_integer(3), Some(&Value::Integer(-7)));
        assert_eq!(value.get_integer(-1), Some(&Value::Integer(1)));
        assert_eq!(
            value.get_integer(-2).and_then(Value::as_bytes),
            Some(&[1_u8, 2][..])
        );
        assert_eq!(value.get_text("fmt"), Some(&Value::Text("none".to_owned())));
        assert_eq!(
            value.get_text("a"),
            Some(&Value::Array(vec![
                Value::Bool(true),
                Value::Bool(false),
                Value::Null
            ]))
        );
    }

    #[test]
    fn reads_long_arguments() {
        assert_eq!(read_exactly(&[0x18, 200]), Ok(Value::Integer(200)));
        assert_eq!(read_exactly(&[0x19, 0x01, 0x00]), Ok(Value::Integer(256)));
        assert_eq!(
            read_exactly(&[0x1a, 0, 1, 0, 0]),
            Ok(Value::Integer(65_536))
        );
        assert_eq!(
            read_exactly(&[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Ok(Value::Integer(-18_446_744_073_709_551_616))
        );
    }

    #[test]
    fn says_how_much_it_read() {
        let (value, used) = read(&[0x42, 9, 9, 0xff, 0xff]).expect("read");
        assert_eq!(value, Value::Bytes(vec![9, 9]));
        assert_eq!(used, 3);
        assert_eq!(
            read_exactly(&[0x42, 9, 9, 0xff]),
            Err(CborError::Unsupported)
        );
    }

    #[test]
    fn refuses_what_is_outside_the_subset() {
        for (input, reason) in [
            (&[0x5f, 0x41, 0x00, 0xff][..], CborError::Unsupported), // indefinite bytes
            (&[0x9f, 0xff][..], CborError::Unsupported),             // indefinite array
            (&[0xc0, 0x00][..], CborError::Unsupported),             // a tag
            (&[0xf9, 0x3c, 0x00][..], CborError::Unsupported),       // a half float
            (&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0][..], CborError::Unsupported), // a double
            (&[0xf7][..], CborError::Unsupported),                   // undefined
            (&[0x1c][..], CborError::Unsupported),                   // reserved
            (&[0x62, 0xff, 0xfe][..], CborError::NotText),
            (&[0xa2, 0x01, 0x00, 0x01, 0x00][..], CborError::DuplicateKey),
            (&[][..], CborError::Truncated),
            (&[0x19, 0x01][..], CborError::Truncated),
            (&[0x45, 1, 2][..], CborError::Truncated),
            (&[0x83, 0x01][..], CborError::Truncated),
            // A length far beyond the input is refused before anything
            // is set aside for it.
            (
                &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
                CborError::Truncated,
            ),
            (
                &[0x9b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
                CborError::Truncated,
            ),
        ] {
            assert_eq!(read(input).map(|(v, _)| v), Err(reason), "{input:02x?}");
        }
    }

    #[test]
    fn refuses_nesting_deeper_than_eight() {
        let mut fits = vec![0x81_u8; 8];
        fits.push(0x00);
        assert!(read_exactly(&fits).is_ok());
        let mut too_deep = vec![0x81_u8; 9];
        too_deep.push(0x00);
        assert_eq!(read_exactly(&too_deep), Err(CborError::TooDeep));
    }

    proptest! {
        #[test]
        fn never_panics_and_never_reads_past_the_end(input in proptest::collection::vec(any::<u8>(), 0..256)) {
            if let Ok((_, used)) = read(&input) {
                prop_assert!(used <= input.len());
            }
        }
    }
}
