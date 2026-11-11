//! Field formats in signed payloads: base64url, `sha256:` hashes, UTC time (design/auth.md section
//! 10.5).

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodingError {
    #[error("not unpadded base64url")]
    Base64,
    #[error("expected {expected} bytes, got {actual}")]
    Length { expected: usize, actual: usize },
    #[error("hash must be `sha256:` followed by 64 lower-case hex digits")]
    Hash,
    #[error("time must be `YYYY-MM-DDTHH:MM:SSZ` in UTC")]
    Time,
}

/// Decodes unpadded base64url. Only the canonical encoding is accepted (the extra trailing bits
/// must be 0), so the same bytes have only one spelling.
pub fn decode_b64(s: &str) -> Result<Vec<u8>, EncodingError> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| EncodingError::Base64)
}

pub fn decode_b64_fixed<const N: usize>(s: &str) -> Result<[u8; N], EncodingError> {
    let bytes = decode_b64(s)?;
    let actual = bytes.len();
    bytes.try_into().map_err(|_| EncodingError::Length {
        expected: N,
        actual,
    })
}

pub fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// serde helper: a `Vec<u8>` field is represented as a base64url string.
pub mod b64 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_b64(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        decode_b64(&s).map_err(serde::de::Error::custom)
    }
}

/// serde helper: a fixed-length byte array is represented as a base64url string.
pub mod b64_fixed {
    use super::*;

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_b64(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(deserializer)?;
        decode_b64_fixed(&s).map_err(serde::de::Error::custom)
    }
}

/// A SHA-256 digest, whose text form is `sha256:` followed by 64 lowercase hexadecimal digits.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    pub fn of(data: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Self(out)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Sha256Digest {
    type Err = EncodingError;

    fn from_str(s: &str) -> Result<Self, EncodingError> {
        let hex = s.strip_prefix("sha256:").ok_or(EncodingError::Hash)?;
        if hex.len() != 64 {
            return Err(EncodingError::Hash);
        }
        let mut out = [0u8; 32];
        for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            out[i] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
        Ok(Self(out))
    }
}

fn hex_digit(c: u8) -> Result<u8, EncodingError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(EncodingError::Hash),
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// UTC time, accurate to the second, whose text form is `YYYY-MM-DDTHH:MM:SSZ`. Internally it is
/// Unix time (seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    pub const fn unix_seconds(self) -> i64 {
        self.0
    }

    /// The current time. Used only to compare with times in signed payloads; durations use a
    /// monotonic clock.
    pub fn now() -> Self {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            // When the clock is earlier than 1970, no payload is treated as unexpired
            .unwrap_or(i64::MAX);
        Self(seconds)
    }
}

impl FromStr for Timestamp {
    type Err = EncodingError;

    fn from_str(s: &str) -> Result<Self, EncodingError> {
        let b = s.as_bytes();
        let shape_ok = b.len() == 20
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z';
        if !shape_ok {
            return Err(EncodingError::Time);
        }
        let num = |range: std::ops::Range<usize>| -> Result<i64, EncodingError> {
            b[range].iter().try_fold(0i64, |acc, &c| {
                if c.is_ascii_digit() {
                    Ok(acc * 10 + i64::from(c - b'0'))
                } else {
                    Err(EncodingError::Time)
                }
            })
        };
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
        let valid = (1..=12).contains(&month)
            && (1..=days_in_month(year, month)).contains(&day)
            && hour < 24
            && minute < 60
            && second < 60;
        if !valid {
            return Err(EncodingError::Time);
        }
        let days = days_from_civil(year, month, day);
        Ok(Self(days * 86_400 + hour * 3_600 + minute * 60 + second))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.0.div_euclid(86_400);
        let secs = self.0.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            secs / 3_600,
            secs % 3_600 / 60,
            secs % 60
        )
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Conversion between a Gregorian date and the number of days since 1970-01-01 (Howard Hinnant's
// days_from_civil algorithm)
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_is_strict() {
        assert_eq!(decode_b64("AQID"), Ok(vec![1, 2, 3]));
        assert_eq!(encode_b64(&[0xfb, 0xff]), "-_8");
        assert!(decode_b64("AQID=").is_err(), "padding");
        assert!(decode_b64("+/8").is_err(), "standard alphabet");
        assert!(decode_b64("-_9").is_err(), "non-zero trailing bits");
        assert_eq!(
            decode_b64_fixed::<4>("AQID"),
            Err(EncodingError::Length {
                expected: 4,
                actual: 3
            })
        );
    }

    #[test]
    fn sha256_text_form() {
        let d = Sha256Digest::of(b"abc");
        let text = d.to_string();
        assert_eq!(
            text,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(text.parse::<Sha256Digest>(), Ok(d));
        assert!(text.to_uppercase().parse::<Sha256Digest>().is_err());
        assert!("sha256:abcd".parse::<Sha256Digest>().is_err());
    }

    #[test]
    fn timestamp_round_trip() {
        for (text, unix) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2000-02-29T23:59:59Z", 951_868_799),
            ("2026-11-06T09:30:00Z", 1_793_957_400),
        ] {
            let t: Timestamp = text.parse().expect(text);
            assert_eq!(t.unix_seconds(), unix, "{text}");
            assert_eq!(t.to_string(), text);
        }
    }

    #[test]
    fn timestamp_rejects_other_forms() {
        for bad in [
            "2026-11-06T09:30:00.000Z",
            "2026-11-06T09:30:00+08:00",
            "2026-11-06 09:30:00Z",
            "2026-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-11-06T24:00:00Z",
            "2026-11-06T23:59:60Z",
            "+026-11-06T09:30:00Z",
        ] {
            assert_eq!(bad.parse::<Timestamp>(), Err(EncodingError::Time), "{bad}");
        }
    }
}
