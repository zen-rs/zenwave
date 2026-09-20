//! Alt-Svc response header parsing (RFC 7838).
//!
//! An `Alt-Svc` header advertises alternative endpoints for an origin —
//! `h3=":443"; ma=86400` says the origin also answers HTTP/3 on UDP 443 for
//! the next day. Only `h3` is interesting here, and only alternatives on the
//! origin's own host are accepted: a different host would need the same
//! certificate checks browsers do before trusting it (RFC 7838 §2.1), which
//! this client does not perform.

use std::{
    fmt,
    time::{Duration, Instant},
};

/// The `ma` an alternative gets when it advertises none (RFC 7838 §3: one day).
// `Duration::from_hours` is not a stable const fn yet.
#[expect(clippy::duration_suboptimal_units)]
const ALT_SVC_DEFAULT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// `ma` is clamped at a year — an advertisement beyond that horizon is
/// indistinguishable from "forever" and overflowing `Instant` is worse.
// `Duration::from_days` is not a stable const fn yet.
#[expect(clippy::duration_suboptimal_units)]
const MAX_AGE_CAP: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// An h3 alternative accepted from an Alt-Svc advertisement.
#[derive(Clone, Copy, Debug)]
pub struct AltSvc {
    /// The UDP port the alternative is served on.
    pub port: u16,
    /// When the advertisement stops being valid.
    pub expires: Instant,
}

/// What an `Alt-Svc` header advertises.
#[derive(Debug, PartialEq, Eq)]
pub enum Advertised {
    /// `clear`: the origin withdraws every advertised alternative.
    Clear,
    /// One or more `protocol-id "=" alt-authority` alternatives.
    Alternatives(Vec<Alternative>),
}

/// A single alternative: `protocol-id "=" "[host]:port"` plus parameters.
#[derive(Debug, PartialEq, Eq)]
pub struct Alternative {
    /// The percent-decoded protocol id, e.g. `h3` or `h3-29`.
    pub protocol: String,
    /// The alternative's host; `None` is the origin's own host.
    pub host: Option<String>,
    /// The alternative's port.
    pub port: u16,
    /// How long the advertisement stays valid (`ma`).
    pub max_age: Duration,
}

/// Why an `Alt-Svc` header value could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltSvcError {
    /// The value is neither `clear` nor a list of `protocol-id =
    /// "alt-authority"` alternatives.
    MalformedAlternative,
    /// A `protocol-id` is not a token or carries bad percent-encoding.
    InvalidProtocolId,
    /// An `alt-authority` quoted-string is missing, unterminated, or not
    /// `[host]:port`.
    InvalidAuthority,
    /// An `ma` parameter is not a number of seconds.
    InvalidMaxAge,
}

impl fmt::Display for AltSvcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedAlternative => write!(f, "not a valid alt-value list"),
            Self::InvalidProtocolId => write!(f, "invalid protocol-id"),
            Self::InvalidAuthority => write!(f, "invalid alt-authority"),
            Self::InvalidMaxAge => write!(f, "invalid ma parameter"),
        }
    }
}

impl core::error::Error for AltSvcError {}

/// Parse an `Alt-Svc` header value: `clear`, or a comma-separated list of
/// `protocol-id "=" quoted-authority` entries with `;` parameters. A malformed
/// header is `Err` — the caller logs it and answers the response anyway.
pub fn parse(value: &str) -> Result<Advertised, AltSvcError> {
    if value.trim() == "clear" {
        return Ok(Advertised::Clear);
    }
    let mut alternatives = Vec::new();
    for entry in split_quoted(value, ',') {
        alternatives.push(alt_value(entry)?);
    }
    Ok(Advertised::Alternatives(alternatives))
}

/// The usable alternative out of an advertisement: the first `h3` entry on
/// the origin's own host (or an omitted host), expiring `ma` from `now`.
/// `Clear` — and anything that is not `h3` on this host — yields `None`.
pub fn accept(advertised: &Advertised, origin_host: &str, now: Instant) -> Option<AltSvc> {
    let Advertised::Alternatives(alternatives) = advertised else {
        return None;
    };
    alternatives
        .iter()
        .filter(|alternative| {
            alternative.protocol == "h3"
                && alternative
                    .host
                    .as_deref()
                    .is_none_or(|host| host.eq_ignore_ascii_case(origin_host))
        })
        .map(|alternative| AltSvc {
            port: alternative.port,
            expires: now.checked_add(alternative.max_age).unwrap_or(now),
        })
        // `ma=0` expires on arrival — an already-dead advertisement is none.
        .find(|alternative| alternative.expires > now)
}

/// One `alt-value`: `protocol-id "=" quoted-string *( ";" parameter )`.
fn alt_value(value: &str) -> Result<Alternative, AltSvcError> {
    let (protocol, rest) = value
        .split_once('=')
        .ok_or(AltSvcError::MalformedAlternative)?;
    let protocol = percent_decode(protocol.trim())?;
    let (quoted, rest) = quoted_string(rest.trim_start())?;
    let (host, port) = authority(quoted.as_str())?;

    let mut max_age = ALT_SVC_DEFAULT_MAX_AGE;
    for parameter in split_quoted(rest, ';') {
        let parameter = parameter.trim();
        if parameter.is_empty() {
            continue;
        }
        let Some((key, value)) = parameter.split_once('=') else {
            return Err(AltSvcError::MalformedAlternative);
        };
        if key.trim() == "ma" {
            let seconds = value
                .trim()
                .trim_matches('"')
                .parse::<u64>()
                .map_err(|_| AltSvcError::InvalidMaxAge)?;
            max_age = Duration::from_secs(seconds).min(MAX_AGE_CAP);
        }
        // Unknown parameters — `persist` included — are ignored.
    }
    Ok(Alternative {
        protocol,
        host,
        port,
        max_age,
    })
}

/// Split `value` on `delimiter` wherever it occurs outside a quoted-string;
/// `\` escapes inside quotes keep a delimiter from splitting.
fn split_quoted(value: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut start = 0;
    for (index, c) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            _ if c == delimiter && !in_quotes => {
                parts.push(&value[start..index]);
                start = index + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

/// A quoted-string at the head of `value`: the unescaped content and the
/// remainder after the closing quote.
fn quoted_string(value: &str) -> Result<(String, &str), AltSvcError> {
    let rest = value
        .strip_prefix('"')
        .ok_or(AltSvcError::InvalidAuthority)?;
    let mut content = String::new();
    let mut escaped = false;
    for (index, c) in rest.char_indices() {
        if escaped {
            content.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return Ok((content, &rest[index + 1..])),
            c => content.push(c),
        }
    }
    Err(AltSvcError::InvalidAuthority)
}

/// `[host]:port` — an empty host defers to the origin's.
fn authority(value: &str) -> Result<(Option<String>, u16), AltSvcError> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or(AltSvcError::InvalidAuthority)?;
    let port = port
        .parse::<u16>()
        .map_err(|_| AltSvcError::InvalidAuthority)?;
    let host = (!host.is_empty()).then(|| host.to_owned());
    Ok((host, port))
}

/// Decode `%XX` escapes in a `protocol-id`; the rest must be token bytes.
fn percent_decode(raw: &str) -> Result<String, AltSvcError> {
    if !raw.contains('%') {
        if raw.is_empty() || !raw.bytes().all(is_token) {
            return Err(AltSvcError::InvalidProtocolId);
        }
        return Ok(raw.to_owned());
    }
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .ok_or(AltSvcError::InvalidProtocolId)?;
            let value = u8::from_str_radix(
                str::from_utf8(hex).map_err(|_| AltSvcError::InvalidProtocolId)?,
                16,
            )
            .map_err(|_| AltSvcError::InvalidProtocolId)?;
            decoded.push(value);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    if !decoded.iter().all(|byte| is_token(*byte)) {
        return Err(AltSvcError::InvalidProtocolId);
    }
    String::from_utf8(decoded).map_err(|_| AltSvcError::InvalidProtocolId)
}

/// RFC 7230 `token` bytes.
const fn is_token(byte: u8) -> bool {
    matches!(byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{Advertised, AltSvcError, accept, parse};

    fn advertised(value: &str) -> Advertised {
        parse(value).expect("test value must parse")
    }

    #[test]
    fn accepts_bare_h3_port() {
        let accepted = accept(&advertised(r#"h3=":443""#), "example.com", Instant::now());
        assert_eq!(accepted.expect("h3 must be accepted").port, 443);
    }

    #[test]
    fn honours_ma() {
        let now = Instant::now();
        let accepted = accept(&advertised(r#"h3=":443"; ma=3600"#), "example.com", now)
            .expect("h3 must be accepted");
        assert_eq!(accepted.expires, now + Duration::from_secs(3600));
    }

    #[test]
    fn rejects_another_host() {
        assert!(
            accept(
                &advertised(r#"h3="alt.example.com:443""#),
                "example.com",
                Instant::now()
            )
            .is_none(),
            "a cross-host alternative is never accepted"
        );
    }

    #[test]
    fn accepts_the_same_host_case_insensitively() {
        let accepted = accept(
            &advertised(r#"h3="LOCALHOST:8443""#),
            "localhost",
            Instant::now(),
        );
        assert_eq!(accepted.expect("same host must be accepted").port, 8443);
    }

    #[test]
    fn ignores_unknown_parameters() {
        let accepted = accept(
            &advertised(r#"h3=":443"; persist=1"#),
            "example.com",
            Instant::now(),
        );
        assert!(accepted.is_some(), "persist must not break parsing");
    }

    #[test]
    fn picks_h3_out_of_a_list() {
        let accepted = accept(
            &advertised(r#"h2=":443", h3=":8443""#),
            "example.com",
            Instant::now(),
        );
        assert_eq!(accepted.expect("h3 must be chosen").port, 8443);
    }

    #[test]
    fn clear_clears() {
        assert!(matches!(
            parse("clear").expect("clear must parse"),
            Advertised::Clear
        ));
        assert!(accept(&advertised("clear"), "example.com", Instant::now()).is_none());
    }

    #[test]
    fn ignores_h3_drafts() {
        assert!(
            accept(
                &advertised(r#"h3-29=":443""#),
                "example.com",
                Instant::now()
            )
            .is_none(),
            "only the exact h3 protocol id counts"
        );
    }

    #[test]
    fn rejects_bad_ma() {
        assert_eq!(
            parse(r#"h3=":443"; ma=abc"#),
            Err(AltSvcError::InvalidMaxAge)
        );
    }

    #[test]
    fn zero_ma_expires_immediately() {
        assert!(
            accept(
                &advertised(r#"h3=":443"; ma=0"#),
                "example.com",
                Instant::now()
            )
            .is_none(),
            "ma=0 expires on arrival"
        );
    }

    #[test]
    fn malformed_values_are_errors() {
        assert_eq!(parse(""), Err(AltSvcError::MalformedAlternative));
        assert_eq!(parse("h3"), Err(AltSvcError::MalformedAlternative));
        assert_eq!(parse(r"h3=:443"), Err(AltSvcError::InvalidAuthority));
        assert_eq!(
            parse(r#"h3=":notaport""#),
            Err(AltSvcError::InvalidAuthority)
        );
        assert_eq!(parse(r#"=":443""#), Err(AltSvcError::InvalidProtocolId));
    }

    #[test]
    fn percent_decoded_protocol_ids_match() {
        // %33 is '3': the decoded protocol is exactly "h3".
        let accepted = accept(&advertised(r#"h%33=":443""#), "example.com", Instant::now());
        assert!(accepted.is_some());
    }
}
