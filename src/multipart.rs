//! `multipart/form-data` request bodies.
//!
//! Build a payload with [`Multipart`] and hand it to
//! [`RequestBuilder::multipart_body`](crate::client::RequestBuilder::multipart_body),
//! which sets the matching `Content-Type` boundary for you:
//!
//! ```no_run
//! use zenwave::{Client, multipart::{Multipart, MultipartPart}};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let form = Multipart::new()
//!     .with_part(MultipartPart::text("name", "zenwave"))
//!     .with_part(MultipartPart::binary(
//!         "avatar",
//!         "avatar.png",
//!         "image/png",
//!         vec![0x89, 0x50, 0x4E, 0x47],
//!     ));
//!
//! let mut client = zenwave::client();
//! let response = client
//!     .post("https://example.com/upload")?
//!     .multipart_body(form)
//!     .await?;
//! # let _ = response;
//! # Ok(())
//! # }
//! ```
//!
//! The payload is assembled in memory, so very large uploads are better sent
//! with [`RequestBuilder::file_body`](crate::client::RequestBuilder::file_body),
//! which streams from disk.

use std::{
    borrow::Cow,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Representation of a multipart/form-data field.
#[derive(Debug, Clone)]
pub struct MultipartPart {
    name: Cow<'static, str>,
    filename: Option<Cow<'static, str>>,
    content_type: Option<Cow<'static, str>>,
    data: Vec<u8>,
}

impl MultipartPart {
    /// Create a field with raw bytes.
    #[must_use]
    pub fn new(name: impl Into<Cow<'static, str>>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            filename: None,
            content_type: None,
            data: data.into(),
        }
    }

    /// Create a text field using UTF-8 content.
    #[must_use]
    pub fn text(name: impl Into<Cow<'static, str>>, value: impl Into<String>) -> Self {
        Self::new(name, value.into().into_bytes())
    }

    /// Create a binary field with filename and content type metadata.
    #[must_use]
    pub fn binary(
        name: impl Into<Cow<'static, str>>,
        filename: impl Into<Cow<'static, str>>,
        content_type: impl Into<Cow<'static, str>>,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            name: name.into(),
            filename: Some(filename.into()),
            content_type: Some(content_type.into()),
            data: data.into(),
        }
    }

    /// Attach/override the filename metadata.
    #[must_use]
    pub fn with_filename(mut self, filename: impl Into<Cow<'static, str>>) -> Self {
        self.filename = Some(filename.into());
        self
    }

    /// Attach/override the content type metadata.
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<Cow<'static, str>>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Field name sent in `Content-Disposition`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Filename sent in `Content-Disposition`, when set.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Per-part `Content-Type`, when set.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Raw field content.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Builder-style helper for assembling multipart bodies.
#[derive(Debug, Default, Clone)]
pub struct Multipart {
    boundary: Option<String>,
    parts: Vec<MultipartPart>,
}

impl Multipart {
    /// Create an empty multipart container.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the boundary string (otherwise generated).
    ///
    /// An explicit boundary is used as given; it is the caller's responsibility
    /// to pick one that does not occur in any part's data. Prefer the generated
    /// boundary, which [`Multipart::encode`] guarantees is collision-free.
    #[must_use]
    pub fn boundary(mut self, boundary: impl Into<String>) -> Self {
        self.boundary = Some(boundary.into());
        self
    }

    /// Add a part to the payload (builder-style).
    #[must_use]
    pub fn with_part(mut self, part: MultipartPart) -> Self {
        self.parts.push(part);
        self
    }

    /// Push a part into the payload.
    pub fn push(&mut self, part: MultipartPart) {
        self.parts.push(part);
    }

    /// Number of parts in the payload.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.parts.len()
    }

    /// Whether the payload has no parts.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Encode the multipart payload into `(boundary, body_bytes)`.
    ///
    /// When no boundary was set, one is generated that is guaranteed not to
    /// appear in any part's data, so a part can never terminate the payload
    /// early.
    #[must_use]
    pub fn encode(self) -> (String, Vec<u8>) {
        encode_with(self.boundary, &self.parts)
    }
}

/// Encode multipart parts into a request body buffer plus boundary string.
// Takes the parts by value to mirror `Multipart::encode`, which owns them.
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn encode(parts: Vec<MultipartPart>) -> (String, Vec<u8>) {
    encode_with(None, &parts)
}

fn encode_with(boundary_override: Option<String>, parts: &[MultipartPart]) -> (String, Vec<u8>) {
    let boundary = boundary_override.unwrap_or_else(|| unique_boundary(parts));

    // Pre-size the buffer: each part costs its data plus a header block.
    let payload_len: usize = parts.iter().map(|part| part.data.len()).sum();
    let mut body = Vec::with_capacity(payload_len + parts.len() * (boundary.len() + 96) + 8);

    for part in parts {
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
        body.extend_from_slice(escape_quotes(part.name()).as_bytes());
        body.push(b'"');
        if let Some(filename) = part.filename() {
            body.extend_from_slice(b"; filename=\"");
            body.extend_from_slice(escape_quotes(filename).as_bytes());
            body.push(b'"');
        }
        body.extend_from_slice(b"\r\n");
        if let Some(content_type) = part.content_type() {
            body.extend_from_slice(b"Content-Type: ");
            body.extend_from_slice(content_type.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(part.data());
        body.extend_from_slice(b"\r\n");
    }

    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");

    (boundary, body)
}

/// Escape quotes and strip newlines so a field name cannot break out of the
/// `Content-Disposition` header it is embedded in.
fn escape_quotes(value: &str) -> Cow<'_, str> {
    if !value.contains(['"', '\\', '\r', '\n']) {
        return Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(value.len() + 8);
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            // A newline here would inject a header; drop it.
            '\r' | '\n' => {}
            other => escaped.push(other),
        }
    }
    Cow::Owned(escaped)
}

/// Generate a boundary that does not occur in any part's data.
///
/// A boundary appearing inside a part would terminate the payload early, so the
/// candidate is checked against every part and extended until it is unique.
fn unique_boundary(parts: &[MultipartPart]) -> String {
    let mut boundary = candidate_boundary();
    while parts
        .iter()
        .any(|part| contains_subslice(part.data(), boundary.as_bytes()))
    {
        use std::fmt::Write as _;
        // Extending the boundary keeps the already-checked prefix intact.
        write!(boundary, "{:x}", next_counter()).expect("writing to a String cannot fail");
    }
    boundary
}

/// A boundary candidate built from the clock and a process-local counter.
fn candidate_boundary() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_micros());
    format!("zenwave-{micros:x}-{:x}", next_counter())
}

/// Monotonic counter so two payloads built in the same microsecond still differ.
fn next_counter() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Whether `haystack` contains `needle`.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{Multipart, MultipartPart, contains_subslice, encode, escape_quotes};

    fn as_text(body: &[u8]) -> String {
        String::from_utf8_lossy(body).into_owned()
    }

    #[test]
    fn encodes_a_text_field_with_crlf_framing() {
        let (boundary, body) = Multipart::new()
            .boundary("BOUND")
            .with_part(MultipartPart::text("name", "zenwave"))
            .encode();

        assert_eq!(boundary, "BOUND");
        assert_eq!(
            as_text(&body),
            "--BOUND\r\n\
             Content-Disposition: form-data; name=\"name\"\r\n\
             \r\n\
             zenwave\r\n\
             --BOUND--\r\n"
        );
    }

    #[test]
    fn encodes_a_binary_field_with_filename_and_content_type() {
        let (_, body) = Multipart::new()
            .boundary("B")
            .with_part(MultipartPart::binary(
                "avatar",
                "a.png",
                "image/png",
                vec![1, 2, 3],
            ))
            .encode();

        let text = as_text(&body);
        assert!(
            text.contains("Content-Disposition: form-data; name=\"avatar\"; filename=\"a.png\""),
            "got {text}"
        );
        assert!(
            text.contains("Content-Type: image/png\r\n\r\n"),
            "got {text}"
        );
    }

    #[test]
    fn encodes_multiple_parts_in_order() {
        let (_, body) = Multipart::new()
            .boundary("B")
            .with_part(MultipartPart::text("first", "1"))
            .with_part(MultipartPart::text("second", "2"))
            .encode();

        let text = as_text(&body);
        let first = text
            .find("name=\"first\"")
            .expect("first part must be present");
        let second = text
            .find("name=\"second\"")
            .expect("second part must be present");
        assert!(first < second, "parts must keep insertion order: {text}");
        assert_eq!(text.matches("--B\r\n").count(), 2);
        assert!(text.ends_with("--B--\r\n"), "got {text}");
    }

    #[test]
    fn an_empty_payload_still_closes_its_boundary() {
        let (_, body) = Multipart::new().boundary("B").encode();
        assert_eq!(as_text(&body), "--B--\r\n");
    }

    #[test]
    fn a_generated_boundary_never_occurs_in_the_payload() {
        // Force a collision: the part data contains a plausible boundary prefix.
        let mut data = b"prefix".to_vec();
        let probe = super::candidate_boundary();
        data.extend_from_slice(probe.as_bytes());

        let (boundary, body) = encode(vec![MultipartPart::new("f", data.clone())]);
        assert!(
            !contains_subslice(&data, boundary.as_bytes()),
            "boundary {boundary} must not appear in the part data"
        );
        // The delimiter must occur exactly where the encoder put it.
        assert_eq!(
            as_text(&body).matches(&format!("--{boundary}")).count(),
            2,
            "boundary must delimit only the part and the terminator"
        );
    }

    #[test]
    fn generated_boundaries_differ_between_payloads() {
        let (first, _) = encode(vec![MultipartPart::text("a", "1")]);
        let (second, _) = encode(vec![MultipartPart::text("a", "1")]);
        assert_ne!(
            first, second,
            "two payloads must not share a boundary even when built together"
        );
    }

    #[test]
    fn field_names_cannot_inject_headers() {
        let (_, body) = Multipart::new()
            .boundary("B")
            .with_part(MultipartPart::text("evil\"\r\nX-Injected: yes", "value"))
            .encode();

        let text = as_text(&body);
        assert!(
            !text.contains("X-Injected: yes\r\n"),
            "a newline in a field name must not create a header: {text}"
        );
        assert!(
            text.contains("name=\"evil\\\"X-Injected: yes\""),
            "got {text}"
        );
    }

    #[test]
    fn quotes_and_backslashes_in_names_are_escaped() {
        assert_eq!(escape_quotes("plain"), "plain");
        assert_eq!(escape_quotes("a\"b"), "a\\\"b");
        assert_eq!(escape_quotes("a\\b"), "a\\\\b");
        assert_eq!(escape_quotes("a\r\nb"), "ab");
    }

    #[test]
    fn part_metadata_is_readable_back() {
        let part = MultipartPart::new("f", vec![7_u8])
            .with_filename("f.bin")
            .with_content_type("application/octet-stream");
        assert_eq!(part.name(), "f");
        assert_eq!(part.filename(), Some("f.bin"));
        assert_eq!(part.content_type(), Some("application/octet-stream"));
        assert_eq!(part.data(), [7]);
    }

    #[test]
    fn payload_length_is_tracked() {
        let mut form = Multipart::new();
        assert!(form.is_empty());
        form.push(MultipartPart::text("a", "1"));
        form.push(MultipartPart::text("b", "2"));
        assert_eq!(form.len(), 2);
        assert!(!form.is_empty());
    }

    #[test]
    fn subslice_search_handles_edge_cases() {
        assert!(contains_subslice(b"hello", b"ell"));
        assert!(contains_subslice(b"hello", b"hello"));
        assert!(!contains_subslice(b"hello", b"world"));
        assert!(!contains_subslice(b"hi", b"longer"));
        assert!(!contains_subslice(b"hi", b""));
    }
}
