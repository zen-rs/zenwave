use std::{
    borrow::Cow,
    time::{SystemTime, UNIX_EPOCH},
};

/// Representation of a multipart/form-data field.
#[derive(Debug)]
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
        data: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            filename: Some(filename.into()),
            content_type: Some(content_type.into()),
            data,
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

    pub(crate) const fn name(&self) -> &Cow<'static, str> {
        &self.name
    }

    pub(crate) const fn filename(&self) -> Option<&Cow<'static, str>> {
        self.filename.as_ref()
    }

    pub(crate) const fn content_type(&self) -> Option<&Cow<'static, str>> {
        self.content_type.as_ref()
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Builder-style helper for assembling multipart bodies.
#[derive(Debug, Default)]
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

    /// Override the boundary string (otherwise auto-generated).
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

    /// Encode the multipart payload into `(boundary, body_bytes)`.
    #[must_use]
    pub fn encode(self) -> (String, Vec<u8>) {
        encode_with(self.boundary, self.parts)
    }
}

/// Encode multipart parts into a request body buffer plus boundary string.
#[must_use]
pub fn encode(parts: Vec<MultipartPart>) -> (String, Vec<u8>) {
    encode_with(None, parts)
}

fn encode_with(boundary_override: Option<String>, parts: Vec<MultipartPart>) -> (String, Vec<u8>) {
    let boundary = boundary_override.unwrap_or_else(default_boundary);
    let mut body = Vec::new();

    for part in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"{}\r\n",
                part.name(),
                part.filename()
                    .map(|name| format!("; filename=\"{name}\""))
                    .unwrap_or_default()
            )
            .as_bytes(),
        );
        if let Some(content_type) = part.content_type() {
            body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(part.data());
        body.extend_from_slice(b"\r\n");
    }

    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

fn default_boundary() -> String {
    format!("zenwave-{:#x}", monotonic_suffix())
}

fn monotonic_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|_| 0, |duration| duration.as_micros())
}
