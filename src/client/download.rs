use std::{
    io::{ErrorKind, SeekFrom},
    path::{Path, PathBuf},
};

use async_fs::OpenOptions;
use futures_util::StreamExt;
use http_kit::{
    BodyError, HttpError, StatusCode, header,
    utils::{AsyncSeekExt, AsyncWriteExt},
};

use super::RequestBuilder;

/// Errors produced while downloading a response body to a file.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError<E: HttpError> {
    /// The range request could not be constructed.
    #[error("request build error: {0}")]
    Build(#[source] Box<crate::Error>),

    /// The underlying client failed to perform the request.
    #[error("request error: {0}")]
    Remote(#[source] E),

    /// The response body stream failed partway through.
    #[error("failed to read response body: {0}")]
    Body(#[source] BodyError),

    /// The destination file could not be opened, written, or flushed.
    #[error("file system error: {0}")]
    Io(#[source] std::io::Error),

    /// The server answered with a status that carries no body to save.
    #[error("upstream returned unsuccessful status: {0}")]
    Upstream(StatusCode),

    /// The server answered `206 Partial Content` for a range other than the one
    /// requested, so appending its body would corrupt the file.
    #[error("server resumed at byte {actual} but byte {expected} was requested")]
    UnexpectedRange {
        /// First byte offset the client asked to resume from.
        expected: u64,
        /// First byte offset the server actually sent.
        actual: u64,
    },
}

impl<E: HttpError> HttpError for DownloadError<E> {
    fn status(&self) -> StatusCode {
        match self {
            Self::Build(err) => err.status(),
            Self::Remote(err) => err.status(),
            Self::Body(_) | Self::UnexpectedRange { .. } => StatusCode::BAD_GATEWAY,
            Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Upstream(status) => *status,
        }
    }
}

// Convert DownloadError to unified zenwave::Error
impl<E> From<DownloadError<E>> for crate::Error
where
    E: HttpError + Into<Self>,
{
    fn from(err: DownloadError<E>) -> Self {
        use crate::error::DownloadErrorKind;

        match err {
            DownloadError::Build(e) => *e,
            DownloadError::Remote(e) => e.into(),
            DownloadError::Body(e) => Self::Download(DownloadErrorKind::BodyRead(e.to_string())),
            DownloadError::Io(e) => Self::Download(DownloadErrorKind::FileSystem(e)),
            DownloadError::Upstream(status) => {
                Self::Download(DownloadErrorKind::UpstreamError(status))
            }
            DownloadError::UnexpectedRange { expected, actual } => {
                Self::Download(DownloadErrorKind::UnexpectedRange { expected, actual })
            }
        }
    }
}

/// Report describing the result of a download operation.
#[derive(Debug, Clone)]
pub struct DownloadReport {
    /// Destination path that was written to.
    pub path: PathBuf,
    /// Offset the download resumed from (0 if this was a fresh download).
    pub resumed_from: u64,
    /// Number of bytes written during this invocation.
    pub bytes_written: u64,
}

impl DownloadReport {
    /// Total bytes now persisted on disk.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.resumed_from + self.bytes_written
    }
}

/// Snapshot of download progress, reported after each chunk is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadProgress {
    /// Bytes already on disk before this download started.
    pub resumed_from: u64,
    /// Bytes written by this download so far.
    pub bytes_written: u64,
    /// Total size of the resource when the server reported one.
    pub total_bytes: Option<u64>,
}

impl DownloadProgress {
    /// Bytes currently persisted on disk.
    #[must_use]
    pub const fn downloaded_bytes(&self) -> u64 {
        self.resumed_from + self.bytes_written
    }

    /// Completion ratio in `0.0..=1.0`, when the total size is known.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fraction(&self) -> Option<f64> {
        let total = self.total_bytes?;
        if total == 0 {
            return Some(1.0);
        }
        Some((self.downloaded_bytes() as f64 / total as f64).min(1.0))
    }
}

/// Configures how downloads should behave.
#[derive(Debug, Clone, Copy)]
pub struct DownloadOptions {
    /// Attempt to resume when the destination file already contains data.
    pub resume_existing: bool,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            resume_existing: true,
        }
    }
}

/// Stream a response body to `path`, resuming from any bytes already there.
///
/// `on_progress` is invoked after each chunk reaches the file.
pub async fn download_to_path<T: crate::Client>(
    mut builder: RequestBuilder<'_, T>,
    path: impl AsRef<Path>,
    options: DownloadOptions,
    mut on_progress: impl FnMut(DownloadProgress),
) -> Result<DownloadReport, DownloadError<T::Error>> {
    let path_buf = path.as_ref().to_path_buf();
    let existing_len = if options.resume_existing {
        match async_fs::metadata(&path_buf).await {
            Ok(meta) => meta.len(),
            Err(err) if err.kind() == ErrorKind::NotFound => 0,
            Err(err) => return Err(DownloadError::Io(err)),
        }
    } else {
        0
    };

    if existing_len > 0 {
        builder = builder
            .header(header::RANGE.as_str(), format!("bytes={existing_len}-"))
            .map_err(|error| DownloadError::Build(Box::new(error)))?;
    }

    let response = builder.await.map_err(DownloadError::Remote)?;
    let status = response.status();

    if !(status.is_success() || status == StatusCode::PARTIAL_CONTENT) {
        return Err(DownloadError::Upstream(status));
    }

    let resuming = existing_len > 0 && status == StatusCode::PARTIAL_CONTENT;
    let content_range = parse_content_range(response.headers());

    // A 206 for a different offset than we asked for would silently corrupt the
    // file, so refuse it rather than appending mismatched bytes.
    if resuming
        && let Some(range) = &content_range
        && range.first_byte != existing_len
    {
        return Err(DownloadError::UnexpectedRange {
            expected: existing_len,
            actual: range.first_byte,
        });
    }

    let total_bytes = if resuming {
        content_range.and_then(|range| range.complete_length)
    } else {
        content_length(response.headers())
    };

    let mut body = response.into_body();
    let resumed_from = if resuming { existing_len } else { 0 };

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(!resuming)
        .open(&path_buf)
        .await
        .map_err(DownloadError::Io)?;
    if resuming {
        file.seek(SeekFrom::Start(existing_len))
            .await
            .map_err(DownloadError::Io)?;
    }

    let mut bytes_written = 0_u64;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(DownloadError::Body)?;
        file.write_all(&chunk).await.map_err(DownloadError::Io)?;
        bytes_written = bytes_written.saturating_add(chunk.len() as u64);
        on_progress(DownloadProgress {
            resumed_from,
            bytes_written,
            total_bytes,
        });
    }
    file.flush().await.map_err(DownloadError::Io)?;

    Ok(DownloadReport {
        path: path_buf,
        resumed_from,
        bytes_written,
    })
}

/// The parts of a `Content-Range: bytes first-last/complete` header we act on.
struct ContentRange {
    first_byte: u64,
    complete_length: Option<u64>,
}

fn parse_content_range(headers: &http_kit::header::HeaderMap) -> Option<ContentRange> {
    let raw = headers.get(header::CONTENT_RANGE)?.to_str().ok()?;
    let spec = raw.trim().strip_prefix("bytes")?.trim_start();
    let (range, complete) = spec.split_once('/')?;
    let first_byte = range.split('-').next()?.trim().parse().ok()?;
    Some(ContentRange {
        first_byte,
        complete_length: complete.trim().parse().ok(),
    })
}

fn content_length(headers: &http_kit::header::HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::{DownloadProgress, parse_content_range};
    use http_kit::header::{CONTENT_RANGE, HeaderMap, HeaderValue};

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_RANGE,
            HeaderValue::from_str(value).expect("test header is valid"),
        );
        headers
    }

    #[test]
    fn parses_a_complete_content_range() {
        let range = parse_content_range(&headers("bytes 1024-4095/4096"))
            .expect("a well-formed range must parse");
        assert_eq!(range.first_byte, 1024);
        assert_eq!(range.complete_length, Some(4096));
    }

    #[test]
    fn parses_a_content_range_with_unknown_total() {
        let range = parse_content_range(&headers("bytes 512-1023/*"))
            .expect("an unknown total must still yield the offset");
        assert_eq!(range.first_byte, 512);
        assert_eq!(range.complete_length, None);
    }

    #[test]
    fn rejects_a_content_range_without_a_total_separator() {
        assert!(parse_content_range(&headers("bytes 0-99")).is_none());
    }

    #[test]
    fn progress_reports_a_fraction_only_when_the_total_is_known() {
        let known = DownloadProgress {
            resumed_from: 100,
            bytes_written: 100,
            total_bytes: Some(400),
        };
        assert_eq!(known.downloaded_bytes(), 200);
        assert_eq!(known.fraction(), Some(0.5));

        let unknown = DownloadProgress {
            resumed_from: 0,
            bytes_written: 10,
            total_bytes: None,
        };
        assert_eq!(unknown.fraction(), None);
    }

    #[test]
    fn progress_fraction_saturates_when_more_arrives_than_promised() {
        let overshoot = DownloadProgress {
            resumed_from: 0,
            bytes_written: 500,
            total_bytes: Some(400),
        };
        assert_eq!(overshoot.fraction(), Some(1.0));
    }
}
