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

#[derive(Debug, thiserror::Error)]
pub enum DownloadError<E: HttpError> {
    #[error("request error: {0}")]
    Remote(#[source] E),

    #[error("invalid request: {0}")]
    Request(String),

    #[error("failed to read response body: {0}")]
    Body(#[source] BodyError),

    #[error("file system error: {0}")]
    Io(#[source] std::io::Error),

    #[error("upstream returned unsuccessful status: {0}")]
    Upstream(StatusCode),
}

impl<E: HttpError> HttpError for DownloadError<E> {
    fn status(&self) -> StatusCode {
        match self {
            Self::Remote(err) => err.status(),
            Self::Request(_) => StatusCode::BAD_REQUEST,
            Self::Body(_) => StatusCode::BAD_GATEWAY,
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
            DownloadError::Remote(e) => e.into(),
            DownloadError::Request(msg) => Self::InvalidRequest(msg),
            DownloadError::Body(e) => Self::Download(DownloadErrorKind::BodyRead(e.to_string())),
            DownloadError::Io(e) => Self::Download(DownloadErrorKind::FileSystem(e)),
            DownloadError::Upstream(status) => {
                Self::Download(DownloadErrorKind::UpstreamError(status))
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
    pub const fn total_bytes(&self) -> u64 {
        self.resumed_from + self.bytes_written
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

pub async fn download_to_path<T: crate::Client>(
    mut builder: RequestBuilder<'_, T>,
    path: impl AsRef<Path>,
    options: DownloadOptions,
) -> Result<DownloadReport, DownloadError<T::Error>> {
    let path_buf = path.as_ref().to_path_buf();
    let existing_len = if options.resume_existing {
        match async_fs::metadata(&path_buf).await {
            Ok(meta) => meta.len(),
            Err(err) if err.kind() == ErrorKind::NotFound => 0,
            Err(err) => {
                return Err(DownloadError::Io(err));
            }
        }
    } else {
        0
    };

    if existing_len > 0 {
        let value = format!("bytes={existing_len}-");
        builder = builder
            .header(header::RANGE.as_str(), value)
            .map_err(|err| DownloadError::Request(err.to_string()))?;
    }

    let response = builder.await.map_err(DownloadError::Remote)?;
    let status = response.status();
    let mut body = response.into_body();

    if !(status.is_success() || status == StatusCode::PARTIAL_CONTENT) {
        return Err(DownloadError::Upstream(status));
    }

    let mut resumed_from = 0_u64;
    let mut file = if existing_len > 0 && status == StatusCode::PARTIAL_CONTENT {
        resumed_from = existing_len;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path_buf)
            .await
            .map_err(DownloadError::Io)?;
        file.seek(SeekFrom::Start(existing_len))
            .await
            .map_err(DownloadError::Io)?;
        file
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path_buf)
            .await
            .map_err(DownloadError::Io)?
    };

    let mut bytes_written = 0_u64;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(DownloadError::Body)?;
        file.write_all(&chunk).await.map_err(DownloadError::Io)?;
        bytes_written += chunk.len() as u64;
    }
    file.flush().await.map_err(DownloadError::Io)?;

    Ok(DownloadReport {
        path: path_buf,
        resumed_from,
        bytes_written,
    })
}
