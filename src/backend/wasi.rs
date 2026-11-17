//! WASI Preview 3 HTTP client backend (`wasi:http/client`).
//!
//! Delegates outgoing HTTP requests to the WASI host via [`wasip3::http::client`]
//! and request-level sleeps to [`WasiClock`](crate::clock::WasiClock). The host
//! owns TLS, certificate verification, proxying, and connection pooling; per-request
//! and transport [`Timeouts`] map directly to `wasi:http/types.request-options`.

use core::{
    future::{Future, IntoFuture},
    pin::{Pin, pin},
    task::{Context, Poll},
    time::Duration,
};
use std::{io, sync::Arc};

use futures_util::{
    FutureExt as _, Stream, StreamExt as _,
    future::{Either, select},
};
use http::{
    HeaderMap, HeaderName, HeaderValue, StatusCode,
    header::{self, CONTENT_LENGTH},
    uri::Authority,
};
use http_kit::{Body, BodyError, BodyFrame, Endpoint, ReceiveError, Request, Response};
use wasip3::{
    http::{
        client,
        types::{
            ErrorCode, Fields, Method as WasiMethod, Request as WasiRequest, RequestOptions,
            Response as WasiResponse, Scheme as WasiScheme,
        },
    },
    wit_bindgen::{FutureReader, FutureWriter, StreamReader, StreamResult, StreamWriter},
    wit_future, wit_stream,
};

use super::shared::{received, take_request};
use crate::{
    Attempt, Cause, Client, ConfigError, ConnectFailure, ConnectPhase, Error, ExchangeFailure, Hop,
    ResolveError, TcpFailure, TimedOut, Timeouts, TlsError, TlsFailure, Transport,
    clock::{Clocked, WasiClock},
};

/// Chunk size for reading from a `wasi:http` response body `stream<u8>`.
const READ_FRAME_SIZE: usize = 16 * 1024;

/// HTTP client backend over WASI Preview 3 `wasi:http/client`.
///
/// The WASI host performs DNS resolution, TLS verification, proxying, and
/// connection pooling. `Timeouts` on the [`Transport`] or per-request are
/// forwarded through `wasi:http/types.request-options`.
#[derive(Debug, Clone)]
pub struct WasiBackend {
    transport: Transport,
}

impl WasiBackend {
    /// Construct a `WasiBackend` backed by `transport`.
    #[must_use]
    pub const fn new(transport: Transport) -> Self {
        Self { transport }
    }

    /// Reject transport settings that the WASI host cannot honor when
    /// `native-backend` is also compiled into the same binary.
    #[cfg(native)]
    fn validate_transport(&self) -> Result<(), Error> {
        if matches!(
            self.transport.proxy().source(),
            crate::transport::proxy::Source::Explicit
        ) {
            return Err(Error::Config(ConfigError::Unsupported {
                what: "custom proxy rules",
            }));
        }
        if !self.transport.extra_roots().is_empty() {
            return Err(Error::Config(ConfigError::Unsupported {
                what: "extra root certificates",
            }));
        }
        Ok(())
    }

    #[cfg(not(native))]
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    const fn validate_transport(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Default for WasiBackend {
    fn default() -> Self {
        Self::new(Transport::system())
    }
}

impl Endpoint for WasiBackend {
    type Error = Error;

    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.validate_transport()?;

        let request_timeouts = request.extensions().get::<Timeouts>().copied();
        let timeouts = request_timeouts
            .unwrap_or_default()
            .or(self.transport.timeouts());
        let http_request = take_request(request);

        let prepared = prepare_request(http_request, timeouts)?;
        let send_ctx = SendContext {
            host: prepared.origin_host,
            port: prepared.origin_port,
            declared_len: prepared.declared_len,
        };

        let (wasi_resp, remaining_pump) = match prepared.body {
            None => {
                let response = client::send(prepared.request)
                    .await
                    .map_err(|code| classify_send_error(code, &send_ctx))?;
                (response, None)
            }
            Some((body, stream_tx, trailers_tx, tx_res)) => {
                drive_streaming_send(
                    prepared.request,
                    body,
                    stream_tx,
                    trailers_tx,
                    tx_res,
                    &send_ctx,
                )
                .await?
            }
        };

        into_response(wasi_resp, remaining_pump)
    }
}

http_kit::impl_send_endpoint!(WasiBackend);

impl Client for WasiBackend {}

impl Clocked for WasiBackend {
    type Clock = WasiClock;

    fn clock(&self) -> Self::Clock {
        WasiClock
    }
}

struct SendContext {
    host: String,
    port: u16,
    declared_len: Option<u64>,
}

type StreamingBody = (
    Body,
    StreamWriter<u8>,
    FutureWriter<Result<Option<Fields>, ErrorCode>>,
    FutureReader<Result<(), ErrorCode>>,
);

struct PreparedRequest {
    request: WasiRequest,
    origin_host: String,
    origin_port: u16,
    declared_len: Option<u64>,
    body: Option<StreamingBody>,
}

fn prepare_request(
    request: http::Request<Body>,
    timeouts: Timeouts,
) -> Result<PreparedRequest, Error> {
    let (mut parts, body) = request.into_parts();
    let options = build_request_options(timeouts)?;
    let declared_len = declared_content_length(&parts.headers)?;

    let host_header = parts
        .headers
        .remove(header::HOST)
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|err| Error::InvalidRequest(err.to_string()))
        })
        .transpose()?;

    let authority_str = match (parts.uri.authority(), host_header) {
        (Some(uri_auth), Some(host)) if !uri_auth.as_str().eq_ignore_ascii_case(&host) => {
            return Err(Error::InvalidRequest(
                "Host header does not match URI authority".to_owned(),
            ));
        }
        (Some(uri_auth), _) => uri_auth.as_str().to_owned(),
        (None, Some(host)) => host,
        (None, None) => return Err(Error::InvalidUri(parts.uri.to_string())),
    };

    let parsed_authority: Authority = authority_str
        .parse()
        .map_err(|_| Error::InvalidUri(parts.uri.to_string()))?;
    let scheme = match parts.uri.scheme_str().unwrap_or("http") {
        "http" => WasiScheme::Http,
        "https" => WasiScheme::Https,
        _ => return Err(Error::InvalidUri(parts.uri.to_string())),
    };
    let default_port = if matches!(scheme, WasiScheme::Https) {
        443
    } else {
        80
    };
    let origin_host = parsed_authority.host().to_owned();
    let origin_port = parsed_authority.port_u16().unwrap_or(default_port);

    let headers = header_map_to_fields(&parts.headers)?;
    let method = map_method(&parts.method);
    let path_with_query = parts
        .uri
        .path_and_query()
        .map(http::uri::PathAndQuery::as_str);

    let (wasi_req, streaming_body) = if body.is_empty() == Some(true) {
        let (trailers_tx, trailers_rx) = wit_future::new(|| Ok(None));
        drop(trailers_tx);
        let (wasi_req, _tx_res) = WasiRequest::new(headers, None, trailers_rx, options);
        (wasi_req, None)
    } else {
        let (stream_tx, stream_rx) = wit_stream::new::<u8>();
        let (trailers_tx, trailers_rx) =
            wit_future::new(|| Err(ErrorCode::HttpRequestBodySize(None)));
        let (wasi_req, tx_res) = WasiRequest::new(headers, Some(stream_rx), trailers_rx, options);
        (wasi_req, Some((body, stream_tx, trailers_tx, tx_res)))
    };

    wasi_req
        .set_method(&method)
        .map_err(|()| Error::InvalidRequest(format!("unsupported HTTP method {}", parts.method)))?;
    wasi_req
        .set_scheme(Some(&scheme))
        .map_err(|()| Error::InvalidUri(parts.uri.to_string()))?;
    wasi_req
        .set_authority(Some(&authority_str))
        .map_err(|()| Error::InvalidUri(parts.uri.to_string()))?;
    wasi_req
        .set_path_with_query(path_with_query)
        .map_err(|()| Error::InvalidUri(parts.uri.to_string()))?;

    Ok(PreparedRequest {
        request: wasi_req,
        origin_host,
        origin_port,
        declared_len,
        body: streaming_body,
    })
}

fn timeout_nanos(duration: Option<Duration>) -> Option<u64> {
    duration
        .filter(|value| *value != Duration::MAX)
        .map(|value| u64::try_from(value.as_nanos()).unwrap_or(u64::MAX))
}

fn build_request_options(timeouts: Timeouts) -> Result<Option<RequestOptions>, Error> {
    let connect = timeout_nanos(timeouts.connect);
    let first_byte = timeout_nanos(timeouts.exchange.response_head);
    let between_bytes = timeout_nanos(timeouts.exchange.body_idle);

    if connect.is_none() && first_byte.is_none() && between_bytes.is_none() {
        return Ok(None);
    }

    let options = RequestOptions::new();
    if connect.is_some() {
        options.set_connect_timeout(connect).map_err(|_| {
            Error::Config(ConfigError::Unsupported {
                what: "connect timeout",
            })
        })?;
    }
    if first_byte.is_some() {
        options.set_first_byte_timeout(first_byte).map_err(|_| {
            Error::Config(ConfigError::Unsupported {
                what: "response-head timeout",
            })
        })?;
    }
    if between_bytes.is_some() {
        options
            .set_between_bytes_timeout(between_bytes)
            .map_err(|_| {
                Error::Config(ConfigError::Unsupported {
                    what: "body-idle timeout",
                })
            })?;
    }
    Ok(Some(options))
}

fn declared_content_length(headers: &HeaderMap) -> Result<Option<u64>, Error> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::InvalidRequest(
            "multiple Content-Length headers".to_owned(),
        ));
    }
    let text = first
        .to_str()
        .map_err(|err| Error::InvalidRequest(err.to_string()))?;
    let parsed = text
        .parse::<u64>()
        .map_err(|_| Error::InvalidRequest(format!("invalid Content-Length `{text}`")))?;
    Ok(Some(parsed))
}

fn header_map_to_fields(headers: &HeaderMap) -> Result<Fields, Error> {
    let entries: Vec<(String, Vec<u8>)> = headers
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    Fields::from_list(&entries).map_err(|err| Error::InvalidRequest(err.to_string()))
}

fn map_method(method: &http::Method) -> WasiMethod {
    match *method {
        http::Method::GET => WasiMethod::Get,
        http::Method::HEAD => WasiMethod::Head,
        http::Method::POST => WasiMethod::Post,
        http::Method::PUT => WasiMethod::Put,
        http::Method::DELETE => WasiMethod::Delete,
        http::Method::CONNECT => WasiMethod::Connect,
        http::Method::OPTIONS => WasiMethod::Options,
        http::Method::TRACE => WasiMethod::Trace,
        http::Method::PATCH => WasiMethod::Patch,
        _ => WasiMethod::Other(method.as_str().to_owned()),
    }
}

type PumpFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

async fn drive_streaming_send(
    wasi_req: WasiRequest,
    body: Body,
    stream_tx: StreamWriter<u8>,
    trailers_tx: FutureWriter<Result<Option<Fields>, ErrorCode>>,
    tx_res: FutureReader<Result<(), ErrorCode>>,
    send_ctx: &SendContext,
) -> Result<(WasiResponse, Option<PumpFuture>), Error> {
    let send_fut = pin!(client::send(wasi_req));
    let pump_fut: PumpFuture = Box::pin(pump_request_body(body, stream_tx, trailers_tx));

    match select(send_fut, pump_fut).await {
        Either::Right((pump_res, send_fut)) => {
            let send_res = send_fut.await;
            pump_res?;
            let response = send_res
                .map_err(|code| classify_send_error(recover_tx_error(code, tx_res), send_ctx))?;
            Ok((response, None))
        }
        Either::Left((send_res, pump_fut)) => {
            let response = send_res
                .map_err(|code| classify_send_error(recover_tx_error(code, tx_res), send_ctx))?;
            Ok((response, Some(pump_fut)))
        }
    }
}

fn recover_tx_error(mut code: ErrorCode, tx_res: FutureReader<Result<(), ErrorCode>>) -> ErrorCode {
    if matches!(code, ErrorCode::InternalError(_))
        && let Some(Err(specific)) = tx_res.into_future().now_or_never()
    {
        code = specific;
    }
    code
}

async fn pump_request_body(
    mut body: Body,
    mut stream_tx: StreamWriter<u8>,
    trailers_tx: FutureWriter<Result<Option<Fields>, ErrorCode>>,
) -> Result<(), Error> {
    let mut trailers = HeaderMap::new();
    while let Some(frame) = body.next().await {
        match frame {
            Ok(BodyFrame::Data(chunk)) => {
                if !chunk.is_empty() {
                    let unwritten = stream_tx.write_all(chunk.to_vec()).await;
                    if !unwritten.is_empty() {
                        // The host dropped `stream_rx` early (e.g., short-circuit response).
                        return Ok(());
                    }
                }
            }
            Ok(BodyFrame::Trailers(map)) => {
                trailers.extend(map);
            }
            Ok(other) => {
                let message = format!("unsupported request body frame in wasi-backend: {other:?}");
                drop(stream_tx);
                let _ = trailers_tx
                    .write(Err(ErrorCode::InternalError(Some(message.clone()))))
                    .await;
                return Err(Error::exchange(
                    ExchangeFailure::RequestBody,
                    Cause::Detail(message),
                ));
            }
            Err(error) => {
                let message = error.to_string();
                drop(stream_tx);
                let _ = trailers_tx
                    .write(Err(ErrorCode::InternalError(Some(message.clone()))))
                    .await;
                return Err(Error::exchange(
                    ExchangeFailure::RequestBody,
                    Cause::Detail(message),
                ));
            }
        }
    }

    drop(stream_tx);
    let encoded_trailers = if trailers.is_empty() {
        None
    } else {
        match header_map_to_fields(&trailers) {
            Ok(fields) => Some(fields),
            Err(error) => {
                let _ = trailers_tx
                    .write(Err(ErrorCode::InternalError(Some(error.to_string()))))
                    .await;
                return Err(error);
            }
        }
    };
    let _ = trailers_tx.write(Ok(encoded_trailers)).await;
    Ok(())
}

fn into_response(
    wasi_resp: WasiResponse,
    remaining_pump: Option<PumpFuture>,
) -> Result<Response, Error> {
    let status = StatusCode::from_u16(wasi_resp.get_status_code()).map_err(|err| {
        Error::exchange(ExchangeFailure::Protocol, Cause::Detail(err.to_string()))
    })?;
    let headers = parse_fields(&wasi_resp.get_headers()).map_err(|detail| {
        Error::exchange(ExchangeFailure::Protocol, Cause::Detail(detail.to_owned()))
    })?;

    let (res_tx, res_rx) = wit_future::new(|| Ok(()));
    let (stream, trailers) = WasiResponse::consume_body(wasi_resp, res_rx);

    let body = Body::from_frames(ResponseBodyStream(std::sync::Mutex::new(
        ResponseBodyState {
            _res_tx: res_tx,
            pump: remaining_pump,
            phase: ReadPhase::Idle { stream, trailers },
        },
    )));

    let mut response = http::Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    received(&response);
    Ok(response)
}

fn parse_fields(fields: &Fields) -> Result<HeaderMap, &'static str> {
    let mut map = HeaderMap::new();
    for (name, value) in fields.copy_all() {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "invalid header name")?;
        let value = HeaderValue::from_bytes(&value).map_err(|_| "invalid header value")?;
        map.append(name, value);
    }
    Ok(map)
}

struct ResponseBodyStream(std::sync::Mutex<ResponseBodyState>);

struct ResponseBodyState {
    // Keep the completion writer alive until the response stream finishes or is dropped
    // so the host I/O task is not signaled prematurely.
    _res_tx: FutureWriter<Result<(), ErrorCode>>,
    pump: Option<PumpFuture>,
    phase: ReadPhase,
}

enum ReadPhase {
    Idle {
        stream: StreamReader<u8>,
        trailers: FutureReader<Result<Option<Fields>, ErrorCode>>,
    },
    Reading(Pin<Box<dyn Future<Output = ReadStep> + Send>>),
    Done,
}

enum ReadStep {
    Data {
        chunk: Vec<u8>,
        stream: StreamReader<u8>,
        trailers: FutureReader<Result<Option<Fields>, ErrorCode>>,
    },
    Trailers(HeaderMap),
    Error(BodyError),
    End,
}

impl Stream for ResponseBodyStream {
    type Item = Result<BodyFrame, BodyError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let state = self
            .get_mut()
            .0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.poll_next(cx)
    }
}

impl ResponseBodyState {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<BodyFrame, BodyError>>> {
        if let Some(pump) = self.pump.as_mut() {
            match pump.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => self.pump = None,
                Poll::Ready(Err(error)) => {
                    self.pump = None;
                    self.phase = ReadPhase::Done;
                    return Poll::Ready(Some(Err(BodyError::Other(Box::new(error)))));
                }
                Poll::Pending => {}
            }
        }

        if let ReadPhase::Idle { .. } = self.phase {
            let ReadPhase::Idle {
                mut stream,
                trailers,
            } = core::mem::replace(&mut self.phase, ReadPhase::Done)
            else {
                unreachable!();
            };
            self.phase = ReadPhase::Reading(Box::pin(async move {
                loop {
                    let (status, chunk) = stream.read(Vec::with_capacity(READ_FRAME_SIZE)).await;
                    match status {
                        StreamResult::Complete(_) => {
                            if !chunk.is_empty() {
                                return ReadStep::Data {
                                    chunk,
                                    stream,
                                    trailers,
                                };
                            }
                        }
                        StreamResult::Dropped | StreamResult::Cancelled => {
                            return match trailers.await {
                                Ok(Some(fields)) => {
                                    match parse_fields(&fields) {
                                        Ok(map) => ReadStep::Trailers(map),
                                        Err(detail) => ReadStep::Error(BodyError::Receive(
                                            ReceiveError::Framing { detail },
                                        )),
                                    }
                                }
                                Ok(None) => ReadStep::End,
                                Err(code) => ReadStep::Error(BodyError::Receive(
                                    classify_receive_error(code),
                                )),
                            };
                        }
                    }
                }
            }));
        }

        match &mut self.phase {
            ReadPhase::Reading(future) => match core::task::ready!(future.as_mut().poll(cx)) {
                ReadStep::Data {
                    chunk,
                    stream,
                    trailers,
                } => {
                    self.phase = ReadPhase::Idle { stream, trailers };
                    Poll::Ready(Some(Ok(BodyFrame::Data(chunk.into()))))
                }
                ReadStep::Trailers(map) => {
                    self.phase = ReadPhase::Done;
                    Poll::Ready(Some(Ok(BodyFrame::Trailers(map))))
                }
                ReadStep::Error(error) => {
                    self.phase = ReadPhase::Done;
                    Poll::Ready(Some(Err(error)))
                }
                ReadStep::End => {
                    self.phase = ReadPhase::Done;
                    Poll::Ready(None)
                }
            },
            ReadPhase::Done => Poll::Ready(None),
            ReadPhase::Idle { .. } => unreachable!(),
        }
    }
}

fn classify_send_error(code: ErrorCode, ctx: &SendContext) -> Error {
    let connect = |failure| Error::connect(Hop::Origin, &ctx.host, ctx.port, failure);
    let tcp = |kind: io::ErrorKind, err: ErrorCode| {
        connect(ConnectFailure::Tcp(TcpFailure::new(vec![Attempt::new(
            None,
            io::Error::new(kind, err),
        )])))
    };

    match code {
        ErrorCode::DnsTimeout => Error::Timeout(TimedOut::Connect {
            during: ConnectPhase::Resolve,
        }),
        ErrorCode::ConnectionTimeout => Error::Timeout(TimedOut::Connect {
            during: ConnectPhase::Tcp,
        }),
        ErrorCode::HttpResponseTimeout | ErrorCode::ConnectionReadTimeout => {
            Error::Timeout(TimedOut::ResponseHead)
        }
        ErrorCode::DestinationNotFound => connect(ConnectFailure::Resolve(ResolveError::NoAddress)),
        ErrorCode::DnsError(ref payload)
            if payload
                .rcode
                .as_deref()
                .is_some_and(|rcode| rcode.eq_ignore_ascii_case("NXDomain")) =>
        {
            connect(ConnectFailure::Resolve(ResolveError::NoAddress))
        }
        ErrorCode::DnsError(_) => connect(ConnectFailure::Resolve(ResolveError::Lookup(
            Cause::Wasi(code),
        ))),
        ErrorCode::ConnectionRefused => tcp(io::ErrorKind::ConnectionRefused, code),
        ErrorCode::DestinationUnavailable => tcp(io::ErrorKind::HostUnreachable, code),
        ErrorCode::DestinationIpProhibited => tcp(io::ErrorKind::PermissionDenied, code),
        ErrorCode::DestinationIpUnroutable => tcp(io::ErrorKind::NetworkUnreachable, code),
        ErrorCode::ConnectionLimitReached => tcp(io::ErrorKind::Other, code),
        ErrorCode::TlsCertificateError => connect(ConnectFailure::Tls(TlsError::new(
            TlsFailure::Certificate,
            Cause::Wasi(code),
        ))),
        ErrorCode::TlsAlertReceived(ref payload) => {
            let failure =
                payload
                    .alert_id
                    .map_or(TlsFailure::Protocol, |alert| TlsFailure::AlertReceived {
                        alert,
                    });
            connect(ConnectFailure::Tls(TlsError::new(
                failure,
                Cause::Wasi(code),
            )))
        }
        ErrorCode::TlsProtocolError => connect(ConnectFailure::Tls(TlsError::new(
            TlsFailure::Protocol,
            Cause::Wasi(code),
        ))),
        other => classify_exchange_error(other, ctx),
    }
}

fn classify_exchange_error(code: ErrorCode, ctx: &SendContext) -> Error {
    match code {
        ErrorCode::HttpRequestUriInvalid | ErrorCode::HttpRequestUriTooLong => {
            Error::InvalidUri(code.to_string())
        }
        ErrorCode::HttpRequestBodySize(_) => {
            let failure = ctx
                .declared_len
                .map_or(ExchangeFailure::RequestBody, |declared| {
                    ExchangeFailure::RequestBodyLength { declared }
                });
            Error::exchange(failure, Cause::Wasi(code))
        }
        ErrorCode::HttpRequestMethodInvalid
        | ErrorCode::HttpRequestDenied
        | ErrorCode::HttpRequestLengthRequired
        | ErrorCode::HttpRequestHeaderSectionSize(_)
        | ErrorCode::HttpRequestHeaderSize(_)
        | ErrorCode::HttpRequestTrailerSectionSize(_)
        | ErrorCode::HttpRequestTrailerSize(_) => {
            Error::exchange(ExchangeFailure::InvalidRequest, Cause::Wasi(code))
        }
        ErrorCode::ConnectionTerminated => {
            Error::exchange(ExchangeFailure::Terminated, Cause::Wasi(code))
        }
        ErrorCode::HttpResponseIncomplete | ErrorCode::HttpResponseBodySize(_) => {
            Error::exchange(ExchangeFailure::Incomplete, Cause::Wasi(code))
        }
        ErrorCode::HttpResponseHeaderSectionSize(limit) => {
            let failure = limit.map_or(ExchangeFailure::Protocol, |size| {
                ExchangeFailure::HeadTooLarge {
                    limit: usize::try_from(size).unwrap_or(usize::MAX),
                }
            });
            Error::exchange(failure, Cause::Wasi(code))
        }
        ErrorCode::HttpResponseHeaderSize(ref payload) => {
            let failure = payload
                .field_size
                .map_or(ExchangeFailure::Protocol, |size| {
                    ExchangeFailure::HeadTooLarge {
                        limit: usize::try_from(size).unwrap_or(usize::MAX),
                    }
                });
            Error::exchange(failure, Cause::Wasi(code))
        }
        ErrorCode::HttpResponseTrailerSectionSize(limit) => {
            let failure = limit.map_or(ExchangeFailure::Protocol, |size| {
                ExchangeFailure::TrailersTooLarge {
                    limit: usize::try_from(size).unwrap_or(usize::MAX),
                }
            });
            Error::exchange(failure, Cause::Wasi(code))
        }
        ErrorCode::HttpResponseTrailerSize(ref payload) => {
            let failure = payload
                .field_size
                .map_or(ExchangeFailure::Protocol, |size| {
                    ExchangeFailure::TrailersTooLarge {
                        limit: usize::try_from(size).unwrap_or(usize::MAX),
                    }
                });
            Error::exchange(failure, Cause::Wasi(code))
        }
        ErrorCode::HttpResponseTransferCoding(_) | ErrorCode::HttpResponseContentCoding(_) => {
            Error::exchange(ExchangeFailure::TransferCoding, Cause::Wasi(code))
        }
        ErrorCode::HttpProtocolError | ErrorCode::HttpUpgradeFailed | ErrorCode::LoopDetected => {
            Error::exchange(ExchangeFailure::Protocol, Cause::Wasi(code))
        }
        ErrorCode::ConfigurationError => Error::Config(ConfigError::Unsupported {
            what: "host HTTP configuration",
        }),
        _ => Error::exchange(ExchangeFailure::Io, Cause::Wasi(code)),
    }
}

fn classify_receive_error(code: ErrorCode) -> ReceiveError {
    match code {
        ErrorCode::HttpResponseTimeout | ErrorCode::ConnectionReadTimeout => ReceiveError::Stalled,
        ErrorCode::HttpResponseIncomplete
        | ErrorCode::HttpResponseBodySize(_)
        | ErrorCode::ConnectionTerminated => ReceiveError::Incomplete,
        ErrorCode::HttpResponseTrailerSectionSize(limit) => ReceiveError::TrailersTooLarge {
            limit: usize::try_from(limit.unwrap_or(0)).unwrap_or(usize::MAX),
        },
        ErrorCode::HttpResponseTrailerSize(ref payload) => ReceiveError::TrailersTooLarge {
            limit: usize::try_from(payload.field_size.unwrap_or(0)).unwrap_or(usize::MAX),
        },
        ErrorCode::HttpProtocolError
        | ErrorCode::HttpResponseTransferCoding(_)
        | ErrorCode::HttpResponseContentCoding(_) => ReceiveError::Framing {
            detail: "wasi:http response body framing error",
        },
        ErrorCode::TlsProtocolError
        | ErrorCode::TlsCertificateError
        | ErrorCode::TlsAlertReceived(_) => {
            ReceiveError::Connection(Arc::new(io::Error::new(io::ErrorKind::InvalidData, code)))
        }
        other => ReceiveError::Connection(Arc::new(io::Error::other(other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasip3::http::types::{DnsErrorPayload, FieldSizePayload, TlsAlertReceivedPayload};

    fn ctx() -> SendContext {
        SendContext {
            host: "example.com".to_owned(),
            port: 443,
            declared_len: Some(12),
        }
    }

    #[test]
    fn classify_timeouts_and_connect_errors() {
        let context = ctx();
        assert!(matches!(
            classify_send_error(ErrorCode::DnsTimeout, &context),
            Error::Timeout(TimedOut::Connect {
                during: ConnectPhase::Resolve
            })
        ));
        assert!(matches!(
            classify_send_error(ErrorCode::ConnectionTimeout, &context),
            Error::Timeout(TimedOut::Connect {
                during: ConnectPhase::Tcp
            })
        ));
        assert!(matches!(
            classify_send_error(ErrorCode::HttpResponseTimeout, &context),
            Error::Timeout(TimedOut::ResponseHead)
        ));
        assert!(matches!(
            classify_send_error(ErrorCode::DestinationNotFound, &context),
            Error::Connect(err) if matches!(err.failure, ConnectFailure::Resolve(ResolveError::NoAddress))
        ));
        assert!(matches!(
            classify_send_error(
                ErrorCode::DnsError(DnsErrorPayload {
                    rcode: Some("NXDomain".to_owned()),
                    info_code: None,
                }),
                &context,
            ),
            Error::Connect(err) if matches!(err.failure, ConnectFailure::Resolve(ResolveError::NoAddress))
        ));
        assert!(matches!(
            classify_send_error(ErrorCode::ConnectionRefused, &context),
            Error::Connect(err) if err.hop == Hop::Origin && err.port == 443 && matches!(err.failure, ConnectFailure::Tcp(_))
        ));
    }

    #[test]
    fn classify_tls_and_transient_flags() {
        let context = ctx();
        let cert = classify_send_error(ErrorCode::TlsCertificateError, &context);
        assert!(matches!(
            cert,
            Error::Connect(ref err)
                if matches!(
                    err.failure,
                    ConnectFailure::Tls(TlsError {
                        failure: TlsFailure::Certificate,
                        ..
                    })
                )
        ));
        assert!(!cert.is_transient());

        let alert = classify_send_error(
            ErrorCode::TlsAlertReceived(TlsAlertReceivedPayload {
                alert_id: Some(42),
                alert_message: None,
            }),
            &context,
        );
        assert!(matches!(
            alert,
            Error::Connect(ref err)
                if matches!(
                    err.failure,
                    ConnectFailure::Tls(TlsError {
                        failure: TlsFailure::AlertReceived { alert: 42 },
                        ..
                    })
                )
        ));
        assert!(!alert.is_transient());

        let terminated = classify_send_error(ErrorCode::ConnectionTerminated, &context);
        assert!(terminated.is_transient());
    }

    #[test]
    fn classify_exchange_and_receive_errors() {
        let context = ctx();
        assert!(matches!(
            classify_send_error(ErrorCode::HttpRequestUriInvalid, &context),
            Error::InvalidUri(_)
        ));
        assert!(matches!(
            classify_send_error(ErrorCode::HttpRequestBodySize(Some(9)), &context),
            Error::Exchange(err) if matches!(err.failure, ExchangeFailure::RequestBodyLength { declared: 12 })
        ));
        assert!(matches!(
            classify_send_error(ErrorCode::HttpResponseHeaderSectionSize(Some(8192)), &context),
            Error::Exchange(err) if matches!(err.failure, ExchangeFailure::HeadTooLarge { limit: 8192 })
        ));
        assert!(matches!(
            classify_send_error(
                ErrorCode::HttpResponseTrailerSize(FieldSizePayload {
                    field_name: Some("x".to_owned()),
                    field_size: Some(64),
                }),
                &context,
            ),
            Error::Exchange(err) if matches!(err.failure, ExchangeFailure::TrailersTooLarge { limit: 64 })
        ));
        assert!(matches!(
            classify_send_error(ErrorCode::HttpResponseTransferCoding(None), &context),
            Error::Exchange(err) if matches!(err.failure, ExchangeFailure::TransferCoding)
        ));
        assert!(matches!(
            classify_send_error(ErrorCode::ConfigurationError, &context),
            Error::Config(ConfigError::Unsupported { .. })
        ));

        let stalled = Error::from(BodyError::Receive(classify_receive_error(
            ErrorCode::HttpResponseTimeout,
        )));
        assert!(matches!(stalled, Error::Timeout(TimedOut::BodyIdle)));

        let incomplete = Error::from(BodyError::Receive(classify_receive_error(
            ErrorCode::HttpResponseIncomplete,
        )));
        assert!(matches!(
            incomplete,
            Error::Exchange(err) if matches!(err.failure, ExchangeFailure::Incomplete)
        ));
    }
}
