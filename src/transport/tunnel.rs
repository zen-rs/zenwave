//! HTTP `CONNECT` tunnels through a forward proxy.

use futures_io::{AsyncRead, AsyncWrite};
use futures_util::{
    FutureExt,
    future::{Either, join, select},
    pin_mut,
};
use http::{
    HeaderValue, Request,
    header::{HOST, PROXY_AUTHORIZATION},
};
use http_body_util::Empty;
use hyper::body::Bytes;

use super::hyper_io::HyperIo;
use crate::{Cause, ConnectFailure, Error, Hop, TunnelError};

/// Ask the proxy on `stream` (at `proxy`, host and port) for a tunnel to
/// `authority` (`host:port`) and hand back the raw stream once the proxy has
/// switched to relaying bytes.
pub async fn connect<S>(
    stream: S,
    proxy: (&str, u16),
    authority: &str,
    authorization: Option<&HeaderValue>,
) -> Result<S, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let fail = |error: TunnelError| {
        Error::connect(Hop::Proxy, proxy.0, proxy.1, ConnectFailure::Tunnel(error))
    };
    let broken = |error: hyper::Error| fail(TunnelError::Connection(Cause::Hyper(error)));

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(HyperIo(stream))
            .await
            .map_err(broken)?;
    // The connection future completes as soon as hyper switches the stream to
    // the upgraded state, which can happen in the same poll that delivers the
    // response. Fuse it and remember whether it already finished.
    let connection = connection.with_upgrades().fuse();
    pin_mut!(connection);
    let mut connection_finished = false;

    let mut request = Request::connect(authority)
        .header(HOST, authority)
        .body(Empty::new())
        .map_err(|error| Error::InvalidRequest(error.to_string()))?;
    if let Some(authorization) = authorization {
        request
            .headers_mut()
            .insert(PROXY_AUTHORIZATION, authorization.clone());
    }

    let response = {
        let send = sender.send_request(request);
        pin_mut!(send);
        match select(send, connection.as_mut()).await {
            Either::Left((response, _)) => response.map_err(broken)?,
            Either::Right((connection_result, send)) => {
                connection_result.map_err(broken)?;
                connection_finished = true;
                send.await.map_err(|error| {
                    if error.is_canceled() || error.is_closed() {
                        fail(TunnelError::Protocol(
                            "proxy closed the connection before answering CONNECT",
                        ))
                    } else {
                        broken(error)
                    }
                })?
            }
        }
    };

    if !response.status().is_success() {
        return Err(fail(TunnelError::Rejected(response.status())));
    }

    let upgraded = if connection_finished {
        hyper::upgrade::on(response).await
    } else {
        let (upgraded, connection_result) = join(hyper::upgrade::on(response), connection).await;
        connection_result.map_err(broken)?;
        upgraded
    };
    let parts = upgraded
        .map_err(broken)?
        .downcast::<HyperIo<S>>()
        .map_err(|_| fail(TunnelError::Protocol("tunnel stream lost its type")))?;
    if !parts.read_buf.is_empty() {
        return Err(fail(TunnelError::Protocol(
            "proxy sent bytes into the tunnel before the client spoke",
        )));
    }
    Ok(parts.io.0)
}
