//! Opening a connection to a target through a [`Transport`].

use super::{Transport, happy_eyeballs, stream::Stream};
use crate::Error;

/// Where a connection should end up.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    pub tls: bool,
}

/// Connect to `target`, wrapping the TCP stream in TLS when the target asks for it.
pub async fn connect(transport: &Transport, target: Target<'_>) -> Result<Stream, Error> {
    let tcp = happy_eyeballs::connect(target.host, target.port)
        .await
        .map_err(|error| Error::Transport(Box::new(error)))?;
    tcp.set_nodelay(true)
        .map_err(|error| Error::Transport(Box::new(error)))?;

    if !target.tls {
        return Ok(Stream::Tcp(tcp));
    }

    let tls = transport.tls().connect(target.host, tcp).await?;
    Ok(Stream::Tls(Box::new(tls)))
}
