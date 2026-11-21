//! The futures-io rustls adapter the fixtures drive: the thin slice of
//! `futures-rustls` the test servers and test-side clients use, written in
//! tree so the crate does not resolve into the parent's dev-dependency graph
//! (a resolved-but-inactive copy there reads as an unused dependency under
//! `cargo::unused_dependencies`).

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

/// A rustls session over a futures-io byte stream, client or server side.
pub struct TlsStream<S> {
    io: S,
    conn: Connection,
}

impl<S> TlsStream<S> {
    /// The inner stream and the rustls session, as `futures-rustls` exposes
    /// them through `get_ref`.
    pub fn get_ref(&self) -> (&S, &Connection) {
        (&self.io, &self.conn)
    }
}

impl<S> Unpin for TlsStream<S> {}

/// `AsyncRead`/`AsyncWrite` presented to rustls's synchronous IO hooks: a
/// pending poll surfaces as `WouldBlock`, which the drive loops above turn
/// back into `Poll::Pending`.
struct Sync<'a, 'b, T>(&'a mut T, &'a mut Context<'b>);

impl<T: AsyncRead + Unpin> Read for Sync<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.0).poll_read(self.1, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<T: AsyncWrite + Unpin> Write for Sync<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.0).poll_write(self.1, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.0).poll_flush(self.1) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

fn tls_error(e: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    conn: &mut Connection,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while conn.is_handshaking() {
        match conn.complete_io(&mut Sync(io, cx)) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e)),
        }
    }
    Poll::Ready(Ok(()))
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            match this.conn.reader().read(buf) {
                Ok(0) => {}
                // `Reader::read` surfaces an empty plaintext buffer as
                // `WouldBlock` too — both mean "pull more ciphertext first".
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                r => return Poll::Ready(r),
            }
            match this.conn.complete_io(&mut Sync(&mut this.io, cx)) {
                Ok((0, 0)) => return Poll::Pending,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let wrote = this.conn.writer().write(buf)?;
        match this.conn.write_tls(&mut Sync(&mut this.io, cx)) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Poll::Ready(Err(e)),
            Ok(_) => {}
        }
        // The plaintext is already in the session's outgoing queue even when
        // the record could not be flushed yet, so the write still counts.
        Poll::Ready(Ok(wrote))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.conn.wants_write() {
            match this.conn.write_tls(&mut Sync(&mut this.io, cx)) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.conn.send_close_notify();
        while this.conn.wants_write() {
            match this.conn.write_tls(&mut Sync(&mut this.io, cx)) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Pin::new(&mut this.io).poll_close(cx)
    }
}

/// Accepts TLS sessions on a futures-io stream, built from an `Arc`-shared
/// server config (`TlsAcceptor::from(arc)`).
#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }
}

impl TlsAcceptor {
    pub async fn accept<S>(&self, mut io: S) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut conn =
            Connection::Server(ServerConnection::new(Arc::clone(&self.config)).map_err(tls_error)?);
        std::future::poll_fn(|cx| handshake(&mut io, &mut conn, cx)).await?;
        Ok(TlsStream { io, conn })
    }
}

/// Opens TLS sessions on a futures-io stream, built from an `Arc`-shared
/// client config (`TlsConnector::from(arc)`).
#[derive(Clone)]
pub struct TlsConnector {
    config: Arc<ClientConfig>,
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl TlsConnector {
    pub async fn connect<S>(
        &self,
        domain: ServerName<'static>,
        mut io: S,
    ) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut conn = Connection::Client(
            ClientConnection::new(Arc::clone(&self.config), domain).map_err(tls_error)?,
        );
        std::future::poll_fn(|cx| handshake(&mut io, &mut conn, cx)).await?;
        Ok(TlsStream { io, conn })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{AsyncReadExt, AsyncWriteExt};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    #[test]
    fn loopback_handshake() {
        // A minimal ECDSA cert for localhost — the same shape the fixtures use.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen");
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.clone().into()).expect("root");
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.into()], key)
            .expect("server config");
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        smol::block_on(async {
            let listener = async_net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let accept = async {
                let (io, _) = listener.accept().await.unwrap();
                TlsAcceptor::from(Arc::new(server)).accept(io).await
            };
            let connect = async {
                let io = async_net::TcpStream::connect(addr).await.unwrap();
                TlsConnector::from(Arc::new(client))
                    .connect(ServerName::try_from("localhost").unwrap().to_owned(), io)
                    .await
            };
            let (a, b) = futures_util::future::join(accept, connect).await;
            let mut srv = a.expect("accept");
            let mut cli = b.expect("connect");
            cli.write_all(b"ping").await.unwrap();
            cli.flush().await.unwrap();
            let mut buf = [0u8; 4];
            srv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            srv.write_all(b"pong").await.unwrap();
            srv.flush().await.unwrap();
            cli.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
        });
    }
}
