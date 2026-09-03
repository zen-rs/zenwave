//! An in-process SOCKS5 server (RFC 1928 CONNECT, optional RFC 1929
//! username/password) that records the destinations it was asked for.
#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    thread,
};

use async_net::{TcpListener, TcpStream};
use futures_util::{AsyncReadExt, AsyncWriteExt, future::select, io::copy};

/// The destination a client asked the SOCKS5 server to reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocksDestination {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Debug)]
pub struct Socks5Proxy {
    addr: SocketAddr,
    log: Arc<Mutex<Vec<SocksDestination>>>,
}

impl Socks5Proxy {
    /// Start a server that requires no authentication.
    pub fn start() -> Self {
        Self::start_with(None)
    }

    /// Start a server that requires exactly these credentials.
    pub fn start_requiring(user: &str, password: &str) -> Self {
        Self::start_with(Some((user.to_owned(), password.to_owned())))
    }

    fn start_with(credentials: Option<(String, String)>) -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let (listener, addr) = smol::block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks5");
            let addr = listener.local_addr().expect("socks5 address");
            (listener, addr)
        });
        let worker_log = Arc::clone(&log);
        thread::spawn(move || {
            smol::block_on(async move {
                loop {
                    let (client, _) = listener.accept().await.expect("accept on socks5");
                    let log = Arc::clone(&worker_log);
                    let credentials = credentials.clone();
                    smol::spawn(async move {
                        let _ = serve(client, log, credentials).await;
                    })
                    .detach();
                }
            });
        });
        Self { addr, log }
    }

    /// `socks5://127.0.0.1:<port>` or `socks5h://…`.
    pub fn uri(&self, scheme: &str) -> String {
        format!("{scheme}://{}", self.addr)
    }

    /// `socks5://<user>:<password>@127.0.0.1:<port>`.
    pub fn uri_with_credentials(&self, scheme: &str, user: &str, password: &str) -> String {
        format!("{scheme}://{user}:{password}@{}", self.addr)
    }

    pub fn destinations(&self) -> Vec<SocksDestination> {
        self.log.lock().expect("socks5 log").clone()
    }
}

async fn serve(
    mut client: TcpStream,
    log: Arc<Mutex<Vec<SocksDestination>>>,
    credentials: Option<(String, String)>,
) -> std::io::Result<()> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    assert_eq!(greeting[0], 0x05, "client must speak SOCKS5");
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await?;

    match &credentials {
        Some((user, password)) => {
            if !methods.contains(&0x02) {
                client.write_all(&[0x05, 0xFF]).await?;
                return Ok(());
            }
            client.write_all(&[0x05, 0x02]).await?;
            let mut header = [0_u8; 2];
            client.read_exact(&mut header).await?;
            let mut offered_user = vec![0_u8; usize::from(header[1])];
            client.read_exact(&mut offered_user).await?;
            let mut password_len = [0_u8; 1];
            client.read_exact(&mut password_len).await?;
            let mut offered_password = vec![0_u8; usize::from(password_len[0])];
            client.read_exact(&mut offered_password).await?;
            let ok = offered_user == user.as_bytes() && offered_password == password.as_bytes();
            client.write_all(&[0x01, u8::from(!ok)]).await?;
            if !ok {
                return Ok(());
            }
        }
        None => {
            client.write_all(&[0x05, 0x00]).await?;
        }
    }

    let mut request = [0_u8; 4];
    client.read_exact(&mut request).await?;
    assert_eq!(request[1], 0x01, "only CONNECT is served");
    let destination = match request[3] {
        0x01 => {
            let mut octets = [0_u8; 4];
            client.read_exact(&mut octets).await?;
            let port = read_port(&mut client).await?;
            SocksDestination::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            client.read_exact(&mut octets).await?;
            let port = read_port(&mut client).await?;
            SocksDestination::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0_u8; usize::from(len[0])];
            client.read_exact(&mut name).await?;
            let port = read_port(&mut client).await?;
            SocksDestination::Domain(String::from_utf8(name).expect("utf-8 hostname"), port)
        }
        other => panic!("unknown address type {other}"),
    };
    log.lock().expect("socks5 log").push(destination.clone());

    let upstream = match &destination {
        SocksDestination::Ip(addr) => TcpStream::connect(*addr).await,
        SocksDestination::Domain(name, port) => TcpStream::connect((name.as_str(), *port)).await,
    };
    let Ok(upstream) = upstream else {
        client
            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    };
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let to_upstream = async {
        let _ = copy(&mut client_read, &mut upstream_write).await;
        let _ = upstream_write.close().await;
    };
    let to_client = async {
        let _ = copy(&mut upstream_read, &mut client_write).await;
        let _ = client_write.close().await;
    };
    let _ = select(Box::pin(to_upstream), Box::pin(to_client)).await;
    Ok(())
}

async fn read_port(client: &mut TcpStream) -> std::io::Result<u16> {
    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}
