//! Synthetic HTTPS CLI used to audit the Agents Vault approval and proxy path.
//! It has no provider-specific behavior and requires broker-supplied proxy
//! variables. The proxy, not this client, enforces task authorization.

use std::{
    env,
    fs::File,
    io::{BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand, ValueEnum};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};

const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Parser)]
#[command(name = "av-fixture", about = "Synthetic proxy approval test client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Request {
        #[arg(long)]
        host: String,
        #[arg(long)]
        method: Method,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "")]
        body: String,
        /// Require Linux network namespace to reject a new direct IP socket.
        #[arg(long)]
        assert_direct_tcp_blocked: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Method {
    Get,
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Request {
            host,
            method,
            path,
            body,
            assert_direct_tcp_blocked,
        } => request(&host, method, &path, &body, assert_direct_tcp_blocked),
    }
}

fn request(
    host: &str,
    method: Method,
    path: &str,
    body: &str,
    assert_direct_tcp_blocked: bool,
) -> Result<()> {
    ensure!(valid_host(host), "host must be a single DNS name");
    ensure!(
        path.starts_with('/') && !path.contains(['\r', '\n']),
        "path must be an absolute HTTP path"
    );
    ensure!(
        matches!(method, Method::Post) || body.is_empty(),
        "GET cannot include a body"
    );
    if assert_direct_tcp_blocked {
        #[cfg(target_os = "linux")]
        {
            let address = SocketAddr::from(([192, 0, 2, 1], 443));
            let error = TcpStream::connect_timeout(&address, Duration::from_millis(500))
                .err()
                .context("direct TCP unexpectedly succeeded")?;
            ensure!(
                error.raw_os_error() == Some(libc::ENETUNREACH),
                "direct TCP did not fail with ENETUNREACH: {error}"
            );
        }
        #[cfg(not(target_os = "linux"))]
        bail!("direct TCP block assertion is Linux-only");
    }

    let proxy = env::var("HTTPS_PROXY").context("HTTPS_PROXY is required")?;
    let (proxy_address, capability) = parse_proxy(&proxy)?;
    let placeholder = env::var("AV_FIXTURE_TOKEN").context("AV_FIXTURE_TOKEN is required")?;
    ensure!(
        !placeholder.is_empty() && !placeholder.bytes().any(|byte| byte.is_ascii_control()),
        "invalid fixture placeholder"
    );
    let ca_file = env::var("SSL_CERT_FILE").context("SSL_CERT_FILE is required")?;
    let roots = load_ca(Path::new(&ca_file))?;

    let mut socket = TcpStream::connect_timeout(&proxy_address, Duration::from_secs(5))
        .context("cannot connect to task proxy")?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(
        socket,
        "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n"
    )?;
    if let Some(capability) = capability {
        let proxy_auth = STANDARD.encode(format!("av:{capability}"));
        write!(socket, "Proxy-Authorization: Basic {proxy_auth}\r\n")?;
    }
    write!(socket, "\r\n")?;
    let connect_response = read_header(&mut socket)?;
    ensure!(
        connect_response.starts_with(b"HTTP/1.1 200 "),
        "task proxy rejected CONNECT"
    );

    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_name = ServerName::try_from(host.to_owned()).context("invalid TLS hostname")?;
    let connection = ClientConnection::new(std::sync::Arc::new(tls_config), server_name)?;
    let mut stream = StreamOwned::new(connection, socket);
    write!(
        stream,
        "{} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {placeholder}\r\nX-AV-Fixture-Input: {placeholder}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        method.as_str(),
        body.len()
    )?;
    stream.flush()?;

    let response_header = read_header(&mut stream).context("cannot read provider response")?;
    let status_line_end = response_header
        .windows(2)
        .position(|window| window == b"\r\n")
        .context("provider response has no status line")?;
    let status_line = std::str::from_utf8(&response_header[..status_line_end])?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .context("provider response has no status code")?
        .parse::<u16>()?;
    ensure!((200..300).contains(&code), "provider returned HTTP {code}");
    println!("fixture request completed: HTTP {code}");
    Ok(())
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.is_ascii()
        && !host.bytes().any(|byte| byte.is_ascii_control())
        && !host.contains([':', '/', ' '])
}

fn parse_proxy(value: &str) -> Result<(SocketAddr, Option<String>)> {
    let raw = value
        .strip_prefix("http://")
        .context("HTTPS_PROXY must use a local HTTP proxy")?;
    let (address, capability) = if let Some(raw) = raw.strip_prefix("av:") {
        let (capability, address) = raw
            .split_once('@')
            .context("HTTPS_PROXY lacks task capability")?;
        ensure!(
            !capability.is_empty() && capability.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "invalid task capability"
        );
        (address, Some(capability.to_owned()))
    } else {
        ensure!(!raw.contains('@'), "unsupported proxy user info");
        (raw, None)
    };
    let address: SocketAddr = address.parse().context("invalid task proxy address")?;
    ensure!(address.ip().is_loopback(), "task proxy must be loopback");
    Ok((address, capability))
}

fn load_ca(path: &Path) -> Result<RootCertStore> {
    let file = File::open(path).context("cannot open task CA")?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::io::Result<Vec<_>>>()
        .context("cannot parse task CA")?;
    ensure!(!certs.is_empty(), "task CA is empty");
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).context("invalid task CA certificate")?;
    }
    Ok(roots)
}

fn read_header(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = Vec::new();
    while header.len() <= MAX_HEADER_BYTES {
        let mut byte = [0_u8];
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    bail!("proxy CONNECT header too large")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_url_requires_loopback() {
        assert_eq!(
            parse_proxy("http://av:abc123@127.0.0.1:14322")
                .unwrap()
                .1
                .as_deref(),
            Some("abc123")
        );
        assert_eq!(parse_proxy("http://127.0.0.1:14322").unwrap().1, None);
        assert!(parse_proxy("http://av:abc123@192.0.2.1:14322").is_err());
        assert!(parse_proxy("http://192.0.2.1:14322").is_err());
    }
}
