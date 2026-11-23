//! One HTTP(S) request per hop over a connection we open ourselves, so each phase
//! (DNS, TCP, TLS, response) is timed separately and the peer certificate is visible.
//! Destinations are resolved and permitted by the caller's policy before connecting.

use crate::{addresses, util, Args};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};

const MAX_HEADER_BYTES: usize = 64 * 1024;

fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring supports the default TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

pub struct Hop {
    pub value: Value,
    pub status: u16,
    pub location: Option<String>,
}

/// Performs one request. Errors describe the phase that failed.
pub async fn hop(a: &Args, url: &reqwest::Url) -> Result<Hop, String> {
    let budget = Duration::from_secs(a.timeout.max(1) * 2);
    tokio::time::timeout(budget, hop_inner(a, url))
        .await
        .map_err(|_| format!("{} did not answer within {}s", url, budget.as_secs()))?
}

async fn hop_inner(a: &Args, url: &reqwest::Url) -> Result<Hop, String> {
    let started = Instant::now();
    let host = url
        .host_str()
        .ok_or("missing host")?
        .trim_matches(['[', ']'])
        .to_string();
    let port = url.port_or_known_default().ok_or("unknown port")?;
    let ips = addresses(a, &host).await?;
    let dns_ms = if host.parse::<IpAddr>().is_ok() {
        0.0
    } else {
        util::ms(started.elapsed())
    };

    let connect_start = Instant::now();
    let mut last_error = String::from("no address to connect to");
    let mut stream = None;
    for ip in ips.iter().take(4) {
        let addr = SocketAddr::new(*ip, port);
        match tokio::time::timeout(Duration::from_secs(a.timeout), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                stream = Some((s, *ip));
                break;
            }
            Ok(Err(e)) => last_error = format!("TCP connect to {addr} failed: {e}"),
            Err(_) => last_error = format!("TCP connect to {addr} timed out"),
        }
    }
    let (tcp, peer) = stream.ok_or(last_error)?;
    let tcp_ms = util::ms(connect_start.elapsed());

    let host_header = match (url.port(), host.parse::<IpAddr>()) {
        (Some(p), Ok(IpAddr::V6(_))) => format!("[{host}]:{p}"),
        (Some(p), _) => format!("{host}:{p}"),
        (None, Ok(IpAddr::V6(_))) => format!("[{host}]"),
        (None, _) => host.clone(),
    };
    let mut path = url.path().to_string();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    let request = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: wheredns/{} (+https://github.com/Shroomate/wheredns-cli)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );

    let (head, tls, tls_ms, response_ms) = if url.scheme() == "https" {
        let tls_start = Instant::now();
        let name = ServerName::try_from(host.clone()).map_err(|e| format!("TLS name: {e}"))?;
        let mut conn = TlsConnector::from(tls_config())
            .connect(name, tcp)
            .await
            .map_err(|e| tls_error(&e.to_string(), &host))?;
        let tls_ms = util::ms(tls_start.elapsed());
        let (_, session) = conn.get_ref();
        let tls = certificate(session);
        let response_start = Instant::now();
        let head = exchange(&mut conn, &request).await?;
        (head, tls, Some(tls_ms), util::ms(response_start.elapsed()))
    } else {
        let mut tcp = tcp;
        let response_start = Instant::now();
        let head = exchange(&mut tcp, &request).await?;
        (head, Value::Null, None, util::ms(response_start.elapsed()))
    };

    let mut header_buf = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut header_buf);
    response
        .parse(&head)
        .map_err(|e| format!("malformed HTTP response: {e}"))?;
    let status = response.code.ok_or("incomplete HTTP response")?;
    let headers: Vec<(String, String)> = response
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    let get = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    let location = get("location");
    let total_ms = util::ms(started.elapsed());
    let value = json!({
        "url": url.as_str(),
        "status": status,
        "headers": headers.iter().map(|(n, v)| json!({"name": n, "value": v})).collect::<Vec<_>>(),
        "elapsed_ms": total_ms.round() as u64,
        "location": location,
        "server": get("server"),
        "content_type": get("content-type").map(|t| t.split(';').next().unwrap_or_default().trim().to_string()),
        "hsts": url.scheme() == "https" && get("strict-transport-security").is_some(),
        "peer_ip": peer,
        "timings": {
            "dns_ms": dns_ms,
            "tcp_ms": tcp_ms,
            "tls_ms": tls_ms,
            "response_ms": response_ms,
            "total_ms": total_ms,
        },
        "tls": tls,
    });
    Ok(Hop {
        value,
        status,
        location,
    })
}

/// Turns rustls' debug-formatted certificate errors into a readable diagnosis.
fn tls_error(raw: &str, host: &str) -> String {
    let names: Vec<&str> = raw
        .split("DnsName(\"")
        .skip(1)
        .filter_map(|part| part.split('"').next())
        .collect();
    if raw.contains("not valid for name") || raw.contains("NotValidForName") {
        let covered = match names.len() {
            0 => String::new(),
            1..=3 => format!("; it covers {}", names.join(", ")),
            n => format!("; it covers {} +{} more", names[..3].join(", "), n - 3),
        };
        return format!("TLS certificate does not cover {host}{covered}");
    }
    if raw.contains("Expired") || raw.contains("expired") {
        return "TLS certificate has expired".into();
    }
    if raw.contains("NotValidYet") {
        return "TLS certificate is not valid yet (check this machine's clock)".into();
    }
    if raw.contains("UnknownIssuer") {
        return "TLS certificate is not signed by a trusted authority (self-signed or missing intermediate)".into();
    }
    if raw.contains("Revoked") {
        return "TLS certificate has been revoked".into();
    }
    format!("TLS handshake failed: {raw}")
}

/// Sends the request and returns the final response's header block. Interim
/// 1xx responses (e.g. 103 Early Hints) are skipped; a connection that closes
/// before the header block ends is an error, as is a block over 64 KiB.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &str,
) -> Result<Vec<u8>, String> {
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("sending request failed: {e}"))?;
    stream.flush().await.map_err(|e| e.to_string())?;
    read_head(stream).await
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut scanned: usize = 0;
    let mut received_any = false;
    loop {
        // Look for the end of the current header block, resuming the search
        // a few bytes back so a delimiter split across reads is still found.
        let from = scanned.saturating_sub(3);
        if let Some(pos) = buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = from + pos + 4;
            if end > MAX_HEADER_BYTES {
                return Err("HTTP response headers exceed 64 KiB".into());
            }
            if interim(&buf[..end]) {
                buf.drain(..end);
                scanned = 0;
                continue;
            }
            buf.truncate(end);
            return Ok(buf);
        }
        scanned = buf.len();
        if buf.len() > MAX_HEADER_BYTES {
            return Err("HTTP response headers exceed 64 KiB".into());
        }
        let n = stream.read(&mut chunk).await.map_err(|e| {
            if received_any {
                format!("reading response failed: {e}")
            } else {
                format!("no HTTP response: {e}")
            }
        })?;
        if n == 0 {
            return Err(if received_any {
                "connection closed before the HTTP response headers ended".into()
            } else {
                "server closed the connection without a response".into()
            });
        }
        received_any = true;
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A complete 1xx header block other than 101 Switching Protocols.
fn interim(head: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut r = httparse::Response::new(&mut headers);
    matches!(r.parse(head), Ok(httparse::Status::Complete(_)))
        && r.code.is_some_and(|c| (100..200).contains(&c) && c != 101)
}

fn certificate(session: &rustls::ClientConnection) -> Value {
    let protocol = session.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        other => format!("{other:?}"),
    });
    let Some(der) = session.peer_certificates().and_then(|c| c.first()) else {
        return json!({"authorized": true, "protocol": protocol});
    };
    let fingerprint = util::colon_hex(ring::digest::digest(&ring::digest::SHA256, der).as_ref());
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return json!({"authorized": true, "protocol": protocol, "fingerprint256": fingerprint});
    };
    let name = |n: &x509_parser::x509::X509Name| {
        let cn = n.iter_common_name().next().and_then(|v| v.as_str().ok());
        let org = n.iter_organization().next().and_then(|v| v.as_str().ok());
        match (cn, org) {
            (Some(cn), Some(org)) if cn != org => format!("{cn} · {org}"),
            (Some(cn), _) => cn.to_string(),
            (None, Some(org)) => org.to_string(),
            (None, None) => n.to_string(),
        }
    };
    let not_after = cert.validity().not_after.timestamp();
    let sans: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .take(50)
                .collect()
        })
        .unwrap_or_default();
    json!({
        "authorized": true,
        "subject": name(cert.subject()),
        "issuer": name(cert.issuer()),
        "valid_from": util::ymd(cert.validity().not_before.timestamp()),
        "valid_to": util::ymd(not_after),
        "days_left": (not_after - util::now_unix()).div_euclid(86400),
        "sans": sans,
        "protocol": protocol,
        "fingerprint256": fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn head_from(chunks: &[&[u8]]) -> Result<Vec<u8>, String> {
        let mut mock = tokio_test_reader(chunks);
        read_head(&mut mock).await
    }

    /// A reader that returns the given chunks one read at a time, then EOF.
    fn tokio_test_reader(chunks: &[&[u8]]) -> impl AsyncRead + Unpin {
        let data: Vec<Vec<u8>> = chunks.iter().map(|c| c.to_vec()).collect();
        Chunks(data.into_iter().collect())
    }
    struct Chunks(std::collections::VecDeque<Vec<u8>>);
    impl AsyncRead for Chunks {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if let Some(mut c) = self.0.pop_front() {
                let n = c.len().min(buf.remaining());
                buf.put_slice(&c[..n]);
                if n < c.len() {
                    self.0.push_front(c.split_off(n));
                }
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn header_blocks() {
        // 103 Early Hints, then the final response; delimiter split across reads.
        let head = head_from(&[
            b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r",
            b"\nServer: x\r\n\r",
            b"\nbody",
        ])
        .await
        .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200 OK"));
        assert!(head.ends_with(b"Server: x\r\n\r\n"));
        // Closed before the header block ended.
        assert!(head_from(&[b"HTTP/1.1 200 OK\r\nServer: x\r\n"])
            .await
            .is_err());
        assert!(head_from(&[]).await.is_err());
        // Oversized, even when the delimiter arrives in the same read.
        let mut big = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        big.extend(vec![b'a'; MAX_HEADER_BYTES]);
        big.extend_from_slice(b"\r\n\r\n");
        assert!(head_from(&[&big]).await.is_err());
        let mut fits = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        fits.extend(vec![b'a'; MAX_HEADER_BYTES - fits.len() - 4]);
        fits.extend_from_slice(b"\r\n\r\n");
        assert_eq!(head_from(&[&fits]).await.unwrap().len(), MAX_HEADER_BYTES);
    }

    #[test]
    fn readable_tls_errors() {
        let raw = r#"invalid peer certificate: certificate not valid for name "1.2.3.4"; certificate is only valid for DnsName("a.com"), DnsName("b.com"), DnsName("c.com") or DnsName("d.com")"#;
        assert_eq!(
            super::tls_error(raw, "1.2.3.4"),
            "TLS certificate does not cover 1.2.3.4; it covers a.com, b.com, c.com +1 more"
        );
        assert!(
            super::tls_error("invalid peer certificate: UnknownIssuer", "x")
                .contains("trusted authority")
        );
    }
}
