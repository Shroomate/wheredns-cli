use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde::Serialize;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

const MAX_CNAME_LINKS: usize = 8;

pub fn parse_record_type(kind: &str) -> Result<String, String> {
    let kind = kind.to_ascii_uppercase();
    RecordType::from_str(&kind).map_err(|e| e.to_string())?;
    Ok(kind)
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub name: String,
    pub rr_type: String,
    pub rr_class: u16,
    pub ttl: u32,
    pub value: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Outcome {
    NoError,
    NxDomain,
}
#[derive(Debug, Clone, Serialize)]
pub struct Answer {
    pub name: String,
    pub rr_type: String,
    pub server: String,
    pub status: String,
    pub outcome: Outcome,
    pub authoritative: bool,
    /// Resolver set the AD flag: it validated DNSSEC for this response.
    pub authenticated: bool,
    pub records: Vec<Record>,
}
pub async fn query(
    name: &str,
    kind: &str,
    server: SocketAddr,
    recurse: bool,
) -> Result<Answer, String> {
    let ty = RecordType::from_str(kind).map_err(|e| e.to_string())?;
    let id = rand::random();
    let mut q = Message::new();
    q.set_id(id)
        .set_recursion_desired(recurse)
        .set_authentic_data(recurse)
        .add_query(Query::query(
            Name::from_ascii(name).map_err(|e| e.to_string())?,
            ty,
        ));
    let bytes = q.to_vec().map_err(|e| e.to_string())?;
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .map_err(|e| e.to_string())?;
    socket.connect(server).await.map_err(|e| e.to_string())?;
    socket.send(&bytes).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0; 65535];
    let n = socket.recv(&mut buf).await.map_err(|e| e.to_string())?;
    let mut m = Message::from_vec(&buf[..n]).map_err(|e| e.to_string())?;
    validate(&m, &q)?;
    if m.truncated() {
        let mut tcp = TcpStream::connect(server)
            .await
            .map_err(|e| e.to_string())?;
        tcp.write_u16(bytes.len() as u16)
            .await
            .map_err(|e| e.to_string())?;
        tcp.write_all(&bytes).await.map_err(|e| e.to_string())?;
        let n = tcp.read_u16().await.map_err(|e| e.to_string())?;
        buf.resize(n as usize, 0);
        tcp.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
        m = Message::from_vec(&buf).map_err(|e| e.to_string())?;
    }
    validate(&m, &q)?;
    if m.truncated() {
        return Err("incomplete TCP DNS response".into());
    }
    if !matches!(
        m.response_code(),
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return Err(format!("DNS resolver failure: {}", m.response_code()));
    }
    Ok(Answer {
        name: name.into(),
        rr_type: kind.into(),
        server: server.to_string(),
        status: response_status(&m, &q.queries()[0]),
        outcome: if m.response_code() == ResponseCode::NoError {
            Outcome::NoError
        } else {
            Outcome::NxDomain
        },
        authoritative: m.authoritative(),
        authenticated: m.authentic_data(),
        records: m
            .answers()
            .iter()
            .map(|r| Record {
                name: r.name().to_string(),
                rr_type: r.record_type().to_string(),
                rr_class: u16::from(r.dns_class()),
                ttl: r.ttl(),
                value: r.data().map(render).unwrap_or_default(),
            })
            .collect(),
    })
}

/// Presentation format for record data, including DNSSEC types hickory leaves opaque.
fn render(data: &RData) -> String {
    match data {
        RData::Unknown { code, rdata } => {
            let b = rdata.anything();
            match (u16::from(*code), b.len() >= 4) {
                // DS / CDS: key tag, algorithm, digest type, digest (hex)
                (43 | 59, true) => format!(
                    "{} {} {} {}",
                    u16::from_be_bytes([b[0], b[1]]),
                    b[2],
                    b[3],
                    b[4..]
                        .iter()
                        .map(|x| format!("{x:02X}"))
                        .collect::<String>()
                ),
                // DNSKEY / CDNSKEY: flags, protocol, algorithm, key (base64)
                (48 | 60, true) => format!(
                    "{} {} {} {}",
                    u16::from_be_bytes([b[0], b[1]]),
                    b[2],
                    b[3],
                    base64(&b[4..])
                ),
                _ => data.to_string(),
            }
        }
        RData::HTTPS(_) | RData::SVCB(_) => data
            .to_string()
            .split_whitespace()
            .map(|t| t.trim_end_matches(','))
            .collect::<Vec<_>>()
            .join(" "),
        _ => data.to_string(),
    }
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn response_status(message: &Message, question: &Query) -> String {
    let code = message.response_code();
    if code != ResponseCode::NoError {
        return code.to_string();
    }
    let mut owner = question.name();
    for _ in 0..=MAX_CNAME_LINKS {
        let records = message
            .answers()
            .iter()
            .filter(|r| r.name() == owner && r.dns_class() == question.query_class());
        if records.clone().any(|r| {
            r.data().is_some()
                && (r.record_type() == question.query_type()
                    || question.query_type() == RecordType::ANY)
        }) {
            return code.to_string();
        }
        let mut aliases = records.filter_map(|r| match r.data() {
            Some(RData::CNAME(target)) => Some(&target.0),
            _ => None,
        });
        match (aliases.next(), aliases.next()) {
            (Some(target), None) => owner = target,
            (None, _) => {
                let mut authority = message
                    .name_servers()
                    .iter()
                    .filter(|r| r.dns_class() == question.query_class());
                // An NS-only authority section is a referral (RFC 2308, §2.2).
                return if authority.clone().any(|r| r.record_type() == RecordType::NS)
                    && !authority.any(|r| r.record_type() == RecordType::SOA)
                {
                    "REFERRAL".into()
                } else {
                    "NODATA".into()
                };
            }
            _ => break,
        }
    }
    code.to_string()
}

fn validate(m: &Message, q: &Message) -> Result<(), String> {
    if m.id() != q.id()
        || m.queries() != q.queries()
        || m.message_type() != hickory_proto::op::MessageType::Response
        || m.op_code() != q.op_code()
    {
        return Err("DNS response mismatch".into());
    }
    Ok(())
}
impl Answer {
    /// "answered", "nodata" or "nxdomain", for JSON and panel tags.
    pub fn kind(&self) -> &'static str {
        if self.outcome == Outcome::NxDomain {
            "nxdomain"
        } else if self.status == "NODATA" || self.status == "REFERRAL" {
            "nodata"
        } else {
            "answered"
        }
    }

    /// IN-class record values of the requested type, at any owner in the answer.
    pub fn values(&self) -> Vec<String> {
        self.records
            .iter()
            .filter(|r| r.rr_class == 1 && r.rr_type == self.rr_type)
            .map(|r| r.value.clone())
            .collect()
    }

    /// IN-class values of the requested type owned by `owner`.
    pub fn values_at(&self, owner: &str) -> Vec<String> {
        let owner = owner.trim_end_matches('.').to_ascii_lowercase();
        self.records
            .iter()
            .filter(|r| {
                r.rr_class == 1
                    && r.rr_type == self.rr_type
                    && r.name.trim_end_matches('.').eq_ignore_ascii_case(&owner)
            })
            .map(|r| r.value.clone())
            .collect()
    }

    /// CNAME targets followed by the resolver.
    pub fn chain(&self) -> Vec<String> {
        if self.rr_type == "CNAME" {
            return Vec::new();
        }
        self.records
            .iter()
            .filter(|r| r.rr_type == "CNAME")
            .map(|r| r.value.trim_end_matches('.').to_string())
            .collect()
    }

    pub fn addresses(&self) -> Result<Vec<IpAddr>, String> {
        if self.outcome != Outcome::NoError {
            return Ok(Vec::new());
        }
        let canonical = |s: &str| s.trim_end_matches('.').to_ascii_lowercase();
        let mut owner = canonical(&self.name);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..=MAX_CNAME_LINKS {
            if !seen.insert(owner.clone()) {
                return Err("CNAME loop".into());
            }
            let aliases: Vec<_> = self
                .records
                .iter()
                .filter(|r| r.rr_class == 1 && canonical(&r.name) == owner && r.rr_type == "CNAME")
                .collect();
            if aliases.len() > 1 {
                return Err("ambiguous CNAME".into());
            }
            if !aliases.is_empty()
                && self.records.iter().any(|r| {
                    r.rr_class == 1
                        && canonical(&r.name) == owner
                        && matches!(r.rr_type.as_str(), "A" | "AAAA")
                })
            {
                return Err("CNAME conflicts with address evidence".into());
            }
            if let Some(alias) = aliases.first() {
                owner = canonical(&alias.value);
                continue;
            }
            return self
                .records
                .iter()
                .filter(|r| {
                    r.rr_class == 1 && canonical(&r.name) == owner && r.rr_type == self.rr_type
                })
                .filter(|r| matches!(r.rr_type.as_str(), "A" | "AAAA"))
                .map(|r| {
                    let ip: IpAddr = r.value.parse().map_err(|_| "invalid address RDATA")?;
                    if (r.rr_type == "A") != ip.is_ipv4() {
                        return Err("address family mismatch".into());
                    }
                    Ok(ip)
                })
                .collect();
        }
        Err("CNAME chain exceeds eight links".into())
    }
}
pub fn reverse(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v) => format!(
            "{}.ip6.arpa",
            v.octets()
                .iter()
                .rev()
                .flat_map(|b| [format!("{:x}", b & 15), format!("{:x}", b >> 4)])
                .collect::<Vec<_>>()
                .join(".")
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn wire_fixture() {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0; 512];
            let (n, p) = s.recv_from(&mut b).await.unwrap();
            let q = Message::from_vec(&b[..n]).unwrap();
            let mut r = Message::new();
            r.set_id(q.id())
                .set_message_type(hickory_proto::op::MessageType::Response)
                .add_queries(q.queries().iter().cloned());
            r.add_answer(hickory_proto::rr::Record::from_rdata(
                Name::from_ascii("example.test.").unwrap(),
                60,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 1)),
            ));
            s.send_to(&r.to_vec().unwrap(), p).await.unwrap();
        });
        let a = query("example.test", "A", addr, true).await.unwrap();
        assert_eq!(a.records[0].value, "192.0.2.1");
        assert_eq!(a.records[0].ttl, 60);
    }
}

#[cfg(test)]
mod hostile_tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, ResponseCode};
    fn question() -> Message {
        let mut q = Message::new();
        q.set_id(123).add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::A,
        ));
        q
    }
    fn response(q: &Message) -> Message {
        let mut r = q.clone();
        r.set_message_type(MessageType::Response);
        r
    }
    #[test]
    fn address_binding() {
        let rec = |n: &str, t: &str, v: &str| Record {
            name: n.into(),
            rr_type: t.into(),
            rr_class: 1,
            ttl: 1,
            value: v.into(),
        };
        let mut a = Answer {
            name: "example.test".into(),
            rr_type: "A".into(),
            server: "fixture".into(),
            status: "No Error".into(),
            outcome: Outcome::NoError,
            authoritative: false,
            authenticated: false,
            records: vec![
                rec("unrelated.test", "A", "127.0.0.1"),
                rec("example.test", "TXT", "127.0.0.1"),
            ],
        };
        assert!(a.addresses().unwrap().is_empty());
        a.records.extend([
            rec("EXAMPLE.test.", "CNAME", "alias.test."),
            rec("alias.test.", "A", "1.1.1.1"),
            rec("alias.test.", "AAAA", "::1"),
        ]);
        assert_eq!(
            a.addresses().unwrap(),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        a.records.push(rec("alias.test.", "CNAME", "example.test."));
        assert!(a.addresses().is_err());
    }
    #[test]
    fn envelope() {
        let q = question();
        let good = response(&q);
        assert!(validate(&good, &q).is_ok());
        for mode in 0..4 {
            let mut r = good.clone();
            match mode {
                0 => {
                    r.set_id(124);
                }
                1 => {
                    r.set_op_code(OpCode::Status);
                }
                2 => {
                    r.set_message_type(MessageType::Query);
                }
                _ => {
                    r.queries_mut()[0].set_query_type(RecordType::MX);
                }
            }
            assert!(validate(&r, &q).is_err());
        }
    }
    #[tokio::test]
    async fn tcp_frames() {
        for mode in [
            "good",
            "tc",
            "id",
            "question",
            "opcode",
            "qr",
            "short",
            "malformed",
            "udp_id",
        ] {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = udp.local_addr().unwrap();
            let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
            let task = tokio::spawn(async move {
                let mut b = [0; 512];
                let (n, p) = udp.recv_from(&mut b).await.unwrap();
                let q = Message::from_vec(&b[..n]).unwrap();
                let mut r = response(&q);
                r.set_truncated(true);
                if mode == "udp_id" {
                    r.set_id(q.id().wrapping_add(1));
                }
                udp.send_to(&r.to_vec().unwrap(), p).await.unwrap();
                if mode == "udp_id" {
                    assert!(tokio::time::timeout(
                        std::time::Duration::from_millis(50),
                        tcp.accept()
                    )
                    .await
                    .is_err());
                    return;
                }
                let (mut socket, _) = tcp.accept().await.unwrap();
                let n = socket.read_u16().await.unwrap();
                let mut b = vec![0; n as usize];
                socket.read_exact(&mut b).await.unwrap();
                let mut r = response(&q);
                match mode {
                    "tc" => {
                        r.set_truncated(true);
                    }
                    "id" => {
                        r.set_id(q.id().wrapping_add(1));
                    }
                    "question" => {
                        r.queries_mut()[0].set_query_type(RecordType::MX);
                    }
                    "opcode" => {
                        r.set_op_code(OpCode::Status);
                    }
                    "qr" => {
                        r.set_message_type(MessageType::Query);
                    }
                    _ => {}
                }
                let wire = if mode == "malformed" {
                    vec![255; 3]
                } else {
                    r.to_vec().unwrap()
                };
                socket.write_u16(wire.len() as u16).await.unwrap();
                if mode != "short" {
                    socket.write_all(&wire).await.unwrap();
                }
            });
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                query("example.test.", "A", addr, true),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), mode == "good", "{mode}: {result:?}");
            task.await.unwrap();
        }
    }
    #[tokio::test]
    async fn negative_statuses() {
        for code in [
            ResponseCode::NoError,
            ResponseCode::NXDomain,
            ResponseCode::ServFail,
            ResponseCode::Refused,
        ] {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = udp.local_addr().unwrap();
            tokio::spawn(async move {
                let mut b = [0; 512];
                let (n, p) = udp.recv_from(&mut b).await.unwrap();
                let q = Message::from_vec(&b[..n]).unwrap();
                let mut r = response(&q);
                r.set_response_code(code);
                udp.send_to(&r.to_vec().unwrap(), p).await.unwrap();
            });
            let r = query("example.test.", "A", addr, true).await;
            assert_eq!(
                r.is_ok(),
                matches!(code, ResponseCode::NoError | ResponseCode::NXDomain)
            );
            if code == ResponseCode::NoError {
                assert_eq!(r.unwrap().status, "NODATA");
            }
        }
    }
}
