use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use serde::Serialize;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::atomic::{AtomicU16, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
static ID: AtomicU16 = AtomicU16::new(1);
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub name: String,
    pub rr_type: String,
    pub ttl: u32,
    pub value: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Answer {
    pub name: String,
    pub rr_type: String,
    pub server: String,
    pub status: String,
    pub authoritative: bool,
    pub records: Vec<Record>,
}
pub async fn query(
    name: &str,
    kind: &str,
    server: SocketAddr,
    recurse: bool,
) -> Result<Answer, String> {
    let ty = RecordType::from_str(kind).map_err(|e| e.to_string())?;
    let id = ID.fetch_add(1, Ordering::Relaxed);
    let mut q = Message::new();
    q.set_id(id)
        .set_recursion_desired(recurse)
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
    if m.id() != id
        || m.queries() != q.queries()
        || m.message_type() != hickory_proto::op::MessageType::Response
    {
        return Err("DNS response mismatch".into());
    }
    Ok(Answer {
        name: name.into(),
        rr_type: kind.into(),
        server: server.to_string(),
        status: if m.response_code() == hickory_proto::op::ResponseCode::NoError
            && m.answers().is_empty()
        {
            "NODATA".into()
        } else {
            m.response_code().to_string()
        },
        authoritative: m.authoritative(),
        records: m
            .answers()
            .iter()
            .map(|r| Record {
                name: r.name().to_string(),
                rr_type: r.record_type().to_string(),
                ttl: r.ttl(),
                value: r.data().map(ToString::to_string).unwrap_or_default(),
            })
            .collect(),
    })
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
