//! Shared fixtures for integration tests. Everything runs against loopback
//! servers; no test touches the public internet.
#![allow(dead_code)]

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::{Name, RecordType};

/// Runs wheredns against a loopback UDP resolver. `respond` edits each reply.
/// Returns the process output and every question the resolver received.
pub async fn run_with_dns(
    target: &str,
    check: &[&str],
    mut respond: impl FnMut(&mut Message),
) -> (std::process::Output, Vec<(Name, RecordType)>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = socket.local_addr().unwrap().to_string();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_wheredns"));
    command
        .arg(target)
        .args(check)
        .args(["--allow-private", "--resolver", &resolver, "--timeout", "2"])
        .kill_on_drop(true);
    let output = command.output();
    tokio::pin!(output);
    let mut buffer = [0; 4096];
    let mut queries = Vec::new();
    loop {
        tokio::select! {
            result = &mut output => return (result.unwrap(), queries),
            packet = socket.recv_from(&mut buffer) => {
                let (size, peer) = packet.unwrap();
                let mut message = Message::from_vec(&buffer[..size]).unwrap();
                let question = &message.queries[0];
                queries.push((question.name().clone(), question.query_type()));
                message.metadata.message_type = MessageType::Response;
                respond(&mut message);
                socket.send_to(&message.to_vec().unwrap(), peer).await.unwrap();
            }
        }
    }
}
