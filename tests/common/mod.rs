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

/// What a [`run_with_fixture`] resolver saw.
pub struct Seen {
    /// Every question, in arrival order (lowercased name without the root dot).
    pub queries: Vec<(String, RecordType)>,
    /// Most questions that were outstanding (received, not yet answered) at once.
    pub peak: usize,
}

/// Like [`run_with_dns`], but each reply is sent from its own task after
/// `delay`, so overlapping questions are observable. `respond` returns false to
/// leave a question unanswered. `env` adds environment variables.
pub async fn run_with_fixture(
    args: &[&str],
    env: &[(&str, &str)],
    delay: std::time::Duration,
    respond: impl Fn(&mut Message) -> bool + Send + Sync + 'static,
) -> (std::process::Output, Seen) {
    use std::sync::{Arc, Mutex};
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let resolver = socket.local_addr().unwrap().to_string();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_wheredns"));
    command
        .args(args)
        .args(["--allow-private", "--resolver", &resolver, "--timeout", "2"])
        .envs(env.iter().copied())
        .kill_on_drop(true);
    let output = command.output();
    tokio::pin!(output);
    let respond = Arc::new(respond);
    let state = Arc::new(Mutex::new((Vec::new(), 0usize, 0usize)));
    let mut buffer = [0; 4096];
    loop {
        tokio::select! {
            result = &mut output => {
                let (queries, _, peak) = std::mem::take(&mut *state.lock().unwrap());
                return (result.unwrap(), Seen { queries, peak });
            }
            packet = socket.recv_from(&mut buffer) => {
                let (size, peer) = packet.unwrap();
                let mut message = Message::from_vec(&buffer[..size]).unwrap();
                let q = &message.queries[0];
                let name = q.name().to_ascii().trim_end_matches('.').to_ascii_lowercase();
                {
                    let mut s = state.lock().unwrap();
                    s.0.push((name, q.query_type()));
                    s.1 += 1;
                    s.2 = s.2.max(s.1);
                }
                let (socket, respond, state) = (socket.clone(), respond.clone(), state.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    message.metadata.message_type = MessageType::Response;
                    if respond(&mut message) {
                        state.lock().unwrap().1 -= 1;
                        let _ = socket.send_to(&message.to_vec().unwrap(), peer).await;
                    }
                });
            }
        }
    }
}
