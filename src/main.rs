mod checks;
mod config;
mod display;
mod dns;
mod headers;
mod rdap;
mod util;
mod web;

use clap::Parser;
use futures_util::{stream::FuturesUnordered, StreamExt};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    io::{self, IsTerminal, Write},
    net::{IpAddr, SocketAddr},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

pub const SCHEMA_VERSION: u8 = 2;

const AFTER_HELP: &str = "\
Checks (combine any; default for a domain is: where email ping whois web):
  where        DNS hosting service, domain registrar, IP network owner
  email        MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI
  ping         10 ICMP echoes with a latency chart
  whois        RDAP registration: registrar, dates, status, nameservers
  web          status, redirects, DNS/TCP/TLS/response timing, certificate, HSTS
  dns [TYPES]  records, e.g. `dns A MX TXT`; default is 14 types + SRV/TLSA presets
  blacklist    the IP (or the domain's mail servers) on 14 DNS blocklists
  ip           reverse DNS + forward confirmation, ASN, BGP prefix, network owner
  ports [N..]  common TCP ports, or up to 10 given, e.g. `ports 22 8080`
  propagation  ask each authoritative nameserver directly and compare
  subdomains   20 common names with randomized wildcard controls
  dkim:SEL     email check using this DKIM selector, e.g. dkim:google
  all          every check

Examples:
  wheredns github.com
  wheredns google.com email dkim:20230601
  wheredns example.com dns A MX propagation
  wheredns 8.8.8.8 blacklist ip
  wheredns cloudflare.com web ports ping
  pbpaste | wheredns headers

Themes: btop (default), tty, purple, phosphor, amber, ansi (terminal colors), none.

Settings (saved in ~/.config/wheredns/config):
  wheredns config                          show settings and the file path
  wheredns config set theme tty            keep a theme
  wheredns config set checks where web dns default checks for a domain
  wheredns config set animate minimal      full (live panels), minimal or off
  wheredns config set background true      paint the theme background
Flags beat WHEREDNS_THEME / WHEREDNS_ANIMATE, which beat the config file.
Exit codes: 0 checks completed, 1 a check failed, 2 invalid input, 130 cancelled or deadline.";

#[derive(Parser, Debug)]
#[command(
    version,
    about = "DNS, email, registration and network diagnostics from your own machine",
    after_help = AFTER_HELP
)]
pub struct Args {
    /// Domain, IP address or URL; or `headers` to analyze an email header from stdin
    target: Option<String>,
    /// Checks to run, with their arguments (see below)
    checks: Vec<String>,
    /// Machine-readable JSON (no colors)
    #[arg(long)]
    pub json: bool,
    /// Color theme for the terminal report [default: btop, or the saved theme]
    #[arg(long, value_enum, env = "WHEREDNS_THEME")]
    pub theme: Option<display::Theme>,
    /// Live animation on a terminal [default: full, or the saved setting]
    #[arg(long, value_enum, env = "WHEREDNS_ANIMATE")]
    pub animate: Option<display::Animate>,
    /// Allow private, loopback and other non-public destinations and resolvers
    #[arg(long)]
    pub allow_private: bool,
    /// Per-operation timeout in seconds
    #[arg(long,default_value_t=5,value_parser=clap::value_parser!(u64).range(1..=30))]
    pub timeout: u64,
    /// Whole-run deadline in seconds
    #[arg(long,default_value_t=60,value_parser=clap::value_parser!(u64).range(1..=300))]
    pub deadline: u64,
    /// Parallel DNS/TCP operations per check
    #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u8).range(1..=16))]
    pub concurrency: u8,
    /// Recursive DNS resolver (IP:port)
    #[arg(long, default_value = "1.1.1.1:53")]
    pub resolver: SocketAddr,
    /// DNS record types for the dns check (same as `dns A MX`)
    #[arg(long = "type", value_delimiter = ',', value_parser = dns::parse_record_type)]
    pub types: Vec<String>,
    /// TCP ports for the ports check (same as `ports 22 443`)
    #[arg(long, value_delimiter = ',')]
    pub ports: Vec<u16>,
    /// DKIM selectors for the email check (same as `dkim:google`)
    #[arg(long, value_delimiter = ',')]
    pub selectors: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Where,
    Email,
    Ping,
    Whois,
    Web,
    Dns,
    Blacklist,
    Ip,
    Ports,
    Propagation,
    Subdomains,
}

impl Group {
    pub const ALL: [Group; 11] = [
        Group::Where,
        Group::Email,
        Group::Ping,
        Group::Whois,
        Group::Web,
        Group::Dns,
        Group::Blacklist,
        Group::Ip,
        Group::Ports,
        Group::Propagation,
        Group::Subdomains,
    ];
    pub fn id(self) -> &'static str {
        match self {
            Group::Where => "where",
            Group::Email => "email",
            Group::Ping => "ping",
            Group::Whois => "whois",
            Group::Web => "web",
            Group::Dns => "dns",
            Group::Blacklist => "blacklist",
            Group::Ip => "ip",
            Group::Ports => "ports",
            Group::Propagation => "propagation",
            Group::Subdomains => "subdomains",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Group::Ip => "ip+asn",
            g => g.id(),
        }
    }
    /// Panel order (1-based).
    pub fn n(self) -> usize {
        Group::ALL.iter().position(|g| *g == self).unwrap_or(0) + 1
    }
    fn domain_only(self) -> bool {
        matches!(
            self,
            Group::Where | Group::Email | Group::Dns | Group::Propagation | Group::Subdomains
        )
    }
    pub fn from_id(id: &str) -> Option<Group> {
        Some(match id {
            "where" | "summary" | "wheredns" => Group::Where,
            "email" | "mail" => Group::Email,
            "ping" | "icmp" => Group::Ping,
            "whois" | "rdap" => Group::Whois,
            "web" | "http" | "https" => Group::Web,
            "dns" => Group::Dns,
            "blacklist" | "bl" | "dnsbl" => Group::Blacklist,
            "ip" | "asn" => Group::Ip,
            "ports" | "tcp" => Group::Ports,
            "propagation" | "prop" => Group::Propagation,
            "subdomains" | "subs" => Group::Subdomains,
            _ => return None,
        })
    }
}

#[derive(Serialize)]
pub struct Row {
    pub check: String,
    pub ok: bool,
    pub elapsed_ms: u128,
    pub data: Value,
    pub error: Option<String>,
}

pub struct CheckFailure {
    pub error: String,
    pub data: Value,
}

impl From<String> for CheckFailure {
    fn from(error: String) -> Self {
        Self {
            error,
            data: Value::Null,
        }
    }
}

impl From<&str> for CheckFailure {
    fn from(error: &str) -> Self {
        error.to_string().into()
    }
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub target: String,
    pub vantage: &'static str,
    pub elapsed_ms: u128,
    pub complete: bool,
    pub results: Vec<Row>,
}

pub struct Target {
    pub host: String,
    pub url: reqwest::Url,
    pub ip: Option<IpAddr>,
    pub explicit_http: bool,
}

pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_multicast()
                || o[0] == 0
                || o[0] >= 224
                || (o[0] == 192 && o[1] == 0)
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19 || (o[1] == 51 && o[2] == 100)))
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || (o[0] == 100 && o[1] & 192 == 64))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || s[0] & 0xfe00 == 0xfc00
                || s[0] & 0xffc0 == 0xfe80
                || s[0] & 0xffc0 == 0xfec0
                || (a.to_ipv4_mapped().is_none()
                    && (s[0] & 0xe000 != 0x2000
                        || (s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0xdb8))
                        || s[0] == 0x2002))
                || a.to_ipv4_mapped().is_some_and(|v| !public(IpAddr::V4(v))))
        }
    }
}

pub fn permit(ip: IpAddr, a: &Args) -> Result<(), String> {
    if a.allow_private || public(ip) {
        Ok(())
    } else {
        Err(format!("destination {ip} requires --allow-private"))
    }
}

fn target(raw: &str) -> Result<(String, reqwest::Url), String> {
    if raw.parse::<IpAddr>().is_ok_and(|v| v.is_ipv6()) {
        return target(&format!("https://[{raw}]/"));
    }
    let u = reqwest::Url::parse(if raw.contains("://") {
        raw
    } else {
        return target(&format!("https://{raw}"));
    })
    .map_err(|e| format!("invalid target {raw:?}: {e}"))?;
    if !["http", "https"].contains(&u.scheme())
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return Err("expected a domain, IP address or HTTP(S) URL without credentials".into());
    }
    let host = u
        .host_str()
        .ok_or("missing hostname")?
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_string();
    Ok((host, u))
}

fn partials() -> &'static Mutex<HashMap<&'static str, Value>> {
    static PARTIAL: OnceLock<Mutex<HashMap<&'static str, Value>>> = OnceLock::new();
    PARTIAL.get_or_init(Default::default)
}

/// Streams a running check's evidence so far to the live view.
pub fn publish(g: Group, v: Value) {
    partials().lock().unwrap().insert(g.id(), v);
}

fn partial(g: Group) -> Option<Value> {
    partials().lock().unwrap().get(g.id()).cloned()
}

type CacheKey = (String, String, SocketAddr, bool);

fn cache() -> &'static Mutex<HashMap<CacheKey, Result<dns::Answer, String>>> {
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, Result<dns::Answer, String>>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// One DNS question, memoized for the run so checks share evidence.
pub async fn lookup(
    a: &Args,
    name: &str,
    kind: &str,
    server: SocketAddr,
    recursive: bool,
) -> Result<dns::Answer, String> {
    permit(server.ip(), a)?;
    let key = (
        name.to_ascii_lowercase(),
        kind.to_string(),
        server,
        recursive,
    );
    if let Some(hit) = cache().lock().unwrap().get(&key) {
        return hit.clone();
    }
    let result = tokio::time::timeout(
        Duration::from_secs(a.timeout),
        dns::query(name, kind, server, recursive),
    )
    .await
    .map_err(|_| "DNS timeout".to_string())
    .and_then(|r| r);
    cache().lock().unwrap().insert(key, result.clone());
    result
}

pub async fn addresses(a: &Args, host: &str) -> Result<Vec<IpAddr>, String> {
    let mut ips = vec![];
    if let Ok(ip) = host.parse() {
        ips.push(ip)
    } else {
        let (v4, v6) = tokio::join!(
            lookup(a, host, "A", a.resolver, true),
            lookup(a, host, "AAAA", a.resolver, true)
        );
        let (v4, v6) = (v4?, v6?);
        if v4.outcome == dns::Outcome::NxDomain && v6.outcome == dns::Outcome::NxDomain {
            return Err(format!("{host} does not exist (NXDOMAIN)"));
        }
        ips.extend(v4.addresses()?);
        ips.extend(v6.addresses()?);
    }
    if ips.is_empty() {
        return Err(format!("{host} has no A or AAAA record"));
    }
    for ip in &ips {
        permit(*ip, a)?
    }
    Ok(ips)
}

async fn run_group(a: &Args, t: &Target, g: Group) -> Row {
    let start = Instant::now();
    let result = match g {
        Group::Where => checks::where_(a, t).await,
        Group::Email => checks::email(a, t).await,
        Group::Ping => checks::ping(a, t).await,
        Group::Whois => checks::whois(a, t).await,
        Group::Web => checks::web(a, t).await,
        Group::Dns => checks::dns(a, t).await,
        Group::Blacklist => checks::blacklist(a, t).await,
        Group::Ip => checks::ip(a, t).await,
        Group::Ports => checks::ports(a, t).await,
        Group::Propagation => checks::propagation(a, t).await,
        Group::Subdomains => checks::subdomains(a, t).await,
    };
    let elapsed_ms = start.elapsed().as_millis();
    match result {
        Ok(data) => Row {
            check: g.id().into(),
            ok: true,
            elapsed_ms,
            data,
            error: None,
        },
        Err(f) => Row {
            check: g.id().into(),
            ok: false,
            elapsed_ms,
            data: f.data,
            error: Some(f.error),
        },
    }
}

fn usage(message: impl std::fmt::Display) -> ! {
    eprintln!("wheredns: {message}\nRun `wheredns --help` for checks and examples.");
    std::process::exit(2)
}

/// Turns `dns A MX ports 22 dkim:google all` into groups and their arguments.
fn plan(a: &mut Args, is_ip: bool, saved: Option<&[String]>) -> Vec<Group> {
    let mut groups: Vec<Group> = vec![];
    let mut after_dns = false;
    let mut numbers = vec![];
    let mut all = false;
    for token in a.checks.clone() {
        let flag = token.trim_start_matches('-').to_ascii_lowercase();
        if let Some(sel) = flag.strip_prefix("dkim:") {
            if sel.is_empty()
                || sel.len() > 63
                || !sel
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c))
            {
                usage(format!("invalid DKIM selector in {token:?}"));
            }
            a.selectors.push(sel.to_string());
            groups.push(Group::Email);
            continue;
        }
        if flag.bytes().all(|c| c.is_ascii_digit()) && !flag.is_empty() {
            match flag.parse::<u16>() {
                Ok(p) if p > 0 => numbers.push(p),
                _ => usage(format!("invalid port {token:?}")),
            }
            continue;
        }
        if flag == "all" {
            all = true;
            continue;
        }
        // After `dns`, record types win over check names (e.g. `dns HTTPS`).
        if after_dns {
            if let Ok(ty) = dns::parse_record_type(&flag) {
                if !a.types.contains(&ty) {
                    a.types.push(ty);
                }
                continue;
            }
        }
        if let Some(g) = Group::from_id(&flag) {
            after_dns = g == Group::Dns;
            groups.push(g);
            continue;
        }
        usage(format!("unknown check or argument {token:?}"));
    }
    if !numbers.is_empty() {
        if !groups.contains(&Group::Ports) && !all {
            usage("port numbers need the `ports` check, e.g. `ports 22 8080`");
        }
        for p in numbers {
            if !a.ports.contains(&p) {
                a.ports.push(p);
            }
        }
    }
    if a.ports.len() > 10 || a.types.len() > 20 || a.selectors.len() > 10 {
        usage("at most 10 ports, 20 record types and 10 DKIM selectors");
    }
    if all {
        groups = Group::ALL.to_vec();
    } else if groups.is_empty() {
        let saved: Vec<Group> = saved
            .unwrap_or_default()
            .iter()
            .filter_map(|c| Group::from_id(c))
            .filter(|g| !(is_ip && g.domain_only()))
            .collect();
        groups = if !saved.is_empty() {
            saved
        } else if is_ip {
            vec![Group::Ping, Group::Whois, Group::Web, Group::Ip]
        } else {
            vec![
                Group::Where,
                Group::Email,
                Group::Ping,
                Group::Whois,
                Group::Web,
            ]
        };
    }
    if is_ip {
        if !all {
            if let Some(g) = groups.iter().find(|g| g.domain_only()) {
                usage(format!("{} needs a domain, not an IP address", g.id()));
            }
        }
        groups.retain(|g| !g.domain_only());
    }
    let mut ordered: Vec<Group> = Group::ALL
        .iter()
        .copied()
        .filter(|g| groups.contains(g))
        .collect();
    ordered.dedup();
    ordered
}

/// Bookkeeping for the live view: what is committed above, how tall the
/// redrawn region below is, and when each panel started its entrance.
struct LiveView {
    printed: usize,
    height: usize,
    reveal_at: Vec<Option<Instant>>,
}

/// Redraws the live region in place. Finished panels are committed above it
/// in order (after a short entrance); `last` commits everything that is done.
fn draw(
    r: &display::Renderer,
    groups: &[Group],
    slots: &[Option<Row>],
    v: &mut LiveView,
    frame: usize,
    started: &[Instant],
    last: bool,
) -> String {
    let max_lines = display::term_rows().saturating_sub(1).max(8);
    let mut s = String::from("\x1b[?2026h");
    let mut up = v.height;
    if let Some(old) = r.refresh_width() {
        // Terminals rewrap the old rows when the window narrows.
        let cols = r.width() + 1;
        if old + 1 > cols {
            up = v.height * (old + 1).div_ceil(cols);
        }
    }
    if up > 0 {
        s.push_str(&format!("\x1b[{up}F"));
    }
    let now = Instant::now();
    while v.printed < groups.len() {
        let i = v.printed;
        let Some(row) = &slots[i] else { break };
        let panel = r.panel(row, Some(groups[i]));
        let tall = panel.matches('\n').count() + 2 > max_lines;
        let queue = slots[i..].iter().take_while(|s| s.is_some()).count();
        let at = *v.reveal_at[i].get_or_insert(now);
        let lines = panel.matches('\n').count() as u64;
        let dur = (200 + lines * 8).min(450) / queue.clamp(1, 3) as u64;
        let p = now.duration_since(at).as_millis() as f64 / dur as f64;
        if last || tall || p >= 1.0 {
            s.push_str(&panel);
            v.printed += 1;
        } else {
            break;
        }
    }
    v.height = 0;
    if !last && v.printed < groups.len() {
        let live: Vec<(Group, display::Slot)> = (v.printed..groups.len())
            .map(|i| {
                let g = groups[i];
                let slot = match &slots[i] {
                    Some(row) if i == v.printed => {
                        let at = v.reveal_at[i].unwrap_or(now);
                        let lines = r.panel(row, Some(g)).matches('\n').count() as u64;
                        let queue = slots[i..].iter().take_while(|s| s.is_some()).count();
                        let dur = (200 + lines * 8).min(450) / queue.clamp(1, 3) as u64;
                        display::Slot::Reveal(
                            row,
                            now.duration_since(at).as_millis() as f64 / dur as f64,
                        )
                    }
                    Some(row) => display::Slot::Ready(row),
                    None => display::Slot::Running {
                        elapsed_ms: now.duration_since(started[i]).as_millis(),
                        partial: partial(g),
                    },
                };
                (g, slot)
            })
            .collect();
        let states: Vec<(Group, Option<bool>)> = groups
            .iter()
            .zip(slots)
            .map(|(g, s)| (*g, s.as_ref().map(|r| r.ok)))
            .collect();
        let (text, lines) = r.live(&live, &states, frame, max_lines);
        s.push_str(&text);
        v.height = lines;
    }
    s.push_str("\x1b[J\x1b[?2026l");
    s
}

#[tokio::main]
async fn main() {
    let mut a = Args::parse();
    if a.target.as_deref() == Some("config") {
        if let Err(e) = config::command(&a.checks) {
            usage(e);
        }
        return;
    }
    let cfg = config::load();
    let theme = a.theme.or(cfg.theme).unwrap_or_default();
    let animate = a.animate.or(cfg.animate).unwrap_or_default();
    let background = cfg.background.unwrap_or(false);
    if a.target.as_deref() == Some("headers") {
        let raw = headers::read(io::stdin()).unwrap_or_else(|e| usage(e));
        let v = headers::parse(&raw);
        let out = if a.json {
            serde_json::to_string(&v).unwrap()
        } else {
            display::Renderer::new(theme, false, background).headers(&v)
        };
        // A closed pipe (e.g. `| head`) is not an error worth a panic.
        let _ = writeln!(io::stdout().lock(), "{out}");
        return;
    }
    let Some(raw) = a.target.clone() else {
        usage("target required, e.g. `wheredns example.com` (or `headers` to read stdin)");
    };
    let (host, url) = target(&raw).unwrap_or_else(|e| usage(e));
    let ip = host.parse::<IpAddr>().ok();
    let groups = plan(&mut a, ip.is_some(), cfg.checks.as_deref());
    let t = Target {
        host: host.to_ascii_lowercase(),
        url,
        ip,
        explicit_http: raw.to_ascii_lowercase().starts_with("http://"),
    };

    let renderer = display::Renderer::new(theme, a.json, background);
    let full = renderer.is_live() && animate == display::Animate::Full;
    let line =
        renderer.is_live() && animate == display::Animate::Minimal && io::stderr().is_terminal();
    let start = Instant::now();
    let mut stdout = io::stdout().lock();
    if !a.json {
        if full {
            write!(stdout, "\x1b[?25l").ok();
        }
        write!(stdout, "{}", renderer.header(&t.host, &groups)).ok();
        stdout.flush().ok();
    }

    let started: Vec<Instant> = groups.iter().map(|_| Instant::now()).collect();
    let mut pending: FuturesUnordered<_> = groups
        .iter()
        .enumerate()
        .map(|(i, g)| {
            let (a, t) = (&a, &t);
            async move { (i, run_group(a, t, *g).await) }
        })
        .collect();
    let mut slots: Vec<Option<Row>> = groups.iter().map(|_| None).collect();
    let mut view = LiveView {
        printed: 0,
        height: 0,
        reveal_at: groups.iter().map(|_| None).collect(),
    };
    let mut frame = 0usize;
    let mut tick = tokio::time::interval(Duration::from_millis(if full { 40 } else { 90 }));
    let deadline = tokio::time::sleep(Duration::from_secs(a.deadline));
    tokio::pin!(deadline);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut stop: Option<&str> = None;
    let clear = |line: bool| {
        if line {
            eprint!("\r\x1b[2K");
        }
    };
    while view.printed < groups.len() {
        tokio::select! {
            Some((i, row)) = pending.next() => {
                slots[i] = Some(row);
                if a.json {
                    while view.printed < groups.len() && slots[view.printed].is_some() {
                        view.printed += 1;
                    }
                } else if full {
                    write!(stdout, "{}", draw(&renderer, &groups, &slots, &mut view, frame, &started, false)).ok();
                    stdout.flush().ok();
                } else {
                    clear(line);
                    while view.printed < groups.len() {
                        let Some(row) = &slots[view.printed] else { break };
                        write!(stdout, "{}", renderer.panel(row, Some(groups[view.printed]))).ok();
                        view.printed += 1;
                    }
                    stdout.flush().ok();
                }
            }
            _ = tick.tick(), if full || line => {
                frame += 1;
                if full {
                    write!(stdout, "{}", draw(&renderer, &groups, &slots, &mut view, frame, &started, false)).ok();
                    stdout.flush().ok();
                } else {
                    let states: Vec<(Group, Option<bool>)> = groups.iter().zip(&slots).map(|(g, s)| (*g, s.as_ref().map(|r| r.ok))).collect();
                    eprint!("\r\x1b[2K{}", renderer.progress(&states, frame));
                    io::stderr().flush().ok();
                }
            }
            _ = &mut deadline => { stop = Some("aggregate deadline exceeded"); break; }
            _ = &mut ctrl_c => { stop = Some("cancelled"); break; }
        }
    }
    drop(pending);
    clear(line);
    if full {
        write!(
            stdout,
            "{}",
            draw(&renderer, &groups, &slots, &mut view, frame, &started, true)
        )
        .ok();
    }
    let printed = view.printed;
    let mut rows: Vec<Row> = vec![];
    for (i, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(row) => {
                if i >= printed && !a.json {
                    write!(stdout, "{}", renderer.panel(&row, Some(groups[i]))).ok();
                }
                rows.push(row)
            }
            None if stop.is_some() => rows.push(Row {
                check: groups[i].id().into(),
                ok: false,
                elapsed_ms: start.elapsed().as_millis(),
                data: Value::Null,
                error: Some(stop.unwrap().into()),
            }),
            None => {}
        }
    }
    let complete = stop.is_none();
    if !complete {
        rows.push(Row {
            check: "run".into(),
            ok: false,
            elapsed_ms: start.elapsed().as_millis(),
            data: Value::Null,
            error: Some(stop.unwrap().into()),
        });
    }
    let ok = complete && rows.iter().all(|r| r.ok);
    let report = Report {
        schema_version: SCHEMA_VERSION,
        target: t.host.clone(),
        vantage: "local",
        elapsed_ms: start.elapsed().as_millis(),
        complete,
        results: rows,
    };
    if a.json {
        writeln!(stdout, "{}", serde_json::to_string(&report).unwrap()).ok();
    } else {
        write!(stdout, "{}", renderer.footer(&report)).ok();
        if full {
            write!(stdout, "\x1b[?25h").ok();
        }
    }
    stdout.flush().ok();
    if !ok {
        std::process::exit(if complete { 1 } else { 130 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_headers_and_platform_policy() {
        assert!(headers::read(&vec![b' '; 65537][..]).is_err());
        assert!(headers::read(&b"Subject: x\n\xff"[..]).is_err());
        struct Broken;
        impl io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("fixture"))
            }
        }
        assert!(headers::read(Broken).is_err());
        assert_eq!(
            headers::parse("\nSubject: body")["fields"],
            serde_json::json!([])
        );
        assert_eq!(headers::parse(" orphan\nSubject: x")["malformed_lines"], 1);
        for ip in [
            "fec0::1",
            "2001:db8::1",
            "2002::1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public(ip.parse().unwrap()));
        }
        use checks::ping_program;
        assert_eq!(ping_program("macos", "::1".parse().unwrap()), "ping6");
        assert_eq!(ping_program("linux", "::1".parse().unwrap()), "ping");
        assert_eq!(ping_program("windows", "::1".parse().unwrap()), "ping");
    }
    #[test]
    fn url_normalization() {
        assert_eq!(
            target("https://Example.com/path?q=1").unwrap().0,
            "example.com"
        );
        assert!(target("https://user:pass@example.com").is_err());
        assert!(target("file:///etc/passwd").is_err());
        assert_eq!(
            target("example.com/path?q=1").unwrap().1.as_str(),
            "https://example.com/path?q=1"
        );
    }
    #[test]
    fn header_fixture() {
        let v=headers::parse("From: sender@example.test\nAuthentication-Results: untrusted\nX-Test: a\nX-Test: b\nbroken");
        assert_eq!(v["fields"].as_array().unwrap().len(), 4);
        assert_eq!(v["malformed_lines"], 1);
        assert_eq!(v["authentication_results_untrusted"], true);
    }
    #[test]
    fn address_policy() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "100.64.0.1",
        ] {
            assert!(!public(s.parse().unwrap()))
        }
    }
    #[test]
    fn ping_parsing_handles_each_platform() {
        let mac = "PING 1.1.1.1: 56 data bytes\n64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.3 ms\nRequest timeout for icmp_seq 1\n64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=10.0 ms\n";
        let s = checks::parse_ping(mac, 10);
        assert_eq!(&s[..3], &[Some(12.3), None, Some(10.0)]);
        let linux = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=9.1 ms\n64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=8 ms\n";
        let s = checks::parse_ping(linux, 10);
        assert_eq!(&s[..3], &[Some(9.1), None, Some(8.0)]);
        let win = "Reply from 1.1.1.1: bytes=32 time=14ms TTL=57\nReply from 1.1.1.1: bytes=32 time<1ms TTL=57\n";
        let s = checks::parse_ping(win, 10);
        assert_eq!(&s[..2], &[Some(14.0), Some(1.0)]);
    }
    #[test]
    fn provider_attribution() {
        let p = checks::dns_hosting_providers(&[
            "dns1.p08.nsone.net.".into(),
            "ns-421.awsdns-52.com".into(),
            "ns1.example-host.net".into(),
        ]);
        assert_eq!(p[0]["name"], "NS1");
        assert_eq!(p[1]["name"], "Amazon Route 53");
        assert_eq!(p[2]["name"], "example-host.net");
        assert_eq!(p[2]["basis"], "nameserver-domain");
    }
}
