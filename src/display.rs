use crate::{Report, Row};
use clap::ValueEnum;
use serde_json::Value;
use std::fmt::Write;
use std::io::{self, IsTerminal};
use textwrap::{core::display_width, Options, WordSplitter};

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Theme {
    Tty,
    Btop,
    #[default]
    Purple,
    Phosphor,
    Amber,
}

#[derive(Clone, Copy)]
struct Palette {
    accent: (u8, u8, u8),
    background: (u8, u8, u8),
}

impl Theme {
    fn palette(self) -> Palette {
        let (accent, background) = match self {
            Self::Tty => ((143, 184, 216), (14, 16, 18)),
            Self::Btop => ((95, 215, 255), (0, 0, 0)),
            Self::Purple => ((216, 107, 255), (7, 7, 31)),
            Self::Phosphor => ((182, 255, 200), (4, 10, 5)),
            Self::Amber => ((255, 213, 138), (12, 8, 2)),
        };
        Palette { accent, background }
    }
}

struct Terminal {
    width: usize,
    palette: Option<Palette>,
}

impl Terminal {
    fn current(theme: Theme) -> Option<Self> {
        if !io::stdout().is_terminal() || std::env::var("TERM").as_deref() == Ok("dumb") {
            return None;
        }
        let width = textwrap::termwidth().saturating_sub(1).min(124);
        let color = std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty());
        (width >= 34).then(|| Self {
            width,
            palette: color.then(|| theme.palette()),
        })
    }

    fn panel(&self, output: &mut String, title: &str, badge: Option<(&str, Tone)>, body: &str) {
        let suffix = badge.map_or(3, |(label, _)| label.len() + 5);
        let rule = "─".repeat(self.width.saturating_sub(display_width(title) + suffix + 4));
        self.start(output, Tone::Accent);
        write!(output, "╭─ {title} {rule}").unwrap();
        if let Some((label, tone)) = badge {
            self.paint(output, tone);
            write!(output, " [{label}] ").unwrap();
            self.paint(output, Tone::Accent);
        } else {
            output.push_str("──");
        }
        output.push('╮');
        self.end(output);
        let inner = self.width - 4;
        for row in body.lines() {
            let prefix = row.len() - row.trim_start_matches(' ').len();
            let prefix = prefix.min(inner - 8);
            let continuation = (prefix + 2).min(inner - 8);
            let indent = " ".repeat(prefix);
            let hanging = " ".repeat(continuation);
            let options = Options::new(inner)
                .word_splitter(WordSplitter::NoHyphenation)
                .initial_indent(&indent)
                .subsequent_indent(&hanging);
            let tone = Tone::for_line(row);
            for wrapped in textwrap::wrap(row.trim_start_matches(' '), options) {
                self.start(output, Tone::Accent);
                output.push_str("│ ");
                self.paint(output, tone);
                output.push_str(&wrapped);
                let padding = " ".repeat(inner.saturating_sub(display_width(&wrapped)));
                output.push_str(&padding);
                self.paint(output, Tone::Accent);
                output.push_str(" │");
                self.end(output);
            }
        }
        self.start(output, Tone::Accent);
        write!(output, "╰{}╯", "─".repeat(self.width - 2)).unwrap();
        self.end(output);
    }

    fn start(&self, output: &mut String, tone: Tone) {
        if let Some(palette) = self.palette {
            let (r, g, b) = palette.background;
            write!(output, "\x1b[48;2;{r};{g};{b}m").unwrap();
            self.paint(output, tone);
        }
    }

    fn paint(&self, output: &mut String, tone: Tone) {
        if let Some(palette) = self.palette {
            let (r, g, b) = match tone {
                Tone::Accent => palette.accent,
                Tone::Text => (226, 224, 239),
                Tone::Muted => (160, 160, 183),
                Tone::Good => (112, 230, 214),
                Tone::Warn => (255, 213, 138),
                Tone::Bad => (255, 115, 175),
            };
            write!(output, "\x1b[38;2;{r};{g};{b}m").unwrap();
        }
    }

    fn end(&self, output: &mut String) {
        if self.palette.is_some() {
            output.push_str("\x1b[0m");
        }
        output.push('\n');
    }
}

#[derive(Clone, Copy)]
enum Tone {
    Accent,
    Text,
    Muted,
    Good,
    Warn,
    Bad,
}

impl Tone {
    fn for_line(line: &str) -> Self {
        let line = line.trim_start();
        if line.starts_with("Error:") {
            Self::Bad
        } else if line.starts_with("Server:")
            || line.starts_with("Resolver:")
            || line == "No records returned"
        {
            Self::Muted
        } else if line.ends_with("[No Error]") {
            Self::Good
        } else if line.ends_with("[NODATA]") || line.ends_with("[Non-Existent Domain]") {
            Self::Warn
        } else {
            match line
                .split_once("  ")
                .and_then(|(status, url)| {
                    url.starts_with("http").then(|| status.parse::<u16>().ok())
                })
                .flatten()
            {
                Some(200..=299) => Self::Good,
                Some(300..=399) => Self::Warn,
                Some(400..=599) => Self::Bad,
                _ => Self::Text,
            }
        }
    }
}

fn check_name(check: &str) -> &str {
    match check {
        "dns" => "DNS",
        "email" => "Email DNS",
        "http" | "web" => "HTTP",
        "whois" | "rdap" => "RDAP",
        "tcp" | "ports" => "TCP",
        "ip" => "IP and reverse DNS",
        "prop" | "propagation" => "DNS propagation",
        "subdomains" => "Subdomains",
        "ping" => "Ping",
        "run" => "Run",
        check => check,
    }
}

fn check_status(row: &Row, complete: bool) -> (&'static str, Tone) {
    if row.ok {
        ("OK", Tone::Good)
    } else if complete {
        ("FAILED", Tone::Bad)
    } else {
        ("INCOMPLETE", Tone::Warn)
    }
}

fn check_body(output: &mut String, row: &Row, indent: usize) {
    if let Some(error) = &row.error {
        line(output, indent, format_args!("Error: {}", text(error)));
    }
    if !row.data.is_null() {
        if let Some(hops) = row.data["hops"].as_array() {
            http_hops(output, hops, indent);
        }
        section(output, &row.data, indent, true);
    }
}

pub fn report(report: &Report, theme: Theme) -> String {
    if let Some(terminal) = Terminal::current(theme) {
        return terminal_report(&terminal, report);
    }
    plain_report(report)
}

fn terminal_report(terminal: &Terminal, report: &Report) -> String {
    let mut output = String::new();
    let passed = report.results.iter().filter(|row| row.ok).count();
    let total = report.results.len();
    terminal.panel(
        &mut output,
        "WhereDNS",
        Some(("LOCAL", Tone::Accent)),
        &format!(
            "{}\n{passed}/{total} checks passed  ·  {} ms",
            text(&report.target),
            report.elapsed_ms
        ),
    );
    for row in &report.results {
        output.push('\n');
        let mut body = String::new();
        check_body(&mut body, row, 0);
        terminal.panel(
            &mut output,
            check_name(&row.check),
            Some(check_status(row, report.complete)),
            &body,
        );
    }
    output.pop();
    output
}

fn plain_report(report: &Report) -> String {
    let mut output = format!("{}  ({} ms)", text(&report.target), report.elapsed_ms);
    for row in &report.results {
        let check = check_name(&row.check);
        let (status, _) = check_status(row, report.complete);
        write!(output, "\n\n{check}  [{status}]\n").unwrap();
        check_body(&mut output, row, 2);
        output.truncate(output.trim_end_matches('\n').len());
    }
    output
}

pub fn headers(data: &Value, theme: Theme) -> String {
    if let Some(terminal) = Terminal::current(theme) {
        let mut output = String::new();
        let mut body = String::new();
        header_body(&mut body, data, 0);
        terminal.panel(&mut output, "Email headers", None, &body);
        output.pop();
        return output;
    }
    let mut output = String::from("Email headers\n");
    header_body(&mut output, data, 2);
    output.trim_end_matches('\n').to_owned()
}

fn header_body(output: &mut String, data: &Value, indent: usize) {
    fields(output, data["fields"].as_array().unwrap(), indent);
    let malformed = &data["malformed_lines"];
    if malformed.as_u64().is_some_and(|count| count > 0) {
        writeln!(output, "\nMalformed lines: {malformed}").unwrap();
    }
    if data["authentication_results_untrusted"] == true {
        output.push_str("\nAuthentication results are untrusted.\n");
    }
}

fn text(value: &str) -> String {
    // Render control characters as text so remote evidence cannot change the terminal display.
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_control() {
            output.extend(ch.escape_default());
        } else {
            output.push(ch);
        }
    }
    output
}

fn scalar(value: &Value) -> String {
    match value {
        Value::String(s) => text(s),
        Value::Bool(true) => "yes".into(),
        Value::Bool(false) => "no".into(),
        _ => value.to_string(),
    }
}

fn field(value: &Value, key: &str) -> String {
    scalar(&value[key])
}

fn line(output: &mut String, indent: usize, value: impl std::fmt::Display) {
    writeln!(output, "{:indent$}{value}", "").unwrap();
}

fn fields(output: &mut String, values: &[Value], indent: usize) {
    if values.is_empty() {
        line(output, indent, "(none)");
    }
    for value in values {
        let name = field(value, "name");
        let value = field(value, "value");
        line(output, indent, format_args!("{name}: {value}"));
    }
}

fn dns_answer(
    output: &mut String,
    answer: &Value,
    records: &[Value],
    indent: usize,
    show_server: bool,
) {
    let kind = field(answer, "rr_type");
    let name = field(answer, "name");
    let status = field(answer, "status");
    let server = field(answer, "server");
    let authority = if answer["authoritative"] == true {
        "  (authoritative)"
    } else {
        ""
    };
    line(
        output,
        indent,
        format_args!("{kind}  {name}{authority}  [{status}]"),
    );
    if show_server {
        line(output, indent + 2, format_args!("Server: {server}"));
    }
    if records.is_empty() {
        line(output, indent + 2, "No records returned");
    }
    for record in records {
        let name = field(record, "name");
        let kind = field(record, "rr_type");
        let class = match record["rr_class"].as_u64() {
            Some(1) => "IN".to_owned(),
            _ => format!("class {}", field(record, "rr_class")),
        };
        let ttl = field(record, "ttl");
        let value = field(record, "value");
        line(
            output,
            indent + 2,
            format_args!("{name}  {ttl}s  {class}  {kind}  {value}"),
        );
    }
}

fn dns_queries(output: &mut String, queries: &[Value], indent: usize) {
    let shared_server = queries
        .first()
        .and_then(|query| query["server"].as_str())
        .filter(|server| queries.iter().all(|query| query["server"] == *server));
    if let Some(server) = shared_server {
        line(output, indent, format_args!("Resolver: {}", text(server)));
        output.push('\n');
    }
    for query in queries {
        if let Some(records) = query["records"].as_array() {
            dns_answer(output, query, records, indent, shared_server.is_none());
        } else {
            section(output, query, indent, true);
        }
    }
}

fn http_hops(output: &mut String, hops: &[Value], indent: usize) {
    for hop in hops {
        let status = field(hop, "status");
        let url = field(hop, "url");
        let elapsed = field(hop, "elapsed_ms");
        line(
            output,
            indent,
            format_args!("{status}  {url}  ({elapsed} ms)"),
        );
        fields(output, hop["headers"].as_array().unwrap(), indent + 2);
    }
}

fn section(output: &mut String, value: &Value, indent: usize, diagnostic: bool) {
    match value {
        Value::Object(entries) if entries.is_empty() => line(output, indent, "(empty)"),
        Value::Object(entries) => {
            if diagnostic && entries.contains_key("rr_type") {
                if let Some(records) = value["records"].as_array() {
                    dns_answer(output, value, records, indent, true);
                    return;
                }
            }
            for (key, item) in entries {
                let label = text(&key.replace('_', " "));
                match (diagnostic, key.as_str(), item) {
                    (true, "queries", Value::Array(queries)) => {
                        dns_queries(output, queries, indent);
                    }
                    (true, "hops" | "http_success" | "success", _)
                    | (true, "body", Value::Null) => {}
                    (true, "raw", Value::String(raw)) => {
                        for row in raw.lines() {
                            line(output, indent, text(row));
                        }
                    }
                    (_, _, Value::Array(values)) if values.is_empty() => {
                        line(output, indent, format_args!("{label}: (none)"));
                    }
                    (_, _, Value::Object(_) | Value::Array(_)) => {
                        line(output, indent, format_args!("{label}:"));
                        section(output, item, indent + 2, diagnostic && key != "body");
                    }
                    _ => line(output, indent, format_args!("{label}: {}", scalar(item))),
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if item.is_object() || item.is_array() {
                    line(output, indent, format_args!("{}.", index + 1));
                    section(output, item, indent + 2, diagnostic);
                } else {
                    line(output, indent, format_args!("- {}", scalar(item)));
                }
            }
        }
        _ => line(output, indent, scalar(value)),
    }
}
