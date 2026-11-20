//! Terminal report modeled on the WhereDNS website: framed, numbered panels with
//! per-check colors, status tags, hanging-indent wrapping, charts and bars.
//! Remote text is escaped before display so evidence cannot drive the terminal.

use crate::{util, Group, Report, Row};
use clap::ValueEnum;
use serde_json::Value;
use std::cell::Cell;
use std::fmt::Write;
use std::io::{self, IsTerminal};
use textwrap::core::display_width;

#[derive(Clone, Copy, Debug, Default, PartialEq, ValueEnum)]
pub enum Theme {
    #[default]
    Btop,
    Tty,
    Purple,
    Phosphor,
    Amber,
}

/// How a terminal run shows progress.
#[derive(Clone, Copy, Debug, Default, PartialEq, ValueEnum)]
pub enum Animate {
    /// Live panels: skeletons while checks run, streaming ping, bars that grow in
    #[default]
    Full,
    /// One progress line; each panel prints when ready
    Minimal,
    /// No progress output
    Off,
}

type Rgb = (u8, u8, u8);

const fn hex(v: u32) -> Rgb {
    ((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

#[derive(Clone, Copy)]
struct Palette {
    bg: Rgb,
    fg: Rgb,
    dim: Rgb,
    accent: Rgb,
    border: Rgb,
    ok: Rgb,
    warn: Rgb,
    fail: Rgb,
    info: Rgb,
    /// Panel border color per group, in Group::ALL order.
    b: [Rgb; 11],
    /// Panel title color per group.
    t: [Rgb; 11],
}

impl Theme {
    fn name(self) -> &'static str {
        match self {
            Theme::Purple => "purple",
            Theme::Tty => "tty",
            Theme::Btop => "btop",
            Theme::Phosphor => "phosphor",
            Theme::Amber => "amber",
        }
    }

    // Colors are the website's CSS tokens (web/public/style.css).
    fn palette(self) -> Palette {
        match self {
            Theme::Tty => Palette {
                bg: hex(0x0E1012),
                fg: hex(0xC8CCCF),
                dim: hex(0x6B7378),
                accent: hex(0x8FB8D8),
                border: hex(0x2C3236),
                ok: hex(0x93C08A),
                warn: hex(0xD9B36C),
                fail: hex(0xD9787A),
                info: hex(0x8FB8D8),
                b: [
                    0x35505A, 0x4F4A36, 0x3A5052, 0x463F55, 0x3C4F3A, 0x3A4C5A, 0x553A3B, 0x3A4C5A,
                    0x4F4236, 0x4A3D4C, 0x2C3236,
                ]
                .map(hex),
                t: [
                    0x7FC4C4, 0xD9B36C, 0x7FC4C4, 0xB39DDB, 0x93C08A, 0x8FB8D8, 0xD9787A, 0x8FB8D8,
                    0xD9A27A, 0xC99AC2, 0x8FB8D8,
                ]
                .map(hex),
            },
            Theme::Btop => {
                let c = [
                    0x5FD7D7, 0xD7AF5F, 0x5FD7D7, 0xAF87D7, 0x87D75F, 0x5FD7AF, 0xD75F5F, 0x5FAFD7,
                    0xD7875F, 0xD787AF, 0x5FD7FF,
                ]
                .map(hex);
                Palette {
                    bg: hex(0x000000),
                    fg: hex(0xE0E0E0),
                    dim: hex(0x707070),
                    accent: hex(0x5FD7FF),
                    border: hex(0x404040),
                    ok: hex(0x87D75F),
                    warn: hex(0xFFD75F),
                    fail: hex(0xFF5F5F),
                    info: hex(0x5FAFFF),
                    b: c,
                    t: c,
                }
            }
            Theme::Purple => Palette {
                bg: hex(0x07071F),
                fg: hex(0xC9C7D8),
                dim: hex(0x77738F),
                accent: hex(0xD86BFF),
                border: hex(0x3B3157),
                ok: hex(0x55C7FF),
                warn: hex(0xF2B84B),
                fail: hex(0xF05AAC),
                info: hex(0x55C7FF),
                b: [
                    0x5A3F78, 0x80662F, 0x6E3F8F, 0x633D83, 0x356D82, 0x355F8C, 0x7B315F, 0x355F8C,
                    0x7B4F2E, 0x713D75, 0x3B3157,
                ]
                .map(hex),
                t: [
                    0xD86BFF, 0xF2B84B, 0xD86BFF, 0xB98CFF, 0x5FD7D7, 0x55C7FF, 0xF05AAC, 0x55C7FF,
                    0xE8934F, 0xF05AAC, 0xD86BFF,
                ]
                .map(hex),
            },
            Theme::Phosphor => Palette {
                bg: hex(0x040A05),
                fg: hex(0x7CF29A),
                dim: hex(0x3B8A52),
                accent: hex(0xB6FFC8),
                border: hex(0x1D4A2A),
                ok: hex(0x7CF29A),
                warn: hex(0xE8F27C),
                fail: hex(0xFF8A7A),
                info: hex(0xB6FFC8),
                b: [hex(0x1D4A2A); 11],
                t: [hex(0xB6FFC8); 11],
            },
            Theme::Amber => Palette {
                bg: hex(0x0C0802),
                fg: hex(0xFFB847),
                dim: hex(0x9A7028),
                accent: hex(0xFFD58A),
                border: hex(0x4A3510),
                ok: hex(0xFFD58A),
                warn: hex(0xFFB847),
                fail: hex(0xFF7A47),
                info: hex(0xFFD58A),
                b: [hex(0x4A3510); 11],
                t: [hex(0xFFD58A); 11],
            },
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Tone {
    Fg,
    Dim,
    Strong,
    Accent,
    Ok,
    Warn,
    Fail,
    Info,
    Title(usize),
    Border(usize),
    Bar(usize),
    Key,
}

#[derive(Clone)]
struct Span {
    text: String,
    tone: Tone,
}

type Line = Vec<Span>;

/// Escapes control characters so remote evidence cannot change the terminal.
fn clean(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_control() {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

fn sp(text: impl AsRef<str>, tone: Tone) -> Span {
    Span {
        text: clean(text.as_ref()),
        tone,
    }
}

fn width(line: &[Span]) -> usize {
    line.iter().map(|s| display_width(&s.text)).sum()
}

fn pad(text: &str, w: usize) -> String {
    let n = display_width(text);
    if n >= w {
        text.to_string()
    } else {
        format!("{text}{}", " ".repeat(w - n))
    }
}

fn truncate(text: &str, w: usize) -> String {
    if display_width(text) <= w {
        return text.to_string();
    }
    let mut out = String::new();
    for ch in text.chars() {
        if display_width(&out) + display_width(&ch.to_string()) + 1 > w {
            break;
        }
        out.push(ch);
    }
    out.push('…');
    out
}

/// Greedy word wrap across styled spans. Words longer than a line are split.
fn wrap(spans: &[Span], w: usize) -> Vec<Line> {
    let w = w.max(4);
    let mut lines: Vec<Line> = vec![vec![]];
    let mut cur = 0usize;
    for span in spans {
        let mut token = String::new();
        let mut token_space = None;
        let flush = |token: &mut String, space: bool, lines: &mut Vec<Line>, cur: &mut usize| {
            if token.is_empty() {
                return;
            }
            let tw = display_width(token);
            if space {
                if *cur > 0 && *cur + tw <= w {
                    lines.last_mut().unwrap().push(sp(&*token, span.tone));
                    *cur += tw;
                }
            } else {
                if *cur + tw > w && *cur > 0 {
                    // Drop trailing spaces before breaking.
                    let last = lines.last_mut().unwrap();
                    while let Some(s) = last.last_mut() {
                        let trimmed = s.text.trim_end().to_string();
                        if trimmed.is_empty() {
                            last.pop();
                        } else {
                            s.text = trimmed;
                            break;
                        }
                    }
                    lines.push(vec![]);
                    *cur = 0;
                }
                let mut rest = token.as_str();
                while display_width(rest) + *cur > w {
                    let mut take = String::new();
                    for ch in rest.chars() {
                        if *cur + display_width(&take) + display_width(&ch.to_string()) > w {
                            break;
                        }
                        take.push(ch);
                    }
                    if take.is_empty() {
                        lines.push(vec![]);
                        *cur = 0;
                        continue;
                    }
                    rest = &rest[take.len()..];
                    lines.last_mut().unwrap().push(Span {
                        text: take,
                        tone: span.tone,
                    });
                    lines.push(vec![]);
                    *cur = 0;
                }
                if !rest.is_empty() {
                    *cur += display_width(rest);
                    lines.last_mut().unwrap().push(Span {
                        text: rest.to_string(),
                        tone: span.tone,
                    });
                }
            }
            token.clear();
        };
        for ch in span.text.chars() {
            let is_space = ch == ' ';
            if token_space.is_some_and(|s| s != is_space) {
                flush(&mut token, token_space.unwrap(), &mut lines, &mut cur);
            }
            token_space = Some(is_space);
            token.push(ch);
        }
        flush(
            &mut token,
            token_space.unwrap_or(false),
            &mut lines,
            &mut cur,
        );
    }
    if lines.len() > 1 && lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines
}

struct Body {
    inner: usize,
    lines: Vec<Line>,
}

impl Body {
    fn new(inner: usize) -> Self {
        Self {
            inner,
            lines: vec![],
        }
    }
    fn blank(&mut self) {
        if self.lines.last().is_some_and(|l| !l.is_empty()) {
            self.lines.push(vec![]);
        }
    }
    fn text(&mut self, spans: Line) {
        self.lines.extend(wrap(&spans, self.inner));
    }
    /// Fixed-width leading columns, then a value that wraps under itself.
    fn row(&mut self, lead: Line, lead_w: usize, value: Line) {
        self.row_min(lead, lead_w, value, 16, 2)
    }
    /// Like `row`, but stacks the value under `stack_indent` when it would get
    /// fewer than `min_room` columns.
    fn row_min(
        &mut self,
        lead: Line,
        lead_w: usize,
        value: Line,
        min_room: usize,
        stack_indent: usize,
    ) {
        let room = self.inner.saturating_sub(lead_w);
        if room < min_room {
            self.lines.push(lead);
            for l in wrap(&value, self.inner - stack_indent) {
                let mut line = vec![sp(" ".repeat(stack_indent), Tone::Fg)];
                line.extend(l);
                self.lines.push(line);
            }
            return;
        }
        let mut lead = lead;
        let lw = width(&lead);
        if lw < lead_w {
            lead.push(sp(" ".repeat(lead_w - lw), Tone::Fg));
        }
        for (i, l) in wrap(&value, room).into_iter().enumerate() {
            let mut line = if i == 0 {
                lead.clone()
            } else {
                vec![sp(" ".repeat(lead_w), Tone::Fg)]
            };
            line.extend(l);
            self.lines.push(line);
        }
    }
    /// A dim `└ detail` line under a value column.
    fn note(&mut self, indent: usize, text: &str) {
        if text.is_empty() {
            return;
        }
        let indent = if self.inner.saturating_sub(indent) < 16 {
            2
        } else {
            indent
        };
        let room = self.inner - indent - 2;
        for (i, l) in wrap(&[sp(text, Tone::Dim)], room).into_iter().enumerate() {
            let mut line = vec![sp(
                format!("{}{}", " ".repeat(indent), if i == 0 { "└ " } else { "  " }),
                Tone::Dim,
            )];
            line.extend(l);
            self.lines.push(line);
        }
    }
    fn raw(&mut self, line: Line) {
        self.lines.push(line);
    }
}

fn kind_tag(kind: &str) -> (&'static str, Tone) {
    match kind {
        "pass" => (" OK ", Tone::Ok),
        "clean" | "none" => (" -- ", Tone::Dim),
        "open" => ("OPEN", Tone::Ok),
        "found" => ("FOUND", Tone::Ok),
        "possible" => ("MAYBE", Tone::Warn),
        "not_found" => (" -- ", Tone::Dim),
        "warn" => ("WARN", Tone::Warn),
        "timeout" => ("TIME", Tone::Warn),
        "fail" => ("FAIL", Tone::Fail),
        "listed" => ("LIST", Tone::Fail),
        "error" => ("ERR!", Tone::Fail),
        "pending" => ("····", Tone::Dim),
        "closed" => ("SHUT", Tone::Dim),
        "skipped" => ("SKIP", Tone::Dim),
        _ => ("INFO", Tone::Info),
    }
}

fn tag(kind: &str) -> Span {
    let (label, tone) = kind_tag(kind);
    sp(format!("[{label}]"), tone)
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_default()
}

fn fmt_ms(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.2}s", ms / 1000.0)
    } else {
        format!("{}ms", ms.round())
    }
}

const SUPERSCRIPT: [&str; 12] = ["", "¹", "²", "³", "⁴", "⁵", "⁶", "⁷", "⁸", "⁹", "¹⁰", "¹¹"];
const EIGHTHS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
const LEFT_EIGHTHS: [char; 9] = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

fn hbar(ratio: f64, w: usize) -> String {
    let eighths = (ratio.clamp(0.0, 1.0) * (w * 8) as f64).round() as usize;
    let mut s = "█".repeat(eighths / 8);
    if !eighths.is_multiple_of(8) {
        s.push(LEFT_EIGHTHS[eighths % 8]);
    }
    s
}

/// Ease-out cubic: fast start, gentle landing.
fn ease(p: f64) -> f64 {
    let p = p.clamp(0.0, 1.0);
    1.0 - (1.0 - p).powi(3)
}

/// What a running check is doing, shown in its skeleton panel.
fn activity(g: Group) -> &'static str {
    match g {
        Group::Where => "nameservers → DNS host · RDAP → registrar · Team Cymru → network owner",
        Group::Email => "MX · SPF · DMARC · DKIM · MTA-STS · TLS-RPT · BIMI",
        Group::Ping => "resolving target · 10 ICMP echoes",
        Group::Whois => "RDAP bootstrap → registry → registrar",
        Group::Web => "DNS → TCP → TLS → HEAD · following redirects",
        Group::Dns => "querying record types through the resolver",
        Group::Blacklist => "14 DNS blocklists",
        Group::Ip => "PTR · forward confirmation · ASN · BGP prefix · RDAP",
        Group::Ports => "TCP connect to common service ports",
        Group::Propagation => "asking each authoritative nameserver directly",
        Group::Subdomains => "20 common names · randomized wildcard controls",
    }
}

/// One check's state in the live view.
pub enum Slot<'a> {
    /// Still running; `partial` is streamed evidence when the check publishes it.
    Running {
        elapsed_ms: u128,
        partial: Option<Value>,
    },
    /// Finished but waiting for a panel above it.
    Ready(&'a Row),
    /// Finished and animating in; `p` runs from 0 to 1.
    Reveal(&'a Row, f64),
}

pub struct Renderer {
    width: Cell<usize>,
    palette: Option<Palette>,
    theme: Theme,
    background: bool,
    live: bool,
    /// Animation progress for bars and charts (1.0 = final).
    anim: Cell<f64>,
    frame: Cell<usize>,
}

fn term_width() -> usize {
    textwrap::termwidth().saturating_sub(1).max(40)
}

pub fn term_rows() -> usize {
    terminal_size::terminal_size()
        .map(|(_, h)| h.0 as usize)
        .unwrap_or(24)
}

impl Renderer {
    pub fn new(theme: Theme, json: bool, background: bool) -> Self {
        let tty =
            !json && io::stdout().is_terminal() && std::env::var("TERM").as_deref() != Ok("dumb");
        let color = tty && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
        Self {
            width: Cell::new(if tty { term_width() } else { 100 }),
            palette: color.then(|| theme.palette()),
            theme,
            background,
            live: tty,
            anim: Cell::new(1.0),
            frame: Cell::new(0),
        }
    }

    pub fn is_live(&self) -> bool {
        self.live
    }

    /// Re-reads the terminal width; returns the old width when it changed.
    pub fn refresh_width(&self) -> Option<usize> {
        if !self.live {
            return None;
        }
        let (old, new) = (self.width.get(), term_width());
        (old != new).then(|| {
            self.width.set(new);
            old
        })
    }

    pub fn width(&self) -> usize {
        self.width.get()
    }

    fn rgb(&self, tone: Tone) -> Option<(Rgb, bool)> {
        let p = self.palette?;
        Some(match tone {
            Tone::Fg => (p.fg, false),
            Tone::Dim => (p.dim, false),
            Tone::Strong => (p.fg, true),
            Tone::Accent => (p.accent, true),
            Tone::Ok => (p.ok, false),
            Tone::Warn => (p.warn, false),
            Tone::Fail => (p.fail, true),
            Tone::Info => (p.info, false),
            Tone::Title(i) => (p.t[i], true),
            Tone::Border(i) => (if i < 11 { p.b[i] } else { p.border }, false),
            Tone::Bar(i) => (p.t[i], false),
            Tone::Key => (p.accent, true),
        })
    }

    fn paint(&self, out: &mut String, tone: Tone) {
        let (Some(p), Some(((r, g, b), bold))) = (self.palette, self.rgb(tone)) else {
            return;
        };
        let bold = if bold { ";1" } else { "" };
        if self.background || tone == Tone::Key {
            let (br, bgc, bb) = if tone == Tone::Key { p.border } else { p.bg };
            write!(out, "\x1b[0;48;2;{br};{bgc};{bb};38;2;{r};{g};{b}{bold}m").unwrap();
        } else {
            write!(out, "\x1b[0;38;2;{r};{g};{b}{bold}m").unwrap();
        }
    }

    /// Writes one line. On a terminal the rest of the row is erased in the
    /// theme background, so it reaches the right edge without trailing spaces.
    fn emit(&self, out: &mut String, line: &[Span]) {
        for s in line {
            self.paint(out, s.tone);
            out.push_str(&s.text);
        }
        if self.live {
            if self.palette.is_some() && self.background {
                // Pad in the theme background through the terminal's last column
                // (erase-line does not carry the background on every terminal).
                // Every row is then fully overwritten when the live view redraws.
                self.paint(out, Tone::Fg);
                let used = width(line);
                out.push_str(&" ".repeat((self.width() + 1).saturating_sub(used)));
            } else {
                if self.palette.is_some() {
                    out.push_str("\x1b[0m");
                }
                out.push_str("\x1b[K");
            }
        }
        if self.palette.is_some() {
            out.push_str("\x1b[0m");
        }
        out.push('\n');
    }

    fn inner(&self) -> usize {
        self.width() - 4
    }

    fn frame(&self, out: &mut String, gi: usize, title: Line, right: Line, body: Body) {
        let w = self.width();
        let border = Tone::Border(gi);
        let mut top = vec![sp("╭┤", border)];
        let room = w.saturating_sub(width(&right) + 6);
        let mut tw = 0;
        for s in title {
            let sw = display_width(&s.text);
            if tw + sw > room {
                top.push(sp(truncate(&s.text, room.saturating_sub(tw)), s.tone));
                tw = room;
                break;
            }
            tw += sw;
            top.push(s);
        }
        top.push(sp("├", border));
        let fill = w.saturating_sub(tw + width(&right) + 5);
        top.push(sp("─".repeat(fill), border));
        top.extend(right);
        top.push(sp("─╮", border));
        self.emit(out, &top);
        for line in body.lines {
            let mut l = vec![sp("│ ", border)];
            let used = width(&line);
            l.extend(line);
            l.push(sp(" ".repeat(self.inner().saturating_sub(used)), Tone::Fg));
            l.push(sp(" │", border));
            self.emit(out, &l);
        }
        self.emit(out, &[sp(format!("╰{}╯", "─".repeat(w - 2)), border)]);
        self.emit(out, &[]);
    }

    pub fn header(&self, target: &str, groups: &[Group]) -> String {
        let mut out = String::new();
        let left = vec![
            sp("wheredns", Tone::Accent),
            sp(format!(" v{}", env!("CARGO_PKG_VERSION")), Tone::Dim),
            sp("  ", Tone::Fg),
            sp(target, Tone::Strong),
        ];
        let right = vec![
            sp("from:", Tone::Dim),
            sp("this machine", Tone::Fg),
            sp("  store:", Tone::Dim),
            sp("none", Tone::Fg),
            sp("  theme:", Tone::Dim),
            sp(self.theme.name(), Tone::Fg),
        ];
        let gap = self.width().saturating_sub(width(&left) + width(&right));
        let mut line = left.clone();
        if gap >= 2 {
            line.push(sp(" ".repeat(gap), Tone::Fg));
            line.extend(right);
            self.emit(&mut out, &line);
        } else {
            self.emit(&mut out, &left);
        }
        let mut pills: Line = vec![];
        for g in groups {
            pills.push(sp(g.n().to_string(), Tone::Title(g.n() - 1)));
            pills.push(sp(format!(":{}  ", g.label()), Tone::Dim));
        }
        if let Some(last) = pills.last_mut() {
            last.text = last.text.trim_end().to_string();
        }
        for l in wrap(&pills, self.width()) {
            self.emit(&mut out, &l);
        }
        self.emit(&mut out, &[]);
        out
    }

    fn progress_line(&self, states: &[(Group, Option<bool>)], frame: usize) -> Line {
        let done = states.iter().filter(|(_, s)| s.is_some()).count();
        let total = states.len();
        let w = 20;
        let fill = (done * w).checked_div(total).unwrap_or(0);
        let mut line = vec![
            sp(SPINNER[frame % SPINNER.len()].to_string(), Tone::Accent),
            sp(" [", Tone::Dim),
            sp("█".repeat(fill), Tone::Accent),
            sp("░".repeat(w - fill), Tone::Dim),
            sp(format!("] {done}/{total}  "), Tone::Dim),
        ];
        for (g, s) in states {
            let (mark, tone) = match s {
                Some(true) => ("✓".to_string(), Tone::Ok),
                Some(false) => ("✗".to_string(), Tone::Fail),
                None => (
                    SPINNER[(frame + g.n()) % SPINNER.len()].to_string(),
                    Tone::Title(g.n() - 1),
                ),
            };
            line.push(sp(mark, tone));
            line.push(sp(
                format!("{} ", g.label()),
                if s.is_none() { Tone::Fg } else { Tone::Dim },
            ));
        }
        let mut kept = vec![];
        let mut used = 0;
        for s in line {
            let sw = display_width(&s.text);
            if used + sw > self.width() {
                break;
            }
            used += sw;
            kept.push(s);
        }
        kept
    }

    /// The one-line progress display for `--animate minimal` (written to stderr).
    pub fn progress(&self, states: &[(Group, Option<bool>)], frame: usize) -> String {
        let mut out = String::new();
        for s in self.progress_line(states, frame) {
            if let Some(((r, g, b), bold)) = self.rgb(s.tone) {
                write!(
                    out,
                    "\x1b[0;38;2;{r};{g};{b}{}m",
                    if bold { ";1" } else { "" }
                )
                .unwrap();
            }
            out.push_str(&s.text);
        }
        if self.palette.is_some() {
            out.push_str("\x1b[0m");
        }
        out
    }

    /// The live region below the finished panels: the next panels (streaming,
    /// revealing or skeleton) and a status line, at most `max_lines` tall.
    pub fn live(
        &self,
        slots: &[(Group, Slot)],
        states: &[(Group, Option<bool>)],
        frame: usize,
        max_lines: usize,
    ) -> (String, usize) {
        self.frame.set(frame);
        let mut out = String::new();
        let mut lines = 0;
        let status_lines = 1;
        let mut hidden = 0;
        for (i, (g, slot)) in slots.iter().enumerate() {
            let s = match slot {
                Slot::Reveal(row, p) => self.panel_at(row, Some(*g), *p),
                Slot::Ready(row) => self.waiting(*g, row),
                Slot::Running {
                    elapsed_ms,
                    partial,
                } => self.running(*g, *elapsed_ms, partial.as_ref()),
            };
            let n = s.matches('\n').count();
            if lines + n + status_lines + 1 > max_lines {
                // Only the leading panel may be tall; later ones collapse to a count.
                hidden = slots.len() - i;
                break;
            }
            lines += n;
            out.push_str(&s);
        }
        if hidden > 0 {
            self.emit(
                &mut out,
                &[sp(
                    format!(
                        "  + {hidden} more panel{} below",
                        if hidden == 1 { "" } else { "s" }
                    ),
                    Tone::Dim,
                )],
            );
            lines += 1;
        }
        let status = self.progress_line(states, frame);
        self.emit(&mut out, &status);
        lines += 1;
        (out, lines)
    }

    fn title(&self, g: Group, extra: Line) -> Line {
        let gi = g.n() - 1;
        let mut t = vec![
            sp(SUPERSCRIPT[g.n()], Tone::Title(gi)),
            sp(g.label(), Tone::Title(gi)),
        ];
        t.extend(extra);
        t
    }

    fn running(&self, g: Group, elapsed_ms: u128, partial: Option<&Value>) -> String {
        let gi = g.n() - 1;
        let frame = self.frame.get();
        let spin = SPINNER[frame % SPINNER.len()];
        let mut body = Body::new(self.inner());
        let mut extra = vec![sp(format!(" {spin} "), Tone::Title(gi))];
        match partial {
            Some(d) => {
                let sub = self.render(g, d, &mut body);
                extra.push(sp(
                    if sub.is_empty() { "live".into() } else { sub },
                    Tone::Dim,
                ));
            }
            None => {
                extra.push(sp("running", Tone::Dim));
                body.text(vec![sp("▸ ", Tone::Title(gi)), sp(activity(g), Tone::Fg)]);
                body.raw(self.scanner(gi, frame, self.inner()));
            }
        }
        let right = vec![
            sp(" ", Tone::Fg),
            sp(format!("{:.1}s", elapsed_ms as f64 / 1000.0), Tone::Dim),
            sp(" ", Tone::Fg),
        ];
        let mut out = String::new();
        self.frame(&mut out, gi, self.title(g, extra), right, body);
        out
    }

    /// A sweeping comet across the panel, like the site's loading shimmer.
    fn scanner(&self, gi: usize, frame: usize, w: usize) -> Line {
        let comet = 12usize;
        let span = w + comet;
        let head = (frame * 3) % span;
        let mut line = vec![];
        for x in 0..w {
            let d = head as isize - x as isize;
            let (ch, tone) = if (0..comet as isize).contains(&d) {
                let ch = match d {
                    0 => "█",
                    1 | 2 => "▓",
                    3..=5 => "▒",
                    _ => "░",
                };
                (ch, Tone::Bar(gi))
            } else {
                ("─", Tone::Border(gi))
            };
            line.push(sp(ch, tone));
        }
        line
    }

    fn waiting(&self, g: Group, row: &Row) -> String {
        let gi = g.n() - 1;
        let mut body = Body::new(self.inner());
        let (mark, tone) = if row.ok {
            ("✓ ready", Tone::Ok)
        } else {
            ("✗ ready", Tone::Fail)
        };
        body.text(vec![sp(
            "results ready · shown in order once the panels above finish",
            Tone::Dim,
        )]);
        let right = vec![
            sp(" ", Tone::Fg),
            sp(fmt_ms(row.elapsed_ms as f64), Tone::Dim),
            sp(" ", Tone::Fg),
        ];
        let mut out = String::new();
        self.frame(
            &mut out,
            gi,
            self.title(g, vec![sp(format!(" {mark}"), tone)]),
            right,
            body,
        );
        out
    }

    pub fn panel(&self, row: &Row, group: Option<Group>) -> String {
        self.panel_at(row, group, 1.0)
    }

    /// A finished panel part-way through its entrance: rows appear top-down and
    /// bars and charts grow to their measured size.
    pub fn panel_at(&self, row: &Row, group: Option<Group>, p: f64) -> String {
        self.anim.set(ease(p));
        let mut out = String::new();
        let inner = self.inner();
        let mut body = Body::new(inner);
        let gi = group.map_or(11, |g| g.n() - 1);
        let d = &row.data;
        let sub = match group {
            Some(g) if !d.is_null() => self.render(g, d, &mut body),
            _ => String::new(),
        };
        self.anim.set(1.0);
        if let Some(err) = &row.error {
            let show = d.is_null()
                || matches!(
                    group,
                    Some(Group::Web | Group::Ping | Group::Propagation | Group::Ip | Group::Where)
                );
            if show {
                body.blank();
                body.row(vec![tag("error")], 7, vec![sp(err, Tone::Fail)]);
            }
        }
        if body.lines.is_empty() {
            body.text(vec![sp("no evidence returned", Tone::Dim)]);
        }
        if p < 1.0 {
            let n = body.lines.len() as f64 * ease((p * 1.6).min(1.0));
            body.lines.truncate((n.ceil() as usize).max(1));
        }
        let mut title = vec![];
        if let Some(g) = group {
            title.push(sp(SUPERSCRIPT[g.n()], Tone::Title(gi)));
            title.push(sp(g.label(), Tone::Title(gi)));
        } else {
            title.push(sp(&row.check, Tone::Accent));
        }
        if !sub.is_empty() {
            title.push(sp(format!(" {sub}"), Tone::Dim));
        }
        let mut right = vec![sp(" ", Tone::Fg)];
        if !row.ok {
            right.push(sp("✗ ", Tone::Fail));
        }
        right.push(sp(fmt_ms(row.elapsed_ms as f64), Tone::Dim));
        right.push(sp(" ", Tone::Fg));
        self.frame(&mut out, gi, title, right, body);
        out
    }

    pub fn footer(&self, report: &Report) -> String {
        let mut out = String::new();
        let total = report.results.iter().filter(|r| r.check != "run").count();
        let ok = report.results.iter().filter(|r| r.ok).count();
        let (mark, tone) = if !report.complete {
            ("■", Tone::Warn)
        } else if ok == total {
            ("✓", Tone::Ok)
        } else {
            ("✗", Tone::Fail)
        };
        let mut line = vec![
            sp(format!("{mark} "), tone),
            sp(format!("{ok}/{total} checks ok"), tone),
            sp(
                format!("  ·  {}", fmt_ms(report.elapsed_ms as f64)),
                Tone::Dim,
            ),
        ];
        if !report.complete {
            line.push(sp("  ·  incomplete", Tone::Warn));
        }
        line.push(sp(
            "  ·  checks ran from this machine · results are not stored",
            Tone::Dim,
        ));
        for l in wrap(&line, self.width()) {
            self.emit(&mut out, &l);
        }
        let keys: Line = [
            ("--json", "for scripts"),
            ("--theme", "btop tty purple phosphor amber"),
            ("wheredns config", "save defaults"),
            ("--help", "every check"),
        ]
        .iter()
        .flat_map(|(k, v)| [sp(*k, Tone::Key), sp(format!(" {v}   "), Tone::Dim)])
        .collect();
        for l in wrap(&keys, self.width()) {
            self.emit(&mut out, &l);
        }
        out
    }

    pub fn headers(&self, v: &Value) -> String {
        let mut out = String::new();
        let mut body = Body::new(self.inner());
        let a = &v["analysis"];
        for (k, key) in [
            ("from", "from"),
            ("to", "to"),
            ("subject", "subject"),
            ("date", "date"),
            ("message-id", "message_id"),
            ("return-path", "return_path"),
        ] {
            if let Some(val) = a[key].as_str() {
                body.row(vec![sp(k, Tone::Dim)], 14, vec![sp(val, Tone::Fg)]);
            }
        }
        if let Some(auth) = a["auth"].as_array().filter(|x| !x.is_empty()) {
            body.blank();
            for x in auth {
                let result = str_of(x, "result");
                let kind = match result {
                    "pass" => "pass",
                    "fail" | "permerror" => "fail",
                    "softfail" | "neutral" | "temperror" | "policy" => "warn",
                    "none" => "none",
                    _ => "info",
                };
                body.row(
                    vec![
                        tag(kind),
                        sp(" ", Tone::Fg),
                        sp(str_of(x, "method").to_uppercase(), Tone::Strong),
                    ],
                    16,
                    vec![
                        sp(result, Tone::Fg),
                        sp(format!("  {}", str_of(x, "detail")), Tone::Dim),
                    ],
                );
            }
            body.note(
                0,
                "authentication results are claims made by receiving servers; untrusted",
            );
        }
        if let Some(hops) = a["hops"].as_array().filter(|x| !x.is_empty()) {
            body.blank();
            body.raw(vec![sp(
                format!("{} hops, oldest first", hops.len()),
                Tone::Title(0),
            )]);
            for (i, h) in hops.iter().enumerate() {
                let delay = h["delay_s"]
                    .as_i64()
                    .map(|s| format!("+{s}s"))
                    .unwrap_or_default();
                let delay_tone = match h["delay_s"].as_i64() {
                    Some(s) if s >= 300 => Tone::Fail,
                    Some(s) if s >= 60 => Tone::Warn,
                    _ => Tone::Dim,
                };
                let mut value = vec![];
                if let Some(from) = h["from"].as_str() {
                    value.push(sp(from, Tone::Fg));
                    value.push(sp(" → ", Tone::Dim));
                }
                value.push(sp(h["by"].as_str().unwrap_or("?"), Tone::Strong));
                if let Some(w) = h["with"].as_str() {
                    value.push(sp(format!("  {w}"), Tone::Dim));
                }
                body.row(
                    vec![
                        sp(format!("{:>2}.", i + 1), Tone::Dim),
                        sp(format!("{delay:>7} "), delay_tone),
                    ],
                    12,
                    value,
                );
                body.note(12, str_of(h, "date"));
            }
            if let Some(t) = a["total_delay_s"].as_i64() {
                body.note(0, &format!("total transit {t}s"));
            }
        }
        let skip = [
            "received",
            "dkim-signature",
            "authentication-results",
            "x-received",
            "from",
            "to",
            "subject",
            "date",
            "message-id",
            "return-path",
            "received-spf",
        ];
        let others: Vec<&Value> = v["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| {
                let n = str_of(f, "name");
                !skip.contains(&n) && !n.starts_with("arc-")
            })
            .collect();
        if !others.is_empty() {
            body.blank();
            body.raw(vec![sp(
                format!("{} other fields", others.len()),
                Tone::Title(0),
            )]);
            for f in others {
                let val: String = str_of(f, "value").chars().take(300).collect();
                body.row(
                    vec![sp(str_of(f, "name"), Tone::Dim)],
                    26,
                    vec![sp(val, Tone::Fg)],
                );
            }
        }
        if v["fields"].as_array().is_some_and(|f| f.is_empty()) {
            body.text(vec![sp("no header fields found", Tone::Dim)]);
        }
        if let Some(n) = v["malformed_lines"].as_u64().filter(|n| *n > 0) {
            body.note(0, &format!("{n} malformed line(s) ignored"));
        }
        body.note(0, "parsed locally; the header never leaves this machine");
        self.frame(
            &mut out,
            0,
            vec![
                sp("headers", Tone::Title(0)),
                sp(" email header trace", Tone::Dim),
            ],
            vec![sp(" ", Tone::Fg)],
            body,
        );
        out.truncate(out.trim_end_matches('\n').len());
        // Drop the trailing blank padding line in plain mode for tidy pipes.
        out
    }

    /// Fills `body` for one check; returns the title's subtitle.
    fn render(&self, g: Group, d: &Value, body: &mut Body) -> String {
        let gi = g.n() - 1;
        match g {
            Group::Where => self.where_(d, body),
            Group::Email => {
                let findings = d["findings"].as_array().cloned().unwrap_or_default();
                for f in &findings {
                    body.row(
                        vec![
                            tag(str_of(f, "kind")),
                            sp(" ", Tone::Fg),
                            sp(str_of(f, "name"), Tone::Strong),
                        ],
                        16,
                        vec![sp(str_of(f, "value"), Tone::Fg)],
                    );
                    body.note(16, str_of(f, "note"));
                }
                let pass = findings.iter().filter(|f| f["kind"] == "pass").count();
                format!("{pass}/{} pass", findings.len())
            }
            Group::Ping => self.ping(d, body, gi),
            Group::Whois => self.whois(d, body),
            Group::Web => self.web(d, body, gi),
            Group::Dns => self.dns(d, body, gi),
            Group::Blacklist => self.blacklist(d, body),
            Group::Ip => {
                for r in d["rows"].as_array().into_iter().flatten() {
                    body.row(
                        vec![
                            tag(str_of(r, "kind")),
                            sp(format!(" {}", str_of(r, "k")), Tone::Dim),
                        ],
                        19,
                        vec![sp(str_of(r, "v"), Tone::Fg)],
                    );
                    if r["kind"] != "pass" {
                        body.note(19, str_of(r, "note"));
                    }
                }
                if d["ptr_confirmed"] == true {
                    body.note(
                        0,
                        "ptr: forward-confirmed (hostname resolves back to this ip)",
                    );
                }
                match d["from"].as_str() {
                    Some(f) => format!("{} ← {f}", str_of(d, "ip")),
                    None => str_of(d, "ip").into(),
                }
            }
            Group::Ports => self.ports(d, body, gi),
            Group::Propagation => self.propagation(d, body),
            Group::Subdomains => self.subdomains(d, body),
        }
    }

    fn where_(&self, d: &Value, body: &mut Body) -> String {
        let dns = &d["dns"];
        let reg = &d["registration"];
        let infra = &d["infrastructure"];
        let kind = |status: &str| match status {
            "found" => "pass",
            "not_found" => "warn",
            _ => "error",
        };
        let providers: Vec<String> = dns["providers"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|p| {
                if p["basis"] == "recognized" {
                    str_of(p, "name").to_string()
                } else {
                    format!("{} (provider unconfirmed)", str_of(p, "name"))
                }
            })
            .collect();
        let lead = |k: &str, label: &str| vec![tag(k), sp(format!(" {label}"), Tone::Dim)];
        let stacked = body.inner < 29 + 44;
        let w = if stacked { 7 } else { 29 };
        let row = |body: &mut Body, l: Line, v: Line| {
            if stacked {
                body.row_min(l, 99, v, usize::MAX, 7)
            } else {
                body.row(l, 29, v)
            }
        };
        row(
            body,
            lead(kind(str_of(dns, "status")), "DNS hosted by"),
            vec![sp(
                if providers.is_empty() {
                    str_of(dns, "detail").to_string()
                } else {
                    providers.join(" + ")
                },
                if providers.is_empty() {
                    Tone::Dim
                } else {
                    Tone::Strong
                },
            )],
        );
        if let Some(ns) = dns["nameservers"].as_array().filter(|n| !n.is_empty()) {
            let names: Vec<&str> = ns.iter().filter_map(Value::as_str).collect();
            body.note(
                w,
                &format!(
                    "zone: {} · nameservers: {}",
                    str_of(dns, "zone"),
                    names.join(" · ")
                ),
            );
        }
        row(
            body,
            lead(kind(str_of(reg, "status")), "Domain registered at"),
            vec![sp(str_of(reg, "registrar"), Tone::Strong)],
        );
        let detail: Vec<&str> = ["registered_domain", "registrant_country", "source"]
            .iter()
            .filter_map(|k| reg[*k].as_str())
            .collect();
        body.note(w, &detail.join(" · "));
        body.note(w, str_of(reg, "detail"));
        let found = infra["status"] == "found";
        row(
            body,
            lead(if found { "info" } else { "none" }, "IP network"),
            vec![sp(
                if found {
                    str_of(infra, "provider")
                } else {
                    "unavailable"
                },
                if found { Tone::Strong } else { Tone::Dim },
            )],
        );
        if found {
            body.note(
                w,
                &format!(
                    "{} · {} · network registration / probable operator; not proof of hosting or CDN",
                    str_of(infra, "ip"),
                    str_of(infra, "source")
                ),
            );
        } else {
            body.note(w, str_of(infra, "detail"));
        }
        str_of(d, "domain").to_string()
    }

    fn ping(&self, d: &Value, body: &mut Body, gi: usize) -> String {
        let live = d["live"] == true;
        let sent = d["sent"].as_u64().unwrap_or(10).max(1) as usize;
        let mut samples: Vec<Option<f64>> = d["samples"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|s| s["ms"].as_f64())
            .collect();
        let arrived = samples.len();
        let got: Vec<f64> = samples.iter().flatten().copied().collect();
        if live {
            samples.resize(sent, None);
        }
        let max = got.iter().copied().fold(0.0, f64::max);
        let ceiling = [25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
            .into_iter()
            .find(|c| *c >= max)
            .unwrap_or((max / 500.0).ceil() * 500.0);
        let label = |v: f64| {
            if v.fract() == 0.0 {
                format!("{v} ms")
            } else {
                format!("{v:.1} ms")
            }
        };
        let rows = 5usize;
        let axis_w = 9;
        // Slots widen with the panel so the chart spans it.
        let slot = ((body.inner.saturating_sub(axis_w + 2)) / samples.len().max(1)).clamp(3, 8);
        let bar = (slot * 2 / 3).clamp(1, 5);
        let grow = self.anim.get();
        let blink = (self.frame.get() / 3).is_multiple_of(2);
        if !got.is_empty() || live {
            for r in (0..rows).rev() {
                let axis = if r == rows - 1 {
                    label(ceiling)
                } else if r == rows / 2 {
                    label(ceiling / 2.0)
                } else if r == 0 {
                    "0 ms".into()
                } else {
                    String::new()
                };
                let tick = if axis.is_empty() { "│" } else { "┤" };
                let mut line = vec![sp(format!("{axis:>7} {tick}"), Tone::Dim)];
                for (i, s) in samples.iter().enumerate() {
                    let pending = live && i >= arrived;
                    let (cell, tone) = match s {
                        Some(ms) => {
                            let level = ((ms / ceiling) * grow * (rows * 8) as f64).round().max(1.0)
                                as usize;
                            let fill = level.saturating_sub(r * 8).min(8);
                            (EIGHTHS[fill].to_string().repeat(bar), Tone::Bar(gi))
                        }
                        None if pending && i == arrived && r == 0 => {
                            (if blink { "▁" } else { " " }.repeat(bar), Tone::Accent)
                        }
                        None if pending => (" ".repeat(bar), Tone::Fg),
                        None if r == 0 => ("✗".repeat(bar), Tone::Fail),
                        None => (" ".repeat(bar), Tone::Fg),
                    };
                    let lpad = (slot - bar) / 2;
                    line.push(sp(" ".repeat(lpad), Tone::Fg));
                    line.push(sp(cell, tone));
                    line.push(sp(" ".repeat(slot - bar - lpad), Tone::Fg));
                }
                body.raw(line);
            }
            let mut seq = vec![sp(" ".repeat(axis_w), Tone::Fg)];
            for i in 1..=samples.len() {
                let lpad = (slot - bar) / 2;
                seq.push(sp(
                    format!("{}{:<w$}", " ".repeat(lpad), i, w = slot - lpad),
                    Tone::Dim,
                ));
            }
            body.raw(seq);
            body.blank();
            let stat = |k: &str| sp(format!("{k:<9}"), Tone::Dim);
            body.raw(vec![
                sp(" ".repeat(axis_w), Tone::Fg),
                stat("recv"),
                stat("min"),
                stat("avg"),
                stat("max"),
            ]);
            let num = |v: Option<f64>| v.map_or("-".to_string(), |v| format!("{v:.1}"));
            let mn = got.iter().copied().reduce(f64::min);
            let avg = (!got.is_empty()).then(|| got.iter().sum::<f64>() / got.len() as f64);
            let lost = got.len() < arrived;
            body.raw(vec![
                sp(" ".repeat(axis_w), Tone::Fg),
                sp(
                    format!(
                        "{:<9}",
                        format!("{}/{}", got.len(), if live { arrived } else { sent })
                    ),
                    if lost { Tone::Warn } else { Tone::Strong },
                ),
                sp(format!("{:<9}", num(mn)), Tone::Fg),
                sp(format!("{:<9}", num(avg)), Tone::Accent),
                sp(
                    format!("{:<9}", num((!got.is_empty()).then_some(max))),
                    Tone::Fg,
                ),
            ]);
        }
        let loss = (100 * (arrived - got.len()))
            .checked_div(arrived)
            .unwrap_or(0);
        let target = match d["from"].as_str() {
            Some(f) => format!("{} ({f})", str_of(d, "ip")),
            None => str_of(d, "ip").to_string(),
        };
        body.note(
            0,
            &format!(
                "ms · loss {loss}% · target {target} · no reply does not mean the host is down"
            ),
        );
        if live {
            format!("icmp echo {arrived}/{sent}")
        } else {
            "icmp echo ×10".into()
        }
    }

    fn whois(&self, d: &Value, body: &mut Body) -> String {
        let kw = 20;
        let kv = |body: &mut Body, k: &str, v: Line| {
            if v.iter().any(|s| !s.text.is_empty()) {
                body.row(vec![sp(k, Tone::Dim)], kw, v);
            }
        };
        let f = |k: &str| sp(str_of(d, k), Tone::Fg);
        if d["kind"] == "ip" {
            kv(body, "network", vec![sp(str_of(d, "name"), Tone::Strong)]);
            kv(body, "handle", vec![f("handle")]);
            kv(body, "range", vec![f("range")]);
            let cidrs: Vec<&str> = d["cidrs"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            kv(body, "cidr", vec![sp(cidrs.join(", "), Tone::Fg)]);
            kv(body, "type", vec![f("type")]);
            kv(body, "holder", vec![sp(str_of(d, "holder"), Tone::Strong)]);
            kv(body, "country", vec![f("country")]);
            kv(body, "abuse", vec![f("abuse")]);
            kv(body, "registered", vec![f("registered")]);
            kv(body, "updated", vec![f("updated")]);
            return str_of(d, "source").into();
        }
        kv(body, "domain", vec![sp(str_of(d, "domain"), Tone::Strong)]);
        let mut registrar = vec![sp(str_of(d, "registrar"), Tone::Strong)];
        if let Some(id) = d["iana_id"].as_str() {
            registrar.push(sp(format!(" (IANA {id})"), Tone::Dim));
        }
        kv(body, "registrar", registrar);
        kv(body, "created", vec![f("created")]);
        if let Some(exp) = d["expires"].as_str() {
            let mut v = vec![sp(exp, Tone::Fg)];
            if let Some(ts) = util::parse_iso_date(exp) {
                let days = (ts - util::now_unix()).div_euclid(86400);
                let (text, tone) = if days < 0 {
                    ("expired".to_string(), Tone::Fail)
                } else if days < 60 {
                    (
                        format!("in {days} days"),
                        if days < 30 { Tone::Fail } else { Tone::Warn },
                    )
                } else {
                    (format!("in {:.1} yr", days as f64 / 365.0), Tone::Dim)
                };
                if tone != Tone::Dim {
                    v[0].tone = tone;
                }
                v.push(sp(format!(" ({text})"), tone));
            }
            kv(body, "expires", v);
        }
        kv(body, "updated", vec![f("updated")]);
        kv(
            body,
            "registrant",
            vec![sp(
                d["registrant"].as_str().unwrap_or("not published"),
                Tone::Fg,
            )],
        );
        kv(body, "registrant country", vec![f("registrant_country")]);
        let ns: Vec<&str> = d["nameservers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        kv(body, "nameservers", vec![sp(ns.join(" "), Tone::Fg)]);
        match d["dnssec"].as_bool() {
            Some(true) => kv(body, "dnssec", vec![sp("signed", Tone::Ok)]),
            Some(false) => kv(body, "dnssec", vec![sp("unsigned", Tone::Dim)]),
            None => {}
        }
        let status: Vec<&str> = d["status"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        kv(body, "status", vec![sp(status.join(", "), Tone::Fg)]);
        kv(body, "abuse", vec![f("abuse")]);
        str_of(d, "source").into()
    }

    fn web(&self, d: &Value, body: &mut Body, gi: usize) -> String {
        let hops = d["hops"].as_array().cloned().unwrap_or_default();
        for (i, h) in hops.iter().enumerate() {
            let status = h["status"].as_u64().unwrap_or(0);
            let tone = match status {
                200..=299 => Tone::Ok,
                300..=399 => Tone::Info,
                _ => Tone::Fail,
            };
            let mut value = vec![sp(str_of(h, "url"), Tone::Fg)];
            if let Some(loc) = h["location"].as_str() {
                value.push(sp(format!(" → {loc}"), Tone::Dim));
            }
            if let Some(ms) = h["timings"]["total_ms"].as_f64() {
                value.push(sp(format!("  {}", fmt_ms(ms)), Tone::Dim));
            }
            body.row(
                vec![
                    sp(format!("{}.", i + 1), Tone::Dim),
                    sp(format!(" {status:<4}"), tone),
                ],
                8,
                value,
            );
        }
        if let Some(last) = hops.last() {
            let mut facts = vec![
                sp("server ", Tone::Dim),
                sp(last["server"].as_str().unwrap_or("-"), Tone::Fg),
                sp("   type ", Tone::Dim),
                sp(last["content_type"].as_str().unwrap_or("-"), Tone::Fg),
            ];
            if let Some(up) = d["http_upgrade"].as_bool() {
                facts.push(sp("   http→https ", Tone::Dim));
                facts.push(if up {
                    sp("yes", Tone::Ok)
                } else {
                    sp("no", Tone::Warn)
                });
            }
            facts.push(sp("   hsts ", Tone::Dim));
            facts.push(if d["hsts"] == true {
                sp("yes", Tone::Ok)
            } else {
                sp("no", Tone::Dim)
            });
            body.blank();
            body.text(facts);
        }
        let t = &d["timings"];
        if let Some(total) = t["total_ms"].as_f64().filter(|v| *v > 0.0) {
            body.blank();
            let bar_w = body.inner.saturating_sub(22).min(96);
            let grow = self.anim.get();
            for (label, key) in [
                ("DNS", "dns_ms"),
                ("TCP", "tcp_ms"),
                ("TLS", "tls_ms"),
                ("response", "response_ms"),
                ("total", "total_ms"),
            ] {
                let Some(v) = t[key].as_f64() else { continue };
                let tone = if key == "total_ms" {
                    Tone::Accent
                } else {
                    Tone::Bar(gi)
                };
                body.raw(vec![
                    sp(
                        format!("{label:<9}"),
                        if key == "total_ms" {
                            Tone::Strong
                        } else {
                            Tone::Dim
                        },
                    ),
                    sp(format!("{v:>8.1} ms  "), Tone::Fg),
                    sp(hbar(v / total * grow, bar_w), tone),
                ]);
            }
            body.note(0, "measured from this machine · response = request sent → headers received · body not downloaded");
        }
        let tls = hops
            .iter()
            .rev()
            .find_map(|h| h["tls"].as_object().map(|_| &h["tls"]));
        if let Some(c) = tls {
            body.blank();
            let kw = 13;
            body.row(
                vec![sp("TLS trust", Tone::Dim)],
                kw,
                vec![sp("chain and hostname verified", Tone::Ok)],
            );
            for (k, key) in [
                ("subject", "subject"),
                ("issuer", "issuer"),
                ("valid from", "valid_from"),
            ] {
                if let Some(v) = c[key].as_str() {
                    body.row(vec![sp(k, Tone::Dim)], kw, vec![sp(v, Tone::Fg)]);
                }
            }
            if let Some(v) = c["valid_to"].as_str() {
                let days = c["days_left"].as_i64().unwrap_or(999);
                let tone = if days < 14 {
                    Tone::Fail
                } else if days < 30 {
                    Tone::Warn
                } else {
                    Tone::Dim
                };
                body.row(
                    vec![sp("expires", Tone::Dim)],
                    kw,
                    vec![
                        sp(v, if tone == Tone::Dim { Tone::Fg } else { tone }),
                        sp(format!(" (in {days} days)"), tone),
                    ],
                );
            }
            if let Some(sans) = c["sans"].as_array().filter(|s| !s.is_empty()) {
                let names: Vec<&str> = sans.iter().filter_map(Value::as_str).take(6).collect();
                let more = if sans.len() > 6 {
                    format!(" +{} more", sans.len() - 6)
                } else {
                    String::new()
                };
                body.row(
                    vec![sp("names", Tone::Dim)],
                    kw,
                    vec![sp(names.join(" "), Tone::Fg), sp(more, Tone::Dim)],
                );
            }
            if let Some(v) = c["protocol"].as_str() {
                body.row(vec![sp("protocol", Tone::Dim)], kw, vec![sp(v, Tone::Fg)]);
            }
            if let Some(v) = c["fingerprint256"].as_str() {
                // 32 bytes as two 16-byte halves so wrapping never splits a byte.
                let v = if v.len() == 95 && display_width(v) > body.inner.saturating_sub(kw) {
                    format!("{} {}", &v[..47], &v[48..])
                } else {
                    v.to_string()
                };
                body.row(vec![sp("SHA-256", Tone::Dim)], kw, vec![sp(v, Tone::Dim)]);
            }
        }
        match d["final"]["status"].as_u64() {
            Some(s) => {
                let r = hops.len().saturating_sub(1);
                format!(
                    "{s} · {r} redirect{} · {}",
                    if r == 1 { "" } else { "s" },
                    fmt_ms(t["total_ms"].as_f64().unwrap_or_default())
                )
            }
            None => "no response".into(),
        }
    }

    fn dns(&self, d: &Value, body: &mut Body, gi: usize) -> String {
        let name = str_of(d, "name");
        if d["nxdomain"] == true {
            body.row(
                vec![tag("fail")],
                7,
                vec![sp(format!("{name} does not exist (NXDOMAIN)"), Tone::Fail)],
            );
            return str_of(d, "resolver").into();
        }
        let lead_w = 16;
        body.raw(vec![
            sp(format!("{:<7}{:>7}  ", "TYPE", "TTL"), Tone::Dim),
            sp("VALUE", Tone::Dim),
        ]);
        let canon = |s: &str| s.trim_end_matches('.').to_ascii_lowercase();
        for q in d["queries"].as_array().into_iter().flatten() {
            let ty = str_of(q, "rr_type");
            let owner = canon(str_of(q, "name"));
            let at = if owner != canon(name) {
                format!(" @ {owner}")
            } else {
                String::new()
            };
            let lead = |ttl: String| {
                vec![
                    sp(format!("{ty:<7}"), Tone::Title(gi)),
                    sp(format!("{ttl:>7}  "), Tone::Dim),
                ]
            };
            match str_of(q, "kind") {
                "answered" => {
                    let records: Vec<&Value> = q["records"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|r| r["rr_type"] == ty)
                        .collect();
                    if records.is_empty() {
                        body.row(
                            lead("-".into()),
                            lead_w,
                            vec![sp("-- no record", Tone::Dim), sp(at.clone(), Tone::Dim)],
                        );
                    }
                    for r in records {
                        let mut v = str_of(r, "value").to_string();
                        if ty != "TXT" {
                            v = v.trim_end_matches('.').to_string();
                        }
                        if display_width(&v) > 240 {
                            v = truncate(&v, 240);
                        }
                        let rowner = canon(str_of(r, "name"));
                        let suffix = if rowner != canon(name) {
                            format!(" @ {rowner}")
                        } else {
                            String::new()
                        };
                        body.row(
                            lead(r["ttl"].to_string()),
                            lead_w,
                            vec![sp(v, Tone::Fg), sp(suffix, Tone::Dim)],
                        );
                    }
                    if let Some(chain) = q["chain"].as_array().filter(|c| !c.is_empty()) {
                        let c: Vec<&str> = chain.iter().filter_map(Value::as_str).collect();
                        body.row(
                            lead(String::new()),
                            lead_w,
                            vec![sp(format!("via CNAME {}", c.join(" → ")), Tone::Dim)],
                        );
                    }
                }
                "nodata" => body.row(
                    lead("-".into()),
                    lead_w,
                    vec![sp("-- no record", Tone::Dim), sp(at, Tone::Dim)],
                ),
                "nxdomain" => body.row(
                    lead("-".into()),
                    lead_w,
                    vec![
                        sp("-- no such name (NXDOMAIN)", Tone::Dim),
                        sp(at, Tone::Dim),
                    ],
                ),
                _ => body.row(
                    lead(String::new()),
                    lead_w,
                    vec![sp(
                        format!("lookup failed: {}", str_of(q, "error")),
                        Tone::Fail,
                    )],
                ),
            }
        }
        body.blank();
        if d["dnssec_validated"] == true {
            body.text(vec![sp(
                "dnssec: resolver authenticated at least one response (AD)",
                Tone::Ok,
            )]);
        } else {
            body.text(vec![sp(
                "dnssec: no authenticated response observed (unsigned or no AD flag)",
                Tone::Dim,
            )]);
        }
        body.text(vec![sp(str_of(d, "coverage"), Tone::Dim)]);
        str_of(d, "resolver").into()
    }

    fn blacklist(&self, d: &Value, body: &mut Body) -> String {
        let rows = d["rows"].as_array().cloned().unwrap_or_default();
        let targets: Vec<&str> = d["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        body.text(vec![
            sp("ip  ", Tone::Dim),
            sp(targets.join("  ·  "), Tone::Strong),
        ]);
        let cells: Line = rows
            .iter()
            .map(|r| match str_of(r, "kind") {
                "pending" => sp("□ ", Tone::Dim),
                k => sp("■ ", kind_tag(k).1),
            })
            .collect();
        body.text(cells);
        let listed = d["listed"].as_u64().unwrap_or(0);
        body.text(vec![
            sp(
                format!("{listed} listed"),
                if listed > 0 { Tone::Fail } else { Tone::Ok },
            ),
            sp(
                format!(" / {} answered / {} queried", d["answered"], d["total"]),
                Tone::Dim,
            ),
        ]);
        body.blank();
        let cell_w = 26;
        let cols = (body.inner / cell_w).clamp(1, 4);
        let multi_ip = targets.len() > 1;
        for chunk in rows.chunks(cols) {
            let mut line = vec![];
            for r in chunk {
                let name = if multi_ip {
                    format!(
                        "{} {}",
                        str_of(r, "name"),
                        str_of(r, "ip")
                            .rsplit('.')
                            .next()
                            .map(|o| format!("·{o}"))
                            .unwrap_or_default()
                    )
                } else {
                    str_of(r, "name").to_string()
                };
                line.push(tag(str_of(r, "kind")));
                line.push(sp(
                    format!(" {}", pad(&truncate(&name, cell_w - 8), cell_w - 7)),
                    Tone::Fg,
                ));
            }
            body.raw(line);
        }
        for r in rows
            .iter()
            .filter(|r| !matches!(str_of(r, "kind"), "clean" | "pending"))
        {
            body.note(
                0,
                &format!(
                    "{}{} ({}): {}",
                    str_of(r, "name"),
                    if multi_ip {
                        format!(" for {}", str_of(r, "ip"))
                    } else {
                        String::new()
                    },
                    str_of(r, "zone"),
                    str_of(r, "detail")
                ),
            );
        }
        body.blank();
        body.text(vec![sp("-- means no listing returned by that list; it does not prove deliverability. Errors mean unavailable.", Tone::Dim)]);
        for s in d["skipped"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            body.text(vec![sp(format!("skipped: {s}"), Tone::Dim)]);
        }
        format!("{listed} listed")
    }

    fn ports(&self, d: &Value, body: &mut Body, gi: usize) -> String {
        let rows = d["rows"].as_array().cloned().unwrap_or_default();
        let cell_w = 38;
        let cols = (body.inner / cell_w).clamp(1, 4);
        for chunk in rows.chunks(cols) {
            let mut line = vec![];
            for r in chunk {
                let detail = match r["ms"].as_f64() {
                    Some(ms) => fmt_ms(ms),
                    None => match str_of(r, "kind") {
                        "closed" => "refused".into(),
                        "timeout" => "no answer".into(),
                        "pending" => "probing".into(),
                        _ => "unavailable".into(),
                    },
                };
                line.push(sp(
                    format!("{:<6}", r["port"].as_u64().unwrap_or_default()),
                    Tone::Title(gi),
                ));
                line.push(sp(format!("{:<11}", str_of(r, "svc")), Tone::Fg));
                line.push(tag(str_of(r, "kind")));
                line.push(sp(format!(" {:<13}", detail), Tone::Dim));
            }
            body.raw(line);
        }
        body.note(
            0,
            "TCP connect only from this machine; nothing is sent after the handshake",
        );
        let open = rows.iter().filter(|r| r["kind"] == "open").count();
        format!("{} · {open} open", str_of(d, "ip"))
    }

    fn propagation(&self, d: &Value, body: &mut Body) -> String {
        let name = str_of(d, "name");
        let server_w = (body.inner / 3).clamp(14, 30);
        let lead_w = 7 + server_w;
        let header_answer_w = d["servers"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| {
                r["answers"].as_array().map_or(1, |a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                        .len()
                        .max(1)
                })
            })
            .max()
            .unwrap_or(1)
            .max(display_width(name) + 2)
            .min(body.inner.saturating_sub(lead_w + 14));
        body.raw(vec![
            sp(format!("{:<7}{:<server_w$}", "", "NAMESERVER"), Tone::Dim),
            sp(pad(&format!("A {name}"), header_answer_w), Tone::Dim),
            sp("  SOA SERIAL", Tone::Dim),
        ]);
        let joined = |r: &Value| {
            let a: Vec<&str> = r["answers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if a.is_empty() {
                "-".to_string()
            } else {
                a.join(" ")
            }
        };
        let servers: Vec<&Value> = d["servers"].as_array().into_iter().flatten().collect();
        let answer_w = servers
            .iter()
            .map(|r| display_width(&joined(r)))
            .max()
            .unwrap_or(1)
            .max(display_width(name) + 2)
            .min(body.inner.saturating_sub(lead_w + 14));
        for r in servers {
            let mut value = vec![sp(pad(&joined(r), answer_w), Tone::Fg)];
            if let Some(s) = r["serial"].as_u64() {
                value.push(sp(format!("  {s}"), Tone::Dim));
            }
            body.row(
                vec![
                    tag(str_of(r, "kind")),
                    sp(
                        format!(
                            " {}",
                            pad(&truncate(str_of(r, "server"), server_w - 2), server_w - 1)
                        ),
                        Tone::Strong,
                    ),
                ],
                lead_w,
                value,
            );
            body.note(7, str_of(r, "detail"));
        }
        body.blank();
        let checked = d["checked"].as_u64().unwrap_or(0);
        let summary = if checked == 0 {
            vec![sp("no nameserver answered", Tone::Fail)]
        } else if d["agree"] == true {
            let mut s = vec![sp(format!("all {checked} nameservers agree"), Tone::Ok)];
            if d["providers"].as_u64().unwrap_or(0) > 1 {
                s.push(sp(
                    format!(" · {} DNS providers", d["providers"]),
                    Tone::Dim,
                ));
            }
            s
        } else if d["answers_differ"] == true {
            vec![sp("nameservers give different answers: a change is still propagating, a server is stale, or this is geo-DNS", Tone::Warn)]
        } else {
            vec![sp("SOA serials differ within one provider: a zone update has not reached every server yet", Tone::Warn)]
        };
        body.text(summary);
        let rec = &d["recursive"];
        let answers: Vec<&str> = rec["answers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if answers.is_empty() {
            body.text(vec![sp(
                format!("{}: no A record", str_of(rec, "resolver")),
                Tone::Dim,
            )]);
        } else {
            body.text(vec![
                sp(
                    format!("{} cached: {} ", str_of(rec, "resolver"), answers.join(" ")),
                    Tone::Fg,
                ),
                if rec["matches"] == true {
                    sp("(matches)", Tone::Ok)
                } else {
                    sp(
                        "(differs; normal for geo-DNS / CDNs, or the cache has not expired)",
                        Tone::Dim,
                    )
                },
            ]);
        }
        format!("zone {}", str_of(d, "zone"))
    }

    fn subdomains(&self, d: &Value, body: &mut Body) -> String {
        let rows = d["rows"].as_array().cloned().unwrap_or_default();
        let lead_w = 10;
        let (mut found, mut possible, mut none, mut unavailable) = (0, 0, vec![], vec![]);
        for r in &rows {
            let name = str_of(r, "name");
            let vals: Vec<&str> = r["cnames"]
                .as_array()
                .into_iter()
                .flatten()
                .chain(r["ips"].as_array().into_iter().flatten())
                .filter_map(Value::as_str)
                .collect();
            match (str_of(r, "status"), r["possible_wildcard"] == true) {
                ("answered", false) => {
                    found += 1;
                    body.row(vec![tag("found")], lead_w, vec![sp(name, Tone::Strong)]);
                    body.note(lead_w, &vals.join(" · "));
                }
                ("answered", true) => {
                    possible += 1;
                    body.row(
                        vec![tag("possible")],
                        lead_w,
                        vec![sp(name, Tone::Fg), sp("  wildcard response", Tone::Warn)],
                    );
                    body.note(lead_w, &vals.join(" · "));
                }
                ("no_match", _) => none.push(name.split('.').next().unwrap_or(name).to_string()),
                _ => unavailable.push(name.to_string()),
            }
        }
        if !none.is_empty() {
            body.row(
                vec![tag("not_found")],
                lead_w,
                vec![sp(none.join(" · "), Tone::Dim)],
            );
        }
        if !unavailable.is_empty() {
            body.row(
                vec![tag("error")],
                lead_w,
                vec![sp(
                    format!("lookup unavailable: {}", unavailable.join(" · ")),
                    Tone::Fail,
                )],
            );
        }
        body.blank();
        if d["wildcard_observed"] == true {
            body.text(vec![sp("wildcard DNS observed: random names resolve, so matching answers may not be real hosts", Tone::Warn)]);
        }
        body.text(vec![sp(str_of(d, "coverage"), Tone::Dim)]);
        let mut sub = format!("{found} found / {}", d["tested"]);
        if possible > 0 {
            sub.push_str(&format!(" · {possible} wildcard"));
        }
        sub
    }
}
