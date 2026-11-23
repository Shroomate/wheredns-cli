//! Saved preferences in `~/.config/wheredns/config` (or `$XDG_CONFIG_HOME/wheredns/config`;
//! `%APPDATA%\wheredns\config` on Windows).
//! The file is plain `key = value` lines; `wheredns config` reads and edits it.
//! Command-line flags beat environment variables, which beat this file.

use crate::display::{Animate, Theme};
use clap::ValueEnum;
use std::{ffi::OsString, fs, path::PathBuf};

pub const KEYS: [(&str, &str); 4] = [
    (
        "theme",
        "btop (default), tty, purple, phosphor, amber, ansi, none",
    ),
    (
        "checks",
        "default checks for a domain, e.g. \"where email web dns\"",
    ),
    (
        "animate",
        "full (live panels, default), minimal (progress line), off",
    ),
    (
        "background",
        "false (terminal background, default) or true (paint the theme background)",
    ),
];

#[derive(Default, Debug)]
pub struct Config {
    pub theme: Option<Theme>,
    pub checks: Option<Vec<String>>,
    pub animate: Option<Animate>,
    pub background: Option<bool>,
}

pub fn path() -> Option<PathBuf> {
    path_from(|k| std::env::var_os(k), cfg!(windows))
}

/// `XDG_CONFIG_HOME` always wins. Otherwise Windows uses `%APPDATA%` (set in
/// every normal shell there), and everything else `$HOME/.config`. Each
/// platform falls back to the other's variable, then `USERPROFILE\.config`.
fn path_from(env: impl Fn(&str) -> Option<OsString>, windows: bool) -> Option<PathBuf> {
    let var = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let home = || var("HOME").map(|h| h.join(".config"));
    let appdata = || var("APPDATA");
    let base = var("XDG_CONFIG_HOME")
        .or_else(|| {
            if windows {
                appdata().or_else(home)
            } else {
                home().or_else(appdata)
            }
        })
        .or_else(|| var("USERPROFILE").map(|h| h.join(".config")))?;
    Some(base.join("wheredns").join("config"))
}

fn entries(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let (k, v) = l.split_once('=')?;
            Some((
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').trim().to_string(),
            ))
        })
        .collect()
}

fn validate(key: &str, value: &str) -> Result<(), String> {
    match key {
        "theme" => Theme::from_str(value, true).map(|_| ()).map_err(|_| {
            "theme must be one of btop, tty, purple, phosphor, amber, ansi, none".into()
        }),
        "animate" => Animate::from_str(value, true)
            .map(|_| ())
            .map_err(|_| "animate must be one of full, minimal, off".into()),
        "background" => parse_bool(value)
            .map(|_| ())
            .ok_or_else(|| "expected true or false".into()),
        "checks" => {
            for c in value.split_whitespace() {
                if crate::Group::from_id(&c.to_ascii_lowercase()).is_none() {
                    return Err(format!("unknown check {c:?}"));
                }
            }
            if value.split_whitespace().next().is_none() {
                return Err("list at least one check".into());
            }
            Ok(())
        }
        _ => Err(format!(
            "unknown setting {key:?}; settings are {}",
            KEYS.map(|(k, _)| k).join(", ")
        )),
    }
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// Reads the saved preferences. Invalid lines are reported once and skipped.
pub fn load() -> Config {
    let mut c = Config::default();
    let Some(text) = path().and_then(|p| fs::read_to_string(p).ok()) else {
        return c;
    };
    for (k, v) in entries(&text) {
        if let Err(e) = validate(&k, &v) {
            eprintln!("wheredns: ignoring config {k} = {v:?}: {e}");
            continue;
        }
        match k.as_str() {
            "theme" => c.theme = Theme::from_str(&v, true).ok(),
            "animate" => c.animate = Animate::from_str(&v, true).ok(),
            "background" => c.background = parse_bool(&v),
            "checks" => c.checks = Some(v.split_whitespace().map(str::to_string).collect()),
            _ => {}
        }
    }
    c
}

fn save(values: &[(String, String)]) -> Result<PathBuf, String> {
    let p = path().ok_or("cannot find a home directory for the config file")?;
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut text =
        String::from("# wheredns settings; edit here or with `wheredns config set KEY VALUE`\n");
    for (k, v) in values {
        let quoted = if v.contains(' ') {
            format!("\"{v}\"")
        } else {
            v.clone()
        };
        text.push_str(&format!("{k} = {quoted}\n"));
    }
    fs::write(&p, text).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(p)
}

/// `wheredns config [set KEY VALUE.. | unset KEY | path]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let current = path()
        .and_then(|p| fs::read_to_string(p).ok())
        .map(|t| entries(&t))
        .unwrap_or_default();
    match args.first().map(String::as_str) {
        None | Some("show") | Some("list") => {
            let p = path().map_or("(no home directory)".into(), |p| p.display().to_string());
            println!("config file: {p}\n");
            for (k, help) in KEYS {
                let v = current
                    .iter()
                    .rev()
                    .find(|(ck, _)| ck == k)
                    .map_or("(default)".to_string(), |(_, v)| v.clone());
                println!("  {k:<11} {v:<24} {help}");
            }
            println!(
                "\nChange one:  wheredns config set theme tty\n             wheredns config set checks where email web dns\n             wheredns config set animate minimal\nReset one:   wheredns config unset theme"
            );
            Ok(())
        }
        Some("path") => {
            println!("{}", path().ok_or("no home directory")?.display());
            Ok(())
        }
        Some("set") => {
            let key = args.get(1).ok_or("usage: wheredns config set KEY VALUE")?;
            let key = key.to_ascii_lowercase();
            let value = args[2..].join(" ");
            if value.is_empty() {
                return Err("usage: wheredns config set KEY VALUE".into());
            }
            let value = if key == "checks" {
                value.to_ascii_lowercase()
            } else {
                value
            };
            validate(&key, &value)?;
            let mut values: Vec<(String, String)> =
                current.into_iter().filter(|(k, _)| *k != key).collect();
            values.push((key.clone(), value.clone()));
            let p = save(&values)?;
            println!("saved {key} = {value} in {}", p.display());
            Ok(())
        }
        Some("unset") | Some("reset") => {
            let key = args
                .get(1)
                .ok_or("usage: wheredns config unset KEY")?
                .to_ascii_lowercase();
            let values: Vec<(String, String)> =
                current.into_iter().filter(|(k, _)| *k != key).collect();
            let p = save(&values)?;
            println!("{key} reset to default in {}", p.display());
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown config command {other:?}; use `wheredns config`, `config set KEY VALUE` or `config unset KEY`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_and_validates() {
        let e = entries("# c\ntheme = tty\nchecks = \"where web\"\n\nbad line\n");
        assert_eq!(e[0], ("theme".into(), "tty".into()));
        assert_eq!(e[1], ("checks".into(), "where web".into()));
        assert!(validate("theme", "btop").is_ok());
        assert!(validate("theme", "pink").is_err());
        assert!(validate("checks", "where nope").is_err());
        assert!(validate("animate", "off").is_ok());
        assert!(validate("background", "maybe").is_err());
        assert!(validate("colour", "x").is_err());
    }

    #[test]
    fn config_path_without_home() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let tail =
            |p: Option<PathBuf>| p.map(|p| p.parent().unwrap().parent().unwrap().to_path_buf());
        let win = env(&[
            ("APPDATA", "C:/Users/u/AppData/Roaming"),
            ("USERPROFILE", "C:/Users/u"),
        ]);
        assert_eq!(
            tail(path_from(win, true)),
            Some("C:/Users/u/AppData/Roaming".into())
        );
        let only_profile = env(&[("USERPROFILE", "C:/Users/u")]);
        assert_eq!(
            tail(path_from(only_profile, true)),
            Some("C:/Users/u/.config".into())
        );
        let xdg = env(&[("XDG_CONFIG_HOME", "/x"), ("HOME", "/h"), ("APPDATA", "/a")]);
        assert_eq!(tail(path_from(xdg, true)), Some("/x".into()));
        assert_eq!(tail(path_from(xdg, false)), Some("/x".into()));
        let unix = env(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "")]);
        assert_eq!(tail(path_from(unix, false)), Some("/h/.config".into()));
        assert_eq!(path_from(env(&[]), false), None);
    }
}
