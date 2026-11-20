//! KAN-110 Task 2 (JAM-17): Follow Stream startup configuration.
//!
//! Follow Stream is a startup opt-in (`FOLLOW_STREAM=1`). Only when it is on
//! does the agent read `RELAY_PORT`, the port the Next.js relay serves on,
//! and `FRONT_DOOR_PORT`, the port the mTLS front door (Caddy) serves the
//! relay on (KAN-294). Both carry retained stream content back over the
//! host, so the agent drops their traffic before the capture pipeline. They
//! select excluded transports, never a bind address. These are pure
//! functions of the raw values, so tests never mutate the process
//! environment.

use std::fmt;

/// The relay's port when `RELAY_PORT` is unset: Next.js's default.
pub const DEFAULT_RELAY_PORT: u16 = 3000;

/// The front door's port when `FRONT_DOOR_PORT` is unset: `deploy/Caddyfile`.
pub const DEFAULT_FRONT_DOOR_PORT: u16 = 8443;

/// The ports whose traffic Follow Stream excludes from live capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowPorts {
    pub relay: u16,
    pub front_door: u16,
}

impl FollowPorts {
    pub fn contains(&self, port: u16) -> bool {
        port == self.relay || port == self.front_door
    }
}

/// `FOLLOW_STREAM` enables the feature only when it is exactly `1`. Unset,
/// empty or any other value leaves it off.
pub fn follow_enabled(value: Option<&str>) -> bool {
    value == Some("1")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProblem {
    /// Set, but empty or whitespace.
    Blank,
    /// Not plain decimal digits (a sign, whitespace or other characters).
    NotDecimal,
    /// Decimal, but zero or above 65535.
    OutOfRange,
}

/// A bad port variable, named so the startup failure says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortError {
    pub var: &'static str,
    pub default: u16,
    pub problem: PortProblem,
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let why = match self.problem {
            PortProblem::Blank => "is set but blank",
            PortProblem::NotDecimal => "is not a decimal number",
            PortProblem::OutOfRange => "is outside 1-65535",
        };
        write!(f, "{} {why}; FOLLOW_STREAM=1 needs a port (default {})", self.var, self.default)
    }
}

impl std::error::Error for PortError {}

/// A port from `var`. Called only when Follow Stream is on; unset means
/// `default`, and anything set must be a plain decimal port in 1..=65535,
/// or opted-in startup fails.
pub fn parse_port(var: &'static str, default: u16, value: Option<&str>) -> Result<u16, PortError> {
    let fail = |problem| Err(PortError { var, default, problem });
    let Some(value) = value else { return Ok(default) };
    if value.trim().is_empty() {
        return fail(PortProblem::Blank);
    }
    // `str::parse` alone would accept a leading `+`.
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return fail(PortProblem::NotDecimal);
    }
    match value.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => fail(PortProblem::OutOfRange),
    }
}

/// The ports to exclude, from the raw `FOLLOW_STREAM`, `RELAY_PORT` and
/// `FRONT_DOOR_PORT` values: `None` when Follow Stream is off, without
/// looking at the ports, so a bad value there never stops an agent that
/// does not use the feature.
pub fn resolve_follow_ports(
    follow_stream: Option<&str>,
    relay_port: Option<&str>,
    front_door_port: Option<&str>,
) -> Result<Option<FollowPorts>, PortError> {
    if !follow_enabled(follow_stream) {
        return Ok(None);
    }
    Ok(Some(FollowPorts {
        relay: parse_port("RELAY_PORT", DEFAULT_RELAY_PORT, relay_port)?,
        front_door: parse_port("FRONT_DOOR_PORT", DEFAULT_FRONT_DOOR_PORT, front_door_port)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULTS: FollowPorts = FollowPorts { relay: DEFAULT_RELAY_PORT, front_door: DEFAULT_FRONT_DOOR_PORT };

    fn relay(value: Option<&str>) -> Result<u16, PortError> {
        parse_port("RELAY_PORT", DEFAULT_RELAY_PORT, value)
    }

    fn problem(r: Result<u16, PortError>) -> Option<PortProblem> {
        r.err().map(|e| e.problem)
    }

    #[test]
    fn ports_are_read_only_when_follow_stream_is_on() {
        assert_eq!(resolve_follow_ports(None, Some("garbage"), Some("garbage")), Ok(None));
        assert_eq!(resolve_follow_ports(Some("0"), Some(""), Some("")), Ok(None));
        assert_eq!(resolve_follow_ports(None, None, None), Ok(None));
        assert_eq!(resolve_follow_ports(Some("1"), None, None), Ok(Some(DEFAULTS)));
        assert_eq!(
            resolve_follow_ports(Some("1"), Some("3100"), Some("9443")),
            Ok(Some(FollowPorts { relay: 3100, front_door: 9443 }))
        );
    }

    #[test]
    fn a_bad_port_names_its_variable() {
        let e = resolve_follow_ports(Some("1"), Some("3100"), Some("x")).unwrap_err();
        assert_eq!((e.var, e.problem), ("FRONT_DOOR_PORT", PortProblem::NotDecimal));
        assert!(e.to_string().starts_with("FRONT_DOOR_PORT is not a decimal number"), "{e}");
        assert!(e.to_string().contains("default 8443"), "{e}");
        let e = resolve_follow_ports(Some("1"), Some("x"), None).unwrap_err();
        assert_eq!(e.var, "RELAY_PORT");
        assert!(e.to_string().contains("default 3000"), "{e}");
    }

    #[test]
    fn follow_ports_contain_both() {
        let p = FollowPorts { relay: 3100, front_door: 9443 };
        assert!(p.contains(3100) && p.contains(9443));
        assert!(!p.contains(3000) && !p.contains(8443));
    }

    #[test]
    fn follow_stream_is_on_only_for_exactly_one() {
        assert!(follow_enabled(Some("1")));
        for off in [None, Some(""), Some(" "), Some("0"), Some("true"), Some("yes"), Some(" 1"), Some("1 "), Some("01"), Some("+1")] {
            assert!(!follow_enabled(off), "{off:?} enabled Follow Stream");
        }
    }

    #[test]
    fn an_unset_port_is_the_default() {
        assert_eq!(relay(None), Ok(DEFAULT_RELAY_PORT));
        assert_eq!(parse_port("FRONT_DOOR_PORT", DEFAULT_FRONT_DOOR_PORT, None), Ok(8443));
    }

    #[test]
    fn ports_at_the_bounds_are_accepted() {
        assert_eq!(relay(Some("1")), Ok(1));
        assert_eq!(relay(Some("3100")), Ok(3100));
        assert_eq!(relay(Some("65535")), Ok(65535));
    }

    #[test]
    fn out_of_range_ports_fail() {
        for v in ["0", "65536", "99999999999999999999"] {
            assert_eq!(problem(relay(Some(v))), Some(PortProblem::OutOfRange), "{v}");
        }
    }

    #[test]
    fn blank_ports_fail() {
        for v in ["", " ", "\t"] {
            assert_eq!(problem(relay(Some(v))), Some(PortProblem::Blank), "{v:?}");
        }
    }

    #[test]
    fn malformed_ports_fail() {
        for v in ["+3000", "-1", " 3000", "3000 ", "30 00", "3e3", "0x10", "3000a", "３０００"] {
            assert_eq!(problem(relay(Some(v))), Some(PortProblem::NotDecimal), "{v:?}");
        }
    }
}
