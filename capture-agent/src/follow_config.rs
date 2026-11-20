//! KAN-110 Task 2 (JAM-17): Follow Stream startup configuration.
//!
//! Follow Stream is a startup opt-in (`FOLLOW_STREAM=1`). Only when it is on
//! does the agent read `RELAY_PORT`, the port the Next.js relay serves on, so
//! it can drop the relay's own loopback traffic (which carries retained
//! stream content) before the capture pipeline. `RELAY_PORT` selects an
//! excluded transport, never a bind address. These are pure functions of the
//! raw values, so tests never mutate the process environment.

use std::fmt;

/// The relay's port when `RELAY_PORT` is unset: Next.js's default.
pub const DEFAULT_RELAY_PORT: u16 = 3000;

/// `FOLLOW_STREAM` enables the feature only when it is exactly `1`. Unset,
/// empty or any other value leaves it off.
pub fn follow_enabled(value: Option<&str>) -> bool {
    value == Some("1")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPortError {
    /// Set, but empty or whitespace.
    Blank,
    /// Not plain decimal digits (a sign, whitespace or other characters).
    NotDecimal,
    /// Decimal, but zero or above 65535.
    OutOfRange,
}

impl fmt::Display for RelayPortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let why = match self {
            RelayPortError::Blank => "is set but blank",
            RelayPortError::NotDecimal => "is not a decimal number",
            RelayPortError::OutOfRange => "is outside 1-65535",
        };
        write!(f, "RELAY_PORT {why}; FOLLOW_STREAM=1 needs the relay's port (default {DEFAULT_RELAY_PORT})")
    }
}

impl std::error::Error for RelayPortError {}

/// The relay port from `RELAY_PORT`. Called only when Follow Stream is on;
/// unset means the default, and anything set must be a plain decimal port
/// in 1..=65535, or opted-in startup fails.
pub fn parse_relay_port(value: Option<&str>) -> Result<u16, RelayPortError> {
    let Some(value) = value else { return Ok(DEFAULT_RELAY_PORT) };
    if value.trim().is_empty() {
        return Err(RelayPortError::Blank);
    }
    // `str::parse` alone would accept a leading `+`.
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RelayPortError::NotDecimal);
    }
    match value.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(RelayPortError::OutOfRange),
    }
}

/// The relay port to exclude, from the raw `FOLLOW_STREAM` and
/// `RELAY_PORT` values: `None` when Follow Stream is off, without looking
/// at `RELAY_PORT`, so a bad value there never stops an agent that does not
/// use the feature.
pub fn resolve_relay_port(follow_stream: Option<&str>, relay_port: Option<&str>) -> Result<Option<u16>, RelayPortError> {
    if !follow_enabled(follow_stream) {
        return Ok(None);
    }
    parse_relay_port(relay_port).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_port_is_read_only_when_follow_stream_is_on() {
        assert_eq!(resolve_relay_port(None, Some("garbage")), Ok(None));
        assert_eq!(resolve_relay_port(Some("0"), Some("")), Ok(None));
        assert_eq!(resolve_relay_port(None, None), Ok(None));
        assert_eq!(resolve_relay_port(Some("1"), None), Ok(Some(DEFAULT_RELAY_PORT)));
        assert_eq!(resolve_relay_port(Some("1"), Some("3100")), Ok(Some(3100)));
        assert_eq!(resolve_relay_port(Some("1"), Some("garbage")), Err(RelayPortError::NotDecimal));
    }

    #[test]
    fn follow_stream_is_on_only_for_exactly_one() {
        assert!(follow_enabled(Some("1")));
        for off in [None, Some(""), Some(" "), Some("0"), Some("true"), Some("yes"), Some(" 1"), Some("1 "), Some("01"), Some("+1")] {
            assert!(!follow_enabled(off), "{off:?} enabled Follow Stream");
        }
    }

    #[test]
    fn an_unset_relay_port_is_the_default() {
        assert_eq!(parse_relay_port(None), Ok(DEFAULT_RELAY_PORT));
    }

    #[test]
    fn relay_ports_at_the_bounds_are_accepted() {
        assert_eq!(parse_relay_port(Some("1")), Ok(1));
        assert_eq!(parse_relay_port(Some("3100")), Ok(3100));
        assert_eq!(parse_relay_port(Some("65535")), Ok(65535));
    }

    #[test]
    fn out_of_range_relay_ports_fail() {
        for v in ["0", "65536", "99999999999999999999"] {
            assert_eq!(parse_relay_port(Some(v)), Err(RelayPortError::OutOfRange), "{v}");
        }
    }

    #[test]
    fn blank_relay_ports_fail() {
        for v in ["", " ", "\t"] {
            assert_eq!(parse_relay_port(Some(v)), Err(RelayPortError::Blank), "{v:?}");
        }
    }

    #[test]
    fn malformed_relay_ports_fail() {
        for v in ["+3000", "-1", " 3000", "3000 ", "30 00", "3e3", "0x10", "3000a", "３０００"] {
            assert_eq!(parse_relay_port(Some(v)), Err(RelayPortError::NotDecimal), "{v:?}");
        }
    }
}
