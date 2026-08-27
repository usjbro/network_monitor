use std::collections::HashMap;
use std::process::Command;

pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
}

/// Parses `lsof -i -n -P` output. Lines look like:
///   Safari   1234 jamesb   45u  IPv4 0x123   0t0  TCP 192.168.1.10:51000->93.184.216.34:443 (ESTABLISHED)
/// Keyed by the *local* port (the number before "->").
pub fn parse_lsof_output(output: &str) -> HashMap<u16, ProcessInfo> {
    let mut map = HashMap::new();
    for line in output.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }
        let name = fields[0].to_string();
        let Ok(pid) = fields[1].parse::<u32>() else { continue };
        let name_field = fields[8];
        let Some(local_part) = name_field.split("->").next() else { continue };
        let Some(port_str) = local_part.rsplit(':').next() else { continue };
        let Ok(port) = port_str.parse::<u16>() else { continue };
        map.insert(port, ProcessInfo { name, pid });
    }
    map
}

pub fn refresh() -> HashMap<u16, ProcessInfo> {
    match Command::new("lsof").args(["-i", "-n", "-P"]).output() {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            parse_lsof_output(&text)
        }
        Err(_) => HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lsof_output_into_port_map() {
        let sample = "\
COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Safari   1234 jamesb   45u  IPv4 0x123      0t0  TCP 192.168.1.10:51000->93.184.216.34:443 (ESTABLISHED)
Slack    5678 jamesb   12u  IPv4 0x456      0t0  UDP 192.168.1.10:60123->8.8.8.8:53
";
        let map = parse_lsof_output(sample);
        assert_eq!(map.get(&51000).unwrap().name, "Safari");
        assert_eq!(map.get(&51000).unwrap().pid, 1234);
        assert_eq!(map.get(&60123).unwrap().name, "Slack");
        assert_eq!(map.get(&60123).unwrap().pid, 5678);
    }

    #[test]
    fn ignores_unparseable_lines() {
        let sample = "COMMAND   PID   USER   FD   TYPE\nnot a real line at all\n";
        let map = parse_lsof_output(sample);
        assert!(map.is_empty());
    }
}
