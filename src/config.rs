use std::collections::HashMap;
use std::fs;
use std::time::Duration;

pub struct ShieldConfig {
    pub lateral_shell_processes: Vec<String>,
    pub lateral_cooldown: Duration,
    pub safe_ports: Vec<u16>,
    pub safe_ip_prefixes: Vec<String>,
    pub safe_172_range: (u8, u8),
}

impl Default for ShieldConfig {
    fn default() -> Self {
        ShieldConfig {
            lateral_shell_processes: vec![
                "cmd.exe".to_string(),
                "powershell.exe".to_string(),
                "wscript.exe".to_string(),
                "mshta.exe".to_string(),
            ],
            lateral_cooldown: Duration::from_secs(60),
            safe_ports: vec![53],
            safe_ip_prefixes: vec![
                "127.".to_string(),
                "10.".to_string(),
                "192.168.".to_string(),
                "::1".to_string(),
            ],
            safe_172_range: (16, 31),
        }
    }
}

impl ShieldConfig {
    pub fn load(path: &str) -> Self {
        let mut cfg = ShieldConfig::default();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return cfg,
        };
        let pairs = parse_kv(&content);
        if let Some(v) = pairs.get("lateral_movement.shell_processes") {
            let list: Vec<String> = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if !list.is_empty() { cfg.lateral_shell_processes = list; }
        }
        if let Some(v) = pairs.get("lateral_movement.cooldown_secs") {
            if let Ok(n) = v.trim().parse::<u64>() {
                if n > 0 { cfg.lateral_cooldown = Duration::from_secs(n); }
            }
        }
        if let Some(v) = pairs.get("allowlist.safe_ports") {
            let ports: Vec<u16> = v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            if !ports.is_empty() { cfg.safe_ports = ports; }
        }
        if let Some(v) = pairs.get("allowlist.safe_ip_prefixes") {
            let prefixes: Vec<String> = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if !prefixes.is_empty() { cfg.safe_ip_prefixes = prefixes; }
        }
        if let Some(v) = pairs.get("allowlist.safe_172_range") {
            let parts: Vec<&str> = v.splitn(2, '-').collect();
            if parts.len() == 2 {
                if let (Ok(lo), Ok(hi)) = (parts[0].trim().parse::<u8>(), parts[1].trim().parse::<u8>()) {
                    cfg.safe_172_range = (lo, hi);
                }
            }
        }
        cfg
    }
}

fn parse_kv(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim().to_string();
            let val = line[pos + 1..].trim().to_string();
            map.insert(key, val);
        }
    }
    map
}
