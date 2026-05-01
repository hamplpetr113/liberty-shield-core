use std::collections::HashMap;
use std::fs;
use std::time::Duration;

pub struct ShieldConfig {
    pub lateral_shell_processes: Vec<String>,
    pub lateral_cooldown: Duration,
    pub safe_ports: Vec<u16>,
    pub safe_ip_prefixes: Vec<String>,
    pub safe_172_range: (u8, u8),
    pub suspicious_ports: Vec<u16>,
    pub threat_score_threshold: u32,
    pub suspicious_process_names: Vec<String>,
    pub suspicious_lineage: Vec<(String, String)>,
    pub pattern_miner_keywords: Vec<String>,
    pub pattern_miner_ports: Vec<u16>,
    pub pattern_keylogger_keywords: Vec<String>,
    pub pattern_botnet_ports: Vec<u16>,
    pub pattern_botnet_host_threshold: u32,
    pub process_suspicious_name_score: u32,
    pub process_suspicious_lineage_score: u32,
    pub network_suspicious_port_score: u32,
    pub network_repeat_score: u32,
    pub network_repeat_threshold: u32,
    pub network_scan_threshold: u32,
    pub engine_attack_window_secs: u64,
    pub pattern_match_score: u32,
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
            suspicious_ports: vec![22, 23, 3389, 4444, 5555],
            threat_score_threshold: 60,
            suspicious_process_names: vec![
                "xmrig.exe".to_string(),
                "miner.exe".to_string(),
                "keylogger.exe".to_string(),
                "mimikatz.exe".to_string(),
                "hacktool.exe".to_string(),
                "rat.exe".to_string(),
                "trojan.exe".to_string(),
            ],
            suspicious_lineage: vec![
                ("powershell.exe".to_string(), "cmd.exe".to_string()),
                ("powershell.exe".to_string(), "wscript.exe".to_string()),
                ("powershell.exe".to_string(), "mshta.exe".to_string()),
            ],
            pattern_miner_keywords: vec!["xmrig.exe".to_string()],
            pattern_miner_ports: vec![4444],
            pattern_keylogger_keywords: vec!["keylogger.exe".to_string()],
            pattern_botnet_ports: vec![4444, 1337, 5555, 6666],
            pattern_botnet_host_threshold: 2,
            process_suspicious_name_score: 40,
            process_suspicious_lineage_score: 30,
            network_suspicious_port_score: 40,
            network_repeat_score: 20,
            network_repeat_threshold: 3,
            network_scan_threshold: 20,
            engine_attack_window_secs: 30,
            pattern_match_score: 50,
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
            let list: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !list.is_empty() {
                cfg.lateral_shell_processes = list;
            }
        }
        if let Some(v) = pairs.get("lateral_movement.cooldown_secs")
            && let Ok(n) = v.trim().parse::<u64>()
            && n > 0
        {
            cfg.lateral_cooldown = Duration::from_secs(n);
        }
        if let Some(v) = pairs.get("allowlist.safe_ports") {
            let ports: Vec<u16> = v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            if !ports.is_empty() {
                cfg.safe_ports = ports;
            }
        }
        if let Some(v) = pairs.get("allowlist.safe_ip_prefixes") {
            let prefixes: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !prefixes.is_empty() {
                cfg.safe_ip_prefixes = prefixes;
            }
        }
        if let Some(v) = pairs.get("allowlist.safe_172_range") {
            let parts: Vec<&str> = v.splitn(2, '-').collect();
            if parts.len() == 2
                && let (Ok(lo), Ok(hi)) =
                    (parts[0].trim().parse::<u8>(), parts[1].trim().parse::<u8>())
            {
                cfg.safe_172_range = (lo, hi);
            }
        }
        if let Some(v) = pairs.get("pattern.miner_keywords") {
            let list: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !list.is_empty() {
                cfg.pattern_miner_keywords = list;
            }
        }
        if let Some(v) = pairs.get("pattern.miner_ports") {
            let ports: Vec<u16> = v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            if !ports.is_empty() {
                cfg.pattern_miner_ports = ports;
            }
        }
        if let Some(v) = pairs.get("pattern.keylogger_keywords") {
            let list: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !list.is_empty() {
                cfg.pattern_keylogger_keywords = list;
            }
        }
        if let Some(v) = pairs.get("pattern.botnet_ports") {
            let ports: Vec<u16> = v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            if !ports.is_empty() {
                cfg.pattern_botnet_ports = ports;
            }
        }
        if let Some(v) = pairs.get("pattern.botnet_host_threshold")
            && let Ok(n) = v.trim().parse::<u32>()
            && n > 0
        {
            cfg.pattern_botnet_host_threshold = n;
        }
        if let Some(v) = pairs.get("process.suspicious_names") {
            let names: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !names.is_empty() {
                cfg.suspicious_process_names = names;
            }
        }
        if let Some(v) = pairs.get("process.suspicious_lineage") {
            let parsed: Vec<(String, String)> = v
                .split(',')
                .filter_map(|pair| {
                    let mut it = pair.trim().splitn(2, '>');
                    Some((it.next()?.trim().to_string(), it.next()?.trim().to_string()))
                })
                .filter(|(p, c)| !p.is_empty() && !c.is_empty())
                .collect();
            if !parsed.is_empty() {
                cfg.suspicious_lineage = parsed;
            }
        }
        if let Some(v) = pairs.get("network.suspicious_ports") {
            let ports: Vec<u16> = v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            if !ports.is_empty() {
                cfg.suspicious_ports = ports;
            }
        }
        if let Some(v) = pairs.get("engine.threat_score_threshold")
            && let Ok(n) = v.trim().parse::<u32>()
            && n > 0
        {
            cfg.threat_score_threshold = n;
        }
        if let Some(v) = pairs.get("process.suspicious_name_score")
            && let Ok(n) = v.trim().parse::<u32>()
        {
            cfg.process_suspicious_name_score = n;
        }
        if let Some(v) = pairs.get("process.suspicious_lineage_score")
            && let Ok(n) = v.trim().parse::<u32>()
        {
            cfg.process_suspicious_lineage_score = n;
        }
        if let Some(v) = pairs.get("network.suspicious_port_score")
            && let Ok(n) = v.trim().parse::<u32>()
        {
            cfg.network_suspicious_port_score = n;
        }
        if let Some(v) = pairs.get("network.repeat_score")
            && let Ok(n) = v.trim().parse::<u32>()
        {
            cfg.network_repeat_score = n;
        }
        if let Some(v) = pairs.get("network.repeat_threshold")
            && let Ok(n) = v.trim().parse::<u32>()
            && n > 0
        {
            cfg.network_repeat_threshold = n;
        }
        if let Some(v) = pairs.get("network.scan_threshold")
            && let Ok(n) = v.trim().parse::<u32>()
            && n > 0
        {
            cfg.network_scan_threshold = n;
        }
        if let Some(v) = pairs.get("engine.attack_window_secs")
            && let Ok(n) = v.trim().parse::<u64>()
            && n > 0
        {
            cfg.engine_attack_window_secs = n;
        }
        if let Some(v) = pairs.get("pattern.match_score")
            && let Ok(n) = v.trim().parse::<u32>()
        {
            cfg.pattern_match_score = n;
        }
        cfg
    }
}

fn parse_kv(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim().to_string();
            let val = line[pos + 1..].trim().to_string();
            map.insert(key, val);
        }
    }
    map
}
