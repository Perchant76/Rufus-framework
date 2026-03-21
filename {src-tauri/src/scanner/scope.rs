// src-tauri/src/scanner/scope.rs
use std::net::IpAddr;

pub struct ScopeEngine {
    scope_items: Vec<ScopeItem>,
}

enum ScopeItem {
    ExactDomain(String),
    WildcardDomain(String),
    CidrRange(IpRange),
    ExactIp(IpAddr),
}

struct IpRange {
    base: u32,
    mask: u32,
}

impl ScopeEngine {
    pub fn new(scope: &[String]) -> Self {
        let scope_items = scope.iter()
            .filter_map(|s| Self::parse_item(s.trim()))
            .collect();
        ScopeEngine { scope_items }
    }

    fn parse_item(s: &str) -> Option<ScopeItem> {
        if let Some((ip_part, prefix_str)) = s.split_once('/') {
            if let (Ok(ip), Ok(prefix)) = (ip_part.parse::<IpAddr>(), prefix_str.parse::<u32>()) {
                if let IpAddr::V4(v4) = ip {
                    let base = u32::from(v4);
                    let mask = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
                    return Some(ScopeItem::CidrRange(IpRange { base: base & mask, mask }));
                }
            }
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(ScopeItem::ExactIp(ip));
        }
        if s.starts_with("*.") {
            return Some(ScopeItem::WildcardDomain(s[2..].to_lowercase()));
        }
        if !s.is_empty() {
            return Some(ScopeItem::ExactDomain(s.to_lowercase()));
        }
        None
    }

    pub fn is_in_scope(&self, value: &str) -> bool {
        let lower = value.to_lowercase();
        let host = Self::extract_host(&lower);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.check_ip(&ip);
        }
        self.check_domain(host)
    }

    fn extract_host(input: &str) -> &str {
        let without_scheme = if let Some(pos) = input.find("://") {
            &input[pos + 3..]
        } else {
            input
        };
        let host = without_scheme.split('/').next().unwrap_or(without_scheme);
        if let Some(colon_pos) = host.rfind(':') {
            if !host.contains('[') {
                return &host[..colon_pos];
            }
        }
        host
    }

    fn check_domain(&self, host: &str) -> bool {
        for item in &self.scope_items {
            match item {
                ScopeItem::ExactDomain(d) => {
                    if host == d || host.ends_with(&format!(".{}", d)) { return true; }
                }
                ScopeItem::WildcardDomain(d) => {
                    if host.ends_with(&format!(".{}", d)) || host == d { return true; }
                }
                _ => {}
            }
        }
        false
    }

    fn check_ip(&self, ip: &IpAddr) -> bool {
        for item in &self.scope_items {
            match item {
                ScopeItem::ExactIp(scope_ip) => {
                    if ip == scope_ip { return true; }
                }
                ScopeItem::CidrRange(range) => {
                    if let IpAddr::V4(v4) = ip {
                        let addr = u32::from(*v4);
                        if addr & range.mask == range.base { return true; }
                    }
                }
                _ => {}
            }
        }
        false
    }
}
