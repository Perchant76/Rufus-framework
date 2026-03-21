// src-tauri/src/scanner/scope.rs
use std::net::IpAddr;
use regex::Regex;

pub struct ScopeEngine {
    scope_items: Vec<ScopeItem>,
}

enum ScopeItem {
    ExactDomain(String),
    WildcardDomain(String),   // *.example.com
    CidrRange(IpRange),
    ExactIp(IpAddr),
}

struct IpRange {
    base: u32,
    mask: u32,
}

impl ScopeEngine {
    pub fn new(scope: &[String]) -> Self {
        let scope_items = scope
            .iter()
            .filter_map(|s| Self::parse_item(s.trim()))
            .collect();
        ScopeEngine { scope_items }
    }

    fn parse_item(s: &str) -> Option<ScopeItem> {
        // CIDR range: 192.168.1.0/24
        if let Some((ip_part, prefix_str)) = s.split_once('/') {
            if let (Ok(ip), Ok(prefix)) = (ip_part.parse::<IpAddr>(), prefix_str.parse::<u32>()) {
                if let IpAddr::V4(v4) = ip {
                    let base = u32::from(v4);
                    let mask = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
                    return Some(ScopeItem::CidrRange(IpRange { base: base & mask, mask }));
                }
            }
        }
        // Exact IP
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(ScopeItem::ExactIp(ip));
        }
        // Wildcard domain: *.example.com
        if s.starts_with("*.") {
            let domain = s[2..].to_lowercase();
            return Some(ScopeItem::WildcardDomain(domain));
        }
        // Exact domain or subdomain
        if !s.is_empty() {
            return Some(ScopeItem::ExactDomain(s.to_lowercase()));
        }
        None
    }

    /// Returns true if the given hostname or IP is in scope
    pub fn is_in_scope(&self, value: &str) -> bool {
        let lower = value.to_lowercase();

        // Strip scheme and path if it's a URL
        let host = Self::extract_host(&lower);

        // Check if it's an IP
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.check_ip(&ip);
        }

        // It's a domain
        self.check_domain(host)
    }

    fn extract_host(input: &str) -> &str {
        // Remove scheme
        let without_scheme = if let Some(pos) = input.find("://") {
            &input[pos + 3..]
        } else {
            input
        };
        // Remove path/query
        let host = without_scheme
            .split('/')
            .next()
            .unwrap_or(without_scheme);
        // Remove port
        if let Some(colon_pos) = host.rfind(':') {
            // Make sure it's not an IPv6 address
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
                    if host == d || host.ends_with(&format!(".{}", d)) {
                        return true;
                    }
                }
                ScopeItem::WildcardDomain(d) => {
                    if host.ends_with(&format!(".{}", d)) || host == d {
                        return true;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_exact_domain() {
        let engine = ScopeEngine::new(&["example.com".to_string()]);
        assert!(engine.is_in_scope("example.com"));
        assert!(engine.is_in_scope("sub.example.com"));
        assert!(engine.is_in_scope("a.b.sub.example.com"));
        assert!(!engine.is_in_scope("notexample.com"));
        assert!(!engine.is_in_scope("other.com"));
    }

    #[test]
    fn test_scope_cidr() {
        let engine = ScopeEngine::new(&["192.168.1.0/24".to_string()]);
        assert!(engine.is_in_scope("192.168.1.1"));
        assert!(engine.is_in_scope("192.168.1.254"));
        assert!(!engine.is_in_scope("192.168.2.1"));
        assert!(!engine.is_in_scope("10.0.0.1"));
    }
}
