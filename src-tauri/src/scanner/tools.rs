// src-tauri/src/scanner/tools.rs
use std::process::Command;
use crate::db::models::ToolStatus;

pub struct ToolDef {
    pub name: &'static str,
    pub category: &'static str,
    pub install_cmd: &'static str,
    pub version_flag: &'static str,
    pub description: &'static str,
}

pub const ALL_TOOLS: &[ToolDef] = &[
    // ── Subdomain / DNS ───────────────────────────────────────────────────────
    ToolDef { name: "subfinder",    category: "Subdomain Enum",     install_cmd: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", version_flag: "-version", description: "Passive subdomain enumeration via CT logs, APIs, OSINT" },
    ToolDef { name: "dnsx",         category: "DNS Resolver",        install_cmd: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",              version_flag: "-version", description: "Fast multi-purpose DNS toolkit — bulk resolve, A/CNAME/MX/TXT records" },
    ToolDef { name: "amass",        category: "Attack Surface Mgmt", install_cmd: "go install github.com/owasp-amass/amass/v4/...@master",                    version_flag: "-version", description: "In-depth attack surface mapping, ASN discovery, network intel" },

    // ── Port / Host Discovery ─────────────────────────────────────────────────
    ToolDef { name: "nmap",         category: "Port Scanner",        install_cmd: "apt install nmap / brew install nmap",                                      version_flag: "--version", description: "Gold-standard port scanner: SYN scan, OS/service detection, NSE scripts" },
    ToolDef { name: "naabu",        category: "Fast Port Scanner",   install_cmd: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",          version_flag: "-version", description: "Ultra-fast SYN/CONNECT port scanner — scan 65535 ports in seconds" },
    ToolDef { name: "httpx",        category: "HTTP Probe",          install_cmd: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",              version_flag: "-version", description: "Probe HTTP/S on discovered hosts — status codes, titles, tech, CDN, WAF" },
    ToolDef { name: "masscan",      category: "Mass Port Scanner",   install_cmd: "apt install masscan / brew install masscan",                                 version_flag: "--version", description: "Fastest port scanner on earth — scan internet-scale ranges" },

    // ── Web Crawling / URL Discovery ──────────────────────────────────────────
    ToolDef { name: "katana",       category: "Web Crawler",         install_cmd: "go install github.com/projectdiscovery/katana/cmd/katana@latest",            version_flag: "-version", description: "Next-gen web crawler — JavaScript rendering, API endpoint discovery" },
    ToolDef { name: "gau",          category: "URL Archive Mining",  install_cmd: "go install github.com/lc/gau/v2/cmd/gau@latest",                            version_flag: "-version", description: "Fetch known URLs from Wayback Machine, Common Crawl, OTX, URLScan" },
    ToolDef { name: "waybackurls",  category: "URL Archive Mining",  install_cmd: "go install github.com/tomnomnom/waybackurls@latest",                         version_flag: "-h",        description: "Pull all URLs the Wayback Machine knows about for a domain" },
    ToolDef { name: "hakrawler",    category: "Web Crawler",         install_cmd: "go install github.com/hakluke/hakrawler@latest",                             version_flag: "-h",        description: "Fast Go web crawler for endpoints, JS files, forms — simple pipeline tool" },

    // ── Directory / Path Discovery ────────────────────────────────────────────
    ToolDef { name: "feroxbuster",  category: "Dir Brute-force",     install_cmd: "cargo install feroxbuster",                                                  version_flag: "--version", description: "Recursive content discovery — fastest Rust-based dir scanner" },
    ToolDef { name: "ffuf",         category: "Web Fuzzer",          install_cmd: "go install github.com/ffuf/ffuf/v2@latest",                                  version_flag: "-V",        description: "Fast web fuzzer — directories, parameters, virtual hosts, headers" },
    ToolDef { name: "gobuster",     category: "Dir Brute-force",     install_cmd: "go install github.com/OJ/gobuster/v3@latest",                                version_flag: "version",   description: "Brute-force URIs, DNS subdomains, virtual hostnames, S3 buckets" },
    ToolDef { name: "dirsearch",    category: "Dir Brute-force",     install_cmd: "pip install dirsearch",                                                      version_flag: "--version", description: "Advanced web path scanner with 10,000+ built-in paths" },

    // ── Vulnerability Scanners ────────────────────────────────────────────────
    ToolDef { name: "nuclei",       category: "Vuln Scanner",        install_cmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",         version_flag: "-version", description: "Template-based vuln scanner — 9000+ community CVE/misconfig templates" },
    ToolDef { name: "nikto",        category: "Web Vuln Scanner",    install_cmd: "apt install nikto / brew install nikto",                                     version_flag: "-Version", description: "Classic web server scanner — 6700+ dangerous files, outdated software" },
    ToolDef { name: "wapiti3",      category: "OWASP Scanner",       install_cmd: "pip install wapiti3",                                                        version_flag: "--version", description: "Black-box web app scanner — SQLi, XSS, SSRF, XXE, CSRF, SSTI" },
    ToolDef { name: "sqlmap",       category: "SQL Injection",       install_cmd: "pip install sqlmap / apt install sqlmap",                                    version_flag: "--version", description: "Automatic SQL injection detection and exploitation tool" },
    ToolDef { name: "dalfox",       category: "XSS Scanner",         install_cmd: "go install github.com/hahwul/dalfox/v2@latest",                             version_flag: "version",   description: "Powerful XSS scanner — parameter analysis, DOM XSS, blind XSS" },

    // ── TLS / Headers ─────────────────────────────────────────────────────────
    ToolDef { name: "testssl.sh",   category: "TLS Analyzer",        install_cmd: "brew install testssl / apt install testssl.sh",                              version_flag: "--version", description: "Check SSL/TLS configs — BEAST, POODLE, HEARTBLEED, cipher suites" },
    ToolDef { name: "wafw00f",      category: "WAF Detector",        install_cmd: "pip install wafw00f",                                                        version_flag: "--version", description: "Detect and fingerprint Web Application Firewalls" },

    // ── Secrets / Leaks ───────────────────────────────────────────────────────
    ToolDef { name: "trufflehog",   category: "Secret Scanner",      install_cmd: "go install github.com/trufflesecurity/trufflehog/v3@latest",                 version_flag: "--version", description: "Find leaked secrets in git repos, S3, filesystems, APIs" },
    ToolDef { name: "gitleaks",     category: "Secret Scanner",      install_cmd: "go install github.com/gitleaks/gitleaks/v8@latest",                         version_flag: "version",   description: "Scan git repos for secrets — API keys, passwords, tokens" },

    // ── Parameter / JS Analysis ───────────────────────────────────────────────
    ToolDef { name: "arjun",        category: "Parameter Discovery", install_cmd: "pip install arjun",                                                          version_flag: "--version", description: "HTTP parameter discovery — find hidden GET/POST parameters" },
    ToolDef { name: "linkfinder",   category: "JS Analyzer",         install_cmd: "pip install linkfinder",                                                    version_flag: "--version", description: "Discover endpoints and params in JavaScript files" },

    // ── Tech Fingerprinting ───────────────────────────────────────────────────
    ToolDef { name: "whatweb",      category: "Tech Fingerprint",    install_cmd: "apt install whatweb / gem install whatweb",                                  version_flag: "--version", description: "Identify CMS, frameworks, server software, JS libraries" },
    ToolDef { name: "wpscan",       category: "WordPress Scanner",   install_cmd: "gem install wpscan",                                                         version_flag: "--version", description: "WordPress vulnerability scanner — plugins, themes, users, config" },

    // ── Email / SPF / DMARC ───────────────────────────────────────────────────
    ToolDef { name: "theHarvester", category: "Email / OSINT",       install_cmd: "pip install theHarvester / apt install theharvester",                       version_flag: "-h",        description: "Gather emails, subdomains, hosts, IPs from public sources" },
];

pub fn check_tool(def: &ToolDef) -> ToolStatus {
    match Command::new(def.name).arg(def.version_flag).output() {
        Ok(output) => {
            let raw = String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr);
            ToolStatus {
                name: def.name.to_string(),
                available: true,
                version: extract_version(&raw),
                path: which_path(def.name),
                install_cmd: def.install_cmd.to_string(),
            }
        }
        Err(_) => ToolStatus {
            name: def.name.to_string(),
            available: false,
            version: None,
            path: None,
            install_cmd: def.install_cmd.to_string(),
        },
    }
}

pub fn check_all() -> Vec<ToolStatus> {
    ALL_TOOLS.iter().map(check_tool).collect()
}

fn extract_version(output: &str) -> Option<String> {
    let re = regex::Regex::new(r"v?(\d+\.\d+[\.\d]*)").ok()?;
    re.captures(output)?.get(1).map(|m| m.as_str().to_string())
}

fn which_path(name: &str) -> Option<String> {
    Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg(name)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
