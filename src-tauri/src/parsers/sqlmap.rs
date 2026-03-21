// src-tauri/src/parsers/sqlmap.rs
// sqlmap: pip install sqlmap  OR  apt install sqlmap
// Invocation: sqlmap -u "https://target.com/page?id=1" --batch --level=2 --risk=1 --output-dir=/tmp/sqlmap_out --json
// Output: Directory-based JSON output, parsed from /tmp/sqlmap_out/<target>/log
use crate::db::models::RawFinding;
use super::ToolParser;

pub struct SqlmapParser;

impl ToolParser for SqlmapParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        let mut findings = vec![];

        // Parse sqlmap's text log output (--batch produces parseable text)
        let lines: Vec<&str> = output.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            // SQLi confirmed
            if line.contains("is vulnerable") || line.contains("Parameter:") && line.contains("is injectable") {
                let param = extract_between(line, "Parameter: ", " (");
                let db_type = lines.get(i + 1)
                    .and_then(|l| if l.contains("Type:") { Some(*l) } else { None })
                    .map(|l| l.replace("Type:", "").trim().to_string())
                    .unwrap_or_default();

                let url = lines.iter().rev()
                    .find(|l| l.contains("sqlmap -u") || l.contains("Target:"))
                    .map(|l| l.trim().to_string())
                    .unwrap_or_default();

                findings.push(RawFinding {
                    source_tool: "sqlmap".to_string(),
                    severity: "CRITICAL".to_string(),
                    title: format!("SQL Injection Confirmed — Parameter: {}", param),
                    description: format!("SQLmap confirmed SQL injection in parameter '{}'. Type: {}", param, db_type),
                    affected_url: url.clone(),
                    affected_port: None,
                    cve_references: vec!["CWE-89".to_string()],
                    cvss_score: Some(9.8),
                    evidence: format!("Parameter: {}\nType: {}\nSQLmap output:\n{}", param, db_type, lines[i.saturating_sub(2)..=(i+5).min(lines.len()-1)].join("\n")),
                    remediation: "Use parameterized queries / prepared statements. NEVER concatenate user input into SQL queries. Consider a WAF as additional defence-in-depth.".to_string(),
                    http_request: None,
                    http_response: None,
                });
            }

            // Database fingerprinted
            if line.contains("back-end DBMS:") {
                let dbms = line.replace("back-end DBMS:", "").trim().to_string();
                let url = lines.iter().rev()
                    .find(|l| l.contains("Target:") || l.contains("URL:"))
                    .map(|l| l.trim().to_string())
                    .unwrap_or_default();
                findings.push(RawFinding {
                    source_tool: "sqlmap".to_string(),
                    severity: "INFO".to_string(),
                    title: format!("Database Fingerprinted: {}", dbms),
                    description: format!("SQLmap identified the backend database as: {}", dbms),
                    affected_url: url,
                    affected_port: None,
                    cve_references: vec![],
                    cvss_score: None,
                    evidence: line.to_string(),
                    remediation: "Suppress database error messages and version disclosure in responses.".to_string(),
                    http_request: None,
                    http_response: None,
                });
            }
        }

        findings
    }
}

fn extract_between<'a>(s: &'a str, start: &str, end: &str) -> &'a str {
    if let Some(si) = s.find(start) {
        let after = &s[si + start.len()..];
        if let Some(ei) = after.find(end) {
            return &after[..ei];
        }
        return after;
    }
    s
}
