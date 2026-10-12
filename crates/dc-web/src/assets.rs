//! Embedded dashboard assets — compiled into the binary so the appliance
//! ISO serves the operator UI with zero external files (and zero network
//! dependencies: no CDN, no fonts, no telemetry).

/// The single-file dashboard (HTML + CSS + JS).
pub const DASHBOARD_HTML: &[u8] = include_bytes!("../assets/index.html");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_embeds_and_is_self_contained() {
        let html = std::str::from_utf8(DASHBOARD_HTML).expect("dashboard is utf-8");
        assert!(html.contains("discCleaner Ops Center"));
        // Air-gap discipline: no external resource loads of any kind.
        assert!(!html.contains("http://"), "no plain-http resources");
        assert!(!html.contains("https://"), "no CDN/network resources");
        assert!(!html.contains("<script src="), "no external scripts");
        assert!(!html.contains("<link "), "no external stylesheets");
        // Security posture: the arm gate exists.
        assert!(html.contains("Type ERASE to arm"));
    }
}
