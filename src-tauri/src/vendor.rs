//! MAC address -> manufacturer, from the embedded Wireshark OUI table.
//! Regenerate the table with `scripts/update_oui.py`.

use std::collections::HashMap;
use std::sync::OnceLock;

static OUI_TSV: &str = include_str!("../data/oui.tsv");

/// Keys are 6, 7 or 9 uppercase hex digits (/24, /28 and /36 assignments).
fn table() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    TABLE.get_or_init(|| OUI_TSV.lines().filter_map(|l| l.split_once('\t')).collect())
}

pub fn lookup(mac: &str) -> String {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if hex.len() != 12 {
        return String::new();
    }
    // Most specific assignment wins.
    for digits in [9, 7, 6] {
        if let Some(vendor) = table().get(&hex[..digits]) {
            return vendor.to_string();
        }
    }
    // Locally administered bit set: phones and laptops randomising their MAC.
    let first = u8::from_str_radix(&hex[..2], 16).unwrap_or(0);
    if first & 0x02 != 0 {
        return "Private (random MAC)".into();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::lookup;

    #[test]
    fn known_vendors() {
        assert_eq!(lookup("B8:27:EB:12:34:56"), "Raspberry Pi Foundation");
        assert_eq!(lookup("00:11:32:aa:bb:cc"), "Synology");
        assert_eq!(lookup("00-1B-C5-00-1F-FF"), "OpenRB.com, Direct SIA"); // /36 block
        assert_eq!(lookup("3A:12:34:56:78:9A"), "Private (random MAC)");
        assert_eq!(lookup("nonsense"), "");
    }
}
