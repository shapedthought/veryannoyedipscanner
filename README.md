# Very Annoyed IP Scanner 😤

A grumpy little clone of Angry IP Scanner, built with Tauri v2 (Rust + plain HTML/JS).

- Scan an IP range or CIDR block concurrently
- Ping, reverse DNS hostname, MAC (from the ARP cache) and open TCP ports
- **Vendor** from the MAC address (embedded IEEE/Wireshark OUI table; randomised
  "private" MACs are flagged as such)
- **Service identification** on open ports: HTTP page titles and `Server`
  headers (following same-host redirects), TLS certificate names, and banners
  from SSH/FTP/SMTP/VNC/etc. Toggle with *Identify services*.
- **History**: every completed scan is saved to SQLite and automatically diffed
  against the previous scan of the same range: new devices, gone devices, IP
  moves (matched by MAC), MAC changes on the same IP, and ports opened/closed.
  Changed rows get badges; details live in the side panel (Host / Changes /
  History), where you can also view or compare any two saved scans.
- Colour-coded rows: red = dead, green = alive, blue = open ports
- Sortable columns, hide dead hosts, right-click to copy/rescan, CSV export
- Complains constantly

## Run

```sh
npm install
npm run dev      # development window
npm run build    # release bundle in src-tauri/target/release/bundle/
```

Rust tests: `cd src-tauri && cargo test`

Scan history lives in the app data directory
(`~/Library/Application Support/com.shapedthought.veryannoyedipscanner/history.sqlite` on macOS).

Refresh the MAC vendor table with `python3 scripts/update_oui.py` (source:
Wireshark's `manuf` file, derived from the IEEE registry).

The original Python/tkinter version is still in `very_annoyed_ip_scanner.py`.
