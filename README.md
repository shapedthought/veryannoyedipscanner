# Very Annoyed IP Scanner 😤

A grumpy little clone of Angry IP Scanner, built with Tauri v2 (Rust + plain HTML/JS).

- Scan **several targets at once**: CIDR blocks, ranges (`10.0.0.1-50`) and
  single addresses in one field, with a live count of what you've asked for
- **Port presets**: Quick, Web, Windows, Databases, Remote access, Home & IoT,
  Top 100
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
- **Listens before it sweeps**: an mDNS/Bonjour and SSDP/UPnP round at the start
  of each scan, so devices introduce themselves. Gives real names
  (`LGwebOSTV`, `Edwards-MacBook-Pro`) and service labels (AirPlay, HomeKit,
  Printer, Chromecast), and finds devices that answer nothing else.
- **Finds hosts that ignore ping**: a completed ARP entry counts as proof a
  device exists (Windows boxes, printers, cameras), shown as `[arp]` in the
  Ping column. Configurable ping retries catch Wi-Fi devices in power-save.
- Pings over an **unprivileged ICMP socket** (no admin rights, no `ping`
  process per host), falling back to the `ping` command where that is blocked
- **Your names, not theirs**: label any device with a name and note, stored
  against its MAC so both survive a change of IP. Approve the devices that
  belong on the network; anything unapproved stays flagged `UNKNOWN` in every
  scan, not just the one where it first appeared.
- **Scheduled rescans**: pick an interval in the status bar and it rescans the
  range on a timer, sending a macOS notification when something changes —
  devices you haven't approved first, then new arrivals, ports opening, and
  departures. Scans you start yourself stay silent, since you're watching.
- **Lives in the menu bar**: the number of devices currently up sits next to
  the icon, with last-scan detail, *Scan now* and *Open window* in its menu.
  Closing the window hides it rather than quitting, so scheduled scans carry
  on; quit from the menu bar when you mean it.
- **Says what's worth a look**: telnet, exposed databases, an unauthenticated
  Docker socket, expired or soon-to-expire certificates, obsolete TLS, login
  pages served over plain HTTP. Each finding carries a severity and a sentence
  on why it matters. These are outside-view inferences — nothing authenticates
  — so they report what is *exposed*, not that it is broken.
- Colour-coded rows: red = dead, green = alive, blue = open ports
- **Filter as you type** (⌘F): plain text searches the whole row, `port:22`,
  `vendor:apple`, `name:`, `via:` and friends search one field, and bare words
  like `new`, `unknown`, `risk` or `-dead` match what a row *is*. Terms combine.
- Sortable columns, hide dead hosts, right-click to copy/rescan, CSV export
- Complains constantly

## Run

```sh
npm install
npm run dev      # development window
npm run build    # release bundle in src-tauri/target/release/bundle/
```

Rust tests: `cd src-tauri && cargo test`

Frontend tests: `node --test ui/*.test.js`

Scan history lives in the app data directory
(`~/Library/Application Support/com.shapedthought.veryannoyedipscanner/history.sqlite` on macOS).

Refresh the MAC vendor table with `python3 scripts/update_oui.py` (source:
Wireshark's `manuf` file, derived from the IEEE registry).

The original Python/tkinter version is still in `very_annoyed_ip_scanner.py`.
