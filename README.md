# Very Annoyed IP Scanner 😤

[![CI](https://github.com/shapedthought/veryannoyedipscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/shapedthought/veryannoyedipscanner/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/shapedthought/veryannoyedipscanner?sort=semver)](https://github.com/shapedthought/veryannoyedipscanner/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%2011%2B-lightgrey)](https://github.com/shapedthought/veryannoyedipscanner/releases/latest)
[![Built with Tauri](https://img.shields.io/badge/built%20with-Tauri%20v2-24C8DB)](https://tauri.app)

A grumpy little clone of Angry IP Scanner, built with Rust and Tauri. It scans
your network, tells you what's on it, remembers what was there last time, and
complains the entire way through.

No admin rights, no installer, no telemetry: everything it learns stays in one
SQLite file on your machine.

---

## What it does

### Finds things other scanners miss

- **Pings over an unprivileged ICMP socket** — no `ping` process per host, so a
  /24 sweeps in a few seconds.
- **Listens before it sweeps.** An mDNS/Bonjour and SSDP/UPnP round at the start
  of each scan, so devices introduce themselves: real names (`LivingRoomTV`) and
  what they offer (AirPlay, HomeKit, Printer, Chromecast).
- **Counts a completed ARP entry as proof of life**, which catches Windows
  machines, printers and cameras that ignore ping entirely.
- **Retries pings**, because phones dozing on Wi-Fi routinely miss the first one.

Every row says *how* it was found: `3 ms`, `[arp]`, `[port]` or `[mdns]`.

### Says what things are

- **Vendor from the MAC address**, using an embedded IEEE/Wireshark OUI table.
  Randomised "private" MACs are labelled as such rather than left blank.
- **Service identification** on open ports: HTTP page titles and `Server`
  headers (following same-host redirects), TLS certificate names, and banners
  from SSH, FTP, SMTP, VNC and friends.
- **Your names win.** Label any device and add a note; both are stored against
  its MAC, so they survive a change of address.

### Notices what changed

- Every completed scan is saved and **diffed against the previous one**: new
  devices, departed devices, IP moves (matched by MAC), a new MAC on a familiar
  address, and ports opening or closing.
- **Approve the devices that belong.** Anything unapproved stays flagged in
  every scan, not just the one where it first appeared.
- **A history per device**: how many of the scans that looked here it answered,
  a strip showing when it was present, and the moments worth naming.
- **A scan that finds nothing** where there was something last time is called
  out and kept out of comparisons, instead of quietly becoming the baseline that
  makes everything look new.

### Knows where it is

- **Network profiles.** The network is identified by its **gateway's MAC
  address** (and SSID when macOS will say), not by its address range — because
  half the world is 192.168.0.x. Scans, history and approvals belong to a
  profile, so one network is never compared against another.
- An unrecognised network gets a prompt, not a silent mess, and each profile
  remembers what to scan there.

### Tells you without being asked

- **Scheduled rescans** from 1 minute to 6 hours, with a macOS notification when
  something changes — unapproved arrivals first, then new devices, ports
  opening, departures.
- **Watch the handful of things you care about**: a host, or one host and port,
  checked every minute, with a notification when it goes and when it returns,
  and a day of check history so a blip is distinguishable from an outage.
- **Lives in the menu bar**, showing how many devices are up. Closing the window
  hides it so schedules keep running.
- **Webhook on change**, posting the same payload the Changes tab shows. Slack
  and Discord URLs work as they are.

### Shows you the shape of it

- **A map, not just a list**: the gateway at the centre, everything orbiting it,
  with **distance from the centre showing round-trip time** and **size showing
  open ports**. Devices keep their position between scans, so movement means
  something.
- **Filter as you type** (⌘F): `synology`, `port:22`, `vendor:apple`, `new`,
  `unknown`, `risk`, `-dead`. Terms combine, and the map obeys the filter too.

### Points out what's worth a look

Telnet, exposed databases, an unauthenticated Docker socket, expired or
soon-to-expire certificates, obsolete TLS, login pages served over plain HTTP.
Each finding carries a severity and a sentence on why it matters.

These are outside-view inferences — nothing authenticates — so they report what
is **exposed**, not that it is broken. On a home network plenty of it is normal.

### Gets data out

CSV of the table, JSON of the whole scan (services, certificates, findings,
labels), or JSON of just the changes.

---

## Install

Download the latest `.dmg` from
[Releases](https://github.com/shapedthought/veryannoyedipscanner/releases/latest).
Universal build: Apple Silicon and Intel.

The app isn't code signed, so macOS will refuse it on the first launch:
right-click the app and choose **Open**, then confirm.

## Build it yourself

Needs [Rust](https://rustup.rs) and [Node](https://nodejs.org).

```sh
npm install
npm run dev      # development window
npm run build    # release bundle in src-tauri/target/release/bundle/
```

Tests:

```sh
cd src-tauri && cargo test    # scanning, parsing, history, diffing
node --test ui/*.test.js      # filtering and map layout
```

Refresh the MAC vendor table with `python3 scripts/update_oui.py` (source:
Wireshark's `manuf` file, derived from the IEEE registry).

## Where it keeps things

One SQLite database, holding scan history, device labels and approvals, network
profiles, watches and settings:

```
~/Library/Application Support/com.shapedthought.veryannoyedipscanner/history.sqlite
```

Nothing is sent anywhere unless you configure a webhook.

## Scanning other people's networks

Scan networks you run or have permission to scan. Port scanning elsewhere may be
unlawful where you are, and is rude everywhere.

## Licence

[MIT](LICENSE).

Vendor data comes from Wireshark's `manuf` file, itself derived from the public
IEEE OUI registry.
