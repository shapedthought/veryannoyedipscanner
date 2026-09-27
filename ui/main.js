const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const GRUMBLES = {
  start: [
    "Ugh. Fine. Scanning.",
    "You want me to knock on how many doors?",
    "Starting scan. Again. As always.",
    "Oh great, more packets. My favourite.",
  ],
  working: [
    "sighing loudly",
    "rolling eyes",
    "muttering under breath",
    "this is fine",
    "questioning life choices",
    "reading other people's web pages",
  ],
  done: [
    "Done. You're welcome, I guess.",
    "Finished. Can I go back to sleep now?",
    "There. Happy? Don't answer that.",
    "Scan complete. That was exhausting.",
  ],
  stop: [
    "Stopped. Make up your mind.",
    "Oh, NOW you want me to stop?",
    "Cancelled. All that effort, wasted.",
  ],
};
const pick = (list) => list[Math.floor(Math.random() * list.length)];

/** Port lists worth having to hand. "Quick" is the default set. */
const PORT_PRESETS = {
  Quick: "22,80,443,445,3389,5000,8080,8443",
  Web: "80,81,443,591,3000,5000,7080,8000,8008,8080,8081,8088,8443,8888,9000,9080,9443",
  Windows: "135,137,139,445,3389,5985,5986",
  Databases: "1433,1521,3306,5432,5984,6379,7000,7199,9042,9200,11211,27017",
  "Remote access": "22,23,513,514,3389,5800,5900,5901,5985,6000",
  "Home & IoT": "80,443,554,1883,5000,5353,7000,8009,8123,8883,9100,32400,62078",
  "Top 100": [
    7, 20, 21, 22, 23, 25, 53, 67, 80, 88, 110, 111, 123, 135, 137, 139, 143, 161, 389, 443,
    445, 465, 500, 514, 515, 520, 548, 554, 587, 623, 631, 636, 873, 902, 989, 990, 993, 995,
    1025, 1080, 1194, 1433, 1521, 1701, 1723, 1883, 1900, 2049, 2082, 2181, 2375, 2376, 3000,
    3128, 3260, 3268, 3306, 3389, 4444, 4500, 5000, 5060, 5222, 5353, 5432, 5555, 5601, 5672,
    5900, 5985, 6000, 6379, 6667, 7000, 7070, 8000, 8006, 8008, 8080, 8081, 8086, 8123, 8140,
    8443, 8883, 8888, 9000, 9042, 9100, 9200, 9418, 9999, 10000, 11211, 27017, 32400, 49152,
  ].join(","),
};

const $ = (id) => document.getElementById(id);
const el = {
  targets: $("targets"), targetCount: $("targetCount"), preset: $("preset"),
  scan: $("scan"), ports: $("ports"), timeout: $("timeout"), threads: $("threads"),
  banners: $("banners"), hideDead: $("hideDead"), exportBtn: $("export"),
  attempts: $("attempts"), trustArp: $("trustArp"), discover: $("discover"),
  auto: $("auto"), filter: $("filter"), profile: $("profile"),
  ask: $("ask"), askTitle: $("askTitle"), askBody: $("askBody"), askName: $("askName"),
  askTargets: $("askTargets"), askExisting: $("askExisting"), askProfile: $("askProfile"),
  askCreate: $("askCreate"), askSkip: $("askSkip"),
  rows: $("rows"), empty: $("empty"),
  status: $("status"), counts: $("counts"), progress: $("progress"),
  menu: $("menu"), toast: $("toast"),
  panel: $("panel"), togglePanel: $("togglePanel"), closePanel: $("closePanel"),
  changeCount: $("changeCount"),
  tabs: {
    host: $("tab-host"), changes: $("tab-changes"),
    history: $("tab-history"), settings: $("tab-settings"),
  },
};
const COLUMNS = ["ip", "ping", "hostname", "vendor", "mac", "ports", "details"];
const HEADINGS = {
  ip: "IP", ping: "Ping", hostname: "Name", vendor: "Vendor",
  mac: "MAC Address", ports: "Ports", details: "Details",
};

const state = {
  generation: 0,
  scanning: false,
  total: 0,
  done: 0,
  alive: 0,
  startedAt: 0,
  hosts: new Map(),     // ip -> host result
  view: [],             // hosts currently shown, in sort order
  sort: { col: "ip", dir: 1 },
  selected: null,       // ip
  currentScan: null,    // summary of the saved scan in the table, if any
  diff: null,           // diff shown in the Changes tab
  changes: new Map(),   // ip -> { kind: "new" | "changed", change? }
  history: [],
  devices: new Map(),   // device key -> { label, note, approved, ... }
  approvalsInUse: false,
  autoTimer: null,      // handle for the scheduled rescan
  autoStarted: false,   // this scan was started by the timer, not by you
  tab: "host",
  filterTerms: [],      // parsed once per keystroke, not once per row
  timeline: null,       // device history for the selected host, if loaded
  settings: {},         // webhook url and friends, as stored by the backend
  profiles: [],
  profile: null,        // the network we're scanning under
  network: null,        // what we detected about where we are
  declined: null,       // a fingerprint we've already been told not to ask about
  workingGrumble: pick(GRUMBLES.working),
};

// --------------------------------------------------------------------------
// Small helpers
// --------------------------------------------------------------------------

/** Build DOM safely: all strings become text nodes, never HTML. Titles and
 *  banners come from arbitrary devices on the network. */
function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "class") node.className = v;
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : String(child));
  }
  return node;
}

/** replaceChildren with the same flattening and skipping rules as h(). */
function fill(node, ...children) {
  node.replaceChildren(...children.flat(2).filter((c) => c != null && c !== false && c !== ""));
}

/** Scan options, as the Rust side expects them. */
function scanOptions() {
  return {
    timeoutMs: Number(el.timeout.value) || 800,
    attempts: Number(el.attempts.value) || 1,
    banners: el.banners.checked,
    trustArp: el.trustArp.checked,
    discover: el.discover.checked,
  };
}

const ipNum = (ip) => ip.split(".").reduce((n, o) => n * 256 + Number(o), 0);

function fmtDate(ms) {
  return new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function ago(ms) {
  const secs = (ms - Date.now()) / 1000;
  const rtf = new Intl.RelativeTimeFormat([], { numeric: "auto" });
  for (const [unit, size] of [["day", 86400], ["hour", 3600], ["minute", 60]]) {
    if (Math.abs(secs) >= size) return rtf.format(Math.round(secs / size), unit);
  }
  return "just now";
}

/** A device outlives its address, so identity is the MAC where we have one. */
const deviceKey = (host) => host.mac || `ip:${host.ip}`;
const deviceFor = (host) => state.devices.get(deviceKey(host));

/** Your name for it wins over the one it announces. */
const displayName = (host) => deviceFor(host)?.label || host.hostname || "";

/** Alive, and you haven't said it belongs here. Only meaningful once you've
 *  approved something, otherwise every device is "unknown". */
const isUnknown = (host) =>
  state.approvalsInUse && host.alive && !deviceFor(host)?.approved;

const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

// --------------------------------------------------------------------------
// Formatting & sorting
// --------------------------------------------------------------------------

/** The most useful one-liner per host: page titles and versions first, then
 *  redirect notes ("→ …"), then bare protocol names. */
function details(host) {
  const seen = new Set(host.discovered ?? []);
  const parts = [...seen];
  const rank = (s) => (!s.summary ? 2 : s.summary.startsWith("→") ? 1 : 0);
  const ranked = [...(host.services ?? [])].sort((a, b) => rank(a) - rank(b) || a.port - b.port);
  for (const s of ranked) {
    const text = s.summary || s.name;
    if (text && !seen.has(text)) {
      seen.add(text);
      parts.push(text);
    }
  }
  return parts.join(" · ");
}

function cell(host, col) {
  switch (col) {
    case "ping":
      if (host.ping_ms != null) return `${Math.round(host.ping_ms)} ms`;
      if (!host.alive) return "[dead]";
      // Alive without an echo reply: say what gave it away.
      return { arp: "[arp]", port: "[port]", mdns: "[mdns]" }[host.alive_via] ?? "[n/a]";
    case "ports":
      return host.ports.join(",");
    case "details":
      return details(host);
    case "hostname":
      return displayName(host);
    default:
      return host[col] ?? "";
  }
}

function sortKey(host, col) {
  switch (col) {
    case "ip": return ipNum(host.ip);
    case "ping": return host.ping_ms ?? Infinity;
    case "ports": return host.ports.length ? host.ports[0] : Infinity;
    default: return (cell(host, col) || "\uffff").toLowerCase(); // blanks last
  }
}

function compare(a, b) {
  const { col, dir } = state.sort;
  const ka = sortKey(a, col), kb = sortKey(b, col);
  if (ka < kb) return -dir;
  if (ka > kb) return dir;
  return ipNum(a.ip) - ipNum(b.ip);
}

/** The shape filter.js matches against: every searchable field, plus the
 *  flags a row carries. */
function filterRow(host) {
  const device = deviceFor(host);
  const change = state.changes.get(host.ip);
  const flags = new Set([host.alive ? "alive" : "dead"]);
  if (change?.kind === "new") flags.add("new");
  if (change?.kind === "changed") flags.add("changed");
  if (isUnknown(host)) flags.add("unknown");
  if (host.risks?.length) flags.add("risk");
  if (displayName(host)) flags.add("named");

  const fields = {
    ip: host.ip,
    name: displayName(host),
    vendor: host.vendor ?? "",
    mac: host.mac ?? "",
    note: device?.note ?? "",
    details: details(host),
    via: host.alive_via ?? "",
    ports: host.ports ?? [],
    flags,
  };
  return { ...fields, text: Object.values(fields).filter((v) => typeof v === "string").join(" ") };
}

const visible = (host) =>
  (host.alive || !el.hideDead.checked) && hostMatches(filterRow(host), state.filterTerms);
const rowClass = (host) => (host.ports.length ? "ports" : host.alive ? "alive" : "dead");

// --------------------------------------------------------------------------
// Changes (diff) bookkeeping
// --------------------------------------------------------------------------

function changeLabels(change) {
  const labels = [];
  if (change.old_ip) labels.push("MOVED");
  if (change.old_mac) labels.push("NEW MAC");
  if (change.opened.length || change.closed.length) labels.push("PORTS");
  if (change.old_hostname) labels.push("RENAMED");
  return labels;
}

function changeLines(change) {
  const lines = [];
  if (change.old_ip) lines.push(`Moved from ${change.old_ip}`);
  if (change.old_mac) lines.push(`Different device: MAC was ${change.old_mac}`);
  if (change.old_hostname) lines.push(`Was called ${change.old_hostname}`);
  if (change.opened.length) lines.push(h("span", { class: "plus" }, `+ opened ${change.opened.join(", ")}`));
  if (change.closed.length) lines.push(h("span", { class: "minus" }, `− closed ${change.closed.join(", ")}`));
  return lines;
}

function badges(ip) {
  const host = state.hosts.get(ip);
  const out = host && isUnknown(host) ? [h("span", { class: "badge unknown" }, "UNKNOWN")] : [];
  const risks = host?.risks ?? [];
  if (risks.length) {
    const worst = ["high", "medium", "low"].find((s) => risks.some((r) => r.severity === s));
    out.push(h("span", {
      class: `badge risk-${worst}`,
      title: risks.map((r) => r.title).join(" · "),
    }, `⚠ ${risks.length}`));
  }
  const c = state.changes.get(ip);
  if (!c) return out;
  if (c.kind === "new") out.push(h("span", { class: "badge new" }, "NEW"));
  else out.push(...changeLabels(c.change).map((l) => h("span", { class: "badge change" }, l)));
  return out;
}

function applyDiff(diff) {
  state.diff = diff;
  state.changes = new Map();
  if (diff) {
    for (const host of diff.added) state.changes.set(host.ip, { kind: "new" });
    for (const change of diff.changed) state.changes.set(change.host.ip, { kind: "changed", change });
  }
  const n = diff ? diff.added.length + diff.gone.length + diff.changed.length : 0;
  el.changeCount.textContent = n;
  el.changeCount.hidden = n === 0;
  renderAll();
  renderChanges();
  return n;
}

function diffSummary(diff) {
  const bits = [];
  if (diff.added.length) bits.push(`${diff.added.length} new`);
  if (diff.gone.length) bits.push(`${diff.gone.length} gone`);
  if (diff.changed.length) bits.push(`${diff.changed.length} changed`);
  return bits.join(", ");
}

// --------------------------------------------------------------------------
// Table rendering
// --------------------------------------------------------------------------

function makeRow(host) {
  const tr = h("tr", { "data-ip": host.ip, class: rowClass(host) });
  if (host.ip === state.selected) tr.classList.add("selected");
  for (const col of COLUMNS) {
    const text = cell(host, col);
    const td = h("td", {}, text);
    if (col === "ip") td.append(...badges(host.ip));
    if (["hostname", "vendor", "details"].includes(col) && text) td.title = text;
    tr.appendChild(td);
  }
  return tr;
}

/** Insert into the sorted view with a binary search, so rows stay ordered
 *  even though results arrive in whatever order the network feels like. */
function insertHost(host) {
  if (!visible(host)) return;
  let lo = 0, hi = state.view.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (compare(state.view[mid], host) < 0) lo = mid + 1;
    else hi = mid;
  }
  state.view.splice(lo, 0, host);
  el.rows.insertBefore(makeRow(host), el.rows.children[lo] ?? null);
}

function removeHost(ip) {
  const idx = state.view.findIndex((x) => x.ip === ip);
  if (idx >= 0) {
    state.view.splice(idx, 1);
    el.rows.children[idx].remove();
  }
}

function renderAll() {
  state.view = [...state.hosts.values()].filter(visible).sort(compare);
  const frag = document.createDocumentFragment();
  for (const host of state.view) frag.appendChild(makeRow(host));
  el.rows.replaceChildren(frag);
  updateChrome();
}

function updateChrome() {
  el.empty.hidden = state.view.length > 0;
  el.empty.textContent = state.hosts.size
    ? "Every host is dead. Or hiding. Either way, not my problem."
    : "Nothing here yet. Press Start, if you must.";
  for (const th of document.querySelectorAll("th[data-col]")) {
    th.classList.toggle("asc", th.dataset.col === state.sort.col && state.sort.dir === 1);
    th.classList.toggle("desc", th.dataset.col === state.sort.col && state.sort.dir === -1);
  }
  const hidden = state.hosts.size - state.view.length;
  const filtered = state.filterTerms.length ? ` · ${state.view.length} match` : "";
  el.counts.textContent = state.total
    ? `${state.done}/${state.total} scanned · ${state.alive} alive${filtered}`
    : "";
  if (state.filterTerms.length && state.hosts.size && !state.view.length) {
    el.empty.textContent = "Nothing matches that. Try asking for less.";
  } else if (hidden > 0 && !state.view.length) {
    el.empty.textContent = "Every host is dead. Or hiding. Either way, not my problem.";
  }
  el.progress.max = Math.max(state.total, 1);
  el.progress.value = state.done;
}

// --------------------------------------------------------------------------
// Side panel
// --------------------------------------------------------------------------

function openPanel(tab = state.tab) {
  state.tab = tab;
  el.panel.hidden = false;
  for (const btn of el.panel.querySelectorAll("[data-tab]")) {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  }
  for (const [name, body] of Object.entries(el.tabs)) body.hidden = name !== tab;
  if (tab === "host") {
    renderHost();
    const host = state.hosts.get(state.selected);
    if (host && !state.timeline) loadTimeline(host);
  }
  if (tab === "changes") renderChanges();
  if (tab === "history") refreshHistory();
  if (tab === "settings") renderSettings();
}

function closePanel() {
  el.panel.hidden = true;
}

function serviceCards(host) {
  const byPort = new Map((host.services ?? []).map((s) => [s.port, s]));
  return host.ports.map((port) => {
    const s = byPort.get(port);
    return h("div", { class: "card" },
      h("div", { class: "top" },
        h("span", { class: "port" }, port),
        h("span", { class: "muted" }, s?.name || "unknown"),
      ),
      s?.summary
        ? h("div", { class: "summary" }, s.summary)
        : h("div", { class: "sub" }, s ? "Didn't say anything useful." : "No idea what this is. It won't tell me."),
      s?.server && s.server !== s.summary && h("div", { class: "sub" }, `Server: ${s.server}`),
      s?.cert?.length > 0 && h("div", { class: "sub" }, `Certificate: ${s.cert.join(", ")}`),
    );
  });
}

const VIA = {
  icmp: "Alive (answered ping)",
  port: "Alive (ignored ping, but a port is open)",
  arp: "Alive (ignored ping, but answered ARP)",
  mdns: "Alive (announced itself over mDNS/SSDP)",
};
const aliveVia = (host) => VIA[host.alive_via] ?? "Alive";

/** Fetch the selected device's history, then redraw the panel with it. */
async function loadTimeline(host) {
  const key = deviceKey(host);
  state.timeline = null;
  try {
    const history = await invoke("device_history", { key, ip: host.ip });
    // The selection may have moved on while we were waiting.
    if (state.selected === host.ip) {
      state.timeline = history;
      renderHost();
    }
  } catch (err) {
    console.warn("timeline failed", err);
  }
}

/** Presence across past scans, plus the moments worth naming. */
function timelineSection(host) {
  const sightings = state.timeline?.sightings ?? [];
  if (sightings.length < 2) return null; // one scan is not a history

  const recent = sightings.slice(-40);
  const seen = sightings.filter((s) => s.present).length;
  const events = [];
  let previous = null;
  for (const sighting of sightings) {
    if (!sighting.present) continue;
    if (!previous) {
      events.push([sighting.at, "First seen here"]);
    } else {
      if (previous.ip !== sighting.ip) {
        events.push([sighting.at, `Moved from ${previous.ip} to ${sighting.ip}`]);
      }
      const opened = sighting.ports.filter((p) => !previous.ports.includes(p));
      const closed = previous.ports.filter((p) => !sighting.ports.includes(p));
      if (opened.length) events.push([sighting.at, `Opened ${opened.join(", ")}`]);
      if (closed.length) events.push([sighting.at, `Closed ${closed.join(", ")}`]);
    }
    previous = sighting;
  }

  return [
    h("h3", {}, "Over time"),
    h("div", {}, `Answered ${seen} of ${plural(sightings.length, "scan")} that looked here.`),
    h("div", { class: "strip" },
      ...recent.map((s) => h("div", {
        class: s.present ? "tick present" : "tick",
        title: `${fmtDate(s.at)} — ${s.present ? `${s.ip}${s.ports.length ? ` · ports ${s.ports.join(",")}` : ""}` : "no answer"}`,
      }))),
    events.length > 0 && h("div", { class: "events" },
      ...events.slice(-6).reverse().map(([at, text]) =>
        h("div", {}, h("span", { class: "when" }, `${fmtDate(at)} — `), text))),
  ];
}

function renderHost() {
  const body = el.tabs.host;
  const host = state.hosts.get(state.selected);
  if (!host) {
    fill(body, h("p", { class: "hint" }, "Pick a host. Any host. I'll wait. Grudgingly."));
    return;
  }
  const change = state.changes.get(host.ip);
  fill(body, 
    h("h2", {}, host.ip, ...badges(host.ip)),
    h("div", { class: "muted" }, host.hostname || "No hostname. Mysterious."),
    h("dl", { class: "facts" },
      h("dt", {}, "Status"), h("dd", {}, host.alive ? aliveVia(host) : "Dead"),
      h("dt", {}, "Ping"), h("dd", {}, cell(host, "ping")),
      h("dt", {}, "Vendor"), h("dd", {}, host.vendor || "—"),
      h("dt", {}, "MAC"), h("dd", {}, host.mac || "—"),
    ),
    change?.kind === "changed" && [
      h("h3", {}, `Changed since ${fmtDate(state.diff.old.finished_at)}`),
      ...changeLines(change.change).map((line) => h("div", {}, line)),
    ],
    change?.kind === "new" && [
      h("h3", {}, "New"),
      h("div", {}, `Wasn't here on ${fmtDate(state.diff.old.finished_at)}.`),
    ],
    host.discovered?.length > 0 && [
      h("h3", {}, "Announced"),
      h("div", {}, host.discovered.join(" · ")),
    ],
    host.risks?.length > 0 && [
      h("h3", {}, `Worth a look (${host.risks.length})`),
      ...host.risks.map((finding) =>
        h("div", { class: "finding" },
          h("span", { class: `chip ${finding.severity}` }, finding.severity),
          h("div", {},
            h("div", {}, `${finding.title}${finding.port ? ` (port ${finding.port})` : ""}`),
            h("div", { class: "why" }, finding.detail),
          ),
        )),
    ],
    deviceSection(host),
    timelineSection(host),
    h("h3", {}, `Open ports (${host.ports.length})`),
    host.ports.length
      ? [
          ...serviceCards(host),
          !host.services?.length && host.alive &&
            h("p", { class: "muted" }, "Turn on “Identify services” and rescan to see what these are."),
        ]
      : h("p", { class: "muted" }, "None of the ports you asked about. Doors all shut."),
  );
}

/** Naming and approving, plus when this device was first and last seen. */
function deviceSection(host) {
  const device = deviceFor(host) ?? {};
  const label = h("input", { type: "text", value: device.label ?? "", placeholder: host.hostname || "Give it a name" });
  const note = h("textarea", { placeholder: "Notes, if it needs explaining" }, device.note ?? "");
  const saved = h("span", { class: "saved", hidden: true }, "Saved");

  const save = () => saveDevice(host, label.value, note.value).then(() => {
    saved.hidden = false;
    setTimeout(() => (saved.hidden = true), 1500);
  });
  label.addEventListener("keydown", (e) => e.key === "Enter" && save());

  return [
    h("h3", {}, "This device"),
    h("label", { class: "field" }, "Name", label),
    h("label", { class: "field" }, "Note", note),
    h("div", { class: "device-actions" },
      h("button", { type: "button", class: "small", onclick: save }, "Save"),
      h("button", {
        type: "button",
        class: device.approved ? "small" : "small primary",
        onclick: () => setApproved(host, !device.approved),
      }, device.approved ? "Un-approve" : "Approve"),
      saved,
    ),
    device.first_seen > 0 && h("div", { class: "sub" },
      `First seen ${fmtDate(device.first_seen)} · last seen ${fmtDate(device.last_seen)}`),
    !host.mac && h("div", { class: "sub" },
      "No MAC address, so this is remembered by IP and won't follow the device."),
  ];
}

function hostCard(host, lines, { clickable = true, note } = {}) {
  return h("div", {
      class: clickable ? "card clickable" : "card",
      onclick: clickable ? () => focusHost(host.ip) : null,
    },
    h("div", { class: "top" },
      h("span", { class: "port" }, host.ip),
      h("span", { class: "muted" }, host.vendor || host.hostname || host.mac || ""),
    ),
    (host.hostname && host.vendor) && h("div", { class: "sub" }, host.hostname),
    details(host) && h("div", { class: "sub" }, details(host)),
    ...lines.map((l) => h("div", { class: "summary" }, l)),
    note && h("div", { class: "sub" }, note),
  );
}

function renderChanges() {
  const body = el.tabs.changes;
  const diff = state.diff;
  if (!diff) {
    fill(body, h("p", { class: "hint" },
      "No comparison yet. Scan the same range twice and I'll tell you what changed. " +
      "Or compare two scans from History, if you enjoy that sort of thing."));
    return;
  }
  const total = diff.added.length + diff.gone.length + diff.changed.length;
  fill(body, 
    h("div", { class: "diff-head" },
      h("div", {}, h("strong", {}, fmtDate(diff.new.finished_at)), " vs ", fmtDate(diff.old.finished_at)),
      h("div", { class: "muted" }, `${diff.new.range_start} – ${diff.new.range_end}`),
    ),
    total === 0 && h("p", { class: "hint" }, "Nothing changed. Riveting."),
    diff.added.length > 0 && [
      h("h3", {}, `New (${diff.added.length})`),
      ...diff.added.map((host) => hostCard(host, [])),
    ],
    diff.changed.length > 0 && [
      h("h3", {}, `Changed (${diff.changed.length})`),
      ...diff.changed.map((c) => hostCard(c.host, changeLines(c))),
    ],
    diff.gone.length > 0 && [
      h("h3", {}, `Gone (${diff.gone.length})`),
      ...diff.gone.map((host) => hostCard(host, [], {
        clickable: false,
        note: `Last seen ${fmtDate(diff.old.finished_at)}${host.ports.length ? ` · ports ${host.ports.join(",")}` : ""}`,
      })),
    ],
  );
}

async function refreshDevices() {
  try {
    const [devices, inUse] = await Promise.all([
      invoke("list_devices"),
      invoke("approvals_in_use", { profileId: state.profile?.id ?? null }),
    ]);
    state.devices = new Map(devices.map((d) => [d.key, d]));
    state.approvalsInUse = inUse;
  } catch (err) {
    toast(String(err), true);
  }
}

async function saveDevice(host, label, note) {
  const key = deviceKey(host);
  try {
    await invoke("set_device_label", { key, label, note });
    await refreshDevices();
    renderAll();
    renderHost();
  } catch (err) {
    toast(String(err), true);
  }
}

async function setApproved(host, approved) {
  const key = deviceKey(host);
  try {
    await invoke("set_device_approved", { key, approved });
    await refreshDevices();
    renderAll();
    renderHost();
    updateTray();
    setStatus(approved
      ? `${displayName(host) || host.ip} approved. One less thing to worry about.`
      : `${displayName(host) || host.ip} un-approved. Suspicious, are we?`);
  } catch (err) {
    toast(String(err), true);
  }
}

async function loadSettings() {
  try {
    state.settings = await invoke("get_settings");
  } catch (err) {
    console.warn("settings failed", err);
  }
}

async function saveSetting(key, value) {
  state.settings[key] = value;
  try {
    await invoke("set_setting", { key, value });
  } catch (err) {
    toast(String(err), true);
  }
}

function renderSettings() {
  const body = el.tabs.settings;
  const url = h("input", {
    type: "url",
    value: state.settings.webhook_url ?? "",
    placeholder: "https://hooks.slack.com/services/…",
  });
  const onChange = h("input", { type: "checkbox" });
  onChange.checked = state.settings.webhook_on_change === "yes";

  url.addEventListener("change", () => saveSetting("webhook_url", url.value.trim()));
  onChange.addEventListener("change", () =>
    saveSetting("webhook_on_change", onChange.checked ? "yes" : "no"));

  fill(body,
    h("h3", {}, "Webhook"),
    h("p", { class: "muted" },
      "Posts JSON when a scan finds changes: what arrived, what left, what opened a port. " +
      "Slack and Discord webhook URLs work as they are; anything else gets the same JSON."),
    h("label", { class: "field" }, "URL", url),
    h("label", { class: "check" }, onChange, " Send it when a scan finds changes"),
    h("div", { class: "device-actions" },
      h("button", { type: "button", class: "small", onclick: async () => {
        if (!url.value.trim()) return toast("Give it a URL first.");
        await saveSetting("webhook_url", url.value.trim());
        setStatus("Poking the webhook…");
        await sendWebhook({
          text: "Very Annoyed IP Scanner: test message. Ignore me.",
          content: "Very Annoyed IP Scanner: test message. Ignore me.",
          test: true,
        });
      } }, "Send a test"),
    ),
    h("p", { class: "muted" },
      "Whatever you point this at will see device names, addresses and open ports."),
  );
}

async function refreshHistory() {
  try {
    state.history = await invoke("list_scans", { profileId: state.profile?.id ?? null });
  } catch (err) {
    toast(String(err), true);
  }
  renderHistory();
}

function renderHistory() {
  const body = el.tabs.history;
  if (!state.history.length) {
    fill(body, h("p", { class: "hint" }, "No history. You haven't made me do anything yet."));
    return;
  }
  const current = state.currentScan?.id;
  fill(body, 
    h("p", { class: "muted" }, "Completed scans are saved automatically. Stopped ones aren't, because half a scan is a lie."),
    ...state.history.map((scan) => {
      const secs = Math.max(1, Math.round((scan.finished_at - scan.started_at) / 1000));
      const del = h("button", { type: "button", class: "small" }, "Delete");
      del.addEventListener("click", () => deleteScan(scan.id, del));
      return h("div", { class: scan.id === current ? "card current" : "card" },
        h("div", { class: "top" },
          h("strong", {}, fmtDate(scan.finished_at)),
          h("span", { class: "muted" }, ago(scan.finished_at)),
          scan.suspect && h("span", { class: "badge change", title: "Found nothing where something was expected, so it isn't used as a baseline" }, "IGNORED"),
        ),
        h("div", { class: "sub" }, `${scan.range_start} – ${scan.range_end}`),
        h("div", { class: "sub" },
          `${scan.alive} of ${scan.total} alive · ${plural(scan.ports.length, "port")} · ${secs}s`),
        h("div", { class: "actions" },
          h("button", { type: "button", class: "small", onclick: () => viewScan(scan.id),
            disabled: scan.id === current || state.scanning }, scan.id === current ? "Showing" : "View"),
          h("button", { type: "button", class: "small", onclick: () => compareWith(scan.id),
            disabled: !current || scan.id === current,
            title: current ? "Compare with the scan in the table" : "Run or view a scan first" }, "Compare"),
          del,
        ),
      );
    }),
  );
}

/** The previous scan of the same range: the automatic baseline. */
function baselineFor(scan) {
  return state.history.find((s) =>
    s.id < scan.id && s.range_start === scan.range_start && s.range_end === scan.range_end);
}

async function viewScan(id) {
  try {
    const saved = await invoke("load_scan", { id });
    const s = saved.summary;
    state.hosts = new Map(saved.hosts.map((host) => [host.ip, host]));
    Object.assign(state, {
      currentScan: s, total: s.total, done: s.total, alive: s.alive, selected: null,
    });
    el.targets.value = s.targets || `${s.range_start}-${s.range_end}`;
    previewTargets();
    const base = baselineFor(s);
    applyDiff(base ? await invoke("compare_scans", { a: base.id, b: s.id }) : null);
    renderHistory();
    renderHost();
    setStatus(`Viewing the scan from ${fmtDate(s.finished_at)}. Press Start for a fresh one.`);
  } catch (err) {
    toast(String(err), true);
  }
}

async function compareWith(id) {
  if (!state.currentScan) return;
  try {
    const diff = await invoke("compare_scans", { a: id, b: state.currentScan.id });
    const n = applyDiff(diff);
    openPanel("changes");
    setStatus(n ? `Compared: ${diffSummary(diff)}.` : "Compared. Identical. Thrilling.");
  } catch (err) {
    toast(String(err), true);
  }
}

async function deleteScan(id, button) {
  // Two clicks rather than a modal dialog.
  if (button.dataset.armed !== "1") {
    button.dataset.armed = "1";
    button.textContent = "Really?";
    setTimeout(() => {
      button.dataset.armed = "";
      button.textContent = "Delete";
    }, 3000);
    return;
  }
  try {
    await invoke("delete_scan", { id });
    if (state.currentScan?.id === id) state.currentScan = null;
    if (state.diff && (state.diff.old.id === id || state.diff.new.id === id)) applyDiff(null);
    await refreshHistory();
    toast("Deleted. Gone forever. Like my patience.");
  } catch (err) {
    toast(String(err), true);
  }
}

function focusHost(ip) {
  select(ip);
  el.rows.querySelector(`tr[data-ip="${ip}"]`)?.scrollIntoView({ block: "center" });
  openPanel("host");
}

// --------------------------------------------------------------------------
// Feedback
// --------------------------------------------------------------------------

let toastTimer;
function toast(message, isError = false) {
  el.toast.textContent = message;
  el.toast.classList.toggle("error", isError);
  el.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.toast.hidden = true), isError ? 4500 : 2200);
}

const setStatus = (text) => (el.status.textContent = text);

async function copy(text) {
  if (!text) return toast("There's nothing to copy. Obviously.");
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  toast(`Copied ${text}. Don't say I never do anything for you.`);
}

// --------------------------------------------------------------------------
// Scanning
// --------------------------------------------------------------------------

function setScanning(on) {
  state.scanning = on;
  el.scan.textContent = on ? "■ Stop" : "▶ Start";
  el.scan.disabled = false;
  for (const input of [el.targets, el.preset, el.ports, el.timeout,
                       el.threads, el.banners, el.attempts, el.trustArp, el.discover]) {
    input.disabled = on;
  }
}

async function toggleScan() {
  // Moving between networks mid-session is exactly when this matters.
  if (!state.scanning) await checkNetwork();
  if (!el.ask.hidden) return; // waiting on an answer about where we are
  if (state.scanning) {
    el.scan.disabled = true;
    setStatus("Stopping… hold your horses.");
    await invoke("stop_scan");
    return;
  }
  try {
    const started = await invoke("start_scan", {
      targets: el.targets.value,
      ports: el.ports.value,
      threads: Number(el.threads.value) || 64,
      options: scanOptions(),
    });
    if (state.profile && el.targets.value.trim() !== state.profile.targets) {
      invoke("remember_targets", { id: state.profile.id, targets: el.targets.value.trim() })
        .catch((err) => console.warn("couldn't remember targets", err));
      state.profile.targets = el.targets.value.trim();
    }
    Object.assign(state, {
      generation: started.generation,
      total: started.total,
      done: 0,
      alive: 0,
      startedAt: performance.now(),
      selected: null,
      currentScan: null,
      workingGrumble: pick(GRUMBLES.working),
    });
    state.hosts.clear();
    applyDiff(null);
    renderHost();
    setScanning(true);
    setStatus(started.discovering
      ? "Listening for anyone who'll introduce themselves…"
      : pick(GRUMBLES.start));
  } catch (err) {
    toast(`I can't work with this.\n${err}`, true);
  }
}

listen("scan-row", ({ payload }) => {
  if (payload.generation !== state.generation) return;
  const host = payload.host;
  state.done += 1;
  if (host.alive) state.alive += 1;
  state.hosts.set(host.ip, host);
  insertHost(host);
  if (state.done % 25 === 0) state.workingGrumble = pick(GRUMBLES.working);
  setStatus(`Scanning… ${state.workingGrumble}`);
  updateChrome();
});

listen("scan-done", async ({ payload }) => {
  if (payload.generation !== state.generation) return;
  const secs = ((performance.now() - state.startedAt) / 1000).toFixed(1);
  setScanning(false);
  updateChrome();
  const tally = `${state.alive} alive of ${state.done} in ${secs}s.`;

  if (payload.cancelled) {
    state.autoStarted = false;
    setStatus(`${pick(GRUMBLES.stop)}  ${tally} Not saved to history.`);
    return;
  }
  if (payload.error) toast(payload.error, true);

  if (payload.suspect) {
    // Nothing found where there was something last time: almost always the
    // scan's fault, so say so rather than reporting an empty network.
    setScanning(false);
    await refreshHistory();
    renderHistory();
    setStatus(`${tally} That's nothing at all, where there was something last time. ` +
      "Wrong network? Wrong range? I've kept it out of the comparisons.");
    toast("Found nothing. Not using that as a baseline.", true);
    updateTray();
    return;
  }

  await Promise.all([refreshHistory(), refreshDevices()]);
  state.currentScan = state.history.find((s) => s.id === payload.scan_id) ?? null;
  renderHistory();

  const diff = payload.diff;
  const n = applyDiff(diff ?? null);
  if (!diff) {
    setStatus(`${pick(GRUMBLES.done)}  ${tally} First scan of this range: saved. Next time I'll tell you what changed. Joy.`);
  } else if (n === 0) {
    setStatus(`${pick(GRUMBLES.done)}  ${tally} Nothing changed since ${ago(diff.old.finished_at)}. Riveting.`);
  } else {
    setStatus(`${pick(GRUMBLES.done)}  ${tally} Since ${ago(diff.old.finished_at)}: ${diffSummary(diff)}.`);
    openPanel("changes");
  }
  updateTray();
  if (diff && n > 0 && state.settings.webhook_on_change === "yes") {
    sendWebhook(changesPayload(), { quiet: true });
  }
  // Only for scans you didn't start: you're already looking at the others.
  if (state.autoStarted && diff) await notifyAbout(diff);
  state.autoStarted = false;

  const flagged = [...state.hosts.values()].filter((host) => host.risks?.length).length;
  if (flagged) {
    setStatus(`${el.status.textContent} ${plural(flagged, "device")} worth a look.`);
  }
  const unknown = [...state.hosts.values()].filter(isUnknown).length;
  if (unknown) {
    setStatus(`${el.status.textContent} ${plural(unknown, "device")} you haven't approved.`);
  }
});

async function rescan(ip) {
  setStatus(`Rescanning ${ip}. Like I don't have better things to do.`);
  try {
    const host = await invoke("rescan_host", { ip, ports: el.ports.value, options: scanOptions() });
    const old = state.hosts.get(ip);
    if (old) state.alive += Number(host.alive) - Number(old.alive);
    state.hosts.set(ip, host);
    removeHost(ip);
    insertHost(host);
    updateChrome();
    if (state.selected === ip) renderHost();
    setStatus(`Rescanned ${ip}. ${host.alive ? "Still alive." : "Still dead. Shocking."}`);
  } catch (err) {
    toast(String(err), true);
  }
}

/** Say what the targets add up to, so mistakes are visible before scanning. */
async function previewTargets() {
  const text = el.targets.value.trim();
  if (!text) {
    el.targetCount.textContent = "";
    return;
  }
  try {
    const preview = await invoke("preview_targets", { targets: text });
    const span = preview.count > 1 ? ` (${preview.start} – ${preview.end})` : "";
    el.targetCount.textContent = `${preview.count.toLocaleString()} addresses${span}`;
    el.targetCount.classList.remove("error-text");
  } catch {
    // The full complaint can wait until they press Start.
    el.targetCount.textContent = "not a valid target";
    el.targetCount.classList.add("error-text");
  }
}

function csvContent() {
  const quote = (v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  const lines = [COLUMNS.map((c) => HEADINGS[c]).join(",")];
  for (const host of state.view) lines.push(COLUMNS.map((c) => quote(String(cell(host, c)))).join(","));
  return lines.join("\n") + "\n";
}

/** The whole scan: hosts as the backend gave them, plus your labels. */
function scanJson() {
  return JSON.stringify({
    scan: state.currentScan,
    exported_at: new Date().toISOString(),
    hosts: state.view.map((host) => ({
      ...host,
      label: deviceFor(host)?.label ?? "",
      approved: deviceFor(host)?.approved ?? false,
    })),
  }, null, 2);
}

/** The diff, in the shape the Changes tab shows and webhooks receive. */
function changesJson() {
  return JSON.stringify({ ...changesPayload(), exported_at: new Date().toISOString() }, null, 2);
}

async function exportAs(kind) {
  if (!state.hosts.size) return toast("Export what? You haven't scanned anything.");
  if (kind === "changes" && !state.diff) return toast("No changes to export. Scan the same range twice.");
  const stamp = new Date().toISOString().slice(0, 10);
  const { content, name, extension } = {
    csv: { content: csvContent(), name: `annoyed-scan-${stamp}.csv`, extension: "csv" },
    json: { content: scanJson(), name: `annoyed-scan-${stamp}.json`, extension: "json" },
    changes: { content: changesJson(), name: `annoyed-changes-${stamp}.json`, extension: "json" },
  }[kind];
  try {
    const path = await invoke("save_export", { content, fileName: name, extension });
    if (path) setStatus(`Exported to ${path}. Fine.`);
  } catch (err) {
    toast(`Couldn't save that.\n${err}`, true);
  }
}

// --------------------------------------------------------------------------
// Networks
// --------------------------------------------------------------------------

function renderProfiles() {
  fill(el.profile,
    ...state.profiles.map((p) => h("option", { value: p.id }, p.name)),
    h("option", { value: "" }, state.profiles.length ? "Not set" : "No networks yet"),
    state.network && !state.network.profile && h("option", { value: "new" }, "Add this network…"));
  el.profile.value = state.profile ? String(state.profile.id) : "";
}

async function setProfile(id) {
  state.profile = await invoke("use_profile", { id });
  if (state.profile?.targets) {
    el.targets.value = state.profile.targets;
    previewTargets();
  }
  await Promise.all([refreshHistory(), refreshDevices()]);
  renderProfiles();
  renderAll();
  return state.profile;
}

/** Work out where we are, and ask about it if it's somewhere new. */
async function checkNetwork({ askIfUnknown = true } = {}) {
  try {
    state.network = await invoke("current_network");
    state.profiles = await invoke("list_profiles");
  } catch (err) {
    console.warn("network detection failed", err);
    return;
  }
  const known = state.network.profile;
  if (known) {
    if (state.profile?.id !== known.id) {
      await setProfile(known.id);
      setStatus(`${known.name}. I know this one.`);
    } else {
      renderProfiles();
    }
    return;
  }
  // Somewhere new: don't let the previous network's history apply to it.
  if (state.profile) await setProfile(null);
  renderProfiles();
  // Asked once and waved away: don't nag on every scan.
  if (askIfUnknown && state.declined !== state.network.fingerprint.id) askAboutNetwork();
}

function askAboutNetwork() {
  const { fingerprint, suggested_name: suggested } = state.network ?? {};
  if (!fingerprint) return;
  const where = [
    fingerprint.ssid && `“${fingerprint.ssid}”`,
    fingerprint.gateway_ip && `gateway ${fingerprint.gateway_ip}`,
    fingerprint.gateway_mac && `(${fingerprint.gateway_mac})`,
  ].filter(Boolean).join(" ");

  el.askBody.textContent =
    `This is somewhere I haven't scanned before: ${where}. ` +
    "Kept as its own network, its scans won't be compared with anywhere else — " +
    "which matters, since half the world uses the same addresses.";
  el.askName.value = suggested ?? "";
  el.askTargets.value = fingerprint.subnet ?? el.targets.value;

  const others = state.profiles;
  el.askExisting.hidden = others.length === 0;
  fill(el.askProfile,
    h("option", { value: "" }, "Choose…"),
    ...others.map((p) => h("option", { value: p.id }, p.name)));

  el.ask.hidden = false;
  el.askName.focus();
  el.askName.select();
}

async function rememberNetwork() {
  const fingerprint = state.network?.fingerprint;
  if (!fingerprint) return;
  state.declined = null;
  const targets = el.askTargets.value.trim() || fingerprint.subnet;
  try {
    const profile = await invoke("create_profile", {
      name: el.askName.value.trim() || state.network.suggested_name,
      fingerprint: fingerprint.id,
      targets,
      subnet: fingerprint.subnet,
    });
    state.profiles = await invoke("list_profiles");
    el.ask.hidden = true;
    await setProfile(profile.id);
    setStatus(`${profile.name} it is. I'll keep its scans to itself.`);
  } catch (err) {
    toast(String(err), true);
  }
}

// --------------------------------------------------------------------------
// Webhook
// --------------------------------------------------------------------------

/** The diff, plus a sentence. `text` and `content` are what Slack and Discord
 *  render, so a plain webhook URL from either works without any mapping. */
function changesPayload() {
  const diff = state.diff;
  const name = (host) => displayName(host) || host.vendor || host.ip;
  const brief = diff ? diffSummary(diff) : "nothing";
  const sentence = `Very Annoyed IP Scanner: ${brief} since ${fmtDate(diff?.old?.finished_at ?? Date.now())}`;
  const describe = (host) => ({
    ip: host.ip,
    name: name(host),
    mac: host.mac,
    vendor: host.vendor,
    ports: host.ports,
    approved: deviceFor(host)?.approved ?? false,
  });
  return {
    text: sentence,
    content: sentence,
    scan: diff?.new ?? state.currentScan,
    since: diff?.old ?? null,
    added: (diff?.added ?? []).map(describe),
    gone: (diff?.gone ?? []).map(describe),
    changed: (diff?.changed ?? []).map((change) => ({
      ...describe(change.host),
      opened: change.opened,
      closed: change.closed,
      moved_from: change.old_ip ?? null,
      previous_mac: change.old_mac ?? null,
    })),
  };
}

async function sendWebhook(payload, { quiet = false } = {}) {
  const url = state.settings.webhook_url?.trim();
  if (!url) return;
  try {
    const answer = await invoke("send_webhook", { url, payload });
    if (!quiet) setStatus(`Webhook accepted it: ${answer}`);
  } catch (err) {
    toast(`Webhook failed.\n${err}`, true);
  }
}

// --------------------------------------------------------------------------
// Menu bar
// --------------------------------------------------------------------------

/** Keep the menu bar current: the count sits by the icon, the sentence is the
 *  first line of its menu. */
async function updateTray() {
  const alive = [...state.hosts.values()].filter((host) => host.alive);
  const unknown = alive.filter(isUnknown).length;
  const when = state.currentScan ? fmtDate(state.currentScan.finished_at) : "just now";
  const parts = [`${plural(alive.length, "device")} up`];
  if (unknown) parts.push(`${unknown} unapproved`);
  try {
    await invoke("update_tray", {
      count: alive.length ? String(alive.length) : null,
      summary: `${parts.join(" · ")} — ${when}`,
    });
  } catch (err) {
    console.warn("tray update failed", err);
  }
}

// "Scan now" from the menu, possibly with the window hidden.
listen("tray-scan", () => {
  if (state.scanning) return;
  state.autoStarted = true; // you're not watching the table, so do notify
  toggleScan();
});

// --------------------------------------------------------------------------
// Scheduled rescans
// --------------------------------------------------------------------------

function setSchedule(ms) {
  clearInterval(state.autoTimer);
  state.autoTimer = null;
  if (!ms) {
    setStatus("Auto-scan off. Back to doing this by hand, then.");
    return;
  }
  state.autoTimer = setInterval(() => {
    // Never interrupt a scan in progress, or one you started yourself.
    if (state.scanning) return;
    state.autoStarted = true;
    toggleScan();
  }, ms);
  const every = el.auto.selectedOptions[0]?.textContent ?? `${ms} ms`;
  setStatus(`Fine. I'll look again every ${every.toLowerCase()} and tell you if anything changes.`);
}

/** What's worth interrupting someone for, most alarming first. */
function notification(diff) {
  const unapproved = diff.added.filter((host) => isUnknown(host));
  const name = (host) => displayName(host) || host.vendor || host.ip;

  if (unapproved.length) {
    return {
      title: `${plural(unapproved.length, "device")} you haven't approved`,
      body: unapproved.map(name).join(", "),
    };
  }
  if (diff.added.length) {
    return { title: `${plural(diff.added.length, "new device")}`, body: diff.added.map(name).join(", ") };
  }
  const opened = diff.changed.filter((c) => c.opened.length);
  if (opened.length) {
    return {
      title: "Ports opened",
      body: opened.map((c) => `${name(c.host)}: ${c.opened.join(", ")}`).join(" · "),
    };
  }
  if (diff.gone.length) {
    return { title: `${plural(diff.gone.length, "device")} gone`, body: diff.gone.map(name).join(", ") };
  }
  return null;
}

async function notifyAbout(diff) {
  const message = notification(diff);
  if (!message) return;
  try {
    await invoke("notify", { title: `😤 ${message.title}`, body: message.body });
  } catch (err) {
    // A refused notification shouldn't derail the scan that found something.
    console.warn("notification failed", err);
  }
}

// --------------------------------------------------------------------------
// Interaction
// --------------------------------------------------------------------------

function select(ip) {
  if (state.selected !== ip) state.timeline = null;
  state.selected = ip;
  for (const tr of el.rows.querySelectorAll("tr.selected")) tr.classList.remove("selected");
  el.rows.querySelector(`tr[data-ip="${ip}"]`)?.classList.add("selected");
  if (!el.panel.hidden && state.tab === "host") {
    renderHost();
    const host = state.hosts.get(ip);
    if (host) loadTimeline(host);
  }
}

el.rows.addEventListener("click", (e) => {
  const tr = e.target.closest("tr");
  if (tr) select(tr.dataset.ip);
});

el.rows.addEventListener("dblclick", (e) => {
  const tr = e.target.closest("tr");
  if (tr) focusHost(tr.dataset.ip);
});

el.rows.addEventListener("contextmenu", (e) => {
  const tr = e.target.closest("tr");
  if (!tr) return;
  e.preventDefault();
  select(tr.dataset.ip);
  const host = state.hosts.get(tr.dataset.ip);
  el.menu.querySelector('[data-act="approve"]').textContent =
    deviceFor(host)?.approved ? "Un-approve this device" : "Approve this device";
  el.menu.hidden = false;
  const { innerWidth: w, innerHeight: ht } = window;
  const { offsetWidth: mw, offsetHeight: mh } = el.menu;
  el.menu.style.left = `${Math.min(e.clientX, w - mw - 4)}px`;
  el.menu.style.top = `${Math.min(e.clientY, ht - mh - 4)}px`;
});

el.menu.addEventListener("click", (e) => {
  const act = e.target.dataset.act;
  const host = state.hosts.get(state.selected);
  if (!el.menu.hidden && host) {
    el.menu.querySelector('[data-act="approve"]').textContent =
      deviceFor(host)?.approved ? "Un-approve this device" : "Approve this device";
  }
  el.menu.hidden = true;
  if (!act || !host) return;
  if (act === "rescan") rescan(host.ip);
  else if (act === "approve") setApproved(host, !deviceFor(host)?.approved);
  else if (act === "details") focusHost(host.ip);
  else copy(cell(host, act));
});

document.addEventListener("click", (e) => {
  if (!el.menu.contains(e.target)) el.menu.hidden = true;
});
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "f") {
    e.preventDefault();
    el.filter.focus();
    el.filter.select();
  }
  if (e.key === "Escape") {
    if (!el.menu.hidden) el.menu.hidden = true;
    else closePanel();
  }
  if ((e.metaKey || e.ctrlKey) && e.key === "c" && state.selected &&
      !e.target.closest("input") && !window.getSelection().toString()) {
    copy(state.selected);
  }
});
document.addEventListener("contextmenu", (e) => {
  if (!e.target.closest("input")) e.preventDefault();
});

for (const th of document.querySelectorAll("th[data-col]")) {
  th.addEventListener("click", () => {
    const col = th.dataset.col;
    state.sort = { col, dir: state.sort.col === col ? -state.sort.dir : 1 };
    renderAll();
  });
}

for (const btn of el.panel.querySelectorAll("[data-tab]")) {
  btn.addEventListener("click", () => openPanel(btn.dataset.tab));
}
el.closePanel.addEventListener("click", closePanel);
el.togglePanel.addEventListener("click", () => (el.panel.hidden ? openPanel() : closePanel()));

el.scan.addEventListener("click", toggleScan);
el.targets.addEventListener("input", previewTargets);
el.preset.addEventListener("change", () => {
  const ports = PORT_PRESETS[el.preset.value];
  if (ports) {
    el.ports.value = ports;
    setStatus(`${el.preset.value}: ${ports.split(",").length} ports. Your funeral.`);
  }
  el.preset.value = "";
});
for (const input of [el.targets, el.ports, el.timeout, el.threads]) {
  input.addEventListener("keydown", (e) => e.key === "Enter" && !state.scanning && toggleScan());
}
el.hideDead.addEventListener("change", renderAll);
el.profile.addEventListener("change", async () => {
  if (el.profile.value === "new") {
    renderProfiles(); // put the selection back while the dialog decides
    askAboutNetwork();
    return;
  }
  const id = el.profile.value ? Number(el.profile.value) : null;
  const profile = await setProfile(id);
  setStatus(profile ? `Scanning as ${profile.name}.` : "No network profile. Nothing is compared.");
});
el.askCreate.addEventListener("click", rememberNetwork);
el.askSkip.addEventListener("click", () => {
  el.ask.hidden = true;
  state.declined = state.network?.fingerprint?.id ?? null;
  setStatus("Fine, stay anonymous. Nothing here is compared with anywhere else. " +
    "Say “Add this network” in the Network menu if you change your mind.");
});
el.askProfile.addEventListener("change", async () => {
  if (!el.askProfile.value) return;
  el.ask.hidden = true;
  const profile = await setProfile(Number(el.askProfile.value));
  // Same profile, new fingerprint: remember this one too (new router, say).
  if (profile && state.network?.fingerprint) {
    await invoke("create_profile", {
      name: profile.name,
      fingerprint: state.network.fingerprint.id,
      targets: profile.targets || el.targets.value.trim(),
      subnet: state.network.fingerprint.subnet,
    }).catch((err) => toast(String(err), true));
    state.profiles = await invoke("list_profiles");
    renderProfiles();
  }
  setStatus(`Treating this as ${profile?.name}.`);
});

el.filter.addEventListener("input", () => {
  state.filterTerms = parseFilter(el.filter.value);
  renderAll();
});
el.filter.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && el.filter.value) {
    e.stopPropagation(); // don't also close the panel
    el.filter.value = "";
    state.filterTerms = [];
    renderAll();
  }
});
el.auto.addEventListener("change", () => setSchedule(Number(el.auto.value)));
el.exportBtn.addEventListener("change", () => {
  const kind = el.exportBtn.value;
  el.exportBtn.value = "";
  if (kind) exportAs(kind);
});

// --------------------------------------------------------------------------
// Boot
// --------------------------------------------------------------------------

for (const name of Object.keys(PORT_PRESETS)) {
  el.preset.append(h("option", { value: name }, name));
}

invoke("local_range").then((r) => {
  el.targets.value = r.cidr;
  previewTargets();
  // Then let the network we're actually on have the final say.
  checkNetwork();
});
refreshHistory();
loadSettings();
refreshDevices().then(renderAll);
updateChrome();
