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

const $ = (id) => document.getElementById(id);
const el = {
  start: $("start"), end: $("end"), cidr: $("cidr"), apply: $("apply"),
  scan: $("scan"), ports: $("ports"), timeout: $("timeout"), threads: $("threads"),
  banners: $("banners"), hideDead: $("hideDead"), exportBtn: $("export"),
  attempts: $("attempts"), trustArp: $("trustArp"), discover: $("discover"),
  rows: $("rows"), empty: $("empty"),
  status: $("status"), counts: $("counts"), progress: $("progress"),
  menu: $("menu"), toast: $("toast"),
  panel: $("panel"), togglePanel: $("togglePanel"), closePanel: $("closePanel"),
  changeCount: $("changeCount"),
  tabs: { host: $("tab-host"), changes: $("tab-changes"), history: $("tab-history") },
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
  tab: "host",
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

const visible = (host) => host.alive || !el.hideDead.checked;
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
  el.counts.textContent = state.total
    ? `${state.done}/${state.total} scanned · ${state.alive} alive`
    : "";
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
  if (tab === "host") renderHost();
  if (tab === "changes") renderChanges();
  if (tab === "history") refreshHistory();
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
    deviceSection(host),
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
      invoke("approvals_in_use"),
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
    setStatus(approved
      ? `${displayName(host) || host.ip} approved. One less thing to worry about.`
      : `${displayName(host) || host.ip} un-approved. Suspicious, are we?`);
  } catch (err) {
    toast(String(err), true);
  }
}

async function refreshHistory() {
  try {
    state.history = await invoke("list_scans");
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
    el.start.value = s.range_start;
    el.end.value = s.range_end;
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
  for (const input of [el.start, el.end, el.cidr, el.apply, el.ports, el.timeout,
                       el.threads, el.banners, el.attempts, el.trustArp, el.discover]) {
    input.disabled = on;
  }
}

async function toggleScan() {
  if (state.scanning) {
    el.scan.disabled = true;
    setStatus("Stopping… hold your horses.");
    await invoke("stop_scan");
    return;
  }
  try {
    const started = await invoke("start_scan", {
      start: el.start.value,
      end: el.end.value,
      ports: el.ports.value,
      threads: Number(el.threads.value) || 64,
      options: scanOptions(),
    });
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
    setStatus(`${pick(GRUMBLES.stop)}  ${tally} Not saved to history.`);
    return;
  }
  if (payload.error) toast(payload.error, true);

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

async function applyCidr() {
  try {
    const r = await invoke("cidr_range", { cidr: el.cidr.value });
    el.start.value = r.start;
    el.end.value = r.end;
    el.cidr.value = r.cidr;
  } catch (err) {
    toast(String(err), true);
  }
}

async function exportCsv() {
  if (!state.hosts.size) return toast("Export what? You haven't scanned anything.");
  const quote = (v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  const lines = [COLUMNS.map((c) => HEADINGS[c]).join(",")];
  for (const host of state.view) lines.push(COLUMNS.map((c) => quote(String(cell(host, c)))).join(","));
  try {
    const path = await invoke("save_csv", { content: lines.join("\n") + "\n" });
    if (path) setStatus(`Exported to ${path}. Fine.`);
  } catch (err) {
    toast(`Couldn't save that.\n${err}`, true);
  }
}

// --------------------------------------------------------------------------
// Interaction
// --------------------------------------------------------------------------

function select(ip) {
  state.selected = ip;
  for (const tr of el.rows.querySelectorAll("tr.selected")) tr.classList.remove("selected");
  el.rows.querySelector(`tr[data-ip="${ip}"]`)?.classList.add("selected");
  if (!el.panel.hidden && state.tab === "host") renderHost();
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
el.apply.addEventListener("click", applyCidr);
el.cidr.addEventListener("keydown", (e) => e.key === "Enter" && applyCidr());
for (const input of [el.start, el.end, el.ports, el.timeout, el.threads]) {
  input.addEventListener("keydown", (e) => e.key === "Enter" && !state.scanning && toggleScan());
}
el.hideDead.addEventListener("change", renderAll);
el.exportBtn.addEventListener("click", exportCsv);

// --------------------------------------------------------------------------
// Boot
// --------------------------------------------------------------------------

invoke("local_range").then((r) => {
  el.start.value = r.start;
  el.end.value = r.end;
  el.cidr.value = r.cidr;
});
refreshHistory();
refreshDevices().then(renderAll);
updateChrome();
