const test = require("node:test");
const assert = require("node:assert");
const { parseFilter, hostMatches } = require("./filter.js");

const row = (over = {}) => ({
  ip: "192.168.0.10",
  name: "Attic NAS",
  vendor: "Synology",
  mac: "00:11:32:AA:BB:CC",
  note: "backups live here",
  details: "OpenSSH_8.2 · Synology DiskStation",
  via: "icmp",
  ports: [22, 5001],
  text: "192.168.0.10 Attic NAS Synology 00:11:32:AA:BB:CC OpenSSH_8.2 · Synology DiskStation",
  flags: new Set(["alive", "named"]),
  ...over,
});

const matches = (query, over) => hostMatches(row(over), parseFilter(query));

test("empty query matches everything", () => {
  assert.ok(matches(""));
  assert.ok(matches("   "));
});

test("plain text searches the whole row", () => {
  assert.ok(matches("synology"), "case-insensitive");
  assert.ok(matches("attic"));
  assert.ok(matches("00:11:32"));
  assert.ok(!matches("netgear"));
});

test("terms combine with AND", () => {
  assert.ok(matches("attic synology"));
  assert.ok(!matches("attic netgear"));
});

test("key:value searches one field only", () => {
  assert.ok(matches("vendor:synology"));
  assert.ok(!matches("vendor:attic"), "attic is the name, not the vendor");
  assert.ok(matches("name:attic"));
  assert.ok(matches("note:backups"));
  assert.ok(matches("via:icmp"));
});

test("port matches exactly, so port:5 is not port 5001", () => {
  assert.ok(matches("port:22"));
  assert.ok(matches("port:5001"));
  assert.ok(!matches("port:5"));
  assert.ok(!matches("port:80"));
});

test("flags match what the row is, not what it says", () => {
  assert.ok(matches("alive"));
  assert.ok(!matches("unknown"));
  assert.ok(matches("unknown", { flags: new Set(["alive", "unknown"]) }));
  assert.ok(matches("new risk", { flags: new Set(["new", "risk"]) }));
});

test("a leading dash negates", () => {
  assert.ok(matches("-netgear"));
  assert.ok(!matches("-synology"));
  assert.ok(!matches("-port:22"));
  assert.ok(matches("-unknown"), "not flagged unknown");
  assert.ok(matches("synology -dead"));
});

test("an unknown key falls back to plain text", () => {
  // "http://foo" shouldn't be read as the key "http".
  assert.ok(matches("diskstation"));
  assert.ok(!matches("colour:red"));
  assert.ok(matches("colour:red", { text: "something colour:red something" }));
});

test("a bare dash is just text", () => {
  assert.deepEqual(parseFilter("-"), [{ negate: false, text: "-" }]);
});
