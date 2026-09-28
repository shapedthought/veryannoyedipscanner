const test = require("node:test");
const assert = require("node:assert");
const { layoutMap, angleFor, radiusFraction, nodeSize } = require("./map.js");

const host = (ip, over = {}) => ({
  ip,
  alive: true,
  ping_ms: 5,
  hostname: "",
  vendor: "",
  mac: `AA:BB:CC:00:00:${ip.split(".").pop().padStart(2, "0")}`,
  ports: [],
  ...over,
});

const size = { width: 800, height: 600, gatewayIp: "192.168.0.1", selfIp: "192.168.0.54" };
const distance = (node, map) => Math.hypot(node.x - map.cx, node.y - map.cy);

test("the gateway is the hub, and everything else orbits it", () => {
  const map = layoutMap([host("192.168.0.1"), host("192.168.0.10"), host("192.168.0.54")], size);
  assert.equal(map.hub.ip, "192.168.0.1");
  assert.equal(map.nodes.length, 2, "the hub isn't also a node");
  assert.deepEqual([map.hub.x, map.hub.y], [map.cx, map.cy]);
  assert.equal(map.nodes.find((n) => n.ip === "192.168.0.54").kind, "self");
});

test("a network with no gateway in the scan still draws", () => {
  const map = layoutMap([host("10.0.0.5")], { ...size, gatewayIp: "10.0.0.1" });
  assert.equal(map.hub, null);
  assert.equal(map.nodes.length, 1);
});

test("dead hosts are left out", () => {
  const map = layoutMap([host("192.168.0.7", { alive: false, ping_ms: null })], size);
  assert.equal(map.nodes.length, 0);
});

test("distance from the centre grows with latency", () => {
  const near = radiusFraction(1);
  const mid = radiusFraction(20);
  const far = radiusFraction(150);
  assert.ok(near < mid && mid < far, `${near} < ${mid} < ${far}`);
  // Something that answered but couldn't be timed sits at the rim.
  assert.equal(radiusFraction(null), 1);
  // And the scale is log, so the near end isn't squashed into the hub.
  assert.ok(near > 0.17, "1ms is clear of the hub");
  assert.ok(radiusFraction(10_000) <= 1, "absurd latency is clamped, not off-canvas");
});

test("size grows with open ports, within bounds", () => {
  assert.ok(nodeSize(0) < nodeSize(1));
  assert.ok(nodeSize(1) < nodeSize(9));
  assert.ok(nodeSize(500) <= 22, "one busy host can't swallow the map");
  assert.ok(nodeSize(0) >= 9, "and a quiet one is still clickable");
});

test("a device keeps its place between scans", () => {
  const first = layoutMap([host("192.168.0.10")], size).nodes[0];
  // Same device, new address and one more open port.
  const later = layoutMap([host("192.168.0.99", { mac: first.ip && "AA:BB:CC:00:00:10", ports: [22] })], size).nodes[0];
  assert.equal(first.angle, later.angle, "angle comes from the device, not its address");
});

test("angles are spread rather than clustered", () => {
  const angles = ["AA:01", "AA:02", "AA:03", "BB:99", "CC:12"].map(angleFor);
  assert.equal(new Set(angles).size, angles.length, "no two collide");
  assert.ok(angles.every((a) => a >= 0 && a < Math.PI * 2));
});

test("nodes that would overlap are pushed apart", () => {
  // Same latency and nearly the same hash space: force a pile-up.
  const crowd = Array.from({ length: 8 }, (_, i) => host(`192.168.0.${20 + i}`, { ping_ms: 5 }));
  const map = layoutMap(crowd, size);
  for (const a of map.nodes) {
    for (const b of map.nodes) {
      if (a === b) continue;
      assert.ok(Math.hypot(a.x - b.x, a.y - b.y) > 12, `${a.ip} and ${b.ip} overlap`);
    }
  }
});

test("separation keeps nodes on their own ring", () => {
  const crowd = Array.from({ length: 6 }, (_, i) => host(`10.0.0.${i + 2}`, { ping_ms: 3 }));
  const map = layoutMap(crowd, { ...size, gatewayIp: "10.0.0.1" });
  const radii = map.nodes.map((n) => distance(n, map));
  const spread = Math.max(...radii) - Math.min(...radii);
  assert.ok(spread < 1, `same latency, same ring (spread ${spread.toFixed(3)})`);
});

test("what the map can't know is supplied by the caller", () => {
  const map = layoutMap([host("192.168.0.10")], {
    ...size,
    describe: () => ({ label: "Attic NAS", risk: true, unapproved: true, key: "mine" }),
  });
  const node = map.nodes[0];
  assert.equal(node.label, "Attic NAS");
  assert.ok(node.risk && node.unapproved);
  assert.equal(node.angle, angleFor("mine"), "the device key drives placement");
});

test("rings are labelled in milliseconds and ordered outwards", () => {
  const map = layoutMap([host("192.168.0.10")], size);
  assert.deepEqual(map.rings.map((r) => r.ms), [1, 10, 100]);
  assert.ok(map.rings[0].radius < map.rings[1].radius);
  assert.ok(map.rings.at(-1).radius <= map.plotRadius);
});

test("a narrow window still produces a usable plot", () => {
  const map = layoutMap([host("192.168.0.10")], { ...size, width: 320, height: 240 });
  assert.ok(map.plotRadius >= 40);
  assert.ok(map.nodes[0].x > 0 && map.nodes[0].y > 0);
});
