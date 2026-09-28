/**
 * Layout for the network map.
 *
 * The picture is a star, because that's what the network is: everything on a
 * subnet talks through the gateway. So the gateway sits at the centre and
 * every device orbits it, with the two axes carrying real measurements:
 *
 *   distance from centre = round-trip time (log, so 1ms and 200ms both fit)
 *   size                 = how many ports are open
 *
 * Angle carries nothing, so it's derived from the device key: stable between
 * scans, which means a device stays where you last saw it on screen.
 *
 * Pure geometry, no DOM — so it can be tested without a browser.
 */

/** Rings, in milliseconds. Anything slower sits on the outer edge. */
const LATENCY_RINGS = [1, 10, 100];
const MAX_MS = 200;
const MIN_RADIUS = 0.18; // as a fraction of the plot radius, clear of the hub
const NODE_MIN = 9;
const NODE_MAX = 22;

/** Stable angle from a string: the same device lands in the same place. */
function angleFor(key) {
  let hash = 2166136261;
  for (let i = 0; i < key.length; i++) {
    hash ^= key.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return ((hash >>> 0) % 3600) / 3600 * Math.PI * 2;
}

/** Latency to a fraction of the plot radius, log-scaled. */
function radiusFraction(pingMs) {
  // No round-trip time (answered ARP or mDNS only): park it at the rim, where
  // "I couldn't time this" reads as "furthest away".
  if (pingMs == null) return 1;
  const clamped = Math.min(Math.max(pingMs, 0), MAX_MS);
  const scaled = Math.log10(1 + clamped) / Math.log10(1 + MAX_MS);
  return MIN_RADIUS + (1 - MIN_RADIUS) * scaled;
}

function nodeSize(portCount) {
  if (!portCount) return NODE_MIN;
  // Square-rooted: ten ports shouldn't be ten times the radius.
  return Math.min(NODE_MAX, NODE_MIN + Math.sqrt(portCount) * 3.5);
}

/**
 * Nudge nodes that landed on top of each other apart along their ring, so a
 * cluster stays readable without abandoning the layout's meaning.
 */
function separate(nodes, minGap = 26) {
  const byRing = [...nodes].sort((a, b) => a.radius - b.radius || a.angle - b.angle);
  for (let i = 1; i < byRing.length; i++) {
    const node = byRing[i];
    for (let j = 0; j < i; j++) {
      const other = byRing[j];
      const dx = node.x - other.x;
      const dy = node.y - other.y;
      const distance = Math.hypot(dx, dy);
      const needed = minGap + (node.size + other.size) / 2;
      if (distance >= needed || distance === 0) continue;
      // Slide it round its own ring rather than off it.
      const push = (needed - distance) / Math.max(node.radius, 1);
      node.angle += push * (node.angle >= other.angle ? 1 : -1);
      node.x = node.cx + Math.cos(node.angle) * node.radius;
      node.y = node.cy + Math.sin(node.angle) * node.radius;
    }
  }
  return nodes;
}

/**
 * Place hosts around a centre.
 *
 * `describe` supplies what the map can't know: the label, whether the device
 * is approved, whether it has findings. Returns plain data for rendering.
 */
function layoutMap(hosts, options) {
  const { width, height, gatewayIp, selfIp, describe = () => ({}) } = options;
  const cx = width / 2;
  const cy = height / 2;
  // Leave room for labels at the rim.
  const plotRadius = Math.max(40, Math.min(width, height) / 2 - 46);

  const nodes = hosts
    .filter((host) => host.alive && host.ip !== gatewayIp)
    .map((host) => {
      const extra = describe(host) ?? {};
      const radius = radiusFraction(host.ping_ms) * plotRadius;
      const angle = angleFor(extra.key || host.mac || host.ip);
      return {
        ip: host.ip,
        label: extra.label || host.hostname || host.vendor || host.ip,
        kind: host.ip === selfIp ? "self" : "device",
        ping_ms: host.ping_ms ?? null,
        ports: host.ports?.length ?? 0,
        risk: extra.risk ?? false,
        unapproved: extra.unapproved ?? false,
        size: nodeSize(host.ports?.length ?? 0),
        angle,
        radius,
        cx,
        cy,
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
      };
    });

  const gateway = hosts.find((host) => host.ip === gatewayIp);
  return {
    cx,
    cy,
    plotRadius,
    hub: gateway
      ? {
          ip: gateway.ip,
          label: describe(gateway)?.label || gateway.hostname || gateway.vendor || gateway.ip,
          kind: "gateway",
          ports: gateway.ports?.length ?? 0,
          risk: describe(gateway)?.risk ?? false,
          unapproved: describe(gateway)?.unapproved ?? false,
          size: 26,
          x: cx,
          y: cy,
        }
      : null,
    rings: LATENCY_RINGS.map((ms) => ({ ms, radius: radiusFraction(ms) * plotRadius })),
    nodes: separate(nodes),
  };
}

if (typeof module !== "undefined") {
  module.exports = { layoutMap, angleFor, radiusFraction, nodeSize, LATENCY_RINGS, MAX_MS };
}
