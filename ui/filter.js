/**
 * Filter queries for the results table.
 *
 * A query is a list of space-separated terms, all of which must match:
 *   synology            anywhere in the row
 *   vendor:apple        one field
 *   port:22             an open port, exactly
 *   new unknown risk    flags a row carries
 *   -dead               negation
 *
 * Kept apart from the UI so it can be tested without a browser; loaded as a
 * plain script, so no imports or exports here.
 */

/** Fields a `key:value` term can name, and where each reads from. */
const FILTER_FIELDS = {
  ip: (row) => row.ip,
  name: (row) => row.name,
  host: (row) => row.name,
  vendor: (row) => row.vendor,
  mac: (row) => row.mac,
  note: (row) => row.note,
  service: (row) => row.details,
  details: (row) => row.details,
  via: (row) => row.via,
};

/** Bare words that mean "this row is flagged like so". */
const FILTER_FLAGS = ["new", "changed", "unknown", "risk", "named", "alive", "dead"];

function parseFilter(query) {
  return (query ?? "")
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => {
      const negate = word.startsWith("-") && word.length > 1;
      const term = (negate ? word.slice(1) : word).toLowerCase();
      const [maybeKey, ...rest] = term.split(":");
      const value = rest.join(":");
      if (rest.length && (maybeKey === "port" || maybeKey in FILTER_FIELDS)) {
        return { negate, key: maybeKey, value };
      }
      if (FILTER_FLAGS.includes(term)) return { negate, flag: term };
      return { negate, text: term };
    });
}

/** One term against one row. `row.flags` is a Set of the names above. */
function termMatches(term, row) {
  if (term.flag) return row.flags.has(term.flag);
  if (term.key === "port") {
    // Exact, so port:8 doesn't match 8080 — but a bare 8 still would.
    return row.ports.some((port) => String(port) === term.value);
  }
  if (term.key) {
    const field = FILTER_FIELDS[term.key](row) ?? "";
    return field.toLowerCase().includes(term.value);
  }
  return row.text.toLowerCase().includes(term.text);
}

function hostMatches(row, terms) {
  return terms.every((term) => termMatches(term, row) !== term.negate);
}

// Exported for the node tests; harmless in a browser.
if (typeof module !== "undefined") {
  module.exports = { parseFilter, hostMatches, FILTER_FLAGS };
}
