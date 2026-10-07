// Destination policy for the hardened web_fetch (SPEC 12.2).
//
// Accepts only public HTTP(S) URLs on the default web ports, without URL
// credentials, whose host is neither a special-use name nor a non-public IP
// address. Every redirect hop and every resolved address goes through the
// same checks.

export class PolicyError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "PolicyError";
  }
}

const ALLOWED_PORTS = new Set(["", "80", "443"]);

// Special-use and internal names (RFC 6761, RFC 6762, RFC 8375, common
// internal/metadata conventions). Matched as the whole name or a suffix.
const BLOCKED_NAME_SUFFIXES = [
  "localhost",
  "local",
  "localdomain",
  "internal",
  "intranet",
  "lan",
  "home",
  "corp",
  "home.arpa",
  "test",
  "example",
  "invalid",
  "onion",
  "arpa",
];
const BLOCKED_NAMES = new Set(["metadata", "instance-data", "metadata.google.internal", "wpad"]);

export type AddressFamily = 4 | 6;

export interface CheckedUrl {
  url: URL;
  hostname: string; // lowercase, no brackets, no trailing dot
  isIpLiteral: boolean;
}

export function checkUrl(input: string | URL): CheckedUrl {
  let url: URL;
  try {
    url = typeof input === "string" ? new URL(input) : new URL(input.href);
  } catch {
    throw new PolicyError("invalid_url", "not a valid absolute URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new PolicyError("unsupported_protocol", `unsupported protocol ${url.protocol} (only http and https)`);
  }
  if (url.username || url.password) {
    throw new PolicyError("url_credentials", "URLs containing credentials are rejected");
  }
  if (!ALLOWED_PORTS.has(url.port)) {
    throw new PolicyError("port_not_allowed", `port ${url.port} is not allowed (only 80 and 443)`);
  }
  let hostname = url.hostname.toLowerCase();
  const bracketed = hostname.startsWith("[") && hostname.endsWith("]");
  if (bracketed) hostname = hostname.slice(1, -1);
  while (hostname.endsWith(".")) hostname = hostname.slice(0, -1);
  if (!hostname) throw new PolicyError("invalid_host", "empty host");

  const v4 = parseIPv4(hostname);
  if (v4 !== null) {
    assertPublicIPv4(v4, hostname);
    return { url, hostname, isIpLiteral: true };
  }
  if (bracketed || hostname.includes(":")) {
    const v6 = parseIPv6(hostname);
    if (v6 === null) throw new PolicyError("invalid_host", `invalid IPv6 literal ${hostname}`);
    assertPublicIPv6(v6, hostname);
    return { url, hostname, isIpLiteral: true };
  }
  assertPublicName(hostname);
  return { url, hostname, isIpLiteral: false };
}

export function assertPublicName(hostname: string): void {
  if (!/^[a-z0-9.-]+$/.test(hostname) || hostname.includes("..")) {
    throw new PolicyError("invalid_host", `host ${JSON.stringify(hostname)} contains unsupported characters`);
  }
  if (!hostname.includes(".")) {
    throw new PolicyError("non_public_host", `single-label host ${hostname} is not a public name`);
  }
  if (BLOCKED_NAMES.has(hostname)) {
    throw new PolicyError("non_public_host", `${hostname} is an internal or metadata name`);
  }
  for (const suffix of BLOCKED_NAME_SUFFIXES) {
    if (hostname === suffix || hostname.endsWith(`.${suffix}`)) {
      throw new PolicyError("non_public_host", `${hostname} is a special-use or internal name (.${suffix})`);
    }
  }
}

// ── IP parsing ──────────────────────────────────────────────────────────────

export function parseIPv4(text: string): number | null {
  // Strict dotted-quad. The WHATWG URL parser has already canonicalised
  // shorthand forms (0x7f.1, 2130706433, 0177.0.0.1) in URL hosts.
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const parts = m.slice(1).map((p) => Number(p));
  if (parts.some((p, i) => p > 255 || (m[i + 1].length > 1 && m[i + 1].startsWith("0")))) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

export function parseIPv6(text: string): bigint | null {
  let input = text;
  const zone = input.indexOf("%");
  if (zone !== -1) return null; // zone IDs never denote a public destination
  let tailV4: number | null = null;
  const lastColon = input.lastIndexOf(":");
  if (lastColon !== -1 && input.slice(lastColon + 1).includes(".")) {
    tailV4 = parseIPv4(input.slice(lastColon + 1));
    if (tailV4 === null) return null;
    input = `${input.slice(0, lastColon + 1)}${((tailV4 >>> 16) & 0xffff).toString(16)}:${(tailV4 & 0xffff).toString(16)}`;
  }
  const halves = input.split("::");
  if (halves.length > 2) return null;
  const parse = (s: string): number[] | null => {
    if (s === "") return [];
    const groups = s.split(":");
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parse(halves[0]);
  const tail = halves.length === 2 ? parse(halves[1]) : [];
  if (head === null || tail === null) return null;
  let groups: number[];
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...new Array(missing).fill(0), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const g of groups) value = (value << 16n) | BigInt(g);
  return value;
}

// ── Classification ──────────────────────────────────────────────────────────

const V4_BLOCKED: Array<[string, number]> = [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // shared address space (CGNAT), includes 100.100.100.200 metadata
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local, includes 169.254.169.254 metadata
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.31.196.0", 24], // AS112
  ["192.52.193.0", 24], // AMT
  ["192.88.99.0", 24], // 6to4 relay anycast
  ["192.168.0.0", 16], // private
  ["192.175.48.0", 24], // AS112 direct delegation
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved + broadcast
];

const V4_RANGES = V4_BLOCKED.map(([base, bits]) => {
  const b = parseIPv4(base)!;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (b & mask) >>> 0, mask, label: `${base}/${bits}` };
});

export function ipv4Block(addr: number): string | null {
  for (const r of V4_RANGES) {
    if (((addr & r.mask) >>> 0) === r.base) return r.label;
  }
  return null;
}

function v6(text: string): bigint {
  const v = parseIPv6(text);
  if (v === null) throw new Error(`bad constant ${text}`);
  return v;
}

const V6_BLOCKED: Array<[bigint, number, string]> = [
  [v6("::"), 128, "::/128 unspecified"],
  [v6("::1"), 128, "::1/128 loopback"],
  [v6("::"), 96, "::/96 IPv4-compatible"],
  [v6("100::"), 64, "100::/64 discard"],
  [v6("2001::"), 23, "2001::/23 IETF protocol assignments (incl. Teredo)"],
  [v6("2001:db8::"), 32, "2001:db8::/32 documentation"],
  [v6("2002::"), 16, "2002::/16 6to4"],
  [v6("3fff::"), 20, "3fff::/20 documentation"],
  [v6("5f00::"), 16, "5f00::/16 SRv6 SIDs"],
  [v6("fc00::"), 7, "fc00::/7 unique local"],
  [v6("fe80::"), 10, "fe80::/10 link-local"],
  [v6("fec0::"), 10, "fec0::/10 site-local"],
  [v6("ff00::"), 8, "ff00::/8 multicast"],
];

const MASK128 = (1n << 128n) - 1n;

function inPrefix(addr: bigint, base: bigint, bits: number): boolean {
  const mask = bits === 0 ? 0n : (MASK128 << BigInt(128 - bits)) & MASK128;
  return (addr & mask) === (base & mask);
}

export function ipv6Block(addr: bigint): string | null {
  // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96, 64:ff9b:1::/48)
  // embed an IPv4 destination: classify the embedded address.
  if (inPrefix(addr, v6("::ffff:0:0"), 96) || inPrefix(addr, v6("64:ff9b::"), 96)) {
    const embedded = Number(addr & 0xffffffffn);
    const inner = ipv4Block(embedded);
    return inner ? `IPv4-embedded ${inner}` : null;
  }
  if (inPrefix(addr, v6("64:ff9b:1::"), 48)) return "64:ff9b:1::/48 local-use NAT64";
  for (const [base, bits, label] of V6_BLOCKED) {
    if (inPrefix(addr, base, bits)) return label;
  }
  // Only global unicast (2000::/3) is public.
  if (!inPrefix(addr, v6("2000::"), 3)) return "outside 2000::/3 global unicast";
  return null;
}

export function assertPublicIPv4(addr: number, shown: string): void {
  const block = ipv4Block(addr);
  if (block) throw new PolicyError("non_public_address", `${shown} is in non-public range ${block}`);
}

export function assertPublicIPv6(addr: bigint, shown: string): void {
  const block = ipv6Block(addr);
  if (block) throw new PolicyError("non_public_address", `${shown} is in non-public range ${block}`);
}

/** Validate a resolver answer (any family). */
export function assertPublicAddress(address: string, family?: number): void {
  if (family === 4 || (family === undefined && address.includes("."))) {
    const v = parseIPv4(address);
    if (v === null) {
      // IPv4-mapped textual form from some resolvers.
      const as6 = parseIPv6(address);
      if (as6 === null) throw new PolicyError("invalid_address", `resolver returned an invalid address ${address}`);
      assertPublicIPv6(as6, address);
      return;
    }
    assertPublicIPv4(v, address);
    return;
  }
  const v = parseIPv6(address);
  if (v === null) throw new PolicyError("invalid_address", `resolver returned an invalid address ${address}`);
  assertPublicIPv6(v, address);
}

/** Redirect rule: never downgrade from HTTPS to HTTP. */
export function checkRedirect(from: URL, to: URL): void {
  if (from.protocol === "https:" && to.protocol === "http:") {
    throw new PolicyError("https_downgrade", `refusing HTTPS-to-HTTP redirect to ${to.host}`);
  }
}
