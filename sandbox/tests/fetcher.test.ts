// Hermetic tests for the hardened fetcher: local servers only, scripted DNS.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import * as zlib from "node:zlib";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DirectTransport,
  FetchError,
  ProxyTransport,
  REQUEST_HEADERS,
  hardenedFetch,
  transportFromEnv,
  type FetchLimits,
  type RawResponse,
  type Transport,
} from "../lib/fetcher.ts";
import { PolicyError } from "../lib/url-policy.ts";

const PUBLIC_A = "93.184.215.14";
const PUBLIC_B = "151.101.1.69";

const LIMITS: FetchLimits = { maxRedirects: 5, connectTimeoutMs: 1500, totalTimeoutMs: 4000, maxResponseBytes: 64 * 1024 };

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

function listen(server: net.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port)));
}

let httpServer: http.Server;
let httpPort: number;
const seen: http.IncomingHttpHeaders[] = [];
const routes = new Map<string, Handler>();

function scriptedResolver(map: Record<string, Array<[string, number]>>) {
  const calls: string[] = [];
  const resolver = async (host: string) => {
    calls.push(host);
    const answers = map[host];
    if (!answers) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    return answers.map(([address, family]) => ({ address, family }));
  };
  return { resolver, calls };
}

function toLocal(port: () => number) {
  return (_addr: { address: string; family: number }) => ({ address: "127.0.0.1", family: 4, port: port() });
}

before(async () => {
  httpServer = http.createServer((req, res) => {
    seen.push(req.headers);
    const handler = routes.get(req.url ?? "/");
    if (handler) return handler(req, res);
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("missing");
  });
  httpPort = await listen(httpServer);
  routes.set("/page", (_req, res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "set-cookie": "session=abc; Path=/" });
    res.end("<html><head><title>T</title></head><body><p>hello</p></body></html>");
  });
  routes.set("/big", (_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("x".repeat(200 * 1024));
  });
  routes.set("/bomb", (_req, res) => {
    res.writeHead(200, { "content-type": "text/plain", "content-encoding": "gzip" });
    res.end(zlib.gzipSync(Buffer.alloc(8 * 1024 * 1024)));
  });
  routes.set("/slow", (_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    const t = setInterval(() => res.write("."), 200);
    res.on("close", () => clearInterval(t));
  });
  routes.set("/to-private", (_req, res) => {
    res.writeHead(302, { location: "http://rebind.example-site.org/page" });
    res.end();
  });
  routes.set("/to-meta", (_req, res) => {
    res.writeHead(301, { location: "http://169.254.169.254/latest/meta-data/" });
    res.end();
  });
  routes.set("/to-ftp", (_req, res) => {
    res.writeHead(302, { location: "ftp://pub.example-site.org/file" });
    res.end();
  });
  routes.set("/to-creds", (_req, res) => {
    res.writeHead(302, { location: "http://user:pw@pub.example-site.org/page" });
    res.end();
  });
  routes.set("/loop", (_req, res) => {
    res.writeHead(302, { location: "/loop" });
    res.end();
  });
  routes.set("/no-location", (_req, res) => {
    res.writeHead(302);
    res.end();
  });
  routes.set("/500", (_req, res) => {
    res.writeHead(500, { "content-type": "text/plain" });
    res.end("boom");
  });
});

after(() => {
  httpServer.closeAllConnections();
  httpServer.close();
});

describe("direct transport", () => {
  it("fetches a page through a validated, pinned address with fixed headers", async () => {
    const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
    const t = new DirectTransport(resolver, toLocal(() => httpPort));
    seen.length = 0;
    const r = await hardenedFetch("http://pub.example-site.org/page", t, LIMITS);
    assert.equal(r.status, 200);
    assert.match(r.body.toString(), /hello/);
    assert.equal(r.finalUrl, "http://pub.example-site.org/page");
    const headers = seen[0];
    assert.equal(headers.host, "pub.example-site.org");
    assert.equal(headers.cookie, undefined);
    assert.equal(headers.authorization, undefined);
    assert.equal(headers["user-agent"], REQUEST_HEADERS["user-agent"]);
  });

  it("never replays cookies a site sets", async () => {
    const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
    const t = new DirectTransport(resolver, toLocal(() => httpPort));
    seen.length = 0;
    await hardenedFetch("http://pub.example-site.org/page", t, LIMITS);
    await hardenedFetch("http://pub.example-site.org/page", t, LIMITS);
    assert.equal(seen[1].cookie, undefined);
  });

  it("does not leak ambient credentials from the environment", async () => {
    const saved = { ...process.env };
    process.env.GITHUB_TOKEN = "ghp_FAKEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    process.env.OPENAI_API_KEY = "sk-study-room-FAKE-PLACEHOLDER";
    try {
      const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
      seen.length = 0;
      await hardenedFetch("http://pub.example-site.org/page", new DirectTransport(resolver, toLocal(() => httpPort)), LIMITS);
      const flat = JSON.stringify(seen[0]);
      assert.ok(!flat.includes("ghp_"), "GitHub token must not be sent");
      assert.ok(!flat.includes("sk-study-room"), "provider placeholder must not be sent");
    } finally {
      process.env = saved;
    }
  });

  it("rejects a host that resolves to a private address", async () => {
    const { resolver } = scriptedResolver({ "evil.example-site.org": [["10.0.0.5", 4]] });
    await assert.rejects(
      hardenedFetch("http://evil.example-site.org/page", new DirectTransport(resolver, toLocal(() => httpPort)), LIMITS),
      (e: unknown) => e instanceof PolicyError && e.code === "non_public_address",
    );
  });

  it("rejects mixed public/private answer sets (rebinding hidden in a set)", async () => {
    const { resolver } = scriptedResolver({ "mixed.example-site.org": [[PUBLIC_A, 4], ["127.0.0.1", 4]] });
    await assert.rejects(
      hardenedFetch("http://mixed.example-site.org/page", new DirectTransport(resolver, toLocal(() => httpPort)), LIMITS),
      (e: unknown) => e instanceof PolicyError,
    );
  });

  it("re-resolves and revalidates at every redirect hop", async () => {
    const { resolver, calls } = scriptedResolver({
      "pub.example-site.org": [[PUBLIC_A, 4]],
      "rebind.example-site.org": [["::1", 6]],
    });
    await assert.rejects(
      hardenedFetch("http://pub.example-site.org/to-private", new DirectTransport(resolver, toLocal(() => httpPort)), LIMITS),
      (e: unknown) => e instanceof PolicyError && e.code === "non_public_address",
    );
    assert.deepEqual(calls, ["pub.example-site.org", "rebind.example-site.org"]);
  });

  it("pins the connection to the address that was validated", async () => {
    let lookups = 0;
    const resolver = async () => {
      lookups++;
      // A rebinding resolver: public on the first query, loopback after.
      return lookups === 1 ? [{ address: PUBLIC_B, family: 4 }] : [{ address: "127.0.0.1", family: 4 }];
    };
    const connected: string[] = [];
    const t = new DirectTransport(resolver, (addr) => {
      connected.push(addr.address);
      return { address: "127.0.0.1", family: 4, port: httpPort };
    });
    await hardenedFetch("http://pub.example-site.org/page", t, LIMITS);
    assert.equal(lookups, 1, "exactly one resolution per hop");
    assert.deepEqual(connected, [PUBLIC_B]);
  });

  it("rejects redirects to metadata IPs, other protocols and URL credentials", async () => {
    const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
    const t = new DirectTransport(resolver, toLocal(() => httpPort));
    await assert.rejects(hardenedFetch("http://pub.example-site.org/to-meta", t, LIMITS), (e: any) => e.code === "non_public_address");
    await assert.rejects(hardenedFetch("http://pub.example-site.org/to-ftp", t, LIMITS), (e: any) => e.code === "unsupported_protocol");
    await assert.rejects(hardenedFetch("http://pub.example-site.org/to-creds", t, LIMITS), (e: any) => e.code === "url_credentials");
  });

  it("bounds the number of redirects", async () => {
    const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
    await assert.rejects(
      hardenedFetch("http://pub.example-site.org/loop", new DirectTransport(resolver, toLocal(() => httpPort)), LIMITS),
      (e: unknown) => e instanceof FetchError && e.code === "too_many_redirects",
    );
    await assert.rejects(
      hardenedFetch("http://pub.example-site.org/no-location", new DirectTransport(resolver, toLocal(() => httpPort)), LIMITS),
      (e: unknown) => e instanceof FetchError && e.code === "bad_redirect",
    );
  });

  it("truncates bodies at the response-byte limit", async () => {
    const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
    const r = await hardenedFetch("http://pub.example-site.org/big", new DirectTransport(resolver, toLocal(() => httpPort)), LIMITS);
    assert.equal(r.body.length, LIMITS.maxResponseBytes);
    assert.equal(r.truncated, true);
  });

  it("caps decompressed size (gzip bombs)", async () => {
    const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
    const r = await hardenedFetch("http://pub.example-site.org/bomb", new DirectTransport(resolver, toLocal(() => httpPort)), LIMITS);
    assert.equal(r.body.length, LIMITS.maxResponseBytes);
    assert.equal(r.truncated, true);
  });

  it("enforces the total-operation timeout", async () => {
    const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
    const started = Date.now();
    await assert.rejects(
      hardenedFetch("http://pub.example-site.org/slow", new DirectTransport(resolver, toLocal(() => httpPort)), { ...LIMITS, totalTimeoutMs: 700 }),
      (e: unknown) => e instanceof FetchError && e.code === "timeout",
    );
    assert.ok(Date.now() - started < 3000);
  });

  it("enforces the connection timeout", async () => {
    // Accepts TCP but never answers the TLS handshake.
    const sockets: net.Socket[] = [];
    const silent = net.createServer((s) => sockets.push(s));
    const port = await listen(silent);
    try {
      const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
      await assert.rejects(
        hardenedFetch("https://pub.example-site.org/", new DirectTransport(resolver, () => ({ address: "127.0.0.1", family: 4, port })), { ...LIMITS, connectTimeoutMs: 300 }),
        (e: unknown) => e instanceof FetchError && e.code === "connect_timeout",
      );
    } finally {
      sockets.forEach((s) => s.destroy());
      silent.close();
    }
  });

  it("reports non-2xx statuses", async () => {
    const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
    await assert.rejects(
      hardenedFetch("http://pub.example-site.org/500", new DirectTransport(resolver, toLocal(() => httpPort)), LIMITS),
      (e: unknown) => e instanceof FetchError && e.code === "http_status",
    );
  });
});

describe("fetch loop", () => {
  class Scripted implements Transport {
    readonly kind = "direct" as const;
    readonly urls: string[] = [];
    private readonly responses: Array<Partial<RawResponse>>;
    constructor(responses: Array<Partial<RawResponse>>) {
      this.responses = responses;
    }
    async request(url: URL): Promise<RawResponse> {
      this.urls.push(url.href);
      const r = this.responses.shift() ?? { status: 200 };
      return { status: r.status ?? 200, headers: r.headers ?? { "content-type": "text/plain" }, body: r.body ?? Buffer.from("ok"), truncated: false };
    }
  }

  it("refuses HTTPS-to-HTTP downgrade redirects", async () => {
    const t = new Scripted([{ status: 302, headers: { location: "http://example.org/plain" } }]);
    await assert.rejects(hardenedFetch("https://example.org/", t, LIMITS), (e: any) => e.code === "https_downgrade");
  });

  it("resolves relative redirects and records the final URL", async () => {
    const t = new Scripted([{ status: 301, headers: { location: "/next?x=1" } }, { status: 200 }]);
    const r = await hardenedFetch("https://example.org/start", t, LIMITS);
    assert.equal(r.finalUrl, "https://example.org/next?x=1");
    assert.deepEqual(t.urls, ["https://example.org/start", "https://example.org/next?x=1"]);
    assert.equal(r.hops.length, 2);
  });

  it("validates the initial URL before any request", async () => {
    const t = new Scripted([]);
    await assert.rejects(hardenedFetch("http://localhost/", t, LIMITS), PolicyError);
    assert.equal(t.urls.length, 0);
  });
});

// ── TLS and proxy paths ─────────────────────────────────────────────────────

function makeCert(): { key: Buffer; cert: Buffer; dir: string } | null {
  try {
    const dir = mkdtempSync(join(tmpdir(), "sr-cert-"));
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=pub.example-site.org",
      "-addext", "subjectAltName=DNS:pub.example-site.org",
      "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"),
    ], { stdio: "ignore" });
    return { key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")), dir };
  } catch {
    return null;
  }
}

const cert = makeCert();

describe("TLS and proxy", { skip: cert ? false : "openssl is not available to create a test certificate" }, () => {
  let tlsServer: https.Server;
  let tlsPort: number;
  let proxy: http.Server;
  let proxyPort: number;
  const connectTargets: string[] = [];
  const tunnels: net.Socket[] = [];
  let denyHost: string | null = null;

  before(async () => {
    tlsServer = https.createServer({ key: cert!.key, cert: cert!.cert }, (req, res) => {
      seen.push(req.headers);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(`secure ${req.url}`);
    });
    tlsPort = await listen(tlsServer);
    proxy = http.createServer((req, res) => {
      // Absolute-form plain HTTP through the proxy.
      const target = new URL(req.url ?? "");
      connectTargets.push(`GET ${target.host}`);
      if (denyHost && target.hostname === denyHost) {
        res.writeHead(403, { "content-type": "text/plain" });
        res.end("Blocked by network policy");
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(`proxied ${target.pathname}`);
    });
    proxy.on("connect", (req, clientSocket: net.Socket, head) => {
      tunnels.push(clientSocket);
      connectTargets.push(`CONNECT ${req.url}`);
      const host = String(req.url).split(":")[0];
      if (denyHost && host === denyHost) {
        clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
        return;
      }
      const upstream = net.connect(tlsPort, "127.0.0.1", () => {
        tunnels.push(upstream);
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.on("error", () => clientSocket.destroy());
    });
    proxyPort = await listen(proxy);
  });

  after(() => {
    tunnels.forEach((s) => s.destroy());
    tlsServer.closeAllConnections();
    tlsServer.close();
    proxy.closeAllConnections();
    proxy.close();
    rmSync(cert!.dir, { recursive: true, force: true });
  });

  it("direct HTTPS uses SNI for the requested host on the pinned address", async () => {
    const { resolver } = scriptedResolver({ "pub.example-site.org": [[PUBLIC_A, 4]] });
    const t = new DirectTransport(resolver, () => ({ address: "127.0.0.1", family: 4, port: tlsPort }), { ca: cert!.cert });
    const r = await hardenedFetch("https://pub.example-site.org/doc", t, LIMITS);
    assert.equal(r.body.toString(), "secure /doc");
  });

  it("rejects a certificate that does not match", async () => {
    const { resolver } = scriptedResolver({ "other.example-site.org": [[PUBLIC_A, 4]] });
    const t = new DirectTransport(resolver, () => ({ address: "127.0.0.1", family: 4, port: tlsPort }), { ca: cert!.cert });
    await assert.rejects(hardenedFetch("https://other.example-site.org/", t, LIMITS), FetchError);
  });

  it("tunnels HTTPS through the sandbox proxy by host name", async () => {
    connectTargets.length = 0;
    const t = new ProxyTransport(`http://127.0.0.1:${proxyPort}`, { ca: cert!.cert });
    const r = await hardenedFetch("https://pub.example-site.org/via-proxy", t, LIMITS);
    assert.equal(r.body.toString(), "secure /via-proxy");
    assert.deepEqual(connectTargets, ["CONNECT pub.example-site.org:443"]);
  });

  it("sends plain HTTP to the proxy in absolute form", async () => {
    connectTargets.length = 0;
    const t = new ProxyTransport(`http://127.0.0.1:${proxyPort}`);
    const r = await hardenedFetch("http://pub.example-site.org/plain", t, LIMITS);
    assert.equal(r.body.toString(), "proxied /plain");
    assert.deepEqual(connectTargets, ["GET pub.example-site.org"]);
  });

  it("classifies proxy policy refusals", async () => {
    denyHost = "blocked.example-site.org";
    try {
      const t = new ProxyTransport(`http://127.0.0.1:${proxyPort}`, { ca: cert!.cert });
      await assert.rejects(hardenedFetch("https://blocked.example-site.org/", t, LIMITS), (e: any) => e.code === "blocked_by_network_policy");
      await assert.rejects(hardenedFetch("http://blocked.example-site.org/", t, LIMITS), (e: any) => e.code === "http_status");
    } finally {
      denyHost = null;
    }
  });

  it("still applies the destination policy before using the proxy", async () => {
    connectTargets.length = 0;
    const t = new ProxyTransport(`http://127.0.0.1:${proxyPort}`, { ca: cert!.cert });
    await assert.rejects(hardenedFetch("https://169.254.169.254/", t, LIMITS), PolicyError);
    await assert.rejects(hardenedFetch("https://host.docker.internal/", t, LIMITS), PolicyError);
    assert.equal(connectTargets.length, 0);
  });

  it("picks the proxy transport from the sandbox environment", () => {
    assert.equal(transportFromEnv({ HTTPS_PROXY: "http://gateway.docker.internal:3128" }).kind, "proxy");
    assert.equal(transportFromEnv({}).kind, "direct");
    assert.throws(() => transportFromEnv({ HTTPS_PROXY: "http://u:p@proxy:3128" }), FetchError);
  });
});
