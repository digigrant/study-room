// Hardened HTTP(S) retrieval for web_fetch (SPEC 12.2).
//
// * Only URLs that pass url-policy.ts are requested, at every redirect hop.
// * Redirects are followed manually, at most `maxRedirects` times, and never
//   from HTTPS to HTTP.
// * Requests carry a fixed header set: no cookies, no Authorization, nothing
//   from the environment. Responses' Set-Cookie headers are ignored.
// * Connection, total-operation and response-byte limits are enforced here;
//   extraction limits are enforced in extract.ts.
//
// Two transports:
//
// * DirectTransport resolves the host itself, rejects the hop if any answer
//   is non-public, and then connects to exactly the validated address (the
//   socket's lookup is pinned), so DNS rebinding between check and connect is
//   impossible.
// * ProxyTransport is used inside Docker Sandboxes, where the sandbox has no
//   resolver and every HTTP(S) request leaves through the trusted proxy. The
//   proxy resolves and connects; the host-side network policy is the outer
//   restriction for name resolution (see docs/SECURITY.md).

import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import * as tls from "node:tls";
import * as zlib from "node:zlib";
import { lookup as dnsLookup } from "node:dns/promises";
import { PolicyError, assertPublicAddress, checkRedirect, checkUrl } from "./url-policy.ts";

export interface FetchLimits {
  maxRedirects: number;
  connectTimeoutMs: number;
  totalTimeoutMs: number;
  maxResponseBytes: number;
}

export const DEFAULT_LIMITS: FetchLimits = {
  maxRedirects: 5,
  connectTimeoutMs: 10_000,
  totalTimeoutMs: 30_000,
  maxResponseBytes: 5 * 1024 * 1024,
};

export interface RawResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  truncated: boolean;
}

export interface Hop {
  url: string;
  status: number;
}

export interface FetchResult {
  requestedUrl: string;
  finalUrl: string;
  status: number;
  contentType: string;
  body: Buffer;
  truncated: boolean;
  hops: Hop[];
}

export class FetchError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "FetchError";
  }
}

export const REQUEST_HEADERS: Record<string, string> = {
  "user-agent": "study-room-web-fetch/1 (+https://github.com/digigrant/study-room)",
  accept: "text/html,application/xhtml+xml,text/plain,text/markdown,application/pdf;q=0.9,application/json;q=0.5,*/*;q=0.1",
  "accept-encoding": "gzip, deflate",
  "accept-language": "en;q=0.9, *;q=0.5",
  connection: "close",
};

export interface ResolvedAddress {
  address: string;
  family: number;
}

export type Resolver = (hostname: string) => Promise<ResolvedAddress[]>;

export const systemResolver: Resolver = async (hostname) =>
  (await dnsLookup(hostname, { all: true, verbatim: true })).map((a) => ({ address: a.address, family: a.family }));

export interface Transport {
  readonly kind: "direct" | "proxy";
  request(url: URL, hostname: string, isIpLiteral: boolean, limits: FetchLimits, signal: AbortSignal): Promise<RawResponse>;
}

// ── Response reading (shared) ───────────────────────────────────────────────

function readBody(res: http.IncomingMessage, limits: FetchLimits, signal: AbortSignal): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const encoding = String(res.headers["content-encoding"] ?? "identity").toLowerCase().trim();
    let stream: NodeJS.ReadableStream = res;
    if (encoding === "gzip" || encoding === "x-gzip") stream = res.pipe(zlib.createGunzip());
    else if (encoding === "deflate") stream = res.pipe(zlib.createInflate());
    else if (encoding !== "identity" && encoding !== "") {
      res.destroy();
      reject(new FetchError("unsupported_encoding", `unsupported content-encoding ${encoding}`));
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    let truncated = false;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks), truncated });
    };
    const onAbort = () => {
      if (settled) return;
      settled = true;
      res.destroy();
      reject(new FetchError("timeout", "total operation time limit reached"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    stream.on("data", (chunk: Buffer) => {
      if (settled) return;
      const room = limits.maxResponseBytes - total;
      if (chunk.length >= room) {
        if (room > 0) chunks.push(chunk.subarray(0, room));
        total = limits.maxResponseBytes;
        truncated = true;
        res.destroy();
        finish();
        return;
      }
      chunks.push(chunk);
      total += chunk.length;
    });
    stream.on("end", finish);
    stream.on("error", (err: Error) => {
      if (settled) return;
      if (truncated) return finish();
      settled = true;
      signal.removeEventListener("abort", onAbort);
      reject(new FetchError("read_failed", `response read failed: ${err.message}`));
    });
  });
}

function requestPath(url: URL): string {
  return `${url.pathname || "/"}${url.search}`;
}

function hostHeader(url: URL): string {
  return url.host; // includes a non-default port when present
}

function issue(
  mod: typeof http | typeof https,
  options: https.RequestOptions,
  limits: FetchLimits,
  signal: AbortSignal,
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    // A fresh connection per request: no pooled sockets, nothing shared
    // between hops. With createConnection the request needs no agent at all
    // (Node ignores createConnection when given agent: false).
    const agent = typeof (options as any).createConnection === "function" ? undefined : false;
    const req = mod.request({ ...options, method: "GET", agent, signal }, (res) => {
      readBody(res, limits, signal).then(resolve, reject);
    });
    const connectTimer = setTimeout(() => {
      req.destroy(new FetchError("connect_timeout", `connection not established within ${limits.connectTimeoutMs} ms`));
    }, limits.connectTimeoutMs);
    req.on("socket", (socket: net.Socket) => {
      const clear = () => clearTimeout(connectTimer);
      socket.once(socket instanceof tls.TLSSocket ? "secureConnect" : "connect", clear);
      socket.once("close", clear);
    });
    req.on("response", () => clearTimeout(connectTimer));
    req.on("error", (err: Error) => {
      clearTimeout(connectTimer);
      if (err instanceof FetchError) reject(err);
      else if ((err as any).name === "AbortError") reject(new FetchError("timeout", "total operation time limit reached"));
      else reject(new FetchError("connect_failed", `request failed: ${err.message}`));
    });
    req.end();
  });
}

// ── Direct transport: resolve, validate every answer, pin the connection ───

export interface ConnectTarget {
  address: string;
  family: number;
  port: number;
}

export class DirectTransport implements Transport {
  readonly kind = "direct" as const;
  private readonly resolver: Resolver;
  private readonly connectOverride?: (address: ResolvedAddress, port: number) => ConnectTarget;
  private readonly tlsOptions: tls.ConnectionOptions;

  /**
   * `connectOverride` and `tlsOptions` exist for hermetic tests only: the
   * override maps an already-validated public address to a local test server.
   */
  constructor(
    resolver: Resolver = systemResolver,
    connectOverride?: (address: ResolvedAddress, port: number) => ConnectTarget,
    tlsOptions: tls.ConnectionOptions = {},
  ) {
    this.resolver = resolver;
    this.connectOverride = connectOverride;
    this.tlsOptions = tlsOptions;
  }

  async request(url: URL, hostname: string, isIpLiteral: boolean, limits: FetchLimits, signal: AbortSignal): Promise<RawResponse> {
    let answers: ResolvedAddress[];
    if (isIpLiteral) {
      answers = [{ address: hostname, family: hostname.includes(":") ? 6 : 4 }];
    } else {
      try {
        answers = await this.resolver(hostname);
      } catch (err: any) {
        throw new FetchError("dns_failed", `could not resolve ${hostname}: ${err?.code ?? err?.message ?? err}`);
      }
      if (!answers.length) throw new FetchError("dns_failed", `no addresses for ${hostname}`);
    }
    // Every answer must be public: a mixed answer set is how rebinding hides.
    for (const answer of answers) assertPublicAddress(answer.address, answer.family);
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    const target: ConnectTarget = this.connectOverride
      ? this.connectOverride(answers[0], port)
      : { address: answers[0].address, family: answers[0].family, port };
    // The socket connects to exactly the validated address: no second lookup.
    const pinnedLookup = (_host: string, opts: any, cb: any) => {
      const callback = typeof opts === "function" ? opts : cb;
      const options = typeof opts === "function" ? {} : opts ?? {};
      if (options.all) callback(null, [{ address: target.address, family: target.family }]);
      else callback(null, target.address, target.family);
    };
    const base: https.RequestOptions = {
      host: hostname,
      port: target.port,
      path: requestPath(url),
      headers: { ...REQUEST_HEADERS, host: hostHeader(url) },
      lookup: pinnedLookup as any,
    };
    if (url.protocol === "https:") {
      return issue(https, { ...this.tlsOptions, ...base, servername: isIpLiteral ? undefined : hostname }, limits, signal);
    }
    return issue(http, base, limits, signal);
  }
}

// ── Proxy transport: Docker Sandboxes' egress proxy ────────────────────────

export class ProxyTransport implements Transport {
  readonly kind = "proxy" as const;
  readonly proxy: URL;
  private readonly tlsOptions: tls.ConnectionOptions;

  constructor(proxyUrl: string, tlsOptions: tls.ConnectionOptions = {}) {
    const proxy = new URL(proxyUrl);
    if (proxy.protocol !== "http:") throw new FetchError("proxy_unsupported", `unsupported proxy protocol ${proxy.protocol}`);
    if (proxy.username || proxy.password) throw new FetchError("proxy_unsupported", "proxy URLs with credentials are not used");
    this.proxy = proxy;
    this.tlsOptions = tlsOptions;
  }

  async request(url: URL, hostname: string, _isIpLiteral: boolean, limits: FetchLimits, signal: AbortSignal): Promise<RawResponse> {
    const proxyHost = this.proxy.hostname.replace(/^\[|\]$/g, "");
    const proxyPort = Number(this.proxy.port || 80);
    if (url.protocol === "http:") {
      // Absolute-form request through the proxy.
      return issue(
        http,
        { host: proxyHost, port: proxyPort, path: url.href, headers: { ...REQUEST_HEADERS, host: hostHeader(url) } },
        limits,
        signal,
      );
    }
    const port = Number(url.port || 443);
    const tunnel = await new Promise<net.Socket>((resolve, reject) => {
      const req = http.request({
        host: proxyHost,
        port: proxyPort,
        method: "CONNECT",
        path: `${hostname.includes(":") ? `[${hostname}]` : hostname}:${port}`,
        headers: { host: `${hostname}:${port}` },
        agent: false,
        signal,
      });
      const timer = setTimeout(() => req.destroy(new FetchError("connect_timeout", `proxy tunnel not established within ${limits.connectTimeoutMs} ms`)), limits.connectTimeoutMs);
      req.once("connect", (res, socket) => {
        clearTimeout(timer);
        if (res.statusCode !== 200) {
          socket.destroy();
          reject(
            new FetchError(
              res.statusCode === 403 ? "blocked_by_network_policy" : "proxy_refused",
              res.statusCode === 403
                ? `the sandbox network policy blocked ${hostname} (proxy answered 403)`
                : `proxy refused the tunnel to ${hostname} (status ${res.statusCode})`,
            ),
          );
          return;
        }
        resolve(socket);
      });
      req.once("response", (res) => {
        clearTimeout(timer);
        res.resume();
        reject(new FetchError(res.statusCode === 403 ? "blocked_by_network_policy" : "proxy_refused", `proxy refused the tunnel to ${hostname} (status ${res.statusCode})`));
      });
      req.once("error", (err: Error) => {
        clearTimeout(timer);
        reject(err instanceof FetchError ? err : new FetchError("connect_failed", `proxy connection failed: ${err.message}`));
      });
      req.end();
    });
    try {
      return await issue(
        https,
        {
          host: hostname,
          port,
          path: requestPath(url),
          headers: { ...REQUEST_HEADERS, host: hostHeader(url) },
          createConnection: () => tls.connect({ ...this.tlsOptions, socket: tunnel, servername: hostname.includes(":") ? undefined : hostname }),
        } as https.RequestOptions,
        limits,
        signal,
      );
    } finally {
      tunnel.destroy();
    }
  }
}

/** Pick the transport for this process: the sandbox proxy when one is configured. */
export function transportFromEnv(env: NodeJS.ProcessEnv = process.env): Transport {
  const proxy = env.HTTPS_PROXY || env.https_proxy || env.HTTP_PROXY || env.http_proxy;
  if (proxy) return new ProxyTransport(proxy);
  return new DirectTransport();
}

// ── The fetch loop ──────────────────────────────────────────────────────────

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export async function hardenedFetch(
  input: string,
  transport: Transport,
  limits: FetchLimits = DEFAULT_LIMITS,
  outerSignal?: AbortSignal,
): Promise<FetchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), limits.totalTimeoutMs);
  const onOuterAbort = () => controller.abort();
  outerSignal?.addEventListener("abort", onOuterAbort, { once: true });
  const hops: Hop[] = [];
  try {
    let current = checkUrl(input);
    const requestedUrl = current.url.href;
    for (let hop = 0; ; hop++) {
      const res = await transport.request(current.url, current.hostname, current.isIpLiteral, limits, controller.signal);
      hops.push({ url: current.url.href, status: res.status });
      if (REDIRECT_STATUSES.has(res.status)) {
        const location = res.headers.location;
        if (!location) throw new FetchError("bad_redirect", `redirect ${res.status} without a Location header`);
        if (hop >= limits.maxRedirects) throw new FetchError("too_many_redirects", `more than ${limits.maxRedirects} redirects`);
        let next: URL;
        try {
          next = new URL(Array.isArray(location) ? location[0] : location, current.url);
        } catch {
          throw new FetchError("bad_redirect", "redirect Location is not a valid URL");
        }
        checkRedirect(current.url, next);
        current = checkUrl(next);
        continue;
      }
      if (res.status < 200 || res.status >= 300) {
        throw new FetchError("http_status", `server answered HTTP ${res.status}`);
      }
      return {
        requestedUrl,
        finalUrl: current.url.href,
        status: res.status,
        contentType: String(res.headers["content-type"] ?? ""),
        body: res.body,
        truncated: res.truncated,
        hops,
      };
    }
  } catch (err) {
    if (controller.signal.aborted && !(err instanceof PolicyError)) {
      throw new FetchError("timeout", `total operation time limit of ${limits.totalTimeoutMs} ms reached`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
    outerSignal?.removeEventListener("abort", onOuterAbort);
  }
}
