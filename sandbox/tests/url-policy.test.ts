import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PolicyError, assertPublicAddress, checkRedirect, checkUrl, parseIPv6 } from "../lib/url-policy.ts";

function rejects(url: string, code: string) {
  assert.throws(() => checkUrl(url), (err: unknown) => err instanceof PolicyError && err.code === code, `${url} should be rejected with ${code}`);
}

describe("url policy: protocols and credentials", () => {
  it("accepts public http and https URLs", () => {
    assert.equal(checkUrl("https://example.org/a?b=c").hostname, "example.org");
    assert.equal(checkUrl("http://docs.python.org/3/").hostname, "docs.python.org");
    assert.equal(checkUrl("https://EXAMPLE.org./x").hostname, "example.org");
  });
  for (const url of ["ftp://example.org/", "file:///etc/passwd", "gopher://example.org/", "data:text/plain,hi", "javascript:alert(1)", "ws://example.org/"]) {
    it(`rejects ${url.split(":")[0]}:`, () => rejects(url, "unsupported_protocol"));
  }
  it("rejects URL credentials", () => {
    rejects("https://user:pass@example.org/", "url_credentials");
    rejects("https://user@example.org/", "url_credentials");
  });
  it("rejects non-web ports", () => {
    rejects("https://example.org:8443/", "port_not_allowed");
    rejects("http://example.org:22/", "port_not_allowed");
    assert.ok(checkUrl("https://example.org:443/"));
    assert.ok(checkUrl("http://example.org:80/"));
  });
  it("rejects garbage", () => rejects("not a url", "invalid_url"));
});

describe("url policy: IPv4 destinations", () => {
  const blocked = [
    "127.0.0.1", "127.1.2.3", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254", "192.168.1.1",
    "169.254.169.254", "169.254.0.1", "100.64.0.1", "100.100.100.200", "0.0.0.0", "0.1.2.3", "224.0.0.1",
    "239.255.255.250", "240.0.0.1", "255.255.255.255", "192.0.2.10", "198.51.100.7", "203.0.113.9", "198.18.0.1",
    "192.0.0.8", "192.88.99.1",
  ];
  for (const ip of blocked) it(`rejects ${ip}`, () => rejects(`http://${ip}/`, "non_public_address"));
  it("rejects shorthand forms the URL parser canonicalises to loopback", () => {
    rejects("http://2130706433/", "non_public_address");
    rejects("http://0x7f.1/", "non_public_address");
    rejects("http://0177.0.0.1/", "non_public_address");
    rejects("http://127.1/", "non_public_address");
  });
  for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.215.14", "172.32.0.1", "100.128.0.1", "11.0.0.1"]) {
    it(`accepts public ${ip}`, () => assert.ok(checkUrl(`https://${ip}/`).isIpLiteral));
  }
});

describe("url policy: IPv6 destinations", () => {
  const blocked = [
    "[::1]", "[::]", "[fe80::1]", "[fc00::1]", "[fd00:ec2::254]", "[ff02::1]", "[::ffff:127.0.0.1]",
    "[::ffff:10.0.0.1]", "[::ffff:169.254.169.254]", "[64:ff9b::7f00:1]", "[2001:db8::1]", "[2002:7f00:1::1]",
    "[2001::1]", "[fec0::1]", "[100::1]", "[::127.0.0.1]",
  ];
  for (const ip of blocked) it(`rejects ${ip}`, () => rejects(`http://${ip}/`, "non_public_address"));
  it("accepts public global unicast", () => {
    assert.ok(checkUrl("https://[2606:4700:4700::1111]/").isIpLiteral);
    assert.ok(checkUrl("https://[::ffff:8.8.8.8]/").isIpLiteral);
  });
  it("parses compressed and embedded forms", () => {
    assert.equal(parseIPv6("::1"), 1n);
    assert.equal(parseIPv6("::ffff:1.2.3.4"), (0xffffn << 32n) | 0x01020304n);
    assert.equal(parseIPv6("1:2:3:4:5:6:7:8:9"), null);
    assert.equal(parseIPv6("fe80::1%eth0"), null);
  });
});

describe("url policy: names", () => {
  for (const host of [
    "localhost", "foo.localhost", "printer.local", "metadata.google.internal", "host.docker.internal",
    "gateway.docker.internal", "router.lan", "nas.home.arpa", "x.test", "x.example", "x.invalid", "abc.onion",
    "1.0.0.127.in-addr.arpa", "intranet", "metadata", "wpad",
  ]) {
    it(`rejects ${host}`, () => rejects(`https://${host}/`, "non_public_host"));
  }
  it("rejects names with odd characters", () => rejects("https://exa_mple.org/", "invalid_host"));
});

describe("resolver answers and redirects", () => {
  it("rejects private resolver answers in either family", () => {
    assert.throws(() => assertPublicAddress("10.1.2.3", 4), PolicyError);
    assert.throws(() => assertPublicAddress("::1", 6), PolicyError);
    assert.throws(() => assertPublicAddress("::ffff:192.168.0.1", 6), PolicyError);
    assertPublicAddress("93.184.215.14", 4);
    assertPublicAddress("2606:4700::6810:84e5", 6);
  });
  it("forbids HTTPS-to-HTTP downgrades only", () => {
    assert.throws(() => checkRedirect(new URL("https://a.org/"), new URL("http://a.org/")), (e: any) => e.code === "https_downgrade");
    checkRedirect(new URL("http://a.org/"), new URL("https://a.org/"));
    checkRedirect(new URL("https://a.org/"), new URL("https://b.org/"));
  });
});
