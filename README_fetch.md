# libv2ray_fetch — HTTP/DNS fetch with fragment, ECH and uTLS

Two additive functions in [`libv2ray_fetch.go`](libv2ray_fetch.go) that reuse
xray-core's own TLS-fragmentation, ECH and uTLS code. `GetDataFromWeb` is
unchanged and unaffected.

| function | purpose |
| --- | --- |
| `FetchWeb(optionsJSON string) *FetchResult` | HTTP(S) GET/POST |
| `ResolveDoH(optionsJSON string) *DNSResult` | DNS query over DoH |

Both take a single JSON options string, so the binding signature stays stable as
options are added. Both accept the same transport options: proxy, fragment, ECH,
uTLS fingerprint, browser header profile.

---

## 1. Full options reference

Every accepted key in one place. Two pairs are mutually exclusive:

* `fragment` and `proxy` — a proxy reassembles the stream, so the combination is
  rejected outright. Fragment on the direct path.
* `ech.configList` and `ech.domain` + `ech.doh` — a literal config list skips the
  DNS lookup.

### `FetchWeb`

```json
{
  "url": "https://example.com/api/sub",
  "method": "GET",
  "data": "",

  "timeout": 15000,
  "proxy": "",
  "ip": "",
  "alpn": "auto",
  "allowInsecure": false,
  "serverName": "",

  "fingerprint": "chrome",
  "fragment": {
    "packets": "tlshello",
    "lengths": ["1-3", "10-30"],
    "delays":  ["5-15", "5-15"],
    "maxSplit": "6-10"
  },
  "ech": {
    "domain": "encryptedsni.com",
    "doh": "https://1.1.1.1/dns-query",
    "configList": ""
  },

  "browser": "chrome",
  "variant": "nav",
  "userAgent": "",
  "headers": { "X-Request-Id": "abc123" }
}
```

To go through xray instead, set `"proxy": "http://127.0.0.1:10809"` and remove
`fragment`. Nothing else changes.

Result:

```json
{
  "RespBody":    "<!DOCTYPE html>...",
  "RespHeader":  "",
  "RespHeaders": "{\"Content-Type\":[\"text/html\"]}",
  "RespError":   "",
  "StatusCode":  200,
  "Proto":       "HTTP/2.0",
  "EchAccepted": true
}
```

### `ResolveDoH`

```json
{
  "domain": "www.google.com",
  "type": "A",
  "server": "https://1.1.1.1/dns-query",

  "timeout": 20000,
  "proxy": "",
  "ip": "",
  "alpn": "auto",
  "allowInsecure": false,
  "serverName": "",

  "fingerprint": "",
  "fragment": {
    "packets": "tlshello",
    "lengths": ["1-3", "10-30"],
    "delays":  ["5-15", "5-15"],
    "maxSplit": "6-10"
  },
  "ech": {
    "domain": "encryptedsni.com",
    "doh": "https://1.1.1.1/dns-query",
    "configList": ""
  },

  "browser": "chrome",
  "variant": "fetch",
  "userAgent": "",
  "headers": { "X-Request-Id": "abc123" }
}
```

Here `ech` protects the SNI of the **DoH connection itself**, so it needs the
DoH host to have a usable ECHConfigList. No major public resolver publishes one
today (`cloudflare-dns.com`, `dns.google`, `dns.quad9.net`, `dns.adguard-dns.com`
all lack an `ech=` key), but `ech.domain` can borrow a config from another name
at the same provider: `"server": "https://cloudflare-dns.com/dns-query"` with
`"domain": "encryptedsni.com"` yields `EchAccepted: true`, because what has to
match is the ECH public name, not the request host.

Result:

```json
{
  "Answers":     "[{\"name\":\"www.google.com\",\"type\":\"A\",\"ttl\":295,\"value\":\"142.251.150.119\"}]",
  "IPs":         "142.251.150.119,142.251.151.119",
  "Rcode":       "NOERROR",
  "TTL":         295,
  "Proto":       "HTTP/2.0",
  "EchAccepted": false,
  "RespError":   ""
}
```

---


## 2. Options JSON

### Shared transport options

| key | type | default | meaning |
| --- | --- | --- | --- |
| `proxy` | string | `""` (direct) | `http://host:port` or `socks5://host:port`, optional `user:pass@`. Empty follows OS routing, exactly like `GetDataFromWeb`. |
| `ip` | string | `""` | Connect to this address instead of resolving the URL host. See [Pinned IP](#pinned-ip). |
| `timeout` | int | `8000` | Whole-operation budget, milliseconds. |
| `allowInsecure` | bool | `false` | Skip certificate verification. |
| `serverName` | string | URL host | SNI / certificate name override. |
| `alpn` | string | `"auto"` | HTTP version: `auto`, `h1`, `h2`. See [ALPN](#alpn). |
| `fingerprint` | string | `""` (stdlib TLS) | uTLS ClientHello. See [Fingerprints](#fingerprints). |
| `fragment` | object | none | TLS ClientHello splitting. See [Fragment](#fragment). **Cannot be combined with `proxy`.** |
| `ech` | object | none | Encrypted Client Hello. See [ECH](#ech). |
| `browser` | string | `"chrome"` | Header profile: `chrome`, `edge`, `firefox`, `safari`, `curl`, `golang`. |
| `variant` | string | `nav` for GET, `fetch` otherwise | Request context: `nav`, `fetch`, `ws`. |
| `userAgent` | string | profile's own | Overrides the UA but **keeps** the rest of the profile. |
| `headers` | object | none | `{"K":"V"}`, applied last, wins over everything above. |

### `FetchWeb` extra keys

| key | type | default | meaning |
| --- | --- | --- | --- |
| `url` | string | **required** | `http://` or `https://`. |
| `method` | string | `POST` if `data` set, else `GET` | Any HTTP method. |
| `data` | string | `""` | Request body. `Content-Type: application/json` is added if you don't set one. |

### `ResolveDoH` extra keys

| key | type | default | meaning |
| --- | --- | --- | --- |
| `domain` | string | **required** | Name to query. |
| `server` | string | **required** | DoH endpoint, e.g. `https://1.1.1.1/dns-query`. |
| `type` | string | `A` | `A`, `AAAA`, `HTTPS`, `TXT`, `CNAME`, `MX`, `NS`, `SRV`, `SOA`, `PTR`, `SVCB`, … |

### Fragment

Same JSON shape as an xray config's fragment mask — copy values straight from a
working config. Parsed and validated by xray's own `infra/conf.FragmentMask`.

```json
"fragment": {
  "packets": "tlshello",
  "lengths": ["1-3", "10-30"],
  "delays":  ["5-15", "5-15"],
  "maxSplit": "6-10"
}
```

| key | meaning |
| --- | --- |
| `packets` | `"tlshello"` splits only the first TLS record (record-layer aware). `"1-5"` splits packets 1..5 of any stream. `""` splits everything. |
| `lengths` | Per-segment byte range. Entry *n* applies to segment *n*; the last entry repeats. Legacy scalar `"length": "10-20"` also accepted. |
| `delays` | Per-segment sleep in ms, same indexing. Legacy `"delay"` accepted. |
| `maxSplit` | Cap on the number of segments. |

A single `"delays": ["0-0"]` merges every segment into one write — one TCP
segment, which a reassembling DPI sees whole. Use a non-zero delay.

### ECH

```json
"ech": { "domain": "encryptedsni.com", "doh": "https://1.1.1.1/dns-query" }
```

| key | meaning |
| --- | --- |
| `domain` | Name whose HTTPS (type-65) record carries the ECHConfigList. Defaults to the request host. |
| `doh` | DoH endpoint used for that lookup. |
| `configList` | base64 ECHConfigList, used verbatim; skips DNS entirely. |

The lookup runs over **this call's own transport**, so it honours `proxy` and
`fragment`. xray's `tls.QueryRecord` is deliberately not used: it dials via
`internet.DialSystem`, which `NewV2RayPoint` points at the `ProtectedDialer`, so
the DNS query would leave the device on a different path than the request.
Results are cached until the record's TTL expires.

### Pinned IP

```json
"ip": "188.114.97.6"
```

Connects to that address instead of resolving the URL's host. Everything else
still derives from the URL — SNI, certificate verification and the `Host` header
all keep the original hostname — so this fronts the request through a chosen
edge address rather than rewriting it.

* The port still comes from the URL, so put a non-standard one there:
  `https://cloudflare-dns.com:2053/dns-query`.
* IPv4 and IPv6 literals both work. A hostname is rejected up front.
* Applies through `proxy` too: the CONNECT / SOCKS request names the pinned
  address, so the proxy dials it.
* `fragment` and `ech` apply exactly as they do without a pin.
* **Not inherited by the ECH lookup.** `ip` pins this request's host, and the
  ECH resolver is a different server. Pin that one by putting a literal address
  in `ech.doh`, e.g. `https://1.1.1.1/dns-query`.
* Empty or absent means normal resolution.

Verified against `cloudflare-dns.com` pinned to `188.114.97.6`, reading back
Cloudflare's own `/cdn-cgi/trace`:

```
h=cloudflare-dns.com   tls=TLSv1.3   http=http/2   sni=plaintext     # ip + fragment
h=cloudflare-dns.com   tls=TLSv1.3   http=http/2   sni=encrypted     # ip + fragment + ech
```

`h=` confirms the Host header survived the pin; `sni=encrypted` confirms ECH
still applies on a pinned connection.

### ALPN

```json
"alpn": "auto"
```

Pins the HTTP version. HTTP/3 is not supported — it runs over QUIC, and this
transport is TCP only; `"h3"` is refused with that explanation rather than
silently downgrading.

| value | offer | behaviour |
| --- | --- | --- |
| `auto` (default) | `h2`, `http/1.1` | Server picks. Every major DoH resolver picks h2. |
| `h1` | `http/1.1` only | h2 cannot be negotiated. |
| `h2` | `h2` only | Handshake fails if the server will not speak h2. |

`http/1.1`, `http1`, `http2`, `http/2` are accepted aliases, case-insensitive.
`h2` requires an `https` url — cleartext h2c is not supported.

On the standard TLS path the offer is ours, so `alpn` is enforced exactly. With
`"h2"` the request is driven through `x/net/http2` directly, because
`net/http`'s own HTTP/2 setup rewrites `NextProtos` to re-add `http/1.1` and
would let a server downgrade.

**With a `fingerprint`, `alpn` becomes an assertion rather than a control.** The
uTLS ClientHello carries its own ALPN list, so the offer is not ours to change;
a mismatch fails loudly instead of quietly using another version:

```
alpn "h1" requested but fingerprint "chrome" negotiated "h2": a uTLS ClientHello
carries its own ALPN list, so pick a fingerprint that offers the version you
want (or drop the fingerprint)
```

`chrome` and `firefox` offer `h2, http/1.1`; `android` and `randomizednoalpn`
end up on HTTP/1.1. So for forced h1 with a fingerprint, use `android`; for
forced h1 in general, drop `fingerprint`.

### Fingerprints

`""` (default) uses the standard library: ECH works and HTTP/2 is negotiated
automatically. Set a name to send a real browser ClientHello instead —
`chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`,
plus pinned ones like `hellochrome_133`, `hellofirefox_148`,
`helloandroid_11_okhttp`.

**With `ech` set, only `chrome`, `firefox`, `hellochrome_*` and `hellofirefox_*`
work.** Every other hello fails the handshake (`malformed outer client hello`,
or plain handshake failure); `random` re-rolls per process start out of a pool
containing incompatible entries, so it would fail nondeterministically. All
three cases are rejected up front with an explanatory error rather than left to
fail at connect time.

`android` / `helloandroid_11_okhttp` negotiates TLS 1.2 with no ALPN, so it is
HTTP/1.1 only — a coherent pairing for `"userAgent": "okhttp/3.12.1"`.

---

## 3. Results

### `FetchResult`

| field | Java getter | meaning |
| --- | --- | --- |
| `RespBody` | `getRespBody()` | Body, gzip-decoded. Empty when `StatusCode > 299`. |
| `RespHeader` | `getRespHeader()` | `X-From-Server`, for parity with `GetDataFromWeb`. |
| `RespHeaders` | `getRespHeaders()` | All response headers as a JSON object. |
| `RespError` | `getRespError()` | Empty on success. Check this first. |
| `StatusCode` | `getStatusCode()` → `long` | HTTP status. |
| `Proto` | `getProto()` | `"HTTP/1.1"` / `"HTTP/2.0"`. |
| `EchAccepted` | `getEchAccepted()` | `true` only if the server actually accepted ECH. |

`StatusCode > 299` sets `RespError` to `ERR status code: <n>\n<body>` and leaves
`RespBody` empty — same convention as `GetDataFromWeb`.

### `DNSResult`

| field | Java getter | meaning |
| --- | --- | --- |
| `Answers` | `getAnswers()` | JSON array of `{name,type,ttl,value}`. |
| `IPs` | `getIPs()` | Comma-separated A/AAAA answers. |
| `Rcode` | `getRcode()` | `"NOERROR"`, `"NXDOMAIN"`, … |
| `TTL` | `getTTL()` → `long` | TTL of the first answer. |
| `Proto` | `getProto()` | HTTP version used for the DoH request. |
| `EchAccepted` | `getEchAccepted()` | Whether the DoH connection itself used ECH. |
| `RespError` | `getRespError()` | Empty on success. |

An empty `Answers` (`[]`) with `Rcode: "NOERROR"` is a valid no-data answer, not
an error.

---

## 4. Calling from Android

```java
import libv2ray.Libv2ray;
import libv2ray.FetchResult;
import libv2ray.DNSResult;
```

### Subscription fetch, direct, with fragment

```java
String opts = "{"
    + "\"url\":\"https://example.com/sub\","
    + "\"timeout\":8000,"
    + "\"fragment\":{\"packets\":\"tlshello\",\"lengths\":[\"1-3\",\"10-30\"],\"delays\":[\"5-15\",\"5-15\"]}"
    + "}";

FetchResult r = Libv2ray.fetchWeb(opts);
if (!r.getRespError().isEmpty()) {
    Log.e("fetch", r.getRespError());
} else {
    Log.i("fetch", "HTTP " + r.getStatusCode() + " " + r.getProto());
    handle(r.getRespBody());
}
```

Build the JSON with `JSONObject` rather than string concatenation in real code:

```java
JSONObject o = new JSONObject();
o.put("url", url);
o.put("timeout", 8000);
if (overXray) o.put("proxy", "http://127.0.0.1:10809");
if (useEch) o.put("ech", new JSONObject()
        .put("domain", "encryptedsni.com")
        .put("doh", "https://1.1.1.1/dns-query"));
FetchResult r = Libv2ray.fetchWeb(o.toString());
```

### Through xray, with ECH and a Chrome fingerprint

```json
{
  "url": "https://example.com/sub",
  "proxy": "http://127.0.0.1:10809",
  "timeout": 15000,
  "fingerprint": "chrome",
  "ech": { "domain": "encryptedsni.com", "doh": "https://1.1.1.1/dns-query" }
}
```

### Preserving the existing WARP/CF API call

```json
{
  "url": "https://api.cloudflareclient.com/v0a2158/reg",
  "method": "POST",
  "data": "{...}",
  "timeout": 7000,
  "fingerprint": "android",
  "userAgent": "okhttp/3.12.1",
  "headers": {
    "Content-Type": "application/json; charset=UTF-8",
    "CF-Client-Version": "a-6.30-3596",
    "Accept-Encoding": "gzip"
  }
}
```

### DNS lookup

```java
String q = "{\"domain\":\"www.google.com\",\"type\":\"A\","
         + "\"server\":\"https://1.1.1.1/dns-query\",\"timeout\":8000,"
         + "\"proxy\":\"http://127.0.0.1:10809\"}";

DNSResult d = Libv2ray.resolveDoH(q);
if (d.getRespError().isEmpty() && d.getRcode().equals("NOERROR")) {
    String[] ips = d.getIPs().split(",");   // "" when there are no A/AAAA answers
}
```

Both calls block. Run them off the main thread (`Thread`, `ExecutorService`, or
a coroutine on `Dispatchers.IO`), as `wget_module` already does.

---

## 5. Calling from Go

```go
import "github.com/GFW-knocker/AndroidLibXrayLite"
```

Same API, no binding layer:

```go
r := libv2ray.FetchWeb(`{
  "url": "https://example.com/sub",
  "timeout": 8000,
  "fragment": {"packets":"tlshello","lengths":["1-3","10-30"],"delays":["5-15","5-15"]}
}`)
if r.RespError != "" {
    return errors.New(r.RespError)
}
fmt.Println(r.StatusCode, r.Proto, r.EchAccepted, len(r.RespBody))

d := libv2ray.ResolveDoH(`{"domain":"example.com","type":"HTTPS","server":"https://1.1.1.1/dns-query"}`)
fmt.Println(d.Rcode, d.Answers)
```

The package as a whole is Android-only — `libv2ray_support.go` uses
`golang.org/x/sys/unix`, so it will not build on Windows or macOS. To exercise
these two functions on a desktop, copy `libv2ray_fetch.go` into a scratch module
on its own; it has no Android dependencies.

---

## 6. Notes and constraints

**`proxy: ""` is not "always direct."** It follows OS routing. That is direct
today only because MahsaNG excludes its own package from the VPN in every mode
(`V2RayVpnService.kt`, all three branches). Put the package back inside the VPN
and these calls would route through the tun, same as `GetDataFromWeb`.

**`fragment` + `proxy` is rejected, not ignored.** A proxy reassembles the
stream, and with `packets: "tlshello"` the first write behind a CONNECT is the
CONNECT line, so the ClientHello would slip through unfragmented — a silent
no-op. Fragment on the direct path; for the tunnelled path configure
fragmentation in the xray outbound.

**ECH fails closed.** With `ech` set and no usable ECHConfigList, the request
fails rather than falling back to a plaintext SNI. A missing record gives
`no ECH record for <domain>` instead of xray's `tls: malformed ECHConfigList`.

**`EchAccepted` is the ground truth.** It comes from the TLS connection state,
not from whether a config was found. `EchAccepted == false` with no error means
the server declined ECH.

**HTTP versions.** HTTP/1.1 and HTTP/2 only; see [ALPN](#alpn) to pin one.
HTTP/3 is out of scope — it needs QUIC, and neither `fragment` (which splits a
TLS record on a TCP stream) nor `proxy` (CONNECT and SOCKS5 are TCP) could
follow it there. On the uTLS path ALPN comes from the fingerprint, so the
handshake happens in the dialer and the negotiated protocol picks between
`net/http` and `x/net/http2`. Redirects that cross an HTTP-version boundary fail
with an explicit error rather than corrupt output.

**Body cap** 32 MiB; DoH response cap 64 KiB.

**Proxy schemes** `http://` (CONNECT, Basic auth supported) ,
`socks5://` , `socks5h://`. note that `https://` proxies are not supported because main usage is to connect to Localhost xray inbound.
