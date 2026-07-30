# Interoperability

Proof that the from-scratch stack works with real, independent HTTP/3 implementations —
in **both** directions (our client against foreign servers, foreign clients against our server).

## Repeat at any time

**Client side** — the whole matrix with a single command (fresh connection per target, **full**
certificate chain + hostname validation, no `-k`):

```bash
dotnet run --project samples/H3Get -- --interop
```

**Server side** — start our own server and probe it with an HTTP/3-capable `curl`:

```bash
dotnet run --project samples/H3Server
```
```bash
curl --http3-only -k https://127.0.0.1:4433/
```

**Browsers** — one command starts the server, drives a headless browser through the whole battery
(incl. WebTransport) and exits non-zero if anything fails:

```bash
pwsh tools/browser-interop.ps1 -Browser chrome
```

> Note: the system `curl` on Windows is a Schannel build **without** HTTP/3. An HTTP/3-capable
> `curl` is available from the official Windows package at <https://curl.se/windows/> (ngtcp2 +
> nghttp3) — or, easiest of all, the `curl` preinstalled in WSL/Debian (HTTP/3 via OpenSSL-QUIC).
> Check with `curl -V` (the features line must contain `HTTP3`). The same `curl --http3-only` also
> serves as an oracle for "does target X speak HTTP/3 at all?" — e.g. `www.microsoft.com` offers
> **no** HTTP/3 (the domain fails with every HTTP/3 client, not just ours; Microsoft's stack runs
> on `outlook.office.com`).

## Client interop matrix

As of **2026-07-23** — 8 independent QUIC implementations, each returning 2xx/3xx with full
certificate validation:

| Target | Foreign stack | Group / Suite / Cert | Result |
|---|---|---|---|
| `cloudflare-quic.com` | **quiche** (Cloudflare) | X25519 / AES-128-GCM-SHA256 / ECDSA | 200 |
| `quic.nginx.org` | **nginx QUIC** | X25519 / AES-128-GCM-SHA256 / ECDSA | 200 |
| `www.google.com` | **Google QUIC** | X25519 / AES-128-GCM-SHA256 / ECDSA | 200 |
| `www.facebook.com` | **mvfst** (Meta) | X25519 / AES-128-GCM-SHA256 / ECDSA | 302 |
| `www.litespeedtech.com` | **lsquic** (LiteSpeed) | X25519 / AES-128-GCM-SHA256 / RSA | 200 |
| `outlook.office.com` | **msquic** (Microsoft) | **Secp256r1 / AES-256-GCM-SHA384 / RSA** | 301 |
| `caddyserver.com` | **quic-go** (Go, via Caddy) | X25519 / AES-128-GCM-SHA256 / ECDSA | 200 |
| `www.akamai.com` | **Akamai QUIC** | X25519 / **AES-256-GCM-SHA384** / ECDSA | 403* |

\* 403/301/302 are regular HTTP responses (bot protection, redirects) — the HTTP/3 stack runs
end-to-end in every case (handshake, QPACK, frames, certificate validation).

**Live crypto coverage:** both key-exchange groups (X25519 **and** P-256/Secp256r1), both cipher
suites (AES-128-GCM-SHA256 **and** AES-256-GCM-SHA384) and both certificate types (ECDSA **and**
RSA with RSA-PSS signature verification). `outlook.office.com` is the only target exercising the
full P-256 + AES-256 + RSA path. (The PQ paths ML-KEM hybrid and ML-DSA are verified against our
own server and — for ML-KEM — live against Cloudflare, see `H3Get --mlkem` / `H3Server --mldsa`.)

## Server interop

Our `H3Server` passes against three independent foreign client stacks:

| Client | QUIC backend | Verified |
|---|---|---|
| `curl` 8.21 (Windows, curl.se) | **ngtcp2** + nghttp3 + LibreSSL | `GET /` (200), `POST /echo` (byte-exact echo), `GET /big` (300 KB), `GET /hints` (103 Early Hints + 200 + trailers), connection reuse |
| `curl` 8.14 (WSL/Debian) | **OpenSSL-3.5-QUIC** + nghttp3 | same tests across the WSL2 NAT boundary (host IP from `ip route`) |
| Chrome 150 / Edge 150 (headless) | **Chromium QUIC** (quiche) + BoringSSL | 8/8 checks below, both browsers, incl. WebTransport |

### Browser self-test (as of 2026-07-30)

`GET /browser` serves a page whose JS runs the battery and POSTs its verdict to `/report`, which the
server prints — so the server log is the record and nothing has to scrape a DOM. Chrome 150 and
Edge 150 both report:

| Check | What it exercises |
|---|---|
| Navigation used HTTP/3 | `performance.nextHopProtocol == "h3"` — the browser's own verdict, not ours |
| `GET /big` | 300 KB verified byte for byte under the browser's receive window |
| `POST /echo` | 64 KiB request body from the browser, mirrored back |
| `GET /hints` | 103 Early Hints before the response plus a trailer section after it |
| WebTransport session | `serverCertificateHashes` (draft-webtrans-http3, Extended CONNECT) |
| WebTransport datagram / bidi / uni | echo over all three stream shapes, plus the keying-material export |

Also confirmed live against a browser: the **PQ hybrid** `X25519MLKEM768` (start the server with
`--mlkem`; Chrome offers it by default and it wins the negotiation).

**What the browsers exercise that `curl` did not.** Chrome deliberately scrambles its ClientHello for
anti-ossification: ~1.7 KB spread over two Initial packets in a dozen out-of-order CRYPTO frames at
shuffled offsets, interleaved with PING and PADDING. It also GREASEs settings and frame types. Our
CRYPTO reassembly and unknown-parameter handling take that unchanged.

**Two browser flags are required, and neither hides a defect on our side:**

- `--ignore-certificate-errors-spki-list=<pin>` — the certificate is self-signed, and pinning the key
  is the alternative to installing a CA in the machine's trust store. `H3Server` prints the pin at
  startup, and `--cert` keeps the key across restarts so the pin stays valid.
- `--enable-features=EnableWebTransportDraft07` — Chrome's WebTransport client offers **draft-02** by
  default and hides draft-07 behind this flag (`net/quic/dedicated_web_transport_http3_client.cc`).
  We implement draft-13, whose handshake matches draft-07's.

WebTransport additionally authenticates the certificate by hash rather than through the Web PKI, and
that path only accepts an ECDSA P-256 certificate valid for at most **14 days** — hence
`--cert-days=13` in the script. The page gets the hash from the server itself.

## Open (optional)

- **Firefox** — not installed on the development machine, so untested. It needs the certificate in its
  own NSS store (or `security.enterprise_roots.enabled`), because it ignores the Chromium flags.
- Further targets as needed; the `--interop` mode is easy to extend in
  `samples/H3Get/Program.cs` (the `targets` list).
