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

Our `H3Server` passes against two independent foreign client stacks:

| Client | QUIC backend | Verified |
|---|---|---|
| `curl` 8.21 (Windows, curl.se) | **ngtcp2** + nghttp3 + LibreSSL | `GET /` (200), `POST /echo` (byte-exact echo), `GET /big` (300 KB), `GET /hints` (103 Early Hints + 200 + trailers), connection reuse |
| `curl` 8.14 (WSL/Debian) | **OpenSSL-3.5-QUIC** + nghttp3 | same tests across the WSL2 NAT boundary (host IP from `ip route`) |

## Open (optional)

- **Browsers** (Firefox/Chrome) against `H3Server` — they require a trusted certificate
  (local CA instead of self-signed).
- Further targets as needed; the `--interop` mode is easy to extend in
  `samples/H3Get/Program.cs` (the `targets` list).
