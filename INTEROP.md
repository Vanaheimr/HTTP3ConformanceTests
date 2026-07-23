# Interoperabilität

Nachweis, dass der from-scratch-Stack mit echten, fremden HTTP/3-Implementierungen zusammenarbeitet —
in **beide** Richtungen (unser Client gegen fremde Server, fremde Clients gegen unseren Server).

## Jederzeit wiederholen

**Client-Seite** — die ganze Matrix mit einem Befehl (frische Verbindung je Ziel, **volle**
Zertifikatskette + Hostname, kein `-k`):

```bash
dotnet run --project samples/H3Get -- --interop
```

**Server-Seite** — den eigenen Server starten und mit einem HTTP/3-fähigen `curl` prüfen:

```bash
dotnet run --project samples/H3Server
```
```bash
curl --http3-only -k https://127.0.0.1:4433/
```

> Hinweis: Das System-`curl` unter Windows ist ein Schannel-Build **ohne** HTTP/3. Ein HTTP/3-fähiges
> `curl` liefert das offizielle Windows-Paket von <https://curl.se/windows/> (ngtcp2 + nghttp3) — oder,
> am einfachsten, das in WSL/Debian vorinstallierte `curl` (HTTP/3 über OpenSSL-QUIC). Prüfen mit
> `curl -V` (Feature-Zeile muss `HTTP3` enthalten). Dasselbe `curl --http3-only` taugt auch als Orakel
> „spricht Ziel X überhaupt HTTP/3?" — z. B. `www.microsoft.com` bietet **kein** HTTP/3 (die Domain
> scheitert bei jedem HTTP/3-Client, nicht nur bei uns; der Microsoft-Stack läuft über
> `outlook.office.com`).

## Client-Interop-Matrix

Stand **2026-07-23** — 8 unabhängige QUIC-Implementierungen, je Status 2xx/3xx mit voller
Zertifikatsprüfung:

| Ziel | Fremd-Stack | Gruppe / Suite / Cert | Ergebnis |
|---|---|---|---|
| `cloudflare-quic.com` | **quiche** (Cloudflare) | X25519 / AES-128-GCM-SHA256 / ECDSA | 200 |
| `quic.nginx.org` | **nginx QUIC** | X25519 / AES-128-GCM-SHA256 / ECDSA | 200 |
| `www.google.com` | **Google QUIC** | X25519 / AES-128-GCM-SHA256 / ECDSA | 200 |
| `www.facebook.com` | **mvfst** (Meta) | X25519 / AES-128-GCM-SHA256 / ECDSA | 302 |
| `www.litespeedtech.com` | **lsquic** (LiteSpeed) | X25519 / AES-128-GCM-SHA256 / RSA | 200 |
| `outlook.office.com` | **msquic** (Microsoft) | **Secp256r1 / AES-256-GCM-SHA384 / RSA** | 301 |
| `caddyserver.com` | **quic-go** (Go, via Caddy) | X25519 / AES-128-GCM-SHA256 / ECDSA | 200 |
| `www.akamai.com` | **Akamai QUIC** | X25519 / **AES-256-GCM-SHA384** / ECDSA | 403* |

\* 403/301/302 sind reguläre HTTP-Antworten (Bot-Schutz, Redirect) — der HTTP/3-Stack läuft in allen
Fällen end-to-end durch (Handshake, QPACK, Frames, Cert-Prüfung).

**Krypto-Abdeckung live:** beide Schlüsselaustausch-Gruppen (X25519 **und** P-256/Secp256r1), beide
Cipher-Suiten (AES-128-GCM-SHA256 **und** AES-256-GCM-SHA384) und beide Zertifikatstypen (ECDSA **und**
RSA mit RSA-PSS-Signaturprüfung). `outlook.office.com` übt als einziges Ziel den kompletten Pfad
P-256 + AES-256 + RSA. (Die PQ-Pfade ML-KEM-Hybrid und ML-DSA werden gegen den eigenen Server sowie —
für ML-KEM — live gegen Cloudflare geprüft, siehe `H3Get --mlkem` / `H3Server --mldsa`.)

## Server-Interop

Unser `H3Server` besteht gegen zwei unabhängige fremde Client-Stacks:

| Client | QUIC-Backend | geprüft |
|---|---|---|
| `curl` 8.21 (Windows, curl.se) | **ngtcp2** + nghttp3 + LibreSSL | `GET /` (200), `POST /echo` (byte-genaues Echo), `GET /big` (300 KB), `GET /hints` (103 Early Hints + 200 + Trailer), Connection-Reuse |
| `curl` 8.14 (WSL/Debian) | **OpenSSL-3.5-QUIC** + nghttp3 | dieselben Tests über die WSL2-NAT-Grenze (Host-IP aus `ip route`) |

## Offen (Kür)

- **Browser** (Firefox/Chrome) gegen `H3Server` — brauchen ein vertrauenswürdiges Zertifikat
  (lokale CA statt self-signed).
- Weitere Ziele nach Bedarf; der `--interop`-Modus lässt sich in `samples/H3Get/Program.cs`
  (Liste `targets`) leicht erweitern.
