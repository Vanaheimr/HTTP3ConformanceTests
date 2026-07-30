/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/// <summary>
/// The page behind <c>GET /browser</c>: a self-test that a real browser runs against this server.
/// Its JS exercises what no command-line client reaches the same way — the browser's own fetch stack
/// with its own flow control, and WebTransport from an independent implementation — and then POSTs a
/// JSON summary to <c>/report</c>. The server log is therefore the evidence; nothing has to scrape
/// the DOM or drive the DevTools protocol, which is what makes the check scriptable in headless mode.
/// </summary>
static class BrowserTestPage
{
    /// <summary>
    /// Renders the page for a server whose certificate hashes to
    /// <paramref name="certificateHashSha256"/> (lowercase hex). The hash goes into the page because
    /// WebTransport authenticates a self-signed certificate against exactly that value — the server
    /// knows it, so nobody has to copy it onto a command line.
    /// </summary>
    public static string Render(string certificateHashSha256)
        => Html.Replace("{{CERTIFICATE_HASH}}", certificateHashSha256);

    private const string Html = """
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><title>HTTP/3 browser self-test</title></head>
        <body>
        <h1>HTTP/3 browser self-test</h1>
        <p>Results are posted to <code>/report</code> and printed by the server.</p>
        <pre id="out">running …</pre>
        <script>
        const results = [];
        const out = document.getElementById('out');

        function record(name, ok, detail) {
          results.push({ name, ok, detail });
          out.textContent += "\n" + (ok ? "PASS  " : "FAIL  ") + name + "  (" + detail + ")";
        }

        // Every step is bounded: a stalled read must not leave the whole page hanging, because the
        // report is what the server prints and a missing report is indistinguishable from a crash.
        function withTimeout(promise, ms, what) {
          return Promise.race([
            promise,
            new Promise((_, reject) => setTimeout(() => reject(new Error("timeout after " + ms + " ms: " + what)), ms)),
          ]);
        }

        async function run(name, fn) {
          try { await withTimeout(fn(), 15000, name); }
          catch (e) { record(name, false, String(e)); }
        }

        // GET /big: 300 KB with a deterministic pattern. Exercises the browser's receive window and
        // our DATA framing over many packets, and verifies the bytes rather than just the length.
        async function bigBody() {
          const response = await fetch('/big');
          const bytes = new Uint8Array(await response.arrayBuffer());
          let mismatch = -1;
          for (let i = 0; i < bytes.length; i++)
            if (bytes[i] !== ((i * 13 + 5) & 0xff)) { mismatch = i; break; }
          record('GET /big (300 KB, byte-exact)',
                 bytes.length === 300000 && mismatch < 0,
                 bytes.length + ' bytes, first mismatch ' + mismatch);
        }

        // POST /echo: a request body from the browser, mirrored back byte for byte.
        async function echoBody() {
          const sent = new Uint8Array(64 * 1024);
          for (let i = 0; i < sent.length; i++) sent[i] = (i * 7 + 3) & 0xff;
          const response = await fetch('/echo', { method: 'POST', body: sent });
          const back = new Uint8Array(await response.arrayBuffer());
          let equal = back.length === sent.length;
          for (let i = 0; equal && i < sent.length; i++) equal = back[i] === sent[i];
          record('POST /echo (64 KiB round-trip)', equal, back.length + ' bytes back');
        }

        // GET /hints: 103 Early Hints before the final response plus a trailer section after it.
        // Neither is visible to JS — the point is that the browser accepts the sequence at all.
        async function earlyHints() {
          const response = await fetch('/hints');
          const text = await response.text();
          record('GET /hints (103 + trailers)',
                 response.status === 200 && text.includes('Body after 103.'),
                 'status ' + response.status + ', ' + text.length + ' chars');
        }

        // WebTransport (draft-webtrans-http3) from a foreign implementation: datagrams, a
        // bidirectional stream and a unidirectional one, all against the /wt echo handler.
        //
        // The connection is authenticated by certificate hash rather than by the Web PKI. A browser
        // launched with --ignore-certificate-errors-spki-list still refuses a WebTransport session to
        // an untrusted certificate — that flag covers ordinary requests, not this path — so the only
        // way in without touching the machine's trust store is serverCertificateHashes, which the
        // server fills in below. It is rejected unless the certificate is ECDSA P-256 and valid for at
        // most 14 days, hence H3Server's --cert-days.
        const certificateHash = '{{CERTIFICATE_HASH}}';

        function hexToBytes(hex) {
          const bytes = new Uint8Array(hex.length / 2);
          for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
          return bytes;
        }

        async function webTransport() {
          if (typeof WebTransport === 'undefined') {
            record('WebTransport', false, 'not implemented by this browser');
            return;
          }
          const url = 'https://' + location.host + '/wt';
          let transport;
          try {
            transport = new WebTransport(url, {
              serverCertificateHashes: [{ algorithm: 'sha-256', value: hexToBytes(certificateHash) }],
            });
            await transport.ready;
            record('WebTransport session (serverCertificateHashes)', true, 'certificate hash accepted');
          }
          catch (e) {
            // Fall back to the Web PKI so the report distinguishes "hash refused" from "server broke".
            record('WebTransport session (serverCertificateHashes)', false, String(e));
            transport = new WebTransport(url);
            await transport.ready;
            record('WebTransport session (Web PKI)', true, 'trusted chain accepted');
          }

          const writer = transport.datagrams.writable.getWriter();
          const reader = transport.datagrams.readable.getReader();
          await writer.write(new TextEncoder().encode('datagram-ping'));
          const datagram = await reader.read();
          record('WebTransport datagram echo',
                 new TextDecoder().decode(datagram.value) === 'datagram-ping',
                 datagram.value.length + ' bytes');

          const bidi = await transport.createBidirectionalStream();
          const bidiWriter = bidi.writable.getWriter();
          await bidiWriter.write(new TextEncoder().encode('bidi-hello'));
          await bidiWriter.close();
          let echoed = '';
          const bidiReader = bidi.readable.getReader();
          for (;;) {
            const chunk = await bidiReader.read();
            if (chunk.done) break;
            echoed += new TextDecoder().decode(chunk.value);
          }
          record('WebTransport bidirectional stream echo', echoed === 'bidi-hello', '"' + echoed + '"');

          // Unidirectional: nothing comes back, so the server log is the only witness.
          const uni = await transport.createUnidirectionalStream();
          const uniWriter = uni.getWriter();
          await uniWriter.write(new TextEncoder().encode('uni-hello'));
          await uniWriter.close();
          record('WebTransport unidirectional stream', true, 'sent — see the server log');

          transport.close();
        }

        (async () => {
          out.textContent = '';
          // The browser's own verdict on which protocol carried this page.
          const navigation = performance.getEntriesByType('navigation')[0];
          const hop = navigation ? navigation.nextHopProtocol : '(unknown)';
          record('Navigation used HTTP/3', hop === 'h3', 'nextHopProtocol = "' + hop + '"');

          await run('GET /big (300 KB, byte-exact)', bigBody);
          await run('POST /echo (64 KiB round-trip)', echoBody);
          await run('GET /hints (103 + trailers)', earlyHints);
          await run('WebTransport', webTransport);

          await fetch('/report', {
            method:  'POST',
            headers: { 'content-type': 'application/json' },
            body:    JSON.stringify({ userAgent: navigator.userAgent, results }),
          });
        })();
        </script>
        </body></html>
        """;
}
