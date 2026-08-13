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

#region Usings

using System.Net;
using System.Net.Sockets;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

// h3interop: our client against public HTTP/3 servers of eight different QUIC stacks — each with
// its own fresh connection and FULL certificate validation (chain + hostname). No -k.
//
// This is the one harness that runs the other way round. h3semantics and h3attack drive OUR server
// with foreign code; here our client is the one under test and the far end belongs to Cloudflare,
// Google, Meta and the rest.
//
// It reaches the open internet, so it is not part of tests/run-tests.ps1 — a gate that goes red
// because Akamai's bot protection dislikes a hosted runner teaches nobody anything. The nightly
// workflow runs it and records the output as an artifact instead. Details and history: INTEROP.md.
//
//   dotnet run --project tests/h3interop --configuration Release

(string Host, string Stack)[] targets =
[
    ("cloudflare-quic.com",   "quiche (Cloudflare)"),
    ("quic.nginx.org",        "nginx QUIC"),
    ("www.google.com",        "Google QUIC"),
    ("www.facebook.com",      "mvfst (Meta)"),
    ("www.litespeedtech.com", "lsquic (LiteSpeed)"),
    ("outlook.office.com",    "msquic (Microsoft)"),
    ("caddyserver.com",       "quic-go (Caddy)"),
    ("www.akamai.com",        "Akamai QUIC"),
];

Console.WriteLine("== HTTP/3 Conformance Tests — interop matrix (full certificate validation) ==\n");
Console.WriteLine($"{"Target",-24} {"Stack",-20} {"Group/Suite/Cert",-34} Result");
Console.WriteLine(new string('-', 100));

int reachable = 0;
foreach ((string targetHost, string stack) in targets)
{
    bool success = TryInterop(targetHost, out string crypto, out string result);
    if (success) reachable++;
    Console.WriteLine($"{targetHost,-24} {stack,-20} {crypto,-34} {(success ? "✓ " : "✗ ")}{result}");
}

Console.WriteLine(new string('-', 100));
Console.WriteLine($"\n{reachable}/{targets.Length} stacks reachable (2xx/3xx = the HTTP/3 stack runs end to end; "
                  + "3xx/4xx are regular responses such as redirects/bot protection).");

// Non-zero only when every single target failed. That threshold is deliberately loose: a night
// where six of eight answered says something about those two hosts, not about this stack, and a
// gate nobody trusts gets clicked away. Tightening it needs a runner baseline first — see the note
// in .github/workflows/nightly.yml.
return reachable > 0 ? 0 : 1;

// A single interop attempt: fresh connection, GET /, full cert validation. Returns the crypto
// profile and a result text; true as soon as an HTTP/3 status was received.
static bool TryInterop(string targetHost, out string crypto, out string result)
{
    crypto = "—";
    result = "";
    try
    {
        var addresses = Dns.GetHostAddresses(targetHost).Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
        if (addresses.Length == 0) { result = "no IPv4 address"; return false; }
        var remote = new IPEndPoint(addresses[0], 443);

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 400 };
        try { socket.IOControl(unchecked((int) 0x9800000C), [0, 0, 0, 0], null); } catch { /* non-Windows */ }

        using var conn = new Http3ClientConnection(targetHost, new TransportParameters(), CertificateValidationOptions.Default);
        conn.Start();

        void Pump()
        {
            conn.CheckTimeouts();
            foreach (byte[] dg in conn.GetDatagramsToSend())
                socket.SendTo(dg, remote);
            byte[] buffer = new byte[2048];
            for (int i = 0; i < 32; i++)
            {
                try
                {
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    int n = socket.ReceiveFrom(buffer, ref from);
                    conn.ProcessDatagram(buffer.AsSpan(0, n));
                }
                catch (SocketException) { break; }
            }
        }

        for (int round = 0; round < 40 && !conn.HandshakeConfirmed; round++)
            Pump();
        if (!conn.HandshakeConfirmed) { result = "handshake failed (may not offer HTTP/3)"; return false; }

        crypto = $"{conn.Quic.NegotiatedGroup}/{conn.Quic.NegotiatedCipherSuite}/{CertKind(conn.Quic.ServerCertificate?.PublicKey.Oid.Value)}";

        conn.InitializeHttp3();
        for (int round = 0; round < 3; round++) Pump();

        ulong streamId = conn.SendRequest(Http3Request.Get(targetHost, "/"));
        Http3Response? response = null;
        for (int round = 0; round < 200 && response is null; round++)
        {
            Pump();
            conn.TryGetResponse(streamId, out response);
        }
        conn.Close();
        foreach (byte[] dg in conn.GetDatagramsToSend()) socket.SendTo(dg, remote);

        if (response is null) { result = "no response"; return false; }
        result = $"HTTP/3 {response.Status}";
        return true;
    }
    catch (CertificateValidationException ex) { result = $"cert invalid: {ex.Message}"; return false; }
    catch (Exception ex) { result = $"{ex.GetType().Name}: {ex.Message}"; return false; }
}

// The public-key algorithm of a certificate from the SPKI OID (for the crypto column of the matrix).
static string CertKind(string? oid) => oid switch
{
    "1.2.840.10045.2.1"    => "ECDSA",
    "1.2.840.113549.1.1.1" => "RSA",
    "1.3.101.112"          => "Ed25519",
    "1.3.101.113"          => "Ed448",
    "2.16.840.1.101.3.4.3.17" or "2.16.840.1.101.3.4.3.18" or "2.16.840.1.101.3.4.3.19" => "ML-DSA",
    null                   => "?",
    _                      => oid,
};
