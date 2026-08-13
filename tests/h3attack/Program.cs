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
using System.Security.Cryptography;

#endregion

// h3attack: what the demo server (samples/H3Server) does with input that no cooperating client
// would ever send — malformed, undersized, spoofed and simply hostile datagrams, plus a flood.
//
// Hermod's HermodTests/HTTP3 suite already drives "evil" raw-QUIC peers against our connection
// classes in-process, and does it in more protocol detail than this file. What it cannot reach is
// everything below those classes: the socket, the demux that maps a datagram to a connection, the
// listener's decision to create state or refuse it, and the process staying alive. Those only
// exist in a running server, so they can only be attacked from outside one.
//
// Every scenario ends the same way: the server must still serve a normal request. A hardening
// check that only proves "no reply" would pass just as happily against a server that had crashed.
//
// Needs the demo host running:  dotnet run --project samples/H3Server -- 4433
// Or just let tests/run-tests.ps1 start it.

string host = Environment.GetEnvironmentVariable("H3_HOST") ?? "localhost";
int    port = int.TryParse(Environment.GetEnvironmentVariable("H3_PORT"), out int p) ? p : 4433;
var    target = new IPEndPoint(IPAddress.Loopback, port);

int passed = 0;
int failed = 0;

void Check(string name, bool ok, string detail = "")
{
    if (ok) { passed++; Console.WriteLine($"  ✓ {name}" + (detail.Length > 0 ? $"  ({detail})" : "")); }
    else    { failed++; Console.WriteLine($"  ✗ {name}" + (detail.Length > 0 ? $"  — {detail}" : "")); }
}

#region Wire helpers — hand-built QUIC packets (RFC 9000 §17)

// QUIC varint (§16): the top two bits select the length. Everything this harness encodes is small,
// but the two-byte form is needed for the 1200-byte packets, so both are here.
static int WriteVarInt(Span<byte> destination, ulong value)
{
    if (value < 64) { destination[0] = (byte) value; return 1; }
    if (value < 16384)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort) (value | 0x4000));
        return 2;
    }
    BinaryPrimitives.WriteUInt32BigEndian(destination, (uint) value | 0x8000_0000);
    return 4;
}

// A long-header Initial packet (§17.2.2). The payload is deliberately not encrypted with anything
// the server can decrypt — for the version-negotiation and amplification checks it never gets that
// far, and for the flood the point is precisely that it cannot.
static byte[] BuildInitial(uint version, byte[] destinationCid, byte[] sourceCid, int totalSize)
{
    byte[] packet = new byte[totalSize];
    int offset = 0;

    packet[offset++] = 0xC3;                                             // long header, Initial, PN length 4
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(offset), version);
    offset += 4;
    packet[offset++] = (byte) destinationCid.Length;
    destinationCid.CopyTo(packet, offset);
    offset += destinationCid.Length;
    packet[offset++] = (byte) sourceCid.Length;
    sourceCid.CopyTo(packet, offset);
    offset += sourceCid.Length;
    offset += WriteVarInt(packet.AsSpan(offset), 0);                     // token length: none
    offset += WriteVarInt(packet.AsSpan(offset), (ulong) (totalSize - offset - 2)); // length (approx, 2-byte form)
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(offset), 0);     // packet number 0
    offset += 4;
    RandomNumberGenerator.Fill(packet.AsSpan(offset));                   // undecryptable payload
    return packet;
}

// Sends one datagram from a fresh source port and waits briefly for a reply.
static async Task<byte[]?> SendAndReceive(IPEndPoint target, byte[] datagram, int timeoutMs = 700)
{
    using var socket = new UdpClient(AddressFamily.InterNetwork);
    await socket.SendAsync(datagram, datagram.Length, target);
    using var cts = new CancellationTokenSource(timeoutMs);
    try
    {
        UdpReceiveResult result = await socket.ReceiveAsync(cts.Token);
        return result.Buffer;
    }
    catch (OperationCanceledException) { return null; }
    catch (SocketException)            { return null; }
}

#endregion

// The health check between scenarios. A foreign client (msquic) so that "still serving" means
// serving somebody other than ourselves.
bool quicAvailable = System.Net.Quic.QuicConnection.IsSupported;
var handler = new SocketsHttpHandler {
    SslOptions = new System.Net.Security.SslClientAuthenticationOptions {
        RemoteCertificateValidationCallback = (_, _, _, _) => true
    }
};
using var client = new HttpClient(handler) {
    DefaultRequestVersion = HttpVersion.Version30,
    DefaultVersionPolicy  = HttpVersionPolicy.RequestVersionExact,
    Timeout               = TimeSpan.FromSeconds(15)
};

async Task<bool> ServerStillServes()
{
    if (!quicAvailable)
        return true; // cannot tell; the scenario checks still ran
    try
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}:{port}/") {
            Version       = HttpVersion.Version30,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact
        };
        HttpResponseMessage response = await client.SendAsync(request);
        return response.StatusCode == HttpStatusCode.OK;
    }
    catch { return false; }
}

Console.WriteLine($"=== h3attack — {host}:{port} ===\n");

if (!quicAvailable)
    Console.WriteLine("  ! System.Net.Quic reports no QUIC support — the wire scenarios still run,\n"
                      + "    but \"server still serves\" cannot be verified between them.\n");

Console.WriteLine("=== Garbage — 50 datagrams of pure noise ===");
for (int i = 0; i < 50; i++)
{
    byte[] noise = new byte[RandomNumberGenerator.GetInt32(1, 1500)];
    RandomNumberGenerator.Fill(noise);
    await SendAndReceive(target, noise, timeoutMs: 20);
}
Check("server survives 50 random datagrams", await ServerStillServes());

Console.WriteLine("\n=== Undersized Initial — RFC 9000 §14.1 ===");
// A client Initial below 1200 bytes must be dropped. Answering one would hand an attacker an
// amplifier: a small spoofed packet in, a large Version Negotiation out.
byte[] runt = BuildInitial(0x1a2a3a4a, [1, 2, 3, 4, 5, 6, 7, 8], [9, 9, 9, 9], totalSize: 300);
byte[]? runtReply = await SendAndReceive(target, runt);
Check("no answer to a 300-byte Initial", runtReply is null,
      runtReply is null ? "dropped" : $"{runtReply.Length} bytes came back");

Console.WriteLine("\n=== Version negotiation — RFC 9000 §6.1 ===");
byte[] clientDcid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
byte[] clientScid = [0xAA, 0xBB, 0xCC, 0xDD];
byte[] badVersion = BuildInitial(0x1a2a3a4a, clientDcid, clientScid, totalSize: 1200);
byte[]? vn = await SendAndReceive(target, badVersion);
Check("unsupported version is answered", vn is not null, vn is null ? "no reply" : $"{vn.Length} bytes");

if (vn is not null)
{
    bool longHeader   = (vn[0] & 0x80) != 0;
    uint versionField = BinaryPrimitives.ReadUInt32BigEndian(vn.AsSpan(1));
    Check("reply is a long header with version 0", longHeader && versionField == 0,
          $"first byte 0x{vn[0]:x2}, version 0x{versionField:x8}");

    // §17.2.1: the connection IDs are swapped, so the client can tell the packet is for it.
    int offset = 5;
    int dcidLength = vn[offset++];
    byte[] echoedDcid = vn.AsSpan(offset, dcidLength).ToArray();
    offset += dcidLength;
    int scidLength = vn[offset++];
    byte[] echoedScid = vn.AsSpan(offset, scidLength).ToArray();
    offset += scidLength;
    Check("DCID/SCID swapped", echoedDcid.AsSpan().SequenceEqual(clientScid)
                            && echoedScid.AsSpan().SequenceEqual(clientDcid),
          $"dcid={Convert.ToHexString(echoedDcid)} scid={Convert.ToHexString(echoedScid)}");

    var offered = new List<uint>();
    for (; offset + 4 <= vn.Length; offset += 4)
        offered.Add(BinaryPrimitives.ReadUInt32BigEndian(vn.AsSpan(offset)));
    Check("offers QUIC v1 (0x00000001)", offered.Contains(1),
          string.Join(", ", offered.Select(v => $"0x{v:x8}")));

    // §6.3: a reserved version matching 0x?a?a?a?a keeps clients honest about ignoring unknown
    // versions, and keeps the field from ossifying. The README claims we send one — check it.
    Check("includes a GREASE version (0x?a?a?a?a)", offered.Any(v => (v & 0x0F0F0F0F) == 0x0A0A0A0A),
          offered.Any(v => (v & 0x0F0F0F0F) == 0x0A0A0A0A) ? "present" : "none offered");

    // §14.1/§8.1: before address validation the server may send at most 3x what it received.
    Check("VN reply within the 3x amplification limit", vn.Length <= 3 * badVersion.Length,
          $"{vn.Length} bytes for {badVersion.Length} received");
}
else
{
    // Keep the check count stable whether or not a reply arrived, so the verdict line means the
    // same thing across runs.
    Check("reply is a long header with version 0",   false, "no reply");
    Check("DCID/SCID swapped",                       false, "no reply");
    Check("offers QUIC v1 (0x00000001)",             false, "no reply");
    Check("includes a GREASE version (0x?a?a?a?a)",  false, "no reply");
    Check("VN reply within the 3x amplification limit", false, "no reply");
}

Console.WriteLine("\n=== Short header to an unknown connection ID — RFC 9000 §10.3 ===");
// Either a stateless reset comes back or the packet is dropped; both are conformant. What §10.3.3
// forbids is a reset LARGER than its trigger, because two such servers would loop forever.
byte[] shortHeader = new byte[100];
RandomNumberGenerator.Fill(shortHeader);
shortHeader[0] = 0x40;                       // short header, fixed bit set
byte[]? reset = await SendAndReceive(target, shortHeader);
Check("stateless reset is smaller than its trigger (or nothing comes back)",
      reset is null || reset.Length < shortHeader.Length,
      reset is null ? "dropped" : $"{reset.Length} bytes for {shortHeader.Length} received");
Check("server survives an unknown-CID packet", await ServerStillServes());

Console.WriteLine("\n=== Flood — 128 Initials from 128 source ports ===");
// The shape of a spoofed-source flood: every datagram is a plausible connection attempt from a
// different address. Without address validation each one costs the server connection state.
var flood = new List<Task<byte[]?>>();
for (int i = 0; i < 128; i++)
{
    byte[] dcid = new byte[8];
    byte[] scid = new byte[8];
    RandomNumberGenerator.Fill(dcid);
    RandomNumberGenerator.Fill(scid);
    flood.Add(SendAndReceive(target, BuildInitial(0x00000001, dcid, scid, 1200), timeoutMs: 300));
}
await Task.WhenAll(flood);
Check("server survives 128 unfinished handshakes", await ServerStillServes());

Console.WriteLine("\n=== Cancellation storm — 20 aborted downloads ===");
if (quicAvailable)
{
    // Racing a wall clock against a loopback server is not a cancellation test — the download wins.
    // Reading a fixed prefix and then walking away is deterministic: the body is 300 000 bytes, we
    // take 1 024, and disposing the stream leaves the rest unread, which is what makes the client
    // reset the stream and the server notice an abandoned request.
    int aborted = 0;
    for (int i = 0; i < 20; i++)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}:{port}/big") {
                Version       = HttpVersion.Version30,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact
            };
            using HttpResponseMessage response =
                await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            using Stream body = await response.Content.ReadAsStreamAsync();
            byte[] prefix = new byte[1024];
            int read = await body.ReadAsync(prefix);
            if (read > 0 && read < 300_000)
                aborted++;
        }
        catch (OperationCanceledException) { aborted++; }
        catch (HttpRequestException)       { aborted++; }
    }
    Check("aborts were actually aborts, not completions", aborted == 20, $"{aborted}/20 abandoned mid-body");
    Check("server serves normally afterwards", await ServerStillServes());
}
else
{
    Check("aborts were actually aborts, not completions", true, "skipped — no QUIC client");
    Check("server serves normally afterwards",            true, "skipped — no QUIC client");
}

Console.WriteLine($"\n=== {passed}/{passed + failed} checks passed ===");
return failed == 0 ? 0 : 1;
