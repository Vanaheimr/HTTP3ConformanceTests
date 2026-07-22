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

using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// WebTransport Application Protocol Negotiation (draft-ietf-webtrans-http3-13 §3.3): der ALPN-artige
/// Austausch über die Structured-Fields-Header WT-Available-Protocols (List aus Strings) und
/// WT-Protocol (Item-String).
/// </summary>
[TestFixture]
public class WebTransportProtocolNegotiationTests
{
    // ---- Unit: Structured-Fields-Kodierung (RFC 9651) --------------------------------------

    [Test]
    public void SerializeProtocolList_QuotesAndEscapes()
    {
        Assert.That(WebTransportProtocols.SerializeProtocolList(["chat-v2", "chat-v1"]),
                    Is.EqualTo("\"chat-v2\", \"chat-v1\""));
        // SF-Strings escapen DQUOTE und Backslash (RFC 9651 §4.1.6).
        Assert.That(WebTransportProtocols.SerializeProtocol("a\"b\\c"), Is.EqualTo("\"a\\\"b\\\\c\""));
        // Nicht darstellbare Zeichen (außerhalb %x20-7E) und leere Listen sind Fehler.
        Assert.Throws<ArgumentException>(() => WebTransportProtocols.SerializeProtocol("umlaut-ä"));
        Assert.Throws<ArgumentException>(() => WebTransportProtocols.SerializeProtocolList([]));
    }

    [Test]
    public void TryParseProtocolList_ParsesStrings_AndIgnoresParameters()
    {
        Assert.That(WebTransportProtocols.TryParseProtocolList("\"a\", \"b\"", out List<string> list1), Is.True);
        Assert.That(list1, Is.EqualTo(new[] { "a", "b" }));

        // Parameter haben keine Semantik und werden überlesen (draft §3.3) — auch String-/Zahl-Werte.
        // (RFC 9651 §4.2.3.2: Parameter hängen OHNE Leerzeichen vor dem „;" am Mitglied.)
        Assert.That(WebTransportProtocols.TryParseProtocolList("\"a\";q=0.9;note=\"x,y\", \"b\";flag", out List<string> list2), Is.True);
        Assert.That(list2, Is.EqualTo(new[] { "a", "b" }));

        // Escapes im String-Wert.
        Assert.That(WebTransportProtocols.TryParseProtocolList("\"a\\\"b\\\\c\"", out List<string> list3), Is.True);
        Assert.That(list3, Is.EqualTo(new[] { "a\"b\\c" }));
    }

    [Test]
    public void TryParseProtocolList_NonStringMember_InvalidatesWholeField()
    {
        // draft §3.3: jeder andere Werttyp als String macht das GESAMTE Feld ungültig.
        Assert.That(WebTransportProtocols.TryParseProtocolList("\"a\", token", out _), Is.False);
        Assert.That(WebTransportProtocols.TryParseProtocolList("42, \"a\"", out _), Is.False);
        Assert.That(WebTransportProtocols.TryParseProtocolList("(\"a\" \"b\")", out _), Is.False); // Inner List
        Assert.That(WebTransportProtocols.TryParseProtocolList("\"a\",", out _), Is.False);        // hängendes Komma
        Assert.That(WebTransportProtocols.TryParseProtocolList("\"a\" \"b\"", out _), Is.False);   // fehlendes Komma
        Assert.That(WebTransportProtocols.TryParseProtocolList("\"unbeendet", out _), Is.False);
        Assert.That(WebTransportProtocols.TryParseProtocolList("", out _), Is.False);
    }

    [Test]
    public void TryParseProtocol_ItemString_WithParametersIgnored()
    {
        Assert.That(WebTransportProtocols.TryParseProtocol("\"chat\"", out string p1), Is.True);
        Assert.That(p1, Is.EqualTo("chat"));

        Assert.That(WebTransportProtocols.TryParseProtocol(" \"chat\";v=2 ", out string p2), Is.True);
        Assert.That(p2, Is.EqualTo("chat"));

        Assert.That(WebTransportProtocols.TryParseProtocol("chat", out _), Is.False);         // Token, kein String
        Assert.That(WebTransportProtocols.TryParseProtocol("\"a\", \"b\"", out _), Is.False); // List, kein Item
        Assert.That(WebTransportProtocols.TryParseProtocol("?1", out _), Is.False);           // Boolean
    }

    // ---- Integration: Ende-zu-Ende über echte CONNECT-Header --------------------------------

    [Test]
    public void Negotiation_EndToEnd_ServerPicksFromClientList()
    {
        // Server unterstützt chat-v2/chat-v1 und nimmt das erste (= vom Client bevorzugte) Angebot.
        (Http3ClientConnection client, Http3ServerConnection server, ServerCertificate cert) = Pair(
            selector: (_, offered) => offered.FirstOrDefault(p => p is "chat-v2" or "chat-v1"));
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        ulong id = client.ConnectWebTransport("localhost", "/wt",
            availableProtocols: ["chat-v3", "chat-v2", "chat-v1"]);
        WebTransportSession? session = null;
        for (int r = 0; r < 20 && session is null; r++) { Pump(client, server); client.TryGetWebTransportSession(id, out session); }

        Assert.That(session, Is.Not.Null);
        Assert.That(session!.NegotiatedProtocol, Is.EqualTo("chat-v2"));       // Client-Sicht
        Assert.That(_serverSession!.NegotiatedProtocol, Is.EqualTo("chat-v2")); // Server-Sicht
    }

    [Test]
    public void Negotiation_SelectorChoiceOutsideOfferedList_IsDropped()
    {
        // draft §3.3 MUST: die Server-Wahl muss aus der Angebotsliste stammen — sonst kein WT-Protocol.
        (Http3ClientConnection client, Http3ServerConnection server, ServerCertificate cert) = Pair(
            selector: (_, _) => "nicht-angeboten");
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        ulong id = client.ConnectWebTransport("localhost", "/wt", availableProtocols: ["chat"]);
        WebTransportSession? session = null;
        for (int r = 0; r < 20 && session is null; r++) { Pump(client, server); client.TryGetWebTransportSession(id, out session); }

        Assert.That(session, Is.Not.Null);
        Assert.That(session!.NegotiatedProtocol, Is.Null);
        Assert.That(_serverSession!.NegotiatedProtocol, Is.Null);
    }

    [Test]
    public void Negotiation_WithoutClientOffer_YieldsNoProtocol()
    {
        // Ohne WT-Available-Protocols darf der Server nichts wählen (Selector bekommt kein Angebot).
        bool selectorCalled = false;
        (Http3ClientConnection client, Http3ServerConnection server, ServerCertificate cert) = Pair(
            selector: (_, _) => { selectorCalled = true; return "chat"; });
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        ulong id = client.ConnectWebTransport("localhost", "/wt");
        WebTransportSession? session = null;
        for (int r = 0; r < 20 && session is null; r++) { Pump(client, server); client.TryGetWebTransportSession(id, out session); }

        Assert.That(session, Is.Not.Null);
        Assert.That(selectorCalled, Is.False, "Ohne Angebotsliste darf der Selector nicht gefragt werden.");
        Assert.That(session!.NegotiatedProtocol, Is.Null);
        Assert.That(_serverSession!.NegotiatedProtocol, Is.Null);
    }

    // ---- Helfer ---------------------------------------------------------------------------

    private WebTransportSession? _serverSession;

    private (Http3ClientConnection, Http3ServerConnection, ServerCertificate) Pair(
        Func<Http3Request, IReadOnlyList<string>, string?> selector)
    {
        _serverSession = null;
        var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var server = new Http3ServerConnection(cert, _ => new Http3Response { Status = 200, Body = [] },
            webTransportMaxSessions: 4,
            webTransportHandler: _ => session => _serverSession = session,
            webTransportProtocolSelector: selector);
        var client = new Http3ClientConnection("localhost", certificateValidation: validation, webTransportMaxSessions: 4);
        client.Start();
        for (int r = 0; r < 20 && !client.HandshakeConfirmed; r++) Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();
        for (int r = 0; r < 5; r++) Pump(client, server); // SETTINGS beidseitig
        return (client, server, cert);
    }

    private static void Pump(Http3ClientConnection client, Http3ServerConnection server)
    {
        client.CheckTimeouts();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }
}
