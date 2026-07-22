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

using System.Threading;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// 0-RTT / Early Data (RFC 8446 §2.3, RFC 9001 §4), Phase B: Verbindung 1 sammelt ein Ticket mit erlaubtem
/// early_data; Verbindung 2 queuet die HTTP/3-Anfrage VOR dem Handshake, sodass sie als 0-RTT-Paket
/// (Long Header 0x01, Application-PN-Space) rausgeht. Der Server akzeptiert die Early Data, verarbeitet die
/// Anfrage und antwortet — über den vollen QUIC/HTTP-3-Datagramm-Pfad, beide Enden from scratch.
/// </summary>
public class ZeroRttTests
{
    private const uint MaxEarly = 0xffffffff; // QUIC nutzt 0xFFFFFFFF (RFC 9001 §4.6.1)

    private static Http3Response Handler(Http3Request request) => new()
    {
        Status = 200,
        Headers = [new HeaderField("content-type", "text/plain")],
        Body = System.Text.Encoding.UTF8.GetBytes($"0-RTT-Antwort auf {request.Path}"),
    };

    [Fact]
    public void ClientSendsEarlyGet_ServerAcceptsEarlyData_AndResponds()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        // --- Verbindung 1: Ticket (mit erlaubtem early_data) einsammeln ---
        ResumptionTicket ticket;
        using (var server1 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly))
        using (var client1 = new Http3ClientConnection("localhost", certificateValidation: validation))
        {
            client1.Start();
            bool sent = false;
            ulong stream1 = 0;
            Http3Response? r = null;
            for (int round = 0; round < 40 && (r is null || client1.NewSessionTickets.Count == 0); round++)
            {
                client1.CheckTimeouts();
                foreach (byte[] dg in client1.GetDatagramsToSend()) server1.ProcessDatagram(dg);
                foreach (byte[] dg in server1.GetDatagramsToSend()) client1.ProcessDatagram(dg);
                if (client1.HandshakeConfirmed && !sent)
                {
                    client1.InitializeHttp3();
                    stream1 = client1.SendRequest(Http3Request.Get("localhost", "/one"));
                    sent = true;
                }
                if (sent) client1.TryGetResponse(stream1, out r);
            }
            Assert.NotEmpty(client1.NewSessionTickets);
            ticket = client1.NewSessionTickets[0];
            Assert.True(ticket.AllowsEarlyData, "Das Ticket muss 0-RTT erlauben (max_early_data_size > 0).");
        }

        // --- Verbindung 2: 0-RTT — die Anfrage VOR dem Handshake queuen ---
        using var server2 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly);
        using var client2 = new Http3ClientConnection("localhost", certificateValidation: validation, resumptionTicket: ticket);
        client2.Start();
        client2.InitializeHttp3();                                              // Control-/QPACK-Streams
        ulong stream = client2.SendRequest(Http3Request.Get("localhost", "/zero")); // Request — alles als Early Data

        Http3Response? response = null;
        for (int round = 0; round < 40 && response is null; round++)
        {
            client2.CheckTimeouts();
            foreach (byte[] dg in client2.GetDatagramsToSend()) server2.ProcessDatagram(dg);
            foreach (byte[] dg in server2.GetDatagramsToSend()) client2.ProcessDatagram(dg);
            client2.TryGetResponse(stream, out response);
        }

        Assert.True(client2.EarlyDataAccepted, "Der Server muss 0-RTT akzeptiert haben (EncryptedExtensions).");
        Assert.True(server2.EarlyDataAccepted, "Serverseitig muss early_data akzeptiert sein.");
        Assert.NotNull(response);
        Assert.Equal(200, response!.Status);
        Assert.Contains("/zero", response.BodyText);
    }

    /// <summary>
    /// RFC 9001 §4.9.3: Der Client verwirft seine 0-RTT-Schlüssel, sobald die 1-RTT-Schlüssel installiert sind
    /// (danach sendet er keine 0-RTT-Pakete mehr, §5.6, und empfängt selbst nie welche ⇒ die Keys sind nutzlos).
    /// Der Test queuet 0-RTT-Daten, prüft, dass die Keys während des frühen Sendens existieren, und dass sie nach
    /// dem 1-RTT-Install (Handshake bestätigt) verworfen sind. Das SOFORTIGE, bedingungslose Verwerfen ist zugleich
    /// der Beleg, dass es beim Client – anders als beim Server – KEIN Reordering-Fenster gibt (er hat keinen
    /// 0-RTT-Read-Pfad, reorderte Pakete nutzen nie 0-RTT-Keys).
    /// </summary>
    [Fact]
    public void Client_DiscardsZeroRttKeys_OnInstallingOneRttKeys()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        // Verbindung 1: Ticket mit erlaubtem early_data einsammeln.
        ResumptionTicket ticket;
        using (var server1 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly))
        using (var client1 = new Http3ClientConnection("localhost", certificateValidation: validation))
        {
            client1.Start();
            bool sent = false;
            ulong s1 = 0;
            Http3Response? r = null;
            for (int round = 0; round < 40 && (r is null || client1.NewSessionTickets.Count == 0); round++)
            {
                client1.CheckTimeouts();
                foreach (byte[] dg in client1.GetDatagramsToSend()) server1.ProcessDatagram(dg);
                foreach (byte[] dg in server1.GetDatagramsToSend()) client1.ProcessDatagram(dg);
                if (client1.HandshakeConfirmed && !sent) { client1.InitializeHttp3(); s1 = client1.SendRequest(Http3Request.Get("localhost", "/one")); sent = true; }
                if (sent) client1.TryGetResponse(s1, out r);
            }
            ticket = client1.NewSessionTickets[0];
        }

        // Verbindung 2: 0-RTT — Anfrage vor dem Handshake queuen, sodass 0-RTT-Keys installiert werden.
        using var server2 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly);
        using var client2 = new Http3ClientConnection("localhost", certificateValidation: validation, resumptionTicket: ticket);
        client2.Start();
        client2.InitializeHttp3();
        client2.SendRequest(Http3Request.Get("localhost", "/zero"));

        // Erster Sende-Schub: 0-RTT geht raus, die 0-RTT-Keys müssen jetzt installiert sein (1-RTT noch nicht).
        byte[][] firstFlight = client2.GetDatagramsToSend().ToArray();
        Assert.True(client2.Quic.HasZeroRttKeysForTest, "Vor dem 1-RTT-Install müssen die 0-RTT-Keys installiert sein.");
        foreach (byte[] dg in firstFlight) server2.ProcessDatagram(dg);

        // Handshake zu Ende pumpen; mit dem 1-RTT-Install müssen die 0-RTT-Keys verschwinden.
        for (int round = 0; round < 40 && !client2.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in server2.GetDatagramsToSend()) client2.ProcessDatagram(dg);
            foreach (byte[] dg in client2.GetDatagramsToSend()) server2.ProcessDatagram(dg);
        }

        Assert.True(client2.HandshakeConfirmed);
        Assert.False(client2.Quic.HasZeroRttKeysForTest,
            "Mit dem Installieren der 1-RTT-Keys muss der Client seine 0-RTT-Keys verworfen haben (RFC 9001 §4.9.3).");
    }

    [Fact]
    public void RejectedEarlyData_IsRetriedOver1Rtt_AndStillSucceeds()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        // Verbindung 1: Server erlaubt 0-RTT ⇒ Ticket erlaubt Early Data.
        ResumptionTicket ticket;
        using (var server1 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly))
        using (var client1 = new Http3ClientConnection("localhost", certificateValidation: validation))
        {
            client1.Start();
            bool sent = false;
            ulong s1 = 0;
            Http3Response? r = null;
            for (int round = 0; round < 40 && (r is null || client1.NewSessionTickets.Count == 0); round++)
            {
                client1.CheckTimeouts();
                foreach (byte[] dg in client1.GetDatagramsToSend()) server1.ProcessDatagram(dg);
                foreach (byte[] dg in server1.GetDatagramsToSend()) client1.ProcessDatagram(dg);
                if (client1.HandshakeConfirmed && !sent) { client1.InitializeHttp3(); s1 = client1.SendRequest(Http3Request.Get("localhost", "/one")); sent = true; }
                if (sent) client1.TryGetResponse(s1, out r);
            }
            ticket = client1.NewSessionTickets[0];
        }

        // Verbindung 2: der Client bietet 0-RTT an (Ticket erlaubt es), aber der Server LEHNT AB
        // (maxEarlyDataSize = 0). Die früh gesendeten 0-RTT-Daten müssen über 1-RTT wiederholt werden.
        using var server2 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: 0);
        using var client2 = new Http3ClientConnection("localhost", certificateValidation: validation, resumptionTicket: ticket);
        client2.Start();
        client2.InitializeHttp3();
        ulong stream = client2.SendRequest(Http3Request.Get("localhost", "/rejected"));

        Http3Response? response = null;
        for (int round = 0; round < 80 && response is null; round++)
        {
            client2.CheckTimeouts();
            foreach (byte[] dg in client2.GetDatagramsToSend()) server2.ProcessDatagram(dg);
            foreach (byte[] dg in server2.GetDatagramsToSend()) client2.ProcessDatagram(dg);
            client2.TryGetResponse(stream, out response);
        }

        Assert.False(client2.EarlyDataAccepted, "Der Server hat 0-RTT abgelehnt.");
        Assert.NotNull(response); // trotzdem beantwortet – die Anfrage lief über 1-RTT
        Assert.Equal(200, response!.Status);
        Assert.Contains("/rejected", response.BodyText);
    }

    /// <summary>
    /// Handshake-Keys nach 0-RTT-Ablehnung (RFC 9001 §4.9.2 + §4.1.2): Auch wenn die ersten Application-Pakete
    /// abgelehnte 0-RTT-Pakete waren, muss der Handshake-Key-Discard korrekt greifen. Kritisch: 0-RTT und 1-RTT
    /// teilen den Application-PN-Space, aber die §4.1.2-Bestätigung darf NUR die Quittung eines echten 1-RTT-
    /// Pakets zählen. Hier wird HANDSHAKE_DONE unterdrückt, sodass die Bestätigung ausschließlich über den 1-RTT-
    /// ACK der über 1-RTT wiederholten Anfrage läuft – und der Client dann seine Handshake-Keys verwirft.
    /// </summary>
    [Fact]
    public void RejectedEarlyData_HandshakeStillConfirmsAndDiscardsHandshakeKeys_ViaOneRttAck()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        // Verbindung 1: Ticket mit erlaubtem early_data einsammeln.
        ResumptionTicket ticket;
        using (var server1 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly))
        using (var client1 = new Http3ClientConnection("localhost", certificateValidation: validation))
        {
            client1.Start();
            bool sent = false;
            ulong s1 = 0;
            Http3Response? r = null;
            for (int round = 0; round < 40 && (r is null || client1.NewSessionTickets.Count == 0); round++)
            {
                client1.CheckTimeouts();
                foreach (byte[] dg in client1.GetDatagramsToSend()) server1.ProcessDatagram(dg);
                foreach (byte[] dg in server1.GetDatagramsToSend()) client1.ProcessDatagram(dg);
                if (client1.HandshakeConfirmed && !sent) { client1.InitializeHttp3(); s1 = client1.SendRequest(Http3Request.Get("localhost", "/one")); sent = true; }
                if (sent) client1.TryGetResponse(s1, out r);
            }
            ticket = client1.NewSessionTickets[0];
        }

        // Verbindung 2: Client bietet 0-RTT an, Server LEHNT AB (maxEarlyDataSize = 0) UND unterdrückt HANDSHAKE_DONE.
        using var server2 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: 0);
        server2.Quic.SuppressHandshakeDoneForTest = true; // Bestätigung nur über den 1-RTT-ACK erzwingen (§4.1.2)
        using var client2 = new Http3ClientConnection("localhost", certificateValidation: validation, resumptionTicket: ticket);
        client2.Start();
        client2.InitializeHttp3();
        ulong stream = client2.SendRequest(Http3Request.Get("localhost", "/rejected")); // geht als (abgelehntes) 0-RTT raus

        Http3Response? response = null;
        for (int round = 0; round < 80 && (response is null || !client2.HandshakeConfirmed); round++)
        {
            client2.CheckTimeouts();
            foreach (byte[] dg in client2.GetDatagramsToSend()) server2.ProcessDatagram(dg);
            foreach (byte[] dg in server2.GetDatagramsToSend()) client2.ProcessDatagram(dg);
            client2.TryGetResponse(stream, out response);
        }

        Assert.False(client2.EarlyDataAccepted, "Der Server hat 0-RTT abgelehnt.");
        Assert.NotNull(response);
        Assert.Equal(200, response!.Status); // über 1-RTT wiederholt und beantwortet
        Assert.True(client2.HandshakeConfirmed,
            "Trotz 0-RTT-Ablehnung UND fehlendem HANDSHAKE_DONE muss der Client per 1-RTT-ACK bestätigen (§4.1.2) – nicht durch ein 0-RTT-Paket.");
        Assert.False(client2.Quic.HasHandshakeKeysForTest,
            "Mit der Bestätigung müssen die Handshake-Keys verworfen sein (RFC 9001 §4.9.2) – auch auf dem 0-RTT-Ablehnungspfad.");
    }

    private static ResumptionTicket AcquireTicket(ServerCertificate cert, ServerResumptionCache cache, CertificateValidationOptions validation)
    {
        using var server1 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly);
        using var client1 = new Http3ClientConnection("localhost", certificateValidation: validation);
        client1.Start();
        bool sent = false;
        ulong s1 = 0;
        Http3Response? r = null;
        for (int round = 0; round < 40 && (r is null || client1.NewSessionTickets.Count == 0); round++)
        {
            client1.CheckTimeouts();
            foreach (byte[] dg in client1.GetDatagramsToSend()) server1.ProcessDatagram(dg);
            foreach (byte[] dg in server1.GetDatagramsToSend()) client1.ProcessDatagram(dg);
            if (client1.HandshakeConfirmed && !sent) { client1.InitializeHttp3(); s1 = client1.SendRequest(Http3Request.Get("localhost", "/one")); sent = true; }
            if (sent) client1.TryGetResponse(s1, out r);
        }
        return client1.NewSessionTickets[0];
    }

    /// <summary>
    /// RFC 9001 §4.9.3 (letzter Satz): Der Server DARF die 0-RTT-Read-Keys FRÜHER als nach 3×PTO verwerfen, sobald
    /// er alle 0-RTT-Pakete erhalten hat (lückenlose Paketnummern). Im verlustfreien In-Process-Lauf ist der
    /// Application-Space ab 0 lückenlos, sobald das erste 1-RTT-Paket ankommt ⇒ die Keys müssen weg sein, obwohl
    /// die 3×PTO-Frist (hier absichtlich auf 5 min gesetzt) noch lange nicht abgelaufen ist.
    /// </summary>
    [Fact]
    public void Server_DiscardsZeroRttKeysEarly_WhenAllPacketsReceived_NoGap()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        ResumptionTicket ticket = AcquireTicket(cert, cache, validation);

        using var server2 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly);
        server2.Quic.ServerZeroRttDiscardDelayForTest = TimeSpan.FromMinutes(5); // Timer-Pfad praktisch ausschließen
        using var client2 = new Http3ClientConnection("localhost", certificateValidation: validation, resumptionTicket: ticket);
        client2.Start();
        client2.InitializeHttp3();
        ulong stream = client2.SendRequest(Http3Request.Get("localhost", "/zero"));

        Http3Response? response = null;
        for (int round = 0; round < 40 && (response is null || !client2.HandshakeConfirmed); round++)
        {
            client2.CheckTimeouts();
            foreach (byte[] dg in client2.GetDatagramsToSend()) server2.ProcessDatagram(dg);
            foreach (byte[] dg in server2.GetDatagramsToSend()) client2.ProcessDatagram(dg);
            client2.TryGetResponse(stream, out response);
        }

        Assert.True(server2.EarlyDataAccepted, "Der Server muss 0-RTT akzeptiert haben.");
        Assert.NotNull(response);
        Assert.Equal(200, response!.Status);
        // Kein Verlust ⇒ lückenlos ⇒ der Server verwirft die 0-RTT-Read-Keys sofort mit dem ersten 1-RTT-Paket,
        // ohne die (5-Minuten-)Frist abzuwarten.
        Assert.False(server2.Quic.HasZeroRttKeysForTest,
            "Bei lückenlos empfangenen 0-RTT-Paketen MUSS der Server die 0-RTT-Read-Keys früh verwerfen (RFC 9001 §4.9.3).");
    }

    /// <summary>
    /// Gegenprobe zur Frühverwerfung: Fehlt dem Server eine Paketnummer im Application-Space (hier wird das erste
    /// 1-RTT-Paket „verworfen", sodass eine dauerhafte Lücke unterhalb späterer Pakete bleibt), kann er NICHT sicher
    /// sein, alle 0-RTT-Pakete erhalten zu haben — er behält die 0-RTT-Read-Keys bis zum Ablauf der kurzen Frist
    /// (RECOMMENDED 3×PTO) und verwirft sie dann zeitgesteuert. (0-RTT-Pakete selbst sind hier mit dem Initial
    /// koalesziert und daher nicht einzeln droppbar; für die Lücken-Logik zählt jede fehlende PN gleich.)
    /// </summary>
    [Fact]
    public void Server_RetainsZeroRttKeys_UntilTimeout_WhenPacketNumberGapPersists()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        ResumptionTicket ticket = AcquireTicket(cert, cache, validation);

        using var server2 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly);
        server2.Quic.ServerZeroRttDiscardDelayForTest = TimeSpan.FromMilliseconds(300);
        using var client2 = new Http3ClientConnection("localhost", certificateValidation: validation, resumptionTicket: ticket);
        client2.Start();
        client2.InitializeHttp3();
        client2.SendRequest(Http3Request.Get("localhost", "/zero"));

        // Das ERSTE 1-RTT-Paket (Short Header) NICHT ausliefern ⇒ dauerhafte PN-Lücke unterhalb der folgenden
        // 1-RTT-Pakete. Feste Rundenzahl (kein Break), damit der Server danach weitere 1-RTT-Pakete empfängt und die
        // Frist scharfschaltet, die Lücke aber bestehen bleibt.
        bool droppedOneRtt = false;
        for (int round = 0; round < 40; round++)
        {
            client2.CheckTimeouts();
            foreach (byte[] dg in client2.GetDatagramsToSend())
            {
                if (!droppedOneRtt && !PacketFormat.IsLongHeader(dg[0])) { droppedOneRtt = true; continue; } // simulierter Verlust
                server2.ProcessDatagram(dg);
            }
            foreach (byte[] dg in server2.GetDatagramsToSend()) client2.ProcessDatagram(dg);
        }

        Assert.True(droppedOneRtt, "Es muss ein 1-RTT-Paket zum Verwerfen gegeben haben.");
        Assert.True(server2.EarlyDataAccepted, "Der Server akzeptiert early_data anhand des ClientHello (unabhängig vom Paketverlust).");
        Assert.True(client2.HandshakeConfirmed);
        // Persistente Lücke ⇒ keine Frühverwerfung; innerhalb der 300-ms-Frist sind die Keys noch da.
        Assert.True(server2.Quic.HasZeroRttKeysForTest,
            "Bei einer PN-Lücke behält der Server die 0-RTT-Read-Keys bis zum Fristablauf (RFC 9001 §4.9.3).");

        // Frist zeitlich ablaufen lassen ⇒ zeitgesteuerte Verwerfung.
        Thread.Sleep(360);
        server2.Quic.CheckLossDetectionTimeout();
        Assert.False(server2.Quic.HasZeroRttKeysForTest,
            "Nach Ablauf der Frist MUSS der Server die 0-RTT-Read-Keys verwerfen (RFC 9001 §4.9.3).");
    }

    /// <summary>
    /// Verbindungsende (Dispose): Endet die Verbindung, bevor die 0-RTT-Read-Keys regulär verworfen wurden (hier
    /// durch eine PN-Lücke + faktisch nie ablaufende Frist erzwungen), müssen sie spätestens beim Dispose freigegeben
    /// werden — sonst läge Schlüsselmaterial bis zum GdC undisposed vor. Test ohne <c>using</c> für den Server, um
    /// den Zustand direkt vor und nach dem manuellen Dispose zu prüfen.
    /// </summary>
    [Fact]
    public void Server_DiscardsZeroRttKeys_OnDispose()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        ResumptionTicket ticket = AcquireTicket(cert, cache, validation);

        var server3 = new Http3ServerConnection(cert, Handler, resumptionCache: cache, maxEarlyDataSize: MaxEarly);
        server3.Quic.ServerZeroRttDiscardDelayForTest = TimeSpan.FromMinutes(5); // Timer feuert im Test nie
        using var client3 = new Http3ClientConnection("localhost", certificateValidation: validation, resumptionTicket: ticket);
        client3.Start();
        client3.InitializeHttp3();
        client3.SendRequest(Http3Request.Get("localhost", "/zero"));

        // Erstes 1-RTT-Paket verwerfen ⇒ persistente PN-Lücke ⇒ keine Frühverwerfung; lange Frist ⇒ auch kein Timer.
        bool droppedOneRtt = false;
        for (int round = 0; round < 40; round++)
        {
            client3.CheckTimeouts();
            foreach (byte[] dg in client3.GetDatagramsToSend())
            {
                if (!droppedOneRtt && !PacketFormat.IsLongHeader(dg[0])) { droppedOneRtt = true; continue; }
                server3.ProcessDatagram(dg);
            }
            foreach (byte[] dg in server3.GetDatagramsToSend()) client3.ProcessDatagram(dg);
        }

        Assert.True(server3.EarlyDataAccepted, "Der Server muss 0-RTT akzeptiert und die Read-Keys installiert haben.");
        Assert.True(server3.Quic.HasZeroRttKeysForTest,
            "Vorbedingung: die 0-RTT-Read-Keys sind noch da (Lücke ⇒ kein Früh-Discard, lange Frist ⇒ kein Timer).");

        server3.Dispose(); // Verbindungsende

        Assert.False(server3.Quic.HasZeroRttKeysForTest,
            "Beim Verbindungsende (Dispose) müssen die 0-RTT-Read-Keys freigegeben werden.");
    }
}
