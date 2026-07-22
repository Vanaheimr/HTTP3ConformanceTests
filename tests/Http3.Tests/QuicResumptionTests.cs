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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Session Resumption über den vollen QUIC-Datagramm-Pfad: Verbindung 1 schließt den Handshake ab und
/// empfängt das NewSessionTicket des Servers (Application-Level-CRYPTO im 1-RTT-Paket); Verbindung 2
/// resümiert mit dem Ticket. Prüft damit auch das Senden/Empfangen von Post-Handshake-CRYPTO.
/// </summary>
[TestFixture]
public class QuicResumptionTests
{
    private static void Pump(QuicClientConnection client, QuicServerConnection server)
    {
        foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
    }

    [Test]
    public void ClientResumesAgainstOwnServer_OverDatagrams_NoCertificate()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        // --- Verbindung 1: voller Handshake + Ticket-Empfang ---
        ResumptionTicket ticket;
        using (var client = new QuicClientConnection("localhost", certificateValidation: validation))
        using (var server = new QuicServerConnection(cert, resumptionCache: cache))
        {
            client.Start();
            for (int r = 0; r < 40 && !client.HandshakeConfirmed; r++)
                Pump(client, server);
            Assert.That(client.HandshakeConfirmed, Is.True, "Handshake (Verbindung 1) muss abschließen.");

            // Das NewSessionTicket kommt post-Handshake auf Application-Level – ein paar Runden nachpumpen.
            for (int r = 0; r < 6 && client.NewSessionTickets.Count == 0; r++)
                Pump(client, server);
            Assert.That(client.NewSessionTickets, Is.Not.Empty);
            ticket = client.NewSessionTickets[0];
        }

        // --- Verbindung 2: Resumption mit dem Ticket ---
        using var client2 = new QuicClientConnection("localhost", certificateValidation: validation, resumptionTicket: ticket);
        using var server2 = new QuicServerConnection(cert, resumptionCache: cache);
        client2.Start();
        for (int r = 0; r < 40 && !client2.HandshakeConfirmed; r++)
            Pump(client2, server2);

        Assert.That(client2.HandshakeConfirmed, Is.True, "Handshake (Verbindung 2) muss abschließen.");
        Assert.That(client2.ResumptionAccepted, Is.True, "Client muss die PSK-Annahme erkennen.");
        Assert.That(server2.ResumptionAccepted, Is.True, "Server muss den Binder akzeptiert haben.");
    }
}
