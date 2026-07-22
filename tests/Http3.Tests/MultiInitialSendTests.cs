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
/// Prüft das Senden großer CRYPTO-Daten über mehrere Pakete (RFC 9000 §12.2): Ein ClientHello mit dem
/// PQ-Hybrid X25519MLKEM768 (1216-Byte-Key-Share ⇒ ~1450-Byte-ClientHello) passt nicht in ein einzelnes
/// 1200-Byte-Initial und muss offset-korrekt auf mehrere Initials verteilt werden. Die Server-Seite
/// reassembliert sie und der Handshake läuft durch – über den echten Datagramm-Pfad (nicht in-process).
/// </summary>
[TestFixture]
public class MultiInitialSendTests
{
    [Test]
    public void LargePqClientHello_IsSplitAcrossMultipleMtuSizedInitials_AndHandshakeCompletes()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation,
            keyExchangeGroups: [NamedGroup.X25519MlKem768]);
        using var server = new QuicServerConnection(cert, preferredGroups: [NamedGroup.X25519MlKem768]);

        client.Start();

        // Erste Flight des Clients: der große ClientHello muss auf ≥2 Initials aufgeteilt sein, und KEIN
        // Datagramm darf die QUIC-sichere MTU überschreiten (sonst droht Fragmentierung/Drop im Netz).
        IReadOnlyList<byte[]> firstFlight = client.GetDatagramsToSend();
        Assert.That(firstFlight.Count >= 2, Is.True, $"Der PQ-ClientHello sollte über ≥2 Initials verteilt sein, waren {firstFlight.Count}.");
        foreach (byte[] datagram in firstFlight)
            Assert.That(datagram.Length <= 1252, Is.True, $"Initial-Datagramm mit {datagram.Length} Byte überschreitet die MTU (1252).");

        foreach (byte[] dg in firstFlight)
            server.ProcessDatagram(dg);

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);
            foreach (byte[] dg in client.GetDatagramsToSend())
                server.ProcessDatagram(dg);
        }

        Assert.That(client.HandshakeConfirmed, Is.True, "Handshake muss trotz aufgeteiltem ClientHello abschließen.");
        Assert.That(client.NegotiatedGroup, Is.EqualTo(NamedGroup.X25519MlKem768));
    }
}
