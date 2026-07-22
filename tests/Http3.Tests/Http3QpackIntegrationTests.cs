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

using System.Text;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// End-to-End: die dynamische QPACK-Tabelle (RFC 9204) über den vollständigen HTTP/3-Stack. Client und
/// Server kündigen je eine Kapazität an, tauschen Encoder-Stream-Instruktionen aus und referenzieren
/// dynamische Einträge – in-process gegeneinander gefahren.
/// </summary>
public class Http3QpackIntegrationTests
{
    [Fact]
    public void DynamicTable_RequestAndResponse_OverFullHttp3Stack()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        // "x-served-by" ist kein Static-Table-Name ⇒ erzwingt einen dynamischen Insert in der Antwort.
        Http3Response Handler(Http3Request request) => new()
        {
            Status = 200,
            Headers = [new HeaderField("content-type", "text/plain"), new HeaderField("x-served-by", "http3-from-scratch")],
            Body = Encoding.UTF8.GetBytes($"dynamic ok {request.Path}"),
        };

        using var server = new Http3ServerConnection(cert, Handler, qpackMaxTableCapacity: 4096);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation, qpackMaxTableCapacity: 4096);
        client.Start();

        void Pump()
        {
            foreach (byte[] dg in client.GetDatagramsToSend())
                server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);
        }

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump();
        Assert.True(client.HandshakeConfirmed);

        client.InitializeHttp3();
        // SETTINGS und Stream-Typ-Präfixe beidseitig fließen lassen (der Client lernt die Server-Kapazität).
        for (int round = 0; round < 6; round++)
            Pump();

        ulong requestStream = client.SendRequest(Http3Request.Get("localhost", "/hello"));
        Http3Response? response = null;
        for (int round = 0; round < 40 && response is null; round++)
        {
            Pump();
            client.TryGetResponse(requestStream, out response);
        }

        Assert.NotNull(response);
        Assert.Equal(200, response!.Status);
        Assert.Equal("text/plain", response.GetHeader("content-type"));
        Assert.Equal("http3-from-scratch", response.GetHeader("x-served-by"));
        Assert.Contains("dynamic ok /hello", response.BodyText);

        // Die dynamische Tabelle wurde tatsächlich genutzt: der Client hat Request-Header eingefügt,
        // der Server hat dieselben Instruktionen über den Encoder-Stream nachvollzogen.
        Assert.True(client.QpackEncoderInsertCount > 0, "Der Client muss die dynamische Tabelle nutzen.");
        Assert.Equal(client.QpackEncoderInsertCount, server.QpackDecoderInsertCount);

        // Ebenso für die Antwort-Header (Server-Encoder ↔ Client-Decoder).
        Assert.True(server.QpackEncoderInsertCount > 0, "Der Server muss die dynamische Tabelle für die Antwort nutzen.");
        Assert.Equal(server.QpackEncoderInsertCount, client.QpackDecoderInsertCount);

        // Noch etwas pendeln lassen, damit die Section-Acknowledgment des Clients den Server erreicht.
        for (int round = 0; round < 4; round++)
            Pump();
        Assert.True(server.QpackEncoderKnownReceivedCount > 0,
            "Der Server muss die Section-Acknowledgment des Clients erhalten haben (RFC 9204 §4.4.1).");
    }
}
