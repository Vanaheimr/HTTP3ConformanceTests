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
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// End-to-End: unser HTTP/3-Client spricht in-process mit unserem HTTP/3-Server (beide from scratch).
/// Die Datagramme werden direkt zwischen beiden ausgetauscht (kein echtes Netzwerk). Validiert den
/// vollständigen Server-Pfad: QUIC-Server-Handshake, HTTP/3-Server, QPACK-kodierte Antwort.
/// </summary>
public class Http3ClientServerTests
{
    [Fact]
    public void Client_Gets_ResponseFromOwnServer()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");

        Http3Response Handler(Http3Request request) => new()
        {
            Status = 200,
            Headers = [new HeaderField("content-type", "text/plain")],
            Body = System.Text.Encoding.UTF8.GetBytes($"Hello from scratch! Du hast {request.Path} angefragt."),
        };

        // Der Client vertraut dem selbstsignierten Testzertifikat als Custom-Trust-Root und prüft es real.
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();

        ulong requestStream = 0;
        bool requestSent = false;
        Http3Response? response = null;

        // Datagramme direkt zwischen Client und Server pendeln lassen.
        for (int round = 0; round < 20 && response is null; round++)
        {
            client.CheckTimeouts();
            foreach (byte[] dg in client.GetDatagramsToSend())
                server.ProcessDatagram(dg);

            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);

            if (client.HandshakeConfirmed && !requestSent)
            {
                client.InitializeHttp3();
                requestStream = client.SendRequest(Http3Request.Get("localhost", "/hello"));
                requestSent = true;
            }

            if (requestSent)
                client.TryGetResponse(requestStream, out response);
        }

        Assert.NotNull(response);
        Assert.Equal(200, response!.Status);
        Assert.Equal("text/plain", response.GetHeader("content-type"));
        Assert.Contains("/hello", response.BodyText);
        Assert.Contains("from scratch", response.BodyText);
    }

    [Fact]
    public void LargeResponse_TransfersFully_ThroughPacedCongestionControlledSendPath()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");

        // ~150 KB deterministischer Rumpf – groß genug, um den cwnd-/Pacing-begrenzten Sendepfad
        // über viele Pakete zu treiben (Slow Start, Pacing-Budget, MTU-Paketierung).
        byte[] body = new byte[150_000];
        for (int i = 0; i < body.Length; i++)
            body[i] = (byte)(i * 31 + 7);

        Http3Response Handler(Http3Request request) => new()
        {
            Status = 200,
            Headers = [new HeaderField("content-type", "application/octet-stream")],
            Body = body,
        };

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();

        ulong requestStream = 0;
        bool requestSent = false;
        Http3Response? response = null;
        int maxServerDatagram = 0;

        for (int round = 0; round < 2000 && response is null; round++)
        {
            client.CheckTimeouts();
            foreach (byte[] dg in client.GetDatagramsToSend())
                server.ProcessDatagram(dg);

            foreach (byte[] dg in server.GetDatagramsToSend())
            {
                maxServerDatagram = Math.Max(maxServerDatagram, dg.Length);
                client.ProcessDatagram(dg);
            }

            if (client.HandshakeConfirmed && !requestSent)
            {
                client.InitializeHttp3();
                requestStream = client.SendRequest(Http3Request.Get("localhost", "/big"));
                requestSent = true;
            }

            if (requestSent)
                client.TryGetResponse(requestStream, out response);
        }

        Assert.NotNull(response);
        Assert.Equal(200, response!.Status);
        Assert.Equal(body.Length, response.Body.Length);
        Assert.True(body.AsSpan().SequenceEqual(response.Body), "Der empfangene Rumpf muss byte-genau stimmen.");

        // Der MTU-begrenzte Emitter darf keine überdimensionierten Datagramme erzeugen.
        Assert.True(maxServerDatagram <= 1300, $"Server-Datagramm zu groß: {maxServerDatagram} Bytes.");
    }

    [Fact]
    public void IdleTimeout_SilentlyClosesConnection_AfterInactivity()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        Http3Response Handler(Http3Request request) => new() { Status = 200, Body = [] };

        // Server kündigt einen kurzen Idle-Timeout an (300 ms). Nach dem Handshake ist die In-Process-RTT
        // winzig ⇒ 3·PTO ≪ 300 ms, also dominiert der ausgehandelte Wert.
        var serverParams = new TransportParameters { MaxIdleTimeoutMs = 300 };
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler, serverParams);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend())
                server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);
        }

        Assert.True(client.HandshakeConfirmed, "Handshake muss zustande kommen.");
        Assert.False(server.IsIdleTimedOut);

        // Ohne weiteren Paketaustausch verstreicht mehr als der ausgehandelte Idle-Timeout.
        Thread.Sleep(600);
        server.CheckTimeouts();

        Assert.True(server.IsIdleTimedOut, "Der Server muss die Verbindung nach dem Idle-Timeout schließen.");
        Assert.Empty(server.GetDatagramsToSend()); // still geschlossen ⇒ keine Datagramme mehr
    }
}
