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
[TestFixture]
public class Http3ClientServerTests
{
    [Test]
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

        Assert.That(response, Is.Not.Null);
        Assert.That(response!.Status, Is.EqualTo(200));
        Assert.That(response.GetHeader("content-type"), Is.EqualTo("text/plain"));
        Assert.That(response.BodyText, Does.Contain("/hello"));
        Assert.That(response.BodyText, Does.Contain("from scratch"));
    }

    [Test]
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

        Assert.That(response, Is.Not.Null);
        Assert.That(response!.Status, Is.EqualTo(200));
        Assert.That(response.Body.Length, Is.EqualTo(body.Length));
        Assert.That(body.AsSpan().SequenceEqual(response.Body), Is.True, "Der empfangene Rumpf muss byte-genau stimmen.");

        // Der MTU-begrenzte Emitter darf keine überdimensionierten Datagramme erzeugen.
        Assert.That(maxServerDatagram <= 1300, Is.True, $"Server-Datagramm zu groß: {maxServerDatagram} Bytes.");
    }

    [Test]
    public void Post_WithRequestBody_ServerReceivesBodyAndContentLength()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");

        byte[] requestBody = System.Text.Encoding.UTF8.GetBytes("Hallo Server, hier kommt ein POST-Rumpf!");
        Http3Request? seenRequest = null;

        // Echo-Handler: spiegelt den Request-Rumpf zurück (beweist Empfang UND Antwortpfad).
        Http3Response Handler(Http3Request request)
        {
            seenRequest = request;
            return new Http3Response
            {
                Status = 200,
                Headers = [new HeaderField("content-type", "application/octet-stream")],
                Body = request.Body,
            };
        }

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();

        ulong requestStream = 0;
        bool requestSent = false;
        Http3Response? response = null;

        for (int round = 0; round < 30 && response is null; round++)
        {
            client.CheckTimeouts();
            foreach (byte[] dg in client.GetDatagramsToSend())
                server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);

            if (client.HandshakeConfirmed && !requestSent)
            {
                client.InitializeHttp3();
                requestStream = client.SendRequest(Http3Request.Post("localhost", "/echo", requestBody, "text/plain"));
                requestSent = true;
            }

            if (requestSent)
                client.TryGetResponse(requestStream, out response);
        }

        // Der Server hat Methode, Header und den vollständigen Rumpf gesehen (RFC 9114 §4.1).
        Assert.That(seenRequest, Is.Not.Null);
        Assert.That(seenRequest!.Method, Is.EqualTo("POST"));
        Assert.That(seenRequest.Path, Is.EqualTo("/echo"));
        Assert.That(seenRequest.AdditionalHeaders.FirstOrDefault(h => h.Name == "content-type").Value, Is.EqualTo("text/plain"));
        Assert.That(seenRequest.AdditionalHeaders.FirstOrDefault(h => h.Name == "content-length").Value, Is.EqualTo(requestBody.Length.ToString()));
        Assert.That(requestBody.AsSpan().SequenceEqual(seenRequest.Body), Is.True, "Der Request-Rumpf muss byte-genau ankommen.");

        // Und das Echo kam vollständig zurück.
        Assert.That(response, Is.Not.Null);
        Assert.That(response!.Status, Is.EqualTo(200));
        Assert.That(requestBody.AsSpan().SequenceEqual(response.Body), Is.True, "Das Echo muss byte-genau stimmen.");
    }

    [Test]
    public void LargeRequestBody_UploadsFully_ThroughClientSendPath()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");

        // ~120 KB Upload – treibt erstmals den CLIENT-Sendepfad (cwnd, Pacing, MTU-Paketierung,
        // Flow Control) über viele Pakete; bisher testeten nur Downloads die Gegenrichtung.
        byte[] requestBody = new byte[120_000];
        for (int i = 0; i < requestBody.Length; i++)
            requestBody[i] = (byte)(i * 17 + 3);

        int seenBodyLength = -1;
        Http3Response Handler(Http3Request request)
        {
            seenBodyLength = request.Body.Length;
            // Antwort mit Prüfsumme statt Echo (hält die Antwort klein und beweist Byte-Genauigkeit).
            byte[] hash = System.Security.Cryptography.SHA256.HashData(request.Body);
            return new Http3Response { Status = 200, Body = hash };
        }

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();

        ulong requestStream = 0;
        bool requestSent = false;
        Http3Response? response = null;
        int maxClientDatagram = 0;

        for (int round = 0; round < 2000 && response is null; round++)
        {
            client.CheckTimeouts();
            foreach (byte[] dg in client.GetDatagramsToSend())
            {
                maxClientDatagram = Math.Max(maxClientDatagram, dg.Length);
                server.ProcessDatagram(dg);
            }
            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);

            if (client.HandshakeConfirmed && !requestSent)
            {
                client.InitializeHttp3();
                requestStream = client.SendRequest(Http3Request.Post("localhost", "/upload", requestBody));
                requestSent = true;
            }

            if (requestSent)
                client.TryGetResponse(requestStream, out response);
        }

        Assert.That(seenBodyLength, Is.EqualTo(requestBody.Length));
        Assert.That(response, Is.Not.Null);
        Assert.That(response!.Status, Is.EqualTo(200));
        Assert.That(System.Security.Cryptography.SHA256.HashData(requestBody).AsSpan().SequenceEqual(response.Body), Is.True, "Die SHA-256-Prüfsumme des Uploads muss stimmen — der Rumpf kam byte-genau an.");

        // Auch der Client-Emitter bleibt MTU-begrenzt.
        Assert.That(maxClientDatagram <= 1300, Is.True, $"Client-Datagramm zu groß: {maxClientDatagram} Bytes.");
    }

    [Test]
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

        Assert.That(client.HandshakeConfirmed, Is.True, "Handshake muss zustande kommen.");
        Assert.That(server.IsIdleTimedOut, Is.False);

        // Ohne weiteren Paketaustausch verstreicht mehr als der ausgehandelte Idle-Timeout.
        Thread.Sleep(600);
        server.CheckTimeouts();

        Assert.That(server.IsIdleTimedOut, Is.True, "Der Server muss die Verbindung nach dem Idle-Timeout schließen.");
        Assert.That(server.GetDatagramsToSend(), Is.Empty); // still geschlossen ⇒ keine Datagramme mehr
    }
}
