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

using System.Security.Cryptography.X509Certificates;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Führt Client- und Server-TLS-1.3-Handshake in-process gegeneinander (beide from scratch): die
/// CRYPTO-Bytes werden je Encryption-Level zwischen den beiden Engines ausgetauscht. Validiert den
/// Server-Handshake inklusive CertificateVerify-Signatur und der Zertifikatskette, ohne echtes Netzwerk.
/// </summary>
public class TlsHandshakeInProcessTests
{
    /// <summary>
    /// Prüft das selbstsignierte Testzertifikat gegen sich selbst als Custom-Trust-Root (echter Ketten-Pfad).
    /// </summary>
    private static CertificateValidationOptions TrustingOptions(ServerCertificate cert)
        => new() { CustomTrustRoots = [cert.Certificate] };

    [Fact]
    public void ClientAndServer_CompleteHandshake_WithMatchingSecrets()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var clientTp = new byte[] { 0x0f, 0x00 };  // minimaler Transport-Param-Block (initial_source_connection_id leer)
        var serverTp = new byte[] { 0x0f, 0x00 };

        var client = new TlsClientHandshake("localhost", clientTp, certificateValidation: TrustingOptions(cert));
        using var server = new TlsServerHandshake(cert, serverTp);

        RunHandshake(client, server);

        Assert.True(server.ClientFinishedValid, "Server muss den Client-Finished akzeptieren.");
        Assert.True(client.ServerCertificateValid, "Client muss das Serverzertifikat geprüft haben.");
        Assert.NotNull(client.ServerCertificate);
        AssertMatchingSecrets(client, server);

        // Standardmäßig einigt man sich auf X25519 (erste angebotene Gruppe, kein HRR).
        Assert.Equal(NamedGroup.X25519, client.NegotiatedGroup);
        Assert.False(server.SentHelloRetryRequest);
        client.Dispose();
    }

    [Fact]
    public void ClientAndServer_CompleteHandshake_WithX25519MlKem768()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var tp = new byte[] { 0x0f, 0x00 };

        // Client bietet nur den PQ-Hybrid an, Server bevorzugt ihn → Einigung ohne HRR. Prüft zugleich, dass
        // die großen Key Shares (1216/1120 Byte) korrekt durch ClientHello/ServerHello serialisiert werden.
        var client = new TlsClientHandshake("localhost", tp,
            keyShareGroups: [NamedGroup.X25519MlKem768],
            supportedGroups: [NamedGroup.X25519MlKem768],
            certificateValidation: TrustingOptions(cert));
        using var server = new TlsServerHandshake(cert, tp, preferredGroups: [NamedGroup.X25519MlKem768]);

        RunHandshake(client, server);

        Assert.Equal(NamedGroup.X25519MlKem768, client.NegotiatedGroup);
        Assert.False(server.SentHelloRetryRequest);
        Assert.True(server.ClientFinishedValid);
        Assert.True(client.ServerCertificateValid);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Fact]
    public void ClientAndServer_CompleteHandshake_WithX448()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var tp = new byte[] { 0x0f, 0x00 };

        // Client bietet nur X448 an, Server bevorzugt X448 → Einigung auf X448 ohne HRR.
        var client = new TlsClientHandshake("localhost", tp,
            keyShareGroups: [NamedGroup.X448],
            supportedGroups: [NamedGroup.X448],
            certificateValidation: TrustingOptions(cert));
        using var server = new TlsServerHandshake(cert, tp, preferredGroups: [NamedGroup.X448]);

        RunHandshake(client, server);

        Assert.Equal(NamedGroup.X448, client.NegotiatedGroup);
        Assert.False(server.SentHelloRetryRequest);
        Assert.True(server.ClientFinishedValid);
        Assert.True(client.ServerCertificateValid);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Fact]
    public void ClientAndServer_CompleteHandshake_WithEd25519ServerCertificate()
    {
        using var cert = ServerCertificate.CreateSelfSignedEd25519("localhost");
        Assert.Equal(SignatureScheme.Ed25519, cert.SignatureScheme);
        var tp = new byte[] { 0x0f, 0x00 };

        // Insecure prüft die CertificateVerify-Signatur — hier also unseren Ed25519-Verifikationspfad —,
        // aber nicht die X.509-Kette (Ed25519-Ketten-Support im OS ist nicht garantiert).
        var client = new TlsClientHandshake("localhost", tp,
            certificateValidation: CertificateValidationOptions.Insecure);
        using var server = new TlsServerHandshake(cert, tp);

        RunHandshake(client, server);

        Assert.True(client.ServerCertificateValid, "Client muss die Ed25519-CertificateVerify-Signatur akzeptieren.");
        Assert.True(server.ClientFinishedValid);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Fact]
    public void ClientAndServer_CompleteHandshake_WithEd448ServerCertificate()
    {
        using var cert = ServerCertificate.CreateSelfSignedEd448("localhost");
        Assert.Equal(SignatureScheme.Ed448, cert.SignatureScheme);
        var tp = new byte[] { 0x0f, 0x00 };

        // Insecure prüft die CertificateVerify-Signatur — hier unseren Ed448-Verifikationspfad —,
        // aber nicht die X.509-Kette (Ed448-Ketten-Support im OS ist nicht garantiert).
        var client = new TlsClientHandshake("localhost", tp,
            certificateValidation: CertificateValidationOptions.Insecure);
        using var server = new TlsServerHandshake(cert, tp);

        RunHandshake(client, server);

        Assert.True(client.ServerCertificateValid, "Client muss die Ed448-CertificateVerify-Signatur akzeptieren.");
        Assert.True(server.ClientFinishedValid);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Fact]
    public void HelloRetryRequest_WhenClientOffersOnlyP256ButServerPrefersX25519()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var tp = new byte[] { 0x0f, 0x00 };

        // Client sendet nur einen P-256-Key-Share, listet aber X25519 in supported_groups.
        var client = new TlsClientHandshake("localhost", tp,
            keyShareGroups: [NamedGroup.Secp256r1],
            supportedGroups: [NamedGroup.X25519, NamedGroup.Secp256r1],
            certificateValidation: TrustingOptions(cert));
        // Server akzeptiert NUR X25519 → keine passende Key Share vorhanden → HelloRetryRequest.
        using var server = new TlsServerHandshake(cert, tp, preferredGroups: [NamedGroup.X25519]);

        RunHandshake(client, server);

        Assert.True(server.SentHelloRetryRequest, "Server muss einen HRR gesendet haben.");
        Assert.Equal(NamedGroup.X25519, client.NegotiatedGroup); // nach HRR auf X25519 geeinigt
        Assert.True(server.ClientFinishedValid);
        Assert.True(client.ServerCertificateValid);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Fact]
    public void ClientRejects_WhenHostnameDoesNotMatchCertificate()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var tp = new byte[] { 0x0f, 0x00 };

        // Erwarteter Hostname passt NICHT zum Zertifikat (SAN: localhost) → Prüfung muss scheitern.
        var client = new TlsClientHandshake("wrong.example", tp,
            certificateValidation: new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] });
        using var server = new TlsServerHandshake(cert, tp);

        var ex = Assert.Throws<CertificateValidationException>(() => RunHandshake(client, server));
        Assert.Contains("Hostname", ex.Message);
        client.Dispose();
    }

    [Fact]
    public void ClientRejects_SelfSignedCertificate_UnderDefaultPolicy()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var tp = new byte[] { 0x0f, 0x00 };

        // Standard-Policy prüft die Kette gegen die System-Roots → selbstsigniert ist nicht vertrauenswürdig.
        var client = new TlsClientHandshake("localhost", tp); // CertificateValidationOptions.Default
        using var server = new TlsServerHandshake(cert, tp);

        Assert.Throws<CertificateValidationException>(() => RunHandshake(client, server));
        client.Dispose();
    }

    [Fact]
    public void ClientAccepts_SelfSignedCertificate_UnderInsecurePolicy()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var tp = new byte[] { 0x0f, 0x00 };

        // curl -k: Signatur wird geprüft, Kette/Hostname nicht → Handshake gelingt.
        var client = new TlsClientHandshake("beliebig.example", tp,
            certificateValidation: CertificateValidationOptions.Insecure);
        using var server = new TlsServerHandshake(cert, tp);

        RunHandshake(client, server);

        Assert.True(client.ServerCertificateValid);
        Assert.True(server.ClientFinishedValid);
        client.Dispose();
    }

    private static void RunHandshake(TlsClientHandshake client, TlsServerHandshake server)
    {
        client.Start();
        for (int round = 0; round < 10 && !(client.IsComplete && server.IsComplete); round++)
        {
            Pump(client, server);
            Pump(server, client);
        }
        Assert.True(client.IsComplete, "Client-Handshake unvollständig.");
        Assert.True(server.IsComplete, "Server-Handshake unvollständig.");
    }

    private static void AssertMatchingSecrets(ITlsHandshake client, ITlsHandshake server)
    {
        Assert.NotNull(client.HandshakeSecrets);
        Assert.NotNull(server.HandshakeSecrets);
        Assert.Equal(client.HandshakeSecrets!.ServerHandshakeTrafficSecret,
                     server.HandshakeSecrets!.ServerHandshakeTrafficSecret);
        Assert.Equal(client.ApplicationSecrets!.ClientApplicationTrafficSecret,
                     server.ApplicationSecrets!.ClientApplicationTrafficSecret);
        Assert.Equal(client.ApplicationSecrets.ServerApplicationTrafficSecret,
                     server.ApplicationSecrets.ServerApplicationTrafficSecret);
    }

    private static void Pump(ITlsHandshake from, ITlsHandshake to)
    {
        while (from.TryGetOutgoingCrypto(out EncryptionLevel level, out byte[] data))
            to.ProvideCrypto(level, data);
    }
}
