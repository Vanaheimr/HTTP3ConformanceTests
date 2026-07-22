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
[TestFixture]
public class TlsHandshakeInProcessTests
{
    /// <summary>
    /// Prüft das selbstsignierte Testzertifikat gegen sich selbst als Custom-Trust-Root (echter Ketten-Pfad).
    /// </summary>
    private static CertificateValidationOptions TrustingOptions(ServerCertificate cert)
        => new() { CustomTrustRoots = [cert.Certificate] };

    [Test]
    public void ClientAndServer_CompleteHandshake_WithMatchingSecrets()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var clientTp = new byte[] { 0x0f, 0x00 };  // minimaler Transport-Param-Block (initial_source_connection_id leer)
        var serverTp = new byte[] { 0x0f, 0x00 };

        var client = new TlsClientHandshake("localhost", clientTp, certificateValidation: TrustingOptions(cert));
        using var server = new TlsServerHandshake(cert, serverTp);

        RunHandshake(client, server);

        Assert.That(server.ClientFinishedValid, Is.True, "Server muss den Client-Finished akzeptieren.");
        Assert.That(client.ServerCertificateValid, Is.True, "Client muss das Serverzertifikat geprüft haben.");
        Assert.That(client.ServerCertificate, Is.Not.Null);
        AssertMatchingSecrets(client, server);

        // Standardmäßig einigt man sich auf X25519 (erste angebotene Gruppe, kein HRR).
        Assert.That(client.NegotiatedGroup, Is.EqualTo(NamedGroup.X25519));
        Assert.That(server.SentHelloRetryRequest, Is.False);
        client.Dispose();
    }

    [Test]
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

        Assert.That(client.NegotiatedGroup, Is.EqualTo(NamedGroup.X25519MlKem768));
        Assert.That(server.SentHelloRetryRequest, Is.False);
        Assert.That(server.ClientFinishedValid, Is.True);
        Assert.That(client.ServerCertificateValid, Is.True);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Test]
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

        Assert.That(client.NegotiatedGroup, Is.EqualTo(NamedGroup.X448));
        Assert.That(server.SentHelloRetryRequest, Is.False);
        Assert.That(server.ClientFinishedValid, Is.True);
        Assert.That(client.ServerCertificateValid, Is.True);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Test]
    public void ClientAndServer_CompleteHandshake_WithEd25519ServerCertificate()
    {
        using var cert = ServerCertificate.CreateSelfSignedEd25519("localhost");
        Assert.That(cert.SignatureScheme, Is.EqualTo(SignatureScheme.Ed25519));
        var tp = new byte[] { 0x0f, 0x00 };

        // Insecure prüft die CertificateVerify-Signatur — hier also unseren Ed25519-Verifikationspfad —,
        // aber nicht die X.509-Kette (Ed25519-Ketten-Support im OS ist nicht garantiert).
        var client = new TlsClientHandshake("localhost", tp,
            certificateValidation: CertificateValidationOptions.Insecure);
        using var server = new TlsServerHandshake(cert, tp);

        RunHandshake(client, server);

        Assert.That(client.ServerCertificateValid, Is.True, "Client muss die Ed25519-CertificateVerify-Signatur akzeptieren.");
        Assert.That(server.ClientFinishedValid, Is.True);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Test]
    public void ClientAndServer_CompleteHandshake_WithEd448ServerCertificate()
    {
        using var cert = ServerCertificate.CreateSelfSignedEd448("localhost");
        Assert.That(cert.SignatureScheme, Is.EqualTo(SignatureScheme.Ed448));
        var tp = new byte[] { 0x0f, 0x00 };

        // Insecure prüft die CertificateVerify-Signatur — hier unseren Ed448-Verifikationspfad —,
        // aber nicht die X.509-Kette (Ed448-Ketten-Support im OS ist nicht garantiert).
        var client = new TlsClientHandshake("localhost", tp,
            certificateValidation: CertificateValidationOptions.Insecure);
        using var server = new TlsServerHandshake(cert, tp);

        RunHandshake(client, server);

        Assert.That(client.ServerCertificateValid, Is.True, "Client muss die Ed448-CertificateVerify-Signatur akzeptieren.");
        Assert.That(server.ClientFinishedValid, Is.True);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Test]
    public void ClientAndServer_CompleteHandshake_WithMLDsaServerCertificate()
    {
        if (!System.Security.Cryptography.MLDsa.IsSupported)
            Assert.Ignore("ML-DSA wird auf dieser Plattform nicht unterstützt (BCL/OS).");

        using var cert = ServerCertificate.CreateSelfSignedMLDsa("localhost");
        Assert.That(cert.SignatureScheme, Is.EqualTo(SignatureScheme.MLDsa65));
        var tp = new byte[] { 0x0f, 0x00 };

        // Insecure prüft die CertificateVerify-Signatur — hier den ML-DSA-Verifikationspfad
        // (draft-ietf-tls-mldsa §4: pure, FIPS-204-Kontext leer) —, aber nicht die X.509-Kette.
        var client = new TlsClientHandshake("localhost", tp,
            certificateValidation: CertificateValidationOptions.Insecure);
        using var server = new TlsServerHandshake(cert, tp);

        RunHandshake(client, server);

        Assert.That(client.ServerCertificateValid, Is.True, "Client muss die ML-DSA-CertificateVerify-Signatur akzeptieren.");
        Assert.That(server.ClientFinishedValid, Is.True);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Test]
    public void MLDsaCertificates_AllThreeParameterSets_CarryMatchingKeys()
    {
        if (!System.Security.Cryptography.MLDsa.IsSupported)
            Assert.Ignore("ML-DSA wird auf dieser Plattform nicht unterstützt (BCL/OS).");

        // NIST-CSOR-OIDs: id-ML-DSA-44/65/87 = 2.16.840.1.101.3.4.3.17/.18/.19.
        foreach ((SignatureScheme scheme, string oid) in new[]
        {
            (SignatureScheme.MLDsa44, "2.16.840.1.101.3.4.3.17"),
            (SignatureScheme.MLDsa65, "2.16.840.1.101.3.4.3.18"),
            (SignatureScheme.MLDsa87, "2.16.840.1.101.3.4.3.19"),
        })
        {
            using var cert = ServerCertificate.CreateSelfSignedMLDsa("localhost", scheme);
            Assert.That(cert.SignatureScheme, Is.EqualTo(scheme));
            Assert.That(cert.Certificate.PublicKey.Oid.Value, Is.EqualTo(oid));
            Assert.That(cert.SignCertificateVerify([1, 2, 3]), Is.Not.Empty);
        }

        Assert.Throws<ArgumentException>(() => ServerCertificate.CreateSelfSignedMLDsa("localhost", SignatureScheme.Ed25519));
    }

    [Test]
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

        Assert.That(server.SentHelloRetryRequest, Is.True, "Server muss einen HRR gesendet haben.");
        Assert.That(client.NegotiatedGroup, Is.EqualTo(NamedGroup.X25519)); // nach HRR auf X25519 geeinigt
        Assert.That(server.ClientFinishedValid, Is.True);
        Assert.That(client.ServerCertificateValid, Is.True);
        AssertMatchingSecrets(client, server);
        client.Dispose();
    }

    [Test]
    public void ClientRejects_WhenHostnameDoesNotMatchCertificate()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var tp = new byte[] { 0x0f, 0x00 };

        // Erwarteter Hostname passt NICHT zum Zertifikat (SAN: localhost) → Prüfung muss scheitern.
        var client = new TlsClientHandshake("wrong.example", tp,
            certificateValidation: new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] });
        using var server = new TlsServerHandshake(cert, tp);

        var ex = Assert.Throws<CertificateValidationException>(() => RunHandshake(client, server));
        Assert.That(ex!.Message, Does.Contain("Hostname"));
        client.Dispose();
    }

    [Test]
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

    [Test]
    public void ClientAccepts_SelfSignedCertificate_UnderInsecurePolicy()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var tp = new byte[] { 0x0f, 0x00 };

        // curl -k: Signatur wird geprüft, Kette/Hostname nicht → Handshake gelingt.
        var client = new TlsClientHandshake("beliebig.example", tp,
            certificateValidation: CertificateValidationOptions.Insecure);
        using var server = new TlsServerHandshake(cert, tp);

        RunHandshake(client, server);

        Assert.That(client.ServerCertificateValid, Is.True);
        Assert.That(server.ClientFinishedValid, Is.True);
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
        Assert.That(client.IsComplete, Is.True, "Client-Handshake unvollständig.");
        Assert.That(server.IsComplete, Is.True, "Server-Handshake unvollständig.");
    }

    private static void AssertMatchingSecrets(ITlsHandshake client, ITlsHandshake server)
    {
        Assert.That(client.HandshakeSecrets, Is.Not.Null);
        Assert.That(server.HandshakeSecrets, Is.Not.Null);
        Assert.That(server.HandshakeSecrets!.ServerHandshakeTrafficSecret, Is.EqualTo(client.HandshakeSecrets!.ServerHandshakeTrafficSecret));
        Assert.That(server.ApplicationSecrets!.ClientApplicationTrafficSecret, Is.EqualTo(client.ApplicationSecrets!.ClientApplicationTrafficSecret));
        Assert.That(server.ApplicationSecrets.ServerApplicationTrafficSecret, Is.EqualTo(client.ApplicationSecrets.ServerApplicationTrafficSecret));
    }

    private static void Pump(ITlsHandshake from, ITlsHandshake to)
    {
        while (from.TryGetOutgoingCrypto(out EncryptionLevel level, out byte[] data))
            to.ProvideCrypto(level, data);
    }
}
