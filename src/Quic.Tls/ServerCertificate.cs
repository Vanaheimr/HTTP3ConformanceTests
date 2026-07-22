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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;

/// <summary>
/// Das Serverzertifikat samt privatem Schlüssel für den TLS-1.3-Handshake. Erzeugt bei Bedarf ein
/// selbstsigniertes Testzertifikat (für Tests / <c>curl -k</c>) — wahlweise ECDSA-P-256 oder Ed25519 —
/// und signiert die CertificateVerify-Nachricht (RFC 8446 §4.4.3).
/// </summary>
public sealed class ServerCertificate : IDisposable
{
    private readonly ICertificateSigner _signer;

    /// <summary>
    /// Das Zertifikat (Kette hier: genau dieses eine, selbstsigniert).
    /// </summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>
    /// DER-Kodierung des Zertifikats (für die TLS-Certificate-Nachricht).
    /// </summary>
    public byte[] Der => Certificate.RawData;

    /// <summary>
    /// Verwendetes Signaturverfahren (ecdsa_secp256r1_sha256 oder ed25519).
    /// </summary>
    public SignatureScheme SignatureScheme => _signer.Scheme;

    private ServerCertificate(X509Certificate2 certificate, ICertificateSigner signer)
    {
        Certificate = certificate;
        _signer = signer;
    }

    /// <summary>
    /// Erzeugt ein frisches selbstsigniertes ECDSA-P-256-Zertifikat für <paramref name="commonName"/>.
    /// </summary>
    public static ServerCertificate CreateSelfSigned(string commonName = "localhost")
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
        AddExtensions(request, commonName);

        X509Certificate2 cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return new ServerCertificate(cert, new EcdsaSigner(key));
    }

    /// <summary>
    /// Erzeugt ein frisches selbstsigniertes <b>Ed25519</b>-Zertifikat (RFC 8410) für
    /// <paramref name="commonName"/>. Schlüssel und Signatur kommen aus BouncyCastle
    /// (<see cref="Ed25519Signature"/>); den TBSCertificate-Bau übernimmt die BCL über einen
    /// <see cref="X509SignatureGenerator"/>, sodass Subject-Alt-Name usw. unverändert bleiben.
    /// </summary>
    public static ServerCertificate CreateSelfSignedEd25519(string commonName = "localhost")
    {
        var ed = new Ed25519Signature();
        X509Certificate2 cert = CreateSelfSignedFromGenerator(commonName, new Ed25519SignatureGenerator(ed));
        return new ServerCertificate(cert, new Ed25519CertSigner(ed));
    }

    /// <summary>
    /// Erzeugt ein frisches selbstsigniertes <b>Ed448</b>-Zertifikat (RFC 8032/8410) für
    /// <paramref name="commonName"/>. Aufbau wie <see cref="CreateSelfSignedEd25519"/>, nur mit dem
    /// Edwards448-Primitiv (57-Byte-Schlüssel, id-Ed448 1.3.101.113).
    /// </summary>
    public static ServerCertificate CreateSelfSignedEd448(string commonName = "localhost")
    {
        var ed = new Ed448Signature();
        X509Certificate2 cert = CreateSelfSignedFromGenerator(commonName, new Ed448SignatureGenerator(ed));
        return new ServerCertificate(cert, new Ed448CertSigner(ed));
    }

    /// <summary>
    /// Baut das selbstsignierte Zertifikat über einen <see cref="X509SignatureGenerator"/> (für Schlüsseltypen,
    /// die die BCL nicht nativ kennt — Ed25519/Ed448). SAN + BasicConstraints wie bei den ECDSA-Zertifikaten.
    /// </summary>
    private static X509Certificate2 CreateSelfSignedFromGenerator(string commonName, X509SignatureGenerator generator)
    {
        var request = new CertificateRequest(
            new X500DistinguishedName($"CN={commonName}"), generator.PublicKey, HashAlgorithmName.SHA256);
        AddExtensions(request, commonName);

        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F; // positive, nicht-leere Seriennummer
        return request.Create(
            request.SubjectName, generator,
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), serial);
    }

    private static void AddExtensions(CertificateRequest request, string commonName)
    {
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(commonName);
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, false, 0, critical: true));
    }

    /// <summary>
    /// Signiert den CertificateVerify-Inhalt im TLS-Format des jeweiligen Verfahrens (RFC 8446 §4.4.3).
    /// </summary>
    public byte[] SignCertificateVerify(ReadOnlySpan<byte> content) => _signer.Sign(content);

    public void Dispose()
    {
        _signer.Dispose();
        Certificate.Dispose();
    }

    // ---- Signer-Abstraktion (ECDSA aus der BCL, Ed25519 aus BouncyCastle) -------------------

    private interface ICertificateSigner : IDisposable
    {
        SignatureScheme Scheme { get; }
        byte[] Sign(ReadOnlySpan<byte> content);
    }

    private sealed class EcdsaSigner(ECDsa key) : ICertificateSigner
    {
        public SignatureScheme Scheme => SignatureScheme.EcdsaSecp256r1Sha256;

        // TLS überträgt ECDSA-Signaturen als DER-kodierte r/s-Sequenz.
        public byte[] Sign(ReadOnlySpan<byte> content)
            => key.SignData(content, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        public void Dispose() => key.Dispose();
    }

    private sealed class Ed25519CertSigner(Ed25519Signature ed) : ICertificateSigner
    {
        public SignatureScheme Scheme => SignatureScheme.Ed25519;
        public byte[] Sign(ReadOnlySpan<byte> content) => ed.Sign(content);
        public void Dispose() { }
    }

    private sealed class Ed448CertSigner(Ed448Signature ed) : ICertificateSigner
    {
        public SignatureScheme Scheme => SignatureScheme.Ed448;
        public byte[] Sign(ReadOnlySpan<byte> content) => ed.Sign(content);
        public void Dispose() { }
    }

    /// <summary>
    /// Brücke, damit <see cref="CertificateRequest.Create(X500DistinguishedName, X509SignatureGenerator,
    /// DateTimeOffset, DateTimeOffset, byte[])"/> ein Ed25519-Zertifikat bauen kann: liefert den
    /// Ed25519-SubjectPublicKeyInfo, den AlgorithmIdentifier (id-Ed25519, ohne Parameter) und die
    /// PureEdDSA-Signatur über die TBSCertificate-Bytes.
    /// </summary>
    private sealed class Ed25519SignatureGenerator(Ed25519Signature ed) : X509SignatureGenerator
    {
        // AlgorithmIdentifier ::= SEQUENCE { OID 1.3.101.112 } — Parameter MÜSSEN fehlen (RFC 8410 §3).
        private static readonly byte[] AlgorithmId = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) => AlgorithmId;

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) => ed.Sign(data);

        protected override PublicKey BuildPublicKey()
        {
            // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier(Ed25519), BIT STRING(publicKey) }.
            // Fester Rahmen für den 32-Byte-Schlüssel — 12 Byte Präfix + 32 Byte Schlüssel = 44 Byte.
            byte[] spki = new byte[44];
            ReadOnlySpan<byte> prefix =
                [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];
            prefix.CopyTo(spki);
            ed.PublicKey.CopyTo(spki.AsSpan(12));
            return PublicKey.CreateFromSubjectPublicKeyInfo(spki, out _);
        }
    }

    /// <summary>Wie <see cref="Ed25519SignatureGenerator"/>, aber für id-Ed448 (1.3.101.113): 57-Byte-Schlüssel,
    /// leerer Signaturkontext.</summary>
    private sealed class Ed448SignatureGenerator(Ed448Signature ed) : X509SignatureGenerator
    {
        // AlgorithmIdentifier ::= SEQUENCE { OID 1.3.101.113 } — Parameter MÜSSEN fehlen (RFC 8410 §3).
        private static readonly byte[] AlgorithmId = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71];

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) => AlgorithmId;

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) => ed.Sign(data);

        protected override PublicKey BuildPublicKey()
        {
            // SubjectPublicKeyInfo für Ed448 — 12 Byte Präfix + 57 Byte Schlüssel = 69 Byte.
            byte[] spki = new byte[69];
            ReadOnlySpan<byte> prefix =
                [0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71, 0x03, 0x3A, 0x00];
            prefix.CopyTo(spki);
            ed.PublicKey.CopyTo(spki.AsSpan(12));
            return PublicKey.CreateFromSubjectPublicKeyInfo(spki, out _);
        }
    }
}
