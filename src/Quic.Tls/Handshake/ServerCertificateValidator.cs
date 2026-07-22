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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

/// <summary>
/// Wird geworfen, wenn die Prüfung des Serverzertifikats fehlschlägt (fataler Handshake-Fehler).
/// </summary>
public sealed class CertificateValidationException(string message) : Exception(message);

/// <summary>
/// Prüft das Serverzertifikat clientseitig: (1) die CertificateVerify-Signatur über den Transcript-Hash
/// mit dem öffentlichen Schlüssel des Leaf-Zertifikats (RFC 8446 §4.4.3) und (2) gemäß Policy die
/// Zertifikatskette, den Hostname und den Gültigkeitszeitraum.
/// </summary>
public static class ServerCertificateValidator
{
    /// <summary>
    /// Führt die vollständige Prüfung durch und wirft bei Fehlschlag eine
    /// <see cref="CertificateValidationException"/>. Gibt das geprüfte Leaf-Zertifikat zurück.
    /// </summary>
    /// <param name="certificateChainDer">Die DER-Zertifikate aus der Certificate-Nachricht (Leaf zuerst).</param>
    /// <param name="scheme">Signaturverfahren aus der CertificateVerify-Nachricht.</param>
    /// <param name="signature">Signatur aus der CertificateVerify-Nachricht.</param>
    /// <param name="transcriptHash">Transcript-Hash bis einschließlich Certificate.</param>
    /// <param name="serverName">Erwarteter Hostname (für die Hostname-Prüfung).</param>
    /// <param name="options">Vertrauens-Policy.</param>
    public static X509Certificate2 Validate(
        IReadOnlyList<byte[]> certificateChainDer,
        SignatureScheme scheme,
        ReadOnlySpan<byte> signature,
        byte[] transcriptHash,
        string serverName,
        CertificateValidationOptions options)
    {
        if (certificateChainDer.Count == 0)
            throw new CertificateValidationException("Server sendete kein Zertifikat.");

        var leaf = X509CertificateLoader.LoadCertificate(certificateChainDer[0]);

        // (1) CertificateVerify-Signatur — immer, unabhängig von der Policy.
        byte[] content = CertificateVerify.BuildSignatureContent(CertificateVerify.ServerContext, transcriptHash);
        if (!VerifySignature(leaf, scheme, signature, content))
        {
            leaf.Dispose();
            throw new CertificateValidationException(
                $"CertificateVerify-Signatur ungültig (Verfahren {scheme}).");
        }

        // (2) Hostname — Policy.
        if (options.VerifyHostname && !leaf.MatchesHostname(serverName))
        {
            leaf.Dispose();
            throw new CertificateValidationException(
                $"Zertifikat gilt nicht für Hostname '{serverName}'.");
        }

        // (3) Kette + Gültigkeitszeitraum — Policy.
        if (options.VerifyCertificateChain && !VerifyChain(leaf, certificateChainDer, options, out string? error))
        {
            leaf.Dispose();
            throw new CertificateValidationException($"Zertifikatskette ungültig: {error}");
        }

        return leaf;
    }

    /// <summary>
    /// Prüft die CertificateVerify-Signatur mit dem passenden Algorithmus des Leaf-Schlüssels.
    /// </summary>
    private static bool VerifySignature(X509Certificate2 leaf, SignatureScheme scheme, ReadOnlySpan<byte> signature, byte[] content)
    {
        switch (scheme)
        {
            case SignatureScheme.EcdsaSecp256r1Sha256:
            case SignatureScheme.EcdsaSecp384r1Sha384:
            {
                using ECDsa? ecdsa = leaf.GetECDsaPublicKey();
                if (ecdsa is null)
                    return false;
                HashAlgorithmName hash = scheme == SignatureScheme.EcdsaSecp256r1Sha256
                    ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
                // TLS überträgt ECDSA-Signaturen als DER-kodierte r/s-Sequenz.
                return ecdsa.VerifyData(content, signature, hash, DSASignatureFormat.Rfc3279DerSequence);
            }

            case SignatureScheme.RsaPssRsaeSha256:
            case SignatureScheme.RsaPssRsaeSha384:
            case SignatureScheme.RsaPssRsaeSha512:
            {
                using RSA? rsa = leaf.GetRSAPublicKey();
                if (rsa is null)
                    return false;
                HashAlgorithmName hash = scheme switch
                {
                    SignatureScheme.RsaPssRsaeSha256 => HashAlgorithmName.SHA256,
                    SignatureScheme.RsaPssRsaeSha384 => HashAlgorithmName.SHA384,
                    _ => HashAlgorithmName.SHA512,
                };
                return rsa.VerifyData(content, signature, hash, RSASignaturePadding.Pss);
            }

            case SignatureScheme.Ed25519:
            {
                // Ed25519 signiert den Inhalt direkt (PureEdDSA, kein Vor-Hash). Der öffentliche Schlüssel
                // kommt als SubjectPublicKeyInfo (id-Ed25519, 1.3.101.112) aus dem Leaf-Zertifikat; die BCL
                // kann Ed25519 nicht verifizieren, daher über das BouncyCastle-Primitiv.
                if (leaf.PublicKey.Oid.Value != "1.3.101.112")
                    return false;
                return Ed25519Signature.VerifyWithSubjectPublicKeyInfo(
                    leaf.PublicKey.ExportSubjectPublicKeyInfo(), content, signature);
            }

            case SignatureScheme.Ed448:
            {
                // Ed448 signiert den Inhalt direkt (PureEdDSA, leerer Kontext). Public Key aus dem
                // Leaf-SPKI (id-Ed448, 1.3.101.113); die BCL kann Ed448 nicht verifizieren.
                if (leaf.PublicKey.Oid.Value != "1.3.101.113")
                    return false;
                return Ed448Signature.VerifyWithSubjectPublicKeyInfo(
                    leaf.PublicKey.ExportSubjectPublicKeyInfo(), content, signature);
            }

            case SignatureScheme.MLDsa44:
            case SignatureScheme.MLDsa65:
            case SignatureScheme.MLDsa87:
            {
                // ML-DSA (FIPS 204, draft-ietf-tls-mldsa §4): pure Signatur, FIPS-204-Kontext leer.
                // Der Schlüssel kommt als id-ML-DSA-44/65/87-SPKI aus dem Leaf; die Parameterstärke
                // MUSS zum SignatureScheme passen (§4: „subject public key MUST … corresponding").
                // SYSLIB5006: X509-PQC-Integration in .NET 10 noch „experimentell" — punktuell unterdrückt.
#pragma warning disable SYSLIB5006
                using MLDsa? mldsa = leaf.GetMLDsaPublicKey();
#pragma warning restore SYSLIB5006
                if (mldsa is null)
                    return false;
                MLDsaAlgorithm expected = scheme switch
                {
                    SignatureScheme.MLDsa44 => MLDsaAlgorithm.MLDsa44,
                    SignatureScheme.MLDsa65 => MLDsaAlgorithm.MLDsa65,
                    _ => MLDsaAlgorithm.MLDsa87,
                };
                if (mldsa.Algorithm != expected)
                    return false;
                return mldsa.VerifyData(content.AsSpan(), signature, context: default);
            }

            default:
                // rsa_pkcs1_* sind in TLS 1.3 für CertificateVerify unzulässig; alles Übrige nicht unterstützt.
                throw new CertificateValidationException($"Signaturverfahren {scheme} wird nicht unterstützt.");
        }
    }

    /// <summary>
    /// Baut die Kette (mit den mitgesendeten Zwischenzertifikaten) und prüft sie.
    /// </summary>
    private static bool VerifyChain(X509Certificate2 leaf, IReadOnlyList<byte[]> chainDer, CertificateValidationOptions options, out string? error)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // offline-freundlich; kein OCSP/CRL
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        // Mitgesendete Zwischenzertifikate als Baumaterial bereitstellen.
        var intermediates = new List<X509Certificate2>();
        for (int i = 1; i < chainDer.Count; i++)
        {
            var intermediate = X509CertificateLoader.LoadCertificate(chainDer[i]);
            intermediates.Add(intermediate);
            chain.ChainPolicy.ExtraStore.Add(intermediate);
        }

        if (options.CustomTrustRoots is { Count: > 0 } roots)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        }

        try
        {
            if (chain.Build(leaf))
            {
                error = null;
                return true;
            }

            error = chain.ChainStatus.Length > 0
                ? string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()))
                : "unbekannt";
            return false;
        }
        finally
        {
            foreach (X509Certificate2 intermediate in intermediates)
                intermediate.Dispose();
        }
    }
}
