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
/// Thrown when validation of the server certificate fails (fatal handshake error).
/// </summary>
public sealed class CertificateValidationException(string message) : Exception(message);

/// <summary>
/// Validates the server certificate on the client side: (1) the CertificateVerify signature over the
/// transcript hash with the public key of the leaf certificate (RFC 8446 §4.4.3) and (2), per policy,
/// the certificate chain, the hostname and the validity period.
/// </summary>
public static class ServerCertificateValidator
{
    /// <summary>
    /// Performs the full validation and throws a <see cref="CertificateValidationException"/> on
    /// failure. Returns the validated leaf certificate.
    /// </summary>
    /// <param name="certificateChainDer">The DER certificates from the Certificate message (leaf first).</param>
    /// <param name="scheme">Signature scheme from the CertificateVerify message.</param>
    /// <param name="signature">Signature from the CertificateVerify message.</param>
    /// <param name="transcriptHash">Transcript hash up to and including Certificate.</param>
    /// <param name="serverName">Expected hostname (for the hostname check).</param>
    /// <param name="options">Trust policy.</param>
    public static X509Certificate2 Validate(
        IReadOnlyList<byte[]> certificateChainDer,
        SignatureScheme scheme,
        ReadOnlySpan<byte> signature,
        byte[] transcriptHash,
        string serverName,
        CertificateValidationOptions options)
    {
        if (certificateChainDer.Count == 0)
            throw new CertificateValidationException("Server sent no certificate.");

        var leaf = X509CertificateLoader.LoadCertificate(certificateChainDer[0]);

        // (1) CertificateVerify signature — always, regardless of policy.
        byte[] content = CertificateVerify.BuildSignatureContent(CertificateVerify.ServerContext, transcriptHash);
        if (!VerifySignature(leaf, scheme, signature, content))
        {
            leaf.Dispose();
            throw new CertificateValidationException(
                $"CertificateVerify signature invalid (scheme {scheme}).");
        }

        // (2) Hostname — policy.
        if (options.VerifyHostname && !leaf.MatchesHostname(serverName))
        {
            leaf.Dispose();
            throw new CertificateValidationException(
                $"Certificate is not valid for hostname '{serverName}'.");
        }

        // (3) Chain + validity period — policy.
        if (options.VerifyCertificateChain && !VerifyChain(leaf, certificateChainDer, options, out string? error))
        {
            leaf.Dispose();
            throw new CertificateValidationException($"Certificate chain invalid: {error}");
        }

        return leaf;
    }

    /// <summary>
    /// Verifies the CertificateVerify signature with the algorithm matching the leaf key.
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
                // TLS transmits ECDSA signatures as a DER-encoded r/s sequence.
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
                // Ed25519 signs the content directly (PureEdDSA, no pre-hash). The public key comes
                // as a SubjectPublicKeyInfo (id-Ed25519, 1.3.101.112) from the leaf certificate; the
                // BCL cannot verify Ed25519, hence via the BouncyCastle primitive.
                if (leaf.PublicKey.Oid.Value != "1.3.101.112")
                    return false;
                return Ed25519Signature.VerifyWithSubjectPublicKeyInfo(
                    leaf.PublicKey.ExportSubjectPublicKeyInfo(), content, signature);
            }

            case SignatureScheme.Ed448:
            {
                // Ed448 signs the content directly (PureEdDSA, empty context). Public key from the
                // leaf SPKI (id-Ed448, 1.3.101.113); the BCL cannot verify Ed448.
                if (leaf.PublicKey.Oid.Value != "1.3.101.113")
                    return false;
                return Ed448Signature.VerifyWithSubjectPublicKeyInfo(
                    leaf.PublicKey.ExportSubjectPublicKeyInfo(), content, signature);
            }

            case SignatureScheme.MLDsa44:
            case SignatureScheme.MLDsa65:
            case SignatureScheme.MLDsa87:
            {
                // ML-DSA (FIPS 204, draft-ietf-tls-mldsa §4): pure signature, empty FIPS 204 context.
                // The key comes as an id-ML-DSA-44/65/87 SPKI from the leaf; the parameter strength
                // MUST match the SignatureScheme (§4: "subject public key MUST … corresponding").
                // SYSLIB5006: X509 PQC integration in .NET 10 is still "experimental" — suppressed locally.
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
                // rsa_pkcs1_* are not permitted for CertificateVerify in TLS 1.3; everything else unsupported.
                throw new CertificateValidationException($"Signature scheme {scheme} is not supported.");
        }
    }

    /// <summary>
    /// Builds the chain (with the intermediates sent along) and validates it.
    /// </summary>
    private static bool VerifyChain(X509Certificate2 leaf, IReadOnlyList<byte[]> chainDer, CertificateValidationOptions options, out string? error)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // offline-friendly; no OCSP/CRL
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        // Provide the intermediates sent along as building material.
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
                : "unknown";
            return false;
        }
        finally
        {
            foreach (X509Certificate2 intermediate in intermediates)
                intermediate.Dispose();
        }
    }
}
