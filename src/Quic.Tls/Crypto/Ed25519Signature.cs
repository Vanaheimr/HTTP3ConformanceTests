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

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;

/// <summary>
/// Ed25519-Signaturen (RFC 8032, PureEdDSA) über BouncyCastle. Die BCL kennt Ed25519 nicht als
/// Signaturalgorithmus — wie bei <see cref="X25519KeyExchange"/> kommt das Primitiv aus BouncyCastle,
/// gekapselt in dieser Klasse. In TLS 1.3 ist das der SignatureScheme <c>ed25519</c> (0x0807, RFC 8446
/// §4.2.3): der CertificateVerify-Inhalt wird <b>ohne</b> Vor-Hash direkt signiert. Öffentlicher
/// Schlüssel und Signatur sind 32 bzw. 64 Byte.
/// </summary>
public sealed class Ed25519Signature
{
    private readonly Ed25519PrivateKeyParameters _privateKey;

    /// <summary>
    /// Der öffentliche Schlüssel (32 Byte, RFC 8032 §5.1.5).
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Erzeugt ein frisches Schlüsselpaar.
    /// </summary>
    public Ed25519Signature() : this(new Ed25519PrivateKeyParameters(new SecureRandom())) { }

    /// <summary>
    /// Übernimmt einen vorhandenen 32-Byte-Seed (privater Schlüssel) — v. a. für RFC-Testvektoren.
    /// </summary>
    public Ed25519Signature(ReadOnlySpan<byte> seed)
        : this(new Ed25519PrivateKeyParameters(seed.ToArray(), 0)) { }

    private Ed25519Signature(Ed25519PrivateKeyParameters privateKey)
    {
        _privateKey = privateKey;
        PublicKey = privateKey.GeneratePublicKey().GetEncoded();
    }

    /// <summary>
    /// Signiert den Inhalt direkt (PureEdDSA, kein Vor-Hash). Ergebnis: 64 Byte.
    /// </summary>
    public byte[] Sign(ReadOnlySpan<byte> content)
    {
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, _privateKey);
        signer.BlockUpdate(content.ToArray(), 0, content.Length);
        return signer.GenerateSignature();
    }

    /// <summary>
    /// Verifiziert eine Ed25519-Signatur gegen einen rohen 32-Byte-Public-Key.
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> content, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != Ed25519PublicKeyParameters.KeySize)
            return false;
        return VerifyWith(new Ed25519PublicKeyParameters(publicKey.ToArray(), 0), content, signature);
    }

    /// <summary>
    /// Verifiziert gegen den Ed25519-Public-Key aus einem SubjectPublicKeyInfo (id-Ed25519, 1.3.101.112) —
    /// wie es aus einem X.509-Leaf-Zertifikat exportiert wird.
    /// </summary>
    public static bool VerifyWithSubjectPublicKeyInfo(byte[] spki, ReadOnlySpan<byte> content, ReadOnlySpan<byte> signature)
    {
        if (PublicKeyFactory.CreateKey(spki) is not Ed25519PublicKeyParameters pub)
            return false;
        return VerifyWith(pub, content, signature);
    }

    private static bool VerifyWith(Ed25519PublicKeyParameters pub, ReadOnlySpan<byte> content, ReadOnlySpan<byte> signature)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, pub);
        verifier.BlockUpdate(content.ToArray(), 0, content.Length);
        return verifier.VerifySignature(signature.ToArray());
    }
}
