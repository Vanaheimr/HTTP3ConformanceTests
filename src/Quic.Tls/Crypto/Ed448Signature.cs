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
/// Ed448-Signaturen (RFC 8032, PureEdDSA über Edwards448/SHAKE256) über BouncyCastle. Wie
/// <see cref="Ed25519Signature"/> eine BCL-Lücke, die BouncyCastle füllt. In TLS 1.3 ist das der
/// SignatureScheme <c>ed448</c> (0x0808, RFC 8446 §4.2.3): der CertificateVerify-Inhalt wird <b>ohne</b>
/// Vor-Hash und mit <b>leerem Kontext</b> signiert. Öffentlicher Schlüssel und Signatur sind 57 bzw. 114 Byte.
/// </summary>
public sealed class Ed448Signature
{
    // Ed448 signiert immer über einen Kontext; TLS 1.3 verlangt den leeren Kontext (RFC 8446 §4.2.3).
    private static readonly byte[] EmptyContext = [];

    private readonly Ed448PrivateKeyParameters _privateKey;

    /// <summary>
    /// Der öffentliche Schlüssel (57 Byte, RFC 8032 §5.2.5).
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Erzeugt ein frisches Schlüsselpaar.
    /// </summary>
    public Ed448Signature() : this(new Ed448PrivateKeyParameters(new SecureRandom())) { }

    /// <summary>
    /// Übernimmt einen vorhandenen 57-Byte-Seed (privater Schlüssel) — v. a. für RFC-Testvektoren.
    /// </summary>
    public Ed448Signature(ReadOnlySpan<byte> seed)
        : this(new Ed448PrivateKeyParameters(seed.ToArray(), 0)) { }

    private Ed448Signature(Ed448PrivateKeyParameters privateKey)
    {
        _privateKey = privateKey;
        PublicKey = privateKey.GeneratePublicKey().GetEncoded();
    }

    /// <summary>
    /// Signiert den Inhalt direkt (PureEdDSA, kein Vor-Hash, leerer Kontext). Ergebnis: 114 Byte.
    /// </summary>
    public byte[] Sign(ReadOnlySpan<byte> content)
    {
        var signer = new Ed448Signer(EmptyContext);
        signer.Init(forSigning: true, _privateKey);
        signer.BlockUpdate(content.ToArray(), 0, content.Length);
        return signer.GenerateSignature();
    }

    /// <summary>
    /// Verifiziert eine Ed448-Signatur gegen einen rohen 57-Byte-Public-Key.
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> content, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != Ed448PublicKeyParameters.KeySize)
            return false;
        return VerifyWith(new Ed448PublicKeyParameters(publicKey.ToArray(), 0), content, signature);
    }

    /// <summary>
    /// Verifiziert gegen den Ed448-Public-Key aus einem SubjectPublicKeyInfo (id-Ed448, 1.3.101.113) —
    /// wie es aus einem X.509-Leaf-Zertifikat exportiert wird.
    /// </summary>
    public static bool VerifyWithSubjectPublicKeyInfo(byte[] spki, ReadOnlySpan<byte> content, ReadOnlySpan<byte> signature)
    {
        if (PublicKeyFactory.CreateKey(spki) is not Ed448PublicKeyParameters pub)
            return false;
        return VerifyWith(pub, content, signature);
    }

    private static bool VerifyWith(Ed448PublicKeyParameters pub, ReadOnlySpan<byte> content, ReadOnlySpan<byte> signature)
    {
        var verifier = new Ed448Signer(EmptyContext);
        verifier.Init(forSigning: false, pub);
        verifier.BlockUpdate(content.ToArray(), 0, content.Length);
        return verifier.VerifySignature(signature.ToArray());
    }
}
