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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;

/// <summary>
/// ECDHE-Schlüsselaustausch über NIST-Kurven (RFC 8446 §4.2.8, §7.4.2). Für QUIC v1 nutzen wir
/// secp256r1 (P-256). Der öffentliche Schlüssel wird als unkomprimierter Punkt (0x04‖X‖Y) übertragen;
/// das gemeinsame Geheimnis ist die X-Koordinate des Produktpunkts.
/// </summary>
public sealed class EcdheKeyExchange : IKeyExchange
{
    private readonly ECDiffieHellman _ecdh;
    private readonly int _fieldBytes;

    public NamedGroup Group { get; }

    /// <summary>
    /// Der öffentliche Schlüssel als unkomprimierter Punkt (0x04‖X‖Y).
    /// </summary>
    public byte[] PublicKey { get; }

    private EcdheKeyExchange(NamedGroup group, ECDiffieHellman ecdh, int fieldBytes)
    {
        Group = group;
        _ecdh = ecdh;
        _fieldBytes = fieldBytes;

        ECParameters p = ecdh.ExportParameters(includePrivateParameters: false);
        PublicKey = new byte[1 + 2 * fieldBytes];
        PublicKey[0] = 0x04; // uncompressed point
        p.Q.X!.CopyTo(PublicKey, 1);
        p.Q.Y!.CopyTo(PublicKey, 1 + fieldBytes);
    }

    /// <summary>
    /// Erzeugt ein frisches Schlüsselpaar für die angegebene Gruppe.
    /// </summary>
    public static EcdheKeyExchange Create(NamedGroup group)
    {
        (ECCurve curve, int fieldBytes) = group switch
        {
            NamedGroup.Secp256r1 => (ECCurve.NamedCurves.nistP256, 32),
            NamedGroup.Secp384r1 => (ECCurve.NamedCurves.nistP384, 48),
            _ => throw new NotSupportedException($"Gruppe {group} wird (noch) nicht unterstützt."),
        };
        return new EcdheKeyExchange(group, ECDiffieHellman.Create(curve), fieldBytes);
    }

    /// <summary>
    /// Leitet das gemeinsame Geheimnis aus dem öffentlichen Schlüssel der Gegenseite ab
    /// (unkomprimierter Punkt). Ergebnis ist die rohe X-Koordinate – so verlangt es TLS 1.3.
    /// </summary>
    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey)
    {
        int expected = 1 + 2 * _fieldBytes;
        if (peerPublicKey.Length != expected || peerPublicKey[0] != 0x04)
            throw new ArgumentException("Ungültiger unkomprimierter EC-Punkt.", nameof(peerPublicKey));

        var peerParams = new ECParameters
        {
            Curve = _ecdh.ExportParameters(false).Curve,
            Q = new ECPoint
            {
                X = peerPublicKey.Slice(1, _fieldBytes).ToArray(),
                Y = peerPublicKey.Slice(1 + _fieldBytes, _fieldBytes).ToArray(),
            },
        };

        using ECDiffieHellman peer = ECDiffieHellman.Create(peerParams);
        return _ecdh.DeriveRawSecretAgreement(peer.PublicKey);
    }

    public void Dispose() => _ecdh.Dispose();
}
