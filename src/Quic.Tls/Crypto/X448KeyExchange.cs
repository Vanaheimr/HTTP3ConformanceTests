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

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;

/// <summary>
/// X448-Schlüsselaustausch (RFC 7748, Curve448/„Goldilocks") über BouncyCastle. Wie <see cref="X25519KeyExchange"/>
/// eine BCL-Lücke, die BouncyCastle füllt — gekapselt hinter <see cref="IKeyExchange"/>. Öffentlicher
/// Schlüssel und Geheimnis sind je 56 Byte. In TLS 1.3 ist das die Named Group <c>x448</c> (0x001e).
/// </summary>
public sealed class X448KeyExchange : IKeyExchange
{
    private readonly X448PrivateKeyParameters _privateKey;

    public NamedGroup Group => NamedGroup.X448;
    public byte[] PublicKey { get; }

    public X448KeyExchange() : this(new X448PrivateKeyParameters(new SecureRandom())) { }

    /// <summary>
    /// Übernimmt einen festen privaten Schlüssel (56 Byte) — v. a. für RFC-7748-Testvektoren.
    /// </summary>
    internal X448KeyExchange(ReadOnlySpan<byte> privateKey)
        : this(new X448PrivateKeyParameters(privateKey.ToArray(), 0)) { }

    private X448KeyExchange(X448PrivateKeyParameters privateKey)
    {
        _privateKey = privateKey;
        PublicKey = _privateKey.GeneratePublicKey().GetEncoded();
    }

    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey)
    {
        if (peerPublicKey.Length != X448PublicKeyParameters.KeySize)
            throw new ArgumentException("X448-Public-Key muss 56 Byte lang sein.", nameof(peerPublicKey));

        var peer = new X448PublicKeyParameters(peerPublicKey.ToArray(), 0);
        var agreement = new X448Agreement();
        agreement.Init(_privateKey);
        byte[] secret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(peer, secret, 0);
        return secret;
    }

    public void Dispose() { }
}
