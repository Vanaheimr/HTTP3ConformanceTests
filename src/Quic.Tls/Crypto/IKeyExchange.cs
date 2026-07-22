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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;

/// <summary>
/// Ein (EC)DHE-Schlüsselaustausch für TLS 1.3 (RFC 8446 §4.2.8). Abstrahiert über die konkrete Gruppe,
/// sodass Transport/Handshake unverändert bleiben, egal ob P-256 (BCL) oder X25519 (BouncyCastle).
/// </summary>
public interface IKeyExchange : IDisposable
{
    NamedGroup Group { get; }

    /// <summary>
    /// Der öffentliche Schlüssel im Wire-Format der Gruppe (P-256: 0x04‖X‖Y; X25519: 32 Byte).
    /// </summary>
    byte[] PublicKey { get; }

    /// <summary>
    /// Leitet das gemeinsame Geheimnis aus dem öffentlichen Schlüssel der Gegenseite ab (Client-Seite).
    /// </summary>
    byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey);

    /// <summary>
    /// Server-Seite: erzeugt aus dem Key Share des Clients die eigene Antwort (Key Share) und das gemeinsame
    /// Geheimnis. Für klassisches (EC)DHE ist die Antwort schlicht der eigene öffentliche Schlüssel (und das
    /// Geheimnis das DH-Produkt); für einen KEM-Hybrid (X25519MLKEM768) ist die Antwort der ML-KEM-Ciphertext
    /// (‖ X25519) aus der Encapsulation gegen den Client-Schlüssel. Diese Asymmetrie ist der Grund für die
    /// getrennten Client-/Server-Methoden — beim KEM hängt die Server-Antwort vom Client-Share ab.
    /// </summary>
    (byte[] ResponseShare, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> peerShare)
        => (PublicKey, DeriveSharedSecret(peerShare));
}

/// <summary>
/// Erzeugt den passenden Schlüsselaustausch für eine Named Group.
/// </summary>
public static class KeyExchange
{
    /// <summary>
    /// Standard-Reihenfolge der angebotenen Gruppen: zuerst X25519 (Feld-Standard), dann P-256.
    /// </summary>
    public static IReadOnlyList<NamedGroup> DefaultGroups { get; } = [NamedGroup.X25519, NamedGroup.Secp256r1];

    public static IKeyExchange Create(NamedGroup group) => group switch
    {
        NamedGroup.X25519 => new X25519KeyExchange(),
        NamedGroup.X448 => new X448KeyExchange(),
        NamedGroup.X25519MlKem768 => new X25519MlKem768KeyExchange(),
        NamedGroup.Secp256r1 or NamedGroup.Secp384r1 => EcdheKeyExchange.Create(group),
        _ => throw new NotSupportedException($"Named Group {group} wird nicht unterstützt."),
    };

    public static bool IsSupported(NamedGroup group)
        => group is NamedGroup.X25519 or NamedGroup.X448 or NamedGroup.X25519MlKem768
            or NamedGroup.Secp256r1 or NamedGroup.Secp384r1;
}
