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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

/// <summary>
/// Gemeinsame Schnittstelle der TLS-1.3-Handshake-Engine für beide Rollen. Die QUIC-Schicht liefert
/// empfangene CRYPTO-Bytes je Encryption-Level hinein und holt zu sendende heraus; abgeleitete
/// Schlüssel erscheinen als <see cref="HandshakeSecrets"/> / <see cref="ApplicationSecrets"/>.
/// </summary>
public interface ITlsHandshake : IDisposable
{
    /// <summary>
    /// Übergibt (geordnete) empfangene CRYPTO-Bytes eines Levels an die Handshake-Maschine.
    /// </summary>
    void ProvideCrypto(EncryptionLevel level, ReadOnlySpan<byte> data);

    /// <summary>
    /// Holt die nächste zu sendende CRYPTO-Nachricht (mit Ziel-Level), falls vorhanden.
    /// </summary>
    bool TryGetOutgoingCrypto(out EncryptionLevel level, out byte[] data);

    CipherSuite? NegotiatedCipherSuite { get; }
    HandshakeTrafficSecrets? HandshakeSecrets { get; }
    ApplicationTrafficSecrets? ApplicationSecrets { get; }

    /// <summary>
    /// <c>true</c>, sobald der Handshake aus Sicht dieser Seite abgeschlossen ist.
    /// </summary>
    bool IsComplete { get; }

    /// <summary>
    /// Die rohen quic_transport_parameters der Gegenseite (opak für TLS).
    /// </summary>
    byte[]? PeerQuicTransportParameters { get; }

    /// <summary>
    /// Das <c>client_early_traffic_secret</c> für 0-RTT (RFC 8446 §7.1), sobald verfügbar: auf dem Client beim
    /// Anbieten von early_data, auf dem Server beim Akzeptieren. <c>null</c>, wenn kein 0-RTT im Spiel ist.
    /// </summary>
    byte[]? EarlyTrafficSecret { get; }

    /// <summary>
    /// Die Cipher-Suite der 0-RTT-Schlüssel (die des Tickets); nötig, weil sie vor dem ServerHello feststeht.
    /// </summary>
    CipherSuite? EarlyDataCipherSuite { get; }

    /// <summary>
    /// <c>true</c>, wenn 0-RTT (early_data) tatsächlich akzeptiert wurde (Client: laut EncryptedExtensions).
    /// </summary>
    bool EarlyDataAccepted { get; }
}
