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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

/// <summary>
/// Stateless Reset (RFC 9000 §10.3): Ein Endpoint, der den für eine Verbindung nötigen Zustand verloren
/// hat (etwa nach einem Neustart), kann kein reguläres CONNECTION_CLOSE senden (dafür fehlen die Schlüssel).
/// Stattdessen sendet er ein Paket, das äußerlich wie ein 1-RTT-Paket aussieht (Short-Header-Form, sonst
/// unvorhersehbare Bytes) und in den <b>letzten 16 Bytes</b> den zur Connection ID gehörenden
/// Stateless-Reset-Token trägt. Der Empfänger erkennt es am bekannten Token und beendet die Verbindung.
/// </summary>
public static class StatelessReset
{
    /// <summary>
    /// Länge des Stateless-Reset-Tokens (RFC 9000 §10.3).
    /// </summary>
    public const int TokenLength = 16;

    /// <summary>
    /// Mindestlänge eines Stateless-Reset-Pakets (RFC 9000 §10.3): mind. 5 unvorhersehbare Bytes +
    /// 16-Byte-Token. Praktisch wird größer gesendet, damit es wie ein echtes Paket wirkt.
    /// </summary>
    public const int MinLength = 5 + TokenLength;

    /// <summary>
    /// Baut ein Stateless-Reset-Paket mit <paramref name="token"/> in den letzten 16 Bytes. Der Rest ist
    /// zufällig; das erste Byte trägt Header-Form 0 und Fixed Bit 1 (sieht aus wie ein Short Header).
    /// </summary>
    public static byte[] Build(ReadOnlySpan<byte> token, int totalLength = 41)
    {
        if (token.Length != TokenLength)
            throw new ArgumentException($"Token muss {TokenLength} Bytes lang sein.", nameof(token));

        int length = Math.Max(totalLength, MinLength);
        byte[] packet = RandomNumberGenerator.GetBytes(length);
        packet[0] = (byte)(0x40 | (packet[0] & 0x3f)); // Header Form 0 (Short), Fixed Bit 1
        token.CopyTo(packet.AsSpan(length - TokenLength));
        return packet;
    }

    /// <summary>
    /// Prüft konstantzeitig, ob <paramref name="datagram"/> mit <paramref name="token"/> endet.
    /// </summary>
    public static bool EndsWith(ReadOnlySpan<byte> datagram, ReadOnlySpan<byte> token)
        => token.Length == TokenLength
           && datagram.Length >= TokenLength
           && CryptographicOperations.FixedTimeEquals(datagram[^TokenLength..], token);

    /// <summary>
    /// Baut die Antwort auf ein Paket, das keiner Verbindung zugeordnet werden konnte (RFC 9000 §10.3): Aus der
    /// Destination Connection ID (feste Länge <paramref name="localCidLength"/>) wird das Token berechnet und ein
    /// Stateless Reset gesendet. Nur auf <b>Short-Header</b>-Pakete (1-RTT-Form; Long-Header wären eine neue
    /// Verbindung) ab einer Mindestgröße. Loop-Vermeidung (§10.3.3): der Reset ist stets <b>kleiner</b> als das
    /// auslösende Paket. Gibt <c>null</c> zurück, wenn kein Reset gesendet werden soll.
    /// </summary>
    public static byte[]? BuildResponse(ReadOnlySpan<byte> incomingDatagram, int localCidLength, StatelessResetTokenGenerator generator)
    {
        // Nur 1-RTT-förmige Pakete zurücksetzen und nur, wenn ein echt kleinerer, gültiger Reset (≥ MinLength) passt.
        if (incomingDatagram.Length <= MinLength ||
            !PacketFormat.IsShortHeader(incomingDatagram[0]) ||
            incomingDatagram.Length < 1 + localCidLength)
            return null;

        byte[] token = generator.ComputeToken(incomingDatagram.Slice(1, localCidLength));
        int resetLength = Math.Min(incomingDatagram.Length - 1, 41); // kleiner als der Auslöser, aber kompakt
        return Build(token, resetLength);
    }
}
