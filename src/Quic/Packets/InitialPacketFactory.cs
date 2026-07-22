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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Core;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

/// <summary>
/// Baut Client-Initial-Pakete zusammen (CRYPTO-Frame + PADDING + Packet/Header Protection).
/// </summary>
public static class InitialPacketFactory
{
    /// <summary>
    /// Ein Client-Initial-Datagramm MUSS mindestens 1200 Byte groß sein (RFC 9000 §14.1), damit der
    /// Server ausreichend Amplification-Budget hat. Trägt der ClientHello weniger, wird mit PADDING aufgefüllt.
    /// </summary>
    public const int MinimumClientInitialSize = 1200;

    /// <summary>
    /// Erzeugt ein geschütztes Client-Initial, das <paramref name="cryptoData"/> (typischerweise den
    /// ClientHello) in einem CRYPTO-Frame ab Offset 0 transportiert und auf ≥ 1200 Byte gepolstert ist.
    /// </summary>
    public static byte[] BuildClientInitial(
        PacketProtection clientProtection,
        uint version,
        ConnectionId destinationConnectionId,
        ConnectionId sourceConnectionId,
        ReadOnlySpan<byte> token,
        ulong packetNumber,
        int packetNumberLength,
        ReadOnlySpan<byte> cryptoData)
    {
        byte[] payload = FrameParser.Serialize([new CryptoFrame(0, cryptoData.ToArray())]);
        return BuildPadded(clientProtection, version, destinationConnectionId, sourceConnectionId,
            token, packetNumber, packetNumberLength, payload);
    }

    /// <summary>
    /// Baut ein Initial-Paket aus beliebigen bereits serialisierten Frames und polstert es mit
    /// PADDING auf ≥ 1200 Byte. Nutzbar für das erste Initial (CRYPTO) wie für spätere Initials
    /// (z. B. nur ein ACK) – jedes Datagramm mit einem Client-Initial muss die Mindestgröße erfüllen.
    /// </summary>
    public static byte[] BuildPadded(
        PacketProtection clientProtection,
        uint version,
        ConnectionId destinationConnectionId,
        ConnectionId sourceConnectionId,
        ReadOnlySpan<byte> token,
        ulong packetNumber,
        int packetNumberLength,
        ReadOnlySpan<byte> frames)
    {
        // Header-Overhead vorab berechnen, um die nötige PADDING-Menge zu bestimmen.
        // Length-Feld ist bei ~1200-Byte-Paketen 2 Bytes lang (Wert < 16384).
        int headerOverhead =
            1                                     // erstes Byte
            + 4                                   // Version
            + 1 + destinationConnectionId.Length  // DCID-Länge + DCID
            + 1 + sourceConnectionId.Length       // SCID-Länge + SCID
            + VarInt.GetLength((ulong)token.Length) + token.Length
            + 2                                   // Length-VarInt (Annahme: 2 Byte)
            + packetNumberLength;
        const int authTag = 16;

        int payloadForMinimum = MinimumClientInitialSize - headerOverhead - authTag;
        int payloadLength = Math.Max(frames.Length, payloadForMinimum);

        byte[] payload = new byte[payloadLength];
        frames.CopyTo(payload);
        // Rest bleibt 0 => PADDING-Frames.

        return LongHeader.Build(
            clientProtection, LongPacketType.Initial, version,
            destinationConnectionId, sourceConnectionId, token,
            packetNumber, packetNumberLength, payload);
    }
}
