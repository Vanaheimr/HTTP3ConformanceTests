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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Crypto;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

/// <summary>
/// Parsen von Short-Header-Paketen (1-RTT, RFC 9000, §17.3).
/// <para>
/// Anders als der Long Header enthält der Short Header <em>kein</em> Längenfeld für die Destination
/// Connection ID. Der Empfänger muss deren Länge aus dem Verbindungszustand kennen (er hat die CID
/// ja selbst vergeben). Ein Short-Header-Datagramm füllt außerdem stets den Rest des UDP-Pakets –
/// es gibt kein Length-Feld, daher kein Coalescing danach.
/// </para>
/// </summary>
public static class ShortHeader
{
    /// <summary>
    /// Ermittelt den Offset des Paketnummernfelds anhand der bekannten lokalen DCID-Länge.
    /// Der Aufrufer übergibt das Ergebnis an <see cref="PacketProtection.UnprotectPacket"/>
    /// (mit <c>longHeader: false</c>).
    /// </summary>
    /// <returns><c>true</c>, wenn das Paket ein gültiger Short Header ist und groß genug für DCID + Sample.</returns>
    public static bool TryLocatePacketNumber(
        ReadOnlySpan<byte> datagram,
        int localConnectionIdLength,
        out ConnectionId destinationConnectionId,
        out int packetNumberOffset)
    {
        destinationConnectionId = ConnectionId.Empty;
        packetNumberOffset = 0;

        if (datagram.IsEmpty)
            return false;
        byte first = datagram[0];
        if (!PacketFormat.IsShortHeader(first) || (first & PacketFormat.FixedBit) == 0)
            return false;

        int dcidEnd = 1 + localConnectionIdLength;
        if (datagram.Length < dcidEnd)
            return false;

        destinationConnectionId = new ConnectionId(datagram.Slice(1, localConnectionIdLength));
        packetNumberOffset = dcidEnd;
        return true;
    }

    /// <summary>
    /// Baut ein geschütztes 1-RTT-Paket (Short Header). Das erste Byte trägt Header Form 0, Fixed Bit 1,
    /// Spin 0, Reserved 0, Key Phase <paramref name="keyPhase"/> und die Paketnummernlänge.
    /// </summary>
    public static byte[] Build(
        PacketProtection protection,
        ConnectionId destinationConnectionId,
        ulong packetNumber,
        int packetNumberLength,
        ReadOnlySpan<byte> payload,
        bool keyPhase = false)
    {
        if (packetNumberLength is < 1 or > 4)
            throw new ArgumentOutOfRangeException(nameof(packetNumberLength));

        using var header = new BufferWriter();
        byte first = (byte)(PacketFormat.FixedBit | (keyPhase ? 0x04 : 0) | (packetNumberLength - 1));
        header.WriteByte(first);
        header.WriteBytes(destinationConnectionId.Span);

        Span<byte> pn = stackalloc byte[4];
        PacketNumber.Encode(pn, packetNumber, packetNumberLength);
        header.WriteBytes(pn[..packetNumberLength]);

        // Sehr kleine Nutzlast mit PADDING auffüllen, damit das Header-Protection-Sample passt (RFC 9001 §5.4.2).
        byte[] padded = PacketPadding.ForSampling(payload, packetNumberLength);
        return protection.ProtectPacket(header.WrittenSpan, packetNumberLength, packetNumber, padded, longHeader: false);
    }
}
