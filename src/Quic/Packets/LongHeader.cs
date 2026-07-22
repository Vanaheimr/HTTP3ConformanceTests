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
/// Die im Klartext lesbaren Felder eines Long-Header-Pakets mit Paketnummer
/// (Initial / Handshake / 0-RTT), bis unmittelbar vor die Header-geschützten Bytes.
/// <para>
/// Alle Felder außer den unteren Bits des ersten Bytes und der Paketnummer selbst liegen
/// unverschlüsselt vor. Aus diesem Prefix ergibt sich <see cref="PacketNumberOffset"/>, den die
/// <see cref="PacketProtection"/> zum Entfernen der Header Protection braucht.
/// </para>
/// </summary>
public sealed class LongHeaderPrefix
{
    public required LongPacketType Type { get; init; }
    public required uint Version { get; init; }
    public required ConnectionId DestinationConnectionId { get; init; }
    public required ConnectionId SourceConnectionId { get; init; }

    /// <summary>
    /// Retry-/NEW_TOKEN-Token; nur bei Initial-Paketen vorhanden (sonst leer).
    /// </summary>
    public required byte[] Token { get; init; }

    /// <summary>
    /// Länge von Paketnummer + Payload (inkl. AEAD-Tag) laut Length-Feld.
    /// </summary>
    public required long Length { get; init; }

    /// <summary>
    /// Offset des Paketnummernfelds innerhalb des Datagramms.
    /// </summary>
    public required int PacketNumberOffset { get; init; }

    /// <summary>
    /// Offset des ersten Bytes nach diesem Paket (für Coalesced Packets): <c>PacketNumberOffset + Length</c>.
    /// </summary>
    public int PacketEndOffset => PacketNumberOffset + (int)Length;
}

/// <summary>
/// Parsen und Serialisieren von Long-Header-Paketen (RFC 9000, §17.2).
/// </summary>
public static class LongHeader
{
    /// <summary>
    /// Parst die Klartext-Felder eines Long-Header-Pakets mit Paketnummer (Initial/Handshake/0-RTT).
    /// Header- und Packet Protection werden hier <em>nicht</em> entfernt – dafür anschließend
    /// <see cref="PacketProtection.UnprotectPacket"/> mit <see cref="LongHeaderPrefix.PacketNumberOffset"/> aufrufen.
    /// </summary>
    /// <returns><c>true</c> bei wohlgeformtem Prefix; <c>false</c> bei zu kurzen/ungültigen Daten (Paket verwerfen).</returns>
    public static bool TryParse(ReadOnlySpan<byte> datagram, out LongHeaderPrefix? prefix)
    {
        prefix = null;
        var reader = new BufferReader(datagram);

        if (!reader.TryReadByte(out byte first))
            return false;
        if (!PacketFormat.IsLongHeader(first) || (first & PacketFormat.FixedBit) == 0)
            return false;

        if (!reader.TryReadUInt32(out uint version))
            return false;
        // Version 0 = Version Negotiation: anderes Format, hier nicht behandelt.
        if (version == 0)
            return false;

        LongPacketType type = PacketFormat.GetLongPacketType(first);
        // Retry trägt keine Länge/Paketnummer – separat behandeln.
        if (type == LongPacketType.Retry)
            return false;

        if (!TryReadConnectionId(ref reader, out ConnectionId dcid) ||
            !TryReadConnectionId(ref reader, out ConnectionId scid))
            return false;

        byte[] token = [];
        if (type == LongPacketType.Initial)
        {
            if (!reader.TryReadVarInt(out ulong tokenLength) || tokenLength > (ulong)reader.Remaining)
                return false;
            if (!reader.TryReadBytes((int)tokenLength, out ReadOnlySpan<byte> tokenSpan))
                return false;
            token = tokenSpan.ToArray();
        }

        if (!reader.TryReadVarInt(out ulong length))
            return false;

        int pnOffset = reader.Position;
        // Das Length-Feld muss vollständig im Datagramm liegen.
        if (length > (ulong)reader.Remaining)
            return false;

        prefix = new LongHeaderPrefix
        {
            Type = type,
            Version = version,
            DestinationConnectionId = dcid,
            SourceConnectionId = scid,
            Token = token,
            Length = (long)length,
            PacketNumberOffset = pnOffset,
        };
        return true;
    }

    /// <summary>
    /// Liest die <em>versionsunabhängigen</em> Felder eines Long Headers (RFC 8999): erstes Byte,
    /// Version, Destination und Source Connection ID. Funktioniert auch für unbekannte Versionen und
    /// Version-Negotiation-/Retry-Pakete, da dieses Prefix in allen QUIC-Versionen identisch aufgebaut ist.
    /// </summary>
    public static bool TryParseInvariant(ReadOnlySpan<byte> datagram, out uint version, out ConnectionId dcid, out ConnectionId scid)
    {
        version = 0;
        dcid = ConnectionId.Empty;
        scid = ConnectionId.Empty;

        var reader = new BufferReader(datagram);
        if (!reader.TryReadByte(out byte first) || !PacketFormat.IsLongHeader(first))
            return false;
        if (!reader.TryReadUInt32(out version))
            return false;
        return TryReadConnectionId(ref reader, out dcid) && TryReadConnectionId(ref reader, out scid);
    }

    private static bool TryReadConnectionId(ref BufferReader reader, out ConnectionId cid)
    {
        cid = ConnectionId.Empty;
        if (!reader.TryReadByte(out byte len))
            return false;
        if (len > ConnectionId.MaxLength)
            return false; // RFC 9000 §17.2: > 20 Bytes -> Paket verwerfen.
        if (!reader.TryReadBytes(len, out ReadOnlySpan<byte> bytes))
            return false;
        cid = new ConnectionId(bytes);
        return true;
    }

    /// <summary>
    /// Baut ein vollständiges, geschütztes Initial-, Handshake- oder 0-RTT-Paket aus strukturierten Feldern.
    /// </summary>
    /// <param name="protection">Packet/Header Protection der sendenden Seite/des Levels.</param>
    /// <param name="type"><see cref="LongPacketType.Initial"/>, <see cref="LongPacketType.Handshake"/> oder
    /// <see cref="LongPacketType.ZeroRtt"/> (0-RTT hat wie Handshake kein Token-Feld).</param>
    /// <param name="token">Initial-Token (leer, falls keins); bei Handshake/0-RTT ignoriert.</param>
    /// <param name="packetNumberLength">Länge der Paketnummer auf dem Draht (1–4).</param>
    public static byte[] Build(
        PacketProtection protection,
        LongPacketType type,
        uint version,
        ConnectionId destinationConnectionId,
        ConnectionId sourceConnectionId,
        ReadOnlySpan<byte> token,
        ulong packetNumber,
        int packetNumberLength,
        ReadOnlySpan<byte> payload)
    {
        if (type is not (LongPacketType.Initial or LongPacketType.Handshake or LongPacketType.ZeroRtt))
            throw new ArgumentException("Build unterstützt nur Initial, Handshake und 0-RTT.", nameof(type));
        if (packetNumberLength is < 1 or > 4)
            throw new ArgumentOutOfRangeException(nameof(packetNumberLength));

        // Kleine Nutzlast (z. B. nur ein ACK) mit PADDING auffüllen, damit das Sample passt (RFC 9001 §5.4.2).
        payload = PacketPadding.ForSampling(payload, packetNumberLength);

        using var header = new BufferWriter();
        header.WriteByte(PacketFormat.BuildLongHeaderFirstByte(type, packetNumberLength));
        header.WriteUInt32(version);
        header.WriteByte((byte)destinationConnectionId.Length);
        header.WriteBytes(destinationConnectionId.Span);
        header.WriteByte((byte)sourceConnectionId.Length);
        header.WriteBytes(sourceConnectionId.Span);
        if (type == LongPacketType.Initial)
        {
            header.WriteVarInt((ulong)token.Length);
            header.WriteBytes(token);
        }

        // Length = Paketnummer + Payload + 16-Byte-AEAD-Tag.
        long lengthField = packetNumberLength + payload.Length + 16;
        header.WriteVarInt((ulong)lengthField);

        Span<byte> pn = stackalloc byte[4];
        PacketNumber.Encode(pn, packetNumber, packetNumberLength);
        header.WriteBytes(pn[..packetNumberLength]);

        return protection.ProtectPacket(header.WrittenSpan, packetNumberLength, packetNumber, payload, longHeader: true);
    }
}
