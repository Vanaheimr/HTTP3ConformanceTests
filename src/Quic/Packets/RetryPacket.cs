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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Crypto;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

/// <summary>
/// Retry-Paket (RFC 9000 §17.2.5). Ein Server sendet es zur Adressvalidierung: Es enthält ein Retry Token,
/// das der Client in seinem nächsten Initial zurückspiegelt, sowie einen 16-Byte Retry Integrity Tag
/// (RFC 9001 §5.8) über das ursprüngliche DCID. Trägt keine Paketnummer/Länge. Die vom Server gewählte
/// Source Connection ID wird zur neuen Destination Connection ID des Clients.
/// </summary>
public static class RetryPacket
{
    /// <summary>
    /// Baut ein Retry-Paket. <paramref name="originalDestinationConnectionId"/> ist die DCID aus dem
    /// Client-Initial, das den Retry auslöste (fließt in den Integrity Tag ein).
    /// </summary>
    public static byte[] Build(
        uint version,
        ConnectionId destinationConnectionId,
        ConnectionId sourceConnectionId,
        ReadOnlySpan<byte> retryToken,
        ConnectionId originalDestinationConnectionId)
    {
        using var w = new BufferWriter(32 + retryToken.Length);
        // Erstes Byte: Long-Header-Form + Fixed Bit + Typ Retry (3); die unteren 4 Bits sind unbedeutend.
        w.WriteByte((byte)(0xC0 | ((byte)LongPacketType.Retry << 4) | (RandomNumberGenerator.GetBytes(1)[0] & 0x0f)));
        w.WriteUInt32(version);
        w.WriteByte((byte)destinationConnectionId.Length);
        w.WriteBytes(destinationConnectionId.Span);
        w.WriteByte((byte)sourceConnectionId.Length);
        w.WriteBytes(sourceConnectionId.Span);
        w.WriteBytes(retryToken);

        byte[] tag = RetryIntegrity.ComputeTag(originalDestinationConnectionId.Span, w.WrittenSpan);
        w.WriteBytes(tag);
        return w.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Parst ein Retry-Paket in seine Felder (ohne den Integrity Tag zu prüfen – dafür <see cref="Verify"/>).
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> datagram, out uint version, out ConnectionId dcid, out ConnectionId scid, out byte[] token, out byte[] integrityTag)
    {
        version = 0;
        dcid = ConnectionId.Empty;
        scid = ConnectionId.Empty;
        token = [];
        integrityTag = [];

        var r = new BufferReader(datagram);
        if (!r.TryReadByte(out byte first) || !PacketFormat.IsLongHeader(first))
            return false;
        if (PacketFormat.GetLongPacketType(first) != LongPacketType.Retry)
            return false;
        if (!r.TryReadUInt32(out version))
            return false;
        if (!TryReadCid(ref r, out dcid) || !TryReadCid(ref r, out scid))
            return false;

        // Rest = Retry Token ‖ 16-Byte Integrity Tag; der Token hat keine explizite Länge.
        if (r.Remaining < 16)
            return false;
        int tokenLength = r.Remaining - 16;
        r.TryReadBytes(tokenLength, out ReadOnlySpan<byte> tokenSpan);
        token = tokenSpan.ToArray();
        r.TryReadBytes(16, out ReadOnlySpan<byte> tagSpan);
        integrityTag = tagSpan.ToArray();
        return true;
    }

    /// <summary>
    /// Prüft den Integrity Tag eines empfangenen Retry-Pakets (RFC 9001 §5.8) gegen die ursprüngliche DCID.
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> retryDatagram, ConnectionId originalDestinationConnectionId)
    {
        if (retryDatagram.Length < 16)
            return false;
        ReadOnlySpan<byte> withoutTag = retryDatagram[..^16];
        ReadOnlySpan<byte> tag = retryDatagram[^16..];
        return RetryIntegrity.Verify(originalDestinationConnectionId.Span, withoutTag, tag);
    }

    private static bool TryReadCid(ref BufferReader r, out ConnectionId cid)
    {
        cid = ConnectionId.Empty;
        if (!r.TryReadByte(out byte len) || len > ConnectionId.MaxLength || !r.TryReadBytes(len, out ReadOnlySpan<byte> bytes))
            return false;
        cid = new ConnectionId(bytes);
        return true;
    }
}
