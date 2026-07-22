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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

/// <summary>
/// Version-Negotiation-Paket (RFC 9000 §17.2.1). Ein Server sendet es, wenn er die vom Client gewählte
/// Version nicht unterstützt; es listet die vom Server unterstützten Versionen. Erkennbar am Versionsfeld
/// 0. Trägt keine Paketnummer, keine Verschlüsselung. Beim Antworten vertauscht der Server DCID/SCID:
/// die SCID des Clients wird zur DCID des VN-Pakets und umgekehrt.
/// </summary>
public static class VersionNegotiationPacket
{
    /// <summary>
    /// Baut ein Version-Negotiation-Paket mit der Liste unterstützter Versionen.
    /// </summary>
    public static byte[] Build(ConnectionId destinationConnectionId, ConnectionId sourceConnectionId, IReadOnlyList<uint> supportedVersions)
    {
        using var w = new BufferWriter(16 + supportedVersions.Count * 4);
        // Erstes Byte: nur die Long-Header-Form ist bedeutsam; die übrigen 7 Bits werden zufällig gesetzt
        // (RFC 9000 §17.2.1 – erschwert Ossifizierung). Der Empfänger erkennt VN am Versionsfeld 0.
        w.WriteByte((byte)(0x80 | (RandomNumberGenerator.GetBytes(1)[0] & 0x7f)));
        w.WriteUInt32(0); // Version = 0 kennzeichnet Version Negotiation
        w.WriteByte((byte)destinationConnectionId.Length);
        w.WriteBytes(destinationConnectionId.Span);
        w.WriteByte((byte)sourceConnectionId.Length);
        w.WriteBytes(sourceConnectionId.Span);
        foreach (uint v in supportedVersions)
            w.WriteUInt32(v);
        return w.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Parst ein Version-Negotiation-Paket. Setzt <paramref name="supportedVersions"/> auf die Liste.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> datagram, out ConnectionId dcid, out ConnectionId scid, out List<uint> supportedVersions)
    {
        dcid = ConnectionId.Empty;
        scid = ConnectionId.Empty;
        supportedVersions = [];

        var r = new BufferReader(datagram);
        if (!r.TryReadByte(out byte first) || !PacketFormat.IsLongHeader(first))
            return false;
        if (!r.TryReadUInt32(out uint version) || version != 0)
            return false;
        if (!TryReadCid(ref r, out dcid) || !TryReadCid(ref r, out scid))
            return false;

        // Der Rest ist eine Folge von 4-Byte-Versionen (mind. eine).
        while (r.Remaining >= 4)
        {
            r.TryReadUInt32(out uint v);
            supportedVersions.Add(v);
        }
        return supportedVersions.Count > 0;
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
