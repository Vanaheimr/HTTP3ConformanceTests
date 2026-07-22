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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

/// <summary>
/// Die zerlegten Felder eines NewSessionTicket (RFC 8446 §4.6.1).
/// </summary>
/// <param name="LifetimeSeconds">Gültigkeitsdauer des Tickets in Sekunden (max. 7 Tage).</param>
/// <param name="AgeAdd">Zufälliger Wert, mit dem der Client das Ticket-Alter verschleiert (obfuscated_ticket_age).</param>
/// <param name="Nonce">Ticket-Nonce; unterscheidet mehrere PSKs aus demselben resumption_master_secret.</param>
/// <param name="Ticket">Das opake Ticket (Identity), das der Client im pre_shared_key zurückspielt.</param>
/// <param name="MaxEarlyDataSize">Aus der early_data-Extension; <c>0</c> = kein 0-RTT erlaubt. QUIC nutzt 0xFFFFFFFF.</param>
public sealed record NewSessionTicketInfo(
    uint LifetimeSeconds,
    uint AgeAdd,
    byte[] Nonce,
    byte[] Ticket,
    uint MaxEarlyDataSize);

/// <summary>
/// Baut und zerlegt NewSessionTicket-Nachrichten (RFC 8446 §4.6.1) – die Grundlage der Session Resumption.
/// </summary>
public static class NewSessionTicket
{
    /// <summary>
    /// Zerlegt den Rumpf (ohne den 4-Byte-Handshake-Header) einer NewSessionTicket-Nachricht.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> body, out NewSessionTicketInfo? info)
    {
        info = null;
        var r = new BufferReader(body);
        if (!r.TryReadUInt32(out uint lifetime) ||
            !r.TryReadUInt32(out uint ageAdd) ||
            !r.TryReadByte(out byte nonceLen) ||
            !r.TryReadBytes(nonceLen, out ReadOnlySpan<byte> nonce) ||
            !r.TryReadUInt16(out ushort ticketLen) ||
            !r.TryReadBytes(ticketLen, out ReadOnlySpan<byte> ticket) ||
            !r.TryReadUInt16(out ushort extensionsLen) ||
            !r.TryReadBytes(extensionsLen, out ReadOnlySpan<byte> extensions))
            return false;

        uint maxEarlyData = ReadMaxEarlyDataSize(extensions);
        info = new NewSessionTicketInfo(lifetime, ageAdd, nonce.ToArray(), ticket.ToArray(), maxEarlyData);
        return true;
    }

    /// <summary>
    /// Baut eine vollständige NewSessionTicket-Handshake-Nachricht. <paramref name="maxEarlyDataSize"/> &gt; 0
    /// fügt die early_data-Extension hinzu (für QUIC 0-RTT ist der Wert 0xFFFFFFFF, RFC 9001 §4.6.1).
    /// </summary>
    public static byte[] Build(
        uint lifetimeSeconds, uint ageAdd, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ticket, uint maxEarlyDataSize = 0)
    {
        var w = new BufferWriter(64 + ticket.Length);
        try
        {
            w.WriteByte((byte)HandshakeType.NewSessionTicket);
            int bodyLen = TlsWriter.BeginVector(ref w, 3);

            w.WriteUInt32(lifetimeSeconds);
            w.WriteUInt32(ageAdd);
            w.WriteByte(checked((byte)nonce.Length));
            w.WriteBytes(nonce);
            w.WriteUInt16(checked((ushort)ticket.Length));
            w.WriteBytes(ticket);

            int extLen = TlsWriter.BeginVector(ref w, 2);
            if (maxEarlyDataSize > 0)
            {
                Span<byte> value = stackalloc byte[4];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(value, maxEarlyDataSize);
                TlsWriter.WriteExtension(ref w, ExtensionType.EarlyData, value);
            }
            TlsWriter.EndVector(ref w, extLen, 2);

            TlsWriter.EndVector(ref w, bodyLen, 3);
            return w.WrittenSpan.ToArray();
        }
        finally { w.Dispose(); }
    }

    private static uint ReadMaxEarlyDataSize(ReadOnlySpan<byte> extensions)
    {
        var r = new BufferReader(extensions);
        while (r.Remaining >= 4)
        {
            if (!r.TryReadUInt16(out ushort type) ||
                !r.TryReadUInt16(out ushort length) ||
                !r.TryReadBytes(length, out ReadOnlySpan<byte> data))
                break;
            if (type == (ushort)ExtensionType.EarlyData && data.Length == 4)
                return System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(data);
        }
        return 0;
    }
}
