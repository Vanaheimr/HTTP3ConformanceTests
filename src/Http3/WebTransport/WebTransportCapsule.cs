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

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;

/// <summary>
/// Ein Capsule des Capsule-Protokolls (RFC 9297 §3.2): Typ ‖ Länge ‖ Wert. Auf dem CONNECT-Stream
/// einer WebTransport-Session tragen Capsules Session-Steuerung (WT_CLOSE_SESSION) und Flow Control
/// (WT_MAX_STREAMS/WT_MAX_DATA/…). Unbekannte Typen MÜSSEN still übersprungen werden (§3.2).
/// </summary>
public readonly record struct WebTransportCapsule(ulong Type, ReadOnlyMemory<byte> Value)
{
    /// <summary>
    /// Serialisiert ein Capsule (Typ ‖ VarInt-Länge ‖ Wert).
    /// </summary>
    public static byte[] Build(ulong type, ReadOnlySpan<byte> value)
    {
        var writer = new BufferWriter(value.Length + 16);
        try
        {
            writer.WriteVarInt(type);
            writer.WriteVarInt((ulong)value.Length);
            writer.WriteBytes(value);
            return writer.WrittenSpan.ToArray();
        }
        finally { writer.Dispose(); }
    }

    /// <summary>
    /// Ein Capsule mit einem einzelnen VarInt-Wert (WT_MAX_STREAMS/WT_MAX_DATA/…).
    /// </summary>
    public static byte[] BuildVarIntCapsule(ulong type, ulong value)
    {
        var inner = new BufferWriter(8);
        try
        {
            inner.WriteVarInt(value);
            return Build(type, inner.WrittenSpan);
        }
        finally { inner.Dispose(); }
    }

    /// <summary>
    /// Das WT_CLOSE_SESSION-Capsule (§6): 32-Bit-Fehlercode (big-endian) ‖ UTF-8-Meldung (≤ 1024 B).
    /// </summary>
    public static byte[] BuildCloseSession(uint errorCode, string reason)
    {
        byte[] reasonBytes = System.Text.Encoding.UTF8.GetBytes(reason);
        if (reasonBytes.Length > 1024)
            reasonBytes = reasonBytes[..1024];
        var value = new byte[4 + reasonBytes.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(value, errorCode);
        reasonBytes.CopyTo(value, 4);
        return Build(WebTransportConstants.CapsuleCloseSession, value);
    }

    /// <summary>
    /// Liest so viele vollständige Capsules wie möglich aus <paramref name="buffer"/>;
    /// <paramref name="consumed"/> gibt die verbrauchten Bytes an (der Rest ist ein unvollständiges
    /// Capsule – auf weitere Stream-Daten warten).
    /// </summary>
    public static List<WebTransportCapsule> ReadAll(ReadOnlyMemory<byte> buffer, out int consumed)
    {
        var capsules = new List<WebTransportCapsule>();
        consumed = 0;
        var reader = new BufferReader(buffer.Span);
        while (!reader.IsEmpty)
        {
            if (!reader.TryReadVarInt(out ulong type) || !reader.TryReadVarInt(out ulong length))
                break; // Capsule-Kopf unvollständig
            if (length > (ulong)reader.Remaining)
                break; // Wert noch nicht vollständig
            int valueStart = reader.Position;
            if (!reader.TrySkip((int)length))
                break;
            capsules.Add(new WebTransportCapsule(type, buffer.Slice(valueStart, (int)length)));
            consumed = reader.Position;
        }
        return capsules;
    }
}
