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

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Ein rohes HTTP/3-Frame: Typ + Nutzlast (RFC 9114 §7.1: Type(i) ‖ Length(i) ‖ Payload).
/// </summary>
public readonly record struct Http3Frame(ulong Type, ReadOnlyMemory<byte> Payload);

/// <summary>
/// Serialisieren und (inkrementelles) Parsen von HTTP/3-Frames.
/// </summary>
public static class Http3Frames
{
    /// <summary>
    /// Schreibt ein HTTP/3-Frame (Typ, Länge, Nutzlast) in <paramref name="writer"/>.
    /// </summary>
    public static void Write(ref BufferWriter writer, ulong type, ReadOnlySpan<byte> payload)
    {
        writer.WriteVarInt(type);
        writer.WriteVarInt((ulong)payload.Length);
        writer.WriteBytes(payload);
    }

    /// <summary>
    /// Baut ein einzelnes HTTP/3-Frame als Byte-Array.
    /// </summary>
    public static byte[] Build(ulong type, ReadOnlySpan<byte> payload)
    {
        var writer = new BufferWriter(payload.Length + 8);
        try
        {
            Write(ref writer, type, payload);
            return writer.WrittenSpan.ToArray();
        }
        finally { writer.Dispose(); }
    }

    /// <summary>
    /// Liest so viele vollständige Frames wie möglich aus <paramref name="buffer"/>.
    /// <paramref name="consumed"/> gibt an, wie viele Bytes verbraucht wurden – der Rest ist ein
    /// noch unvollständiges Frame (auf weitere Stream-Daten warten).
    /// </summary>
    public static bool TryReadAll(ReadOnlyMemory<byte> buffer, out List<Http3Frame> frames, out int consumed)
    {
        frames = [];
        consumed = 0;
        var reader = new BufferReader(buffer.Span);

        while (!reader.IsEmpty)
        {
            if (!reader.TryReadVarInt(out ulong type) || !reader.TryReadVarInt(out ulong length))
                break; // Frame-Kopf unvollständig
            if (length > (ulong)reader.Remaining)
                break; // Nutzlast noch nicht vollständig

            int payloadStart = reader.Position;
            if (!reader.TrySkip((int)length))
                break;

            frames.Add(new Http3Frame(type, buffer.Slice(payloadStart, (int)length)));
            consumed = reader.Position;
        }

        return true;
    }
}
