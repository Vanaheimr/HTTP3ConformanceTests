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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;

/// <summary>
/// STREAM-Frame (Typ 0x08..0x0f, RFC 9000 §19.8): trägt Anwendungs-Stream-Daten. Die unteren drei
/// Bits des Typs sind Flags: OFF (0x04) = Offset-Feld vorhanden, LEN (0x02) = Length-Feld vorhanden,
/// FIN (0x01) = Stream-Ende.
/// </summary>
public sealed record StreamFrame(ulong StreamId, ulong Offset, ReadOnlyMemory<byte> Data, bool Fin) : Frame
{
    public override void Write(ref BufferWriter writer)
    {
        // Wir schreiben stets mit LEN-Bit (explizite Länge) – robust auch bei Coalescing mit Folge-Frames.
        byte type = (byte)FrameType.StreamBase;
        if (Offset != 0) type |= FrameType.StreamOffBit;
        type |= FrameType.StreamLenBit;
        if (Fin) type |= FrameType.StreamFinBit;

        writer.WriteVarInt(type);
        writer.WriteVarInt(StreamId);
        if (Offset != 0)
            writer.WriteVarInt(Offset);
        writer.WriteVarInt((ulong)Data.Length);
        writer.WriteBytes(Data.Span);
    }

    /// <summary>
    /// Parst den Frame-Rumpf. <paramref name="type"/> ist das bereits gelesene Typ-Byte (mit Flags).
    /// </summary>
    public static bool TryReadBody(ref BufferReader reader, byte type, out StreamFrame? frame)
    {
        frame = null;
        bool hasOffset = (type & FrameType.StreamOffBit) != 0;
        bool hasLength = (type & FrameType.StreamLenBit) != 0;
        bool fin = (type & FrameType.StreamFinBit) != 0;

        if (!reader.TryReadVarInt(out ulong streamId))
            return false;

        ulong offset = 0;
        if (hasOffset && !reader.TryReadVarInt(out offset))
            return false;

        int length;
        if (hasLength)
        {
            if (!reader.TryReadVarInt(out ulong len) || len > (ulong)reader.Remaining)
                return false;
            length = (int)len;
        }
        else
        {
            // Ohne LEN-Bit reicht die Stream-Data bis zum Paketende.
            length = reader.Remaining;
        }

        if (!reader.TryReadBytes(length, out ReadOnlySpan<byte> data))
            return false;

        frame = new StreamFrame(streamId, offset, data.ToArray(), fin);
        return true;
    }
}
