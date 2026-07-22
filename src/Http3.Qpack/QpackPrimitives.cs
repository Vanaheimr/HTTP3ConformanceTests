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

using System.Text;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;

/// <summary>
/// Die Kodier-Primitive von QPACK/HPACK: Integer mit N-Bit-Präfix (RFC 7541 §5.1) und
/// längenpräfigierte Strings mit optionaler Huffman-Kodierung (§5.2).
/// </summary>
internal static class QpackPrimitives
{
    /// <summary>
    /// Kodiert eine Ganzzahl mit <paramref name="prefixBits"/>-Bit-Präfix. <paramref name="prefixPattern"/>
    /// enthält die höherwertigen Typ-Bits, die im ersten Byte über dem Präfix stehen.
    /// </summary>
    public static void EncodeInteger(ref BufferWriter writer, ulong value, int prefixBits, byte prefixPattern)
    {
        uint max = (1u << prefixBits) - 1;
        if (value < max)
        {
            writer.WriteByte((byte)(prefixPattern | (byte)value));
            return;
        }

        writer.WriteByte((byte)(prefixPattern | (byte)max));
        value -= max;
        while (value >= 128)
        {
            writer.WriteByte((byte)((value & 0x7f) | 0x80));
            value >>= 7;
        }
        writer.WriteByte((byte)value);
    }

    /// <summary>
    /// Dekodiert eine Ganzzahl mit N-Bit-Präfix. <paramref name="firstByte"/> ist das bereits gelesene
    /// erste Byte; die niederwertigen <paramref name="prefixBits"/> Bits bilden den Startwert.
    /// </summary>
    public static bool TryDecodeInteger(ref BufferReader reader, byte firstByte, int prefixBits, out ulong value)
    {
        uint max = (1u << prefixBits) - 1;
        value = (uint)(firstByte & max);
        if (value < max)
            return true;

        int shift = 0;
        while (true)
        {
            if (!reader.TryReadByte(out byte b))
                return false;
            value += (ulong)(b & 0x7f) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
            if (shift > 62)
                return false; // Schutz gegen überlange Kodierung
        }
    }

    /// <summary>
    /// Schreibt einen String (Name oder Wert): 1 Bit Huffman-Flag + <paramref name="prefixBits"/>-Bit-
    /// Längenpräfix, dann die (ggf. Huffman-kodierten) Bytes. Huffman wird gewählt, wenn es kürzer ist.
    /// </summary>
    public static void EncodeString(ref BufferWriter writer, string value, int prefixBits, byte prefixPattern)
    {
        byte[] raw = Encoding.ASCII.GetBytes(value);
        int huffmanLength = Huffman.EncodedLength(raw);

        byte huffmanBit = (byte)(1 << prefixBits); // das Bit direkt über dem Längenpräfix
        if (huffmanLength < raw.Length)
        {
            EncodeInteger(ref writer, (ulong)huffmanLength, prefixBits, (byte)(prefixPattern | huffmanBit));
            Huffman.Encode(ref writer, raw);
        }
        else
        {
            EncodeInteger(ref writer, (ulong)raw.Length, prefixBits, prefixPattern);
            writer.WriteBytes(raw);
        }
    }

    /// <summary>
    /// Liest einen String. <paramref name="firstByte"/> ist bereits gelesen (enthält Huffman-Bit + Länge).
    /// </summary>
    public static bool TryDecodeString(ref BufferReader reader, byte firstByte, int prefixBits, out string value)
    {
        value = string.Empty;
        bool huffman = (firstByte & (1 << prefixBits)) != 0;
        if (!TryDecodeInteger(ref reader, firstByte, prefixBits, out ulong length) || length > (ulong)reader.Remaining)
            return false;

        if (!reader.TryReadBytes((int)length, out ReadOnlySpan<byte> raw))
            return false;

        if (huffman)
        {
            if (!Huffman.TryDecode(raw, out byte[] decoded))
                return false;
            value = Encoding.ASCII.GetString(decoded);
        }
        else
        {
            value = Encoding.ASCII.GetString(raw);
        }
        return true;
    }
}
