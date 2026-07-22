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

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;

/// <summary>
/// Huffman-Kodierung/-Dekodierung nach der statischen HPACK/QPACK-Tabelle (RFC 7541, Anhang B).
/// Codes sind präfixfrei; die Kodierung füllt am Ende mit 1-Bits (dem EOS-Präfix) bis zur Bytegrenze auf.
/// </summary>
internal static partial class Huffman
{
    // (Bitlänge << 32) | Code  ->  Symbol. Präfixfreiheit garantiert höchstens einen Treffer je Schritt.
    // Lazy, da die Feld-Initialisierungsreihenfolge über Partial-Class-Dateien (Table) nicht garantiert ist.
    private static Dictionary<long, int>? _decodeMap;
    private static Dictionary<long, int> DecodeMap => _decodeMap ??= BuildDecodeMap();

    private static Dictionary<long, int> BuildDecodeMap()
    {
        var map = new Dictionary<long, int>(Table.Length);
        for (int sym = 0; sym < Table.Length; sym++)
            map[Key(Table[sym].Bits, Table[sym].Code)] = sym;
        return map;
    }

    private static long Key(int bits, uint code) => ((long)bits << 32) | code;

    /// <summary>
    /// Länge der Huffman-kodierten Form von <paramref name="data"/> in Bytes.
    /// </summary>
    public static int EncodedLength(ReadOnlySpan<byte> data)
    {
        long bits = 0;
        foreach (byte b in data)
            bits += Table[b].Bits;
        return (int)((bits + 7) / 8);
    }

    /// <summary>
    /// Kodiert <paramref name="data"/> Huffman und schreibt das Ergebnis in <paramref name="writer"/>.
    /// </summary>
    public static void Encode(ref BufferWriter writer, ReadOnlySpan<byte> data)
    {
        ulong buffer = 0;
        int bitCount = 0;
        foreach (byte b in data)
        {
            (uint code, byte bits) = Table[b];
            buffer = (buffer << bits) | code;
            bitCount += bits;
            while (bitCount >= 8)
            {
                bitCount -= 8;
                writer.WriteByte((byte)(buffer >> bitCount));
            }
        }
        if (bitCount > 0)
        {
            // Mit 1-Bits (EOS-Präfix) auffüllen.
            int pad = 8 - bitCount;
            byte last = (byte)((buffer << pad) | ((1u << pad) - 1));
            writer.WriteByte(last);
        }
    }

    /// <summary>
    /// Dekodiert eine Huffman-kodierte Bytefolge. Gibt <c>false</c> bei ungültiger Kodierung zurück.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> data, out byte[] result)
    {
        result = [];
        var output = new List<byte>(data.Length * 2);
        uint code = 0;
        int len = 0;

        foreach (byte b in data)
        {
            for (int i = 7; i >= 0; i--)
            {
                code = (code << 1) | (uint)((b >> i) & 1);
                len++;
                if (len > 30)
                    return false; // kein Code länger als 30 Bit
                if (DecodeMap.TryGetValue(Key(len, code), out int sym))
                {
                    if (sym == 256)
                        return false; // EOS darf in einem String nicht vorkommen
                    output.Add((byte)sym);
                    code = 0;
                    len = 0;
                }
            }
        }

        // Rest muss gültiges Padding sein: weniger als 8 Bit, alle 1 (Präfix von EOS).
        if (len >= 8)
            return false;
        if (len > 0 && code != (1u << len) - 1)
            return false;

        result = [.. output];
        return true;
    }
}
