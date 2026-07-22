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
/// QPACK-Encoder ohne dynamische Tabelle (RFC 9204). Kodiert Header-Feld-Sektionen ausschließlich mit
/// der statischen Tabelle und Literalen – spec-konform und interop-fähig, wenn
/// <c>SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0</c> angesagt wird (dann verzichtet auch der Peer auf die
/// dynamische Tabelle). Erzeugt keine Encoder-Stream-Instruktionen.
/// </summary>
public static class QpackEncoder
{
    /// <summary>
    /// Kodiert eine Header-Liste als Encoded Field Section (inklusive Prefix).
    /// </summary>
    public static byte[] Encode(IReadOnlyList<HeaderField> headers)
    {
        var writer = new BufferWriter(128);
        try
        {
            // Field Section Prefix: Required Insert Count = 0, S = 0, Delta Base = 0.
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);

            foreach (HeaderField header in headers)
                EncodeField(ref writer, header.Name.ToLowerInvariant(), header.Value);

            return writer.WrittenSpan.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static void EncodeField(ref BufferWriter writer, string name, string value)
    {
        // 1) Exaktes (Name,Wert)-Paar in der Static Table → Indexed Field Line.
        if (QpackStaticTable.TryGetPairIndex(name, value, out int pairIndex))
        {
            // 1 T=1 Index(6+)  → Muster 0b1100_0000
            QpackPrimitives.EncodeInteger(ref writer, (ulong)pairIndex, 6, 0b1100_0000);
            return;
        }

        // 2) Name in der Static Table → Literal Field Line with Name Reference.
        if (QpackStaticTable.TryGetNameIndex(name, out int nameIndex))
        {
            // 0 1 N=0 T=1 NameIndex(4+)  → Muster 0b0101_0000
            QpackPrimitives.EncodeInteger(ref writer, (ulong)nameIndex, 4, 0b0101_0000);
            QpackPrimitives.EncodeString(ref writer, value, 7, 0x00);
            return;
        }

        // 3) Sonst → Literal Field Line with Literal Name.
        // 0 0 1 N=0 H NameLen(3+)  → Muster 0b0010_0000, Huffman-Bit = 0x08
        QpackPrimitives.EncodeString(ref writer, name, 3, 0b0010_0000);
        QpackPrimitives.EncodeString(ref writer, value, 7, 0x00);
    }
}
