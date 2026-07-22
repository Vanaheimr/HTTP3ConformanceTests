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

using System.Buffers.Binary;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;

/// <summary>
/// Hilfsfunktionen für das TLS-Wire-Format über einem <see cref="BufferWriter"/>. TLS nutzt durchgängig
/// längenpräfigierte Vektoren mit 1-, 2- oder 3-Byte-Längen (RFC 8446, §3.4). Das Muster hier:
/// Platzhalter für die Länge schreiben, Inhalt schreiben, dann die Länge nachtragen (Back-Patching).
/// </summary>
public static class TlsWriter
{
    /// <summary>
    /// Beginnt einen längenpräfigierten Block und gibt den Offset des Längenfelds zurück.
    /// </summary>
    public static int BeginVector(ref BufferWriter writer, int prefixBytes)
    {
        int offset = writer.Length;
        for (int i = 0; i < prefixBytes; i++)
            writer.WriteByte(0);
        return offset;
    }

    /// <summary>
    /// Schließt einen mit <see cref="BeginVector"/> begonnenen Block und trägt seine Länge ein.
    /// </summary>
    public static void EndVector(ref BufferWriter writer, int offset, int prefixBytes)
    {
        int contentLength = writer.Length - offset - prefixBytes;
        Span<byte> slot = writer.PatchSpan(offset, prefixBytes);
        switch (prefixBytes)
        {
            case 1:
                slot[0] = checked((byte)contentLength);
                break;
            case 2:
                BinaryPrimitives.WriteUInt16BigEndian(slot, checked((ushort)contentLength));
                break;
            case 3:
                slot[0] = (byte)(contentLength >> 16);
                slot[1] = (byte)(contentLength >> 8);
                slot[2] = (byte)contentLength;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(prefixBytes));
        }
    }

    /// <summary>
    /// Schreibt eine TLS-Extension mit 2-Byte-Typ und 2-Byte-längenpräfigiertem Inhalt.
    /// </summary>
    public static void WriteExtension(ref BufferWriter writer, ExtensionType type, ReadOnlySpan<byte> data)
    {
        writer.WriteUInt16((ushort)type);
        writer.WriteUInt16(checked((ushort)data.Length));
        writer.WriteBytes(data);
    }
}
