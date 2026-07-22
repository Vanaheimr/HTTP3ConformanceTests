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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Core;

/// <summary>
/// QUIC Variable-Length Integer (RFC 9000, §16).
/// <para>
/// Die beiden höchstwertigen Bits des ersten Bytes kodieren die Länge des Integers
/// (2^bits Bytes: 1, 2, 4 oder 8). Die restlichen Bits bilden zusammen mit den
/// Folgebytes den Wert (Big-Endian). Nutzbarer Wertebereich: 0 .. 2^62-1.
/// </para>
/// <code>
///   2Bit | Länge | Nutzbare Bits | Maximalwert
///   -----+-------+---------------+---------------------------
///    00  |   1   |       6       | 63
///    01  |   2   |      14       | 16383
///    10  |   4   |      30       | 1073741823
///    11  |   8   |      62       | 4611686018427387903
/// </code>
/// </summary>
public static class VarInt
{
    /// <summary>
    /// Größter kodierbarer Wert (2^62 - 1).
    /// </summary>
    public const ulong MaxValue = (1UL << 62) - 1;

    private const ulong Max1Byte = (1UL << 6) - 1;   // 63
    private const ulong Max2Byte = (1UL << 14) - 1;  // 16383
    private const ulong Max4Byte = (1UL << 30) - 1;  // 1073741823

    /// <summary>
    /// Liefert die Anzahl Bytes, die <paramref name="value"/> im Wire-Format belegt (1, 2, 4 oder 8).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Wenn <paramref name="value"/> &gt; <see cref="MaxValue"/>.</exception>
    public static int GetLength(ulong value)
    {
        if (value <= Max1Byte) return 1;
        if (value <= Max2Byte) return 2;
        if (value <= Max4Byte) return 4;
        if (value <= MaxValue) return 8;
        throw new ArgumentOutOfRangeException(nameof(value), value,
            $"Wert überschreitet den maximal kodierbaren VarInt ({MaxValue}).");
    }

    /// <summary>
    /// Liefert die Gesamtlänge (in Bytes) eines VarInts anhand seines ersten Bytes,
    /// ohne den Rest zu lesen. Nützlich, um vorab zu prüfen, ob genug Bytes vorliegen.
    /// </summary>
    public static int GetLengthFromFirstByte(byte first) => 1 << (first >> 6);

    /// <summary>
    /// Kodiert <paramref name="value"/> in <paramref name="destination"/> und gibt die
    /// Anzahl geschriebener Bytes zurück.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Wenn der Wert zu groß ist.</exception>
    /// <exception cref="ArgumentException">Wenn <paramref name="destination"/> zu klein ist.</exception>
    public static int Write(Span<byte> destination, ulong value)
    {
        int length = GetLength(value);
        if (destination.Length < length)
            throw new ArgumentException(
                $"Zielpuffer zu klein: benötigt {length}, vorhanden {destination.Length}.",
                nameof(destination));

        switch (length)
        {
            case 1:
                // Präfix 00 — die oberen 2 Bits sind für Werte <= 63 ohnehin 0.
                destination[0] = (byte)value;
                break;
            case 2:
                // Präfix 01
                BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)(value | (0b01UL << 14)));
                break;
            case 4:
                // Präfix 10
                BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)(value | (0b10UL << 30)));
                break;
            default: // 8
                // Präfix 11
                BinaryPrimitives.WriteUInt64BigEndian(destination, value | (0b11UL << 62));
                break;
        }

        return length;
    }

    /// <summary>
    /// Liest einen VarInt aus <paramref name="source"/>. Gibt bei Erfolg <c>true</c> zurück und
    /// setzt <paramref name="value"/> sowie <paramref name="bytesRead"/>. Bei zu wenigen Bytes
    /// (unvollständiges Paket) <c>false</c>, ohne zu werfen.
    /// </summary>
    public static bool TryRead(ReadOnlySpan<byte> source, out ulong value, out int bytesRead)
    {
        value = 0;
        bytesRead = 0;
        if (source.IsEmpty)
            return false;

        int length = GetLengthFromFirstByte(source[0]);
        if (source.Length < length)
            return false;

        switch (length)
        {
            case 1:
                value = (ulong)(source[0] & 0x3F);
                break;
            case 2:
                value = BinaryPrimitives.ReadUInt16BigEndian(source) & 0x3FFFUL;
                break;
            case 4:
                value = BinaryPrimitives.ReadUInt32BigEndian(source) & 0x3FFF_FFFFUL;
                break;
            default: // 8
                value = BinaryPrimitives.ReadUInt64BigEndian(source) & 0x3FFF_FFFF_FFFF_FFFFUL;
                break;
        }

        bytesRead = length;
        return true;
    }
}
