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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

/// <summary>
/// Vorwärts-Leser über einen <see cref="ReadOnlySpan{Byte}"/> (Big-Endian, wie im QUIC-Wire-Format).
/// <para>
/// Als <c>ref struct</c> ausgelegt – lebt nur auf dem Stack, keine Allokation, kein Kopieren des
/// zugrunde liegenden Puffers. Die <c>Try*</c>-Methoden werfen nie; sie geben <c>false</c> zurück,
/// wenn nicht genug Bytes vorliegen (unvollständiges Paket). Die nicht-<c>Try</c>-Varianten werfen
/// <see cref="EndOfBufferException"/> und sind für Stellen gedacht, an denen die Länge zuvor geprüft wurde.
/// </para>
/// </summary>
public ref struct BufferReader
{
    private readonly ReadOnlySpan<byte> _buffer;

    public BufferReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        Position = 0;
    }

    /// <summary>
    /// Aktuelle Leseposition (Bytes ab Beginn).
    /// </summary>
    public int Position { get; private set; }

    /// <summary>
    /// Anzahl noch nicht gelesener Bytes.
    /// </summary>
    public readonly int Remaining => _buffer.Length - Position;

    /// <summary>
    /// <c>true</c>, wenn alle Bytes gelesen wurden.
    /// </summary>
    public readonly bool IsEmpty => Remaining == 0;

    /// <summary>
    /// Der noch nicht gelesene Rest, ohne die Position zu verändern.
    /// </summary>
    public readonly ReadOnlySpan<byte> RemainingSpan => _buffer[Position..];

    public bool TryReadByte(out byte value)
    {
        if (Remaining < 1)
        {
            value = 0;
            return false;
        }
        value = _buffer[Position];
        Position += 1;
        return true;
    }

    public byte ReadByte()
        => TryReadByte(out byte v) ? v : throw EndOfBuffer(1);

    public bool TryReadUInt16(out ushort value)
    {
        if (Remaining < 2)
        {
            value = 0;
            return false;
        }
        value = BinaryPrimitives.ReadUInt16BigEndian(_buffer[Position..]);
        Position += 2;
        return true;
    }

    public ushort ReadUInt16()
        => TryReadUInt16(out ushort v) ? v : throw EndOfBuffer(2);

    public bool TryReadUInt32(out uint value)
    {
        if (Remaining < 4)
        {
            value = 0;
            return false;
        }
        value = BinaryPrimitives.ReadUInt32BigEndian(_buffer[Position..]);
        Position += 4;
        return true;
    }

    public uint ReadUInt32()
        => TryReadUInt32(out uint v) ? v : throw EndOfBuffer(4);

    public bool TryReadUInt64(out ulong value)
    {
        if (Remaining < 8)
        {
            value = 0;
            return false;
        }
        value = BinaryPrimitives.ReadUInt64BigEndian(_buffer[Position..]);
        Position += 8;
        return true;
    }

    public ulong ReadUInt64()
        => TryReadUInt64(out ulong v) ? v : throw EndOfBuffer(8);

    /// <summary>
    /// Liest einen QUIC-VarInt (RFC 9000 §16).
    /// </summary>
    public bool TryReadVarInt(out ulong value)
    {
        if (VarInt.TryRead(RemainingSpan, out value, out int read))
        {
            Position += read;
            return true;
        }
        return false;
    }

    public ulong ReadVarInt()
        => TryReadVarInt(out ulong v) ? v : throw EndOfBuffer(1);

    /// <summary>
    /// Liest genau <paramref name="length"/> Bytes als Slice des zugrunde liegenden Puffers
    /// (kein Kopieren).
    /// </summary>
    public bool TryReadBytes(int length, out ReadOnlySpan<byte> value)
    {
        if (length < 0 || Remaining < length)
        {
            value = default;
            return false;
        }
        value = _buffer.Slice(Position, length);
        Position += length;
        return true;
    }

    public ReadOnlySpan<byte> ReadBytes(int length)
        => TryReadBytes(length, out ReadOnlySpan<byte> v) ? v : throw EndOfBuffer(length);

    /// <summary>
    /// Überspringt <paramref name="length"/> Bytes.
    /// </summary>
    public bool TrySkip(int length)
    {
        if (length < 0 || Remaining < length)
            return false;
        Position += length;
        return true;
    }

    private readonly EndOfBufferException EndOfBuffer(int needed)
        => new(needed, Remaining);
}

/// <summary>
/// Wird geworfen, wenn ein Lesevorgang über das Pufferende hinausginge.
/// </summary>
public sealed class EndOfBufferException(int needed, int available)
    : Exception($"Pufferende erreicht: benötigt {needed} Byte(s), verfügbar {available}.")
{
    public int Needed { get; } = needed;
    public int Available { get; } = available;
}
