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

using System.Buffers;
using System.Buffers.Binary;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

/// <summary>
/// Wachsender Schreibpuffer (Big-Endian) zum Zusammenbauen ausgehender QUIC-Pakete.
/// <para>
/// Der Backing-Store wird aus dem <see cref="ArrayPool{Byte}"/> geliehen und bei Bedarf
/// verdoppelt. <see cref="Dispose"/> gibt ihn zurück – daher stets mit <c>using</c> verwenden.
/// Als <c>struct</c> ausgelegt; per <c>ref</c> übergeben, um Kopien (und doppeltes Dispose) zu vermeiden.
/// </para>
/// </summary>
public struct BufferWriter : IDisposable
{
    private const int DefaultCapacity = 1500;

    private byte[]? _buffer;
    private int _written;
    private bool _disposed;

    public BufferWriter(int initialCapacity = DefaultCapacity)
    {
        if (initialCapacity <= 0)
            throw new ArgumentOutOfRangeException(nameof(initialCapacity));
        _buffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
        _written = 0;
        _disposed = false;
    }

    /// <summary>
    /// Anzahl bislang geschriebener Bytes.
    /// </summary>
    public readonly int Length => _written;

    /// <summary>
    /// Die bisher geschriebenen Bytes als Slice (gültig bis zur nächsten Schreib-/Dispose-Operation).
    /// </summary>
    public readonly ReadOnlySpan<byte> WrittenSpan
        => _buffer is null ? ReadOnlySpan<byte>.Empty : _buffer.AsSpan(0, _written);

    public void WriteByte(byte value)
    {
        byte[] buf = EnsureCapacity(1);
        buf[_written] = value;
        _written += 1;
    }

    public void WriteUInt16(ushort value)
    {
        byte[] buf = EnsureCapacity(2);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(_written), value);
        _written += 2;
    }

    public void WriteUInt32(uint value)
    {
        byte[] buf = EnsureCapacity(4);
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(_written), value);
        _written += 4;
    }

    public void WriteUInt64(ulong value)
    {
        byte[] buf = EnsureCapacity(8);
        BinaryPrimitives.WriteUInt64BigEndian(buf.AsSpan(_written), value);
        _written += 8;
    }

    /// <summary>
    /// Schreibt einen QUIC-VarInt (RFC 9000 §16).
    /// </summary>
    public void WriteVarInt(ulong value)
    {
        byte[] buf = EnsureCapacity(VarInt.GetLength(value));
        _written += VarInt.Write(buf.AsSpan(_written), value);
    }

    public void WriteBytes(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
            return;
        byte[] buf = EnsureCapacity(value.Length);
        value.CopyTo(buf.AsSpan(_written));
        _written += value.Length;
    }

    /// <summary>
    /// Schreibt <paramref name="count"/> Bytes mit dem Wert <paramref name="value"/> (z. B. PADDING).
    /// </summary>
    public void WriteRepeated(byte value, int count)
    {
        if (count <= 0)
            return;
        byte[] buf = EnsureCapacity(count);
        buf.AsSpan(_written, count).Fill(value);
        _written += count;
    }

    /// <summary>
    /// Reserviert <paramref name="count"/> Bytes und gibt einen beschreibbaren Span darauf zurück.
    /// Nützlich, um z. B. eine Länge nachträglich einzutragen. Der Span ist nur bis zur nächsten
    /// Schreiboperation (mögliche Reallokation) gültig.
    /// </summary>
    public Span<byte> GetSpan(int count)
    {
        byte[] buf = EnsureCapacity(count);
        Span<byte> span = buf.AsSpan(_written, count);
        _written += count;
        return span;
    }

    /// <summary>
    /// Liefert einen beschreibbaren Span auf bereits geschriebene Bytes zum nachträglichen Patchen
    /// (z. B. ein Längenfeld eintragen, dessen Wert erst nach dem Schreiben des Inhalts feststeht).
    /// Nur unmittelbar vor der nächsten Schreiboperation gültig.
    /// </summary>
    public readonly Span<byte> PatchSpan(int offset, int count)
    {
        if (offset < 0 || count < 0 || offset + count > _written)
            throw new ArgumentOutOfRangeException(nameof(offset));
        return _buffer!.AsSpan(offset, count);
    }

    /// <summary>
    /// Stellt Platz für <paramref name="additional"/> weitere Bytes sicher und gibt den Backing-Store zurück.
    /// </summary>
    private byte[] EnsureCapacity(int additional)
    {
        ObjectDisposedException.ThrowIf(_disposed, typeof(BufferWriter));

        // Lazy-Init: Ein per 'new BufferWriter()' (impliziter struct-Default-Ctor) erzeugter
        // Writer hat noch keinen geliehenen Puffer.
        _buffer ??= ArrayPool<byte>.Shared.Rent(Math.Max(DefaultCapacity, additional));

        int required = _written + additional;
        if (required <= _buffer.Length)
            return _buffer;

        int newCapacity = _buffer.Length * 2;
        while (newCapacity < required)
            newCapacity *= 2;

        byte[] newBuffer = ArrayPool<byte>.Shared.Rent(newCapacity);
        _buffer.AsSpan(0, _written).CopyTo(newBuffer);
        ArrayPool<byte>.Shared.Return(_buffer);
        _buffer = newBuffer;
        return _buffer;
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        if (_buffer is not null)
            ArrayPool<byte>.Shared.Return(_buffer);
        _buffer = null;
        _disposed = true;
    }
}
