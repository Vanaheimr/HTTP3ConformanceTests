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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

/// <summary>
/// Byte-Warteschlange für den Zero-Alloc-Pfad (Phase 9): hinten anhängen, vorne konsumieren —
/// beides amortisiert O(1) und ohne Allokation im eingeschwungenen Zustand. Ersetzt die früheren
/// <c>List&lt;byte&gt;</c>-Puffer, deren <c>RemoveRange(0, n)</c> bei jedem Konsum ALLE Restbytes
/// verschob (O(n²) über einen Transfer) und deren Auslesen (<c>ToArray</c>) je Pump-Durchlauf den
/// gesamten Inhalt kopierte. Der Backing-Store wächst bei Bedarf (Verdopplung) und wird
/// wiederverwendet; Kompaktion (Restbytes an den Anfang schieben) geschieht nur, wenn hinten kein
/// Platz mehr ist — amortisiert O(1) je Byte.
/// </summary>
public sealed class ByteQueue
{
    private byte[] _buffer = [];
    private int _head; // Index des ersten ungelesenen Bytes
    private int _tail; // Index der ersten freien Position

    /// <summary>
    /// Anzahl der gepufferten (noch nicht konsumierten) Bytes.
    /// </summary>
    public int Count => _tail - _head;

    /// <summary>
    /// Die gepufferten Bytes als Span — gültig bis zum nächsten <see cref="Append"/>/<see cref="Consume"/>.
    /// </summary>
    public ReadOnlySpan<byte> Span => _buffer.AsSpan(_head, _tail - _head);

    /// <summary>
    /// Die gepufferten Bytes als Memory (für Parser mit <c>ReadOnlyMemory</c>-Signatur) — gültig bis
    /// zur nächsten Mutation.
    /// </summary>
    public ReadOnlyMemory<byte> Memory => _buffer.AsMemory(_head, _tail - _head);

    /// <summary>
    /// Hängt Bytes hinten an.
    /// </summary>
    public void Append(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return;
        EnsureSpace(data.Length);
        data.CopyTo(_buffer.AsSpan(_tail));
        _tail += data.Length;
    }

    /// <summary>
    /// Konsumiert die vordersten <paramref name="count"/> Bytes (rückt nur den Lese-Index vor).
    /// </summary>
    public void Consume(int count)
    {
        if (count < 0 || count > Count)
            throw new ArgumentOutOfRangeException(nameof(count));
        _head += count;
        if (_head == _tail)
            _head = _tail = 0; // leer ⇒ Indizes zurücksetzen (bester Fall: nie kompaktieren)
    }

    /// <summary>
    /// Verwirft den gesamten Inhalt (Backing-Store bleibt zur Wiederverwendung erhalten).
    /// </summary>
    public void Clear() => _head = _tail = 0;

    /// <summary>
    /// Kopiert den Inhalt in ein frisches Array (nur für Übergaben, die Besitz übernehmen müssen).
    /// </summary>
    public byte[] ToArray() => Span.ToArray();

    private void EnsureSpace(int needed)
    {
        if (_tail + needed <= _buffer.Length)
            return;
        int count = Count;
        if (count + needed <= _buffer.Length)
        {
            // Hinten voll, aber vorne ist Platz frei ⇒ kompaktieren statt wachsen
            // (Buffer.BlockCopy ist überlappungssicher, wie memmove).
            Buffer.BlockCopy(_buffer, _head, _buffer, 0, count);
        }
        else
        {
            int capacity = Math.Max(256, _buffer.Length);
            while (capacity < count + needed)
                capacity *= 2;
            byte[] grown = new byte[capacity];
            Buffer.BlockCopy(_buffer, _head, grown, 0, count);
            _buffer = grown;
        }
        _head = 0;
        _tail = count;
    }
}
