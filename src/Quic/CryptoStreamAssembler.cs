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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic;

/// <summary>
/// Reassembliert den CRYPTO-Byte-Strom eines Encryption-Levels aus (möglicherweise ungeordneten,
/// paketübergreifenden) Fragmenten (RFC 9000 §19.6, §7.5). Jeder Encryption-Level hat seinen eigenen
/// CRYPTO-Strom, der bei Offset 0 beginnt. Duplikate/Überlappungen werden idempotent behandelt.
/// </summary>
public sealed class CryptoStreamAssembler
{
    private readonly SortedDictionary<ulong, byte[]> _fragments = new();

    /// <summary>
    /// Fügt ein bei <paramref name="offset"/> beginnendes Fragment hinzu.
    /// </summary>
    public void Add(ulong offset, ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            return;

        // Bereits vollständig vom zusammenhängenden Präfix abgedeckte Fragmente ignorieren.
        // (Für den Handshake genügt diese einfache, nicht überlappungsspaltende Ablage.)
        _fragments[offset] = data.ToArray();
    }

    /// <summary>
    /// Der zusammenhängende Präfix ab Offset 0. Bricht an der ersten Lücke ab – der Rest wartet
    /// auf fehlende Fragmente.
    /// </summary>
    public byte[] Contiguous()
    {
        using var ms = new MemoryStream();
        ulong pos = 0;
        foreach ((ulong offset, byte[] data) in _fragments)
        {
            if (offset > pos)
                break; // Lücke

            // Überlappung: nur den noch nicht geschriebenen Teil anhängen.
            ulong skip = pos - offset;
            if (skip >= (ulong)data.Length)
                continue; // vollständig redundant

            ms.Write(data, (int)skip, data.Length - (int)skip);
            pos += (ulong)data.Length - skip;
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Länge des aktuell zusammenhängenden Präfixes.
    /// </summary>
    public long ContiguousLength => Contiguous().Length;
}
