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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

/// <summary>
/// Eine QUIC Connection ID (RFC 9000, §5.1): 0–20 Bytes, die eine Verbindung unabhängig von der
/// IP-Adresse identifizieren. Als <c>readonly struct</c> mit Wertegleichheit ausgelegt, damit sie
/// direkt als Dictionary-Schlüssel für das Verbindungs-Demultiplexing dienen kann.
/// </summary>
public readonly struct ConnectionId : IEquatable<ConnectionId>
{
    /// <summary>
    /// Maximale Länge in QUIC v1.
    /// </summary>
    public const int MaxLength = 20;

    private readonly byte[]? _bytes;

    public ConnectionId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > MaxLength)
            throw new ArgumentOutOfRangeException(nameof(bytes), $"Connection ID länger als {MaxLength} Bytes.");
        _bytes = bytes.IsEmpty ? [] : bytes.ToArray();
    }

    /// <summary>
    /// Die leere Connection ID (Länge 0) – zulässig und häufig für die Server-DCID genutzt.
    /// </summary>
    public static ConnectionId Empty => default;

    public int Length => _bytes?.Length ?? 0;

    public ReadOnlySpan<byte> Span => _bytes ?? [];

    public byte[] ToArray() => Span.ToArray();

    public static ConnectionId Parse(string hex) => new(Convert.FromHexString(hex));

    public bool Equals(ConnectionId other) => Span.SequenceEqual(other.Span);

    public override bool Equals(object? obj) => obj is ConnectionId other && Equals(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Span);
        return hash.ToHashCode();
    }

    public override string ToString() => Convert.ToHexString(Span).ToLowerInvariant();

    public static bool operator ==(ConnectionId left, ConnectionId right) => left.Equals(right);
    public static bool operator !=(ConnectionId left, ConnectionId right) => !left.Equals(right);
}
