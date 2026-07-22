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

using System.Security.Cryptography;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

/// <summary>
/// Leitet Stateless-Reset-Tokens deterministisch aus einer Connection ID ab (RFC 9000 §10.3.1):
/// <c>token = HMAC-SHA256(geheim, connection_id)[0..16]</c>. Damit kann ein Endpoint, der den Zustand einer
/// Verbindung verloren hat (Neustart), das zur DCID gehörende Token neu berechnen und einen Stateless Reset
/// senden — ohne je Zustand gehalten zu haben. Das Geheimnis lebt prozessweit; alle Instanzen teilen es.
/// </summary>
public sealed class StatelessResetTokenGenerator
{
    private readonly byte[] _secret;

    /// <summary>
    /// <paramref name="secret"/> = das (persistente) Server-Geheimnis; ohne Angabe wird eines erzeugt.
    /// </summary>
    public StatelessResetTokenGenerator(byte[]? secret = null)
        => _secret = secret is { Length: > 0 } ? secret : RandomNumberGenerator.GetBytes(32);

    /// <summary>
    /// Das zur <paramref name="connectionId"/> gehörende 16-Byte-Stateless-Reset-Token.
    /// </summary>
    public byte[] ComputeToken(ReadOnlySpan<byte> connectionId)
    {
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_secret, connectionId, mac);
        return mac[..StatelessReset.TokenLength].ToArray();
    }
}
