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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Crypto;

/// <summary>
/// Ableitung der Initial-Schlüssel aus der Destination Connection ID des ersten Client-Pakets
/// (RFC 9001, §5.2). Beide Seiten kennen die DCID und können damit dieselben Schlüssel bilden –
/// der Initial-Level ist daher nur gegen Off-Path-Angreifer geschützt, nicht vertraulich.
/// </summary>
public sealed class InitialSecrets
{
    /// <summary>
    /// Versionsspezifischer Salt für QUIC v1 (RFC 9001, §5.2).
    /// </summary>
    public static ReadOnlySpan<byte> InitialSaltV1 =>
    [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    ];

    /// <summary>
    /// Initial nutzt fest AEAD_AES_128_GCM mit SHA-256 (RFC 9001, §5.2).
    /// </summary>
    private const int InitialKeyLength = 16;

    /// <summary>
    /// Der gemeinsame <c>initial_secret</c> (HKDF-Extract).
    /// </summary>
    public byte[] InitialSecret { get; }

    /// <summary>
    /// Schlüssel zum Schutz der Client-Pakete.
    /// </summary>
    public TrafficKeys Client { get; }

    /// <summary>
    /// Schlüssel zum Schutz der Server-Pakete.
    /// </summary>
    public TrafficKeys Server { get; }

    private InitialSecrets(byte[] initialSecret, TrafficKeys client, TrafficKeys server)
    {
        InitialSecret = initialSecret;
        Client = client;
        Server = server;
    }

    /// <summary>
    /// Leitet die Initial-Schlüssel für QUIC v1 aus der <paramref name="destinationConnectionId"/> ab.
    /// </summary>
    public static InitialSecrets DeriveV1(ReadOnlySpan<byte> destinationConnectionId)
    {
        HashAlgorithmName hash = HashAlgorithmName.SHA256;

        // initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
        byte[] initialSecret = TlsHkdf.Extract(hash, InitialSaltV1, destinationConnectionId);

        byte[] clientSecret = TlsHkdf.ExpandLabel(hash, initialSecret, "client in", 32);
        byte[] serverSecret = TlsHkdf.ExpandLabel(hash, initialSecret, "server in", 32);

        TrafficKeys client = TrafficKeys.FromSecret(hash, clientSecret, InitialKeyLength);
        TrafficKeys server = TrafficKeys.FromSecret(hash, serverSecret, InitialKeyLength);

        return new InitialSecrets(initialSecret, client, server);
    }
}
