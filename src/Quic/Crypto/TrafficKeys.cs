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
/// Ein Satz Schlüssel für eine Richtung/Encryption-Level, abgeleitet aus einem Traffic Secret
/// (RFC 9001, §5.1): Packet-Protection-Key, IV und Header-Protection-Key.
/// </summary>
public sealed class TrafficKeys
{
    /// <summary>
    /// Der zugrunde liegende Traffic Secret (für spätere Key Updates).
    /// </summary>
    public byte[] Secret { get; }

    /// <summary>
    /// AEAD-Schlüssel für die Packet Protection ("quic key").
    /// </summary>
    public byte[] Key { get; }

    /// <summary>
    /// IV für die AEAD-Nonce ("quic iv"), 12 Bytes.
    /// </summary>
    public byte[] Iv { get; }

    /// <summary>
    /// Schlüssel für die Header Protection ("quic hp").
    /// </summary>
    public byte[] HeaderProtectionKey { get; }

    private TrafficKeys(byte[] secret, byte[] key, byte[] iv, byte[] hp)
    {
        Secret = secret;
        Key = key;
        Iv = iv;
        HeaderProtectionKey = hp;
    }

    /// <summary>
    /// Leitet Key/IV/HP aus einem Traffic Secret ab.
    /// </summary>
    /// <param name="hash">Hash der Cipher Suite (SHA-256 für die Initial-Suite).</param>
    /// <param name="secret">Der Traffic Secret.</param>
    /// <param name="keyLength">AEAD-Schlüssellänge in Bytes (16 für AES-128, 32 für AES-256/ChaCha20).</param>
    public static TrafficKeys FromSecret(HashAlgorithmName hash, ReadOnlySpan<byte> secret, int keyLength)
    {
        // RFC 9001 §5.1: IV ist immer 12 Bytes; HP-Key hat dieselbe Länge wie der AEAD-Key.
        byte[] key = TlsHkdf.ExpandLabel(hash, secret, "quic key", keyLength);
        byte[] iv = TlsHkdf.ExpandLabel(hash, secret, "quic iv", 12);
        byte[] hp = TlsHkdf.ExpandLabel(hash, secret, "quic hp", keyLength);
        return new TrafficKeys(secret.ToArray(), key, iv, hp);
    }

    /// <summary>
    /// Leitet die nächste Generation für ein Key Update ab (RFC 9001 §6.1):
    /// <c>secret_&lt;n+1&gt; = HKDF-Expand-Label(secret_&lt;n&gt;, "quic ku", "", Hash.length)</c>,
    /// daraus neuer Key und IV. Der <b>Header-Protection-Key bleibt unverändert</b>.
    /// </summary>
    /// <param name="hash">Hash der Suite.</param>
    /// <param name="hashLength">Länge des Hash-Ausgangs (= Secret-Länge; 32 für SHA-256).</param>
    public TrafficKeys Next(HashAlgorithmName hash, int hashLength)
    {
        byte[] nextSecret = TlsHkdf.ExpandLabel(hash, Secret, "quic ku", hashLength);
        byte[] key = TlsHkdf.ExpandLabel(hash, nextSecret, "quic key", Key.Length);
        byte[] iv = TlsHkdf.ExpandLabel(hash, nextSecret, "quic iv", 12);
        return new TrafficKeys(nextSecret, key, iv, HeaderProtectionKey);
    }
}
