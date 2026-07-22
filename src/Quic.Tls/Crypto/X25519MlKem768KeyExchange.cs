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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;

/// <summary>
/// Post-Quantum-Hybrid <c>X25519MLKEM768</c> (Named Group 0x11EC, draft-ietf-tls-ecdhe-mlkem): kombiniert
/// den klassischen X25519-Schlüsselaustausch (BouncyCastle) mit dem ML-KEM-768-KEM (FIPS 203, in der BCL von
/// .NET 10 nativ als <see cref="MLKem"/>). Motivation: „harvest now, decrypt later" — selbst wenn X25519
/// später durch einen Quantencomputer fällt, schützt ML-KEM das Geheimnis; und selbst wenn ML-KEM eine
/// klassische Schwäche hätte, schützt X25519. Chrome/Firefox/Cloudflare fahren den Hybrid seit 2024/25.
/// <para>
/// Anders als reines (EC)DHE ist ein KEM asymmetrisch: der Client sendet einen ML-KEM-Encapsulation-Key und
/// <b>decapsuliert</b> später den Ciphertext des Servers; der Server <b>encapsuliert</b> gegen den Client-Key
/// (<see cref="Encapsulate"/>). Reihenfolge laut Draft für <c>X25519MLKEM768</c>: ML-KEM-Teil zuerst, dann
/// X25519 — sowohl in den Key Shares als auch im gemeinsamen Geheimnis.
/// </para>
/// </summary>
public sealed class X25519MlKem768KeyExchange : IKeyExchange
{
    // Feste Größen für ML-KEM-768 (FIPS 203) und X25519.
    private const int MlKemEncapsulationKeyLength = 1184;
    private const int MlKemCiphertextLength = 1088;
    private const int MlKemSharedSecretLength = 32;
    private const int X25519KeyLength = 32;

    private readonly MLKem _mlKem;                 // Client-Rolle: hält den Decapsulation-Key
    private readonly X25519KeyExchange _x25519;

    public NamedGroup Group => NamedGroup.X25519MlKem768;

    /// <summary>
    /// Der angebotene Key Share des Clients: ML-KEM-Encapsulation-Key (1184) ‖ X25519-Public-Key (32) = 1216 Byte.
    /// </summary>
    public byte[] PublicKey { get; }

    public X25519MlKem768KeyExchange()
    {
        _mlKem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        _x25519 = new X25519KeyExchange();

        PublicKey = new byte[MlKemEncapsulationKeyLength + X25519KeyLength];
        _mlKem.ExportEncapsulationKey(PublicKey.AsSpan(0, MlKemEncapsulationKeyLength));
        _x25519.PublicKey.CopyTo(PublicKey.AsSpan(MlKemEncapsulationKeyLength));
    }

    /// <summary>
    /// Client-Seite: aus dem Server-Share (ML-KEM-Ciphertext ‖ X25519-Public-Key) das Geheimnis ableiten —
    /// ML-KEM decapsulieren und X25519 rechnen. Ergebnis: ML-KEM-Secret (32) ‖ X25519-Secret (32) = 64 Byte.
    /// </summary>
    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerShare)
    {
        if (peerShare.Length != MlKemCiphertextLength + X25519KeyLength)
            throw new ArgumentException(
                $"X25519MLKEM768-Server-Share muss {MlKemCiphertextLength + X25519KeyLength} Byte lang sein.", nameof(peerShare));

        byte[] mlKemSecret = _mlKem.Decapsulate(peerShare[..MlKemCiphertextLength].ToArray());
        byte[] x25519Secret = _x25519.DeriveSharedSecret(peerShare[MlKemCiphertextLength..]);
        return Concat(mlKemSecret, x25519Secret);
    }

    /// <summary>
    /// Server-Seite: gegen den Client-Share (ML-KEM-Encapsulation-Key ‖ X25519-Public-Key) encapsulieren.
    /// Liefert die Antwort (ML-KEM-Ciphertext (1088) ‖ eigener X25519-Public-Key (32) = 1120 Byte) und das
    /// Geheimnis (ML-KEM-Secret (32) ‖ X25519-Secret (32) = 64 Byte).
    /// </summary>
    public (byte[] ResponseShare, byte[] SharedSecret) Encapsulate(ReadOnlySpan<byte> peerShare)
    {
        if (peerShare.Length != MlKemEncapsulationKeyLength + X25519KeyLength)
            throw new ArgumentException(
                $"X25519MLKEM768-Client-Share muss {MlKemEncapsulationKeyLength + X25519KeyLength} Byte lang sein.", nameof(peerShare));

        using MLKem peerKem = MLKem.ImportEncapsulationKey(
            MLKemAlgorithm.MLKem768, peerShare[..MlKemEncapsulationKeyLength]);
        peerKem.Encapsulate(out byte[] ciphertext, out byte[] mlKemSecret);
        byte[] x25519Secret = _x25519.DeriveSharedSecret(peerShare[MlKemEncapsulationKeyLength..]);

        byte[] responseShare = Concat(ciphertext, _x25519.PublicKey);
        byte[] sharedSecret = Concat(mlKemSecret, x25519Secret);
        return (responseShare, sharedSecret);
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        byte[] result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }

    public void Dispose()
    {
        _mlKem.Dispose();
        _x25519.Dispose();
    }
}
