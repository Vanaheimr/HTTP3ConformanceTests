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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Crypto;

/// <summary>
/// AEAD-Verfahren einer Cipher Suite: AES-GCM (AES-128/256) oder ChaCha20-Poly1305.
/// </summary>
public enum AeadAlgorithm
{
    AesGcm,
    ChaCha20Poly1305,
}

/// <summary>
/// Packet Protection (AEAD, RFC 9001 §5.3) und Header Protection (§5.4) für eine Richtung auf einem
/// Encryption-Level. Kapselt Key, IV und HP-Key als einsatzbereite Krypto-Objekte. Unterstützt AES-GCM
/// (HP via AES-ECB) und ChaCha20-Poly1305 (HP via ChaCha20-Keystream, RFC 9001 §5.4.4).
/// </summary>
public sealed class PacketProtection : IDisposable
{
    private readonly AesGcm? _aesGcm;
    private readonly ChaCha20Poly1305? _chacha;
    private readonly byte[] _iv;
    private readonly Aes? _headerProtectionAes;   // AES-ECB (AES-GCM-Suiten)
    private readonly byte[]? _headerProtectionKey; // ChaCha20-HP-Schlüssel (ChaCha20-Suite)

    private const int TagLength = 16;
    private const int SampleLength = 16;

    /// <summary>
    /// Erzeugt eine Protection für das angegebene AEAD-Verfahren (Standard: AES-GCM, u. a. Initial).
    /// </summary>
    public PacketProtection(TrafficKeys keys, AeadAlgorithm algorithm = AeadAlgorithm.AesGcm)
    {
        ArgumentNullException.ThrowIfNull(keys);
        _iv = keys.Iv;
        if (algorithm == AeadAlgorithm.ChaCha20Poly1305)
        {
            _chacha = new ChaCha20Poly1305(keys.Key);
            _headerProtectionKey = keys.HeaderProtectionKey;
        }
        else
        {
            _aesGcm = new AesGcm(keys.Key, TagLength);
            _headerProtectionAes = Aes.Create();
            _headerProtectionAes.Key = keys.HeaderProtectionKey;
        }
    }

    // ---- AEAD-Nonce (RFC 9001 §5.3) --------------------------------------------------------

    /// <summary>
    /// Nonce = IV XOR (Paketnummer, linksbündig mit Nullen auf IV-Länge aufgefüllt, Big-Endian).
    /// Es zählt die volle rekonstruierte Paketnummer, nicht die verkürzte Wire-Kodierung.
    /// </summary>
    private void ComputeNonce(ulong packetNumber, Span<byte> nonce)
    {
        _iv.CopyTo(nonce);
        for (int i = 0; i < 8; i++)
            nonce[nonce.Length - 1 - i] ^= (byte)(packetNumber >> (8 * i));
    }

    // ---- AEAD encrypt/decrypt --------------------------------------------------------------

    /// <summary>
    /// Verschlüsselt <paramref name="plaintext"/> mit dem Header als Associated Data.
    /// <paramref name="output"/> muss <c>plaintext.Length + 16</c> Bytes fassen; Rückgabe ist die geschriebene Länge.
    /// </summary>
    public int Encrypt(ulong packetNumber, ReadOnlySpan<byte> header, ReadOnlySpan<byte> plaintext, Span<byte> output)
    {
        Span<byte> nonce = stackalloc byte[12];
        ComputeNonce(packetNumber, nonce);

        Span<byte> ciphertext = output[..plaintext.Length];
        Span<byte> tag = output.Slice(plaintext.Length, TagLength);
        if (_chacha is not null)
            _chacha.Encrypt(nonce, plaintext, ciphertext, tag, header);
        else
            _aesGcm!.Encrypt(nonce, plaintext, ciphertext, tag, header);
        return plaintext.Length + TagLength;
    }

    /// <summary>
    /// Entschlüsselt <paramref name="ciphertextWithTag"/> (Ciphertext gefolgt vom 16-Byte-Tag).
    /// Gibt <c>false</c> zurück, wenn der Tag nicht passt (Authentifizierungsfehler), statt zu werfen.
    /// </summary>
    public bool Decrypt(ulong packetNumber, ReadOnlySpan<byte> header, ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintext, out int written)
    {
        written = 0;
        if (ciphertextWithTag.Length < TagLength)
            return false;

        Span<byte> nonce = stackalloc byte[12];
        ComputeNonce(packetNumber, nonce);

        ReadOnlySpan<byte> ciphertext = ciphertextWithTag[..^TagLength];
        ReadOnlySpan<byte> tag = ciphertextWithTag[^TagLength..];
        try
        {
            if (_chacha is not null)
                _chacha.Decrypt(nonce, ciphertext, tag, plaintext[..ciphertext.Length], header);
            else
                _aesGcm!.Decrypt(nonce, ciphertext, tag, plaintext[..ciphertext.Length], header);
            written = ciphertext.Length;
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
    }

    // ---- Header Protection (RFC 9001 §5.4) -------------------------------------------------

    /// <summary>
    /// Berechnet die 5-Byte-Maske aus einem 16-Byte-Sample des Ciphertexts: <c>AES-ECB(hp_key, sample)[0..5]</c>
    /// bzw. für ChaCha20 der ChaCha20-Keystream über den HP-Schlüssel (RFC 9001 §5.4.4).
    /// </summary>
    public void HeaderProtectionMask(ReadOnlySpan<byte> sample, Span<byte> mask)
    {
        if (_headerProtectionKey is not null)
        {
            ChaCha20.HeaderProtectionMask(_headerProtectionKey, sample[..SampleLength], mask);
            return;
        }
        Span<byte> block = stackalloc byte[16];
        _headerProtectionAes!.EncryptEcb(sample[..SampleLength], block, PaddingMode.None);
        block[..5].CopyTo(mask);
    }

    // ---- High-Level: ganzes Paket schützen / entschützen ----------------------------------

    /// <summary>
    /// Schützt ein komplettes Paket: verschlüsselt die Nutzlast und wendet anschließend die
    /// Header Protection an. <paramref name="unprotectedHeader"/> endet mit den (unmaskierten)
    /// Paketnummern-Bytes; <paramref name="packetNumberLength"/> ist deren Anzahl (1..4).
    /// </summary>
    /// <param name="longHeader"><c>true</c> für Long-Header-Pakete (Initial/Handshake/0-RTT), sonst Short Header.</param>
    /// <returns>Das fertige, geschützte Paket (Header + Ciphertext + Tag).</returns>
    public byte[] ProtectPacket(
        ReadOnlySpan<byte> unprotectedHeader,
        int packetNumberLength,
        ulong packetNumber,
        ReadOnlySpan<byte> payload,
        bool longHeader)
    {
        if (packetNumberLength is < 1 or > 4)
            throw new ArgumentOutOfRangeException(nameof(packetNumberLength));

        int pnOffset = unprotectedHeader.Length - packetNumberLength;
        byte[] packet = new byte[unprotectedHeader.Length + payload.Length + TagLength];
        unprotectedHeader.CopyTo(packet);

        // 1) Nutzlast verschlüsseln (AAD = unmaskierter Header).
        Encrypt(packetNumber, unprotectedHeader, payload, packet.AsSpan(unprotectedHeader.Length));

        // 2) Header Protection: Sample beginnt 4 Bytes nach Beginn des Paketnummernfelds.
        int sampleOffset = pnOffset + 4;
        Span<byte> mask = stackalloc byte[5];
        HeaderProtectionMask(packet.AsSpan(sampleOffset, SampleLength), mask);
        ApplyHeaderMask(packet, pnOffset, packetNumberLength, mask, longHeader);

        return packet;
    }

    /// <summary>
    /// Entschützt ein komplettes empfangenes Paket. <paramref name="packetNumberOffset"/> ist der
    /// Offset des Paketnummernfelds (nach Version/CIDs/Token/Length beim Long Header bzw. nach der
    /// DCID beim Short Header). Bei Erfolg werden die entschlüsselten Frames nach
    /// <paramref name="plaintext"/> geschrieben.
    /// </summary>
    public bool UnprotectPacket(
        Span<byte> packet,
        int packetNumberOffset,
        long largestAckedPacketNumber,
        bool longHeader,
        Span<byte> plaintext,
        out ulong packetNumber,
        out int plaintextLength)
    {
        plaintextLength = 0;
        if (!RemoveHeaderProtection(packet, packetNumberOffset, largestAckedPacketNumber, longHeader,
                out packetNumber, out int headerLength))
            return false;

        ReadOnlySpan<byte> header = packet[..headerLength];
        ReadOnlySpan<byte> ciphertextWithTag = packet[headerLength..];
        return Decrypt(packetNumber, header, ciphertextWithTag, plaintext, out plaintextLength);
    }

    /// <summary>
    /// Entfernt nur die Header Protection (RFC 9001 §5.4) und rekonstruiert die Paketnummer, <em>ohne</em>
    /// AEAD-Entschlüsselung. Der HP-Key ist über Key Updates konstant (§6.1), sodass das erste Byte danach
    /// gelesen werden kann (u. a. das Key-Phase-Bit), um die passenden AEAD-Schlüssel zu wählen.
    /// <paramref name="headerLength"/> ist die Länge des Headers bis inkl. Paketnummer (= Beginn des Ciphertexts).
    /// </summary>
    public bool RemoveHeaderProtection(
        Span<byte> packet,
        int packetNumberOffset,
        long largestAckedPacketNumber,
        bool longHeader,
        out ulong packetNumber,
        out int headerLength)
    {
        packetNumber = 0;
        headerLength = 0;

        int sampleOffset = packetNumberOffset + 4;
        if (packet.Length < sampleOffset + SampleLength)
            return false;

        Span<byte> mask = stackalloc byte[5];
        HeaderProtectionMask(packet.Slice(sampleOffset, SampleLength), mask);

        // 1) Erstes Byte entmaskieren -> Paketnummernlänge (und Key-Phase-Bit) gewinnen.
        byte firstByteMask = longHeader ? (byte)0x0f : (byte)0x1f;
        packet[0] ^= (byte)(mask[0] & firstByteMask);
        int packetNumberLength = (packet[0] & 0x03) + 1;

        // 2) Paketnummern-Bytes entmaskieren und rekonstruieren.
        uint truncatedPn = 0;
        for (int i = 0; i < packetNumberLength; i++)
        {
            byte b = (byte)(packet[packetNumberOffset + i] ^ mask[1 + i]);
            packet[packetNumberOffset + i] = b;
            truncatedPn = (truncatedPn << 8) | b;
        }

        packetNumber = PacketNumber.Decode(truncatedPn, packetNumberLength, largestAckedPacketNumber);
        headerLength = packetNumberOffset + packetNumberLength;
        return true;
    }

    private static void ApplyHeaderMask(Span<byte> packet, int pnOffset, int pnLength, ReadOnlySpan<byte> mask, bool longHeader)
    {
        byte firstByteMask = longHeader ? (byte)0x0f : (byte)0x1f;
        packet[0] ^= (byte)(mask[0] & firstByteMask);
        for (int i = 0; i < pnLength; i++)
            packet[pnOffset + i] ^= mask[1 + i];
    }

    public void Dispose()
    {
        _aesGcm?.Dispose();
        _chacha?.Dispose();
        _headerProtectionAes?.Dispose();
    }
}
