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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

/// <summary>
/// Die für den Key-Schedule wesentlichen Felder eines geparsten ServerHello (RFC 8446 §4.1.3).
/// </summary>
public sealed class ServerHelloInfo
{
    /// <summary>
    /// <c>true</c>, wenn es sich um einen HelloRetryRequest handelt (spezieller Random-Wert).
    /// </summary>
    public required bool IsHelloRetryRequest { get; init; }
    public required CipherSuite CipherSuite { get; init; }
    public ushort? SelectedVersion { get; init; }

    /// <summary>
    /// Gruppe des Server-Key-Share (aus der key_share-Extension).
    /// </summary>
    public NamedGroup? KeyShareGroup { get; init; }

    /// <summary>
    /// Öffentlicher Schlüssel des Servers (unkomprimierter Punkt bei EC-Gruppen).
    /// </summary>
    public byte[]? KeySharePublicKey { get; init; }

    /// <summary>
    /// Index der vom Server akzeptierten PSK-Identity (pre_shared_key); <c>null</c> = keine Resumption.
    /// </summary>
    public ushort? SelectedPskIdentity { get; init; }
}

/// <summary>
/// Parst eine ServerHello-Handshake-Nachricht (nur Lesen – der Server erzeugt sie).
/// </summary>
public static class ServerHello
{
    // SHA-256("HelloRetryRequest") – dieser Random-Wert markiert einen HRR (RFC 8446 §4.1.3).
    private static ReadOnlySpan<byte> HelloRetryRequestRandom =>
    [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    ];

    /// <summary>
    /// Baut eine ServerHello-Handshake-Nachricht: legacy_version, Random, Session-ID-Echo, gewählte
    /// Cipher Suite, und die Extensions supported_versions (nur die gewählte Version) + key_share
    /// (der Server-Key-Share). <paramref name="keySharePublicKey"/> ist der unkomprimierte EC-Punkt.
    /// </summary>
    public static byte[] Build(CipherSuite cipherSuite, NamedGroup keyShareGroup, ReadOnlySpan<byte> keySharePublicKey,
        ushort? selectedPskIdentity = null)
    {
        var w = new BufferWriter(128);
        try
        {
            w.WriteByte((byte)HandshakeType.ServerHello);
            int bodyLen = TlsWriter.BeginVector(ref w, 3);

            w.WriteUInt16(TlsVersions.Tls12); // legacy_version

            Span<byte> random = stackalloc byte[32];
            RandomNumberGenerator.Fill(random);
            w.WriteBytes(random);

            w.WriteByte(0);                        // legacy_session_id_echo: leer (QUIC)
            w.WriteUInt16((ushort)cipherSuite);
            w.WriteByte(0);                        // legacy_compression_method

            int extLen = TlsWriter.BeginVector(ref w, 2);
            {
                // supported_versions (ServerHello-Form: nur die gewählte Version 0x0304).
                TlsWriter.WriteExtension(ref w, ExtensionType.SupportedVersions, [0x03, 0x04]);

                // key_share: eine KeyShareEntry (group + key_exchange<2-Byte-Länge>).
                w.WriteUInt16((ushort)ExtensionType.KeyShare);
                int ks = TlsWriter.BeginVector(ref w, 2);
                w.WriteUInt16((ushort)keyShareGroup);
                w.WriteUInt16((ushort)keySharePublicKey.Length);
                w.WriteBytes(keySharePublicKey);
                TlsWriter.EndVector(ref w, ks, 2);

                // pre_shared_key (nur bei Resumption): der gewählte Identity-Index (RFC 8446 §4.2.11).
                if (selectedPskIdentity is { } identity)
                    TlsWriter.WriteExtension(ref w, ExtensionType.PreSharedKey,
                        [(byte)(identity >> 8), (byte)identity]);
            }
            TlsWriter.EndVector(ref w, extLen, 2);

            TlsWriter.EndVector(ref w, bodyLen, 3);
            return w.WrittenSpan.ToArray();
        }
        finally { w.Dispose(); }
    }

    /// <summary>
    /// Baut einen HelloRetryRequest (RFC 8446 §4.1.4): formal ein ServerHello mit dem festen
    /// HRR-Random-Wert; die key_share-Extension enthält nur die angeforderte <paramref name="requestedGroup"/>
    /// (ohne Schlüssel).
    /// </summary>
    public static byte[] BuildHelloRetryRequest(CipherSuite cipherSuite, NamedGroup requestedGroup)
    {
        var w = new BufferWriter(64);
        try
        {
            w.WriteByte((byte)HandshakeType.ServerHello);
            int bodyLen = TlsWriter.BeginVector(ref w, 3);

            w.WriteUInt16(TlsVersions.Tls12);
            w.WriteBytes(HelloRetryRequestRandom); // markiert die Nachricht als HRR
            w.WriteByte(0);
            w.WriteUInt16((ushort)cipherSuite);
            w.WriteByte(0);

            int extLen = TlsWriter.BeginVector(ref w, 2);
            {
                TlsWriter.WriteExtension(ref w, ExtensionType.SupportedVersions, [0x03, 0x04]);
                // key_share (HRR-Form): nur die angeforderte Gruppe.
                TlsWriter.WriteExtension(ref w, ExtensionType.KeyShare,
                    [(byte)((ushort)requestedGroup >> 8), (byte)(ushort)requestedGroup]);
            }
            TlsWriter.EndVector(ref w, extLen, 2);

            TlsWriter.EndVector(ref w, bodyLen, 3);
            return w.WrittenSpan.ToArray();
        }
        finally { w.Dispose(); }
    }

    /// <summary>
    /// Parst den Handshake-Rumpf (inklusive Handshake-Header mit Typ + 3-Byte-Länge).
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> handshakeMessage, out ServerHelloInfo? info)
    {
        info = null;
        var reader = new BufferReader(handshakeMessage);

        if (!reader.TryReadByte(out byte msgType) || msgType != (byte)HandshakeType.ServerHello)
            return false;
        if (!reader.TryReadByte(out byte l0) || !reader.TryReadByte(out byte l1) || !reader.TryReadByte(out byte l2))
            return false;
        int bodyLength = (l0 << 16) | (l1 << 8) | l2;
        if (bodyLength > reader.Remaining)
            return false;

        if (!reader.TryReadUInt16(out _)) // legacy_version
            return false;

        if (!reader.TryReadBytes(32, out ReadOnlySpan<byte> random))
            return false;
        bool isHrr = random.SequenceEqual(HelloRetryRequestRandom);

        // legacy_session_id_echo<0..32>
        if (!reader.TryReadByte(out byte sessionIdLen) || !reader.TrySkip(sessionIdLen))
            return false;

        if (!reader.TryReadUInt16(out ushort cipherSuite))
            return false;

        if (!reader.TryReadByte(out _)) // legacy_compression_method
            return false;

        if (!reader.TryReadUInt16(out ushort extensionsLength) || extensionsLength > reader.Remaining)
            return false;

        ushort? selectedVersion = null;
        NamedGroup? keyShareGroup = null;
        byte[]? keySharePublicKey = null;
        ushort? selectedPskIdentity = null;

        if (!reader.TryReadBytes(extensionsLength, out ReadOnlySpan<byte> extensions))
            return false;
        if (!ParseExtensions(extensions, ref selectedVersion, ref keyShareGroup, ref keySharePublicKey, ref selectedPskIdentity))
            return false;

        info = new ServerHelloInfo
        {
            IsHelloRetryRequest = isHrr,
            CipherSuite = (CipherSuite)cipherSuite,
            SelectedVersion = selectedVersion,
            KeyShareGroup = keyShareGroup,
            KeySharePublicKey = keySharePublicKey,
            SelectedPskIdentity = selectedPskIdentity,
        };
        return true;
    }

    private static bool ParseExtensions(
        ReadOnlySpan<byte> extensions,
        ref ushort? selectedVersion,
        ref NamedGroup? keyShareGroup,
        ref byte[]? keySharePublicKey,
        ref ushort? selectedPskIdentity)
    {
        var reader = new BufferReader(extensions);
        while (!reader.IsEmpty)
        {
            if (!reader.TryReadUInt16(out ushort type) ||
                !reader.TryReadUInt16(out ushort length) ||
                !reader.TryReadBytes(length, out ReadOnlySpan<byte> data))
                return false;

            switch ((ExtensionType)type)
            {
                case ExtensionType.SupportedVersions when data.Length >= 2:
                    selectedVersion = (ushort)((data[0] << 8) | data[1]);
                    break;

                case ExtensionType.KeyShare when data.Length == 2:
                    // HelloRetryRequest-KeyShare: nur die angeforderte Gruppe, kein Schlüssel.
                    keyShareGroup = (NamedGroup)((data[0] << 8) | data[1]);
                    break;

                case ExtensionType.KeyShare when data.Length >= 4:
                    // ServerHello-KeyShare: KeyShareEntry = group(2) + key_exchange<1..2^16-1>.
                    var ksReader = new BufferReader(data);
                    if (ksReader.TryReadUInt16(out ushort group) &&
                        ksReader.TryReadUInt16(out ushort keyLen) &&
                        ksReader.TryReadBytes(keyLen, out ReadOnlySpan<byte> key))
                    {
                        keyShareGroup = (NamedGroup)group;
                        keySharePublicKey = key.ToArray();
                    }
                    break;

                case ExtensionType.PreSharedKey when data.Length == 2:
                    // selected_identity (RFC 8446 §4.2.11): der Server hat unsere PSK akzeptiert.
                    selectedPskIdentity = (ushort)((data[0] << 8) | data[1]);
                    break;
            }
        }
        return true;
    }
}
