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
using System.Text;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

/// <summary>
/// Konfiguration für einen ClientHello (RFC 8446 §4.1.2, für QUIC/HTTP-3 zugeschnitten).
/// </summary>
public sealed class ClientHelloOptions
{
    /// <summary>
    /// Server-Name für die SNI-Extension (z. B. "cloudflare-quic.com").
    /// </summary>
    public required string ServerName { get; init; }

    /// <summary>
    /// ALPN-Protokolle; für HTTP/3 zwingend "h3".
    /// </summary>
    public IReadOnlyList<string> AlpnProtocols { get; init; } = ["h3"];

    public IReadOnlyList<CipherSuite> CipherSuites { get; init; } =
        [CipherSuite.Aes128GcmSha256, CipherSuite.Aes256GcmSha384];

    public IReadOnlyList<NamedGroup> SupportedGroups { get; init; } = [NamedGroup.X25519, NamedGroup.Secp256r1];

    public IReadOnlyList<SignatureScheme> SignatureSchemes { get; init; } =
    [
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.Ed25519,
        SignatureScheme.Ed448,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
        SignatureScheme.RsaPssRsaeSha512,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.RsaPkcs1Sha256,
        // Post-Quantum (draft-ietf-tls-mldsa): wir VERIFIZIEREN ML-DSA-signierte CertificateVerify.
        SignatureScheme.MLDsa65,
        SignatureScheme.MLDsa44,
        SignatureScheme.MLDsa87,
    ];

    /// <summary>
    /// Die mitgesendeten Key Shares (Gruppe + öffentlicher Schlüssel), in Präferenzreihenfolge.
    /// </summary>
    public required IReadOnlyList<KeyShareEntry> KeyShares { get; init; }

    /// <summary>
    /// Opake Bytes der QUIC-Transport-Parameter (von der QUIC-Schicht kodiert).
    /// </summary>
    public required ReadOnlyMemory<byte> QuicTransportParameters { get; init; }

    /// <summary>
    /// 32-Byte-Zufall; wenn leer, wird kryptografisch sicher erzeugt.
    /// </summary>
    public ReadOnlyMemory<byte> Random { get; init; }

    /// <summary>
    /// Optionales PSK-Angebot für Session Resumption (RFC 8446 §4.2.11). Ist es gesetzt, schreibt der Builder
    /// zusätzlich psk_key_exchange_modes und – als <b>letzte</b> Extension – pre_shared_key inklusive Binder.
    /// </summary>
    public PskIdentity? PskIdentity { get; init; }

    /// <summary>
    /// Länge eines PSK-Binders in Byte (= Hash-Länge der Suite, 32/48). Nur mit <see cref="PskIdentity"/>.
    /// </summary>
    public int PskBinderLength { get; init; }

    /// <summary>
    /// Berechnet den PSK-Binder über den abgeschnittenen ClientHello (bis vor die Binder-Liste, RFC 8446
    /// §4.2.11.2). Der Aufrufer kapselt hier <c>HMAC(finished_key(binder_key), Transcript-Hash(truncated))</c>.
    /// </summary>
    public Func<ReadOnlyMemory<byte>, byte[]>? ComputeBinder { get; init; }

    /// <summary>
    /// Fügt (für 0-RTT, Phase B) die leere early_data-Extension hinzu. Nur mit gesetztem PSK sinnvoll.
    /// </summary>
    public bool OfferEarlyData { get; init; }
}

/// <summary>
/// Ein Key-Share-Eintrag: Named Group + öffentlicher Schlüssel (Wire-Format der Gruppe).
/// </summary>
public readonly record struct KeyShareEntry(NamedGroup Group, ReadOnlyMemory<byte> PublicKey);

/// <summary>
/// Eine PSK-Identity im pre_shared_key-Angebot: das Ticket + sein verschleiertes Alter (RFC 8446 §4.2.11).
/// </summary>
public readonly record struct PskIdentity(ReadOnlyMemory<byte> Identity, uint ObfuscatedTicketAge);

/// <summary>
/// Serialisiert einen ClientHello als vollständige TLS-Handshake-Nachricht (mit Typ + 3-Byte-Länge).
/// </summary>
public static class ClientHello
{
    public static byte[] Build(ClientHelloOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var w = new BufferWriter(512);
        try
        {
            // Handshake-Header: msg_type (1) + length (3, nachträglich).
            w.WriteByte((byte)HandshakeType.ClientHello);
            int bodyLengthOffset = TlsWriter.BeginVector(ref w, prefixBytes: 3);

            WriteBody(ref w, options, out int binderListOffset, out int binderValueOffset);

            TlsWriter.EndVector(ref w, bodyLengthOffset, prefixBytes: 3);

            // PSK-Binder (RFC 8446 §4.2.11.2): HMAC über den ClientHello bis vor die Binder-Liste – alle
            // Längenfelder sind bereits so gesetzt, als wären die Binder vorhanden. Erst jetzt patchbar.
            if (binderValueOffset >= 0 && options.ComputeBinder is not null)
            {
                ReadOnlyMemory<byte> truncated = w.WrittenSpan[..binderListOffset].ToArray();
                byte[] binder = options.ComputeBinder(truncated);
                binder.CopyTo(w.PatchSpan(binderValueOffset, binder.Length));
            }

            return w.WrittenSpan.ToArray();
        }
        finally
        {
            w.Dispose();
        }
    }

    private static void WriteBody(ref BufferWriter w, ClientHelloOptions options,
        out int binderListOffset, out int binderValueOffset)
    {
        // legacy_version = TLS 1.2 (0x0303) – die echte Version steckt in supported_versions.
        w.WriteUInt16(TlsVersions.Tls12);

        // Random (32 Byte).
        Span<byte> random = stackalloc byte[32];
        if (options.Random.Length == 32)
            options.Random.Span.CopyTo(random);
        else
            RandomNumberGenerator.Fill(random);
        w.WriteBytes(random);

        // legacy_session_id: leer – QUIC nutzt keinen TLS-Compatibility-Mode (RFC 9001 §8.4).
        w.WriteByte(0);

        // cipher_suites (2-Byte-Längenpräfix).
        int csOffset = TlsWriter.BeginVector(ref w, 2);
        foreach (CipherSuite suite in options.CipherSuites)
            w.WriteUInt16((ushort)suite);
        TlsWriter.EndVector(ref w, csOffset, 2);

        // legacy_compression_methods: nur "null" (0), 1-Byte-Länge.
        w.WriteByte(1);
        w.WriteByte(0);

        // extensions (2-Byte-Längenpräfix).
        int extOffset = TlsWriter.BeginVector(ref w, 2);
        WriteExtensions(ref w, options, out binderListOffset, out binderValueOffset);
        TlsWriter.EndVector(ref w, extOffset, 2);
    }

    private static void WriteExtensions(ref BufferWriter w, ClientHelloOptions options,
        out int binderListOffset, out int binderValueOffset)
    {
        binderListOffset = -1;
        binderValueOffset = -1;

        WriteServerName(ref w, options.ServerName);
        WriteSupportedGroups(ref w, options.SupportedGroups);
        WriteSignatureAlgorithms(ref w, options.SignatureSchemes);
        WriteSupportedVersions(ref w);
        WriteKeyShares(ref w, options.KeyShares);
        WriteAlpn(ref w, options.AlpnProtocols);
        TlsWriter.WriteExtension(ref w, ExtensionType.QuicTransportParameters, options.QuicTransportParameters.Span);

        // psk_key_exchange_modes IMMER senden: signalisiert Resumption-Fähigkeit, damit der Server auch ohne
        // aktuelles PSK-Angebot ein NewSessionTicket ausstellt (RFC 8446 §4.2.9).
        WritePskKeyExchangeModes(ref w);

        // Bei Resumption zusätzlich: optional early_data und pre_shared_key als ALLERLETZTE Extension.
        if (options.PskIdentity is { } identity)
        {
            if (options.OfferEarlyData)
                TlsWriter.WriteExtension(ref w, ExtensionType.EarlyData, ReadOnlySpan<byte>.Empty);
            WritePreSharedKey(ref w, identity, options.PskBinderLength, out binderListOffset, out binderValueOffset);
        }
    }

    private static void WritePskKeyExchangeModes(ref BufferWriter w)
    {
        w.WriteUInt16((ushort)ExtensionType.PskKeyExchangeModes);
        int extLen = TlsWriter.BeginVector(ref w, 2);
        {
            int listLen = TlsWriter.BeginVector(ref w, 1); // ke_modes<1..255>
            w.WriteByte((byte)PskKeyExchangeMode.PskDheKe);
            TlsWriter.EndVector(ref w, listLen, 1);
        }
        TlsWriter.EndVector(ref w, extLen, 2);
    }

    private static void WritePreSharedKey(
        ref BufferWriter w, PskIdentity identity, int binderLength, out int binderListOffset, out int binderValueOffset)
    {
        w.WriteUInt16((ushort)ExtensionType.PreSharedKey);
        int extLen = TlsWriter.BeginVector(ref w, 2);
        {
            // identities<7..2^16-1>
            int idsLen = TlsWriter.BeginVector(ref w, 2);
            w.WriteUInt16(checked((ushort)identity.Identity.Length));
            w.WriteBytes(identity.Identity.Span);
            w.WriteUInt32(identity.ObfuscatedTicketAge);
            TlsWriter.EndVector(ref w, idsLen, 2);

            // binders<33..2^16-1> – Werte zunächst 0; sie liegen NACH der Trunkierungsgrenze und werden gepatcht.
            binderListOffset = w.Length;
            int bindersLen = TlsWriter.BeginVector(ref w, 2);
            w.WriteByte(checked((byte)binderLength)); // PskBinderEntry<32..255>
            binderValueOffset = w.Length;
            for (int i = 0; i < binderLength; i++)
                w.WriteByte(0);
            TlsWriter.EndVector(ref w, bindersLen, 2);
        }
        TlsWriter.EndVector(ref w, extLen, 2);
    }

    private static void WriteServerName(ref BufferWriter w, string serverName)
    {
        byte[] host = Encoding.ASCII.GetBytes(serverName);
        w.WriteUInt16((ushort)ExtensionType.ServerName);
        int extLen = TlsWriter.BeginVector(ref w, 2);
        {
            int listLen = TlsWriter.BeginVector(ref w, 2); // ServerNameList
            w.WriteByte(0);                                // NameType = host_name
            w.WriteUInt16((ushort)host.Length);            // HostName<1..2^16-1>
            w.WriteBytes(host);
            TlsWriter.EndVector(ref w, listLen, 2);
        }
        TlsWriter.EndVector(ref w, extLen, 2);
    }

    private static void WriteSupportedGroups(ref BufferWriter w, IReadOnlyList<NamedGroup> groups)
    {
        w.WriteUInt16((ushort)ExtensionType.SupportedGroups);
        int extLen = TlsWriter.BeginVector(ref w, 2);
        {
            int listLen = TlsWriter.BeginVector(ref w, 2);
            foreach (NamedGroup g in groups)
                w.WriteUInt16((ushort)g);
            TlsWriter.EndVector(ref w, listLen, 2);
        }
        TlsWriter.EndVector(ref w, extLen, 2);
    }

    private static void WriteSignatureAlgorithms(ref BufferWriter w, IReadOnlyList<SignatureScheme> schemes)
    {
        w.WriteUInt16((ushort)ExtensionType.SignatureAlgorithms);
        int extLen = TlsWriter.BeginVector(ref w, 2);
        {
            int listLen = TlsWriter.BeginVector(ref w, 2);
            foreach (SignatureScheme s in schemes)
                w.WriteUInt16((ushort)s);
            TlsWriter.EndVector(ref w, listLen, 2);
        }
        TlsWriter.EndVector(ref w, extLen, 2);
    }

    private static void WriteSupportedVersions(ref BufferWriter w)
    {
        w.WriteUInt16((ushort)ExtensionType.SupportedVersions);
        int extLen = TlsWriter.BeginVector(ref w, 2);
        {
            int listLen = TlsWriter.BeginVector(ref w, 1); // 1-Byte-Länge (ClientHello-Form)
            w.WriteUInt16(TlsVersions.Tls13);
            TlsWriter.EndVector(ref w, listLen, 1);
        }
        TlsWriter.EndVector(ref w, extLen, 2);
    }

    private static void WriteKeyShares(ref BufferWriter w, IReadOnlyList<KeyShareEntry> shares)
    {
        w.WriteUInt16((ushort)ExtensionType.KeyShare);
        int extLen = TlsWriter.BeginVector(ref w, 2);
        {
            int sharesLen = TlsWriter.BeginVector(ref w, 2); // client_shares
            foreach (KeyShareEntry entry in shares)
            {
                w.WriteUInt16((ushort)entry.Group);              // KeyShareEntry.group
                w.WriteUInt16((ushort)entry.PublicKey.Length);   // key_exchange<1..2^16-1>
                w.WriteBytes(entry.PublicKey.Span);
            }
            TlsWriter.EndVector(ref w, sharesLen, 2);
        }
        TlsWriter.EndVector(ref w, extLen, 2);
    }

    private static void WriteAlpn(ref BufferWriter w, IReadOnlyList<string> protocols)
    {
        w.WriteUInt16((ushort)ExtensionType.Alpn);
        int extLen = TlsWriter.BeginVector(ref w, 2);
        {
            int listLen = TlsWriter.BeginVector(ref w, 2); // ProtocolNameList
            foreach (string p in protocols)
            {
                byte[] name = Encoding.ASCII.GetBytes(p);
                w.WriteByte((byte)name.Length); // ProtocolName<1..2^8-1>
                w.WriteBytes(name);
            }
            TlsWriter.EndVector(ref w, listLen, 2);
        }
        TlsWriter.EndVector(ref w, extLen, 2);
    }
}
