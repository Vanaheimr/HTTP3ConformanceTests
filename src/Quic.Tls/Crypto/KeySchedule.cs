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
/// Die aus dem Handshake-Secret abgeleiteten Traffic Secrets (RFC 8446 §7.1).
/// </summary>
public sealed record HandshakeTrafficSecrets(
    byte[] HandshakeSecret,
    byte[] ClientHandshakeTrafficSecret,
    byte[] ServerHandshakeTrafficSecret);

/// <summary>
/// Die aus dem Master-Secret abgeleiteten Application Traffic Secrets (1-RTT).
/// </summary>
public sealed record ApplicationTrafficSecrets(
    byte[] MasterSecret,
    byte[] ClientApplicationTrafficSecret,
    byte[] ServerApplicationTrafficSecret);

/// <summary>
/// Der TLS-1.3-Key-Schedule (RFC 8446 §7.1). Kette:
/// <code>
///   Early Secret ─(Derive "derived")→ ─Extract(ECDHE)→ Handshake Secret ─(Derive "* hs traffic")
///   Handshake Secret ─(Derive "derived")→ ─Extract(0)→ Master Secret ─(Derive "* ap traffic")
/// </code>
/// Alle Ableitungen laufen über <c>HKDF-Expand-Label</c> (siehe <see cref="TlsHkdf"/>).
/// QUIC nutzt dieselben Traffic Secrets, ersetzt aber die Key/IV-Labels durch "quic key"/"quic iv"
/// (das erledigt <c>TrafficKeys.FromSecret</c> in der QUIC-Schicht).
/// </summary>
public sealed class KeySchedule
{
    private readonly HashAlgorithmName _hash;
    private readonly byte[] _emptyTranscriptHash;

    /// <summary>
    /// Länge des Hash-Ausgangs (32 für SHA-256, 48 für SHA-384) – zugleich Secret-Länge.
    /// </summary>
    public int HashLength { get; }

    /// <summary>
    /// AEAD-Schlüssellänge der Suite (16 für AES-128/ChaCha20, 32 für AES-256).
    /// </summary>
    public int AeadKeyLength { get; }

    public HashAlgorithmName Hash => _hash;

    public KeySchedule(CipherSuite suite)
    {
        (_hash, int hashLen, int aeadKeyLen) = suite switch
        {
            CipherSuite.Aes128GcmSha256 => (HashAlgorithmName.SHA256, 32, 16),
            CipherSuite.ChaCha20Poly1305Sha256 => (HashAlgorithmName.SHA256, 32, 32),
            CipherSuite.Aes256GcmSha384 => (HashAlgorithmName.SHA384, 48, 32),
            _ => throw new NotSupportedException($"Cipher Suite {suite} wird nicht unterstützt."),
        };
        HashLength = hashLen;
        AeadKeyLength = aeadKeyLen;
        _emptyTranscriptHash = HashBytes(ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    /// Transcript-Hash über die (konkatenierten) Handshake-Nachrichten.
    /// </summary>
    public byte[] TranscriptHash(ReadOnlySpan<byte> handshakeMessages) => HashBytes(handshakeMessages);

    /// <summary>
    /// <c>Derive-Secret(Secret, Label, Messages)</c>
    /// = <c>HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)</c>.
    /// </summary>
    public byte[] DeriveSecret(ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> transcriptHash)
        => TlsHkdf.ExpandLabel(_hash, secret, label, transcriptHash, HashLength);

    /// <summary>
    /// Early Secret = HKDF-Extract(salt = 0, IKM = PSK). Ohne PSK ist die IKM eine Null-Folge.
    /// </summary>
    public byte[] EarlySecret(ReadOnlySpan<byte> psk = default)
    {
        byte[] ikm = psk.IsEmpty ? new byte[HashLength] : psk.ToArray();
        byte[] salt = new byte[HashLength];
        return TlsHkdf.Extract(_hash, salt, ikm);
    }

    /// <summary>
    /// Handshake Secret = HKDF-Extract(salt = Derive-Secret(Early,"derived",""), IKM = (EC)DHE).
    /// </summary>
    public byte[] HandshakeSecret(ReadOnlySpan<byte> earlySecret, ReadOnlySpan<byte> sharedSecret)
    {
        byte[] salt = DeriveSecret(earlySecret, "derived", _emptyTranscriptHash);
        return TlsHkdf.Extract(_hash, salt, sharedSecret);
    }

    /// <summary>
    /// Master Secret = HKDF-Extract(salt = Derive-Secret(Handshake,"derived",""), IKM = 0).
    /// </summary>
    public byte[] MasterSecret(ReadOnlySpan<byte> handshakeSecret)
    {
        byte[] salt = DeriveSecret(handshakeSecret, "derived", _emptyTranscriptHash);
        return TlsHkdf.Extract(_hash, salt, new byte[HashLength]);
    }

    /// <summary>
    /// Bequemer Einstieg: leitet aus dem ECDHE-Geheimnis und dem Transcript-Hash über
    /// ClientHello‖ServerHello die Handshake Traffic Secrets ab. Bei Resumption fließt der
    /// <paramref name="psk"/> in das Early Secret ein (RFC 8446 §7.1); ohne PSK (Standard) ist es 0.
    /// </summary>
    public HandshakeTrafficSecrets DeriveHandshakeSecrets(
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> transcriptHashClientHelloToServerHello,
        ReadOnlySpan<byte> psk = default)
    {
        byte[] early = EarlySecret(psk);
        byte[] handshake = HandshakeSecret(early, sharedSecret);
        byte[] client = DeriveSecret(handshake, "c hs traffic", transcriptHashClientHelloToServerHello);
        byte[] server = DeriveSecret(handshake, "s hs traffic", transcriptHashClientHelloToServerHello);
        return new HandshakeTrafficSecrets(handshake, client, server);
    }

    /// <summary>
    /// Der <c>binder_key</c> für eine Resumption-PSK (RFC 8446 §7.1): <c>Derive-Secret(Early Secret,
    /// "res binder", "")</c>. Der PSK-Binder ist dann die <see cref="FinishedVerifyData"/> über den
    /// Transcript-Hash des (bis vor die Binder) abgeschnittenen ClientHello.
    /// </summary>
    public byte[] ResumptionBinderKey(ReadOnlySpan<byte> psk)
        => DeriveSecret(EarlySecret(psk), "res binder", _emptyTranscriptHash);

    /// <summary>
    /// Das <c>resumption_master_secret</c> (RFC 8446 §7.1): <c>Derive-Secret(Master Secret, "res master",
    /// ClientHello…client Finished)</c>. Grundlage der später ausgegebenen Resumption-PSKs.
    /// </summary>
    public byte[] ResumptionMasterSecret(
        ReadOnlySpan<byte> masterSecret, ReadOnlySpan<byte> transcriptHashThroughClientFinished)
        => DeriveSecret(masterSecret, "res master", transcriptHashThroughClientFinished);

    /// <summary>
    /// Die aus einem NewSessionTicket resultierende Resumption-PSK (RFC 8446 §4.6.1):
    /// <c>HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)</c>.
    /// </summary>
    public byte[] ResumptionPsk(ReadOnlySpan<byte> resumptionMasterSecret, ReadOnlySpan<byte> ticketNonce)
        => TlsHkdf.ExpandLabel(_hash, resumptionMasterSecret, "resumption", ticketNonce, HashLength);

    /// <summary>
    /// Das <c>client_early_traffic_secret</c> (RFC 8446 §7.1) für 0-RTT: <c>Derive-Secret(Early Secret(psk),
    /// "c e traffic", ClientHello)</c>. Aus ihm leitet die QUIC-Schicht die 0-RTT-Schlüssel ab (nur Client→Server).
    /// </summary>
    public byte[] ClientEarlyTrafficSecret(ReadOnlySpan<byte> psk, ReadOnlySpan<byte> transcriptHashClientHello)
        => DeriveSecret(EarlySecret(psk), "c e traffic", transcriptHashClientHello);

    /// <summary>
    /// Leitet aus dem Handshake Secret und dem Transcript-Hash bis einschließlich Server-Finished
    /// die Application (1-RTT) Traffic Secrets ab.
    /// </summary>
    public ApplicationTrafficSecrets DeriveApplicationSecrets(
        ReadOnlySpan<byte> handshakeSecret,
        ReadOnlySpan<byte> transcriptHashThroughServerFinished)
    {
        byte[] master = MasterSecret(handshakeSecret);
        byte[] client = DeriveSecret(master, "c ap traffic", transcriptHashThroughServerFinished);
        byte[] server = DeriveSecret(master, "s ap traffic", transcriptHashThroughServerFinished);
        return new ApplicationTrafficSecrets(master, client, server);
    }

    /// <summary>
    /// Das <c>exporter_master_secret</c> (RFC 8446 §7.1): <c>Derive-Secret(Master Secret, "exp master",
    /// ClientHello…server Finished)</c>. Grundlage aller Keying-Material-Exporte (§7.5).
    /// </summary>
    public byte[] ExporterMasterSecret(
        ReadOnlySpan<byte> masterSecret, ReadOnlySpan<byte> transcriptHashThroughServerFinished)
        => DeriveSecret(masterSecret, "exp master", transcriptHashThroughServerFinished);

    /// <summary>
    /// Der TLS-Exporter (RFC 8446 §7.5): <c>HKDF-Expand-Label(Derive-Secret(exporter_master_secret,
    /// label, ""), "exporter", Hash(context), length)</c>. Beide Seiten der Verbindung erhalten für
    /// gleiches Label/gleichen Kontext identisches Schlüsselmaterial (z. B. für Channel Binding).
    /// </summary>
    public byte[] ExportKeyingMaterial(
        ReadOnlySpan<byte> exporterMasterSecret, string label, ReadOnlySpan<byte> context, int length)
    {
        byte[] derived = DeriveSecret(exporterMasterSecret, label, _emptyTranscriptHash);
        return TlsHkdf.ExpandLabel(_hash, derived, "exporter", HashBytes(context), length);
    }

    /// <summary>
    /// Der <c>finished_key</c> eines Traffic Secrets: <c>HKDF-Expand-Label(secret, "finished", "", Hash.length)</c>
    /// (RFC 8446 §4.4.4). Kontext ist leer.
    /// </summary>
    public byte[] FinishedKey(ReadOnlySpan<byte> baseTrafficSecret)
        => TlsHkdf.ExpandLabel(_hash, baseTrafficSecret, "finished", HashLength);

    /// <summary>
    /// Die <c>verify_data</c> einer Finished-Nachricht: <c>HMAC(finished_key, Transcript-Hash)</c>
    /// (RFC 8446 §4.4.4). Für den Server-Finished ist der Transcript CH..CertificateVerify, für den
    /// Client-Finished CH..server-Finished.
    /// </summary>
    public byte[] FinishedVerifyData(ReadOnlySpan<byte> baseTrafficSecret, ReadOnlySpan<byte> transcriptHash)
    {
        byte[] key = FinishedKey(baseTrafficSecret);
        return _hash == HashAlgorithmName.SHA384
            ? HMACSHA384.HashData(key, transcriptHash)
            : HMACSHA256.HashData(key, transcriptHash);
    }

    private byte[] HashBytes(ReadOnlySpan<byte> data)
    {
        byte[] output = new byte[HashLength];
        if (_hash == HashAlgorithmName.SHA256)
            SHA256.HashData(data, output);
        else
            SHA384.HashData(data, output);
        return output;
    }
}
