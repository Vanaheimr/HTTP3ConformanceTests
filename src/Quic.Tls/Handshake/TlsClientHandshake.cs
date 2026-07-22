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
using System.Security.Cryptography.X509Certificates;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

/// <summary>
/// Treibt die Client-Seite des TLS-1.3-Handshakes für QUIC (RFC 8446 + RFC 9001). Bietet Key Shares für
/// mehrere Gruppen an (Standard: X25519 + P-256) und behandelt HelloRetryRequest (RFC 8446 §4.1.4).
/// Interface zur QUIC-Schicht wie gehabt (CRYPTO rein/raus, Schlüssel erscheinen als Properties).
/// <para>Prüft das Serverzertifikat: die CertificateVerify-Signatur immer, Kette/Hostname gemäß
/// <see cref="CertificateValidationOptions"/>; ebenso den Server-Finished-MAC.</para>
/// </summary>
public sealed class TlsClientHandshake : ITlsHandshake
{
    private enum State { New, WaitServerHello, WaitServerFinished, Complete }

    private readonly string _serverName;
    private readonly byte[] _quicTransportParameters;
    private readonly IReadOnlyList<NamedGroup> _keyShareGroups;
    private readonly IReadOnlyList<NamedGroup> _supportedGroups;
    private readonly IReadOnlyList<CipherSuite> _cipherSuites;
    private readonly CertificateValidationOptions _validation;
    private readonly Dictionary<NamedGroup, IKeyExchange> _keyExchanges = [];
    private readonly Queue<(EncryptionLevel Level, byte[] Data)> _outgoing = new();
    private readonly Dictionary<EncryptionLevel, List<byte>> _recvBuffers = new();

    private State _state = State.New;
    private byte[] _clientHello1 = [];
    private bool _hrrHandled;
    private KeySchedule? _ks;
    private Transcript? _transcript;
    private List<byte[]>? _serverCertChain;

    // Session Resumption (RFC 8446 §2.2): das angebotene Ticket, der daraus abgeleitete Binder-Key,
    // das resumption_master_secret dieser Verbindung und die vom Server empfangenen neuen Tickets.
    private readonly ResumptionTicket? _resumptionTicket;
    private byte[]? _binderKey;
    private bool _pskAccepted;
    private byte[]? _resumptionMasterSecret;
    private byte[]? _exporterMasterSecret; // exporter_master_secret (RFC 8446 §7.1) für §7.5-Exporte
    private readonly List<ResumptionTicket> _newSessionTickets = [];

    // 0-RTT (RFC 8446 §2.3): angebotenes/abgeleitetes Early-Traffic-Secret + ob der Server es akzeptierte.
    private bool _earlyDataOffered;
    private byte[]? _earlyTrafficSecret;

    public TlsClientHandshake(
        string serverName,
        byte[] quicTransportParameters,
        IReadOnlyList<NamedGroup>? keyShareGroups = null,
        IReadOnlyList<NamedGroup>? supportedGroups = null,
        CertificateValidationOptions? certificateValidation = null,
        IReadOnlyList<CipherSuite>? cipherSuites = null,
        ResumptionTicket? resumptionTicket = null)
    {
        _serverName = serverName;
        _quicTransportParameters = quicTransportParameters;
        _keyShareGroups = keyShareGroups ?? KeyExchange.DefaultGroups;
        _supportedGroups = supportedGroups ?? [NamedGroup.X25519, NamedGroup.Secp256r1, NamedGroup.Secp384r1];
        _cipherSuites = cipherSuites ?? [CipherSuite.Aes128GcmSha256, CipherSuite.Aes256GcmSha384];
        _validation = certificateValidation ?? CertificateValidationOptions.Default;
        _resumptionTicket = resumptionTicket;
    }

    /// <summary>
    /// <c>true</c>, wenn der Server unser PSK-Angebot akzeptiert hat (Handshake per Resumption statt Zertifikat).
    /// </summary>
    public bool ResumptionAccepted => _pskAccepted;

    /// <summary>
    /// Die vom Server nach dem Handshake ausgestellten Session-Tickets (RFC 8446 §4.6.1) für spätere Resumption.
    /// </summary>
    public IReadOnlyList<ResumptionTicket> NewSessionTickets => _newSessionTickets;

    /// <summary>
    /// Diagnose: Anzahl empfangener NewSessionTicket-Nachrichten (auch solche, die nicht als Ticket taugten).
    /// </summary>
    public int NewSessionTicketMessagesSeen { get; private set; }

    public byte[]? EarlyTrafficSecret => _earlyTrafficSecret;
    public CipherSuite? EarlyDataCipherSuite => _earlyDataOffered ? _resumptionTicket?.CipherSuite : null;
    public bool EarlyDataAccepted { get; private set; }

    public CipherSuite? NegotiatedCipherSuite { get; private set; }
    public HandshakeTrafficSecrets? HandshakeSecrets { get; private set; }
    public ApplicationTrafficSecrets? ApplicationSecrets { get; private set; }

    /// <summary>
    /// TLS-Keying-Material-Exporter (RFC 8446 §7.5) auf Basis des <c>exporter_master_secret</c>;
    /// verfügbar, sobald die Application Secrets abgeleitet sind (nach dem Server-Finished).
    /// </summary>
    public byte[] ExportKeyingMaterial(string label, ReadOnlySpan<byte> context, int length)
        => _exporterMasterSecret is { } secret && _ks is { } ks
            ? ks.ExportKeyingMaterial(secret, label, context, length)
            : throw new InvalidOperationException("Keying-Material-Export erst nach dem Server-Finished möglich (RFC 8446 §7.5).");
    public bool ServerFinishedValid { get; private set; }
    public bool IsComplete => _state == State.Complete;
    public byte[]? PeerQuicTransportParameters { get; private set; }

    /// <summary>
    /// Das geprüfte Leaf-Zertifikat des Servers (erst nach CertificateVerify verfügbar).
    /// </summary>
    public X509Certificate2? ServerCertificate { get; private set; }

    /// <summary>
    /// <c>true</c>, sobald das Serverzertifikat samt CertificateVerify-Signatur geprüft wurde.
    /// </summary>
    public bool ServerCertificateValid { get; private set; }

    /// <summary>
    /// Die Gruppe, mit der der Handshake letztlich abgeschlossen wurde (nach evtl. HRR).
    /// </summary>
    public NamedGroup? NegotiatedGroup { get; private set; }

    /// <summary>
    /// Startet den Handshake: erzeugt Key Shares und baut den (ersten) ClientHello.
    /// </summary>
    public void Start()
    {
        foreach (NamedGroup group in _keyShareGroups)
            _keyExchanges[group] = KeyExchange.Create(group);

        // Resumption: Key-Schedule (an die Ticket-Suite gebunden) und Binder-Key vorbereiten, damit der
        // ClientHello den PSK-Binder tragen kann.
        if (_resumptionTicket is { } ticket)
        {
            _ks = new KeySchedule(ticket.CipherSuite);
            _binderKey = _ks.ResumptionBinderKey(ticket.Psk);
            _earlyDataOffered = ticket.AllowsEarlyData; // erlaubt das Ticket 0-RTT, bieten wir es an
        }

        _clientHello1 = BuildClientHello(_keyShareGroups);
        _outgoing.Enqueue((EncryptionLevel.Initial, _clientHello1));

        // 0-RTT: Early-Traffic-Secret über den Hash des (vollständigen) ClientHello ableiten – daraus
        // installiert die QUIC-Schicht die 0-RTT-Schreibschlüssel, um sofort Anwendungsdaten zu senden.
        if (_earlyDataOffered && _resumptionTicket is { } t && _ks is not null)
            _earlyTrafficSecret = _ks.ClientEarlyTrafficSecret(t.Psk, _ks.TranscriptHash(_clientHello1));

        _state = State.WaitServerHello;
    }

    /// <summary>
    /// Sendet nach einem QUIC-Retry denselben ClientHello erneut (unveränderter Inhalt, RFC 9000 §17.2.5).
    /// Der Transkript-Hash beginnt weiterhin erst beim ServerHello, daher ist kein Neuaufbau nötig.
    /// </summary>
    public void ResendClientHello()
    {
        if (_clientHello1.Length > 0)
            _outgoing.Enqueue((EncryptionLevel.Initial, _clientHello1));
    }

    public bool TryGetOutgoingCrypto(out EncryptionLevel level, out byte[] data)
    {
        if (_outgoing.Count > 0)
        {
            (level, data) = _outgoing.Dequeue();
            return true;
        }
        level = default;
        data = [];
        return false;
    }

    public void ProvideCrypto(EncryptionLevel level, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return;
        if (!_recvBuffers.TryGetValue(level, out List<byte>? buffer))
            _recvBuffers[level] = buffer = [];
        buffer.AddRange(data);

        if (!HandshakeMessages.TryReadAll(buffer.ToArray(), out List<HandshakeMessage> messages, out int consumed))
            return;
        foreach (HandshakeMessage message in messages)
            ProcessMessage(message);
        buffer.RemoveRange(0, consumed);
    }

    private void ProcessMessage(HandshakeMessage message)
    {
        switch (message.Type)
        {
            case HandshakeType.ServerHello when _state == State.WaitServerHello:
                ProcessServerHello(message);
                break;
            case HandshakeType.Finished when _state == State.WaitServerFinished:
                VerifyServerFinished(message);
                _transcript!.Append(message.Full.Span);
                GenerateClientFinishedAndAppKeys();
                break;
            case HandshakeType.EncryptedExtensions:
                ExtractTransportParameters(message.Body.Span);
                _transcript?.Append(message.Full.Span);
                break;
            case HandshakeType.Certificate:
                ProcessCertificate(message);
                break;
            case HandshakeType.CertificateVerify:
                ProcessCertificateVerify(message);
                break;
            case HandshakeType.NewSessionTicket:
                // Post-Handshake-Nachricht: NICHT an den Handshake-Transcript anhängen.
                NewSessionTicketMessagesSeen++;
                ProcessNewSessionTicket(message);
                break;
            default:
                _transcript?.Append(message.Full.Span);
                break;
        }
    }

    private void ProcessCertificate(HandshakeMessage message)
    {
        if (!CertificateMessage.TryParse(message.Body.Span, out List<byte[]> chain))
            throw new InvalidOperationException("Ungültige Certificate-Nachricht.");
        _serverCertChain = chain;
        _transcript?.Append(message.Full.Span);
    }

    private void ProcessCertificateVerify(HandshakeMessage message)
    {
        if (_serverCertChain is null)
            throw new InvalidOperationException("CertificateVerify ohne vorangehendes Certificate.");
        if (!CertificateVerify.TryParse(message.Body.Span, out SignatureScheme scheme, out byte[] signature))
            throw new InvalidOperationException("Ungültige CertificateVerify-Nachricht.");

        // Der signierte Transcript-Hash reicht bis einschließlich Certificate – also VOR dem Anhängen dieser Nachricht.
        byte[] transcriptHash = _transcript!.CurrentHash();
        ServerCertificate = ServerCertificateValidator.Validate(
            _serverCertChain, scheme, signature, transcriptHash, _serverName, _validation);
        ServerCertificateValid = true;

        _transcript.Append(message.Full.Span);
    }

    private void ProcessServerHello(HandshakeMessage message)
    {
        if (!ServerHello.TryParse(message.Full.Span, out ServerHelloInfo? sh) || sh is null)
            throw new InvalidOperationException("Ungültiger ServerHello.");

        NegotiatedCipherSuite = sh.CipherSuite;

        if (sh.IsHelloRetryRequest)
        {
            HandleHelloRetryRequest(message, sh);
            return;
        }

        if (sh.KeyShareGroup is not { } group || sh.KeySharePublicKey is null)
            throw new InvalidOperationException("ServerHello ohne Key Share.");
        if (!_keyExchanges.TryGetValue(group, out IKeyExchange? kex))
            throw new InvalidOperationException($"Server wählte nicht angebotene Gruppe {group}.");

        // Hat der Server unser PSK-Angebot akzeptiert? Dann läuft der Handshake per Resumption (kein Zertifikat).
        _pskAccepted = _resumptionTicket is not null && sh.SelectedPskIdentity == 0;

        // Transcript beim ersten (nicht durch HRR ausgelösten) ServerHello anlegen. Bei Resumption ist _ks
        // bereits mit der Ticket-Suite angelegt (für den Binder) und wird beibehalten.
        if (_transcript is null)
        {
            _ks ??= new KeySchedule(sh.CipherSuite);
            _transcript = new Transcript(_ks.Hash);
            _transcript.Append(_clientHello1);
        }
        _transcript.Append(message.Full.Span);

        NegotiatedGroup = group;
        byte[] shared = kex.DeriveSharedSecret(sh.KeySharePublicKey);
        // Bei akzeptierter Resumption fließt die PSK ins Early Secret ein (RFC 8446 §7.1).
        ReadOnlySpan<byte> psk = _pskAccepted ? _resumptionTicket!.Psk : default;
        HandshakeSecrets = _ks!.DeriveHandshakeSecrets(shared, _transcript.CurrentHash(), psk);
        _state = State.WaitServerFinished;
    }

    private void HandleHelloRetryRequest(HandshakeMessage hrr, ServerHelloInfo sh)
    {
        if (_hrrHandled)
            throw new InvalidOperationException("Zweiter HelloRetryRequest ist unzulässig.");
        _hrrHandled = true;

        if (sh.KeyShareGroup is not { } group)
            throw new InvalidOperationException("HRR ohne angeforderte Gruppe.");
        if (!_supportedGroups.Contains(group) || !KeyExchange.IsSupported(group))
            throw new InvalidOperationException($"HRR fordert nicht unterstützte Gruppe {group}.");

        _ks = new KeySchedule(sh.CipherSuite);
        _transcript = new Transcript(_ks.Hash);

        // RFC 8446 §4.4.1: ClientHello1 wird durch die synthetische message_hash-Nachricht ersetzt.
        _transcript.Append(SyntheticMessageHash(_ks.TranscriptHash(_clientHello1), _ks.HashLength));
        _transcript.Append(hrr.Full.Span);

        if (!_keyExchanges.ContainsKey(group))
            _keyExchanges[group] = KeyExchange.Create(group);

        byte[] clientHello2 = BuildClientHello([group]);
        _transcript.Append(clientHello2);
        _outgoing.Enqueue((EncryptionLevel.Initial, clientHello2));
        _state = State.WaitServerHello;
    }

    private byte[] BuildClientHello(IReadOnlyList<NamedGroup> keyShareGroups)
    {
        var shares = new List<KeyShareEntry>(keyShareGroups.Count);
        foreach (NamedGroup group in keyShareGroups)
            shares.Add(new KeyShareEntry(group, _keyExchanges[group].PublicKey));

        PskIdentity? pskIdentity = null;
        int binderLength = 0;
        Func<ReadOnlyMemory<byte>, byte[]>? computeBinder = null;
        if (_resumptionTicket is { } ticket && _ks is { } ks && _binderKey is { } binderKey)
        {
            pskIdentity = new PskIdentity(ticket.Identity, ticket.ObfuscatedTicketAge(DateTimeOffset.UtcNow));
            binderLength = ks.HashLength;
            // Binder = HMAC(finished_key(binder_key), Transcript-Hash(abgeschnittener ClientHello)).
            computeBinder = truncated => ks.FinishedVerifyData(binderKey, ks.TranscriptHash(truncated.Span));
        }

        return ClientHello.Build(new ClientHelloOptions
        {
            ServerName = _serverName,
            CipherSuites = _cipherSuites,
            SupportedGroups = _supportedGroups,
            KeyShares = shares,
            QuicTransportParameters = _quicTransportParameters,
            PskIdentity = pskIdentity,
            PskBinderLength = binderLength,
            ComputeBinder = computeBinder,
            OfferEarlyData = _earlyDataOffered,
        });
    }

    /// <summary>
    /// Die synthetische message_hash-Nachricht (RFC 8446 §4.4.1): Typ 0xFE ‖ 3-Byte-Länge ‖ Hash.
    /// </summary>
    private static byte[] SyntheticMessageHash(byte[] hash, int hashLength)
    {
        byte[] message = new byte[4 + hashLength];
        message[0] = 0xFE; // message_hash
        message[3] = (byte)hashLength;
        hash.CopyTo(message, 4);
        return message;
    }

    private void ExtractTransportParameters(ReadOnlySpan<byte> encryptedExtensionsBody)
    {
        var reader = new BufferReader(encryptedExtensionsBody);
        if (!reader.TryReadUInt16(out ushort extensionsLength) || extensionsLength > reader.Remaining)
            return;
        while (reader.Remaining >= 4)
        {
            if (!reader.TryReadUInt16(out ushort type) ||
                !reader.TryReadUInt16(out ushort length) ||
                !reader.TryReadBytes(length, out ReadOnlySpan<byte> data))
                return;
            if (type == (ushort)ExtensionType.QuicTransportParameters)
                PeerQuicTransportParameters = data.ToArray();
            else if (type == (ushort)ExtensionType.EarlyData)
                EarlyDataAccepted = true; // Server bestätigt 0-RTT (RFC 8446 §4.2.10)
        }
    }

    private void VerifyServerFinished(HandshakeMessage finished)
    {
        byte[] expected = _ks!.FinishedVerifyData(HandshakeSecrets!.ServerHandshakeTrafficSecret, _transcript!.CurrentHash());
        ServerFinishedValid = CryptographicOperations.FixedTimeEquals(expected, finished.Body.Span);
    }

    private void GenerateClientFinishedAndAppKeys()
    {
        byte[] transcriptThroughServerFinished = _transcript!.CurrentHash();
        ApplicationSecrets = _ks!.DeriveApplicationSecrets(HandshakeSecrets!.HandshakeSecret, transcriptThroughServerFinished);
        // exporter_master_secret (RFC 8446 §7.1) über CH…server-Finished — für §7.5-Keying-Material-Exporte.
        _exporterMasterSecret = _ks.ExporterMasterSecret(ApplicationSecrets.MasterSecret, transcriptThroughServerFinished);

        byte[] verifyData = _ks.FinishedVerifyData(HandshakeSecrets.ClientHandshakeTrafficSecret, transcriptThroughServerFinished);
        byte[] clientFinished = Finished.BuildMessage(verifyData);
        _outgoing.Enqueue((EncryptionLevel.Handshake, clientFinished));
        _transcript.Append(clientFinished);

        // resumption_master_secret (RFC 8446 §7.1) über CH…client-Finished – Grundlage der später
        // per NewSessionTicket ausgestellten Resumption-PSKs.
        _resumptionMasterSecret = _ks.ResumptionMasterSecret(
            ApplicationSecrets.MasterSecret, _transcript.CurrentHash());
        _state = State.Complete;
    }

    private void ProcessNewSessionTicket(HandshakeMessage message)
    {
        if (_resumptionMasterSecret is null || _ks is null || NegotiatedCipherSuite is not { } suite)
            return; // vor Handshake-Abschluss ungültig
        if (!Messages.NewSessionTicket.TryParse(message.Body.Span, out NewSessionTicketInfo? info) || info is null)
            return;

        byte[] psk = _ks.ResumptionPsk(_resumptionMasterSecret, info.Nonce);
        _newSessionTickets.Add(new ResumptionTicket(
            psk, info.Ticket, info.AgeAdd, suite, _serverName,
            info.LifetimeSeconds, info.MaxEarlyDataSize, PeerQuicTransportParameters ?? []));
    }

    public void Dispose()
    {
        foreach (IKeyExchange kex in _keyExchanges.Values)
            kex.Dispose();
        _transcript?.Dispose();
        ServerCertificate?.Dispose();
    }
}
