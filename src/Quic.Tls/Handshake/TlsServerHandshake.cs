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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

/// <summary>
/// Die Server-Seite des TLS-1.3-Handshakes für QUIC (RFC 8446 + RFC 9001). Wählt eine Gruppe aus den
/// Key Shares des Clients (Standardpräferenz X25519, dann P-256) und sendet einen HelloRetryRequest,
/// falls der Client keine passende Key Share, aber eine passende supported_group anbietet. Erzeugt
/// ServerHello → EncryptedExtensions → Certificate → CertificateVerify (signiert) → Finished und prüft
/// den Client-Finished.
/// </summary>
public sealed class TlsServerHandshake : ITlsHandshake
{
    private enum State { New, WaitClientHello2, WaitClientFinished, Complete }

    private readonly ServerCertificate _certificate;
    private readonly byte[] _quicTransportParameters;
    private readonly IReadOnlyList<NamedGroup> _preferredGroups;
    private readonly Queue<(EncryptionLevel Level, byte[] Data)> _outgoing = new();
    private readonly Dictionary<EncryptionLevel, List<byte>> _recvBuffers = new();

    private State _state = State.New;
    private KeySchedule? _ks;
    private Transcript? _transcript;
    private byte[] _clientHello1 = [];
    private NamedGroup _requestedGroup;
    private byte[] _transcriptThroughServerFinished = [];

    private readonly IReadOnlyList<CipherSuite> _preferredCipherSuites;
    private CipherSuite _cipherSuite = CipherSuite.Aes128GcmSha256;

    // Session Resumption (RFC 8446 §2.2): optionaler Ticket-Store. Ist er gesetzt, akzeptiert der Server
    // gültige PSK-Angebote und stellt nach dem Handshake neue Tickets aus.
    private readonly ServerResumptionCache? _resumptionCache;
    private readonly uint _ticketLifetimeSeconds;
    private readonly uint _maxEarlyDataSize;
    private bool _pskAccepted;
    private byte[] _selectedPsk = [];
    private bool _newTicketIssued;

    // 0-RTT (RFC 8446 §2.3): akzeptiertes early_data + das zum Lesen der 0-RTT-Pakete nötige Early-Secret.
    private byte[]? _earlyTrafficSecret;

    public TlsServerHandshake(
        ServerCertificate certificate,
        byte[] quicTransportParameters,
        IReadOnlyList<NamedGroup>? preferredGroups = null,
        IReadOnlyList<CipherSuite>? preferredCipherSuites = null,
        ServerResumptionCache? resumptionCache = null,
        uint ticketLifetimeSeconds = 7200,
        uint maxEarlyDataSize = 0)
    {
        _certificate = certificate;
        _quicTransportParameters = quicTransportParameters;
        _preferredGroups = preferredGroups ?? [NamedGroup.X25519, NamedGroup.Secp256r1];
        // Präferenz: AES-128, dann ChaCha20, dann AES-256; der Server akzeptiert alle drei.
        _preferredCipherSuites = preferredCipherSuites ??
            [CipherSuite.Aes128GcmSha256, CipherSuite.ChaCha20Poly1305Sha256, CipherSuite.Aes256GcmSha384];
        _resumptionCache = resumptionCache;
        _ticketLifetimeSeconds = ticketLifetimeSeconds;
        _maxEarlyDataSize = maxEarlyDataSize;
    }

    /// <summary>
    /// <c>true</c>, wenn ein PSK-Angebot des Clients akzeptiert und der Handshake per Resumption geführt wurde.
    /// </summary>
    public bool ResumptionAccepted => _pskAccepted;

    public byte[]? EarlyTrafficSecret => _earlyTrafficSecret;
    public CipherSuite? EarlyDataCipherSuite => _earlyTrafficSecret is not null ? _cipherSuite : null;
    public bool EarlyDataAccepted { get; private set; }

    public CipherSuite? NegotiatedCipherSuite { get; private set; }
    public HandshakeTrafficSecrets? HandshakeSecrets { get; private set; }
    public ApplicationTrafficSecrets? ApplicationSecrets { get; private set; }
    public byte[]? PeerQuicTransportParameters { get; private set; }
    public bool ClientFinishedValid { get; private set; }
    public bool IsComplete => _state == State.Complete;

    /// <summary>
    /// Ob ein HelloRetryRequest gesendet wurde (Diagnose/Test).
    /// </summary>
    public bool SentHelloRetryRequest { get; private set; }

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
            case HandshakeType.ClientHello when _state == State.New:
                ProcessClientHello(message, isSecond: false);
                break;
            case HandshakeType.ClientHello when _state == State.WaitClientHello2:
                ProcessClientHello(message, isSecond: true);
                break;
            case HandshakeType.Finished when _state == State.WaitClientFinished:
                VerifyClientFinished(message);
                _transcript!.Append(message.Full.Span); // bis client Finished – Grundlage für res_master
                _state = State.Complete;
                if (ClientFinishedValid)
                    IssueNewSessionTicket();
                break;
        }
    }

    /// <summary>
    /// Stellt nach dem Handshake ein NewSessionTicket aus (RFC 8446 §4.6.1), sofern ein Ticket-Store gesetzt
    /// ist: leitet das resumption_master_secret ab, wählt Nonce + PSK, hinterlegt sie unter einer neuen
    /// Identity im Store und reiht die Nachricht auf Application-Level ein (post-Handshake, 1-RTT).
    /// </summary>
    private void IssueNewSessionTicket()
    {
        if (_newTicketIssued || _resumptionCache is null || ApplicationSecrets is null || _ks is null)
            return;
        _newTicketIssued = true;

        byte[] resMaster = _ks.ResumptionMasterSecret(ApplicationSecrets.MasterSecret, _transcript!.CurrentHash());
        byte[] nonce = RandomNumberGenerator.GetBytes(8);
        byte[] psk = _ks.ResumptionPsk(resMaster, nonce);
        byte[] identity = _resumptionCache.Issue(psk, _cipherSuite, _maxEarlyDataSize, _quicTransportParameters);
        uint ageAdd = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));

        byte[] ticket = Messages.NewSessionTicket.Build(
            _ticketLifetimeSeconds, ageAdd, nonce, identity, _maxEarlyDataSize);
        _outgoing.Enqueue((EncryptionLevel.Application, ticket));
    }

    private void ProcessClientHello(HandshakeMessage message, bool isSecond)
    {
        if (!ClientHelloParser.TryParse(message.Full.Span, out ClientHelloInfo? ch) || ch is null)
            throw new InvalidOperationException("Ungültiger ClientHello.");

        // Cipher Suite aushandeln: erste bevorzugte, die der Client anbietet (nur beim ersten ClientHello).
        if (!isSecond)
        {
            if (!TrySelectCipherSuite(ch, out _cipherSuite))
                throw new InvalidOperationException("Keine gemeinsame Cipher Suite (handshake_failure).");
            NegotiatedCipherSuite = _cipherSuite;
        }

        PeerQuicTransportParameters = ch.QuicTransportParameters;

        if (isSecond)
        {
            // Zweiter ClientHello nach HRV: Transcript hat bereits synthetic+HRR; jetzt CH2 anhängen.
            if (!ch.KeyShares.TryGetValue((ushort)_requestedGroup, out byte[]? clientKeyShare2))
                throw new InvalidOperationException("ClientHello2 enthält nicht die angeforderte Gruppe.");
            _transcript!.Append(message.Full.Span);
            EmitServerFlight(_requestedGroup, clientKeyShare2);
            return;
        }

        _clientHello1 = message.Full.ToArray();

        // 1) Gibt es eine bevorzugte Gruppe, für die der Client bereits eine Key Share sendet?
        if (TrySelectGroupWithKeyShare(ch, out NamedGroup group, out byte[]? clientKeyShare))
        {
            _ks = new KeySchedule(_cipherSuite);
            _transcript = new Transcript(_ks.Hash);
            _transcript.Append(_clientHello1);
            TryAcceptResumption(ch);
            EmitServerFlight(group, clientKeyShare!);
            return;
        }

        // 2) Sonst: eine bevorzugte Gruppe, die der Client in supported_groups listet → HelloRetryRequest.
        if (TrySelectGroupForHrr(ch, out NamedGroup hrrGroup))
        {
            SendHelloRetryRequest(hrrGroup);
            return;
        }

        throw new InvalidOperationException("Keine gemeinsame Named Group (handshake_failure).");
    }

    private void SendHelloRetryRequest(NamedGroup group)
    {
        _requestedGroup = group;
        _ks = new KeySchedule(_cipherSuite);
        _transcript = new Transcript(_ks.Hash);

        // RFC 8446 §4.4.1: ClientHello1 → synthetische message_hash-Nachricht.
        _transcript.Append(SyntheticMessageHash(_ks.TranscriptHash(_clientHello1), _ks.HashLength));

        byte[] hrr = ServerHello.BuildHelloRetryRequest(_cipherSuite, group);
        _transcript.Append(hrr);
        _outgoing.Enqueue((EncryptionLevel.Initial, hrr));
        SentHelloRetryRequest = true;
        _state = State.WaitClientHello2;
    }

    /// <summary>
    /// Prüft ein PSK-Angebot des Clients (RFC 8446 §4.2.11): löst die Ticket-Identity im Store auf und
    /// verifiziert den Binder über den abgeschnittenen ClientHello. Bei Erfolg wird die Resumption akzeptiert.
    /// Voraussetzung: _ks und _transcript sind angelegt und der ClientHello ist angehängt.
    /// </summary>
    private void TryAcceptResumption(ClientHelloInfo ch)
    {
        if (_resumptionCache is null || !ch.OffersPskDheKe || ch.OfferedPsks.Count == 0 || ch.PskBinderListOffset < 0)
            return;

        OfferedPsk offer = ch.OfferedPsks[0];
        if (!_resumptionCache.TryResolve(offer.Identity, out byte[] psk, out _))
            return;

        // Binder = HMAC(finished_key(binder_key), Transcript-Hash(ClientHello bis vor die Binder-Liste)).
        // Ein Hash-Mismatch (falsche Suite) scheitert hier automatisch an der Längendifferenz.
        byte[] binderKey = _ks!.ResumptionBinderKey(psk);
        byte[] truncatedHash = _ks.TranscriptHash(_clientHello1.AsSpan(0, ch.PskBinderListOffset));
        byte[] expected = _ks.FinishedVerifyData(binderKey, truncatedHash);
        if (!CryptographicOperations.FixedTimeEquals(expected, offer.Binder))
            return;

        _pskAccepted = true;
        _selectedPsk = psk;

        // 0-RTT annehmen, wenn der Client early_data anbietet und wir es zulassen (max_early_data_size > 0).
        // Das Early-Secret (client_early_traffic_secret) leitet die QUIC-Schicht zum LESEN der 0-RTT-Pakete ab.
        if (ch.OffersEarlyData && _maxEarlyDataSize > 0)
        {
            EarlyDataAccepted = true;
            _earlyTrafficSecret = _ks.ClientEarlyTrafficSecret(psk, _ks.TranscriptHash(_clientHello1));
        }
    }

    /// <summary>
    /// Erzeugt den Server-Flight (ServerHello + Handshake-Nachrichten). Transcript reicht bis vor ServerHello.
    /// </summary>
    private void EmitServerFlight(NamedGroup group, byte[] clientKeyShare)
    {
        using IKeyExchange kex = KeyExchange.Create(group);
        // Server-Seite: aus dem Client-Share Antwort + Geheimnis erzeugen. Bei (EC)DHE ist die Antwort der
        // eigene Public Key; beim KEM-Hybrid (X25519MLKEM768) der Ciphertext — daher hängt sie vom Client-Share
        // ab und muss VOR dem ServerHello berechnet werden.
        (byte[] responseShare, byte[] shared) = kex.Encapsulate(clientKeyShare);

        // Bei akzeptierter Resumption: selected_identity im ServerHello, PSK ins Early Secret, KEIN Zertifikat.
        ushort? selectedIdentity = _pskAccepted ? (ushort)0 : null;
        byte[] serverHello = ServerHello.Build(_cipherSuite, group, responseShare, selectedIdentity);
        _outgoing.Enqueue((EncryptionLevel.Initial, serverHello));
        _transcript!.Append(serverHello);

        ReadOnlySpan<byte> psk = _pskAccepted ? _selectedPsk : default;
        HandshakeSecrets = _ks!.DeriveHandshakeSecrets(shared, _transcript.CurrentHash(), psk);

        byte[] encryptedExtensions = BuildEncryptedExtensions();
        _transcript.Append(encryptedExtensions);
        _outgoing.Enqueue((EncryptionLevel.Handshake, encryptedExtensions));

        if (!_pskAccepted)
        {
            // Volle Authentifizierung nur ohne Resumption – bei PSK bürgt der Binder für die Identität.
            byte[] certificate = BuildCertificate(_certificate.Der);
            _transcript.Append(certificate);
            _outgoing.Enqueue((EncryptionLevel.Handshake, certificate));

            byte[] certificateVerify = BuildCertificateVerify(_transcript.CurrentHash());
            _transcript.Append(certificateVerify);
            _outgoing.Enqueue((EncryptionLevel.Handshake, certificateVerify));
        }

        byte[] verifyData = _ks.FinishedVerifyData(HandshakeSecrets.ServerHandshakeTrafficSecret, _transcript.CurrentHash());
        byte[] finished = Finished.BuildMessage(verifyData);
        _transcript.Append(finished);
        _outgoing.Enqueue((EncryptionLevel.Handshake, finished));

        _transcriptThroughServerFinished = _transcript.CurrentHash();
        ApplicationSecrets = _ks.DeriveApplicationSecrets(HandshakeSecrets.HandshakeSecret, _transcriptThroughServerFinished);
        _state = State.WaitClientFinished;
    }

    /// <summary>
    /// Wählt die erste bevorzugte Cipher Suite, die der Client anbietet.
    /// </summary>
    private bool TrySelectCipherSuite(ClientHelloInfo ch, out CipherSuite suite)
    {
        foreach (CipherSuite preferred in _preferredCipherSuites)
            if (ch.CipherSuites.Contains((ushort)preferred))
            {
                suite = preferred;
                return true;
            }
        suite = CipherSuite.Aes128GcmSha256;
        return false;
    }

    private bool TrySelectGroupWithKeyShare(ClientHelloInfo ch, out NamedGroup group, out byte[]? keyShare)
    {
        foreach (NamedGroup g in _preferredGroups)
        {
            if (KeyExchange.IsSupported(g) && ch.KeyShares.TryGetValue((ushort)g, out keyShare))
            {
                group = g;
                return true;
            }
        }
        group = default;
        keyShare = null;
        return false;
    }

    private bool TrySelectGroupForHrr(ClientHelloInfo ch, out NamedGroup group)
    {
        foreach (NamedGroup g in _preferredGroups)
        {
            if (KeyExchange.IsSupported(g) && ch.SupportedGroups.Contains((ushort)g))
            {
                group = g;
                return true;
            }
        }
        group = default;
        return false;
    }

    private void VerifyClientFinished(HandshakeMessage finished)
    {
        byte[] expected = _ks!.FinishedVerifyData(HandshakeSecrets!.ClientHandshakeTrafficSecret, _transcriptThroughServerFinished);
        ClientFinishedValid = CryptographicOperations.FixedTimeEquals(expected, finished.Body.Span);
    }

    private static byte[] SyntheticMessageHash(byte[] hash, int hashLength)
    {
        byte[] message = new byte[4 + hashLength];
        message[0] = 0xFE; // message_hash
        message[3] = (byte)hashLength;
        hash.CopyTo(message, 4);
        return message;
    }

    // ---- Nachrichten-Builder ---------------------------------------------------------------

    private byte[] BuildEncryptedExtensions()
    {
        var w = new BufferWriter(64);
        try
        {
            w.WriteByte((byte)HandshakeType.EncryptedExtensions);
            int bodyLen = TlsWriter.BeginVector(ref w, 3);
            int extLen = TlsWriter.BeginVector(ref w, 2);

            w.WriteUInt16((ushort)ExtensionType.Alpn);
            int alpnExt = TlsWriter.BeginVector(ref w, 2);
            int protoList = TlsWriter.BeginVector(ref w, 2);
            w.WriteByte(2);
            w.WriteBytes("h3"u8);
            TlsWriter.EndVector(ref w, protoList, 2);
            TlsWriter.EndVector(ref w, alpnExt, 2);

            TlsWriter.WriteExtension(ref w, ExtensionType.QuicTransportParameters, _quicTransportParameters);

            // Bei akzeptiertem 0-RTT die (leere) early_data-Extension bestätigen (RFC 8446 §4.2.10).
            if (EarlyDataAccepted)
                TlsWriter.WriteExtension(ref w, ExtensionType.EarlyData, ReadOnlySpan<byte>.Empty);

            TlsWriter.EndVector(ref w, extLen, 2);
            TlsWriter.EndVector(ref w, bodyLen, 3);
            return w.WrittenSpan.ToArray();
        }
        finally { w.Dispose(); }
    }

    private static byte[] BuildCertificate(byte[] der)
    {
        var w = new BufferWriter(der.Length + 32);
        try
        {
            w.WriteByte((byte)HandshakeType.Certificate);
            int bodyLen = TlsWriter.BeginVector(ref w, 3);
            w.WriteByte(0); // certificate_request_context: leer
            int listLen = TlsWriter.BeginVector(ref w, 3);
            {
                int certLen = TlsWriter.BeginVector(ref w, 3);
                w.WriteBytes(der);
                TlsWriter.EndVector(ref w, certLen, 3);
                w.WriteUInt16(0); // Extensions dieses Eintrags: leer
            }
            TlsWriter.EndVector(ref w, listLen, 3);
            TlsWriter.EndVector(ref w, bodyLen, 3);
            return w.WrittenSpan.ToArray();
        }
        finally { w.Dispose(); }
    }

    private byte[] BuildCertificateVerify(byte[] transcriptHash)
    {
        byte[] content = CertificateVerify.BuildSignatureContent(CertificateVerify.ServerContext, transcriptHash);
        byte[] signature = _certificate.SignCertificateVerify(content);

        var w = new BufferWriter(signature.Length + 16);
        try
        {
            w.WriteByte((byte)HandshakeType.CertificateVerify);
            int bodyLen = TlsWriter.BeginVector(ref w, 3);
            w.WriteUInt16((ushort)_certificate.SignatureScheme);
            w.WriteUInt16((ushort)signature.Length);
            w.WriteBytes(signature);
            TlsWriter.EndVector(ref w, bodyLen, 3);
            return w.WrittenSpan.ToArray();
        }
        finally { w.Dispose(); }
    }

    public void Dispose() => _transcript?.Dispose();
}
