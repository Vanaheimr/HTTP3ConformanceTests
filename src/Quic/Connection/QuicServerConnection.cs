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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;

/// <summary>
/// Eine Server-QUIC-Verbindung (RFC 9000/9001). Leitet die Initial-Schlüssel aus der vom Client
/// gewählten DCID ab, treibt den <see cref="TlsServerHandshake"/> und sendet nach abgeschlossenem
/// Handshake HANDSHAKE_DONE. Optional erzwingt sie eine Adressvalidierung per Retry (RFC 9000 §8.1)
/// und beantwortet nicht unterstützte Versionen mit einem Version-Negotiation-Paket (§6). Die
/// gemeinsame Transport-Logik liegt in <see cref="QuicEndpoint"/>.
/// </summary>
public sealed class QuicServerConnection : QuicEndpoint
{
    private readonly ServerCertificate _certificate;
    private readonly bool _requireRetry;
    private readonly IReadOnlyList<CipherSuite>? _preferredCipherSuites;
    private readonly IReadOnlyList<NamedGroup>? _preferredGroups;
    private readonly ServerResumptionCache? _resumptionCache;
    private readonly uint _maxEarlyDataSize;
    private TlsServerHandshake? _serverTls;
    private bool _handshakeDoneSent;
    private bool _retrySent;
    private byte[] _retryToken = [];
    private ConnectionId _originalDcid = ConnectionId.Empty;
    private readonly List<ulong> _newlyOpenedRequestStreams = [];

    protected override bool IsServer => true;

    // Der Server bestätigt den Handshake mit dessen Abschluss ⇒ Handshake-Keys verwerfbar (RFC 9001 §4.9.2).
    protected override bool HandshakeIsConfirmed => HandshakeComplete;

    public QuicServerConnection(
        ServerCertificate certificate,
        TransportParameters? transportParameters = null,
        uint version = 0x0000_0001,
        bool requireRetry = false,
        IReadOnlyList<CipherSuite>? preferredCipherSuites = null,
        IReadOnlyList<NamedGroup>? preferredGroups = null,
        ServerResumptionCache? resumptionCache = null,
        uint maxEarlyDataSize = 0,
        StatelessResetTokenGenerator? statelessResetTokens = null)
        : base(transportParameters, version)
    {
        _certificate = certificate;
        _requireRetry = requireRetry;
        _preferredCipherSuites = preferredCipherSuites;
        _preferredGroups = preferredGroups;
        StatelessResetTokens = statelessResetTokens; // aus der CID ableitbare Tokens ⇒ Stateless Reset sendbar
        _resumptionCache = resumptionCache;
        _maxEarlyDataSize = maxEarlyDataSize;
    }

    /// <summary>
    /// <c>true</c>, wenn der Handshake per Session Resumption (PSK) geführt wurde.
    /// </summary>
    public bool ResumptionAccepted => _serverTls?.ResumptionAccepted ?? false;

    /// <summary>
    /// <c>true</c>, wenn 0-RTT (early_data) akzeptiert wurde.
    /// </summary>
    public bool EarlyDataAccepted => _serverTls?.EarlyDataAccepted ?? false;

    /// <summary>
    /// <c>true</c>, sobald der Server ein Retry zur Adressvalidierung gesendet hat.
    /// </summary>
    public bool SentRetry => _retrySent;

    /// <summary>
    /// <c>true</c>, sobald der Client-Finished geprüft wurde und der Handshake steht.
    /// </summary>
    public bool HandshakeComplete => _serverTls is { IsComplete: true, ClientFinishedValid: true };

    /// <summary>
    /// Öffnet einen server-initiierten unidirektionalen Stream (HTTP/3-Control/QPACK).
    /// </summary>
    public QuicStream OpenUnidirectionalStream() => OpenLocalStream(bidirectional: false);

    /// <summary>
    /// Öffnet einen server-initiierten bidirektionalen Stream (z. B. eine server-seitige
    /// WebTransport-Bidi-Stream, RFC-Draft webtrans-http3 §4.2).
    /// </summary>
    public QuicStream OpenBidirectionalStream() => OpenLocalStream(bidirectional: true);

    /// <summary>
    /// Seit dem letzten Aufruf neu vom Client geöffnete bidirektionale (Request-)Streams.
    /// </summary>
    public IReadOnlyList<ulong> TakeNewRequestStreams()
    {
        var result = _newlyOpenedRequestStreams.ToList();
        _newlyOpenedRequestStreams.Clear();
        return result;
    }

    protected override void OnLongHeaderPacket(LongPacketType type, LongHeaderPrefix prefix)
    {
        if (TlsHandshake is not null || type != LongPacketType.Initial)
            return;

        Dcid = prefix.SourceConnectionId; // Client-SCID wird unsere DCID (Ziel für Retry/Antwort)

        // Adressvalidierung (RFC 9000 §8.1): auf das erste tokenlose Initial mit einem Retry antworten.
        if (_requireRetry && !_retrySent)
        {
            _originalDcid = prefix.DestinationConnectionId; // D0 – geht in den Integrity Tag und die ODCID-TP ein
            _retryToken = RandomNumberGenerator.GetBytes(16);
            // Retry: DCID = Client-SCID, SCID = eigene Scid (bleibt fortan die DCID des Clients), Tag über D0.
            EnqueueDatagram(RetryPacket.Build(Version, prefix.SourceConnectionId, Scid, _retryToken, _originalDcid));
            _retrySent = true;
            return; // noch keine Schlüssel/kein TLS – erst das erneute, token-tragende Initial zählt
        }

        // Nach Retry: nur ein Initial mit exakt unserem Token akzeptieren.
        if (_requireRetry && !prefix.Token.AsSpan().SequenceEqual(_retryToken))
            return;
        if (_requireRetry)
            MarkAddressValidated(); // gültiges Retry-Token beweist die Client-Adresse (RFC 9000 §8.1)

        // Nach Retry leiten beide Seiten die Initial-Schlüssel aus DER DCID DIESES Initials ab (= unsere Scid).
        ConnectionId initialKeyDcid = prefix.DestinationConnectionId;

        LocalParams.InitialSourceConnectionIdValue = Scid;
        LocalParams.OriginalDestinationConnectionIdValue = _requireRetry ? _originalDcid : initialKeyDcid;
        if (_requireRetry)
            LocalParams.RetrySourceConnectionIdValue = Scid;
        // Stateless-Reset-Token für die Handshake-CID ankündigen (RFC 9000 §10.3/§18.2).
        // Token der Handshake-CID: aus ihr ableiten (falls Generator gesetzt), damit es nach Zustandsverlust
        // für einen Stateless Reset neu berechenbar ist; sonst zufällig.
        LocalParams.StatelessResetTokenValue = StatelessResetTokens?.ComputeToken(Scid.Span) ?? RandomNumberGenerator.GetBytes(16);

        _serverTls = new TlsServerHandshake(_certificate, LocalParams.Encode(),
            preferredCipherSuites: _preferredCipherSuites, preferredGroups: _preferredGroups,
            resumptionCache: _resumptionCache, maxEarlyDataSize: _maxEarlyDataSize);
        TlsHandshake = _serverTls;

        InstallInitialKeys(initialKeyDcid);
    }

    /// <summary>
    /// Server-Seite der Parameter-Prüfung (RFC 9000 §18.2): ein Client DARF die server-only-Parameter
    /// (original_destination_connection_id, preferred_address, retry_source_connection_id,
    /// stateless_reset_token) NICHT senden — ihr Empfang ist ein TRANSPORT_PARAMETER_ERROR.
    /// </summary>
    internal override string? ValidatePeerTransportParameters(TransportParameters p)
    {
        if (base.ValidatePeerTransportParameters(p) is { } baseProblem)
            return baseProblem;
        if (p.OriginalDestinationConnectionIdValue is not null)
            return "client sent original_destination_connection_id";
        if (p.RetrySourceConnectionIdValue is not null)
            return "client sent retry_source_connection_id";
        if (p.StatelessResetTokenValue is not null)
            return "client sent stateless_reset_token";
        if (p.SawPreferredAddress)
            return "client sent preferred_address";
        return null;
    }

    protected override void HandleUnsupportedVersion(ReadOnlySpan<byte> datagram)
    {
        // Anti-Amplification (RFC 9000 §6.1/§14.1): kein VN auf ein Datagramm, das kleiner ist als das
        // kleinste zulässige Initial (1200 B) – sonst wäre das VN-Paket ein Verstärker für gefälschte Absender.
        if (datagram.Length < InitialPacketFactory.MinimumClientInitialSize)
            return;

        // RFC 9000 §6.1: mit einem Version-Negotiation-Paket antworten, das die unterstützte(n) Version(en) listet.
        if (!LongHeader.TryParseInvariant(datagram, out _, out ConnectionId dcid, out ConnectionId scid))
            return;

        // Eine reservierte GREASE-Version (Muster 0x?a?a?a?a, RFC 9000 §6.3) beilegen: prüft, ob der Client
        // unbekannte Versionen korrekt ignoriert, und beugt der Ossifizierung von Version Negotiation vor.
        uint grease = (BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)) & 0xF0F0F0F0u) | 0x0A0A0A0Au;

        // DCID/SCID vertauschen: die SCID des Clients wird zur DCID des VN-Pakets.
        EnqueueDatagram(VersionNegotiationPacket.Build(scid, dcid, [Version, grease]));
    }

    /// <summary>
    /// Testhilfe: unterdrückt das Senden von HANDSHAKE_DONE (um die 1-RTT-ACK-Bestätigung des Clients zu prüfen).
    /// </summary>
    internal bool SuppressHandshakeDoneForTest { get; set; }

    protected override void AddApplicationControlFrames(List<Frame> frames)
    {
        if (HandshakeComplete && !_handshakeDoneSent && !SuppressHandshakeDoneForTest)
        {
            frames.Add(HandshakeDoneFrame.Instance);
            _handshakeDoneSent = true;
        }
    }

    protected override void OnStreamOpened(StreamId id, bool isNew)
    {
        if (isNew && id.IsClientInitiated && id.IsBidirectional)
            _newlyOpenedRequestStreams.Add(id.Value);
    }
}
