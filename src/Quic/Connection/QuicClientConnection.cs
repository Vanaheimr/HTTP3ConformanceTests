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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;
using System.Security.Cryptography;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;

/// <summary>
/// Eine Client-QUIC-Verbindung (RFC 9000/9001). Wählt DCID und SCID, treibt den
/// <see cref="TlsClientHandshake"/> und bestätigt den Handshake beim Empfang von HANDSHAKE_DONE.
/// Die gemeinsame Transport-Logik liegt in <see cref="QuicEndpoint"/>.
/// </summary>
public sealed class QuicClientConnection : QuicEndpoint
{
    private readonly TlsClientHandshake _tls;
    private readonly ConnectionId _originalDcid;
    private bool _dcidLearned;
    private bool _retryHandled;
    private List<uint> _offeredVersions = [];
    private readonly List<Frame> _applicationFrames = [];

    protected override bool IsServer => false;

    // Handshake bestätigt, sobald der Client HANDSHAKE_DONE empfangen hat ⇒ Handshake-Keys verwerfbar (RFC 9001 §4.9.2).
    protected override bool HandshakeIsConfirmed => HandshakeConfirmed;

    public QuicClientConnection(
        string serverName,
        TransportParameters? transportParameters = null,
        uint version = 0x0000_0001,
        CertificateValidationOptions? certificateValidation = null,
        IReadOnlyList<CipherSuite>? cipherSuites = null,
        IReadOnlyList<NamedGroup>? keyExchangeGroups = null,
        ResumptionTicket? resumptionTicket = null)
        : base(transportParameters, version)
    {
        LocalParams.InitialSourceConnectionIdValue = Scid;

        // Die zufällige DCID des ersten Client-Initials leitet die Initial-Schlüssel ab.
        _originalDcid = new ConnectionId(RandomNumberGenerator.GetBytes(8));
        Dcid = _originalDcid;

        // Angebotene Named Groups (null ⇒ TLS-Standard X25519+P-256); dieselbe Liste als Key Shares und
        // in supported_groups, sodass etwa X448 direkt angeboten wird (kein HelloRetryRequest nötig).
        // Ein resumptionTicket aktiviert Session Resumption (PSK) für diese Verbindung.
        _tls = new TlsClientHandshake(serverName, LocalParams.Encode(), certificateValidation: certificateValidation,
            cipherSuites: cipherSuites, keyShareGroups: keyExchangeGroups, supportedGroups: keyExchangeGroups,
            resumptionTicket: resumptionTicket);
        TlsHandshake = _tls;
        InstallInitialKeys(_originalDcid);
    }

    /// <summary>
    /// <c>true</c>, sobald der Client seinen Finished erzeugt hat.
    /// </summary>
    public bool HandshakeComplete => _tls.IsComplete;

    /// <summary>
    /// <c>true</c>, sobald ein HANDSHAKE_DONE des Servers empfangen wurde.
    /// </summary>
    public bool HandshakeConfirmed { get; private set; }

    /// <summary>
    /// <c>true</c>, wenn der Server-Finished-MAC geprüft wurde und stimmte.
    /// </summary>
    public bool ServerFinishedValid => _tls.ServerFinishedValid;

    /// <summary>
    /// <c>true</c>, sobald das Serverzertifikat inkl. CertificateVerify-Signatur geprüft wurde.
    /// </summary>
    public bool ServerCertificateValid => _tls.ServerCertificateValid;

    /// <summary>
    /// Das geprüfte Leaf-Zertifikat des Servers (Diagnose).
    /// </summary>
    public System.Security.Cryptography.X509Certificates.X509Certificate2? ServerCertificate => _tls.ServerCertificate;

    public CipherSuite? NegotiatedCipherSuite => _tls.NegotiatedCipherSuite;

    /// <summary>
    /// Die im Handshake ausgehandelte Named Group (X25519 oder P-256), nach evtl. HRR.
    /// </summary>
    public NamedGroup? NegotiatedGroup => _tls.NegotiatedGroup;

    /// <summary>
    /// Die vom Server ausgestellten Session-Tickets (RFC 8446 §4.6.1) für spätere Resumption.
    /// </summary>
    public IReadOnlyList<ResumptionTicket> NewSessionTickets => _tls.NewSessionTickets;

    /// <summary>
    /// Diagnose: Anzahl empfangener NewSessionTicket-Nachrichten.
    /// </summary>
    public int NewSessionTicketMessagesSeen => _tls.NewSessionTicketMessagesSeen;

    /// <summary>
    /// <c>true</c>, wenn diese Verbindung per Session Resumption (PSK) statt Zertifikat aufgebaut wurde.
    /// </summary>
    public bool ResumptionAccepted => _tls.ResumptionAccepted;

    /// <summary>
    /// <c>true</c>, wenn 0-RTT (early_data) vom Server akzeptiert wurde.
    /// </summary>
    public bool EarlyDataAccepted => _tls.EarlyDataAccepted;

    /// <summary>
    /// In 1-RTT empfangene Frames (z. B. HANDSHAKE_DONE, HTTP/3-Control-Stream) zur Inspektion.
    /// </summary>
    public IReadOnlyList<Frame> ApplicationFrames => _applicationFrames;

    /// <summary>
    /// <c>true</c>, wenn ein Version-Negotiation-Paket empfangen wurde (keine gemeinsame Version).
    /// </summary>
    public bool VersionNegotiationReceived { get; private set; }

    /// <summary>
    /// Die vom Server im Version-Negotiation-Paket angebotenen Versionen (leer, falls keins empfangen).
    /// </summary>
    public IReadOnlyList<uint> OfferedVersions => _offeredVersions;

    /// <summary>
    /// <c>true</c>, sobald ein Retry verarbeitet und der ClientHello erneut gesendet wurde.
    /// </summary>
    public bool RetryHandled => _retryHandled;

    /// <summary>
    /// Startet den Handshake (baut den ClientHello).
    /// </summary>
    public void Start() => _tls.Start();

    /// <summary>
    /// Öffnet einen client-initiierten bidirektionalen Stream (z. B. eine HTTP/3-Anfrage).
    /// </summary>
    public QuicStream OpenBidirectionalStream() => OpenLocalStream(bidirectional: true);

    /// <summary>
    /// Öffnet einen client-initiierten unidirektionalen Stream (z. B. HTTP/3-Control/QPACK).
    /// </summary>
    public QuicStream OpenUnidirectionalStream() => OpenLocalStream(bidirectional: false);

    protected override void OnLongHeaderPacket(LongPacketType type, LongHeaderPrefix prefix)
    {
        if (!_dcidLearned)
        {
            Dcid = prefix.SourceConnectionId; // Server-SCID wird unsere DCID
            _dcidLearned = true;
        }
    }

    protected override void HandleVersionNegotiationPacket(ReadOnlySpan<byte> datagram)
    {
        // RFC 9000 §6.2: VN verwerfen, wenn bereits ein anderes Paket verarbeitet oder schon ein VN empfangen wurde.
        if (AnyPacketProcessed || VersionNegotiationReceived)
            return;
        if (!VersionNegotiationPacket.TryParse(datagram, out _, out _, out List<uint> versions))
            return;
        // VN verwerfen, wenn sie die vom Client gewählte Version listet (spuriöses/gefälschtes VN).
        if (versions.Contains(Version))
            return;

        _offeredVersions = versions;
        VersionNegotiationReceived = true; // Nur-v1-Client: keine gemeinsame Version → Verbindung aufgeben.
    }

    protected override void HandleRetryPacket(ReadOnlySpan<byte> datagram)
    {
        // Nur genau einen Retry verarbeiten und nur, bevor ein echtes Paket ankam (RFC 9000 §17.2.5.2).
        if (_retryHandled || AnyPacketProcessed)
            return;
        if (!RetryPacket.TryParse(datagram, out uint version, out _, out ConnectionId retrySource, out byte[] token, out _))
            return;
        if (version != Version)
            return;
        // Retry mit SCID == eigener DCID verwerfen (Schleifenschutz, RFC 9000 §17.2.5.2).
        if (retrySource.Span.SequenceEqual(_originalDcid.Span))
            return;
        // Integrity Tag über die ursprüngliche DCID prüfen (RFC 9001 §5.8).
        if (!RetryPacket.Verify(datagram, _originalDcid))
            return;

        _retryHandled = true;
        _dcidLearned = true;                 // DCID nur einmal ändern (RFC 9000 §7.2): jetzt = Retry-SCID
        ApplyRetry(retrySource, token);      // neue Initial-Schlüssel + Token + CRYPTO-Offset 0
        _tls.ResendClientHello();
    }

    protected override void OnHandshakeDoneReceived() => HandshakeConfirmed = true;

    // RFC 9001 §4.1.2: Der Client darf den Handshake auch dann bestätigen, wenn eines seiner 1-RTT-Pakete
    // quittiert wurde – so werden die Handshake-Keys ggf. schon vor einem (verlorenen) HANDSHAKE_DONE verworfen.
    protected override void OnOneRttPacketAcknowledged() => HandshakeConfirmed = true;

    protected override void OnApplicationFrameHandled(Frame frame) => _applicationFrames.Add(frame);
}
