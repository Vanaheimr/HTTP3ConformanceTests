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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Ein HTTP/3-Client (RFC 9114) über einer <see cref="QuicClientConnection"/>. Öffnet den Control-Stream
/// (mit SETTINGS) und die QPACK-Encoder/Decoder-Streams, sendet Requests als HEADERS-Frame auf einem
/// bidirektionalen Stream und setzt die Antwort (HEADERS + DATA) wieder zusammen. Transport-agnostisch:
/// Datagramme kommen über <see cref="GetDatagramsToSend"/> / <see cref="ProcessDatagram"/> herein/heraus.
/// </summary>
public sealed class Http3ClientConnection : IDisposable, IWebTransportHost
{
    private readonly QuicClientConnection _quic;
    private readonly Dictionary<ulong, RequestState> _requests = [];
    private readonly Http3Qpack _qpack;
    private bool _http3Initialized;
    private readonly WebTransportManager _webTransport = new(weAreClient: true);
    private readonly ulong _wtMaxSessions; // draft-webtrans-http3 §9.2 (0 = WebTransport aus)

    /// <param name="qpackMaxTableCapacity">
    /// Angekündigte maximale QPACK-Tabellenkapazität (RFC 9204). <c>0</c> (Standard) = rein statisch
    /// (interop-sicher); &gt; 0 aktiviert die dynamische Tabelle, sobald auch der Peer eine ankündigt.
    /// </param>
    /// <param name="maxFieldSectionSize">
    /// Optionales Limit für die Größe angenommener Field Sections (RFC 9114 §4.2.2, unkomprimiert:
    /// Name + Wert + 32 je Feld). Wird per SETTINGS_MAX_FIELD_SECTION_SIZE angekündigt; größere
    /// Antwort-Header-Sektionen werden verworfen (<see cref="IsResponseTooLarge"/>). <c>null</c> = unbegrenzt.
    /// </param>
    /// <param name="enableDatagrams">
    /// HTTP-Datagramme (RFC 9297/9221) aktivieren: kündigt max_datagram_frame_size = 65535 (QUIC-TP)
    /// und SETTINGS_H3_DATAGRAM = 1 an. Nutzbar, sobald der Peer beides ebenfalls angekündigt hat
    /// (<see cref="DatagramsNegotiated"/>) — Datagramme laufen über Extended-CONNECT-Tunnel.
    /// </param>
    public Http3ClientConnection(
        string serverName,
        TransportParameters? transportParameters = null,
        CertificateValidationOptions? certificateValidation = null,
        ulong qpackMaxTableCapacity = 0,
        IReadOnlyList<Quic.Tls.CipherSuite>? cipherSuites = null,
        IReadOnlyList<Quic.Tls.NamedGroup>? keyExchangeGroups = null,
        Quic.Tls.ResumptionTicket? resumptionTicket = null,
        ulong? maxFieldSectionSize = null,
        bool enableDatagrams = false,
        ulong webTransportMaxSessions = 0)
    {
        _wtMaxSessions = webTransportMaxSessions;
        if (webTransportMaxSessions > 0) // WebTransport setzt HTTP/3-Datagramme voraus (draft §3.1)
            enableDatagrams = true;
        _localDatagramsEnabled = enableDatagrams;
        if (enableDatagrams)
        {
            transportParameters ??= new TransportParameters();
            transportParameters.MaxDatagramFrameSizeValue = 65535; // RFC 9221 §3 RECOMMENDED
        }
        _quic = new QuicClientConnection(serverName, transportParameters, certificateValidation: certificateValidation, cipherSuites: cipherSuites, keyExchangeGroups: keyExchangeGroups, resumptionTicket: resumptionTicket);
        _qpack = new Http3Qpack(qpackMaxTableCapacity, weAreClient: true, FatalConnectionError)
        {
            OnWebTransportUniStream = (stream, sessionId, leftover) =>
                _webTransport.ClaimStream(stream, sessionId, leftover, bidirectional: false),
        };
        _localMaxFieldSectionSize = maxFieldSectionSize;
    }

    private readonly ulong? _localMaxFieldSectionSize; // unser angekündigtes Limit (RFC 9114 §4.2.2)
    private readonly bool _localDatagramsEnabled;      // HTTP-Datagramme lokal aktiviert (RFC 9297)

    /// <summary>
    /// HTTP-Datagramme sind beidseitig ausgehandelt (RFC 9297 §2.1.1: SETTINGS_H3_DATAGRAM gesendet
    /// UND empfangen; RFC 9221 §3: Peer hat max_datagram_frame_size angekündigt).
    /// </summary>
    public bool DatagramsNegotiated
        => _localDatagramsEnabled && _qpack.PeerH3Datagram && _quic.PeerMaxDatagramFrameSize > 0;

    /// <summary>
    /// Sendet ein HTTP-Datagramm zum Request-Stream <paramref name="streamId"/> (RFC 9297 §2.1:
    /// Quarter Stream ID + Payload in einem QUIC-DATAGRAM-Frame; unzuverlässig).
    /// </summary>
    public bool TrySendHttpDatagram(ulong streamId, byte[] payload)
    {
        if (!DatagramsNegotiated ||
            !_requests.TryGetValue(streamId, out RequestState? state) || state.Stream.Send.IsReset)
            return false; // §2.1: nur bei offener Sendeseite

        var writer = new BufferWriter(payload.Length + 8);
        try
        {
            writer.WriteVarInt(streamId / 4); // Quarter Stream ID
            writer.WriteBytes(payload);
            return _quic.TrySendDatagram(writer.WrittenSpan);
        }
        finally { writer.Dispose(); }
    }

    /// <summary>
    /// Ordnet empfangene QUIC-DATAGRAMs ihren Request-Streams zu (RFC 9297 §2.1).
    /// </summary>
    private void DispatchReceivedDatagrams()
    {
        foreach (byte[] datagram in _quic.TakeReceivedDatagrams())
        {
            var reader = new BufferReader(datagram);
            if (!reader.TryReadVarInt(out ulong quarter))
            {
                FatalConnectionError(Http3Error.DatagramError, "malformed HTTP/3 datagram"); // §2.1
                return;
            }
            if (quarter > (1UL << 60) - 1)
            {
                FatalConnectionError(Http3Error.DatagramError, "quarter stream ID too large"); // §2.1
                return;
            }

            // WebTransport-Datagramm (draft §4.4): Quarter Stream ID adressiert den CONNECT-Stream = Session.
            if (_webTransport.TryDeliverDatagram(quarter * 4, datagram[reader.Position..]))
                continue;

            if (!_requests.TryGetValue(quarter * 4, out RequestState? state))
                continue; // Stream unbekannt ⇒ still verwerfen (§2.1 SHALL drop or buffer)

            if (state.Tunnel is { } tunnel)
            {
                if (!state.Stream.IsResetByPeer) // Empfangsseite zu ⇒ still verwerfen (§2.1)
                    tunnel.DeliverDatagram(datagram[reader.Position..]);
            }
            else if (!state.Cancelled)
            {
                // §2: Datagramm zu einem Request ohne Datagram-Semantik ⇒ Request beenden
                // (STREAM-Fehler H3_DATAGRAM_ERROR, kein Verbindungsfehler).
                state.Cancelled = true;
                state.Stream.Reset(Http3Error.DatagramError);
                state.Stream.AbortRead(Http3Error.DatagramError);
            }
        }
    }

    /// <summary>
    /// Meldet einen HTTP/3-Verbindungsfehler (RFC 9114 §8): CONNECTION_CLOSE Typ 0x1d mit H3-Fehlercode.
    /// </summary>
    private void FatalConnectionError(ulong errorCode, string reason) => _quic.CloseApplication(errorCode, reason);

    /// <summary>
    /// Die vom Server ausgestellten Session-Tickets (RFC 8446 §4.6.1) für spätere Resumption.
    /// </summary>
    public IReadOnlyList<Quic.Tls.ResumptionTicket> NewSessionTickets => _quic.NewSessionTickets;

    /// <summary>
    /// <c>true</c>, wenn diese Verbindung per Session Resumption (PSK) aufgebaut wurde.
    /// </summary>
    public bool ResumptionAccepted => _quic.ResumptionAccepted;

    /// <summary>
    /// <c>true</c>, wenn 0-RTT (early_data) vom Server akzeptiert wurde.
    /// </summary>
    public bool EarlyDataAccepted => _quic.EarlyDataAccepted;

    /// <summary>
    /// Das vom Server per SETTINGS_MAX_FIELD_SECTION_SIZE angekündigte Limit (RFC 9114 §4.2.2);
    /// <c>null</c> = nicht angekündigt (unbegrenzt). Größere Field Sections senden wir nicht.
    /// </summary>
    public ulong? ServerMaxFieldSectionSize => _qpack.PeerMaxFieldSectionSize;

    /// <summary>
    /// Insert Count der QPACK-Encoder-Tabelle (Diagnose: &gt; 0 ⇒ dynamische Tabelle genutzt).
    /// </summary>
    public ulong QpackEncoderInsertCount => _qpack.EncoderInsertCount;

    /// <summary>
    /// Insert Count der QPACK-Decoder-Tabelle (Diagnose).
    /// </summary>
    public ulong QpackDecoderInsertCount => _qpack.DecoderInsertCount;

    public bool HandshakeConfirmed => _quic.HandshakeConfirmed;

    /// <summary>
    /// <c>true</c>, sobald die Verbindung wegen Idle-Timeout still geschlossen wurde (RFC 9000 §10.1).
    /// </summary>
    public bool IsIdleTimedOut => _quic.IsIdleTimedOut;

    /// <summary>
    /// <c>true</c>, wenn ein Retry des Servers verarbeitet und der ClientHello erneut gesendet wurde.
    /// </summary>
    public bool RetryHandled => _quic.RetryHandled;

    /// <summary>
    /// <c>true</c>, während die Verbindung nach einem eigenen CONNECTION_CLOSE schließt (RFC 9000 §10.2).
    /// </summary>
    public bool IsClosing => _quic.IsClosing;

    /// <summary>
    /// <c>true</c>, nachdem ein CONNECTION_CLOSE des Peers empfangen wurde (Draining-Zustand).
    /// </summary>
    public bool IsDraining => _quic.IsDraining;

    /// <summary>
    /// <c>true</c>, sobald die Verbindung endgültig geschlossen ist (Closing/Draining nach 3·PTO abgelaufen).
    /// </summary>
    public bool IsClosed => _quic.IsClosed;

    /// <summary>
    /// Das vom Peer empfangene CONNECTION_CLOSE (Fehlercode + Grund), falls vorhanden.
    /// </summary>
    public Quic.Frames.ConnectionCloseFrame? PeerCloseFrame => _quic.PeerCloseFrame;

    /// <summary>
    /// Schließt die Verbindung sofort mit einem CONNECTION_CLOSE (RFC 9000 §10.2; Standard: NO_ERROR).
    /// </summary>
    public void Close(TransportError error = TransportError.NoError, string reason = "") => _quic.Close(error, reason);

    /// <summary>
    /// Schließt die Verbindung HTTP/3-konform ohne Fehler (RFC 9114 §5.2 SHOULD: CONNECTION_CLOSE
    /// Typ 0x1d mit H3_NO_ERROR) — z. B. nachdem der Server per GOAWAY den Abbau eingeleitet hat.
    /// </summary>
    public void CloseGracefully() => _quic.CloseApplication(Http3Error.NoError, "graceful shutdown");

    /// <summary>
    /// Keep-Alive-Intervall (RFC 9000 §10.1.2): sendet PINGs gegen den Idle-Timeout. <c>null</c> = aus.
    /// </summary>
    public TimeSpan? KeepAliveInterval
    {
        get => _quic.KeepAliveInterval;
        set => _quic.KeepAliveInterval = value;
    }

    /// <summary>
    /// Startet eine Pfadvalidierung (RFC 9000 §8.2), Grundlage der Connection Migration.
    /// </summary>
    public void InitiatePathValidation() => _quic.InitiatePathValidation();

    /// <summary>
    /// <c>true</c>, sobald der Pfad per PATH_CHALLENGE/PATH_RESPONSE bestätigt wurde.
    /// </summary>
    public bool PathValidated => _quic.PathValidated;

    /// <summary>
    /// Es läuft eine Pfadvalidierung (Antwort ausstehend).
    /// </summary>
    public bool PathValidationPending => _quic.PathValidationPending;

    /// <summary>
    /// Zugriff auf die zugrunde liegende QUIC-Verbindung (Diagnose).
    /// </summary>
    public QuicClientConnection Quic => _quic;

    public void Start() => _quic.Start();

    /// <summary>
    /// Prüft Loss-Detection-/PTO- und Idle-Timeouts (periodisch aufrufen).
    /// </summary>
    public void CheckTimeouts()
    {
        _quic.CheckLossDetectionTimeout();
        _quic.CheckIdleTimeout();
    }

    public IReadOnlyList<byte[]> GetDatagramsToSend() => _quic.GetDatagramsToSend();

    /// <summary>
    /// Verarbeitet ein Datagramm und pumpt anschließend die HTTP/3-Stream-Daten weiter.
    /// </summary>
    public void ProcessDatagram(ReadOnlySpan<byte> datagram)
    {
        _quic.ProcessDatagram(datagram);
        Pump();
    }

    /// <summary>
    /// Öffnet Control- + QPACK-Streams und sendet die SETTINGS (einmalig, nach dem Handshake).
    /// </summary>
    public void InitializeHttp3()
    {
        if (_http3Initialized)
            return;

        // Control-Stream: Typ 0x00, dann ein SETTINGS-Frame (kündigt unsere QPACK-Kapazität an).
        QuicStream control = _quic.OpenUnidirectionalStream();
        control.SendUrgency = 0; // kritische Streams nie hinter Bulk-Daten verhungern lassen (RFC 9218 §10)
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, BuildSettings()));
        _controlStream = control;

        // QPACK-Encoder-Stream (für Insert-Instruktionen) + Decoder-Stream (Typ-Präfix genügt).
        QuicStream encoderStream = _quic.OpenUnidirectionalStream();
        encoderStream.SendUrgency = 0;
        encoderStream.Write([(byte)Http3StreamType.QpackEncoder]);
        _qpack.SetEncoderStream(encoderStream);
        QuicStream decoderStream = _quic.OpenUnidirectionalStream();
        decoderStream.SendUrgency = 0;
        decoderStream.Write([(byte)Http3StreamType.QpackDecoder]);
        _qpack.SetDecoderStream(decoderStream);

        _http3Initialized = true;
    }

    private QuicStream? _controlStream; // unser Control-Stream (SETTINGS, PRIORITY_UPDATE)

    /// <summary>
    /// Der Server erlaubt Extended CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, RFC 8441/9220).
    /// </summary>
    public bool ServerEnablesConnectProtocol => _qpack.PeerEnableConnectProtocol;

    /// <summary>
    /// Sendet ein Extended CONNECT (RFC 8441 §4 / RFC 9220), z. B. mit <paramref name="protocol"/> =
    /// „websocket". Der Request-Stream bleibt offen — er wird nach einer 2xx-Antwort zum Tunnel
    /// (<see cref="TryGetConnectResponse"/>). Ohne das Server-Setting DARF kein Extended CONNECT
    /// gesendet werden (RFC 8441 §3 MUST NOT) — dann fliegt eine <see cref="InvalidOperationException"/>.
    /// </summary>
    public ulong SendExtendedConnect(string authority, string path, string protocol,
                                     IReadOnlyList<HeaderField>? headers = null, string scheme = "https")
    {
        if (!_qpack.PeerEnableConnectProtocol)
            throw new InvalidOperationException(
                "Der Server hat SETTINGS_ENABLE_CONNECT_PROTOCOL nicht angekündigt (RFC 8441 §3) — Extended CONNECT ist nicht erlaubt.");
        if (_qpack.GoAwayId is not null)
            throw new InvalidOperationException("GOAWAY empfangen (RFC 9114 §5.2): keine neuen Requests auf dieser Verbindung.");

        var fields = new List<HeaderField>
        {
            new(":method", "CONNECT"),
            new(":scheme", scheme),
            new(":authority", authority),
            new(":path", path),
            new(":protocol", protocol),
        };
        if (headers is not null)
            fields.AddRange(headers);
        if (Http3MessageValidator.ValidateRequestHeaders(fields) is { } malformed)
            throw new ArgumentException($"Malformed Extended CONNECT (RFC 8441 §4): {malformed}");

        QuicStream stream = _quic.OpenBidirectionalStream();
        stream.Write(Http3Frames.Build(Http3FrameType.Headers, _qpack.EncodeHeaders(stream.Id.Value, fields)));
        // KEIN Finish: der Stream trägt anschließend die Tunnel-Bytes (RFC 9114 §4.4).

        _requests[stream.Id.Value] = new RequestState(stream) { Method = "CONNECT", IsConnect = true };
        return stream.Id.Value;
    }

    // ---- WebTransport (draft-ietf-webtrans-http3) -----------------------------------------

    /// <summary>
    /// Der Server unterstützt WebTransport (SETTINGS_WT_MAX_SESSIONS &gt; 0 + Extended CONNECT + Datagramme).
    /// </summary>
    public bool ServerSupportsWebTransport
        => _qpack.PeerWtMaxSessions > 0 && _qpack.PeerEnableConnectProtocol && DatagramsNegotiated;

    /// <summary>
    /// Öffnet eine WebTransport-Session (draft-webtrans-http3 §3.2): sendet ein Extended CONNECT mit
    /// <c>:protocol = webtransport</c>. Gibt die CONNECT-Stream-ID (= Session-ID) zurück; die Session
    /// selbst steht nach der 2xx-Antwort über <see cref="TryGetWebTransportSession"/> bereit.
    /// Mit <paramref name="availableProtocols"/> (Präferenz zuerst) wird ein ALPN-artiges
    /// Anwendungsprotokoll ausgehandelt (draft §3.3, Header <c>WT-Available-Protocols</c>); die
    /// Server-Wahl steht danach in <see cref="WebTransportSession.NegotiatedProtocol"/>.
    /// </summary>
    public ulong ConnectWebTransport(string authority, string path, IReadOnlyList<HeaderField>? headers = null,
                                     IReadOnlyList<string>? availableProtocols = null)
    {
        if (!ServerSupportsWebTransport)
            throw new InvalidOperationException("Der Server unterstützt WebTransport nicht (draft §3.1: WT_MAX_SESSIONS/Datagramme fehlen).");
        if (availableProtocols is { Count: > 0 })
        {
            var combined = new List<HeaderField>(headers ?? [])
            {
                new(WebTransportProtocols.AvailableProtocolsHeader,
                    WebTransportProtocols.SerializeProtocolList(availableProtocols)),
            };
            headers = combined;
        }
        ulong streamId = SendExtendedConnect(authority, path, "webtransport", headers);
        _requests[streamId].IsWebTransport = true;
        _requests[streamId].OfferedWtProtocols = availableProtocols is { Count: > 0 } ? [.. availableProtocols] : null;
        return streamId;
    }

    /// <summary>
    /// Liefert die WebTransport-Session, sobald der Server den CONNECT mit 2xx angenommen hat; sonst
    /// (noch nicht da oder abgelehnt) <c>false</c>.
    /// </summary>
    public bool TryGetWebTransportSession(ulong streamId, out WebTransportSession? session)
    {
        session = null;
        if (_requests.TryGetValue(streamId, out RequestState? state) && state.WebTransportSession is { } s)
        {
            session = s;
            return true;
        }
        return false;
    }

    /// <summary>
    /// Der Status der WebTransport-CONNECT-Antwort (z. B. 404, falls abgelehnt), sobald empfangen.
    /// </summary>
    public int? WebTransportConnectStatus(ulong streamId)
        => _requests.TryGetValue(streamId, out RequestState? state) ? state.ConnectStatus : null;

    /// <summary>
    /// Wertet den <c>WT-Protocol</c>-Header der 2xx-Antwort aus (draft §3.3). Das Feld MUSS ignoriert
    /// werden, wenn wir nichts angeboten haben, es mehrfach auftritt (dann wäre es kein einzelnes
    /// SF-Item mehr), kein SF-String ist oder die Server-Wahl nicht aus unserer Angebotsliste stammt.
    /// </summary>
    private static string? SelectNegotiatedProtocol(RequestState state, List<HeaderField> headers)
    {
        if (state.OfferedWtProtocols is not { Count: > 0 } offered)
            return null;
        string? value = null;
        foreach (HeaderField h in headers)
        {
            if (h.Name != WebTransportProtocols.ProtocolHeader)
                continue;
            if (value is not null)
                return null; // mehrfach ⇒ ignorieren
            value = h.Value;
        }
        if (value is null || !WebTransportProtocols.TryParseProtocol(value, out string chosen))
            return null;
        return offered.Contains(chosen) ? chosen : null; // MUSS aus der Angebotsliste stammen
    }

    /// <summary>
    /// Liefert Status (und Header) der Extended-CONNECT-Antwort, sobald sie da ist; bei 2xx zusätzlich
    /// den einsatzbereiten <see cref="Http3Tunnel"/> (sonst <c>null</c> — der CONNECT wurde abgelehnt).
    /// </summary>
    public bool TryGetConnectResponse(ulong streamId, out int status, out IReadOnlyList<HeaderField> headers, out Http3Tunnel? tunnel)
    {
        status = 0;
        headers = [];
        tunnel = null;
        if (!_requests.TryGetValue(streamId, out RequestState? state) || state.ConnectStatus is not { } connectStatus)
            return false;
        status = connectStatus;
        headers = state.Headers;
        tunnel = state.Tunnel;
        return true;
    }

    /// <summary>
    /// Sendet ein PRIORITY_UPDATE (RFC 9218 §7.2) für einen laufenden Request — z. B. um einen
    /// Prefetch (u=7) nachträglich dringlich zu machen (u=0). Das Signal überschreibt serverseitig
    /// den <c>priority</c>-Header; das jeweils zuletzt empfangene Update gewinnt.
    /// </summary>
    public void SendPriorityUpdate(ulong streamId, Http3Priority priority)
    {
        if (_controlStream is null)
            throw new InvalidOperationException("InitializeHttp3() zuerst aufrufen — PRIORITY_UPDATE läuft über den Control-Stream.");

        var writer = new BufferWriter(16);
        try
        {
            writer.WriteVarInt(streamId); // Prioritized Element ID
            byte[] fieldValue = System.Text.Encoding.ASCII.GetBytes(priority.ToHeaderValue());
            _controlStream.Write(Http3Frames.Build(Http3FrameType.PriorityUpdateRequest,
                [.. writer.WrittenSpan.ToArray(), .. fieldValue]));
        }
        finally { writer.Dispose(); }
    }

    /// <summary>
    /// Die per GOAWAY vom Server angekündigte Stream-ID (RFC 9114 §5.2): Requests mit dieser ID oder
    /// größer werden nicht verarbeitet; neue Requests sind auf dieser Verbindung nicht mehr erlaubt.
    /// </summary>
    public ulong? GoAwayStreamId => _qpack.GoAwayId;

    /// <summary>
    /// <c>true</c>, wenn der Request vom Server per GOAWAY zurückgewiesen wurde (Stream-ID ≥ GOAWAY-ID,
    /// RFC 9114 §5.2) — er wurde garantiert NICHT verarbeitet und darf gefahrlos auf einer neuen
    /// Verbindung wiederholt werden.
    /// </summary>
    public bool IsRequestRejected(ulong streamId)
        => _requests.TryGetValue(streamId, out RequestState? state) && state.Rejected;

    /// <summary>
    /// Sendet einen Request auf einem neuen bidirektionalen Stream. Gibt dessen Stream-ID zurück.
    /// Ein nicht-leerer <see cref="Http3Request.Body"/> folgt als DATA-Frame auf das HEADERS-Frame
    /// (RFC 9114 §4.1: Header-Sektion, dann Content als Serie von DATA-Frames), danach FIN.
    /// Nach einem empfangenen GOAWAY sind neue Requests verboten (RFC 9114 §5.2 MUST NOT) —
    /// dann fliegt eine <see cref="InvalidOperationException"/>; auf einer NEUEN Verbindung wiederholen.
    /// </summary>
    public ulong SendRequest(Http3Request request)
    {
        if (_qpack.GoAwayId is not null)
            throw new InvalidOperationException(
                "GOAWAY empfangen (RFC 9114 §5.2): keine neuen Requests auf dieser Verbindung — neue Verbindung aufbauen.");

        // §4.1.2 MUST NOT generate: eigene malformed Requests schon lokal ablehnen.
        if (Http3MessageValidator.ValidateRequestHeaders(request.ToHeaderFields()) is { } malformed)
            throw new ArgumentException($"Malformed Request (RFC 9114 §4.1.2): {malformed}");
        if (request.Trailers.Count > 0 && Http3MessageValidator.ValidateTrailers(request.Trailers) is { } badTrailer)
            throw new ArgumentException($"Malformed Request-Trailer (RFC 9114 §4.3): {badTrailer}");

        // §4.2.2 SHOULD NOT: keine Field Section über dem vom Server angekündigten Limit senden.
        if (_qpack.PeerMaxFieldSectionSize is { } peerLimit)
        {
            if (Http3Qpack.FieldSectionSize(request.ToHeaderFields()) > peerLimit)
                throw new ArgumentException(
                    $"Die Request-Header überschreiten das SETTINGS_MAX_FIELD_SECTION_SIZE des Servers ({peerLimit} Bytes, RFC 9114 §4.2.2).");
            if (request.Trailers.Count > 0 && Http3Qpack.FieldSectionSize(request.Trailers) > peerLimit)
                throw new ArgumentException(
                    $"Die Request-Trailer überschreiten das SETTINGS_MAX_FIELD_SECTION_SIZE des Servers ({peerLimit} Bytes, RFC 9114 §4.2.2).");
        }

        QuicStream stream = _quic.OpenBidirectionalStream();
        if (request.Priority is { } priority) // RFC 9218 §9: auch lokal fürs Senden des Requests nutzen
        {
            stream.SendUrgency = priority.Urgency;
            stream.SendIncremental = priority.Incremental;
        }
        byte[] headerBlock = _qpack.EncodeHeaders(stream.Id.Value, request.ToHeaderFields());
        stream.Write(Http3Frames.Build(Http3FrameType.Headers, headerBlock));
        if (request.Body.Length > 0)
            stream.Write(Http3Frames.Build(Http3FrameType.Data, request.Body));
        if (request.Trailers.Count > 0) // Trailer-Sektion: abschließendes HEADERS-Frame (§4.1 Punkt 3)
            stream.Write(Http3Frames.Build(Http3FrameType.Headers, _qpack.EncodeHeaders(stream.Id.Value, [.. request.Trailers])));
        stream.Finish(); // Ende der Nachricht ⇒ FIN (die QUIC-Schicht paketiert den Stream selbst)

        _requests[stream.Id.Value] = new RequestState(stream) { Method = request.Method };
        return stream.Id.Value;
    }

    /// <summary>
    /// Bricht einen laufenden Request ab (RFC 9114 §4.1.1): setzt die eigene Sendeseite zurück und
    /// bricht das Lesen der Antwort ab (STOP_SENDING) — beides mit <c>H3_REQUEST_CANCELLED</c>
    /// (Clients SOLLEN diesen Code verwenden). Eine bereits vollständige Antwort bleibt nutzbar.
    /// </summary>
    public void CancelRequest(ulong streamId)
    {
        if (!_requests.TryGetValue(streamId, out RequestState? state) || state.Complete || state.Cancelled)
            return;
        state.Cancelled = true;
        state.Stream.Reset(Http3Error.RequestCancelled);     // Sendeseite abrupt beenden (§4.1.1)
        state.Stream.AbortRead(Http3Error.RequestCancelled); // Lesen der Antwort abbrechen (§4.1.1)
    }

    /// <summary>
    /// <c>true</c>, wenn der Request abgebrochen wurde — von uns (<see cref="CancelRequest"/>) oder vom
    /// Server (RESET_STREAM auf der Antwortseite, z. B. <c>H3_REQUEST_REJECTED</c>). Eine Teil-Antwort
    /// SOLL dann nicht verwendet werden (RFC 9114 §4.1.1); <see cref="TryGetResponse"/> liefert nichts.
    /// </summary>
    public bool IsRequestCancelled(ulong streamId)
        => _requests.TryGetValue(streamId, out RequestState? state) &&
           (state.Cancelled || (!state.Complete && state.Stream.IsResetByPeer));

    /// <summary>
    /// Der Fehlercode, mit dem der Server die Antwortseite zurückgesetzt hat (z. B. 0x010b =
    /// H3_REQUEST_REJECTED ⇒ Request gilt als nie gesendet und darf wiederholt werden), sonst <c>null</c>.
    /// </summary>
    public ulong? RequestResetErrorCode(ulong streamId)
        => _requests.TryGetValue(streamId, out RequestState? state) ? state.Stream.PeerResetErrorCode : null;

    /// <summary>
    /// Liefert die fertige Antwort eines Request-Streams, sobald sie vollständig empfangen ist.
    /// </summary>
    public bool TryGetResponse(ulong streamId, out Http3Response? response)
    {
        response = null;
        if (!_requests.TryGetValue(streamId, out RequestState? state) || !state.Complete)
            return false;

        response = new Http3Response
        {
            Status = ParseStatus(state.Headers),
            Headers = state.Headers,
            Body = [.. state.Body],
            InterimResponses = state.Interim,
            Trailers = state.Trailers,
        };
        return true;
    }

    // ---- HTTP/3-Empfang -------------------------------------------------------------------

    private void Pump()
    {
        if (_quic.IsClosing || _quic.IsDraining || _quic.IsClosed)
            return; // nach einem Verbindungsfehler nichts mehr verarbeiten

        // Zuerst die Uni-Streams des Servers (SETTINGS + QPACK-Encoder-Instruktionen) verarbeiten.
        _qpack.PumpPeerStreams(_quic.Streams);

        foreach (RequestState state in _requests.Values)
        {
            if (_quic.IsClosing)
                return; // ein Verbindungsfehler wurde gemeldet

            // GOAWAY (§5.2): Requests mit Stream-ID ≥ der angekündigten ID werden nicht verarbeitet —
            // als „rejected" markieren (gefahrlos wiederholbar) und den Transportzustand aufräumen.
            if (!state.Complete && !state.Rejected &&
                _qpack.GoAwayId is { } goAway && state.Stream.Id.Value >= goAway)
            {
                state.Rejected = true;
                state.Stream.Reset(Http3Error.RequestCancelled);
                state.Stream.AbortRead(Http3Error.RequestCancelled);
                continue;
            }

            if (state.Tunnel is not null && state.Stream.IsResetByPeer)
            {
                state.Tunnel.End(); // abrupter Tunnel-Abbruch (≙ TCP-RST, RFC 9220 §3)
                continue;
            }
            if (state.Cancelled || state.Rejected || state.Malformed || state.TooLarge || state.Stream.IsResetByPeer)
                continue; // abgebrochen (§4.1.1), malformed (§4.1.2) oder zu groß (§4.2.2) – nicht weiterverarbeiten

            byte[] chunk = state.Stream.Read();
            if (chunk.Length > 0)
                state.Buffer.Append(chunk);

            // WebTransport-CONNECT-Stream (draft §5.6/§6): nach der 2xx-Antwort tragen DATA-Frames Capsules.
            if (state.WebTransportSession is { } wtSession)
            {
                ProcessWebTransportConnectStream(state, wtSession);
                continue;
            }

            if (state.Buffer.Count > 0 &&
                Http3Frames.TryReadAll(state.Buffer.Memory, out List<Http3Frame> frames, out int consumed))
            {
                foreach (Http3Frame frame in frames)
                    state.Pending.Enqueue(frame);
                state.Buffer.Consume(consumed);
            }

            // Frame-Zustandsmaschine des Request-Streams (RFC 9114 §4.1, §7.2): Interim-Sektionen (1xx),
            // finale HEADERS, dann DATA, optional eine Trailer-Sektion; blockierte Sektionen halten an.
            while (state.Pending.Count > 0 && !state.Malformed && !state.TooLarge)
            {
                Http3Frame frame = state.Pending.Peek();
                if (!ProcessResponseFrame(state, frame, out bool blocked))
                    return; // Verbindungsfehler gemeldet
                if (blocked)
                    break;  // auf weitere QPACK-Encoder-Stream-Daten warten
                state.Pending.Dequeue();
            }

            // Tunnel-Streams: ein FIN des Servers ist das geordnete Tunnel-Ende (RFC 9220 §3).
            if (state.Tunnel is not null)
            {
                if (state.Stream.IsReceiveComplete && state.Pending.Count == 0)
                    state.Tunnel.End();
                continue;
            }

            if (!state.Malformed && !state.TooLarge && state.Stream.IsReceiveComplete && state.Pending.Count == 0)
            {
                // §7.1: endet der Stream sauber mitten in einem Frame, ist das ein H3_FRAME_ERROR.
                if (state.Buffer.Count > 0)
                {
                    FatalConnectionError(Http3Error.FrameError, "truncated frame at end of stream");
                    return;
                }
                // §4.1.2: content-length MUSS zur DATA-Summe passen — außer die Antwort ist per
                // Definition rumpflos (HEAD, 204, 304) und es kam tatsächlich kein Content.
                int finalStatus = ParseStatus(state.Headers);
                bool contentNeverPresent = state.Method == "HEAD" || finalStatus is 204 or 304;
                if (Http3MessageValidator.ValidateContentLength(state.Headers, (ulong)state.Body.Count, contentNeverPresent) is { } lengthProblem)
                {
                    MarkMalformed(state, lengthProblem);
                    continue;
                }
                state.Complete = true;
            }
        }

        // Server-initiierte Bidi-Streams (draft §4.2): WT_STREAM (0x41) ‖ Session-ID ⇒ WebTransport.
        if (_wtMaxSessions > 0)
            RouteServerInitiatedWebTransportBidi();

        // HTTP-Datagramme ZULETZT zuordnen (RFC 9297 §2.1): so sind Tunnel aus demselben Flight
        // bereits angelegt, statt die Datagramme als „unbekannt" zu verwerfen.
        DispatchReceivedDatagrams();
    }

    private readonly Dictionary<ulong, List<byte>> _serverBidiHeaders = []; // Kopf-Puffer server-initiierter Bidi-Streams

    /// <summary>
    /// Routet server-initiierte bidirektionale Streams (draft §4.2): ihr Kopf ist WT_STREAM (0x41) ‖
    /// Session-ID; danach übernimmt der WebTransport-Manager.
    /// </summary>
    private void RouteServerInitiatedWebTransportBidi()
    {
        foreach ((ulong id, QuicStream stream) in _quic.Streams)
        {
            if (!stream.Id.IsServerInitiated || !stream.Id.IsBidirectional || _routedServerBidi.Contains(id))
                continue;
            if (!_serverBidiHeaders.TryGetValue(id, out List<byte>? buffer))
                _serverBidiHeaders[id] = buffer = [];
            buffer.AddRange(stream.Read());

            var reader = new BufferReader(buffer.ToArray());
            if (!reader.TryReadVarInt(out ulong signal))
                continue; // Kopf noch unvollständig
            if (signal != WebTransportConstants.BidiStreamSignal || !reader.TryReadVarInt(out ulong sessionId))
            {
                if (signal != WebTransportConstants.BidiStreamSignal)
                {
                    _routedServerBidi.Add(id); // kein WT-Stream ⇒ nicht mehr betrachten
                    _serverBidiHeaders.Remove(id);
                }
                continue;
            }
            _routedServerBidi.Add(id);
            _serverBidiHeaders.Remove(id);
            _webTransport.ClaimStream(stream, sessionId, buffer.Skip(reader.Position).ToArray(), bidirectional: true);
        }
    }

    private readonly HashSet<ulong> _routedServerBidi = [];

    /// <summary>
    /// Verarbeitet den WebTransport-CONNECT-Stream (draft §5.6/§6): DATA-Frames tragen Capsules; deren
    /// Wert-Bytes werden akkumuliert und als Capsules an die Session gereicht. FIN beendet die Session.
    /// </summary>
    private void ProcessWebTransportConnectStream(RequestState state, WebTransportSession session)
    {
        if (state.Buffer.Count > 0 &&
            Http3Frames.TryReadAll(state.Buffer.Memory, out List<Http3Frame> frames, out int consumed))
        {
            foreach (Http3Frame frame in frames)
                if (frame.Type == Http3FrameType.Data)
                    state.CapsuleBuffer.Append(frame.Payload.Span);
            state.Buffer.Consume(consumed);
        }
        if (state.CapsuleBuffer.Count > 0)
        {
            List<WebTransportCapsule> capsules = WebTransportCapsule.ReadAll(state.CapsuleBuffer.Memory, out int used);
            foreach (WebTransportCapsule capsule in capsules)
                session.HandleCapsule(capsule);
            state.CapsuleBuffer.Consume(used);
        }
        if ((state.Stream.IsReceiveComplete || state.Stream.IsResetByPeer) && !session.IsClosed)
            session.OnConnectStreamClosed(); // §6: CONNECT-Stream geschlossen ⇒ Session beendet
    }

    // ---- IWebTransportHost (draft-webtrans-http3) -----------------------------------------

    /// <summary>Anfangs-Flow-Control-Limits, die wir je Session gewähren (draft §5.5).</summary>
    internal ulong LocalInitialMaxStreamsUni { get; init; } = 16;
    internal ulong LocalInitialMaxStreamsBidi { get; init; } = 16;
    internal ulong LocalInitialMaxData { get; init; } = 1_048_576;

    bool IWebTransportHost.FlowControlEnabled => _wtMaxSessions > 1 && _qpack.PeerWtMaxSessions > 1; // §5.1
    ulong IWebTransportHost.LocalInitialMaxStreamsUni => LocalInitialMaxStreamsUni;
    ulong IWebTransportHost.LocalInitialMaxStreamsBidi => LocalInitialMaxStreamsBidi;
    ulong IWebTransportHost.LocalInitialMaxData => LocalInitialMaxData;
    ulong IWebTransportHost.PeerInitialMaxStreamsUni => _qpack.PeerWtInitialMaxStreamsUni;
    ulong IWebTransportHost.PeerInitialMaxStreamsBidi => _qpack.PeerWtInitialMaxStreamsBidi;
    ulong IWebTransportHost.PeerInitialMaxData => _qpack.PeerWtInitialMaxData;

    byte[] IWebTransportHost.ExportKeyingMaterial(string label, ReadOnlySpan<byte> context, int length)
        => _quic.ExportKeyingMaterial(label, context, length); // RFC 8446 §7.5 / draft §4.7

    QuicStream IWebTransportHost.OpenWebTransportUniStream(ulong sessionId)
    {
        QuicStream stream = _quic.OpenUnidirectionalStream();
        stream.Write(WebTransportStreamHeader(WebTransportConstants.UniStreamType, sessionId)); // 0x54 ‖ Session-ID
        return stream;
    }

    QuicStream IWebTransportHost.OpenWebTransportBidiStream(ulong sessionId)
    {
        QuicStream stream = _quic.OpenBidirectionalStream();
        stream.Write(WebTransportStreamHeader(WebTransportConstants.BidiStreamSignal, sessionId)); // 0x41 ‖ Session-ID
        return stream;
    }

    bool IWebTransportHost.SendWebTransportDatagram(ulong sessionId, byte[] payload)
        => TrySendHttpDatagram(sessionId, payload); // §4.4: Quarter Stream ID = CONNECT-Stream

    void IWebTransportHost.WriteConnectStreamData(ulong sessionId, byte[] data)
    {
        if (_requests.TryGetValue(sessionId, out RequestState? state))
            state.Stream.Write(Http3Frames.Build(Http3FrameType.Data, data)); // Capsules in DATA-Frames
    }

    void IWebTransportHost.FinishConnectStream(ulong sessionId)
    {
        if (_requests.TryGetValue(sessionId, out RequestState? state))
            state.Stream.Finish();
    }

    private static byte[] WebTransportStreamHeader(ulong signal, ulong sessionId)
    {
        var writer = new BufferWriter(16);
        try
        {
            writer.WriteVarInt(signal);
            writer.WriteVarInt(sessionId);
            return writer.WrittenSpan.ToArray();
        }
        finally { writer.Dispose(); }
    }

    /// <summary>
    /// Verarbeitet EIN Frame des Antwort-Streams gemäß RFC 9114 §4.1/§7.2. Gibt <c>false</c> zurück,
    /// wenn ein Verbindungsfehler gemeldet wurde; <paramref name="blocked"/> zeigt eine blockierte
    /// QPACK-Sektion an (Frame noch nicht konsumieren).
    /// </summary>
    private bool ProcessResponseFrame(RequestState state, Http3Frame frame, out bool blocked)
    {
        blocked = false;

        // WebTransport-CONNECT-Stream (draft §5.6): DATA-Frames tragen Capsules — im selben Flight mit
        // der 2xx-Sektion eintreffende sammeln, statt sie als HTTP zu deuten.
        if (state.WebTransportSession is not null)
        {
            if (frame.Type == Http3FrameType.Data)
                state.CapsuleBuffer.Append(frame.Payload.Span);
            return true;
        }

        // Tunnel-Modus (Extended CONNECT angenommen, RFC 9114 §4.4): nur noch DATA-Frames erlaubt.
        if (state.Tunnel is not null)
        {
            if (frame.Type == Http3FrameType.Data)
            {
                state.Tunnel.Deliver(frame.Payload.ToArray());
                return true;
            }
            if (frame.Type is Http3FrameType.Headers or Http3FrameType.Settings or Http3FrameType.GoAway
                           or Http3FrameType.MaxPushId or Http3FrameType.CancelPush or Http3FrameType.PushPromise
                           or Http3FrameType.PriorityUpdateRequest or Http3FrameType.PriorityUpdatePush ||
                Http3Qpack.IsReservedHttp2FrameType(frame.Type))
            {
                FatalConnectionError(Http3Error.FrameUnexpected, "non-DATA frame on CONNECT stream"); // §4.4
                return false;
            }
            return true; // unbekannte Typen (Grease/Extensions) ignorieren (§9)
        }

        switch (frame.Type)
        {
            case Http3FrameType.Headers when state.TrailersSeen:
                FatalConnectionError(Http3Error.FrameUnexpected, "HEADERS after trailers"); // §4.1
                return false;
            case Http3FrameType.Headers:
                List<HeaderField>? headers = _qpack.TryDecodeHeaders(state.Stream.Id.Value, frame.Payload.Span);
                if (headers is null)
                {
                    blocked = true;
                    return true;
                }
                // §4.2.2: eine Field Section über unserem angekündigten Limit können wir nicht
                // verarbeiten — die Antwort wird verworfen („A client can discard responses …").
                if (_localMaxFieldSectionSize is { } limit && Http3Qpack.FieldSectionSize(headers) > limit)
                {
                    state.TooLarge = true;
                    state.Stream.Reset(Http3Error.RequestCancelled);     // kein Interesse mehr (§4.1.1)
                    state.Stream.AbortRead(Http3Error.RequestCancelled);
                    return true;
                }
                if (state.FinalHeadersSeen)
                {
                    // Trailer-Sektion (§4.1 Punkt 3) — nach Content ODER direkt nach der finalen
                    // Sektion. §4.3: Pseudo-Header sind in Trailern verboten.
                    if (Http3MessageValidator.ValidateTrailers(headers) is not null)
                    {
                        MarkMalformed(state, "malformed trailer section");
                        return true;
                    }
                    state.TrailersSeen = true;
                    state.Trailers.AddRange(headers);
                }
                else if (Http3MessageValidator.ValidateResponseHeaders(headers, out int status) is { } problem)
                {
                    // §4.1.2: Clients DÜRFEN malformed Responses nicht akzeptieren.
                    MarkMalformed(state, problem);
                    return true;
                }
                else if (status is >= 100 and <= 199)
                {
                    // Interim-Response (1xx, §4.1): geht der finalen Antwort voraus, KEIN Teil davon.
                    state.Interim.Add(new Http3InterimResponse(status, headers));
                }
                else if (state.IsConnect)
                {
                    // Extended-CONNECT-Antwort (RFC 8441/9220/webtrans): 2xx ⇒ der Stream wird zum Tunnel
                    // bzw. zur WebTransport-Session; sonst normale (abgelehnte) Antwort bis zum FIN.
                    state.Headers.AddRange(headers);
                    state.ConnectStatus = status;
                    if (status is >= 200 and < 300 && state.IsWebTransport)
                    {
                        // WebTransport-Session etabliert (draft §3.2): CONNECT-Stream trägt fortan Capsules.
                        var session = new WebTransportSession(state.Stream.Id.Value, this)
                        {
                            NegotiatedProtocol = SelectNegotiatedProtocol(state, headers), // draft §3.3
                        };
                        state.WebTransportSession = session;
                        _webTransport.RegisterSession(session);
                    }
                    else if (status is >= 200 and < 300)
                    {
                        ulong tunnelStreamId = state.Stream.Id.Value;
                        state.Tunnel = new Http3Tunnel(state.Stream)
                        {
                            DatagramSender = payload => TrySendHttpDatagram(tunnelStreamId, payload), // RFC 9297
                        };
                    }
                    else
                        state.FinalHeadersSeen = true;
                }
                else
                {
                    state.Headers.AddRange(headers); // die finale Header-Sektion
                    state.FinalHeadersSeen = true;
                }
                return true;

            case Http3FrameType.Data when state.TrailersSeen:
                FatalConnectionError(Http3Error.FrameUnexpected, "DATA after trailers"); // §4.1
                return false;
            case Http3FrameType.Data when !state.FinalHeadersSeen && state.Interim.Count > 0:
                // Framing wäre gültig (HEADERS→DATA), aber Interim-Responses tragen KEINEN Content (§4.1)
                // ⇒ malformed ⇒ STREAM-Error H3_MESSAGE_ERROR (§4.1.2), kein Verbindungsfehler.
                MarkMalformed(state, "DATA after interim response");
                return true;
            case Http3FrameType.Data when !state.FinalHeadersSeen:
                FatalConnectionError(Http3Error.FrameUnexpected, "DATA before HEADERS"); // §4.1
                return false;
            case Http3FrameType.Data:
                state.DataSeen = true;
                state.Body.AddRange(frame.Payload.ToArray());
                return true;

            case Http3FrameType.Settings:
                FatalConnectionError(Http3Error.FrameUnexpected, "SETTINGS on request stream"); // §7.2.4
                return false;
            case Http3FrameType.GoAway:
                FatalConnectionError(Http3Error.FrameUnexpected, "GOAWAY on request stream");   // §7.2.6
                return false;
            case Http3FrameType.MaxPushId:
                FatalConnectionError(Http3Error.FrameUnexpected, "MAX_PUSH_ID sent to client"); // §7.2.7
                return false;
            case Http3FrameType.CancelPush:
                FatalConnectionError(Http3Error.FrameUnexpected, "CANCEL_PUSH on request stream"); // §7.2.3
                return false;
            case Http3FrameType.PushPromise:
                // §4.6/§7.2.5: wir haben nie ein MAX_PUSH_ID gesendet ⇒ jede Push-ID ist zu groß.
                FatalConnectionError(Http3Error.IdError, "PUSH_PROMISE without MAX_PUSH_ID");
                return false;
            case Http3FrameType.PriorityUpdateRequest:
            case Http3FrameType.PriorityUpdatePush:
                // RFC 9218 §7.2: Server MÜSSEN NIE PRIORITY_UPDATE senden (und schon gar nicht hier).
                FatalConnectionError(Http3Error.FrameUnexpected, "PRIORITY_UPDATE sent to client");
                return false;

            default:
                if (Http3Qpack.IsReservedHttp2FrameType(frame.Type))
                {
                    FatalConnectionError(Http3Error.FrameUnexpected, "reserved HTTP/2 frame type"); // §7.2.8
                    return false;
                }
                return true; // unbekannte Typen (inkl. Grease) ignorieren (§9)
        }
    }

    /// <summary>
    /// Behandelt eine malformed Response als STREAM-Fehler H3_MESSAGE_ERROR (RFC 9114 §4.1.2):
    /// die Antwort DARF NICHT akzeptiert werden; der Stream wird abgebrochen, die Verbindung lebt weiter.
    /// </summary>
    private static void MarkMalformed(RequestState state, string reason)
    {
        _ = reason;
        state.Malformed = true;
        state.Stream.Reset(Http3Error.MessageError);
        state.Stream.AbortRead(Http3Error.MessageError);
    }

    /// <summary>
    /// Liest den <c>:status</c>-Pseudo-Header einer Header-Sektion (0, wenn nicht vorhanden/ungültig).
    /// </summary>
    private static int ParseStatus(List<HeaderField> headers)
    {
        foreach (HeaderField h in headers)
            if (h.Name == ":status")
                return int.TryParse(h.Value, out int status) ? status : 0;
        return 0;
    }

    /// <summary>
    /// <c>true</c>, wenn die Antwort als malformed verworfen wurde (RFC 9114 §4.1.2 —
    /// Stream-Fehler H3_MESSAGE_ERROR; Clients MÜSSEN malformed Responses ablehnen).
    /// </summary>
    public bool IsResponseMalformed(ulong streamId)
        => _requests.TryGetValue(streamId, out RequestState? state) && state.Malformed;

    /// <summary>
    /// <c>true</c>, wenn eine Antwort-Field-Section unser angekündigtes
    /// SETTINGS_MAX_FIELD_SECTION_SIZE überschritt und die Antwort verworfen wurde (RFC 9114 §4.2.2).
    /// </summary>
    public bool IsResponseTooLarge(ulong streamId)
        => _requests.TryGetValue(streamId, out RequestState? state) && state.TooLarge;

    private byte[] BuildSettings()
    {
        var writer = new BufferWriter(16);
        try
        {
            writer.WriteVarInt(Http3Setting.QpackMaxTableCapacity);
            writer.WriteVarInt(_qpack.LocalMaxCapacity);
            writer.WriteVarInt(Http3Setting.QpackBlockedStreams);
            writer.WriteVarInt(_qpack.LocalMaxCapacity > 0 ? 16u : 0u);
            if (_localMaxFieldSectionSize is { } maxFieldSection)
            {
                writer.WriteVarInt(Http3Setting.MaxFieldSectionSize); // RFC 9114 §4.2.2
                writer.WriteVarInt(maxFieldSection);
            }
            if (_localDatagramsEnabled)
            {
                writer.WriteVarInt(Http3Setting.H3Datagram); // RFC 9297 §2.1.1
                writer.WriteVarInt(1);
            }
            if (_wtMaxSessions > 0) // draft-webtrans-http3 §3.1: Client kündigt WT_MAX_SESSIONS > 0 an
            {
                writer.WriteVarInt(WebTransportConstants.SettingMaxSessions);
                writer.WriteVarInt(_wtMaxSessions);
                writer.WriteVarInt(WebTransportConstants.SettingInitialMaxStreamsUni);
                writer.WriteVarInt(LocalInitialMaxStreamsUni);
                writer.WriteVarInt(WebTransportConstants.SettingInitialMaxStreamsBidi);
                writer.WriteVarInt(LocalInitialMaxStreamsBidi);
                writer.WriteVarInt(WebTransportConstants.SettingInitialMaxData);
                writer.WriteVarInt(LocalInitialMaxData);
            }
            // Grease-Setting (RFC 9114 §7.2.4.1 SHOULD): 0x1f·N + 0x21 — Empfänger MÜSSEN es ignorieren.
            writer.WriteVarInt(0x1f * 4 + 0x21);
            writer.WriteVarInt(0);
            return writer.WrittenSpan.ToArray();
        }
        finally { writer.Dispose(); }
    }

    public void Dispose() => _quic.Dispose();

    private sealed class RequestState(QuicStream stream)
    {
        public QuicStream Stream { get; } = stream;
        public string Method { get; init; } = "GET"; // für die Content-Length-Ausnahme (HEAD, §4.1.2)
        public bool IsConnect { get; init; }         // Extended CONNECT (RFC 8441/9220)
        public bool IsWebTransport { get; set; }     // :protocol = webtransport (draft-webtrans-http3)
        public List<string>? OfferedWtProtocols { get; set; } // per WT-Available-Protocols angeboten (draft §3.3)
        public int? ConnectStatus { get; set; }      // Status der CONNECT-Antwort, sobald empfangen
        public Http3Tunnel? Tunnel { get; set; }     // Tunnel nach 2xx-Annahme, sonst null
        public WebTransportSession? WebTransportSession { get; set; } // WebTransport-Session (draft-webtrans-http3)
        public ByteQueue CapsuleBuffer { get; } = new(); // Capsule-Protokoll-Bytes des WT-CONNECT-Streams
        public ByteQueue Buffer { get; } = new();
        public Queue<Http3Frame> Pending { get; } = new(); // geparste, noch zu verarbeitende Frames
        public List<HeaderField> Headers { get; } = [];
        public List<byte> Body { get; } = [];
        public List<Http3InterimResponse> Interim { get; } = []; // 1xx-Sektionen vor der finalen Antwort (§4.1)
        public List<HeaderField> Trailers { get; } = [];         // Trailer-Sektion (§4.1 Punkt 3)
        public bool Complete { get; set; }
        public bool Cancelled { get; set; }        // von uns abgebrochen (RFC 9114 §4.1.1)
        public bool Rejected { get; set; }         // per GOAWAY zurückgewiesen (§5.2) ⇒ gefahrlos wiederholbar
        public bool Malformed { get; set; }        // malformed Response verworfen (§4.1.2, H3_MESSAGE_ERROR)
        public bool TooLarge { get; set; }         // Field Section über unserem Limit verworfen (§4.2.2)
        public bool FinalHeadersSeen { get; set; } // finale (nicht-1xx) Header-Sektion dekodiert (§4.1)
        public bool DataSeen { get; set; }         // Content begonnen
        public bool TrailersSeen { get; set; }     // Trailer-Sektion gesehen ⇒ danach sind Frames illegal
    }
}
