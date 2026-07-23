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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Ein HTTP/3-Server (RFC 9114) über einer <see cref="QuicServerConnection"/>. Öffnet nach dem
/// Handshake den Control-Stream (mit SETTINGS) und die QPACK-Streams, nimmt auf bidirektionalen
/// Streams Requests entgegen (HEADERS via QPACK) und beantwortet sie mit dem übergebenen Handler
/// (HEADERS + DATA). Transport-agnostisch: Datagramme über <see cref="GetDatagramsToSend"/> /
/// <see cref="ProcessDatagram"/>.
/// </summary>
public sealed class Http3ServerConnection : IDisposable, IWebTransportHost
{
    private readonly QuicServerConnection _quic;
    private readonly Func<Http3Request, Http3Response> _handler;
    private readonly Dictionary<ulong, RequestState> _requests = [];
    private readonly Http3Qpack _qpack;
    private bool _http3Initialized;
    private QuicStream? _controlStream;      // unser Control-Stream (SETTINGS, GOAWAY)
    private ulong? _goAwayId;                // per GOAWAY angekündigte Grenze (RFC 9114 §5.2)
    private bool _goAwayPending;             // Shutdown angefordert, bevor der Control-Stream stand
    private ulong? _highestRequestStreamId;  // höchste bisher angenommene Request-Stream-ID
    private readonly WebTransportManager _webTransport = new(weAreClient: false);
    private readonly ulong _wtMaxSessions;   // draft-webtrans-http3 §9.2 (0 = WebTransport aus)
    private readonly Func<Http3Request, Action<WebTransportSession>?>? _webTransportHandler;
    private readonly Func<Http3Request, IReadOnlyList<string>, string?>? _webTransportProtocolSelector;
    private int _wtSessionCount;

    /// <param name="qpackMaxTableCapacity">
    /// Angekündigte maximale QPACK-Tabellenkapazität (RFC 9204). Standard 4096 aktiviert die dynamische
    /// Tabelle; ein rein statischer Client (Kapazität 0) löst sie nicht aus, daher interop-sicher.
    /// </param>
    /// <param name="maxFieldSectionSize">
    /// Optionales Limit für die Größe angenommener Field Sections (RFC 9114 §4.2.2, unkomprimiert:
    /// Name + Wert + 32 je Feld). Wird per SETTINGS_MAX_FIELD_SECTION_SIZE angekündigt; größere
    /// Request-Header-Sektionen werden mit **431 Request Header Fields Too Large** beantwortet,
    /// ohne den Handler aufzurufen. <c>null</c> = unbegrenzt.
    /// </param>
    /// <param name="connectHandler">
    /// Optionaler Handler für Extended CONNECT (RFC 8441/9220): ist er gesetzt, kündigt der Server
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 an; er entscheidet je Request (z. B. :protocol
    /// „websocket") über Annahme (2xx + <see cref="Http3ConnectResult.OnTunnel"/>) oder Ablehnung.
    /// Unbekannte :protocol-Werte SOLLEN mit 501 beantwortet werden (RFC 9220 §3).
    /// </param>
    /// <param name="webTransportProtocolSelector">
    /// Optionale ALPN-artige Protokollwahl je WebTransport-Session (draft-webtrans-http3 §3.3): erhält
    /// den Request und die per <c>WT-Available-Protocols</c> angebotenen Protokolle (Präferenz zuerst)
    /// und wählt EINES davon (die 2xx-Antwort trägt es als <c>WT-Protocol</c>) oder <c>null</c> (kein
    /// Header). Eine Wahl außerhalb der Angebotsliste wird verworfen (draft-MUST).
    /// </param>
    public Http3ServerConnection(
        ServerCertificate certificate,
        Func<Http3Request, Http3Response> handler,
        TransportParameters? transportParameters = null,
        bool requireRetry = false,
        ulong qpackMaxTableCapacity = 4096,
        IReadOnlyList<Quic.Tls.NamedGroup>? preferredGroups = null,
        Quic.Tls.ServerResumptionCache? resumptionCache = null,
        uint maxEarlyDataSize = 0,
        Quic.Packets.StatelessResetTokenGenerator? statelessResetTokens = null,
        ulong? maxFieldSectionSize = null,
        Func<Http3Request, Http3ConnectResult>? connectHandler = null,
        bool enableDatagrams = false,
        ulong webTransportMaxSessions = 0,
        Func<Http3Request, Action<WebTransportSession>?>? webTransportHandler = null,
        Func<Http3Request, IReadOnlyList<string>, string?>? webTransportProtocolSelector = null)
    {
        _connectHandler = connectHandler;
        _wtMaxSessions = webTransportMaxSessions;
        _webTransportHandler = webTransportHandler;
        _webTransportProtocolSelector = webTransportProtocolSelector;
        // WebTransport setzt Extended CONNECT + HTTP/3-Datagramme voraus (draft §3.1) ⇒ beides mit aktivieren.
        if (webTransportMaxSessions > 0)
            enableDatagrams = true;
        _localDatagramsEnabled = enableDatagrams;
        if (enableDatagrams)
        {
            transportParameters ??= new TransportParameters();
            transportParameters.MaxDatagramFrameSizeValue = 65535; // RFC 9221 §3 RECOMMENDED
        }
        _quic = new QuicServerConnection(certificate, transportParameters, requireRetry: requireRetry, preferredGroups: preferredGroups, resumptionCache: resumptionCache, maxEarlyDataSize: maxEarlyDataSize, statelessResetTokens: statelessResetTokens);
        _handler = handler;
        _qpack = new Http3Qpack(qpackMaxTableCapacity, weAreClient: false, FatalConnectionError)
        {
            OnPriorityUpdate = ApplyPriorityUpdate, // RFC 9218 §7.2
            OnWebTransportUniStream = (stream, sessionId, leftover) =>
                _webTransport.ClaimStream(stream, sessionId, leftover, bidirectional: false),
        };
        _localMaxFieldSectionSize = maxFieldSectionSize;
    }

    /// <summary>
    /// Obergrenze gepufferter PRIORITY_UPDATEs für noch nicht geöffnete Streams (RFC 9218 §7:
    /// „bounded by local implementation policy" — nur das jeweils letzte Update je Stream zählt).
    /// </summary>
    private const int MaxPendingPriorityUpdates = 32;
    private readonly Dictionary<ulong, Http3Priority> _pendingPriorityUpdates = [];

    /// <summary>
    /// Wendet ein PRIORITY_UPDATE (RFC 9218) an: existiert der Request-Stream schon, wird der
    /// Sende-Scheduler direkt umgestellt (das Update überschreibt den <c>priority</c>-Header);
    /// sonst wird das jeweils LETZTE Update gepuffert und beim Öffnen des Streams angewandt (§7).
    /// </summary>
    private void ApplyPriorityUpdate(ulong streamId, string priorityFieldValue)
    {
        Http3Priority priority = Http3Priority.Parse(priorityFieldValue);
        if (_quic.Streams.TryGetValue(streamId, out QuicStream? stream))
        {
            stream.SendUrgency = priority.Urgency;
            stream.SendIncremental = priority.Incremental;
            if (_requests.TryGetValue(streamId, out RequestState? state))
                state.PriorityUpdated = true; // §7: das Update übertrumpft jeden Header
        }
        else if (_pendingPriorityUpdates.Count < MaxPendingPriorityUpdates || _pendingPriorityUpdates.ContainsKey(streamId))
            _pendingPriorityUpdates[streamId] = priority;
    }

    private readonly ulong? _localMaxFieldSectionSize; // unser angekündigtes Limit (RFC 9114 §4.2.2)
    private readonly Func<Http3Request, Http3ConnectResult>? _connectHandler; // Extended CONNECT (RFC 8441/9220)
    private readonly bool _localDatagramsEnabled;      // HTTP-Datagramme lokal aktiviert (RFC 9297)

    /// <summary>
    /// HTTP-Datagramme sind beidseitig ausgehandelt (RFC 9297 §2.1.1 + RFC 9221 §3).
    /// </summary>
    public bool DatagramsNegotiated
        => _localDatagramsEnabled && _qpack.PeerH3Datagram && _quic.PeerMaxDatagramFrameSize > 0;

    /// <summary>
    /// Sendet ein HTTP-Datagramm zum Request-Stream <paramref name="streamId"/> (RFC 9297 §2.1).
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
                continue; // Stream (noch) unbekannt ⇒ still verwerfen (§2.1 SHALL drop or buffer)

            if (state.Tunnel is { } tunnel)
            {
                if (!state.Stream.IsResetByPeer) // Empfangsseite zu ⇒ still verwerfen (§2.1)
                    tunnel.DeliverDatagram(datagram[reader.Position..]);
            }
            else if (!state.Responded)
            {
                // §2: Datagramm zu einem Request ohne Datagram-Semantik ⇒ Request beenden
                // (STREAM-Fehler H3_DATAGRAM_ERROR, kein Verbindungsfehler).
                state.Stream.Reset(Http3Error.DatagramError);
                state.Stream.AbortRead(Http3Error.DatagramError);
                state.Responded = true;
            }
        }
    }

    /// <summary>
    /// Meldet einen HTTP/3-Verbindungsfehler (RFC 9114 §8): CONNECTION_CLOSE Typ 0x1d mit H3-Fehlercode.
    /// </summary>
    private void FatalConnectionError(ulong errorCode, string reason) => _quic.CloseApplication(errorCode, reason);

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
    /// <c>true</c>, wenn der Handshake per Session Resumption (PSK) geführt wurde.
    /// </summary>
    public bool ResumptionAccepted => _quic.ResumptionAccepted;

    /// <summary>
    /// <c>true</c>, wenn 0-RTT (early_data) akzeptiert wurde.
    /// </summary>
    public bool EarlyDataAccepted => _quic.EarlyDataAccepted;

    /// <summary>
    /// Insert Count der QPACK-Encoder-Tabelle (Diagnose: &gt; 0 ⇒ dynamische Tabelle genutzt).
    /// </summary>
    public ulong QpackEncoderInsertCount => _qpack.EncoderInsertCount;

    /// <summary>
    /// Insert Count der QPACK-Decoder-Tabelle (Diagnose).
    /// </summary>
    public ulong QpackDecoderInsertCount => _qpack.DecoderInsertCount;

    /// <summary>
    /// Vom Client per Section-Ack bestätigte Insert-Anzahl unserer Encoder-Tabelle (Diagnose).
    /// </summary>
    public ulong QpackEncoderKnownReceivedCount => _qpack.EncoderKnownReceivedCount;

    public bool HandshakeComplete => _quic.HandshakeComplete;

    /// <summary>
    /// Die zugrunde liegende QUIC-Serververbindung (symmetrisch zu <see cref="Http3ClientConnection.Quic"/>).
    /// </summary>
    public QuicServerConnection Quic => _quic;

    /// <summary>
    /// <c>true</c>, sobald der Server ein Retry zur Adressvalidierung gesendet hat.
    /// </summary>
    public bool SentRetry => _quic.SentRetry;

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
    /// Das vom Peer empfangene CONNECTION_CLOSE, falls vorhanden.
    /// </summary>
    public Quic.Frames.ConnectionCloseFrame? PeerCloseFrame => _quic.PeerCloseFrame;

    /// <summary>
    /// Schließt die Verbindung sofort mit einem CONNECTION_CLOSE (RFC 9000 §10.2; Standard: NO_ERROR).
    /// </summary>
    public void Close(TransportError error = TransportError.NoError, string reason = "") => _quic.Close(error, reason);

    /// <summary>
    /// Leitet den anständigen Verbindungsabbau ein (RFC 9114 §5.2): sendet ein GOAWAY mit der ersten
    /// NICHT mehr angenommenen Request-Stream-ID. Laufende Requests werden noch zu Ende beantwortet
    /// (<see cref="HasPendingRequests"/>); später eintreffende Request-Streams ≥ der ID werden mit
    /// H3_REQUEST_REJECTED zurückgesetzt (gefahrlos auf neuer Verbindung wiederholbar). Idempotent.
    /// </summary>
    public void InitiateGracefulShutdown()
    {
        if (_goAwayId is not null)
            return; // bereits angekündigt — die ID darf nie anwachsen (§5.2)
        if (_controlStream is null)
        {
            _goAwayPending = true; // Control-Stream steht erst nach dem Handshake — dann nachholen
            return;
        }
        // Erste nicht mehr angenommene client-initiierte Bidi-Stream-ID (…, +4 = nächste; 0 = keine).
        _goAwayId = _highestRequestStreamId is { } highest ? highest + 4 : 0;
        _controlStream.Write(Http3Frames.Build(Http3FrameType.GoAway, BuildVarInt(_goAwayId.Value)));
    }

    /// <summary>
    /// Die im GOAWAY angekündigte Grenze, falls der Shutdown eingeleitet wurde.
    /// </summary>
    public ulong? GoAwaySent => _goAwayId;

    /// <summary>
    /// Es gibt noch angenommene, aber unbeantwortete Requests (nach dem GOAWAY zu Ende bedienen, §5.2).
    /// </summary>
    public bool HasPendingRequests => _requests.Values.Any(s => !s.Responded);

    /// <summary>
    /// Anzahl der bereits an den Handler übergebenen (und beantworteten) Requests.
    /// </summary>
    public int RequestsHandled { get; private set; }

    /// <summary>
    /// Schließt die Verbindung nach vollendetem Graceful Shutdown (RFC 9114 §5.2 SHOULD:
    /// CONNECTION_CLOSE Typ 0x1d mit H3_NO_ERROR).
    /// </summary>
    public void CloseGracefully() => _quic.CloseApplication(Http3Error.NoError, "graceful shutdown");

    private static byte[] BuildVarInt(ulong value)
    {
        var writer = new BufferWriter(8);
        try
        {
            writer.WriteVarInt(value);
            return writer.WrittenSpan.ToArray();
        }
        finally { writer.Dispose(); }
    }

    /// <summary>
    /// Keep-Alive-Intervall (RFC 9000 §10.1.2): sendet PINGs gegen den Idle-Timeout. <c>null</c> = aus.
    /// </summary>
    public TimeSpan? KeepAliveInterval
    {
        get => _quic.KeepAliveInterval;
        set => _quic.KeepAliveInterval = value;
    }

    /// <summary>
    /// <c>true</c>, wenn <paramref name="cid"/> eine aktive lokale Connection ID ist (CID-basiertes Demuxing für Migration).
    /// </summary>
    public bool OwnsConnectionId(Quic.Packets.ConnectionId cid) => _quic.OwnsConnectionId(cid);

    /// <summary>
    /// Startet eine Pfadvalidierung (RFC 9000 §8.2), z. B. nachdem der Client die Adresse gewechselt hat.
    /// </summary>
    public void InitiatePathValidation() => _quic.InitiatePathValidation();

    /// <summary>
    /// <c>true</c>, sobald der (neue) Pfad per PATH_CHALLENGE/PATH_RESPONSE bestätigt wurde.
    /// </summary>
    public bool PathValidated => _quic.PathValidated;

    /// <summary>
    /// <c>true</c>, sobald die Verbindung wegen Idle-Timeout still geschlossen wurde (RFC 9000 §10.1).
    /// </summary>
    public bool IsIdleTimedOut => _quic.IsIdleTimedOut;

    /// <summary>
    /// Prüft Loss-Detection-/PTO- und Idle-Timeouts (periodisch aufrufen).
    /// </summary>
    public void CheckTimeouts()
    {
        _quic.CheckLossDetectionTimeout();
        _quic.CheckIdleTimeout();
    }

    public IReadOnlyList<byte[]> GetDatagramsToSend() => _quic.GetDatagramsToSend();

    public void ProcessDatagram(ReadOnlySpan<byte> datagram)
    {
        _quic.ProcessDatagram(datagram);
        Pump();
    }

    private void Pump()
    {
        if (_quic.IsClosing || _quic.IsDraining || _quic.IsClosed)
            return; // nach einem Verbindungsfehler nichts mehr verarbeiten

        InitializeHttp3IfReady();

        // Uni-Streams des Clients (SETTINGS + QPACK-Encoder-Instruktionen) verarbeiten.
        _qpack.PumpPeerStreams(_quic.Streams);

        foreach (ulong id in _quic.TakeNewRequestStreams())
        {
            // Nach dem GOAWAY (§5.2): Request-Streams ≥ der angekündigten ID werden NICHT verarbeitet,
            // sondern explizit abgebrochen (SHOULD) — H3_REQUEST_REJECTED ⇒ gefahrlos wiederholbar.
            if (_goAwayId is { } goAway && id >= goAway)
            {
                QuicStream rejected = _quic.Streams[id];
                rejected.Reset(Http3Error.RequestRejected);
                rejected.AbortRead(Http3Error.RequestRejected);
                continue;
            }
            var newState = new RequestState(_quic.Streams[id]);
            _requests[id] = newState;
            _highestRequestStreamId = _highestRequestStreamId is { } h ? Math.Max(h, id) : id;

            // Ein VOR dem Öffnen empfangenes PRIORITY_UPDATE jetzt anwenden (RFC 9218 §7).
            if (_pendingPriorityUpdates.Remove(id, out Http3Priority pending))
            {
                newState.Stream.SendUrgency = pending.Urgency;
                newState.Stream.SendIncremental = pending.Incremental;
                newState.PriorityUpdated = true;
            }
        }

        foreach (RequestState state in _requests.Values)
        {
            if (_quic.IsClosing)
                return; // ein Verbindungsfehler wurde gemeldet
            if (state.Responded)
                continue;

            // Client-Abbruch (RFC 9114 §4.1.1): RESET_STREAM auf dem Request ⇒ Antwortseite ebenfalls
            // abbrechen — H3_REQUEST_REJECTED, wenn noch nichts verarbeitet wurde (Request gilt als nie
            // gesendet), sonst H3_REQUEST_CANCELLED. Ein STOP_SENDING des Clients hat unsere Sendeseite
            // bereits automatisch zurückgesetzt (RFC 9000 §3.5).
            if (state.Stream.IsResetByPeer)
            {
                state.Tunnel?.End(); // abrupter Tunnel-Abbruch (≙ TCP-RST, RFC 9220 §3)
                state.Stream.Reset(state.HeadersReceived ? Http3Error.RequestCancelled : Http3Error.RequestRejected);
                state.Responded = true; // erledigt – es wird keine Antwort mehr geben
                continue;
            }

            byte[] chunk = state.Stream.Read();
            if (chunk.Length > 0)
                state.Buffer.Append(chunk);

            // WebTransport-CONNECT-Stream (draft §6/§5.6): nach der 2xx-Antwort tragen die DATA-Frames
            // Capsules (Session-Steuerung/Flow Control). Nicht als HTTP-Frames weiterverarbeiten.
            if (state.WebTransportSession is { } wtSession)
            {
                ProcessWebTransportConnectStream(state, wtSession);
                continue;
            }

            // WebTransport-Bidi-Datenstrom (draft §4.2): beginnt mit WT_STREAM (0x41) ‖ Session-ID —
            // KEIN HTTP-Request. An den WebTransport-Manager übergeben.
            if (_wtMaxSessions > 0 && !state.HeadersReceived)
            {
                WtBidiResult wt = ClassifyWebTransportBidi(state);
                if (wt == WtBidiResult.Claimed)
                {
                    _webTransportClaimed.Add(state.Stream.Id.Value); // nach der Schleife aus _requests entfernen
                    continue;
                }
                if (wt == WtBidiResult.NeedMore)
                    continue; // Kopf noch unvollständig – nächster Pump
            }

            if (state.Buffer.Count > 0 &&
                Http3Frames.TryReadAll(state.Buffer.Memory, out List<Http3Frame> frames, out int consumed))
            {
                foreach (Http3Frame frame in frames)
                    state.Pending.Enqueue(frame);
                state.Buffer.Consume(consumed);
            }

            // Frame-Zustandsmaschine des Request-Streams (RFC 9114 §4.1, §7.2): HEADERS, dann Content
            // als Serie von DATA-Frames, optional eine Trailer-Sektion; eine blockierte QPACK-Sektion
            // hält die Reihe an (wartet auf den Encoder-Stream).
            while (state.Pending.Count > 0 && !state.Responded)
            {
                Http3Frame frame = state.Pending.Peek();
                if (!ProcessRequestFrame(state, frame, out bool blocked))
                    return; // Verbindungsfehler gemeldet
                if (blocked)
                    break;
                state.Pending.Dequeue();
            }

            // Tunnel-Streams (Extended CONNECT): ein FIN des Clients ist das geordnete Tunnel-Ende
            // (≙ TCP-Close, RFC 9220 §3) — kein normales Nachrichten-Ende.
            if (state.Tunnel is not null)
            {
                if (state.Stream.IsReceiveComplete && state.Pending.Count == 0)
                    state.Tunnel.End();
                continue;
            }

            // Antworten, sobald die Nachricht VOLLSTÄNDIG ist (FIN empfangen, alle Frames verarbeitet) –
            // erst dann steht der Request-Rumpf fest (RFC 9114 §4.1).
            if (!state.Responded && state.Stream.IsReceiveComplete && state.Pending.Count == 0)
            {
                // §7.1: endet der Stream sauber mitten in einem Frame, ist das ein H3_FRAME_ERROR.
                if (state.Buffer.Count > 0)
                {
                    FatalConnectionError(Http3Error.FrameError, "truncated frame at end of stream");
                    return;
                }
                if (state.HeadersReceived && state.Request is not null)
                {
                    // §4.1.2: ein vorhandener content-length MUSS der Summe der DATA-Längen entsprechen.
                    if (Http3MessageValidator.ValidateContentLength(state.Request.AdditionalHeaders,
                            (ulong)state.Body.Count, contentNeverPresent: false) is { } lengthProblem)
                    {
                        RejectMalformedRequest(state, lengthProblem);
                        continue;
                    }
                    Http3Request request = state.Request;
                    if (state.Body.Count > 0)
                        request = request with { Body = [.. state.Body] };
                    if (state.Trailers.Count > 0)
                        request = request with { Trailers = state.Trailers };
                    SendResponse(state.Stream.Id.Value, state.Stream, _handler(request));
                    state.Responded = true;
                    RequestsHandled++;
                }
            }
        }

        // Als WebTransport-Bidi-Streams erkannte „Requests" aus der Request-Verwaltung nehmen
        // (der WebTransport-Manager liest sie fortan).
        foreach (ulong claimed in _webTransportClaimed)
            _requests.Remove(claimed);
        _webTransportClaimed.Clear();

        // HTTP-Datagramme ZULETZT zuordnen (RFC 9297 §2.1): so sind Request-Streams/Tunnel aus
        // demselben Flight bereits angelegt, statt die Datagramme als „unbekannt" zu verwerfen.
        DispatchReceivedDatagrams();
    }

    private readonly List<ulong> _webTransportClaimed = [];

    private enum WtBidiResult { NotWebTransport, NeedMore, Claimed }

    /// <summary>
    /// Klassifiziert einen client-initiierten Bidi-Stream: WT_STREAM (0x41) ‖ Session-ID ⇒ WebTransport
    /// (draft §4.2), an den Manager übergeben; sonst normaler HTTP-Request.
    /// </summary>
    private WtBidiResult ClassifyWebTransportBidi(RequestState state)
    {
        var reader = new BufferReader(state.Buffer.Span);
        if (!reader.TryReadVarInt(out ulong signal))
            return WtBidiResult.NeedMore; // erstes VarInt noch unvollständig
        if (signal != WebTransportConstants.BidiStreamSignal)
            return WtBidiResult.NotWebTransport;
        if (!reader.TryReadVarInt(out ulong sessionId))
            return WtBidiResult.NeedMore; // Session-ID noch unvollständig

        byte[] leftover = state.Buffer.Span[reader.Position..].ToArray();
        _webTransport.ClaimStream(state.Stream, sessionId, leftover, bidirectional: true);
        return WtBidiResult.Claimed;
    }

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

    private void InitializeHttp3IfReady()
    {
        if (_http3Initialized || !_quic.HandshakeComplete)
            return;

        QuicStream control = _quic.OpenUnidirectionalStream();
        control.SendUrgency = 0; // kritische Streams nie hinter Bulk-Antworten verhungern lassen (RFC 9218 §10)
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, BuildSettings()));
        _controlStream = control;

        QuicStream encoderStream = _quic.OpenUnidirectionalStream();
        encoderStream.SendUrgency = 0;
        encoderStream.Write([(byte)Http3StreamType.QpackEncoder]);
        _qpack.SetEncoderStream(encoderStream);
        QuicStream decoderStream = _quic.OpenUnidirectionalStream();
        decoderStream.SendUrgency = 0;
        decoderStream.Write([(byte)Http3StreamType.QpackDecoder]);
        _qpack.SetDecoderStream(decoderStream);

        // Dem Client eine Reserve-Connection-ID anbieten (RFC 9000 §5.1), sofern sein Limit es zulässt.
        _quic.IssueConnectionId();

        _http3Initialized = true;

        // Ein vor dem Handshake angeforderter Graceful Shutdown wird jetzt nachgeholt (§5.2).
        if (_goAwayPending)
        {
            _goAwayPending = false;
            InitiateGracefulShutdown();
        }
    }

    /// <summary>
    /// Verarbeitet EIN Frame des Request-Streams gemäß RFC 9114 §4.1/§7.2. Gibt <c>false</c> zurück,
    /// wenn ein Verbindungsfehler gemeldet wurde; <paramref name="blocked"/> zeigt eine blockierte
    /// QPACK-Sektion an (Frame noch nicht konsumieren).
    /// </summary>
    private bool ProcessRequestFrame(RequestState state, Http3Frame frame, out bool blocked)
    {
        blocked = false;

        // WebTransport-CONNECT-Stream (draft §5.6): ab jetzt tragen DATA-Frames Capsules — im selben
        // Flight mit der CONNECT-HEADERS-Sektion eintreffende sammeln, statt sie als HTTP zu deuten.
        if (state.WebTransportSession is not null)
        {
            if (frame.Type == Http3FrameType.Data)
                state.CapsuleBuffer.Append(frame.Payload.Span);
            return true;
        }

        // Tunnel-Modus (Extended CONNECT, RFC 9114 §4.4): nach der CONNECT-Annahme sind auf dem
        // Stream nur noch DATA-Frames erlaubt — sie tragen die getunnelten Bytes.
        if (state.Tunnel is not null)
        {
            if (frame.Type == Http3FrameType.Data)
            {
                state.Tunnel.Deliver(frame.Payload.ToArray());
                return true;
            }
            if (frame.Type == Http3FrameType.Headers || Http3FrameType.CancelPush == frame.Type ||
                frame.Type is Http3FrameType.Settings or Http3FrameType.PushPromise or Http3FrameType.GoAway
                           or Http3FrameType.MaxPushId or Http3FrameType.PriorityUpdateRequest
                           or Http3FrameType.PriorityUpdatePush ||
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
                if (_qpack.TryDecodeHeaders(state.Stream.Id.Value, frame.Payload.Span) is not { } headers)
                {
                    blocked = true;
                    return true;
                }
                // §4.2.2: Request-Header-Sektion über unserem angekündigten Limit ⇒ 431 (RFC 6585)
                // OHNE Handler-Aufruf; das Restlesen wird mit H3_NO_ERROR abgebrochen (§4.1).
                if (_localMaxFieldSectionSize is { } limit && Http3Qpack.FieldSectionSize(headers) > limit)
                {
                    state.Stream.AbortRead(Http3Error.NoError);
                    SendResponse(state.Stream.Id.Value, state.Stream,
                        new Http3Response { Status = 431 }); // Request Header Fields Too Large
                    state.Responded = true; // beendet die Frame-Verarbeitung dieses Streams
                    return true;
                }
                if (!state.HeadersReceived)
                {
                    // Malformed-Prüfung (§4.1.2/§4.3.1): Pseudo-Header-Pflichten/-Verbote, Feldregeln.
                    if (Http3MessageValidator.ValidateRequestHeaders(headers) is { } problem)
                    {
                        RejectMalformedRequest(state, problem);
                        return true;
                    }
                    state.Request = BuildRequest(headers);
                    state.HeadersReceived = true;

                    // `priority`-Header (RFC 9218 §5) auf den Sende-Scheduler anwenden — außer ein
                    // PRIORITY_UPDATE hat die Priorität bereits überschrieben (§7: Update gewinnt).
                    if (!state.PriorityUpdated &&
                        state.Request.AdditionalHeaders.FirstOrDefault(h => h.Name == "priority") is { Name: "priority" } prio)
                    {
                        Http3Priority parsed = Http3Priority.Parse(prio.Value);
                        state.Stream.SendUrgency = parsed.Urgency;
                        state.Stream.SendIncremental = parsed.Incremental;
                    }

                    // CONNECT wird SOFORT behandelt (§4.4/RFC 8441): der Stream bleibt offen —
                    // auf ein FIN zu warten wäre für einen Tunnel sinnlos.
                    if (state.Request.Method == "CONNECT")
                        return HandleConnect(state);
                }
                else
                {
                    // Trailer-Sektion (§4.1 Punkt 3); §4.3: Pseudo-Header sind in Trailern verboten.
                    if (Http3MessageValidator.ValidateTrailers(headers) is { } trailerProblem)
                    {
                        RejectMalformedRequest(state, trailerProblem);
                        return true;
                    }
                    state.TrailersSeen = true;
                    state.Trailers.AddRange(headers);
                }
                return true;

            case Http3FrameType.Data when !state.HeadersReceived || state.TrailersSeen:
                FatalConnectionError(Http3Error.FrameUnexpected, "DATA outside message content"); // §4.1
                return false;
            case Http3FrameType.Data:
                state.Body.AddRange(frame.Payload.ToArray());
                return true;

            case Http3FrameType.Settings:
                FatalConnectionError(Http3Error.FrameUnexpected, "SETTINGS on request stream"); // §7.2.4
                return false;
            case Http3FrameType.GoAway:
                FatalConnectionError(Http3Error.FrameUnexpected, "GOAWAY on request stream");   // §7.2.6
                return false;
            case Http3FrameType.MaxPushId:
                FatalConnectionError(Http3Error.FrameUnexpected, "MAX_PUSH_ID on request stream"); // §7.2.7
                return false;
            case Http3FrameType.CancelPush:
                FatalConnectionError(Http3Error.FrameUnexpected, "CANCEL_PUSH on request stream"); // §7.2.3
                return false;
            case Http3FrameType.PushPromise:
                // §7.2.5: Clients senden NIE PUSH_PROMISE; der Server MUSS mit H3_FRAME_UNEXPECTED schließen.
                FatalConnectionError(Http3Error.FrameUnexpected, "PUSH_PROMISE from client");
                return false;
            case Http3FrameType.PriorityUpdateRequest:
            case Http3FrameType.PriorityUpdatePush:
                // RFC 9218 §7.2: PRIORITY_UPDATE gehört ausschließlich auf den Client-Control-Stream.
                FatalConnectionError(Http3Error.FrameUnexpected, "PRIORITY_UPDATE on request stream");
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
    /// Behandelt einen CONNECT-Request direkt nach den HEADERS (RFC 9114 §4.4, RFC 8441/9220):
    /// klassischer CONNECT (kein :protocol) ⇒ 501 (nicht unterstützt); Extended CONNECT ohne
    /// angekündigtes Setting ⇒ malformed (der Client DARF ihn dann nicht senden, RFC 8441 §3);
    /// sonst entscheidet der Handler — 2xx richtet den Tunnel ein, alles andere lehnt ab.
    /// </summary>
    private bool HandleConnect(RequestState state)
    {
        Http3Request request = state.Request!;

        // WebTransport (draft-webtrans-http3 §3.2): :protocol = webtransport.
        if (request.Protocol == "webtransport" && _wtMaxSessions > 0)
            return HandleWebTransportConnect(state);

        if (request.Protocol is null || _connectHandler is null)
        {
            if (request.Protocol is not null)
            {
                // Extended CONNECT ohne SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 ⇒ malformed (RFC 8441 §3).
                RejectMalformedRequest(state, "extended CONNECT without ENABLE_CONNECT_PROTOCOL");
                return true;
            }
            // Klassischen CONNECT (Proxy-Tunnel) unterstützt dieser Server nicht.
            state.Stream.AbortRead(Http3Error.NoError);
            SendResponse(state.Stream.Id.Value, state.Stream, new Http3Response { Status = 501 });
            state.Responded = true;
            return true;
        }

        Http3ConnectResult result = _connectHandler(request);
        var fields = new List<HeaderField> { new(":status", result.Status.ToString()) };
        fields.AddRange(result.Headers);
        state.Stream.Write(Http3Frames.Build(Http3FrameType.Headers,
            _qpack.EncodeHeaders(state.Stream.Id.Value, fields)));

        if (result.Status is >= 200 and < 300 && result.OnTunnel is not null)
        {
            // Angenommen: KEIN FIN — der Stream ist jetzt der Tunnel (Bytes in DATA-Frames, §4.4).
            ulong tunnelStreamId = state.Stream.Id.Value;
            state.Tunnel = new Http3Tunnel(state.Stream)
            {
                DatagramSender = payload => TrySendHttpDatagram(tunnelStreamId, payload), // RFC 9297
            };
            RequestsHandled++;
            result.OnTunnel(state.Tunnel);
        }
        else
        {
            state.Stream.Finish(); // abgelehnt: Antwort abschließen
            state.Responded = true;
        }
        return true;
    }

    /// <summary>
    /// Nimmt eine WebTransport-Session an (draft-webtrans-http3 §3.2): der Handler entscheidet über
    /// Annahme (2xx + Session-Callback) oder Ablehnung (404). Bei Überschreitung von WT_MAX_SESSIONS
    /// wird der CONNECT-Stream mit H3_REQUEST_REJECTED zurückgesetzt (§5.2). WebTransport verlangt
    /// zwingend HTTP/3- und QUIC-Datagramme — fehlen sie, ist der Request malformed (§3.1).
    /// </summary>
    private bool HandleWebTransportConnect(RequestState state)
    {
        // §3.1: ohne QUIC-/HTTP-Datagramme ist ein WebTransport-Request malformed.
        if (!_localDatagramsEnabled || !_qpack.PeerH3Datagram || _quic.PeerMaxDatagramFrameSize == 0)
        {
            RejectMalformedRequest(state, "WebTransport without datagram support");
            return true;
        }
        // §5.2: mehr Sessions als angekündigt ⇒ CONNECT-Stream mit H3_REQUEST_REJECTED zurücksetzen.
        if ((ulong)_wtSessionCount >= _wtMaxSessions)
        {
            state.Stream.Reset(Http3Error.RequestRejected);
            state.Stream.AbortRead(Http3Error.RequestRejected);
            state.Responded = true;
            return true;
        }

        Action<WebTransportSession>? onSession = _webTransportHandler?.Invoke(state.Request!);
        if (onSession is null)
        {
            state.Stream.AbortRead(Http3Error.NoError); // §3.2: keine passende Ressource ⇒ 404
            SendResponse(state.Stream.Id.Value, state.Stream, new Http3Response { Status = 404 });
            state.Responded = true;
            return true;
        }

        // Protokoll-Aushandlung (draft §3.3): angebotene Protokolle parsen und ggf. eines wählen.
        string? negotiated = NegotiateWebTransportProtocol(state.Request!);

        // 2xx senden (KEIN FIN — der CONNECT-Stream trägt fortan Capsules); Session anlegen.
        SendHeadersOnly(state.Stream, 200,
            negotiated is null ? null : new HeaderField(WebTransportProtocols.ProtocolHeader,
                                                        WebTransportProtocols.SerializeProtocol(negotiated)));
        var session = new WebTransportSession(state.Stream.Id.Value, this) { NegotiatedProtocol = negotiated };
        state.WebTransportSession = session;
        _webTransport.RegisterSession(session);
        _wtSessionCount++;
        RequestsHandled++;
        onSession(session);
        return true;
    }

    /// <summary>
    /// Wertet <c>WT-Available-Protocols</c> des CONNECT-Requests aus und lässt den Selector wählen
    /// (draft §3.3). Mehrere Header-Instanzen werden per Komma zusammengefügt (SF-Lists dürfen über
    /// mehrere Feldzeilen verteilt sein); ein ungültiges Feld wird KOMPLETT ignoriert (MUST), eine
    /// Selector-Wahl außerhalb der Angebotsliste verworfen (MUST include a single choice from the list).
    /// </summary>
    private string? NegotiateWebTransportProtocol(Http3Request request)
    {
        if (_webTransportProtocolSelector is null)
            return null;
        string? fieldValue = null;
        foreach (HeaderField h in request.AdditionalHeaders)
            if (h.Name == WebTransportProtocols.AvailableProtocolsHeader)
                fieldValue = fieldValue is null ? h.Value : fieldValue + "," + h.Value;
        if (fieldValue is null || !WebTransportProtocols.TryParseProtocolList(fieldValue, out List<string> offered))
            return null;
        string? chosen = _webTransportProtocolSelector(request, offered);
        return chosen is not null && offered.Contains(chosen) ? chosen : null;
    }

    private void SendHeadersOnly(QuicStream stream, int status, HeaderField? extra = null)
    {
        var fields = new List<HeaderField> { new(":status", status.ToString()) };
        if (extra is { } field)
            fields.Add(field);
        stream.Write(Http3Frames.Build(Http3FrameType.Headers, _qpack.EncodeHeaders(stream.Id.Value, fields)));
    }

    /// <summary>
    /// Behandelt einen malformed Request (RFC 9114 §4.1.2): Stream-Fehler H3_MESSAGE_ERROR — der
    /// Server DARF vorher eine Fehlantwort senden (wir: 400 Bad Request, ohne Handler-Aufruf).
    /// </summary>
    private void RejectMalformedRequest(RequestState state, string reason)
    {
        _ = reason;
        state.Stream.AbortRead(Http3Error.MessageError);
        SendResponse(state.Stream.Id.Value, state.Stream, new Http3Response { Status = 400 });
        state.Responded = true; // beendet die Frame-Verarbeitung dieses Streams
    }

    private static Http3Request BuildRequest(List<HeaderField> headers)
    {
        string method = "GET", scheme = "https", authority = "", path = "/";
        string? protocol = null;
        var extra = new List<HeaderField>();
        foreach (HeaderField h in headers)
        {
            switch (h.Name)
            {
                case ":method": method = h.Value; break;
                case ":scheme": scheme = h.Value; break;
                case ":authority": authority = h.Value; break;
                case ":path": path = h.Value; break;
                case ":protocol": protocol = h.Value; break; // Extended CONNECT (RFC 8441 §4)
                default: extra.Add(h); break;
            }
        }
        return new Http3Request(method, scheme, authority, path) { AdditionalHeaders = extra, Protocol = protocol };
    }

    private void SendResponse(ulong streamId, QuicStream stream, Http3Response response)
    {
        // §4.2.2 SHOULD NOT: keine Field Section über dem vom Client angekündigten Limit senden.
        ulong? peerLimit = _qpack.PeerMaxFieldSectionSize;

        var fields = new List<HeaderField> { new(":status", response.Status.ToString()) };
        fields.AddRange(response.Headers);
        if (peerLimit is { } lim && Http3Qpack.FieldSectionSize(fields) > lim)
        {
            // Die finale Antwort würde beim Client verworfen — stattdessen ein minimales 500 senden.
            response = new Http3Response { Status = 500 };
            fields = [new(":status", "500")];
        }

        // Interim-Responses (1xx, §4.1): je eine eigene HEADERS-Sektion VOR der finalen Antwort
        // (zu große Interim-Sektionen werden schlicht weggelassen — sie sind rein beratend).
        foreach (Http3InterimResponse interim in response.InterimResponses)
        {
            var interimFields = new List<HeaderField> { new(":status", interim.Status.ToString()) };
            interimFields.AddRange(interim.Headers);
            if (peerLimit is { } il && Http3Qpack.FieldSectionSize(interimFields) > il)
                continue;
            stream.Write(Http3Frames.Build(Http3FrameType.Headers, _qpack.EncodeHeaders(streamId, interimFields)));
        }

        stream.Write(Http3Frames.Build(Http3FrameType.Headers, _qpack.EncodeHeaders(streamId, fields)));
        if (response.Body.Length > 0)
            stream.Write(Http3Frames.Build(Http3FrameType.Data, response.Body));
        if (response.Trailers.Count > 0 && // Trailer-Sektion (§4.1 Punkt 3); zu große Trailer entfallen
            (peerLimit is not { } tl || Http3Qpack.FieldSectionSize(response.Trailers) <= tl))
            stream.Write(Http3Frames.Build(Http3FrameType.Headers, _qpack.EncodeHeaders(streamId, [.. response.Trailers])));
        stream.Finish();
    }

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
            if (_connectHandler is not null || _wtMaxSessions > 0)
            {
                writer.WriteVarInt(Http3Setting.EnableConnectProtocol); // RFC 8441 §3 / RFC 9220 §3
                writer.WriteVarInt(1);
            }
            if (_localDatagramsEnabled)
            {
                writer.WriteVarInt(Http3Setting.H3Datagram); // RFC 9297 §2.1.1
                writer.WriteVarInt(1);
            }
            if (_wtMaxSessions > 0) // draft-webtrans-http3 §3.1/§9.2
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
        public ByteQueue Buffer { get; } = new();
        public Queue<Http3Frame> Pending { get; } = new();
        public Http3Request? Request { get; set; }
        public List<byte> Body { get; } = [];             // eingesammelte DATA-Frame-Nutzlasten (Request-Rumpf)
        public List<HeaderField> Trailers { get; } = [];  // Trailer-Sektion des Requests (§4.1 Punkt 3)
        public bool HeadersReceived;
        public bool TrailersSeen { get; set; }     // Trailer-Sektion gesehen ⇒ danach sind Frames illegal (§4.1)
        public bool PriorityUpdated { get; set; }  // PRIORITY_UPDATE empfangen ⇒ übertrumpft den Header (RFC 9218 §7)
        public Http3Tunnel? Tunnel { get; set; }   // Extended-CONNECT-Tunnel (RFC 8441/9220), sonst null
        public WebTransportSession? WebTransportSession { get; set; } // WebTransport-Session (draft-webtrans-http3)
        public ByteQueue CapsuleBuffer { get; } = new(); // Capsule-Protokoll-Bytes des WT-CONNECT-Streams
        public bool Responded { get; set; }
    }
}
