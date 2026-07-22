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
public sealed class Http3ServerConnection : IDisposable
{
    private readonly QuicServerConnection _quic;
    private readonly Func<Http3Request, Http3Response> _handler;
    private readonly Dictionary<ulong, RequestState> _requests = [];
    private readonly Http3Qpack _qpack;
    private bool _http3Initialized;

    /// <param name="qpackMaxTableCapacity">
    /// Angekündigte maximale QPACK-Tabellenkapazität (RFC 9204). Standard 4096 aktiviert die dynamische
    /// Tabelle; ein rein statischer Client (Kapazität 0) löst sie nicht aus, daher interop-sicher.
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
        Quic.Packets.StatelessResetTokenGenerator? statelessResetTokens = null)
    {
        _quic = new QuicServerConnection(certificate, transportParameters, requireRetry: requireRetry, preferredGroups: preferredGroups, resumptionCache: resumptionCache, maxEarlyDataSize: maxEarlyDataSize, statelessResetTokens: statelessResetTokens);
        _handler = handler;
        _qpack = new Http3Qpack(qpackMaxTableCapacity, weAreClient: false);
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
        InitializeHttp3IfReady();

        // Uni-Streams des Clients (SETTINGS + QPACK-Encoder-Instruktionen) verarbeiten.
        _qpack.PumpPeerStreams(_quic.Streams);

        foreach (ulong id in _quic.TakeNewRequestStreams())
            _requests[id] = new RequestState(_quic.Streams[id]);

        foreach (RequestState state in _requests.Values)
        {
            if (state.Responded)
                continue;

            byte[] chunk = state.Stream.Read();
            if (chunk.Length > 0)
                state.Buffer.AddRange(chunk);

            if (state.Buffer.Count > 0 &&
                Http3Frames.TryReadAll(state.Buffer.ToArray(), out List<Http3Frame> frames, out int consumed))
            {
                foreach (Http3Frame frame in frames)
                    state.Pending.Enqueue(frame);
                state.Buffer.RemoveRange(0, consumed);
            }

            // Frames der Reihe nach; eine blockierte HEADERS-Sektion hält an (wartet auf Encoder-Stream).
            while (!state.HeadersReceived && state.Pending.Count > 0)
            {
                Http3Frame frame = state.Pending.Dequeue();
                if (frame.Type != Http3FrameType.Headers)
                    continue;
                if (_qpack.TryDecodeHeaders(state.Stream.Id.Value, frame.Payload.Span) is not { } headers)
                {
                    state.Pending.Enqueue(frame); // blockiert – zurücklegen, später erneut versuchen
                    break;
                }
                state.Request = BuildRequest(headers);
                state.HeadersReceived = true;
            }

            if (state.HeadersReceived && state.Request is not null)
            {
                SendResponse(state.Stream.Id.Value, state.Stream, _handler(state.Request));
                state.Responded = true;
            }
        }
    }

    private void InitializeHttp3IfReady()
    {
        if (_http3Initialized || !_quic.HandshakeComplete)
            return;

        QuicStream control = _quic.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, BuildSettings()));

        QuicStream encoderStream = _quic.OpenUnidirectionalStream();
        encoderStream.Write([(byte)Http3StreamType.QpackEncoder]);
        _qpack.SetEncoderStream(encoderStream);
        QuicStream decoderStream = _quic.OpenUnidirectionalStream();
        decoderStream.Write([(byte)Http3StreamType.QpackDecoder]);
        _qpack.SetDecoderStream(decoderStream);

        // Dem Client eine Reserve-Connection-ID anbieten (RFC 9000 §5.1), sofern sein Limit es zulässt.
        _quic.IssueConnectionId();

        _http3Initialized = true;
    }

    private static Http3Request BuildRequest(List<HeaderField> headers)
    {
        string method = "GET", scheme = "https", authority = "", path = "/";
        var extra = new List<HeaderField>();
        foreach (HeaderField h in headers)
        {
            switch (h.Name)
            {
                case ":method": method = h.Value; break;
                case ":scheme": scheme = h.Value; break;
                case ":authority": authority = h.Value; break;
                case ":path": path = h.Value; break;
                default: extra.Add(h); break;
            }
        }
        return new Http3Request(method, scheme, authority, path) { AdditionalHeaders = extra };
    }

    private void SendResponse(ulong streamId, QuicStream stream, Http3Response response)
    {
        var fields = new List<HeaderField> { new(":status", response.Status.ToString()) };
        fields.AddRange(response.Headers);

        stream.Write(Http3Frames.Build(Http3FrameType.Headers, _qpack.EncodeHeaders(streamId, fields)));
        if (response.Body.Length > 0)
            stream.Write(Http3Frames.Build(Http3FrameType.Data, response.Body));
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
            return writer.WrittenSpan.ToArray();
        }
        finally { writer.Dispose(); }
    }

    public void Dispose() => _quic.Dispose();

    private sealed class RequestState(QuicStream stream)
    {
        public QuicStream Stream { get; } = stream;
        public List<byte> Buffer { get; } = [];
        public Queue<Http3Frame> Pending { get; } = new();
        public Http3Request? Request { get; set; }
        public bool HeadersReceived;
        public bool Responded { get; set; }
    }
}
