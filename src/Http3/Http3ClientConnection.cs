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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Ein HTTP/3-Client (RFC 9114) über einer <see cref="QuicClientConnection"/>. Öffnet den Control-Stream
/// (mit SETTINGS) und die QPACK-Encoder/Decoder-Streams, sendet Requests als HEADERS-Frame auf einem
/// bidirektionalen Stream und setzt die Antwort (HEADERS + DATA) wieder zusammen. Transport-agnostisch:
/// Datagramme kommen über <see cref="GetDatagramsToSend"/> / <see cref="ProcessDatagram"/> herein/heraus.
/// </summary>
public sealed class Http3ClientConnection : IDisposable
{
    private readonly QuicClientConnection _quic;
    private readonly Dictionary<ulong, RequestState> _requests = [];
    private readonly Http3Qpack _qpack;
    private bool _http3Initialized;

    /// <param name="qpackMaxTableCapacity">
    /// Angekündigte maximale QPACK-Tabellenkapazität (RFC 9204). <c>0</c> (Standard) = rein statisch
    /// (interop-sicher); &gt; 0 aktiviert die dynamische Tabelle, sobald auch der Peer eine ankündigt.
    /// </param>
    public Http3ClientConnection(
        string serverName,
        TransportParameters? transportParameters = null,
        CertificateValidationOptions? certificateValidation = null,
        ulong qpackMaxTableCapacity = 0,
        IReadOnlyList<Quic.Tls.CipherSuite>? cipherSuites = null,
        IReadOnlyList<Quic.Tls.NamedGroup>? keyExchangeGroups = null,
        Quic.Tls.ResumptionTicket? resumptionTicket = null)
    {
        _quic = new QuicClientConnection(serverName, transportParameters, certificateValidation: certificateValidation, cipherSuites: cipherSuites, keyExchangeGroups: keyExchangeGroups, resumptionTicket: resumptionTicket);
        _qpack = new Http3Qpack(qpackMaxTableCapacity, weAreClient: true);
    }

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
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, BuildSettings()));

        // QPACK-Encoder-Stream (für Insert-Instruktionen) + Decoder-Stream (Typ-Präfix genügt).
        QuicStream encoderStream = _quic.OpenUnidirectionalStream();
        encoderStream.Write([(byte)Http3StreamType.QpackEncoder]);
        _qpack.SetEncoderStream(encoderStream);
        QuicStream decoderStream = _quic.OpenUnidirectionalStream();
        decoderStream.Write([(byte)Http3StreamType.QpackDecoder]);
        _qpack.SetDecoderStream(decoderStream);

        _http3Initialized = true;
    }

    /// <summary>
    /// Sendet einen Request auf einem neuen bidirektionalen Stream. Gibt dessen Stream-ID zurück.
    /// </summary>
    public ulong SendRequest(Http3Request request)
    {
        QuicStream stream = _quic.OpenBidirectionalStream();
        byte[] headerBlock = _qpack.EncodeHeaders(stream.Id.Value, request.ToHeaderFields());
        stream.Write(Http3Frames.Build(Http3FrameType.Headers, headerBlock));
        stream.Finish(); // GET ohne Body ⇒ FIN

        _requests[stream.Id.Value] = new RequestState(stream);
        return stream.Id.Value;
    }

    /// <summary>
    /// Liefert die fertige Antwort eines Request-Streams, sobald sie vollständig empfangen ist.
    /// </summary>
    public bool TryGetResponse(ulong streamId, out Http3Response? response)
    {
        response = null;
        if (!_requests.TryGetValue(streamId, out RequestState? state) || !state.Complete)
            return false;

        int status = 0;
        if (state.Headers.FirstOrDefault(h => h.Name == ":status") is { Name: ":status" } s)
            int.TryParse(s.Value, out status);

        response = new Http3Response
        {
            Status = status,
            Headers = state.Headers,
            Body = [.. state.Body],
        };
        return true;
    }

    // ---- HTTP/3-Empfang -------------------------------------------------------------------

    private void Pump()
    {
        // Zuerst die Uni-Streams des Servers (SETTINGS + QPACK-Encoder-Instruktionen) verarbeiten.
        _qpack.PumpPeerStreams(_quic.Streams);

        foreach (RequestState state in _requests.Values)
        {
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

            // Frames der Reihe nach verarbeiten; eine blockierte HEADERS-Sektion hält die Reihe an.
            while (state.Pending.Count > 0)
            {
                Http3Frame frame = state.Pending.Peek();
                if (frame.Type == Http3FrameType.Headers)
                {
                    List<HeaderField>? headers = _qpack.TryDecodeHeaders(state.Stream.Id.Value, frame.Payload.Span);
                    if (headers is null)
                        break; // blockiert – auf weitere Encoder-Stream-Daten warten
                    state.Headers.AddRange(headers);
                }
                else if (frame.Type == Http3FrameType.Data)
                {
                    state.Body.AddRange(frame.Payload.ToArray());
                }
                // Unbekannte Frames werden ignoriert (Greasing).
                state.Pending.Dequeue();
            }

            if (state.Stream.IsReceiveComplete && state.Pending.Count == 0)
                state.Complete = true;
        }
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
        public Queue<Http3Frame> Pending { get; } = new(); // geparste, noch zu verarbeitende Frames
        public List<HeaderField> Headers { get; } = [];
        public List<byte> Body { get; } = [];
        public bool Complete { get; set; }
    }
}
