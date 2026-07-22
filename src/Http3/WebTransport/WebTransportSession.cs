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

using System.Buffers.Binary;
using System.Text;

using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;

/// <summary>
/// Die von einer <see cref="WebTransportSession"/> benötigten Dienste ihrer HTTP/3-Verbindung:
/// WebTransport-Streams öffnen, WT-Datagramme senden, Capsules auf dem CONNECT-Stream schreiben
/// und dessen Senderichtung beenden.
/// </summary>
internal interface IWebTransportHost
{
    QuicStream OpenWebTransportUniStream(ulong sessionId);
    QuicStream OpenWebTransportBidiStream(ulong sessionId);
    bool SendWebTransportDatagram(ulong sessionId, byte[] payload);
    void WriteConnectStreamData(ulong sessionId, byte[] data);
    void FinishConnectStream(ulong sessionId);
    bool FlowControlEnabled { get; }
    ulong LocalInitialMaxStreamsUni { get; }
    ulong LocalInitialMaxStreamsBidi { get; }
    ulong LocalInitialMaxData { get; }
    ulong PeerInitialMaxStreamsUni { get; }
    ulong PeerInitialMaxStreamsBidi { get; }
    ulong PeerInitialMaxData { get; }

    /// <summary>
    /// TLS-Keying-Material-Exporter der zugrunde liegenden QUIC-Verbindung (RFC 8446 §7.5).
    /// </summary>
    byte[] ExportKeyingMaterial(string label, ReadOnlySpan<byte> context, int length);
}

/// <summary>
/// Eine WebTransport-Session über HTTP/3 (draft-ietf-webtrans-http3-13): läuft über einen
/// Extended-CONNECT-Stream (<c>:protocol = webtransport</c>) und multiplext darüber uni-/
/// bidirektionale WebTransport-Streams (§4.1/§4.2), unzuverlässige Datagramme (§4.4) und
/// Session-Steuerung/Flow Control per Capsules (§5.6, §6). Die Session-ID ist die Stream-ID des
/// CONNECT-Streams.
/// </summary>
public sealed class WebTransportSession
{
    private readonly IWebTransportHost _host;

    private readonly Queue<WebTransportStream> _incomingUni = new();
    private readonly Queue<WebTransportStream> _incomingBidi = new();
    private readonly Queue<byte[]> _datagrams = new();
    private readonly List<WebTransportStream> _allStreams = [];

    // Flow Control (nur aktiv, wenn beide WT_MAX_SESSIONS > 1 angekündigt haben, §5.1).
    private ulong _peerMaxStreamsUni, _peerMaxStreamsBidi, _peerMaxData; // vom Peer gewährt
    private ulong _localMaxStreamsUni, _localMaxStreamsBidi, _localMaxData; // von uns gewährt
    private ulong _openedUni, _openedBidi;   // von uns eröffnete Streams (kumulativ)
    private ulong _acceptedUni, _acceptedBidi; // vom Peer eröffnete (kumulativ)
    private ulong _dataSent, _dataReceived;

    internal WebTransportSession(ulong sessionId, IWebTransportHost host)
    {
        SessionId = sessionId;
        _host = host;
        _peerMaxStreamsUni = host.PeerInitialMaxStreamsUni;
        _peerMaxStreamsBidi = host.PeerInitialMaxStreamsBidi;
        _peerMaxData = host.PeerInitialMaxData;
        _localMaxStreamsUni = host.LocalInitialMaxStreamsUni;
        _localMaxStreamsBidi = host.LocalInitialMaxStreamsBidi;
        _localMaxData = host.LocalInitialMaxData;
    }

    /// <summary>Die Session-ID = Stream-ID des CONNECT-Streams (§4).</summary>
    public ulong SessionId { get; }

    /// <summary>Die Session ist beendet (§6: CONNECT-Stream geschlossen oder WT_CLOSE_SESSION).</summary>
    public bool IsClosed { get; private set; }

    /// <summary>Fehlercode/-meldung eines empfangenen (oder impliziten) WT_CLOSE_SESSION.</summary>
    public uint? CloseErrorCode { get; private set; }
    public string? CloseReason { get; private set; }

    /// <summary>Flow Control ist aktiv (beide Seiten WT_MAX_SESSIONS &gt; 1, §5.1).</summary>
    public bool FlowControlEnabled => _host.FlowControlEnabled;

    /// <summary>
    /// Das per WT-Available-Protocols/WT-Protocol ausgehandelte Anwendungsprotokoll (draft §3.3,
    /// ALPN-artig); <c>null</c>, wenn keines angeboten oder vom Server keines gewählt wurde.
    /// </summary>
    public string? NegotiatedProtocol { get; internal set; }

    /// <summary>
    /// Session-gebundener Keying-Material-Exporter (draft §4.7): der TLS-Exporter (RFC 8446 §7.5) der
    /// QUIC-Verbindung mit festem Label <c>EXPORTER-WebTransport</c> und dem „WebTransport Exporter
    /// Context"-Struct (Session-ID ‖ Label ‖ Kontext) — dadurch erhalten verschiedene Sessions
    /// derselben Verbindung getrenntes Material, beide Enden derselben Session aber identisches.
    /// Das anwendungsgegebene Label muss 1–255 UTF-8-Bytes lang sein, der Kontext 0–255 Bytes.
    /// </summary>
    public byte[] ExportKeyingMaterial(string label, ReadOnlySpan<byte> context, int length)
    {
        byte[] labelBytes = Encoding.UTF8.GetBytes(label);
        if (labelBytes.Length is < 1 or > 255)
            throw new ArgumentException("Das Exporter-Label muss 1–255 UTF-8-Bytes lang sein (draft §4.7).", nameof(label));
        if (context.Length > 255)
            throw new ArgumentException("Der Exporter-Kontext darf höchstens 255 Bytes lang sein (draft §4.7).", nameof(context));

        // WebTransport Exporter Context { Session ID (64) ‖ LabelLen (8) ‖ Label ‖ ContextLen (8) ‖ Context }
        byte[] exporterContext = new byte[8 + 1 + labelBytes.Length + 1 + context.Length];
        BinaryPrimitives.WriteUInt64BigEndian(exporterContext, SessionId);
        exporterContext[8] = (byte)labelBytes.Length;
        labelBytes.CopyTo(exporterContext, 9);
        exporterContext[9 + labelBytes.Length] = (byte)context.Length;
        context.CopyTo(exporterContext.AsSpan(10 + labelBytes.Length));

        return _host.ExportKeyingMaterial("EXPORTER-WebTransport", exporterContext, length);
    }

    // ---- Streams (§4.1/§4.2) --------------------------------------------------------------

    /// <summary>
    /// Öffnet einen unidirektionalen WebTransport-Stream (Kopf 0x54 ‖ Session-ID wird geschrieben).
    /// <c>null</c>, wenn die Session zu ist oder das Stream-Limit des Peers erreicht ist (§5.3) —
    /// dann wird ein WT_STREAMS_BLOCKED-Capsule gesendet.
    /// </summary>
    public WebTransportStream? OpenUnidirectionalStream()
    {
        if (IsClosed)
            return null;
        if (FlowControlEnabled && _openedUni >= _peerMaxStreamsUni)
        {
            _host.WriteConnectStreamData(SessionId,
                WebTransportCapsule.BuildVarIntCapsule(WebTransportConstants.CapsuleStreamsBlockedUni, _peerMaxStreamsUni));
            return null;
        }
        _openedUni++;
        // Lokal geöffneter Uni-Stream: send-only.
        var stream = new WebTransportStream(_host.OpenWebTransportUniStream(SessionId), bidirectional: false, canSend: true, canReceive: false);
        _allStreams.Add(stream);
        return stream;
    }

    /// <summary>
    /// Öffnet einen bidirektionalen WebTransport-Stream (Kopf WT_STREAM 0x41 ‖ Session-ID); Limit-/
    /// Zustandsregeln wie bei <see cref="OpenUnidirectionalStream"/>.
    /// </summary>
    public WebTransportStream? OpenBidirectionalStream()
    {
        if (IsClosed)
            return null;
        if (FlowControlEnabled && _openedBidi >= _peerMaxStreamsBidi)
        {
            _host.WriteConnectStreamData(SessionId,
                WebTransportCapsule.BuildVarIntCapsule(WebTransportConstants.CapsuleStreamsBlockedBidi, _peerMaxStreamsBidi));
            return null;
        }
        _openedBidi++;
        var stream = new WebTransportStream(_host.OpenWebTransportBidiStream(SessionId), bidirectional: true, canSend: true, canReceive: true);
        _allStreams.Add(stream);
        return stream;
    }

    /// <summary>Nimmt den nächsten vom Peer geöffneten unidirektionalen Stream ab, falls vorhanden.</summary>
    public WebTransportStream? AcceptUnidirectionalStream() => _incomingUni.Count > 0 ? _incomingUni.Dequeue() : null;

    /// <summary>Nimmt den nächsten vom Peer geöffneten bidirektionalen Stream ab, falls vorhanden.</summary>
    public WebTransportStream? AcceptBidirectionalStream() => _incomingBidi.Count > 0 ? _incomingBidi.Dequeue() : null;

    // ---- Datagramme (§4.4) ----------------------------------------------------------------

    /// <summary>
    /// Sendet ein WebTransport-Datagramm (unzuverlässig); die Nutzlast folgt direkt der Quarter Stream
    /// ID des CONNECT-Streams (§4.4). <c>false</c>, wenn die Session zu ist oder das Datagramm nicht
    /// gesendet werden kann.
    /// </summary>
    public bool SendDatagram(byte[] payload) => !IsClosed && _host.SendWebTransportDatagram(SessionId, payload);

    /// <summary>Nimmt das nächste empfangene Datagramm ab, falls vorhanden.</summary>
    public bool TryReceiveDatagram(out byte[]? payload)
    {
        if (_datagrams.Count > 0) { payload = _datagrams.Dequeue(); return true; }
        payload = null;
        return false;
    }

    // ---- Session-Ende (§6) ----------------------------------------------------------------

    /// <summary>
    /// Beendet die Session (§6): sendet ein WT_CLOSE_SESSION-Capsule und danach ein FIN auf dem
    /// CONNECT-Stream; alle zugehörigen Streams werden mit WT_SESSION_GONE abgebrochen.
    /// </summary>
    public void Close(uint errorCode = 0, string reason = "")
    {
        if (IsClosed)
            return;
        if (errorCode != 0 || reason.Length > 0)
            _host.WriteConnectStreamData(SessionId, WebTransportCapsule.BuildCloseSession(errorCode, reason));
        _host.FinishConnectStream(SessionId);
        MarkClosed(errorCode, reason);
    }

    // ---- Vom Manager aufgerufen -----------------------------------------------------------

    internal void OnIncomingUniStream(QuicStream stream, byte[] leftover)
    {
        _acceptedUni++;
        // Eingehender Uni-Stream: receive-only.
        var wt = new WebTransportStream(stream, bidirectional: false, canSend: false, canReceive: true, leftover);
        _allStreams.Add(wt);
        _incomingUni.Enqueue(wt);
        MaybeGrantStreams(uni: true);
    }

    internal void OnIncomingBidiStream(QuicStream stream, byte[] leftover)
    {
        _acceptedBidi++;
        var wt = new WebTransportStream(stream, bidirectional: true, canSend: true, canReceive: true, leftover);
        _allStreams.Add(wt);
        _incomingBidi.Enqueue(wt);
        MaybeGrantStreams(uni: false);
    }

    internal void OnDatagram(byte[] payload) => _datagrams.Enqueue(payload);

    /// <summary>
    /// Verarbeitet ein auf dem CONNECT-Stream empfangenes Capsule (§5.6/§6). Unbekannte Typen werden
    /// still übersprungen (RFC 9297 §3.2).
    /// </summary>
    internal void HandleCapsule(WebTransportCapsule capsule)
    {
        switch (capsule.Type)
        {
            case WebTransportConstants.CapsuleCloseSession:
                var span = capsule.Value.Span;
                uint code = span.Length >= 4 ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(span) : 0;
                string reason = span.Length > 4 ? System.Text.Encoding.UTF8.GetString(span[4..]) : "";
                MarkClosed(code, reason);
                break;

            // Flow-Control-Capsules werden ignoriert, solange Flow Control nicht ausgehandelt ist (§5.1).
            case WebTransportConstants.CapsuleMaxStreamsUni when FlowControlEnabled:
                if (ReadVarInt(capsule.Value, out ulong maxUni)) _peerMaxStreamsUni = Math.Max(_peerMaxStreamsUni, maxUni);
                break;
            case WebTransportConstants.CapsuleMaxStreamsBidi when FlowControlEnabled:
                if (ReadVarInt(capsule.Value, out ulong maxBidi)) _peerMaxStreamsBidi = Math.Max(_peerMaxStreamsBidi, maxBidi);
                break;
            case WebTransportConstants.CapsuleMaxData when FlowControlEnabled:
                if (ReadVarInt(capsule.Value, out ulong maxData)) _peerMaxData = Math.Max(_peerMaxData, maxData);
                break;
            case WebTransportConstants.CapsuleStreamsBlockedUni when FlowControlEnabled:
            case WebTransportConstants.CapsuleStreamsBlockedBidi when FlowControlEnabled:
            case WebTransportConstants.CapsuleDataBlocked when FlowControlEnabled:
                break; // rein informativ – wir gewähren Streams/Data ohnehin proaktiv (MaybeGrant*)
            // Unbekannte Capsules: still überspringen (RFC 9297 §3.2).
        }
    }

    /// <summary>Session-Ende durch geschlossenen CONNECT-Stream (§6, ohne WT_CLOSE_SESSION = Code 0).</summary>
    internal void OnConnectStreamClosed() => MarkClosed(CloseErrorCode ?? 0, CloseReason ?? "");

    internal bool TryRecordSentData(int bytes)
    {
        if (!FlowControlEnabled)
            return true;
        if (_dataSent + (ulong)bytes > _peerMaxData)
        {
            _host.WriteConnectStreamData(SessionId,
                WebTransportCapsule.BuildVarIntCapsule(WebTransportConstants.CapsuleDataBlocked, _peerMaxData));
            return false;
        }
        _dataSent += (ulong)bytes;
        return true;
    }

    internal void RecordReceivedData(int bytes)
    {
        if (!FlowControlEnabled)
            return;
        _dataReceived += (ulong)bytes;
        // Fenster nachführen (§5.4): ab halbem verbrauchtem Fenster mehr Kredit gewähren.
        if (_localMaxData - _dataReceived < _localMaxData / 2)
        {
            _localMaxData += Math.Max(_host.LocalInitialMaxData, 65536);
            _host.WriteConnectStreamData(SessionId,
                WebTransportCapsule.BuildVarIntCapsule(WebTransportConstants.CapsuleMaxData, _localMaxData));
        }
    }

    private void MaybeGrantStreams(bool uni)
    {
        if (!FlowControlEnabled)
            return;
        // Kumulatives Limit nachführen, sobald der Peer sich seinem aktuellen Limit nähert (§5.3).
        if (uni && _acceptedUni + 1 >= _localMaxStreamsUni)
        {
            _localMaxStreamsUni += Math.Max(_host.LocalInitialMaxStreamsUni, 1);
            _host.WriteConnectStreamData(SessionId,
                WebTransportCapsule.BuildVarIntCapsule(WebTransportConstants.CapsuleMaxStreamsUni, _localMaxStreamsUni));
        }
        else if (!uni && _acceptedBidi + 1 >= _localMaxStreamsBidi)
        {
            _localMaxStreamsBidi += Math.Max(_host.LocalInitialMaxStreamsBidi, 1);
            _host.WriteConnectStreamData(SessionId,
                WebTransportCapsule.BuildVarIntCapsule(WebTransportConstants.CapsuleMaxStreamsBidi, _localMaxStreamsBidi));
        }
    }

    private void MarkClosed(uint code, string reason)
    {
        if (IsClosed)
            return;
        IsClosed = true;
        CloseErrorCode = code;
        CloseReason = reason;
        foreach (WebTransportStream stream in _allStreams) // §6: alle zugehörigen Streams abbrechen
            stream.AbortForSessionGone();
    }

    private static bool ReadVarInt(ReadOnlyMemory<byte> value, out ulong result)
    {
        var reader = new Quic.Core.Buffers.BufferReader(value.Span);
        return reader.TryReadVarInt(out result);
    }
}
