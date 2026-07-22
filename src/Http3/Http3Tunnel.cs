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

using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Ein bidirektionaler Byte-Tunnel über einen Extended-CONNECT-Stream (RFC 9114 §4.4, RFC 8441/9220):
/// Nutzdaten reisen in DATA-Frames des Request-Streams; ein FIN entspricht dem geordneten TCP-Close,
/// ein Reset dem RST (H3_REQUEST_CANCELLED, RFC 9220 §3). Implementiert das transport-agnostische
/// <see cref="IHTTP2Tunnel"/>-Interface, sodass die RFC-6455-<see cref="WebSocketConnection"/>
/// unverändert darüber läuft.
///
/// Nebenläufigkeit: der Tunnel ist — wie der ganze Stack — single-threaded gedacht. Ausstehende
/// <see cref="ReadAsync"/>-Tasks werden SYNCHRON im Pump-Aufruf (<c>ProcessDatagram</c>) vollendet;
/// ihre Continuations (z. B. das Frame-Parsing der WebSocket-Schicht samt automatischer Pong-/
/// Close-Antworten) laufen also inline auf dem Pump-Thread und schreiben race-frei in den Stream.
/// </summary>
public sealed class Http3Tunnel : IHTTP2Tunnel
{
    private readonly QuicStream _stream;
    private readonly Queue<byte[]> _received = new();
    private TaskCompletionSource<byte[]?>? _pendingRead;
    private bool _ended;

    internal Http3Tunnel(QuicStream stream)
        => _stream = stream;

    /// <summary>
    /// Liest den nächsten vom Peer getunnelten Chunk; <c>null</c>, sobald der Peer seine Seite
    /// beendet hat (FIN oder Reset).
    /// </summary>
    public Task<byte[]?> ReadAsync(CancellationToken CancellationToken)
    {
        if (_received.Count > 0)
            return Task.FromResult<byte[]?>(_received.Dequeue());
        if (_ended)
            return Task.FromResult<byte[]?>(null);
        _pendingRead ??= new TaskCompletionSource<byte[]?>();
        return _pendingRead.Task;
    }

    /// <summary>
    /// Sendet einen Chunk zum Peer — als DATA-Frame auf dem CONNECT-Stream (RFC 9114 §4.4).
    /// </summary>
    public Task WriteAsync(byte[] Data, CancellationToken CancellationToken)
    {
        _stream.Write(Http3Frames.Build(Http3FrameType.Data, Data));
        return Task.CompletedTask;
    }

    /// <summary>
    /// Beendet die eigene Senderichtung geordnet (FIN ≙ TCP-Close, RFC 9220 §3).
    /// </summary>
    public void Complete() => _stream.Finish();

    /// <summary>
    /// Bricht den Tunnel abrupt ab (≙ TCP-RST): RESET_STREAM/STOP_SENDING mit H3_REQUEST_CANCELLED.
    /// </summary>
    public void Abort()
    {
        _stream.Reset(Http3Error.RequestCancelled);
        _stream.AbortRead(Http3Error.RequestCancelled);
    }

    /// <summary>
    /// Vom Pump aufgerufen: liefert die Nutzlast eines empfangenen DATA-Frames in den Tunnel.
    /// </summary>
    internal void Deliver(byte[] chunk)
    {
        if (_pendingRead is { } pending)
        {
            _pendingRead = null;
            pending.SetResult(chunk); // Continuation läuft inline auf dem Pump-Thread (s. o.)
        }
        else
            _received.Enqueue(chunk);
    }

    /// <summary>
    /// Vom Pump aufgerufen: die Peer-Seite hat geendet (FIN oder Reset) — ausstehende und künftige
    /// Reads liefern nach dem Leeren der Warteschlange <c>null</c>.
    /// </summary>
    internal void End()
    {
        _ended = true;
        if (_pendingRead is { } pending)
        {
            _pendingRead = null;
            pending.TrySetResult(null);
        }
    }

    // ---- HTTP-Datagramme (RFC 9297) — unzuverlässige Nachrichten neben dem Byte-Strom ------

    private const int MaxBufferedDatagrams = 64; // unzuverlässig ⇒ Überlauf DARF verworfen werden (RFC 9221 §5.3)
    private readonly Queue<byte[]> _datagrams = new();
    internal Func<byte[], bool>? DatagramSender { get; set; }

    /// <summary>
    /// Sendet ein HTTP-Datagramm zu diesem Request-Stream (RFC 9297 §2.1: Quarter Stream ID +
    /// Payload in einem QUIC-DATAGRAM-Frame). <c>false</c>, wenn Datagramme nicht ausgehandelt sind
    /// (SETTINGS_H3_DATAGRAM/max_datagram_frame_size) oder das Datagramm nicht in ein Paket passt.
    /// </summary>
    public bool TrySendDatagram(byte[] payload) => DatagramSender?.Invoke(payload) ?? false;

    /// <summary>
    /// Holt das nächste für diesen Stream empfangene HTTP-Datagramm ab, falls vorhanden.
    /// </summary>
    public bool TryReceiveDatagram(out byte[]? payload)
    {
        if (_datagrams.Count > 0)
        {
            payload = _datagrams.Dequeue();
            return true;
        }
        payload = null;
        return false;
    }

    /// <summary>
    /// Vom Pump aufgerufen: stellt ein empfangenes HTTP-Datagramm zu (bei vollem Puffer wird das
    /// älteste verworfen — Datagramme sind per Definition unzuverlässig).
    /// </summary>
    internal void DeliverDatagram(byte[] payload)
    {
        if (_datagrams.Count >= MaxBufferedDatagrams)
            _datagrams.Dequeue();
        _datagrams.Enqueue(payload);
    }
}

/// <summary>
/// Antwort eines Servers auf ein Extended CONNECT (RFC 8441/9220): Statuscode, Zusatz-Header
/// (z. B. <c>sec-websocket-protocol</c>) und — bei Annahme (2xx) — ein Callback, der den fertigen
/// <see cref="Http3Tunnel"/> erhält (analog zu Hermods <c>HTTP2ConnectResult.RunAsync</c>).
/// </summary>
public sealed class Http3ConnectResult
{
    public required int Status { get; init; }
    public IReadOnlyList<HeaderField> Headers { get; init; } = [];

    /// <summary>
    /// Wird bei 2xx mit dem Tunnel aufgerufen, sobald die Antwort-HEADERS gesendet sind.
    /// </summary>
    public Action<Http3Tunnel>? OnTunnel { get; init; }
}
