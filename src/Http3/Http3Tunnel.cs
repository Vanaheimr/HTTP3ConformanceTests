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
/// A bidirectional byte tunnel over an Extended-CONNECT stream (RFC 9114 §4.4, RFC 8441/9220):
/// payload travels in DATA frames of the request stream; a FIN corresponds to the orderly TCP
/// close, a reset to the RST (H3_REQUEST_CANCELLED, RFC 9220 §3). Implements the transport-agnostic
/// <see cref="IHTTP2Tunnel"/> interface, so the RFC 6455 <see cref="WebSocketConnection"/>
/// runs over it unchanged.
///
/// Concurrency: the tunnel — like the whole stack — is designed single-threaded. Outstanding
/// <see cref="ReadAsync"/> tasks are completed SYNCHRONOUSLY in the pump call
/// (<c>ProcessDatagram</c>); their continuations (e.g. the WebSocket layer's frame parsing incl.
/// automatic pong/close answers) thus run inline on the pump thread and write into the stream
/// race-free.
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
    /// Reads the next chunk tunnelled from the peer; <c>null</c> once the peer has ended its side
    /// (FIN or reset).
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
    /// Sends a chunk to the peer — as a DATA frame on the CONNECT stream (RFC 9114 §4.4).
    /// </summary>
    public Task WriteAsync(byte[] Data, CancellationToken CancellationToken)
    {
        _stream.Write(Http3Frames.Build(Http3FrameType.Data, Data));
        return Task.CompletedTask;
    }

    /// <summary>
    /// Ends our own send direction in an orderly fashion (FIN ≙ TCP close, RFC 9220 §3).
    /// </summary>
    public void Complete() => _stream.Finish();

    /// <summary>
    /// Aborts the tunnel abruptly (≙ TCP RST): RESET_STREAM/STOP_SENDING with H3_REQUEST_CANCELLED.
    /// </summary>
    public void Abort()
    {
        _stream.Reset(Http3Error.RequestCancelled);
        _stream.AbortRead(Http3Error.RequestCancelled);
    }

    /// <summary>
    /// Called by the pump: delivers the payload of a received DATA frame into the tunnel.
    /// </summary>
    internal void Deliver(byte[] chunk)
    {
        if (_pendingRead is { } pending)
        {
            _pendingRead = null;
            pending.SetResult(chunk); // the continuation runs inline on the pump thread (see above)
        }
        else
            _received.Enqueue(chunk);
    }

    /// <summary>
    /// Called by the pump: the peer side has ended (FIN or reset) — outstanding and future reads
    /// return <c>null</c> once the queue has drained.
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

    // ---- HTTP datagrams (RFC 9297) — unreliable messages alongside the byte stream ----------

    private const int MaxBufferedDatagrams = 64; // unreliable ⇒ overflow MAY be discarded (RFC 9221 §5.3)
    private readonly Queue<byte[]> _datagrams = new();
    internal Func<byte[], bool>? DatagramSender { get; set; }

    /// <summary>
    /// Sends an HTTP datagram for this request stream (RFC 9297 §2.1: quarter stream ID + payload in
    /// a QUIC DATAGRAM frame). <c>false</c> when datagrams are not negotiated
    /// (SETTINGS_H3_DATAGRAM/max_datagram_frame_size) or the datagram does not fit into a packet.
    /// </summary>
    public bool TrySendDatagram(byte[] payload) => DatagramSender?.Invoke(payload) ?? false;

    /// <summary>
    /// Fetches the next HTTP datagram received for this stream, if any.
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
    /// Called by the pump: delivers a received HTTP datagram (when the buffer is full, the oldest
    /// one is discarded — datagrams are unreliable by definition).
    /// </summary>
    internal void DeliverDatagram(byte[] payload)
    {
        if (_datagrams.Count >= MaxBufferedDatagrams)
            _datagrams.Dequeue();
        _datagrams.Enqueue(payload);
    }
}

/// <summary>
/// A server's answer to an Extended CONNECT (RFC 8441/9220): status code, additional headers
/// (e.g. <c>sec-websocket-protocol</c>) and — on acceptance (2xx) — a callback receiving the
/// finished <see cref="Http3Tunnel"/> (analogous to Hermod's <c>HTTP2ConnectResult.RunAsync</c>).
/// </summary>
public sealed class Http3ConnectResult
{
    public required int Status { get; init; }
    public IReadOnlyList<HeaderField> Headers { get; init; } = [];

    /// <summary>
    /// Called with the tunnel on 2xx, as soon as the response HEADERS are sent.
    /// </summary>
    public Action<Http3Tunnel>? OnTunnel { get; init; }
}
