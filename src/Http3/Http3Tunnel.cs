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
/// <para>
/// <b>Concurrency — receive side:</b> guarded, like <see cref="Http3RequestBody"/>. A consumer that
/// awaits real I/O between two reads resumes on a thread-pool thread and then reads concurrently
/// with the pump delivering into this tunnel, so the queue, the pending read and the datagram buffer
/// are all under a lock. A waiting read is always completed OUTSIDE that lock: its continuation runs
/// inline on the completing thread and may read again immediately, which would otherwise re-enter
/// mid-operation.
/// </para>
/// <para>
/// <b>Concurrency — send side: NOT guarded.</b> <see cref="WriteAsync"/>, <see cref="Complete"/> and
/// <see cref="Abort"/> reach straight into the QUIC stream's send buffer, which the pump also drives
/// and which has no lock of its own. They are safe from the pump thread — which includes a
/// continuation running inline on it, the case the WebSocket layer relies on — and unsafe from
/// anywhere else. Making them safe means marshalling writes to the pump rather than adding a lock
/// here, because the race is with the pump's own use of that buffer.
/// </para>
/// </summary>
public sealed class Http3Tunnel : IHTTP2Tunnel
{
    private readonly QuicStream _stream;
    private readonly Lock _lock = new();
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
        if (CancellationToken.IsCancellationRequested)
            return Task.FromCanceled<byte[]?>(CancellationToken);

        lock (_lock)
        {
            if (_received.Count > 0)
                return Task.FromResult<byte[]?>(_received.Dequeue());
            if (_ended)
                return Task.FromResult<byte[]?>(null);
            if (_pendingRead is not null)
                throw new InvalidOperationException("Only one read at a time is supported.");

            // Nothing there yet — the pump completes this task as soon as a DATA frame arrives.
            _pendingRead = new TaskCompletionSource<byte[]?>();
            return _pendingRead.Task;
        }
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
        TaskCompletionSource<byte[]?>? toComplete = null;
        lock (_lock)
        {
            if (_ended)
                return; // the peer already finished — anything after that is not ours to hand on
            if (_pendingRead is { } pending)
            {
                _pendingRead = null;
                toComplete = pending;
            }
            else
                _received.Enqueue(chunk);
        }
        toComplete?.TrySetResult(chunk); // outside the lock — the continuation may read again at once
    }

    /// <summary>
    /// Called by the pump: the peer side has ended (FIN or reset) — outstanding and future reads
    /// return <c>null</c> once the queue has drained.
    /// </summary>
    internal void End()
    {
        TaskCompletionSource<byte[]?>? toComplete;
        lock (_lock)
        {
            if (_ended)
                return;
            _ended = true;
            toComplete = _pendingRead;
            _pendingRead = null;
        }
        toComplete?.TrySetResult(null); // outside the lock, for the same reason as in Deliver
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
        lock (_lock)
        {
            if (_datagrams.Count > 0)
            {
                payload = _datagrams.Dequeue();
                return true;
            }
            payload = null;
            return false;
        }
    }

    /// <summary>
    /// Called by the pump: delivers a received HTTP datagram (when the buffer is full, the oldest
    /// one is discarded — datagrams are unreliable by definition).
    /// </summary>
    internal void DeliverDatagram(byte[] payload)
    {
        lock (_lock)
        {
            if (_datagrams.Count >= MaxBufferedDatagrams)
                _datagrams.Dequeue();
            _datagrams.Enqueue(payload);
        }
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
