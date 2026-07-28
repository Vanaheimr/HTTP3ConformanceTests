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

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Hermod.Quic;

using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Task-based server facade: owns the UDP socket, demultiplexes incoming datagrams onto
/// <see cref="Http3ServerConnection"/>s (primarily via the connection ID — so a connection
/// migration per RFC 9000 §9 hits the same connection) and runs timers/sending in a background
/// loop. Only genuine Initial packets open new connections (RFC 9000 §5.2); short-header packets
/// for an unknown connection ID are answered by the server — when a token generator is set —
/// with a stateless reset (RFC 9000 §10.3). The deterministic core remains untouched;
/// all connection accesses run on the single loop task (no locking needed).
/// </summary>
public sealed class Http3Server : IAsyncDisposable
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromMilliseconds(20);
    private const int LocalCidLength = 8;

    private sealed class ServerConn(Http3ServerConnection connection, IPEndPoint endpoint)
    {
        public Http3ServerConnection Connection { get; } = connection;
        public IPEndPoint Endpoint { get; set; } = endpoint;
    }

    private readonly Func<QuicServerConnection.ValidatedRetry?, Http3ServerConnection> _connectionFactory;
    private readonly RetryTokenGenerator? _addressValidation;
    private readonly StatelessResetTokenGenerator? _statelessResetTokens;
    private readonly TimeProvider _timeProvider;
    private readonly int _requestedPort;
    private readonly int _maxConnections;
    private readonly List<ServerConn> _connections = [];

    // Demux index: connection ID -> connection. Without it every datagram cost a linear scan over
    // ALL connections, so the per-packet cost grew with the number of clients — an easy lever for
    // an attacker. Filled lazily on the first packet for a connection ID; 8 random bytes make a
    // collision between connections negligible.
    private readonly Dictionary<ConnectionId, ServerConn> _byConnectionId = [];
    private readonly Dictionary<IPEndPoint, ServerConn> _byEndpoint = [];
    private readonly CancellationTokenSource _cts = new();
    private readonly UdpBatchSender _sender = new();

    private UdpClient? _udp;
    private Task? _loopTask;
    private bool _disposed;

    /// <summary>
    /// Simplest entry point: certificate + request handler; every new connection receives a
    /// default <see cref="Http3ServerConnection"/>.
    /// </summary>
    public Http3Server(ServerCertificate certificate, Func<Http3Request, Http3Response> handler, int port = 443,
                       TimeProvider? timeProvider = null, KeyLog? keyLog = null,
                       RetryTokenGenerator? addressValidation = null,
                       ClientCertificateOptions? clientCertificate = null)
        : this(port, retry => new Http3ServerConnection(certificate, handler, timeProvider: timeProvider,
                                                       keyLog: keyLog, validatedRetry: retry,
                                                       clientCertificate: clientCertificate),
               timeProvider: timeProvider, addressValidation: addressValidation)
    { }

    /// <summary>
    /// Same, but with an asynchronous handler — the recommended form. The handler runs off the loop:
    /// after its first await the loop carries on, so a slow request no longer stalls the other
    /// connections. The token is cancelled when the client aborts the request or the server stops.
    /// </summary>
    public Http3Server(ServerCertificate certificate, Func<Http3Request, CancellationToken, Task<Http3Response>> handler,
                       int port = 443, TimeProvider? timeProvider = null, KeyLog? keyLog = null,
                       RetryTokenGenerator? addressValidation = null,
                       ClientCertificateOptions? clientCertificate = null)
        : this(port, retry => new Http3ServerConnection(certificate, handler, timeProvider: timeProvider,
                                                       keyLog: keyLog, validatedRetry: retry,
                                                       clientCertificate: clientCertificate),
               timeProvider: timeProvider, addressValidation: addressValidation)
    { }

    /// <summary>
    /// Same, with a streaming request body: the handler starts right after the header section and
    /// reads the body as it arrives, so a large upload never has to be buffered. A handler that
    /// reads slowly throttles the peer via QUIC flow control.
    /// </summary>
    public Http3Server(ServerCertificate certificate,
                       Func<Http3Request, Http3RequestBody, CancellationToken, Task<Http3Response>> handler,
                       int port = 443, TimeProvider? timeProvider = null, KeyLog? keyLog = null,
                       RetryTokenGenerator? addressValidation = null,
                       ClientCertificateOptions? clientCertificate = null)
        : this(port, retry => new Http3ServerConnection(certificate, handler, timeProvider: timeProvider,
                                                       keyLog: keyLog, validatedRetry: retry,
                                                       clientCertificate: clientCertificate),
               timeProvider: timeProvider, addressValidation: addressValidation)
    { }

    /// <summary>
    /// Fully configurable: <paramref name="connectionFactory"/> creates the (arbitrarily configured)
    /// connection per client — Extended CONNECT, datagrams, WebTransport, resumption etc. included.
    /// </summary>
    /// <param name="maxConnections">
    /// Upper bound on simultaneously held connections. Beyond it new Initial packets are dropped
    /// SILENTLY — every answer would be an amplification vector, and a handshake costs a signature.
    /// See <see cref="ConnectionsRefused"/>.
    /// </param>
    public Http3Server(int port, Func<Http3ServerConnection> connectionFactory,
                       StatelessResetTokenGenerator? statelessResetTokens = null,
                       TimeProvider? timeProvider = null,
                       int maxConnections = DefaultMaxConnections)
        // A factory that ignores the Retry result cannot serve an address-validating listener: the
        // connection would not adopt the connection ID we already promised the client.
        : this(port, _ => connectionFactory(), statelessResetTokens, timeProvider, maxConnections, addressValidation: null)
    { }

    /// <summary>
    /// As above, but with stateless address validation (RFC 9000 §8.1.2). The factory receives the
    /// validated Retry — the DCID of the client's first Initial and the connection ID we chose in the
    /// Retry packet — and MUST pass it on to the <see cref="Http3ServerConnection"/>, otherwise the
    /// connection uses a different connection ID than the one the client was told to use.
    /// </summary>
    /// <param name="addressValidation">
    /// When set, every connection attempt without a valid token is answered with a Retry — built and
    /// sent WITHOUT creating a connection. Under a spoofed-source flood the server then pays one AEAD
    /// seal per packet instead of a connection object, and the answer goes to the forged address,
    /// where it dies. <c>null</c> disables address validation.
    /// </param>
    public Http3Server(int port, Func<QuicServerConnection.ValidatedRetry?, Http3ServerConnection> connectionFactory,
                       StatelessResetTokenGenerator? statelessResetTokens = null,
                       TimeProvider? timeProvider = null,
                       int maxConnections = DefaultMaxConnections,
                       RetryTokenGenerator? addressValidation = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConnections, 1);
        _requestedPort = port;
        _connectionFactory = connectionFactory;
        _statelessResetTokens = statelessResetTokens;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _maxConnections = maxConnections;
        _addressValidation = addressValidation;
    }

    /// <summary>
    /// Default upper bound on simultaneous connections.
    /// </summary>
    public const int DefaultMaxConnections = 1024;

    /// <summary>
    /// Number of Initial packets rejected because the connection limit was reached (diagnostics).
    /// </summary>
    public long ConnectionsRefused { get; private set; }

    /// <summary>
    /// The actually bound UDP port (with 0 in the constructor: the one assigned by the OS).
    /// </summary>
    public int Port { get; private set; }

    /// <summary>
    /// Number of currently held connections (informational).
    /// </summary>
    public int ConnectionCount => _connections.Count;

    /// <summary>
    /// Binds the socket and starts the receive/timer loop.
    /// </summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_loopTask is not null)
            throw new InvalidOperationException("Start has already been called.");
        _udp = new UdpClient(new IPEndPoint(System.Net.IPAddress.Any, _requestedPort));
        Port = ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
        _loopTask = Task.Run(LoopAsync, CancellationToken.None);
    }

    /// <summary>
    /// Upper bound on datagrams processed per loop pass — keeps one busy peer from starving the
    /// timers of every other connection.
    /// </summary>
    private const int MaxDatagramsPerBatch = 64;

    private async Task LoopAsync()
    {
        Task<UdpReceiveResult>? receive = null;
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                receive ??= _udp!.ReceiveAsync(_cts.Token).AsTask();

                if (!receive.IsCompleted)
                {
                    // Wait for a datagram OR the tick — and CANCEL the timer afterwards, instead of
                    // abandoning one per loop pass.
                    using var tick = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                    await Task.WhenAny(receive, Task.Delay(TickInterval, _timeProvider, tick.Token)).ConfigureAwait(false);
                    tick.Cancel();
                }

                if (receive.IsCompletedSuccessfully)
                {
                    UdpReceiveResult result = receive.Result;
                    receive = null;
                    HandleDatagram(result.Buffer, result.RemoteEndPoint);

                    // Drain what is already queued instead of paying a full async round trip per
                    // datagram — the dominant cost while a client uploads. No async receive is
                    // outstanding at this point, so the synchronous read is safe.
                    for (int batched = 1; batched < MaxDatagramsPerBatch && _udp!.Available > 0; batched++)
                    {
                        IPEndPoint? from = null;
                        byte[] datagram = _udp.Receive(ref from);
                        HandleDatagram(datagram, from!);
                    }
                }
                else
                    RunTimers();
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { receive = null; } // e.g. a client's ICMP "port unreachable"
        }
    }

    private void HandleDatagram(byte[] datagram, IPEndPoint from)
    {
        // 1) Via the destination connection ID (stable after the handshake, even on an address change).
        //    Index first, linear scan only on a miss — and the result is then cached.
        ServerConn? conn = null;
        ConnectionId? dcid = ExtractDcid(datagram);
        if (dcid is { } id)
        {
            if (!_byConnectionId.TryGetValue(id, out conn))
            {
                conn = _connections.FirstOrDefault(c => c.Connection.OwnsConnectionId(id));
                if (conn is not null)
                    _byConnectionId[id] = conn; // learn the ID, no scan next time
            }
        }
        // 2) … otherwise via the sender address (handshake / new connection).
        if (conn is null && _byEndpoint.TryGetValue(from, out ServerConn? byEndpoint))
            conn = byEndpoint;

        if (conn is null)
        {
            byte first = datagram.Length > 0 ? datagram[0] : (byte)0;

            // Short header for an unknown DCID = lost connection ⇒ stateless reset (RFC 9000 §10.3).
            if (datagram.Length > 0 && PacketFormat.IsShortHeader(first))
            {
                if (_statelessResetTokens is { } tokens &&
                    StatelessReset.BuildResponse(datagram, LocalCidLength, tokens) is { } reset)
                    _udp!.Send(reset, reset.Length, from);
                return;
            }

            // Only genuine Initial packets open new connections (RFC 9000 §5.2).
            if (!PacketFormat.IsLongHeader(first) || PacketFormat.GetLongPacketType(first) != LongPacketType.Initial)
                return;

            // Address validation happens BEFORE any state exists — that is the whole point.
            QuicServerConnection.ValidatedRetry? validatedRetry = null;
            if (_addressValidation is not null && !TryValidateAddress(datagram, from, out validatedRetry))
                return;

            // Connection limit: beyond it drop SILENTLY. Any answer would be an amplification
            // vector, and every handshake costs a certificate signature.
            if (_connections.Count >= _maxConnections)
            {
                ConnectionsRefused++;
                return;
            }

            conn = new ServerConn(_connectionFactory(validatedRetry), from);
            _connections.Add(conn);
            _byEndpoint[from] = conn;
            if (dcid is { } initialDcid)
                _byConnectionId[initialDcid] = conn;
        }
        else if (!conn.Endpoint.Equals(from))
        {
            // Connection migration (RFC 9000 §9): validate the new path.
            _byEndpoint.Remove(conn.Endpoint);
            conn.Endpoint = from;
            _byEndpoint[from] = conn;
            conn.Connection.InitiatePathValidation();
        }

        conn.Connection.ProcessDatagram(datagram);
        Flush(conn);
    }

    /// <summary>
    /// Stateless address validation for an Initial that would otherwise create a connection
    /// (RFC 9000 §8.1.2). Returns <c>true</c> when the handshake may proceed; <paramref name="retry"/>
    /// then carries what the connection needs to know about the Retry that already happened.
    /// <para>
    /// Nothing here allocates per-attempt state: the token IS the state. A flood from spoofed
    /// addresses therefore produces Retry packets sent to those addresses and nothing else — no
    /// connection object, no TLS, no certificate signature.
    /// </para>
    /// </summary>
    private bool TryValidateAddress(byte[] datagram, IPEndPoint from,
                                    out QuicServerConnection.ValidatedRetry? retry)
    {
        retry = null;
        RetryTokenGenerator tokens = _addressValidation!;

        // A datagram carrying an Initial must be at least 1200 bytes (RFC 9000 §14.1). Answering a
        // smaller one would make us an amplifier, so it is dropped without a word.
        if (datagram.Length < InitialPacketFactory.MinimumClientInitialSize)
            return false;
        if (!LongHeader.TryParse(datagram, out LongHeaderPrefix? prefix) || prefix is null)
            return false;

        if (prefix.Token.Length == 0)
        {
            // First contact: send a Retry and forget everything about it. The connection ID we pick
            // here becomes the client's DCID (§7.2) and is carried inside the token, so the eventual
            // connection can adopt it.
            var retrySourceCid = new ConnectionId(RandomNumberGenerator.GetBytes(LocalCidLength));
            byte[] token = tokens.Issue(from, prefix.DestinationConnectionId, retrySourceCid);
            byte[] packet = RetryPacket.Build(prefix.Version, prefix.SourceConnectionId, retrySourceCid,
                                              token, prefix.DestinationConnectionId);
            _udp!.Send(packet, packet.Length, from);
            RetriesSent++;
            return false;
        }

        if (!tokens.TryValidate(prefix.Token, from, out ConnectionId originalDcid, out ConnectionId retrySourceCid2) ||
            // The token names the connection ID we handed out; the Initial must actually be addressed
            // to it. Otherwise a token could be pasted onto a packet for a different connection.
            !prefix.DestinationConnectionId.Equals(retrySourceCid2) ||
            !tokens.TryConsume(prefix.Token))
        {
            // §8.1.2: the client will not accept a second Retry, so tell it plainly instead of
            // letting it wait for a handshake timeout. This costs no state — see StatelessClose.
            byte[] refusal = StatelessClose.Build(prefix.Version, prefix.DestinationConnectionId,
                                                  prefix.SourceConnectionId, TransportError.InvalidToken,
                                                  "invalid retry token");
            _udp!.Send(refusal, refusal.Length, from);
            TokensRejected++;
            return false;
        }

        retry = new QuicServerConnection.ValidatedRetry(originalDcid, retrySourceCid2);
        return true;
    }

    /// <summary>
    /// Number of Retry packets sent for address validation (diagnostics).
    /// </summary>
    public long RetriesSent { get; private set; }

    /// <summary>
    /// Number of Initials refused with INVALID_TOKEN — a forged, expired, replayed or misdirected
    /// token (diagnostics).
    /// </summary>
    public long TokensRejected { get; private set; }

    private void RunTimers()
    {
        foreach (ServerConn conn in _connections)
        {
            conn.Connection.CheckTimeouts();
            if (!conn.Connection.IsIdleTimedOut)
                Flush(conn);
        }
        _connections.RemoveAll(conn =>
        {
            if (!conn.Connection.IsIdleTimedOut)
                return false;
            Forget(conn);
            conn.Connection.Dispose();
            return true;
        });
    }

    /// <summary>
    /// Sends everything the connection currently has queued. Streaming bodies produce their data in
    /// portions, so we keep pumping while packets keep coming instead of emitting one chunk per
    /// 20 ms tick — the loop is bounded so one connection cannot monopolise it.
    /// </summary>
    private void Flush(ServerConn conn)
    {
        for (int round = 0; round < MaxFlushRoundsPerPass; round++)
        {
            IReadOnlyList<byte[]> datagrams = conn.Connection.GetDatagramsToSend();
            if (datagrams.Count == 0)
                return;
            _sender.Send(_udp!.Client, datagrams, conn.Endpoint);
            conn.Connection.CheckTimeouts(); // drives handler tasks and the next body chunk
        }
    }

    /// <summary>
    /// Upper bound on send rounds per connection and pass — fairness between connections.
    /// </summary>
    private const int MaxFlushRoundsPerPass = 16;

    /// <summary>
    /// Removes a closed connection from both demux indexes, so their entries cannot outlive it.
    /// </summary>
    private void Forget(ServerConn conn)
    {
        _byEndpoint.Remove(conn.Endpoint);
        foreach (ConnectionId id in _byConnectionId.Where(e => e.Value == conn).Select(e => e.Key).ToList())
            _byConnectionId.Remove(id);
    }

    /// <summary>
    /// Reads the destination connection ID: for long headers from the header itself, for short
    /// headers the first <see cref="LocalCidLength"/> bytes after the first byte (our CIDs are 8 bytes long).
    /// </summary>
    private static ConnectionId? ExtractDcid(ReadOnlySpan<byte> datagram)
    {
        if (datagram.IsEmpty)
            return null;
        if (PacketFormat.IsLongHeader(datagram[0]))
            return LongHeader.TryParseInvariant(datagram, out _, out ConnectionId dcid, out _) ? dcid : null;
        return datagram.Length >= 1 + LocalCidLength ? new ConnectionId(datagram.Slice(1, LocalCidLength)) : null;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;
        _disposed = true;
        _cts.Cancel();
        if (_loopTask is { } loop)
            try { await loop.ConfigureAwait(false); } catch { /* loop shutdown */ }
        foreach (ServerConn conn in _connections)
            conn.Connection.Dispose();
        _connections.Clear();
        _byConnectionId.Clear();
        _byEndpoint.Clear();
        _udp?.Dispose();
        _cts.Dispose();
    }
}
