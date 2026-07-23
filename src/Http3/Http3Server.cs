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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;

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

    private readonly Func<Http3ServerConnection> _connectionFactory;
    private readonly StatelessResetTokenGenerator? _statelessResetTokens;
    private readonly TimeProvider _timeProvider;
    private readonly int _requestedPort;
    private readonly List<ServerConn> _connections = [];
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
                       TimeProvider? timeProvider = null)
        : this(port, () => new Http3ServerConnection(certificate, handler, timeProvider: timeProvider),
               timeProvider: timeProvider)
    { }

    /// <summary>
    /// Fully configurable: <paramref name="connectionFactory"/> creates the (arbitrarily configured)
    /// connection per client — Extended CONNECT, datagrams, WebTransport, resumption etc. included.
    /// </summary>
    public Http3Server(int port, Func<Http3ServerConnection> connectionFactory,
                       StatelessResetTokenGenerator? statelessResetTokens = null,
                       TimeProvider? timeProvider = null)
    {
        _requestedPort = port;
        _connectionFactory = connectionFactory;
        _statelessResetTokens = statelessResetTokens;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

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
        _udp = new UdpClient(new IPEndPoint(IPAddress.Any, _requestedPort));
        Port = ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
        _loopTask = Task.Run(LoopAsync, CancellationToken.None);
    }

    private async Task LoopAsync()
    {
        Task<UdpReceiveResult>? receive = null;
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                receive ??= _udp!.ReceiveAsync(_cts.Token).AsTask();
                Task finished = await Task.WhenAny(receive, Task.Delay(TickInterval, _timeProvider, _cts.Token)).ConfigureAwait(false);

                if (finished == receive)
                {
                    UdpReceiveResult result = await receive.ConfigureAwait(false);
                    receive = null;
                    HandleDatagram(result.Buffer, result.RemoteEndPoint);
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
        // 1) Via the destination connection ID (stable after the handshake, even on an address change) …
        ServerConn? conn = ExtractDcid(datagram) is { } dcid
            ? _connections.FirstOrDefault(c => c.Connection.OwnsConnectionId(dcid))
            : null;
        // 2) … otherwise via the sender address (handshake / new connection).
        conn ??= _connections.FirstOrDefault(c => c.Endpoint.Equals(from));

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

            conn = new ServerConn(_connectionFactory(), from);
            _connections.Add(conn);
        }
        else if (!conn.Endpoint.Equals(from))
        {
            // Connection migration (RFC 9000 §9): validate the new path.
            conn.Endpoint = from;
            conn.Connection.InitiatePathValidation();
        }

        conn.Connection.ProcessDatagram(datagram);
        Flush(conn);
    }

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
            conn.Connection.Dispose();
            return true;
        });
    }

    private void Flush(ServerConn conn)
        => _sender.Send(_udp!.Client, conn.Connection.GetDatagramsToSend(), conn.Endpoint);

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
        _udp?.Dispose();
        _cts.Dispose();
    }
}
