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
/// Task-basierte Server-Fassade: besitzt den UDP-Socket, demultiplext eingehende Datagramme auf
/// <see cref="Http3ServerConnection"/>s (vorrangig über die Connection ID — so trifft eine Connection
/// Migration nach RFC 9000 §9 dieselbe Verbindung) und betreibt Timer/Versand in einer Hintergrund-
/// Schleife. Nur echte Initial-Pakete eröffnen neue Verbindungen (RFC 9000 §5.2); Short-Header-Pakete
/// zu unbekannter Connection ID beantwortet der Server — sofern ein Token-Generator gesetzt ist —
/// mit einem Stateless Reset (RFC 9000 §10.3). Der deterministische Kern bleibt unangetastet;
/// alle Verbindungs-Zugriffe laufen auf der einen Schleifen-Task (kein Locking nötig).
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
    private readonly int _requestedPort;
    private readonly List<ServerConn> _connections = [];
    private readonly CancellationTokenSource _cts = new();
    private readonly UdpBatchSender _sender = new();

    private UdpClient? _udp;
    private Task? _loopTask;
    private bool _disposed;

    /// <summary>
    /// Einfachster Einstieg: Zertifikat + Request-Handler; jede neue Verbindung erhält eine
    /// Standard-<see cref="Http3ServerConnection"/>.
    /// </summary>
    public Http3Server(ServerCertificate certificate, Func<Http3Request, Http3Response> handler, int port = 443)
        : this(port, () => new Http3ServerConnection(certificate, handler))
    { }

    /// <summary>
    /// Voll konfigurierbar: <paramref name="connectionFactory"/> erzeugt die (beliebig konfigurierte)
    /// Verbindung je Client — Extended CONNECT, Datagramme, WebTransport, Resumption usw. inklusive.
    /// </summary>
    public Http3Server(int port, Func<Http3ServerConnection> connectionFactory,
                       StatelessResetTokenGenerator? statelessResetTokens = null)
    {
        _requestedPort = port;
        _connectionFactory = connectionFactory;
        _statelessResetTokens = statelessResetTokens;
    }

    /// <summary>
    /// Der tatsächlich gebundene UDP-Port (bei 0 im Konstruktor: der vom OS vergebene).
    /// </summary>
    public int Port { get; private set; }

    /// <summary>
    /// Anzahl aktuell geführter Verbindungen (informativ).
    /// </summary>
    public int ConnectionCount => _connections.Count;

    /// <summary>
    /// Bindet den Socket und startet die Empfangs-/Timer-Schleife.
    /// </summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_loopTask is not null)
            throw new InvalidOperationException("Start wurde bereits aufgerufen.");
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
                Task finished = await Task.WhenAny(receive, Task.Delay(TickInterval, _cts.Token)).ConfigureAwait(false);

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
            catch (SocketException) { receive = null; } // z. B. ICMP „Port Unreachable" eines Clients
        }
    }

    private void HandleDatagram(byte[] datagram, IPEndPoint from)
    {
        // 1) Über die Ziel-Connection-ID (nach dem Handshake stabil, auch bei Adresswechsel) …
        ServerConn? conn = ExtractDcid(datagram) is { } dcid
            ? _connections.FirstOrDefault(c => c.Connection.OwnsConnectionId(dcid))
            : null;
        // 2) … sonst über die Absenderadresse (Handshake / neue Verbindung).
        conn ??= _connections.FirstOrDefault(c => c.Endpoint.Equals(from));

        if (conn is null)
        {
            byte first = datagram.Length > 0 ? datagram[0] : (byte)0;

            // Short-Header zu unbekannter DCID = verlorene Verbindung ⇒ Stateless Reset (RFC 9000 §10.3).
            if (datagram.Length > 0 && PacketFormat.IsShortHeader(first))
            {
                if (_statelessResetTokens is { } tokens &&
                    StatelessReset.BuildResponse(datagram, LocalCidLength, tokens) is { } reset)
                    _udp!.Send(reset, reset.Length, from);
                return;
            }

            // Nur echte Initial-Pakete eröffnen neue Verbindungen (RFC 9000 §5.2).
            if (!PacketFormat.IsLongHeader(first) || PacketFormat.GetLongPacketType(first) != LongPacketType.Initial)
                return;

            conn = new ServerConn(_connectionFactory(), from);
            _connections.Add(conn);
        }
        else if (!conn.Endpoint.Equals(from))
        {
            // Connection Migration (RFC 9000 §9): neuen Pfad validieren.
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
    /// Liest die Ziel-Connection-ID: bei Long Headern aus dem Header selbst, bei Short Headern die
    /// ersten <see cref="LocalCidLength"/> Bytes nach dem First Byte (unsere CIDs sind 8 Bytes lang).
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
            try { await loop.ConfigureAwait(false); } catch { /* Schleifen-Ende */ }
        foreach (ServerConn conn in _connections)
            conn.Connection.Dispose();
        _connections.Clear();
        _udp?.Dispose();
        _cts.Dispose();
    }
}
