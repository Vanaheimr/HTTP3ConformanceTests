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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Ein HTTP/3-Request ist endgültig fehlgeschlagen (abgebrochen, zurückgewiesen, malformed oder die
/// Verbindung wurde geschlossen). <see cref="IsRetryable"/> zeigt an, ob eine Wiederholung auf einer
/// neuen Verbindung gefahrlos ist (RFC 9114 §5.2: per GOAWAY zurückgewiesene Requests).
/// </summary>
public sealed class Http3RequestException(string message, bool isRetryable = false) : Exception(message)
{
    /// <summary>
    /// Der Request wurde nachweislich nicht verarbeitet und darf gefahrlos wiederholt werden.
    /// </summary>
    public bool IsRetryable { get; } = isRetryable;
}

/// <summary>
/// Task-basierte Fassade über <see cref="Http3ClientConnection"/>: besitzt den UDP-Socket, betreibt
/// eine Hintergrund-Pump (Empfang, Timer, Senden) und bildet Requests auf <c>await</c>-bare Tasks ab.
/// Der deterministische, transport-agnostische Kern bleibt unangetastet — diese Klasse ergänzt nur
/// Socket, Nebenläufigkeit (alle Kern-Zugriffe strikt serialisiert) und die asynchrone API.
/// Für fortgeschrittene Features (Datagramme, WebTransport, Extended CONNECT) stehen
/// <see cref="PerformAsync"/>/<see cref="QueryAsync"/>/<see cref="WaitUntilAsync"/> bereit.
/// </summary>
public sealed class Http3Client : IAsyncDisposable
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromMilliseconds(20);

    private readonly string _host;
    private readonly int _port;
    private readonly Http3ClientConnection _connection;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private readonly Dictionary<ulong, TaskCompletionSource<Http3Response>> _pending = [];
    private readonly UdpBatchSender _sender = new();

    private UdpClient? _udp;
    private Task? _pumpTask;
    private bool _disposed;

    public Http3Client(string host,
                       int port = 443,
                       CertificateValidationOptions? certificateValidation = null,
                       bool enableDatagrams = false,
                       ulong webTransportMaxSessions = 0)
    {
        _host = host;
        _port = port;
        _connection = new Http3ClientConnection(host,
            certificateValidation: certificateValidation,
            enableDatagrams: enableDatagrams,
            webTransportMaxSessions: webTransportMaxSessions);
    }

    /// <summary>
    /// Die zugrunde liegende Verbindung. Nach <see cref="ConnectAsync"/> läuft die Hintergrund-Pump —
    /// dann NICHT mehr direkt zugreifen, sondern über <see cref="PerformAsync"/>/<see cref="QueryAsync"/>
    /// (die Pump und die API teilen sich den single-threaded Kern über ein Mutex).
    /// </summary>
    public Http3ClientConnection Connection => _connection;

    /// <summary>
    /// Baut die QUIC/TLS-Verbindung auf (Socket, Handshake, HTTP/3-Initialisierung) und startet die
    /// Hintergrund-Pump. Wirft <see cref="TimeoutException"/>, wenn der Handshake nicht innerhalb von
    /// <paramref name="timeout"/> (Standard 10 s) bestätigt ist.
    /// </summary>
    public async Task ConnectAsync(TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_pumpTask is not null)
            throw new InvalidOperationException("ConnectAsync wurde bereits aufgerufen.");

        IPAddress address = (await Dns.GetHostAddressesAsync(_host, cancellationToken).ConfigureAwait(false))
            .First(a => a.AddressFamily == AddressFamily.InterNetwork);
        _udp = new UdpClient(AddressFamily.InterNetwork);
        DisableIcmpUnreachableException(_udp);
        _udp.Connect(new IPEndPoint(address, _port));

        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _connection.Start();
            FlushLocked();
        }
        finally { _mutex.Release(); }

        _pumpTask = Task.Run(PumpLoopAsync, CancellationToken.None);

        if (!await WaitUntilAsync(c => c.HandshakeConfirmed, timeout ?? TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false))
            throw new TimeoutException($"QUIC/TLS-Handshake mit {_host}:{_port} nicht abgeschlossen.");
        await PerformAsync(c => c.InitializeHttp3(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Windows meldet ein ICMP „Port Unreachable" als SocketException auf dem UDP-Socket — für einen
    /// Client-Socket abschalten, damit die Pump nicht an einem (noch) toten Server-Port scheitert.
    /// </summary>
    private static void DisableIcmpUnreachableException(UdpClient udp)
    {
        if (!OperatingSystem.IsWindows())
            return;
        const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);
        udp.Client.IOControl(SIO_UDP_CONNRESET, [0, 0, 0, 0], null);
    }

    /// <summary>
    /// Sendet einen Request und liefert die vollständige Antwort. Bei Abbruch über
    /// <paramref name="cancellationToken"/> wird der Request per RESET_STREAM/STOP_SENDING
    /// annulliert (RFC 9114 §4.1.1); endgültige Fehlschläge werfen <see cref="Http3RequestException"/>.
    /// </summary>
    public async Task<Http3Response> SendAsync(Http3Request request, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var tcs = new TaskCompletionSource<Http3Response>(TaskCreationOptions.RunContinuationsAsynchronously);
        ulong streamId;

        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            streamId = _connection.SendRequest(request);
            _pending[streamId] = tcs;
            FlushLocked();
        }
        finally { _mutex.Release(); }

        await using CancellationTokenRegistration registration =
            cancellationToken.Register(() => _ = CancelRequestAsync(streamId, tcs));
        return await tcs.Task.ConfigureAwait(false);
    }

    /// <summary>
    /// Bequemer GET-Request.
    /// </summary>
    public Task<Http3Response> GetAsync(string path = "/", CancellationToken cancellationToken = default)
        => SendAsync(Http3Request.Get(_host, path), cancellationToken);

    /// <summary>
    /// Bequemer POST-Request mit Rumpf.
    /// </summary>
    public Task<Http3Response> PostAsync(string path, byte[] body,
                                         string contentType = "application/octet-stream",
                                         CancellationToken cancellationToken = default)
        => SendAsync(Http3Request.Post(_host, path, body, contentType), cancellationToken);

    /// <summary>
    /// Führt eine Aktion serialisiert auf der Verbindung aus (z. B. Datagramm senden, WebTransport
    /// öffnen) und flusht danach ausstehende QUIC-Datagramme.
    /// </summary>
    public async Task PerformAsync(Action<Http3ClientConnection> action, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            action(_connection);
            FlushLocked();
        }
        finally { _mutex.Release(); }
    }

    /// <summary>
    /// Liest serialisiert einen Wert von der Verbindung.
    /// </summary>
    public async Task<T> QueryAsync<T>(Func<Http3ClientConnection, T> query, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return query(_connection); }
        finally { _mutex.Release(); }
    }

    /// <summary>
    /// Wartet (pollend, die Pump arbeitet währenddessen weiter), bis die Bedingung erfüllt ist;
    /// <c>false</c> bei Ablauf von <paramref name="timeout"/>.
    /// </summary>
    public async Task<bool> WaitUntilAsync(Func<Http3ClientConnection, bool> condition, TimeSpan timeout,
                                           CancellationToken cancellationToken = default)
    {
        long deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        while (Environment.TickCount64 < deadline)
        {
            if (await QueryAsync(condition, cancellationToken).ConfigureAwait(false))
                return true;
            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
        }
        return false;
    }

    /// <summary>
    /// Schließt die Verbindung anständig (CONNECTION_CLOSE mit H3_NO_ERROR) und lässt der Gegenseite
    /// einen Moment, das Close-Paket zu empfangen.
    /// </summary>
    public async Task CloseAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed || _pumpTask is null)
            return;
        await PerformAsync(c => c.CloseGracefully(), cancellationToken).ConfigureAwait(false);
        await Task.Delay(50, cancellationToken).ConfigureAwait(false); // Close-Paket noch zustellen
    }

    // ---- Pump -----------------------------------------------------------------------------

    private async Task PumpLoopAsync()
    {
        Task<UdpReceiveResult>? receive = null;
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                receive ??= _udp!.ReceiveAsync(_cts.Token).AsTask();
                Task finished = await Task.WhenAny(receive, Task.Delay(TickInterval, _cts.Token)).ConfigureAwait(false);

                await _mutex.WaitAsync(_cts.Token).ConfigureAwait(false);
                try
                {
                    if (finished == receive)
                    {
                        UdpReceiveResult result = await receive.ConfigureAwait(false);
                        receive = null;
                        _connection.ProcessDatagram(result.Buffer);
                    }
                    _connection.CheckTimeouts();
                    FlushLocked();
                    CompleteFinishedRequestsLocked();
                }
                finally { _mutex.Release(); }
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { receive = null; } // z. B. ICMP auf Nicht-Windows — weiterpumpen
        }
    }

    private void FlushLocked()
    {
        if (_udp is null)
            return;
        // Verbundener Socket (remote = null) ⇒ Send; auf Linux via GSO gebündelt (RFC-neutral, nur Syscalls).
        _sender.Send(_udp.Client, _connection.GetDatagramsToSend(), remote: null);
    }

    /// <summary>
    /// Vollendet die Tasks aller Requests, deren Ausgang feststeht (Antwort da oder endgültig
    /// gescheitert); bei geschlossener Verbindung scheitern alle ausstehenden Requests.
    /// </summary>
    private void CompleteFinishedRequestsLocked()
    {
        if (_pending.Count == 0)
            return;
        foreach ((ulong id, TaskCompletionSource<Http3Response> tcs) in _pending.ToArray())
        {
            if (_connection.TryGetResponse(id, out Http3Response? response))
                tcs.TrySetResult(response!);
            else if (_connection.IsRequestRejected(id))
                tcs.TrySetException(new Http3RequestException(
                    "Der Request wurde per GOAWAY zurückgewiesen (RFC 9114 §5.2) — auf neuer Verbindung wiederholbar.", isRetryable: true));
            else if (_connection.IsResponseMalformed(id))
                tcs.TrySetException(new Http3RequestException("Die Antwort war malformed und wurde verworfen (RFC 9114 §4.1.2)."));
            else if (_connection.IsResponseTooLarge(id))
                tcs.TrySetException(new Http3RequestException("Die Antwort-Header überschreiten unser MAX_FIELD_SECTION_SIZE (RFC 9114 §4.2.2)."));
            else if (_connection.IsRequestCancelled(id))
                tcs.TrySetException(new Http3RequestException("Der Request wurde abgebrochen (RFC 9114 §4.1.1)."));
            else
                continue;
            _pending.Remove(id);
        }

        if (_connection.IsClosing || _connection.IsDraining || _connection.IsIdleTimedOut)
        {
            foreach (TaskCompletionSource<Http3Response> tcs in _pending.Values)
                tcs.TrySetException(new Http3RequestException("Die Verbindung wurde geschlossen."));
            _pending.Clear();
        }
    }

    private async Task CancelRequestAsync(ulong streamId, TaskCompletionSource<Http3Response> tcs)
    {
        try
        {
            await _mutex.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_pending.Remove(streamId))
                {
                    _connection.CancelRequest(streamId); // §4.1.1: RESET_STREAM + STOP_SENDING
                    FlushLocked();
                }
            }
            finally { _mutex.Release(); }
        }
        catch (ObjectDisposedException) { }
        tcs.TrySetCanceled();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;
        _disposed = true;
        _cts.Cancel();
        if (_pumpTask is { } pump)
            try { await pump.ConfigureAwait(false); } catch { /* Pump-Ende */ }
        foreach (TaskCompletionSource<Http3Response> tcs in _pending.Values)
            tcs.TrySetException(new Http3RequestException("Der Client wurde geschlossen."));
        _pending.Clear();
        _udp?.Dispose();
        _connection.Dispose();
        _cts.Dispose();
        _mutex.Dispose();
    }
}
