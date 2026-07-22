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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;

/// <summary>
/// Idle-Timeout nach RFC 9000 §10.1. Der ausgehandelte Wert ist das Minimum der beiderseits
/// angekündigten <c>max_idle_timeout</c>-Werte (0 = bei diesem Peer deaktiviert). Effektiv wird er auf
/// mindestens <c>3·PTO</c> angehoben, damit der Timeout nicht kürzer als eine plausible Zustellzeit wird.
/// Der Timer startet neu, wenn ein Paket erfolgreich empfangen wurde – und beim Senden eines
/// ack-eliciting Pakets, sofern seit dem letzten Empfang noch keines gesendet wurde.
/// <para>Zeitpunkte sind <see cref="TimeSpan.Ticks"/> (100 ns) einer monotonen Uhr.</para>
/// </summary>
public sealed class IdleTimeout
{
    private TimeSpan _negotiated;               // 0 = deaktiviert
    private long _lastActivityTicks;
    private bool _ackElicitingSinceReceive;

    /// <summary>
    /// <c>true</c>, sobald mindestens eine Seite einen Idle-Timeout angekündigt hat.
    /// </summary>
    public bool Enabled => _negotiated > TimeSpan.Zero;

    /// <summary>
    /// Der ausgehandelte (noch nicht mit 3·PTO verrechnete) Idle-Timeout.
    /// </summary>
    public TimeSpan Negotiated => _negotiated;

    /// <summary>
    /// Handelt den Idle-Timeout aus den lokalen und Peer-Werten (in ms) aus: Minimum der
    /// von null verschiedenen Werte; sind beide 0, bleibt der Timeout deaktiviert.
    /// </summary>
    public void Negotiate(ulong localMs, ulong peerMs)
    {
        ulong negotiated = (localMs, peerMs) switch
        {
            (0, 0) => 0,
            (0, _) => peerMs,
            (_, 0) => localMs,
            _ => Math.Min(localMs, peerMs),
        };
        _negotiated = TimeSpan.FromMilliseconds(negotiated);
    }

    /// <summary>
    /// Startet den Timer (Verbindungsbeginn).
    /// </summary>
    public void Start(long nowTicks)
    {
        _lastActivityTicks = nowTicks;
        _ackElicitingSinceReceive = false;
    }

    /// <summary>
    /// Ein Paket wurde erfolgreich empfangen und verarbeitet: Timer neu starten (RFC 9000 §10.1).
    /// </summary>
    public void OnPacketReceived(long nowTicks)
    {
        _lastActivityTicks = nowTicks;
        _ackElicitingSinceReceive = false;
    }

    /// <summary>
    /// Ein ack-eliciting Paket wurde gesendet: Timer neu starten, sofern seit dem letzten Empfang noch
    /// keines gesendet wurde (RFC 9000 §10.1) – so verlängern reine Sendebursts den Timeout nicht endlos.
    /// </summary>
    public void OnAckElicitingPacketSent(long nowTicks)
    {
        if (_ackElicitingSinceReceive)
            return;
        _lastActivityTicks = nowTicks;
        _ackElicitingSinceReceive = true;
    }

    /// <summary>
    /// Ob (Keep-Alive, RFC 9000 §10.1.2) ein ack-eliciting Paket fällig ist, weil seit der letzten
    /// Aktivität mehr als <paramref name="interval"/> verstrichen ist. Nur relevant, solange ein
    /// Idle-Timeout ausgehandelt ist; <paramref name="interval"/> sollte kleiner als dieser sein.
    /// </summary>
    public bool ShouldSendKeepAlive(long nowTicks, TimeSpan interval)
        => Enabled && nowTicks - _lastActivityTicks >= interval.Ticks;

    /// <summary>
    /// Ob der Timeout abgelaufen ist. Die effektive Grenze ist <c>max(negotiated, 3·pto)</c>
    /// (RFC 9000 §10.1: „at least three times the current Probe Timeout").
    /// </summary>
    public bool IsExpired(long nowTicks, TimeSpan pto)
    {
        if (!Enabled)
            return false;
        TimeSpan threePto = 3 * pto;
        long limitTicks = (_negotiated > threePto ? _negotiated : threePto).Ticks;
        return nowTicks - _lastActivityTicks > limitTicks;
    }
}
