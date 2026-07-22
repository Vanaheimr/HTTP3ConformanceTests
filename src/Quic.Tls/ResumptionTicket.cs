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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;

/// <summary>
/// Ein clientseitig gespeichertes Session-Ticket (RFC 8446 §2.2/§4.6.1) für die spätere Wiederaufnahme
/// (Resumption / PSK). Enthält die aus dem NewSessionTicket abgeleitete Resumption-PSK, die Ticket-Identity,
/// den Verschleierungs-Offset für das Ticket-Alter, die Cipher-Suite (die PSK ist an ihren Hash gebunden)
/// sowie den Empfangszeitpunkt. <see cref="MaxEarlyDataSize"/> und <see cref="PeerTransportParameters"/>
/// werden erst für 0-RTT (Phase B) gebraucht.
/// </summary>
public sealed class ResumptionTicket
{
    public byte[] Psk { get; }
    public byte[] Identity { get; }
    public uint AgeAdd { get; }
    public CipherSuite CipherSuite { get; }
    public DateTimeOffset ReceivedAt { get; }
    public uint LifetimeSeconds { get; }
    public string ServerName { get; }
    public uint MaxEarlyDataSize { get; }
    public byte[] PeerTransportParameters { get; }

    public ResumptionTicket(
        byte[] psk,
        byte[] identity,
        uint ageAdd,
        CipherSuite cipherSuite,
        string serverName,
        uint lifetimeSeconds,
        uint maxEarlyDataSize,
        byte[] peerTransportParameters,
        DateTimeOffset? receivedAt = null)
    {
        Psk = psk;
        Identity = identity;
        AgeAdd = ageAdd;
        CipherSuite = cipherSuite;
        ServerName = serverName;
        LifetimeSeconds = lifetimeSeconds;
        MaxEarlyDataSize = maxEarlyDataSize;
        PeerTransportParameters = peerTransportParameters;
        ReceivedAt = receivedAt ?? DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// <c>true</c>, wenn 0-RTT-Daten mit diesem Ticket zulässig sind (Server kündigte max_early_data_size an).
    /// </summary>
    public bool AllowsEarlyData => MaxEarlyDataSize > 0;

    /// <summary>
    /// Das verschleierte Ticket-Alter (RFC 8446 §4.2.11.1): <c>(verstrichene ms + age_add) mod 2^32</c>.
    /// Der Server rechnet den <see cref="AgeAdd"/> wieder heraus und prüft das Alter gegen die Lebensdauer.
    /// </summary>
    public uint ObfuscatedTicketAge(DateTimeOffset now)
    {
        long elapsedMs = (long)(now - ReceivedAt).TotalMilliseconds;
        if (elapsedMs < 0)
            elapsedMs = 0;
        return unchecked((uint)elapsedMs + AgeAdd);
    }
}
