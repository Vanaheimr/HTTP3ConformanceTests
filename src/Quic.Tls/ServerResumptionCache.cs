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

using System.Security.Cryptography;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;

/// <summary>
/// Ein einfacher, prozesslokaler Ticket-Store für die Server-Seite der Session Resumption (RFC 8446 §4.6.1).
/// Statt eines selbstverschlüsselnden Tickets (self-encrypted) hält der Server hier die ausgegebenen PSKs
/// zustandsbehaftet unter einer zufälligen Identity vor. Ausreichend für eigenen Server + Tests; ein echter
/// Deployment-Server würde die Daten stattdessen AEAD-verschlüsselt ins Ticket kodieren.
/// </summary>
public sealed class ServerResumptionCache
{
    private sealed record Entry(byte[] Psk, CipherSuite CipherSuite, uint MaxEarlyDataSize, byte[] TransportParameters);

    private readonly Dictionary<string, Entry> _entries = [];
    private readonly object _lock = new();

    /// <summary>
    /// Legt eine neue Ticket-Identity für eine PSK an und gibt die opaken Ticket-Bytes zurück.
    /// </summary>
    public byte[] Issue(byte[] psk, CipherSuite cipherSuite, uint maxEarlyDataSize, byte[] transportParameters)
    {
        byte[] identity = RandomNumberGenerator.GetBytes(32);
        lock (_lock)
            _entries[Convert.ToHexString(identity)] = new Entry(psk, cipherSuite, maxEarlyDataSize, transportParameters);
        return identity;
    }

    /// <summary>
    /// Löst eine vom Client zurückgespielte Ticket-Identity in die gespeicherte PSK auf.
    /// </summary>
    public bool TryResolve(byte[] identity, out byte[] psk, out CipherSuite cipherSuite)
    {
        lock (_lock)
        {
            if (_entries.TryGetValue(Convert.ToHexString(identity), out Entry? entry))
            {
                psk = entry.Psk;
                cipherSuite = entry.CipherSuite;
                return true;
            }
        }
        psk = [];
        cipherSuite = default;
        return false;
    }
}
