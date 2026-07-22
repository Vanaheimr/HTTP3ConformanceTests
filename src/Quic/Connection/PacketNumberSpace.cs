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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;

/// <summary>
/// Ein Packet-Number-Space (RFC 9000 §12.3): getrennt für Initial, Handshake und Application. Vergibt
/// aufsteigende Paketnummern beim Senden und merkt sich empfangene Nummern für die ACK-Erzeugung.
/// </summary>
public sealed class PacketNumberSpace
{
    private ulong _nextToSend;
    private readonly SortedSet<ulong> _received = [];

    // Kumulative ECN-Zähler der empfangenen Pakete dieses Space (RFC 9000 §13.4.2), gemeldet im ACK-Frame.
    private ulong _ect0Count;
    private ulong _ect1Count;
    private ulong _ceCount;

    /// <summary>
    /// Anzahl empfangener Pakete mit CE-Markierung (Diagnose/Test).
    /// </summary>
    public ulong ReceivedCeCount => _ceCount;

    /// <summary>
    /// Größte vom Peer bestätigte Paketnummer (für die Wahl der PN-Kodierungslänge); -1 = keine.
    /// </summary>
    public long LargestAckedByPeer { get; private set; } = -1;

    /// <summary>
    /// Größte bislang empfangene Paketnummer (für die PN-Rekonstruktion beim Empfang); -1 = keine.
    /// </summary>
    public long LargestReceived => _received.Count == 0 ? -1 : (long)_received.Max;

    /// <summary>
    /// Es liegen empfangene, noch nicht per ACK quittierte Pakete vor.
    /// </summary>
    public bool AckPending { get; private set; }

    /// <summary>
    /// <c>true</c>, wenn ab Paketnummer 0 lückenlos empfangen wurde (also genau {0,1,…,Max}, keine fehlenden
    /// Nummern). Paketnummern beginnen je Space bei 0 (RFC 9000 §12.3), daher ist das genau dann der Fall, wenn
    /// die Anzahl empfangener Pakete <c>Max+1</c> ist. Nutzung: der Server erkennt so, dass er alle 0-RTT-Pakete
    /// erhalten hat (RFC 9001 §4.9.3, „keeping track of missing packet numbers").
    /// </summary>
    public bool IsContiguousFromZero => _received.Count > 0 && (ulong)_received.Count == _received.Max + 1;

    /// <summary>
    /// Vergibt die nächste zu sendende Paketnummer.
    /// </summary>
    public ulong NextPacketNumber() => _nextToSend++;

    /// <summary>
    /// Vermerkt eine erfolgreich entschützte, empfangene Paketnummer samt ihrem ECN-Codepoint.
    /// </summary>
    public void RecordReceived(ulong packetNumber, EcnCodepoint ecn = EcnCodepoint.NotEct)
    {
        _received.Add(packetNumber);
        AckPending = true;
        switch (ecn)
        {
            case EcnCodepoint.Ect0: _ect0Count++; break;
            case EcnCodepoint.Ect1: _ect1Count++; break;
            case EcnCodepoint.Ce: _ceCount++; break;
        }
    }

    /// <summary>
    /// Verarbeitet ein empfangenes ACK-Frame (aktualisiert die größte bestätigte Nummer).
    /// </summary>
    public void OnAckReceived(ulong largestAcknowledged)
    {
        if ((long)largestAcknowledged > LargestAckedByPeer)
            LargestAckedByPeer = (long)largestAcknowledged;
    }

    /// <summary>
    /// Baut ein ACK-Frame über alle bislang empfangenen Pakete und markiert die ACKs als gesendet.
    /// Gibt <c>null</c> zurück, wenn nichts zu bestätigen ist.
    /// </summary>
    public AckFrame? BuildAck(ulong ackDelay = 0)
    {
        if (_received.Count == 0)
            return null;
        AckPending = false;

        // Sobald ECN-markierte Pakete empfangen wurden, MUSS jedes ACK die kumulativen Zähler tragen
        // (Typ 0x03, RFC 9000 §13.4.2). Ohne ECN-Markierungen bleibt es beim einfachen ACK (0x02).
        EcnCounts? ecn = (_ect0Count | _ect1Count | _ceCount) != 0
            ? new EcnCounts(_ect0Count, _ect1Count, _ceCount)
            : null;
        return AckFrame.FromPacketNumbers(_received, ackDelay) with { Ecn = ecn };
    }
}
