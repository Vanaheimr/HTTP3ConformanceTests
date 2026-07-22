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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;

/// <summary>
/// Verwaltet die Connection IDs einer Verbindung (RFC 9000 §5.1): den Satz der <b>lokal</b> ausgegebenen
/// IDs (die der Peer als Destination Connection ID nutzt) und den Satz der <b>entfernten</b>, vom Peer
/// per NEW_CONNECTION_ID angebotenen IDs (die wir als DCID nutzen). Jede ID trägt eine Sequenznummer;
/// Nummer 0 ist die aus dem Handshake. Erzeugt die zu sendenden NEW_/RETIRE_CONNECTION_ID-Frames und
/// bestimmt beim „Retire Prior To" bzw. bei einer Rotation die neue DCID.
/// </summary>
public sealed class ConnectionIdManager
{
    private sealed class Entry(ulong seq, ConnectionId cid, byte[] token)
    {
        public ulong Seq { get; } = seq;
        public ConnectionId Cid { get; } = cid;
        public byte[] Token { get; set; } = token; // 16-Byte Stateless-Reset-Token (leer = keins bekannt)
    }

    private readonly List<Entry> _local = [];   // von uns ausgegeben (Peer → DCID)
    private readonly List<Entry> _remote = [];  // vom Peer ausgegeben (wir → DCID)
    private ulong _nextLocalSeq = 1;
    private ulong _currentRemoteSeq;

    /// <summary>
    /// Legt den Manager mit der lokalen Handshake-CID (Sequenz 0) an.
    /// </summary>
    public ConnectionIdManager(ConnectionId localSeq0) => _local.Add(new Entry(0, localSeq0, []));

    /// <summary>
    /// Registriert die entfernte Handshake-CID (Sequenz 0), sobald sie feststeht. Einmalig.
    /// </summary>
    public void InitializeRemote(ConnectionId remoteSeq0)
    {
        if (_remote.Count == 0)
        {
            _remote.Add(new Entry(0, remoteSeq0, []));
            _currentRemoteSeq = 0;
        }
    }

    /// <summary>
    /// Anzahl aktiver, von uns ausgegebener Connection IDs (inkl. Sequenz 0).
    /// </summary>
    public int LocalCount => _local.Count;

    /// <summary>
    /// Anzahl bekannter, vom Peer ausgegebener Connection IDs.
    /// </summary>
    public int RemoteCount => _remote.Count;

    /// <summary>
    /// Sequenznummer der aktuell als DCID genutzten entfernten Connection ID.
    /// </summary>
    public ulong CurrentRemoteSequence => _currentRemoteSeq;

    /// <summary>
    /// <c>true</c>, wenn <paramref name="cid"/> eine unserer aktiven lokalen Connection IDs ist.
    /// </summary>
    public bool IsLocalConnectionId(ConnectionId cid) => _local.Exists(e => e.Cid == cid);

    /// <summary>
    /// Setzt den Stateless-Reset-Token der entfernten Handshake-CID (aus dem <c>stateless_reset_token</c>-TP).
    /// </summary>
    public void SetInitialRemoteToken(byte[] token)
    {
        Entry? seq0 = _remote.Find(e => e.Seq == 0);
        if (seq0 is not null && token.Length == StatelessReset.TokenLength)
            seq0.Token = token;
    }

    /// <summary>
    /// Prüft konstantzeitig, ob <paramref name="candidate"/> einem der uns bekannten Stateless-Reset-Tokens
    /// des Peers entspricht (aus NEW_CONNECTION_ID bzw. dem Transport-Parameter). Für die Erkennung eines
    /// Stateless Resets (RFC 9000 §10.3.1).
    /// </summary>
    public bool MatchesRemoteStatelessResetToken(ReadOnlySpan<byte> candidate)
    {
        bool match = false;
        foreach (Entry e in _remote)
            if (e.Token.Length == StatelessReset.TokenLength &&
                CryptographicOperations.FixedTimeEquals(e.Token, candidate))
                match = true; // ohne Early-Exit, um die Laufzeit nicht token-abhängig zu machen
        return match;
    }

    /// <summary>
    /// Gibt eine neue lokale Connection ID aus, sofern das vom Peer angekündigte Limit
    /// (<paramref name="activeLimit"/>, inkl. Sequenz 0) es zulässt. Liefert das zu sendende Frame oder <c>null</c>.
    /// </summary>
    public NewConnectionIdFrame? Issue(ConnectionId newCid, byte[] token, ulong activeLimit)
    {
        if ((ulong)_local.Count >= activeLimit)
            return null;
        ulong seq = _nextLocalSeq++;
        _local.Add(new Entry(seq, newCid, token));
        return new NewConnectionIdFrame(seq, RetirePriorTo: 0, newCid.ToArray(), token);
    }

    /// <summary>
    /// Der Peer zieht eine unserer lokalen Connection IDs zurück (RETIRE_CONNECTION_ID).
    /// </summary>
    public void RetireLocal(ulong sequenceNumber) => _local.RemoveAll(e => e.Seq == sequenceNumber);

    /// <summary>
    /// Verarbeitet ein NEW_CONNECTION_ID des Peers: nimmt die neue entfernte ID auf und zieht bei
    /// „Retire Prior To" alle niedriger nummerierten zurück (liefert die zu sendenden RETIRE-Frames).
    /// Wird dabei die aktuelle DCID zurückgezogen, wird auf die niedrigste verbliebene gewechselt
    /// (<paramref name="newDcid"/> gesetzt, <paramref name="dcidChanged"/> = <c>true</c>).
    /// </summary>
    public List<RetireConnectionIdFrame> OnNewConnectionId(NewConnectionIdFrame frame, out bool dcidChanged, out ConnectionId newDcid)
    {
        dcidChanged = false;
        newDcid = default;

        if (!_remote.Exists(e => e.Seq == frame.SequenceNumber))
            _remote.Add(new Entry(frame.SequenceNumber, new ConnectionId(frame.ConnectionId.Span), frame.StatelessResetToken.ToArray()));

        var retires = new List<RetireConnectionIdFrame>();
        if (frame.RetirePriorTo == 0)
            return retires;

        foreach (Entry e in _remote.FindAll(e => e.Seq < frame.RetirePriorTo))
        {
            _remote.Remove(e);
            retires.Add(new RetireConnectionIdFrame(e.Seq));
        }
        if (!_remote.Exists(e => e.Seq == _currentRemoteSeq) && LowestRemote() is { } next)
        {
            _currentRemoteSeq = next.Seq;
            newDcid = next.Cid;
            dcidChanged = true;
        }
        return retires;
    }

    /// <summary>
    /// Wechselt die DCID aktiv auf eine unbenutzte, höher nummerierte entfernte Connection ID und zieht
    /// die bisherige zurück. Liefert (RETIRE-Frame für die alte, neue DCID) oder <c>null</c>, wenn keine
    /// weitere ID verfügbar ist.
    /// </summary>
    public (RetireConnectionIdFrame Retire, ConnectionId NewDcid)? Rotate()
    {
        Entry? next = null;
        foreach (Entry e in _remote)
            if (e.Seq > _currentRemoteSeq && (next is null || e.Seq < next.Seq))
                next = e;
        if (next is null)
            return null;

        ulong oldSeq = _currentRemoteSeq;
        _remote.RemoveAll(e => e.Seq == oldSeq);
        _currentRemoteSeq = next.Seq;
        return (new RetireConnectionIdFrame(oldSeq), next.Cid);
    }

    private Entry? LowestRemote()
    {
        Entry? lowest = null;
        foreach (Entry e in _remote)
            if (lowest is null || e.Seq < lowest.Seq)
                lowest = e;
        return lowest;
    }
}
