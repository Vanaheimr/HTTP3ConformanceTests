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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;

/// <summary>
/// Routet WebTransport-Streams, -Datagramme und -Capsules zwischen der HTTP/3-Verbindung und den
/// <see cref="WebTransportSession"/>s (draft-ietf-webtrans-http3-13). Peer-initiierte Uni-Streams mit
/// Typ 0x54 (§4.1) und Bidi-Streams mit WT_STREAM-Signal 0x41 (§4.2) werden anhand ihrer Session-ID
/// zugeordnet; noch unbekannte Sessions werden begrenzt gepuffert (§4.5).
/// </summary>
internal sealed class WebTransportManager
{
    private const int MaxBufferedStreams = 16; // §4.5: Puffer begrenzen ⇒ WT_BUFFERED_STREAM_REJECTED

    private readonly bool _weAreClient;
    private readonly Dictionary<ulong, WebTransportSession> _sessions = [];   // Session-ID (CONNECT-Stream) → Session
    private readonly List<BufferedStream> _bufferedForUnknownSession = [];    // §4.5: warten auf ihre Session

    public WebTransportManager(bool weAreClient) => _weAreClient = weAreClient;

    public void RegisterSession(WebTransportSession session)
    {
        _sessions[session.SessionId] = session;
        DrainBufferedStreams(); // §4.5: früh angekommene Streams jetzt zuordnen
    }

    public bool TryGetSession(ulong sessionId, out WebTransportSession? session) => _sessions.TryGetValue(sessionId, out session);

    /// <summary>
    /// Ordnet einen erkannten WebTransport-Datenstrom seiner Session zu (§4.1/§4.2). Der Aufrufer hat
    /// den Kopf (Uni-Typ 0x54 bzw. WT_STREAM 0x41 ‖ Session-ID) bereits geparst und übergibt die schon
    /// mitgelesenen Nutzdaten als <paramref name="leftover"/>. Ist die Session noch nicht da, wird der
    /// Stream begrenzt gepuffert (§4.5) oder bei Überlauf mit WT_BUFFERED_STREAM_REJECTED verworfen.
    /// </summary>
    public void ClaimStream(QuicStream stream, ulong sessionId, byte[] leftover, bool bidirectional)
    {
        if (_sessions.TryGetValue(sessionId, out WebTransportSession? session))
        {
            Deliver(session, stream, bidirectional, leftover);
            return;
        }
        if (_bufferedForUnknownSession.Count >= MaxBufferedStreams)
        {
            stream.Reset(WebTransportConstants.BufferedStreamRejected);
            stream.AbortRead(WebTransportConstants.BufferedStreamRejected);
            return;
        }
        _bufferedForUnknownSession.Add(new BufferedStream(stream, sessionId, leftover, bidirectional));
    }

    private void DrainBufferedStreams()
    {
        for (int i = _bufferedForUnknownSession.Count - 1; i >= 0; i--)
        {
            BufferedStream buffered = _bufferedForUnknownSession[i];
            if (!_sessions.TryGetValue(buffered.SessionId, out WebTransportSession? session))
                continue;
            _bufferedForUnknownSession.RemoveAt(i);
            Deliver(session, buffered.Stream, buffered.Bidirectional, buffered.Leftover);
        }
    }

    private static void Deliver(WebTransportSession session, QuicStream stream, bool bidi, byte[] leftover)
    {
        if (bidi)
            session.OnIncomingBidiStream(stream, leftover);
        else
            session.OnIncomingUniStream(stream, leftover);
    }

    /// <summary>
    /// Liefert ein WebTransport-Datagramm an seine Session (die Quarter Stream ID adressiert den
    /// CONNECT-Stream, §4.4). <c>true</c>, wenn es zu einer bekannten Session gehörte.
    /// </summary>
    public bool TryDeliverDatagram(ulong sessionId, byte[] payload)
    {
        if (!_sessions.TryGetValue(sessionId, out WebTransportSession? session))
            return false;
        session.OnDatagram(payload);
        return true;
    }

    private sealed record BufferedStream(QuicStream Stream, ulong SessionId, byte[] Leftover, bool Bidirectional);
}
