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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;

/// <summary>
/// Sendeseite eines Streams (RFC 9000 §3.1): puffert zu sendende Bytes und erzeugt daraus STREAM-
/// Frames, begrenzt durch das Flow-Control-Fenster des Peers (max_stream_data) und die maximale
/// Frame-Größe. Verfolgt den Sende-Offset und das FIN.
/// </summary>
public sealed class StreamSendBuffer(ulong streamId)
{
    private readonly List<byte> _pending = [];
    private ulong _sentOffset;
    private bool _finQueued;
    private bool _finSent;

    public StreamId StreamId { get; } = new(streamId);

    /// <summary>
    /// Vom Peer gewährtes Sende-Limit (max_stream_data). Wächst über MAX_STREAM_DATA.
    /// </summary>
    public ulong MaxData { get; set; }

    /// <summary>
    /// Bereits in Frames ausgegebene Byte-Menge (Sende-Offset).
    /// </summary>
    public ulong SentOffset => _sentOffset;

    /// <summary>
    /// Die Sendeseite wurde per RESET_STREAM abgebrochen (RFC 9000 §19.4).
    /// </summary>
    public bool IsReset { get; private set; }

    /// <summary>
    /// Der Fehlercode des Abbruchs (gültig, wenn <see cref="IsReset"/>).
    /// </summary>
    public ulong ResetErrorCode { get; private set; }

    /// <summary>
    /// Die im RESET_STREAM mitgeteilte Final Size (RFC 9000 §4.5: Anzahl bereits gesendeter Bytes).
    /// </summary>
    public ulong ResetFinalSize { get; private set; }

    /// <summary>
    /// Ein RESET_STREAM-Frame wartet auf die Emission (wird vom Endpoint abgeholt).
    /// </summary>
    public bool ResetPending { get; private set; }

    /// <summary>
    /// Der Abbruch erfolgte per RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset) mit garantierter
    /// Teilzustellung bis <see cref="ReliableSize"/>.
    /// </summary>
    public bool IsResetAt { get; private set; }

    /// <summary>
    /// Bei einem RESET_STREAM_AT die zuverlässig zuzustellende Byte-Menge; STREAM-Frames unterhalb dieses
    /// Offsets werden bei Verlust weiterhin retransmittiert (draft §5).
    /// </summary>
    public ulong ReliableSize { get; private set; }

    /// <summary>
    /// Es liegen noch nicht ausgegebene Daten oder ein ausstehendes FIN vor.
    /// </summary>
    public bool HasPending => !IsReset && (_pending.Count > 0 || (_finQueued && !_finSent));

    /// <summary>
    /// Der Sender ist durch das Flow-Control-Fenster blockiert (Daten da, aber kein Kredit).
    /// </summary>
    public bool IsBlocked => !IsReset && _pending.Count > 0 && _sentOffset >= MaxData;

    public void Write(ReadOnlySpan<byte> data)
    {
        if (IsReset)
            return; // nach dem Reset werden keine Daten mehr angenommen
        _pending.AddRange(data.ToArray());
    }

    /// <summary>
    /// Markiert das Stream-Ende; das nächste Frame, das die Restdaten leert, trägt das FIN.
    /// </summary>
    public void Finish() => _finQueued = true;

    /// <summary>
    /// Bricht die Sendeseite abrupt ab (RFC 9000 §19.4): verwirft ungesendete Daten, hält die Final
    /// Size (= gesendete Bytes, §4.5) fest und lässt den Endpoint ein RESET_STREAM emittieren. Nach dem
    /// Abbruch werden STREAM-Frames dieses Streams weder gesendet noch retransmittiert. Idempotent.
    /// </summary>
    public void Reset(ulong errorCode)
    {
        if (IsReset)
            return;
        IsReset = true;
        ResetPending = true;
        ResetErrorCode = errorCode;
        ResetFinalSize = _sentOffset;
        _pending.Clear();
    }

    /// <summary>
    /// Bricht die Sendeseite ab, garantiert aber die zuverlässige Zustellung der ersten
    /// <paramref name="reliableSize"/> Bytes (draft-ietf-quic-reliable-stream-reset §5). Es können nur
    /// bereits gesendete Bytes garantiert werden — die Reliable Size wird auf den aktuellen Sende-Offset
    /// begrenzt; ungesendete Daten werden wie beim gewöhnlichen Reset verworfen. Idempotent.
    /// </summary>
    public void ResetAt(ulong errorCode, ulong reliableSize)
    {
        if (IsReset)
            return;
        IsReset = true;
        IsResetAt = true;
        ResetPending = true;
        ResetErrorCode = errorCode;
        ResetFinalSize = _sentOffset;
        ReliableSize = Math.Min(reliableSize, _sentOffset); // nur bereits Gesendetes ist garantierbar
        _pending.Clear();
    }

    /// <summary>
    /// Holt das zu sendende RESET_STREAM- bzw. RESET_STREAM_AT-Frame ab (einmalig; Verlust-Wiederholung
    /// übernimmt die Loss Recovery). Ein RESET_STREAM_AT wird nur erzeugt, wenn der Peer die Extension
    /// angekündigt hat (<paramref name="peerSupportsResetAt"/>) — sonst degradiert der Abbruch zu einem
    /// gewöhnlichen RESET_STREAM (ohne Zustellgarantie).
    /// </summary>
    public Frame? TakeResetFrame(bool peerSupportsResetAt)
    {
        if (!ResetPending)
            return null;
        ResetPending = false;
        return IsResetAt && peerSupportsResetAt
            ? new ResetStreamAtFrame(StreamId.Value, ResetErrorCode, ResetFinalSize, ReliableSize)
            : new ResetStreamFrame(StreamId.Value, ResetErrorCode, ResetFinalSize);
    }

    /// <summary>
    /// Erzeugt das nächste STREAM-Frame (bis zu <paramref name="maxPayload"/> Bytes, innerhalb des
    /// Flow-Control-Fensters) oder <c>null</c>, wenn nichts zu senden ist.
    /// </summary>
    public StreamFrame? NextFrame(int maxPayload)
    {
        if (_finSent || IsReset)
            return null;

        ulong window = _sentOffset < MaxData ? MaxData - _sentOffset : 0;
        int count = (int)Math.Min(Math.Min((ulong)_pending.Count, (ulong)maxPayload), window);

        // Nur ein reines FIN-Frame (ohne Daten) senden, wenn keine Daten mehr ausstehen.
        bool fin = _finQueued && _pending.Count == count;
        if (count == 0 && !fin)
            return null;

        byte[] data = count > 0 ? _pending.GetRange(0, count).ToArray() : [];
        if (count > 0)
            _pending.RemoveRange(0, count);

        var frame = new StreamFrame(StreamId.Value, _sentOffset, data, fin);
        _sentOffset += (ulong)count;
        if (fin)
            _finSent = true;
        return frame;
    }
}
