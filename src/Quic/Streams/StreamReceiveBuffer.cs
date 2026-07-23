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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;

/// <summary>
/// Ergebnis der Aufnahme eines STREAM-Fragments in den Empfangspuffer.
/// </summary>
public enum StreamReceiveResult
{
    Ok,
    /// <summary>
    /// Der höchste Offset überschreitet das gewährte Flow-Control-Fenster ⇒ FLOW_CONTROL_ERROR.
    /// </summary>
    FlowControlError,
    /// <summary>
    /// Widersprüchliche Final Size (FIN) ⇒ FINAL_SIZE_ERROR.
    /// </summary>
    FinalSizeError,
    /// <summary>
    /// RESET_STREAM_AT mit Reliable Size &gt; Final Size (draft §4) ⇒ FRAME_ENCODING_ERROR.
    /// </summary>
    FrameEncodingError,
    /// <summary>
    /// Ein weiteres RESET_STREAM_AT/RESET_STREAM ändert den Fehlercode (draft §5.2) ⇒ STREAM_STATE_ERROR.
    /// </summary>
    StreamStateError,
}

/// <summary>
/// Empfangsseite eines Streams (RFC 9000 §2.2, §3.2): reassembliert (auch ungeordnete, überlappende)
/// STREAM-Daten zu einem geordneten Byte-Strom, verfolgt das FIN/die Final Size und erzwingt das
/// Flow-Control-Fenster. Konsumierte Bytes werden verworfen; <see cref="ReadAvailable"/> liefert den
/// nächsten zusammenhängenden Abschnitt.
/// </summary>
public sealed class StreamReceiveBuffer
{
    private readonly SortedDictionary<ulong, byte[]> _fragments = new();
    private ulong _readOffset;
    private ulong? _finalSize;
    private ulong _flowControlConsumed; // bei RESET(_AT) übernommene Final Size (Kredit-Abrechnung, entkoppelt vom Lese-Offset)
    private ulong? _reliableSize;       // kleinste Reliable Size eines RESET_STREAM_AT (draft §5.2)

    /// <summary>
    /// Höchster empfangener Offset (Ende des am weitesten reichenden Fragments).
    /// </summary>
    public ulong HighestReceivedOffset { get; private set; }

    /// <summary>
    /// Gewährtes Flow-Control-Limit für diesen Stream (max_stream_data). Wächst über MAX_STREAM_DATA.
    /// </summary>
    public ulong MaxData { get; set; } = ulong.MaxValue;

    /// <summary>
    /// Auto-Tuning des empfangsseitigen Stream-Fensters (Phase 9). <c>null</c> = festes Fenster (etwa
    /// bei Streams ohne gesetztes Limit); wird vom Endpoint beim Öffnen mit dem passenden Startwert und
    /// Wachstumslimit belegt.
    /// </summary>
    public ReceiveWindowTuner? WindowTuner { get; set; }

    /// <summary>
    /// Für die Flow-Control-Abrechnung „verbrauchter" Offset. Nach einem RESET(_AT) zählt die Final Size
    /// vollständig als verbraucht (§4.5), auch wenn der Lese-Offset (bei RESET_STREAM_AT) noch bei der
    /// Reliable Size verharrt, während die Anwendung die zuverlässig zugestellten Bytes abholt.
    /// </summary>
    public ulong BytesConsumed => Math.Max(_readOffset, _flowControlConsumed);

    /// <summary>
    /// Der Peer hat die Empfangsseite per RESET_STREAM_AT mit garantierter Teilzustellung abgebrochen; dies
    /// ist die (kleinste) Reliable Size, bis zu der Bytes noch an die Anwendung geliefert werden (draft §5).
    /// <c>null</c> = kein RESET_STREAM_AT.
    /// </summary>
    public ulong? ReliableSize => _reliableSize;

    /// <summary>
    /// FIN empfangen (Final Size bekannt).
    /// </summary>
    public bool FinReceived => _finalSize.HasValue;

    /// <summary>
    /// Der Peer hat diese Empfangsseite per RESET_STREAM abgebrochen (RFC 9000 §19.4).
    /// </summary>
    public bool ResetReceived { get; private set; }

    /// <summary>
    /// Der Fehlercode aus dem RESET_STREAM des Peers (gültig, wenn <see cref="ResetReceived"/>).
    /// </summary>
    public ulong ResetErrorCode { get; private set; }

    /// <summary>
    /// Wir haben das Lesen abgebrochen (RFC 9000 §3.5); ein STOP_SENDING wartet ggf. auf Emission.
    /// </summary>
    public bool ReadingAborted { get; private set; }

    /// <summary>
    /// Der Fehlercode unseres Leseabbruchs (gültig, wenn <see cref="ReadingAborted"/>).
    /// </summary>
    public ulong AbortErrorCode { get; private set; }

    /// <summary>
    /// Ein STOP_SENDING-Frame wartet auf die Emission (wird vom Endpoint abgeholt).
    /// </summary>
    public bool StopSendingPending { get; private set; }

    /// <summary>
    /// Alle Daten bis zum FIN wurden gelesen. Ein per RESET abgebrochener Stream gilt NIE als
    /// vollständig – die Anwendung erkennt den Abbruch über <see cref="ResetReceived"/>.
    /// </summary>
    public bool IsComplete => !ResetReceived && _finalSize == _readOffset && _fragments.Count == 0;

    /// <summary>
    /// Bricht das Lesen ab (RFC 9000 §3.5): der Endpoint sendet ein STOP_SENDING mit
    /// <paramref name="errorCode"/>; bereits gepufferte Daten werden verworfen. Idempotent.
    /// </summary>
    public void AbortReading(ulong errorCode)
    {
        if (ReadingAborted || ResetReceived)
            return; // §3.5: STOP_SENDING nur für Streams, die der Peer nicht schon zurückgesetzt hat
        ReadingAborted = true;
        StopSendingPending = true;
        AbortErrorCode = errorCode;
        _fragments.Clear();
    }

    /// <summary>
    /// Holt das zu sendende STOP_SENDING-Frame ab (einmalig; Verlust-Wiederholung übernimmt die
    /// Loss Recovery). Gibt die Stream-ID nicht mit – der Aufrufer kennt sie.
    /// </summary>
    public ulong? TakeStopSendingErrorCode()
    {
        if (!StopSendingPending)
            return null;
        StopSendingPending = false;
        return AbortErrorCode;
    }

    /// <summary>
    /// Verarbeitet ein empfangenes RESET_STREAM (RFC 9000 §19.4/§4.5): prüft die Final Size gegen
    /// Flow Control und bereits Gesehenes, übernimmt sie (verbindliche Flow-Control-Abrechnung) und
    /// verwirft gepufferte Daten (§19.4: „can discard any data").
    /// </summary>
    public StreamReceiveResult Reset(ulong errorCode, ulong finalSize)
    {
        if (finalSize > MaxData)
            return StreamReceiveResult.FlowControlError;   // §4.1: Final Size verbraucht Kredit
        if (_finalSize is { } known && known != finalSize)
            return StreamReceiveResult.FinalSizeError;     // §4.5: bekannte Final Size ist unveränderlich
        if (HighestReceivedOffset > finalSize)
            return StreamReceiveResult.FinalSizeError;     // §4.5: Daten jenseits der Final Size gesehen

        if (ResetReceived)
            return StreamReceiveResult.Ok; // idempotent (Retransmission des RESET_STREAM)

        ResetReceived = true;
        ResetErrorCode = errorCode;
        _finalSize = finalSize;
        HighestReceivedOffset = finalSize;
        // §4.5: die Final Size zählt vollständig als verbrauchter Flow-Control-Kredit — als „konsumiert"
        // verbuchen, damit die MAX_DATA-Fensterrechnung der Verbindung stimmig bleibt.
        _flowControlConsumed = finalSize;
        _readOffset = finalSize;
        _fragments.Clear();
        return StreamReceiveResult.Ok;
    }

    /// <summary>
    /// Verarbeitet ein empfangenes RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset §4/§5): wie
    /// <see cref="Reset"/>, aber die ersten <paramref name="reliableSize"/> Bytes werden weiterhin an die
    /// Anwendung geliefert. Mehrfache Frames dürfen die Reliable Size nur senken (§5.2); Erhöhungen (durch
    /// Reordering) werden ignoriert, ein geänderter Fehlercode ist ein STREAM_STATE_ERROR.
    /// </summary>
    public StreamReceiveResult ResetAt(ulong errorCode, ulong finalSize, ulong reliableSize)
    {
        if (reliableSize > finalSize)
            return StreamReceiveResult.FrameEncodingError; // draft §4
        if (finalSize > MaxData)
            return StreamReceiveResult.FlowControlError;    // §4.1: Final Size verbraucht Kredit
        if (_finalSize is { } known && known != finalSize)
            return StreamReceiveResult.FinalSizeError;      // §4.5: bekannte Final Size ist unveränderlich
        if (!ResetReceived && HighestReceivedOffset > finalSize)
            return StreamReceiveResult.FinalSizeError;      // §4.5: Daten jenseits der Final Size gesehen
        if (ResetReceived && errorCode != ResetErrorCode)
            return StreamReceiveResult.StreamStateError;    // draft §5.2: Fehlercode darf sich nicht ändern

        if (ResetReceived)
        {
            // §5.2: die Reliable Size darf nur sinken; Erhöhungen (Reordering) ignorieren.
            if (_reliableSize is { } prev && reliableSize < prev)
            {
                _reliableSize = reliableSize;
                TrimAboveReliable(reliableSize);
            }
            return StreamReceiveResult.Ok;
        }

        ResetReceived = true;
        ResetErrorCode = errorCode;
        _finalSize = finalSize;
        _reliableSize = reliableSize;
        HighestReceivedOffset = finalSize;
        // §4.5: die volle Final Size zählt als verbrauchter Kredit; der Lese-Offset verharrt aber bei der
        // Reliable Size, bis die Anwendung die zuverlässig zugestellten Bytes abgeholt hat.
        _flowControlConsumed = finalSize;
        TrimAboveReliable(reliableSize); // Daten jenseits der Reliable Size werden nicht mehr zugestellt
        return StreamReceiveResult.Ok;
    }

    /// <summary>
    /// Verwirft gepufferte Fragmente jenseits der Reliable Size und kürzt ein Fragment, das die Grenze
    /// überschreitet (draft §5.2: jenseits der Reliable Size wird nichts mehr zugestellt).
    /// </summary>
    private void TrimAboveReliable(ulong reliableSize)
    {
        foreach (ulong start in _fragments.Keys.ToArray())
        {
            if (start >= reliableSize)
            {
                _fragments.Remove(start);
                continue;
            }
            byte[] data = _fragments[start];
            if (start + (ulong)data.Length > reliableSize)
                _fragments[start] = data[..(int)(reliableSize - start)];
        }
    }

    /// <summary>
    /// Nimmt ein STREAM-Fragment auf.
    /// </summary>
    public StreamReceiveResult Receive(ulong offset, ReadOnlySpan<byte> data, bool fin)
    {
        ulong end = offset + (ulong)data.Length;
        if (end > MaxData)
            return StreamReceiveResult.FlowControlError;

        if (fin)
        {
            if (_finalSize is { } existing && existing != end)
                return StreamReceiveResult.FinalSizeError;
            // Daten dürfen nicht über die Final Size hinausgehen.
            if (HighestReceivedOffset > end)
                return StreamReceiveResult.FinalSizeError;
            _finalSize = end;
        }
        else if (_finalSize is { } fs && end > fs)
        {
            return StreamReceiveResult.FinalSizeError;
        }

        if (end > HighestReceivedOffset)
            HighestReceivedOffset = end;

        // Bereits konsumierte Daten überspringen.
        if (!data.IsEmpty && end > _readOffset)
        {
            ulong start = offset;
            ReadOnlySpan<byte> slice = data;
            if (start < _readOffset)
            {
                slice = data[(int)(_readOffset - start)..];
                start = _readOffset;
            }
            // Nach RESET_STREAM_AT nichts jenseits der Reliable Size mehr puffern (draft §5.2).
            if (_reliableSize is { } rel)
            {
                if (start >= rel)
                    return StreamReceiveResult.Ok;
                if (start + (ulong)slice.Length > rel)
                    slice = slice[..(int)(rel - start)];
            }
            _fragments[start] = slice.ToArray();
        }

        return StreamReceiveResult.Ok;
    }

    /// <summary>
    /// Liefert den nächsten zusammenhängenden, noch nicht gelesenen Abschnitt und rückt den
    /// Lese-Offset vor. Leeres Array, wenn (noch) keine zusammenhängenden Daten anliegen.
    /// Zero-Alloc-Pfad: der häufige Leer-Fall (jeder Pump-Durchlauf fragt jeden Stream) kostet
    /// nichts; sonst wird die Gesamtlänge vorab bestimmt und genau EIN Ergebnis-Array gefüllt.
    /// </summary>
    public byte[] ReadAvailable()
    {
        if (_fragments.Count == 0)
            return [];

        // Erster Durchlauf: zusammenhängende Länge ab dem Lese-Offset bestimmen (ohne zu kopieren).
        ulong cursor = _readOffset;
        int total = 0;
        foreach ((ulong start, byte[] data) in _fragments)
        {
            if (start > cursor)
                break; // Lücke
            ulong end = start + (ulong)data.Length;
            if (end > cursor)
                total += (int)(end - cursor);
            cursor = Math.Max(cursor, end);
        }
        if (total == 0)
            return [];

        // Zweiter Durchlauf: genau ein Ergebnis-Array füllen, konsumierte Fragmente entfernen.
        byte[] result = new byte[total];
        int written = 0;
        while (_fragments.Count > 0)
        {
            (ulong start, byte[] data) = First();
            if (start > _readOffset)
                break;
            int skip = (int)(_readOffset - start);
            if (skip < data.Length)
            {
                data.AsSpan(skip).CopyTo(result.AsSpan(written));
                written += data.Length - skip;
                _readOffset = start + (ulong)data.Length;
            }
            _fragments.Remove(start);
        }
        return result;
    }

    private (ulong, byte[]) First()
    {
        foreach (KeyValuePair<ulong, byte[]> kv in _fragments)
            return (kv.Key, kv.Value);
        return (0, []);
    }
}
