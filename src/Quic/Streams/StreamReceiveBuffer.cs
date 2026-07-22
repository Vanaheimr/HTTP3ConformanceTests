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

    /// <summary>
    /// Höchster empfangener Offset (Ende des am weitesten reichenden Fragments).
    /// </summary>
    public ulong HighestReceivedOffset { get; private set; }

    /// <summary>
    /// Gewährtes Flow-Control-Limit für diesen Stream (max_stream_data). Wächst über MAX_STREAM_DATA.
    /// </summary>
    public ulong MaxData { get; set; } = ulong.MaxValue;

    /// <summary>
    /// Offset bis zu dem der Anwendung bereits Bytes geliefert wurden.
    /// </summary>
    public ulong BytesConsumed => _readOffset;

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
        _readOffset = finalSize;
        _fragments.Clear();
        return StreamReceiveResult.Ok;
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
            _fragments[start] = slice.ToArray();
        }

        return StreamReceiveResult.Ok;
    }

    /// <summary>
    /// Liefert den nächsten zusammenhängenden, noch nicht gelesenen Abschnitt und rückt den
    /// Lese-Offset vor. Leeres Array, wenn (noch) keine zusammenhängenden Daten anliegen.
    /// </summary>
    public byte[] ReadAvailable()
    {
        using var ms = new MemoryStream();
        while (_fragments.Count > 0)
        {
            (ulong start, byte[] data) = First();
            if (start > _readOffset)
                break; // Lücke

            int skip = (int)(_readOffset - start);
            if (skip < data.Length)
            {
                ms.Write(data, skip, data.Length - skip);
                _readOffset = start + (ulong)data.Length;
            }
            _fragments.Remove(start);
        }
        return ms.ToArray();
    }

    private (ulong, byte[]) First()
    {
        foreach (KeyValuePair<ulong, byte[]> kv in _fragments)
            return (kv.Key, kv.Value);
        return (0, []);
    }
}
