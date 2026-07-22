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
/// Ein QUIC-Stream: bündelt Sende- und Empfangsseite (RFC 9000 §2). Bidirektionale Streams nutzen
/// beide, unidirektionale nur eine Richtung. Die eigentliche Frame-Erzeugung/-Aufnahme übernehmen
/// <see cref="StreamSendBuffer"/> und <see cref="StreamReceiveBuffer"/>; diese Klasse bietet die
/// anwendungsnahe Sicht.
/// </summary>
public sealed class QuicStream
{
    public StreamId Id { get; }
    public StreamSendBuffer Send { get; }
    public StreamReceiveBuffer Receive { get; }

    public QuicStream(StreamId id, ulong initialSendLimit = 0, ulong initialReceiveLimit = ulong.MaxValue)
    {
        Id = id;
        Send = new StreamSendBuffer(id.Value) { MaxData = initialSendLimit };
        Receive = new StreamReceiveBuffer { MaxData = initialReceiveLimit };
    }

    /// <summary>
    /// Schreibt Anwendungsdaten in den Sendepuffer.
    /// </summary>
    public void Write(ReadOnlySpan<byte> data) => Send.Write(data);

    /// <summary>
    /// Markiert das Ende des gesendeten Streams (FIN).
    /// </summary>
    public void Finish() => Send.Finish();

    /// <summary>
    /// Liest den nächsten zusammenhängenden empfangenen Abschnitt.
    /// </summary>
    public byte[] Read() => Receive.ReadAvailable();

    /// <summary>
    /// Der empfangene Stream ist vollständig gelesen (FIN erreicht). Nach einem Peer-Reset nie <c>true</c>.
    /// </summary>
    public bool IsReceiveComplete => Receive.IsComplete;

    /// <summary>
    /// Bricht die Sendeseite abrupt ab (RFC 9000 §2.4/§19.4): ungesendete Daten werden verworfen, der
    /// Endpoint sendet ein RESET_STREAM mit <paramref name="errorCode"/> (zuverlässig, via Loss Recovery).
    /// </summary>
    public void Reset(ulong errorCode) => Send.Reset(errorCode);

    /// <summary>
    /// Bricht die Sendeseite ab, garantiert aber die zuverlässige Zustellung der ersten
    /// <paramref name="reliableSize"/> bereits gesendeten Bytes (draft-ietf-quic-reliable-stream-reset §5):
    /// der Endpoint sendet ein RESET_STREAM_AT (sofern der Peer die Extension unterstützt, sonst ein
    /// gewöhnliches RESET_STREAM). Nützlich, wenn der Empfänger einen kritischen Präfix (z. B. den
    /// WebTransport-Stream-Kopf) trotz Abbruch sehen muss.
    /// </summary>
    public void ResetAt(ulong errorCode, ulong reliableSize) => Send.ResetAt(errorCode, reliableSize);

    /// <summary>
    /// Bricht das Lesen ab (RFC 9000 §2.4/§3.5): der Endpoint sendet ein STOP_SENDING mit
    /// <paramref name="errorCode"/> und bittet den Peer so um ein RESET_STREAM seiner Sendeseite.
    /// </summary>
    public void AbortRead(ulong errorCode) => Receive.AbortReading(errorCode);

    /// <summary>
    /// Der Peer hat seine Sendeseite per RESET_STREAM abgebrochen (Fehlercode in
    /// <see cref="PeerResetErrorCode"/>).
    /// </summary>
    public bool IsResetByPeer => Receive.ResetReceived;

    /// <summary>
    /// Der Fehlercode aus dem RESET_STREAM des Peers, falls empfangen.
    /// </summary>
    public ulong? PeerResetErrorCode => Receive.ResetReceived ? Receive.ResetErrorCode : null;

    /// <summary>
    /// Bei einem per RESET_STREAM_AT abgebrochenen Empfangsstream die (kleinste) Reliable Size, bis zu der
    /// der Peer die Bytes noch zuverlässig zustellt (draft-ietf-quic-reliable-stream-reset §5); <c>null</c>
    /// bei gewöhnlichem RESET_STREAM oder gar keinem Reset.
    /// </summary>
    public ulong? PeerReliableSize => Receive.ReliableSize;

    /// <summary>
    /// Der Fehlercode aus einem empfangenen STOP_SENDING des Peers, falls empfangen (unsere Sendeseite
    /// wurde daraufhin automatisch zurückgesetzt, RFC 9000 §3.5).
    /// </summary>
    public ulong? PeerStopSendingErrorCode { get; internal set; }

    /// <summary>
    /// Sende-Dringlichkeit nach RFC 9218 §4.1: 0 (höchste) … 7 (Hintergrund), Standard 3.
    /// Der Sende-Scheduler bedient Streams in aufsteigender Dringlichkeit; die Anwendungsschicht
    /// (HTTP/3) setzt den Wert aus `priority`-Header bzw. PRIORITY_UPDATE-Frames.
    /// </summary>
    public int SendUrgency { get; set; } = 3;

    /// <summary>
    /// Inkrementell nach RFC 9218 §4.2: <c>true</c> ⇒ gleich dringliche inkrementelle Streams teilen
    /// sich die Bandbreite (Round-Robin); <c>false</c> (Standard) ⇒ nacheinander in Stream-ID-Reihenfolge.
    /// </summary>
    public bool SendIncremental { get; set; }
}
