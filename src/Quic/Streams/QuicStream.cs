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
    /// Der empfangene Stream ist vollständig gelesen (FIN erreicht).
    /// </summary>
    public bool IsReceiveComplete => Receive.IsComplete;
}
