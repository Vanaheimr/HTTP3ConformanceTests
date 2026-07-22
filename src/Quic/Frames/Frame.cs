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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;

/// <summary>
/// Basistyp aller QUIC-Frames (RFC 9000, §19). Ein Paket-Payload ist eine reine Aneinanderreihung
/// von Frames ohne Rahmen – die Frames sind nicht selbstbeschreibend, der Empfänger muss jeden Typ
/// kennen (unbekannte Typen ⇒ FRAME_ENCODING_ERROR).
/// </summary>
public abstract record Frame
{
    /// <summary>
    /// Serialisiert das Frame (inklusive Frame-Typ) in <paramref name="writer"/>.
    /// </summary>
    public abstract void Write(ref BufferWriter writer);
}

/// <summary>
/// Eine oder mehrere aufeinanderfolgende PADDING-Frames (Typ 0x00), zusammengefasst als Lauflänge.
/// Dienen dazu, ein Paket auf eine Mindestgröße zu bringen (z. B. Client-Initial ≥ 1200 Byte).
/// </summary>
public sealed record PaddingFrame(int Length) : Frame
{
    public override void Write(ref BufferWriter writer) => writer.WriteRepeated(0x00, Length);
}

/// <summary>
/// PING-Frame (Typ 0x01): löst beim Empfänger ein ACK aus; dient als Keep-Alive/Path-Probe.
/// </summary>
public sealed record PingFrame : Frame
{
    public static readonly PingFrame Instance = new();
    public override void Write(ref BufferWriter writer) => writer.WriteVarInt(FrameType.Ping);
}

/// <summary>
/// HANDSHAKE_DONE-Frame (Typ 0x1e): der Server bestätigt den abgeschlossenen Handshake.
/// </summary>
public sealed record HandshakeDoneFrame : Frame
{
    public static readonly HandshakeDoneFrame Instance = new();
    public override void Write(ref BufferWriter writer) => writer.WriteVarInt(FrameType.HandshakeDone);
}
