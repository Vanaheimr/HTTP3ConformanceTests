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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

/// <summary>
/// Eine einzelne TLS-Handshake-Nachricht: Typ, Rumpf und die vollständigen Bytes (für den Transcript).
/// </summary>
public readonly record struct HandshakeMessage(HandshakeType Type, ReadOnlyMemory<byte> Body, ReadOnlyMemory<byte> Full);

/// <summary>
/// Zerlegt einen (ggf. aus mehreren CRYPTO-Frames reassemblierten) Byte-Strom in einzelne
/// Handshake-Nachrichten. Jede Nachricht ist <c>Typ (1) ‖ Länge (3) ‖ Rumpf</c> (RFC 8446 §4).
/// </summary>
public static class HandshakeMessages
{
    /// <summary>
    /// Liest so viele vollständige Nachrichten wie möglich. <paramref name="consumed"/> gibt an, wie
    /// viele Bytes verbraucht wurden – der Rest ist eine noch unvollständige Nachricht (mehr CRYPTO-
    /// Daten nötig). Gibt <c>false</c> nur bei strukturell unmöglichen Längen zurück.
    /// </summary>
    public static bool TryReadAll(ReadOnlyMemory<byte> buffer, out List<HandshakeMessage> messages, out int consumed)
    {
        messages = [];
        consumed = 0;
        var reader = new BufferReader(buffer.Span);

        while (reader.Remaining >= 4)
        {
            int start = reader.Position;
            byte type = reader.ReadByte();
            int length = (reader.ReadByte() << 16) | (reader.ReadByte() << 8) | reader.ReadByte();

            if (reader.Remaining < length)
                break; // Nachricht noch nicht vollständig -> auf weitere CRYPTO-Daten warten

            reader.TrySkip(length);
            int end = reader.Position;
            messages.Add(new HandshakeMessage(
                (HandshakeType)type,
                buffer.Slice(start + 4, length),
                buffer.Slice(start, end - start)));
            consumed = end;
        }

        return true;
    }
}
