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
/// CRYPTO-Frame (Typ 0x06, RFC 9000 §19.6): transportiert TLS-Handshake-Bytes als geordneten
/// Byte-Strom je Encryption-Level. Funktional wie ein STREAM-Frame, aber ohne Stream-ID, ohne
/// Flow Control und ohne FIN.
/// </summary>
public sealed record CryptoFrame(ulong Offset, ReadOnlyMemory<byte> Data) : Frame
{
    public override void Write(ref BufferWriter writer)
    {
        writer.WriteVarInt(FrameType.Crypto);
        writer.WriteVarInt(Offset);
        writer.WriteVarInt((ulong)Data.Length);
        writer.WriteBytes(Data.Span);
    }

    /// <summary>
    /// Parst den Frame-Rumpf (nach dem bereits gelesenen Typ-Feld).
    /// </summary>
    public static bool TryReadBody(ref BufferReader reader, out CryptoFrame? frame)
    {
        frame = null;
        if (!reader.TryReadVarInt(out ulong offset) ||
            !reader.TryReadVarInt(out ulong length) ||
            length > (ulong)reader.Remaining ||
            !reader.TryReadBytes((int)length, out ReadOnlySpan<byte> data))
            return false;

        frame = new CryptoFrame(offset, data.ToArray());
        return true;
    }
}
