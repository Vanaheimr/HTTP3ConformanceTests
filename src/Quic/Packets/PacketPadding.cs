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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

/// <summary>
/// Sorgt dafür, dass Paketnummer und Nutzlast zusammen lang genug für das Header-Protection-Sample sind
/// (RFC 9001 §5.4.2). Das 16-Byte-Sample beginnt 4 Bytes hinter dem Beginn des Paketnummernfelds; damit
/// es (zusammen mit dem 16-Byte-AEAD-Tag) im Paket liegt, muss <c>Paketnummernlänge + Nutzlast ≥ 4</c>
/// gelten. Fehlende Bytes werden mit PADDING (0x00) aufgefüllt.
/// </summary>
public static class PacketPadding
{
    public static byte[] ForSampling(ReadOnlySpan<byte> payload, int packetNumberLength)
    {
        int minPayload = 4 - packetNumberLength;
        int length = Math.Max(payload.Length, minPayload);
        byte[] result = new byte[length];
        payload.CopyTo(result);
        // Der Rest bleibt 0 ⇒ PADDING-Frames.
        return result;
    }
}
