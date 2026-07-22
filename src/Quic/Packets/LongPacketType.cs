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
/// Long-Header-Pakettypen in QUIC v1 (RFC 9000, Tabelle 5).
/// </summary>
public enum LongPacketType : byte
{
    Initial = 0x00,
    ZeroRtt = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
}

/// <summary>
/// Hilfsfunktionen für das erste Byte eines Pakets (RFC 9000, §17.2/§17.3).
/// </summary>
public static class PacketFormat
{
    /// <summary>
    /// Header Form (0x80): gesetzt = Long Header.
    /// </summary>
    public const byte HeaderFormBit = 0x80;

    /// <summary>
    /// Fixed Bit (0x40): bei gültigen Paketen gesetzt (außer Version Negotiation).
    /// </summary>
    public const byte FixedBit = 0x40;

    /// <summary>
    /// <c>true</c>, wenn das erste Byte einen Long Header ankündigt.
    /// </summary>
    public static bool IsLongHeader(byte firstByte) => (firstByte & HeaderFormBit) != 0;

    /// <summary>
    /// <c>true</c>, wenn das erste Byte einen Short Header (1-RTT) ankündigt.
    /// </summary>
    public static bool IsShortHeader(byte firstByte) => (firstByte & HeaderFormBit) == 0;

    /// <summary>
    /// Long Packet Type aus Bits 0x30 des ersten Bytes (nur gültig bei Long Headers).
    /// </summary>
    public static LongPacketType GetLongPacketType(byte firstByte) => (LongPacketType)((firstByte & 0x30) >> 4);

    /// <summary>
    /// Version Negotiation wird am Versionsfeld 0 erkannt – nicht am ersten Byte
    /// (dessen untere Bits sind bei VN unbestimmt). Diese Prüfung setzt einen Long Header voraus.
    /// </summary>
    public static bool IsVersionNegotiation(uint version) => version == 0;

    /// <summary>
    /// Baut das erste Byte eines Long-Header-Pakets mit Paketnummer (Initial/Handshake/0-RTT):
    /// Header Form + Fixed Bit + Typ, Reserved = 0, Packet Number Length = <paramref name="pnLength"/> − 1.
    /// </summary>
    public static byte BuildLongHeaderFirstByte(LongPacketType type, int pnLength)
    {
        if (pnLength is < 1 or > 4)
            throw new ArgumentOutOfRangeException(nameof(pnLength));
        return (byte)(HeaderFormBit | FixedBit | ((byte)type << 4) | (pnLength - 1));
    }
}
