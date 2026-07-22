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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;

/// <summary>
/// Frame-Typ-Werte in QUIC v1 (RFC 9000, Tabelle 3). Nicht erschöpfend – erweitert sich mit den Phasen.
/// </summary>
public static class FrameType
{
    public const ulong Padding = 0x00;
    public const ulong Ping = 0x01;
    public const ulong AckNoEcn = 0x02;
    public const ulong AckEcn = 0x03;
    public const ulong ResetStream = 0x04;
    public const ulong StopSending = 0x05;
    public const ulong Crypto = 0x06;
    public const ulong NewToken = 0x07;

    /// <summary>
    /// STREAM-Frames belegen 0x08..0x0f; die unteren 3 Bits kodieren OFF/LEN/FIN.
    /// </summary>
    public const ulong StreamBase = 0x08;
    public const ulong StreamMask = 0x08;
    public const byte StreamFinBit = 0x01;
    public const byte StreamLenBit = 0x02;
    public const byte StreamOffBit = 0x04;

    public const ulong MaxData = 0x10;
    public const ulong MaxStreamData = 0x11;
    public const ulong MaxStreamsBidi = 0x12;
    public const ulong MaxStreamsUni = 0x13;
    public const ulong DataBlocked = 0x14;
    public const ulong StreamDataBlocked = 0x15;
    public const ulong StreamsBlockedBidi = 0x16;
    public const ulong StreamsBlockedUni = 0x17;

    public const ulong PathChallenge = 0x1a;
    public const ulong PathResponse = 0x1b;
    public const ulong ConnectionCloseQuic = 0x1c;
    public const ulong ConnectionCloseApp = 0x1d;
    public const ulong HandshakeDone = 0x1e;

    public static bool IsStream(ulong type) => type is >= StreamBase and <= 0x0f;
}
