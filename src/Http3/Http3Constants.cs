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

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// HTTP/3-Frame-Typen (RFC 9114 §7.2). Unbekannte Typen werden ignoriert (Greasing).
/// </summary>
public static class Http3FrameType
{
    public const ulong Data = 0x00;
    public const ulong Headers = 0x01;
    public const ulong CancelPush = 0x03;
    public const ulong Settings = 0x04;
    public const ulong PushPromise = 0x05;
    public const ulong GoAway = 0x07;
    public const ulong MaxPushId = 0x0d;
}

/// <summary>
/// Typ-Präfixe unidirektionaler HTTP/3-Streams (RFC 9114 §6.2, RFC 9204 §4.2).
/// </summary>
public static class Http3StreamType
{
    public const ulong Control = 0x00;
    public const ulong Push = 0x01;
    public const ulong QpackEncoder = 0x02;
    public const ulong QpackDecoder = 0x03;
}

/// <summary>
/// SETTINGS-Parameter-IDs (RFC 9114 §7.2.4.1, RFC 9204 §5).
/// </summary>
public static class Http3Setting
{
    public const ulong QpackMaxTableCapacity = 0x01;
    public const ulong MaxFieldSectionSize = 0x06;
    public const ulong QpackBlockedStreams = 0x07;
}
