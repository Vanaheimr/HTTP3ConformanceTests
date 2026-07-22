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

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;

/// <summary>
/// Konstanten aus draft-ietf-webtrans-http3-13 (WebTransport über HTTP/3): SETTINGS, Stream-/Frame-
/// Signalwerte, Fehlercodes und Capsule-Typen (§4, §5, §6, §9).
/// </summary>
public static class WebTransportConstants
{
    // ---- HTTP/3-SETTINGS (§9.2) -----------------------------------------------------------

    /// <summary>SETTINGS_WT_MAX_SESSIONS — max. gleichzeitige Sessions; &gt;1 aktiviert Flow Control (§5.1).</summary>
    public const ulong SettingMaxSessions = 0x14e9cd29;
    public const ulong SettingInitialMaxStreamsUni = 0x2b64;
    public const ulong SettingInitialMaxStreamsBidi = 0x2b65;
    public const ulong SettingInitialMaxData = 0x2b61;

    // ---- Stream-/Frame-Signale (§4.1/§4.2, §9.3/§9.4) -------------------------------------

    /// <summary>Uni-Stream-Typ: 0x54 ‖ Session-ID ‖ Nutzdaten (§4.1).</summary>
    public const ulong UniStreamType = 0x54;

    /// <summary>WT_STREAM-Signal am Anfang eines Bidi-Streams: 0x41 ‖ Session-ID ‖ Nutzdaten (§4.2).</summary>
    public const ulong BidiStreamSignal = 0x41;

    // ---- Fehlercodes (§9.5) --------------------------------------------------------------

    public const ulong BufferedStreamRejected = 0x3994bd84;
    public const ulong SessionGone = 0x170d7b68;

    /// <summary>WT_APPLICATION_ERROR-Bereich (§4.3): 32-Bit-App-Codes werden hier hinein abgebildet.</summary>
    public const ulong ApplicationErrorFirst = 0x52e4a40fa8db;
    public const ulong ApplicationErrorLast = 0x52e5ac983162;

    // ---- Capsule-Typen (§6, §5.6, §9.6) --------------------------------------------------

    public const ulong CapsuleCloseSession = 0x2843;
    public const ulong CapsuleMaxStreamsBidi = 0x190B4D3F;
    public const ulong CapsuleMaxStreamsUni = 0x190B4D40;
    public const ulong CapsuleStreamsBlockedBidi = 0x190B4D43;
    public const ulong CapsuleStreamsBlockedUni = 0x190B4D44;
    public const ulong CapsuleMaxData = 0x190B4D3D;
    public const ulong CapsuleDataBlocked = 0x190B4D41;

    /// <summary>
    /// Bildet einen 32-Bit-WebTransport-Anwendungsfehler auf den HTTP/3-Fehlercode-Bereich ab
    /// (§4.3): <c>first + n + floor(n / 0x1e)</c> — überspringt die reservierten Greasing-Codepoints
    /// der Form 0x1f·N + 0x21.
    /// </summary>
    public static ulong ApplicationErrorToHttp(uint code)
        => ApplicationErrorFirst + code + code / 0x1e;

    /// <summary>
    /// Rückabbildung eines HTTP/3-Fehlercodes im WT_APPLICATION_ERROR-Bereich auf den 32-Bit-Code
    /// (§4.3); gibt <c>null</c> zurück, wenn er außerhalb des Bereichs oder ein reservierter Codepoint ist.
    /// </summary>
    public static uint? HttpToApplicationError(ulong http)
    {
        if (http < ApplicationErrorFirst || http > ApplicationErrorLast)
            return null;
        if ((http - 0x21) % 0x1f == 0)
            return null; // reservierter Greasing-Codepoint (§8.1 HTTP/3)
        ulong shifted = http - ApplicationErrorFirst;
        return (uint)(shifted - shifted / 0x1f);
    }
}
