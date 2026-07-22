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

using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Malformed-Erkennung für HTTP/3-Nachrichten (RFC 9114 §4.1.2, §4.2, §4.3): verbotene/fehlende/
/// ungültige Pseudo-Header, Pseudo-Header nach regulären Feldern oder in Trailern, Großbuchstaben
/// und ungültige Zeichen in Feldnamen/-werten, verbindungsspezifische Felder sowie die
/// Content-Length-Konsistenz. Die Prüfungen sind bewusst strikt — §4.1.2: „they are deliberately
/// strict because being permissive can expose implementations to these vulnerabilities."
/// Rückgabe: <c>null</c> = wohlgeformt, sonst eine kurze Begründung.
/// </summary>
internal static class Http3MessageValidator
{
    /// <summary>
    /// Prüft eine Request-Header-Sektion (RFC 9114 §4.3.1). CONNECT (§4.4) gilt als wohlgeformt,
    /// wenn :authority vorhanden ist und :scheme/:path fehlen — ob er unterstützt wird, entscheidet
    /// der Server (501).
    /// </summary>
    public static string? ValidateRequestHeaders(IReadOnlyList<HeaderField> fields)
    {
        bool regularSeen = false;
        int method = 0, scheme = 0, path = 0, authority = 0, protocol = 0;
        string methodValue = "", schemeValue = "", pathValue = "", authorityValue = "", protocolValue = "";
        string? hostValue = null;

        foreach (HeaderField field in fields)
        {
            if (field.Name.StartsWith(':'))
            {
                if (regularSeen)
                    return "pseudo-header after regular field"; // §4.3
                if (!IsValidFieldValue(field.Value))
                    return "invalid characters in pseudo-header value";
                switch (field.Name)
                {
                    case ":method": method++; methodValue = field.Value; break;
                    case ":scheme": scheme++; schemeValue = field.Value; break;
                    case ":path": path++; pathValue = field.Value; break;
                    case ":authority": authority++; authorityValue = field.Value; break;
                    case ":protocol": protocol++; protocolValue = field.Value; break; // RFC 8441 §4
                    default: return "undefined pseudo-header in request"; // §4.3 (inkl. :status)
                }
            }
            else
            {
                regularSeen = true;
                if (ValidateRegularField(field) is { } problem)
                    return problem;
                if (field.Name == "host")
                    hostValue = field.Value;
            }
        }

        if (method != 1)
            return "exactly one :method required"; // §4.3.1
        if (methodValue.Length == 0)
            return "empty :method";

        // :protocol ist NUR auf CONNECT-Requests definiert (RFC 8441 §4).
        if (protocol > 0 && methodValue != "CONNECT")
            return ":protocol on non-CONNECT request";
        if (protocol > 1)
            return "multiple :protocol values"; // RFC 8441 §4: single valued

        // Klassischer CONNECT (§4.4): :scheme/:path MÜSSEN fehlen, :authority MUSS vorhanden sein.
        // Extended CONNECT (RFC 8441 §4): mit :protocol MÜSSEN :scheme und :path vorhanden sein und
        // :authority folgt den NORMALEN Request-Regeln — dieser Fall fällt unten durch.
        if (methodValue == "CONNECT" && protocol == 0)
            return scheme > 0 || path > 0 ? "CONNECT with :scheme/:path"
                 : authority != 1 || authorityValue.Length == 0 ? "CONNECT without :authority"
                 : null;
        if (methodValue == "CONNECT" && protocolValue.Length == 0)
            return "empty :protocol";

        if (scheme != 1 || path != 1)
            return "exactly one :scheme and :path required"; // §4.3.1
        if (schemeValue.Length == 0)
            return "empty :scheme";
        if (pathValue.Length == 0)
            return "empty :path"; // §4.3.1: für http/https MUSS „/" bzw. „*" gesendet werden
        if (authority > 1)
            return "multiple :authority values";

        if (schemeValue is "http" or "https")
        {
            // §4.3.1: :authority ODER Host erforderlich, nicht leer; beide vorhanden ⇒ identisch;
            // die veraltete userinfo-Komponente („…@…") ist verboten.
            string? effective = authority == 1 ? authorityValue : hostValue;
            if (effective is not { Length: > 0 })
                return "missing :authority/Host for http(s) scheme";
            if (authority == 1 && hostValue is not null && authorityValue != hostValue)
                return ":authority and Host differ";
            if (effective.Contains('@'))
                return "userinfo in :authority";
        }

        return null;
    }

    /// <summary>
    /// Prüft eine Response-Header-Sektion (RFC 9114 §4.3.2): genau EIN gültiger <c>:status</c>
    /// (drei Ziffern, 100–599), keine anderen Pseudo-Header, Pseudo-Header vor regulären Feldern.
    /// </summary>
    public static string? ValidateResponseHeaders(IReadOnlyList<HeaderField> fields, out int status)
    {
        status = 0;
        bool regularSeen = false;
        int statusCount = 0;

        foreach (HeaderField field in fields)
        {
            if (field.Name.StartsWith(':'))
            {
                if (regularSeen)
                    return "pseudo-header after regular field"; // §4.3
                if (field.Name != ":status")
                    return "undefined pseudo-header in response"; // §4.3
                statusCount++;
                if (field.Value.Length != 3 || !field.Value.All(char.IsAsciiDigit) ||
                    !int.TryParse(field.Value, out status) || status < 100)
                    return "invalid :status value";
            }
            else
            {
                regularSeen = true;
                if (ValidateRegularField(field) is { } problem)
                    return problem;
            }
        }

        return statusCount != 1 ? "exactly one :status required" : null; // §4.3.2
    }

    /// <summary>
    /// Prüft eine Trailer-Sektion (RFC 9114 §4.3): Pseudo-Header sind dort verboten.
    /// </summary>
    public static string? ValidateTrailers(IReadOnlyList<HeaderField> fields)
    {
        foreach (HeaderField field in fields)
        {
            if (field.Name.StartsWith(':'))
                return "pseudo-header in trailer section"; // §4.3
            if (ValidateRegularField(field) is { } problem)
                return problem;
        }
        return null;
    }

    /// <summary>
    /// Content-Length-Konsistenz (RFC 9114 §4.1.2): ist ein <c>content-length</c> vorhanden, MUSS er
    /// der Summe der DATA-Längen entsprechen — außer die Nachricht ist per Definition rumpflos
    /// (<paramref name="contentNeverPresent"/>: HEAD-Antworten, 204/304) und es kam kein Content.
    /// </summary>
    public static string? ValidateContentLength(IReadOnlyList<HeaderField> fields, ulong actualLength, bool contentNeverPresent)
    {
        ulong? declared = null;
        foreach (HeaderField field in fields)
        {
            if (field.Name != "content-length")
                continue;
            if (field.Value.Length == 0 || !field.Value.All(char.IsAsciiDigit) || !ulong.TryParse(field.Value, out ulong value))
                return "invalid content-length value";
            if (declared is { } previous && previous != value)
                return "conflicting content-length values";
            declared = value;
        }

        if (declared is { } length && length != actualLength && !(contentNeverPresent && actualLength == 0))
            return "content-length does not match DATA length";
        return null;
    }

    /// <summary>
    /// Reguläres Feld (RFC 9114 §4.2): Name aus ASCII-„token"-Zeichen in Kleinschreibung, Wert ohne
    /// NUL/CR/LF; verbindungsspezifische Felder sind verboten, <c>te</c> nur mit „trailers".
    /// </summary>
    private static string? ValidateRegularField(HeaderField field)
    {
        if (!IsValidFieldName(field.Name))
            return field.Name.Any(char.IsAsciiLetterUpper)
                ? "uppercase field name"            // §4.2 MUST
                : "invalid characters in field name";
        if (!IsValidFieldValue(field.Value))
            return "invalid characters in field value";
        if (field.Name is "connection" or "proxy-connection" or "keep-alive" or "transfer-encoding" or "upgrade")
            return "connection-specific field";     // §4.2 (Transfer-Encoding auch §4.1)
        if (field.Name == "te" && !field.Value.Equals("trailers", StringComparison.OrdinalIgnoreCase))
            return "te value other than trailers";  // §4.2
        return null;
    }

    /// <summary>
    /// Feldname: nicht leer, nur „token"-Zeichen (RFC 9110 §5.1) in Kleinschreibung.
    /// </summary>
    private static bool IsValidFieldName(string name)
    {
        if (name.Length == 0)
            return false;
        foreach (char c in name)
        {
            bool ok = c is >= 'a' and <= 'z' or >= '0' and <= '9'
                or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.'
                or '^' or '_' or '`' or '|' or '~';
            if (!ok)
                return false;
        }
        return true;
    }

    /// <summary>
    /// Feldwert: keine NUL-/CR-/LF-Bytes (§4.1.2 „invalid characters", Schutz vor Request Smuggling).
    /// </summary>
    private static bool IsValidFieldValue(string value)
    {
        foreach (char c in value)
            if (c is '\0' or '\r' or '\n')
                return false;
        return true;
    }
}
