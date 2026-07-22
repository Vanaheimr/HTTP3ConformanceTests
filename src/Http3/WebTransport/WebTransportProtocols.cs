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

using System.Text;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;

/// <summary>
/// Application Protocol Negotiation für WebTransport (draft-ietf-webtrans-http3-13 §3.3): der Client
/// bietet im CONNECT-Request per <c>WT-Available-Protocols</c> (Structured-Fields-List aus Strings,
/// RFC 9651) Protokolle in Präferenzreihenfolge an; der Server wählt in der 2xx-Antwort per
/// <c>WT-Protocol</c> (SF-Item-String) genau eines davon. Andere Werttypen als String machen das
/// GESAMTE Feld ungültig (MUST ignore); Parameter werden ignoriert (keine Semantik definiert).
/// </summary>
public static class WebTransportProtocols
{
    /// <summary>
    /// Header-Feldname der Client-Angebotsliste (draft §3.3/§9.7; HTTP/3 verlangt Kleinschreibung).
    /// </summary>
    public const string AvailableProtocolsHeader = "wt-available-protocols";

    /// <summary>
    /// Header-Feldname der Server-Wahl (draft §3.3/§9.7).
    /// </summary>
    public const string ProtocolHeader = "wt-protocol";

    // ---- Serialisieren --------------------------------------------------------------------

    /// <summary>
    /// Serialisiert die Angebotsliste als SF-List aus Strings (RFC 9651 §4.1), Präferenz zuerst.
    /// Wirft <see cref="ArgumentException"/> bei leerer Liste oder nicht als SF-String darstellbaren
    /// Zeichen (nur %x20-7E erlaubt).
    /// </summary>
    public static string SerializeProtocolList(IReadOnlyList<string> protocols)
    {
        if (protocols.Count == 0)
            throw new ArgumentException("Die Protokollliste darf nicht leer sein.", nameof(protocols));
        var sb = new StringBuilder();
        for (int i = 0; i < protocols.Count; i++)
        {
            if (i > 0)
                sb.Append(", ");
            AppendSfString(sb, protocols[i]);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Serialisiert die Server-Wahl als SF-Item-String (RFC 9651 §4.1).
    /// </summary>
    public static string SerializeProtocol(string protocol)
    {
        var sb = new StringBuilder();
        AppendSfString(sb, protocol);
        return sb.ToString();
    }

    /// <summary>
    /// Schreibt einen SF-String (RFC 9651 §4.1.6): DQUOTE-begrenzt, <c>"</c> und <c>\</c> per
    /// Backslash escaped; zulässig sind nur druckbare ASCII-Zeichen (%x20-7E).
    /// </summary>
    private static void AppendSfString(StringBuilder sb, string value)
    {
        sb.Append('"');
        foreach (char c in value)
        {
            if (c is < '\x20' or > '\x7e')
                throw new ArgumentException($"Zeichen U+{(int)c:X4} ist in einem SF-String nicht darstellbar.", nameof(value));
            if (c is '"' or '\\')
                sb.Append('\\');
            sb.Append(c);
        }
        sb.Append('"');
    }

    // ---- Parsen ---------------------------------------------------------------------------

    /// <summary>
    /// Parst <c>WT-Available-Protocols</c> als SF-List aus Strings. Ein Mitglied, das kein String ist
    /// (Token, Zahl, Inner List, …), oder ein Syntaxfehler macht das GESAMTE Feld ungültig (draft §3.3
    /// MUST) ⇒ <c>false</c>. Parameter werden überlesen und ignoriert.
    /// </summary>
    public static bool TryParseProtocolList(string? value, out List<string> protocols)
    {
        protocols = [];
        if (string.IsNullOrWhiteSpace(value))
            return false;
        ReadOnlySpan<char> s = value.AsSpan();
        int i = 0;
        SkipOws(s, ref i);
        while (true)
        {
            if (!TryParseSfString(s, ref i, out string member) || !SkipParameters(s, ref i))
            {
                protocols.Clear();
                return false; // Nicht-String-Mitglied oder Syntaxfehler ⇒ ganzes Feld ignorieren
            }
            protocols.Add(member);
            SkipOws(s, ref i);
            if (i >= s.Length)
                return true;
            if (s[i] != ',')
            {
                protocols.Clear();
                return false;
            }
            i++; // ","
            SkipOws(s, ref i);
            if (i >= s.Length)
            {
                protocols.Clear();
                return false; // RFC 9651 §4.2.1: Komma ohne Folge-Mitglied ist ein Fehler
            }
        }
    }

    /// <summary>
    /// Parst <c>WT-Protocol</c> als SF-Item-String. Anderer Werttyp, Syntaxfehler oder Rest-Zeichen
    /// ⇒ Feld ignorieren (<c>false</c>). Parameter werden überlesen und ignoriert.
    /// </summary>
    public static bool TryParseProtocol(string? value, out string protocol)
    {
        protocol = "";
        if (string.IsNullOrWhiteSpace(value))
            return false;
        ReadOnlySpan<char> s = value.AsSpan();
        int i = 0;
        SkipOws(s, ref i);
        if (!TryParseSfString(s, ref i, out protocol) || !SkipParameters(s, ref i))
            return false;
        SkipOws(s, ref i);
        return i >= s.Length; // Rest-Zeichen ⇒ kein gültiges Item
    }

    /// <summary>
    /// Liest einen SF-String (RFC 9651 §4.2.5): DQUOTE, Zeichen %x20-7E mit <c>\"</c>/<c>\\</c>-Escapes,
    /// DQUOTE. <c>false</c>, wenn an der Position kein gültiger String steht.
    /// </summary>
    private static bool TryParseSfString(ReadOnlySpan<char> s, ref int i, out string result)
    {
        result = "";
        if (i >= s.Length || s[i] != '"')
            return false;
        i++;
        var sb = new StringBuilder();
        while (i < s.Length)
        {
            char c = s[i++];
            if (c == '"')
            {
                result = sb.ToString();
                return true;
            }
            if (c == '\\')
            {
                if (i >= s.Length || (s[i] != '"' && s[i] != '\\'))
                    return false; // nur \" und \\ sind zulässige Escapes
                sb.Append(s[i++]);
                continue;
            }
            if (c is < '\x20' or > '\x7e')
                return false;
            sb.Append(c);
        }
        return false; // unbeendeter String
    }

    /// <summary>
    /// Überliest die Parameter eines Mitglieds (RFC 9651 §4.2.3.2: <c>*( ";" *SP key [ "=" bare-item ] )</c>).
    /// Die Werte werden nur syntaktisch übersprungen — Parameter haben hier keine Semantik (draft §3.3).
    /// </summary>
    private static bool SkipParameters(ReadOnlySpan<char> s, ref int i)
    {
        while (i < s.Length && s[i] == ';')
        {
            i++;
            while (i < s.Length && s[i] == ' ')
                i++;
            // key = (lcalpha / "*") *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
            if (i >= s.Length || (s[i] is not (>= 'a' and <= 'z') && s[i] != '*'))
                return false;
            while (i < s.Length && (s[i] is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '-' or '.' or '*'))
                i++;
            if (i < s.Length && s[i] == '=')
            {
                i++;
                if (!SkipBareItem(s, ref i))
                    return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Überliest ein Bare Item beliebigen Typs (RFC 9651 §4.2.3.1: String, Token, Zahl, Boolean,
    /// Byte-Sequenz, Datum, Display String) — nur syntaktisch, der Wert wird verworfen.
    /// </summary>
    private static bool SkipBareItem(ReadOnlySpan<char> s, ref int i)
    {
        if (i >= s.Length)
            return false;
        char c = s[i];
        if (c == '"')
            return TryParseSfString(s, ref i, out _);
        if (c == '?') // Boolean: ?0 / ?1
        {
            if (i + 1 >= s.Length || (s[i + 1] != '0' && s[i + 1] != '1'))
                return false;
            i += 2;
            return true;
        }
        if (c == ':') // Byte-Sequenz: :base64:
        {
            int close = s[(i + 1)..].IndexOf(':');
            if (close < 0)
                return false;
            i += close + 2;
            return true;
        }
        if (c == '%') // Display String: %"…" (Escapes via %xx, DQUOTE darin immer %22)
        {
            if (i + 1 >= s.Length || s[i + 1] != '"')
                return false;
            int close = s[(i + 2)..].IndexOf('"');
            if (close < 0)
                return false;
            i += close + 3;
            return true;
        }
        if (c == '@') // Datum: @ gefolgt von einer Ganzzahl
            i++;
        if (i < s.Length && (s[i] == '-' || char.IsAsciiDigit(s[i]))) // Integer/Decimal
        {
            if (s[i] == '-')
                i++;
            if (i >= s.Length || !char.IsAsciiDigit(s[i]))
                return false;
            while (i < s.Length && (char.IsAsciiDigit(s[i]) || s[i] == '.'))
                i++;
            return true;
        }
        if (c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or '*') // Token
        {
            while (i < s.Length && (char.IsAsciiLetterOrDigit(s[i]) ||
                   s[i] is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~' or ':' or '/'))
                i++;
            return true;
        }
        return false;
    }

    private static void SkipOws(ReadOnlySpan<char> s, ref int i)
    {
        while (i < s.Length && (s[i] == ' ' || s[i] == '\t'))
            i++;
    }
}
