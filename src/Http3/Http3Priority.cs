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
/// Priorität nach RFC 9218 (Extensible Prioritization Scheme for HTTP): <see cref="Urgency"/>
/// <c>u</c> = 0 (höchste) … 7 (Hintergrund), Standard 3; <see cref="Incremental"/> <c>i</c> = die
/// Antwort ist häppchenweise verwertbar (gleich dringliche inkrementelle Antworten teilen sich die
/// Bandbreite), Standard false. Kodiert als Structured-Fields-Dictionary im <c>priority</c>-Header
/// bzw. im PRIORITY_UPDATE-Frame.
/// </summary>
public readonly record struct Http3Priority(int Urgency, bool Incremental)
{
    /// <summary>
    /// Die Standard-Priorität (u=3, nicht inkrementell) — gilt, wenn keine Parameter signalisiert sind.
    /// </summary>
    public static readonly Http3Priority Default = new(3, false);

    /// <summary>
    /// Serialisiert als Structured-Fields-Dictionary (RFC 9218 §5), z. B. „u=0", „u=5, i" oder „" für
    /// die Standardwerte (Auslassen eines Parameters = Standardwert).
    /// </summary>
    public string ToHeaderValue()
    {
        var parts = new List<string>(2);
        if (Urgency != 3)
            parts.Add($"u={Urgency}");
        if (Incremental)
            parts.Add("i");
        return string.Join(", ", parts);
    }

    /// <summary>
    /// Parst ein Structured-Fields-Dictionary (RFC 9218 §4, fehlertolerant): unbekannte Parameter,
    /// Werte außerhalb des Bereichs oder unerwartete Typen MÜSSEN ignoriert werden; bei mehrfach
    /// auftretenden Schlüsseln gewinnt der letzte (Structured Fields §3.2). Nicht Verwertbares fällt
    /// auf die Standardwerte zurück.
    /// </summary>
    public static Http3Priority Parse(string? value)
    {
        int urgency = 3;
        bool incremental = false;
        if (string.IsNullOrWhiteSpace(value))
            return new Http3Priority(urgency, incremental);

        foreach (string memberRaw in value.Split(','))
        {
            string member = memberRaw.Trim();
            int semicolon = member.IndexOf(';'); // Member-Parameter (";…") interessieren uns nicht
            if (semicolon >= 0)
                member = member[..semicolon].TrimEnd();

            string key = member;
            string? itemValue = null;
            int equals = member.IndexOf('=');
            if (equals >= 0)
            {
                key = member[..equals].Trim();
                itemValue = member[(equals + 1)..].Trim();
            }

            switch (key)
            {
                case "u": // Integer 0..7 (RFC 9218 §4.1); außerhalb/typfremd ⇒ ignorieren
                    if (itemValue is not null && int.TryParse(itemValue, out int u) && u is >= 0 and <= 7)
                        urgency = u;
                    break;
                case "i": // Boolean (RFC 9218 §4.2): bloßer Schlüssel oder „?1" = true, „?0" = false
                    if (itemValue is null || itemValue == "?1")
                        incremental = true;
                    else if (itemValue == "?0")
                        incremental = false;
                    break;
                // Unbekannte Parameter ⇒ ignorieren (RFC 9218 §4 MUST).
            }
        }
        return new Http3Priority(urgency, incremental);
    }
}
