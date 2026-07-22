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
/// Ein HTTP/3-Request. Die Pseudo-Header (:method/:scheme/:authority/:path) sind Pflicht (RFC 9114 §4.3.1).
/// Der optionale Rumpf wird als Serie von DATA-Frames nach dem HEADERS-Frame gesendet (RFC 9114 §4.1).
/// </summary>
public sealed record Http3Request(string Method, string Scheme, string Authority, string Path)
{
    public IReadOnlyList<HeaderField> AdditionalHeaders { get; init; } = [];

    /// <summary>
    /// Der Request-Rumpf (Content, RFC 9114 §4.1 Punkt 2). Leer = kein DATA-Frame.
    /// </summary>
    public byte[] Body { get; init; } = [];

    /// <summary>
    /// Optionale Trailer-Sektion (RFC 9114 §4.1 Punkt 3): wird als abschließendes HEADERS-Frame nach
    /// dem Content gesendet bzw. beim Empfang hier abgelegt. Trailer dürfen KEINE Pseudo-Header tragen.
    /// </summary>
    public IReadOnlyList<HeaderField> Trailers { get; init; } = [];

    /// <summary>
    /// Optionale Priorität (RFC 9218): wird als <c>priority</c>-Header gesendet und clientseitig auch
    /// auf den Sende-Scheduler des Request-Streams angewendet. <c>null</c> = Standard (u=3, nicht
    /// inkrementell), es wird kein Header gesendet.
    /// </summary>
    public Http3Priority? Priority { get; init; }

    /// <summary>
    /// Der <c>:protocol</c>-Pseudo-Header eines Extended CONNECT (RFC 8441 §4 / RFC 9220),
    /// z. B. „websocket"; <c>null</c> bei normalen Requests.
    /// </summary>
    public string? Protocol { get; init; }

    public static Http3Request Get(string authority, string path = "/", string scheme = "https")
        => new("GET", scheme, authority, path);

    /// <summary>
    /// Erzeugt einen POST-Request mit Rumpf und Content-Type.
    /// </summary>
    public static Http3Request Post(string authority, string path, byte[] body,
                                    string contentType = "application/octet-stream", string scheme = "https")
        => new("POST", scheme, authority, path)
        {
            Body = body,
            AdditionalHeaders = [new HeaderField("content-type", contentType)],
        };

    /// <summary>
    /// Erzeugt die Header-Feld-Liste in der von HTTP/3 geforderten Reihenfolge (Pseudo-Header zuerst).
    /// Bei nicht-leerem Rumpf wird <c>content-length</c> ergänzt (RFC 9110 §8.6 SHOULD; RFC 9114 §4.1.2:
    /// der Wert MUSS der Summe der DATA-Frame-Längen entsprechen — wir senden genau <see cref="Body"/>).
    /// </summary>
    public List<HeaderField> ToHeaderFields()
    {
        var fields = new List<HeaderField>
        {
            new(":method", Method),
            new(":scheme", Scheme),
            new(":authority", Authority),
            new(":path", Path),
        };
        fields.AddRange(AdditionalHeaders);
        if (Body.Length > 0 && !AdditionalHeaders.Any(h => h.Name == "content-length"))
            fields.Add(new HeaderField("content-length", Body.Length.ToString()));
        if (Priority is { } priority && !AdditionalHeaders.Any(h => h.Name == "priority"))
        {
            string value = priority.ToHeaderValue();
            if (value.Length > 0)
                fields.Add(new HeaderField("priority", value)); // RFC 9218 §5
        }
        return fields;
    }
}

/// <summary>
/// Eine Interim-Response (1xx, RFC 9114 §4.1 / RFC 9110 §15.2), die der finalen Antwort vorausgeht —
/// z. B. 103 Early Hints. Interim-Responses tragen weder Content noch Trailer.
/// </summary>
public sealed record Http3InterimResponse(int Status, IReadOnlyList<HeaderField> Headers);

/// <summary>
/// Ein HTTP/3-Response: Status, Header und Rumpf, optional Interim-Responses (1xx) davor und eine
/// Trailer-Sektion danach (RFC 9114 §4.1).
/// </summary>
public sealed class Http3Response
{
    public int Status { get; init; }
    public IReadOnlyList<HeaderField> Headers { get; init; } = [];
    public byte[] Body { get; init; } = [];

    /// <summary>
    /// Interim-Responses (1xx), die der finalen Antwort vorausgingen bzw. vorausgehen sollen —
    /// beim Senden schreibt der Server je Eintrag eine eigene HEADERS-Sektion VOR die finale.
    /// </summary>
    public IReadOnlyList<Http3InterimResponse> InterimResponses { get; init; } = [];

    /// <summary>
    /// Optionale Trailer-Sektion (RFC 9114 §4.1 Punkt 3): abschließendes HEADERS-Frame nach dem Content.
    /// </summary>
    public IReadOnlyList<HeaderField> Trailers { get; init; } = [];

    /// <summary>
    /// Der Rumpf als UTF-8-Text.
    /// </summary>
    public string BodyText => System.Text.Encoding.UTF8.GetString(Body);

    public string? GetHeader(string name)
    {
        foreach (HeaderField h in Headers)
            if (h.Name == name)
                return h.Value;
        return null;
    }
}
