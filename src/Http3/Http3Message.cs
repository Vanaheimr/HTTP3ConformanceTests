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
/// </summary>
public sealed record Http3Request(string Method, string Scheme, string Authority, string Path)
{
    public IReadOnlyList<HeaderField> AdditionalHeaders { get; init; } = [];

    public static Http3Request Get(string authority, string path = "/", string scheme = "https")
        => new("GET", scheme, authority, path);

    /// <summary>
    /// Erzeugt die Header-Feld-Liste in der von HTTP/3 geforderten Reihenfolge (Pseudo-Header zuerst).
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
        return fields;
    }
}

/// <summary>
/// Ein HTTP/3-Response: Status, Header und Rumpf.
/// </summary>
public sealed class Http3Response
{
    public int Status { get; init; }
    public IReadOnlyList<HeaderField> Headers { get; init; } = [];
    public byte[] Body { get; init; } = [];

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
