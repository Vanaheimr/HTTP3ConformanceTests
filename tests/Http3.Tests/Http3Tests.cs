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

using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class Http3FrameTests
{
    [Fact]
    public void BuildAndParse_DataFrame_RoundTrips()
    {
        byte[] frame = Http3Frames.Build(Http3FrameType.Data, [0x48, 0x69]); // "Hi"

        Assert.True(Http3Frames.TryReadAll(frame, out var frames, out int consumed));
        Assert.Equal(frame.Length, consumed);
        var parsed = Assert.Single(frames);
        Assert.Equal(Http3FrameType.Data, parsed.Type);
        Assert.Equal(new byte[] { 0x48, 0x69 }, parsed.Payload.ToArray());
    }

    [Fact]
    public void TryReadAll_ParsesMultipleFrames_AndReportsPartialTail()
    {
        // HEADERS(2 Byte) + DATA(3 Byte) + angefangenes drittes Frame (Länge 10, aber nur 1 Byte da).
        byte[] buffer =
        [
            0x01, 0x02, 0xaa, 0xbb,              // HEADERS len=2
            0x00, 0x03, 0x01, 0x02, 0x03,        // DATA len=3
            0x00, 0x0a, 0xff,                    // DATA len=10 (unvollständig)
        ];

        Assert.True(Http3Frames.TryReadAll(buffer, out var frames, out int consumed));
        Assert.Equal(2, frames.Count);
        Assert.Equal(Http3FrameType.Headers, frames[0].Type);
        Assert.Equal(Http3FrameType.Data, frames[1].Type);
        Assert.Equal(9, consumed); // das unvollständige dritte Frame bleibt liegen
    }
}

public class Http3RequestTests
{
    [Fact]
    public void ToHeaderFields_ProducesPseudoHeadersInOrder()
    {
        var request = Http3Request.Get("example.com", "/index.html");
        List<HeaderField> fields = request.ToHeaderFields();

        Assert.Equal(new HeaderField(":method", "GET"), fields[0]);
        Assert.Equal(new HeaderField(":scheme", "https"), fields[1]);
        Assert.Equal(new HeaderField(":authority", "example.com"), fields[2]);
        Assert.Equal(new HeaderField(":path", "/index.html"), fields[3]);
    }

    [Fact]
    public void RequestHeaders_SurviveQpackAndHttp3FrameRoundTrip()
    {
        // So baut der Client die Anfrage: QPACK-Header-Block in einem HEADERS-Frame.
        var request = Http3Request.Get("cloudflare-quic.com", "/");
        byte[] headerBlock = QpackEncoder.Encode(request.ToHeaderFields());
        byte[] frame = Http3Frames.Build(Http3FrameType.Headers, headerBlock);

        // Empfängerseite: Frame parsen -> QPACK dekodieren.
        Assert.True(Http3Frames.TryReadAll(frame, out var frames, out _));
        Assert.Equal(Http3FrameType.Headers, frames[0].Type);
        Assert.Equal(QpackResult.Ok, QpackDecoder.Decode(frames[0].Payload.Span, out var headers));
        Assert.Equal(request.ToHeaderFields(), headers);
    }

    [Fact]
    public void ResponseHeaders_DecodeStatusAndContentType()
    {
        // Ein typischer Server-HEADERS-Block (Static-Table + Literale), so wie ihn Cloudflare sendet.
        byte[] headerBlock = QpackEncoder.Encode(
        [
            new HeaderField(":status", "200"),
            new HeaderField("content-type", "text/html"),
            new HeaderField("server", "cloudflare"),
        ]);
        byte[] frame = Http3Frames.Build(Http3FrameType.Headers, headerBlock);

        Assert.True(Http3Frames.TryReadAll(frame, out var frames, out _));
        Assert.Equal(QpackResult.Ok, QpackDecoder.Decode(frames[0].Payload.Span, out var headers));

        Assert.Contains(new HeaderField(":status", "200"), headers);
        Assert.Contains(new HeaderField("content-type", "text/html"), headers);
    }
}
