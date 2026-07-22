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

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class QpackTests
{
    // --- Huffman (RFC 7541 Anhang B/C) ---------------------------------------------------------

    [Theory]
    [InlineData("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff")]
    [InlineData("/index.html", "60d5485f2bce9a68")] // wird vom Encoder nur genutzt, wenn kürzer
    [InlineData("no-cache", "a8eb10649cbf")]
    public void Huffman_Encode_MatchesKnownVectors(string text, string expectedHex)
    {
        byte[] encoded = HuffmanEncode(text);
        Assert.Equal(expectedHex, Hex.ToHex(encoded));

        Assert.True(Huffman.TryDecode(encoded, out byte[] decoded));
        Assert.Equal(text, System.Text.Encoding.ASCII.GetString(decoded));
    }

    [Fact]
    public void Huffman_RejectsInvalidPadding()
    {
        // Ein Byte 0x00 ist kein gültiger Huffman-String (kein Symbol, ungültiges Padding).
        Assert.False(Huffman.TryDecode([0x00], out _));
    }

    private static byte[] HuffmanEncode(string text)
    {
        var w = new Quic.Core.Buffers.BufferWriter(32);
        try
        {
            Huffman.Encode(ref w, System.Text.Encoding.ASCII.GetBytes(text));
            return w.WrittenSpan.ToArray();
        }
        finally { w.Dispose(); }
    }

    // --- Encoder/Decoder (RFC 9204) ------------------------------------------------------------

    [Fact]
    public void Encode_LiteralWithNameReference_UsesHuffmanWhenShorter()
    {
        // RFC 9204 B.1 kodiert :path=/index.html als Name-Referenz (Static Index 1) + Wert.
        // Das RFC-Beispiel nutzt die Rohform (0b + 11 Byte); unser Encoder bevorzugt Huffman
        // (8 Byte, 0x88) — beides spec-konform. Interop mit der Rohform prüft der Decode-Test unten.
        byte[] encoded = QpackEncoder.Encode([new HeaderField(":path", "/index.html")]);
        Assert.Equal("0000518860d5485f2bce9a68", Hex.ToHex(encoded));
    }

    [Fact]
    public void Encode_ExactPair_ProducesIndexedFieldLine()
    {
        // :method=GET ist Static-Table-Index 17 -> Indexed: 0b1100_0000 | 17 = 0xd1.
        byte[] encoded = QpackEncoder.Encode([new HeaderField(":method", "GET")]);
        Assert.Equal("0000d1", Hex.ToHex(encoded));
    }

    [Fact]
    public void Decode_Rfc9204ExampleB1_YieldsPath()
    {
        QpackResult result = QpackDecoder.Decode(Hex.Parse("0000510b2f696e6465782e68746d6c"), out var headers);
        Assert.Equal(QpackResult.Ok, result);
        Assert.Equal(new HeaderField(":path", "/index.html"), Assert.Single(headers));
    }

    [Fact]
    public void RoundTrip_TypicalRequestHeaders()
    {
        List<HeaderField> headers =
        [
            new(":method", "GET"),
            new(":scheme", "https"),
            new(":authority", "cloudflare-quic.com"),
            new(":path", "/"),
            new("user-agent", "http3-from-scratch/0.1"),
            new("accept", "*/*"),
        ];

        byte[] encoded = QpackEncoder.Encode(headers);
        Assert.Equal(QpackResult.Ok, QpackDecoder.Decode(encoded, out var decoded));
        Assert.Equal(headers, decoded);
    }

    [Fact]
    public void RoundTrip_LiteralNameAndValue_WithHuffman()
    {
        // Ein Header, dessen Name nicht in der Static Table steht -> Literal Name + Literal Value.
        var headers = new List<HeaderField> { new("x-custom-header", "some-longer-value-that-huffman-compresses") };

        byte[] encoded = QpackEncoder.Encode(headers);
        Assert.Equal(QpackResult.Ok, QpackDecoder.Decode(encoded, out var decoded));
        Assert.Equal(headers, decoded);
    }

    [Fact]
    public void Decode_DynamicTableReference_IsRejected()
    {
        // Required Insert Count != 0 signalisiert eine dynamische Tabelle, die wir nicht führen.
        QpackResult result = QpackDecoder.Decode(Hex.Parse("0200d1"), out _);
        Assert.Equal(QpackResult.DynamicTableReference, result);
    }

    [Fact]
    public void StaticTable_HasExpectedAnchors()
    {
        // Stichproben gegen RFC 9204 Anhang A.
        Assert.Equal((":authority", ""), GetStatic(0));
        Assert.Equal((":path", "/"), GetStatic(1));
        Assert.Equal((":method", "GET"), GetStatic(17));
        Assert.Equal(("x-frame-options", "sameorigin"), GetStatic(98));
    }

    private static (string, string) GetStatic(int index)
    {
        // Zugriff über einen Round-Trip einer Indexed Field Line.
        var w = new Quic.Core.Buffers.BufferWriter(8);
        try
        {
            QpackDecoder.Decode(Encode(index), out var headers);
            return (headers[0].Name, headers[0].Value);
        }
        finally { w.Dispose(); }

        static byte[] Encode(int idx)
        {
            // 0000 (Prefix) + Indexed Field Line static (1 T=1 index 6+).
            var w = new Quic.Core.Buffers.BufferWriter(8);
            try
            {
                w.WriteByte(0x00); w.WriteByte(0x00);
                if (idx < 63) { w.WriteByte((byte)(0xC0 | idx)); }
                else { w.WriteByte(0xFF); w.WriteByte((byte)(idx - 63)); }
                return w.WrittenSpan.ToArray();
            }
            finally { w.Dispose(); }
        }
    }
}
