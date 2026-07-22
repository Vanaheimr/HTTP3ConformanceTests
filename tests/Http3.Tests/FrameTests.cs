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

using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class FrameTests
{
    private static byte[] Serialize(params Frame[] frames) => FrameParser.Serialize(frames);

    // --- RFC-9001-A.3-Payload: der echte Server-Initial-Inhalt (ACK + CRYPTO) -----------------

    private const string ServerPayloadHex = """
        02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
        88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
        0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00
        020304
        """;

    [Fact]
    public void Parse_ServerInitialPayload_YieldsAckAndCrypto()
    {
        byte[] payload = Hex.Parse(ServerPayloadHex);

        FrameParseResult result = FrameParser.TryParseAll(payload, out List<Frame> frames);

        Assert.Equal(FrameParseResult.Ok, result);
        Assert.Equal(2, frames.Count);

        var ack = Assert.IsType<AckFrame>(frames[0]);
        Assert.Equal(0UL, ack.LargestAcknowledged);
        Assert.Equal(0UL, ack.AckDelay);
        Assert.Single(ack.Ranges);
        Assert.Equal(new PacketNumberRange(0, 0), ack.Ranges[0]);
        Assert.Null(ack.Ecn);

        var crypto = Assert.IsType<CryptoFrame>(frames[1]);
        Assert.Equal(0UL, crypto.Offset);
        Assert.Equal(90, crypto.Data.Length); // 0x5a
    }

    [Fact]
    public void ParseThenSerialize_ServerInitialPayload_RoundTripsExactly()
    {
        byte[] payload = Hex.Parse(ServerPayloadHex);

        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(payload, out List<Frame> frames));
        byte[] reencoded = Serialize([.. frames]);

        Assert.Equal(Hex.ToHex(payload), Hex.ToHex(reencoded));
    }

    // --- Client-Initial-Payload: CRYPTO + PADDING ---------------------------------------------

    [Fact]
    public void Parse_ClientInitialPayload_CoalescesPadding()
    {
        // CRYPTO(245 Byte) + PADDING bis 1162.
        byte[] cryptoFrame = Hex.Parse("""
            060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
            04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
            616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
            04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
            baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
            0d0010000e0403050306030203080408 050806002d00020101001c0002400100
            3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
            75300901100f088394c8f03e51570806 048000ffff
            """);
        byte[] payload = new byte[1162];
        cryptoFrame.CopyTo(payload, 0);

        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(payload, out List<Frame> frames));
        Assert.Equal(2, frames.Count);
        var crypto = Assert.IsType<CryptoFrame>(frames[0]);
        Assert.Equal(241, crypto.Data.Length);
        var padding = Assert.IsType<PaddingFrame>(frames[1]);
        Assert.Equal(1162 - cryptoFrame.Length, padding.Length);

        // Round-Trip: exakt dieselben Bytes.
        Assert.Equal(Hex.ToHex(payload), Hex.ToHex(Serialize([.. frames])));
    }

    // --- ACK mit mehreren Bereichen -----------------------------------------------------------

    [Fact]
    public void AckFrame_MultipleRanges_RoundTrips()
    {
        var ack = new AckFrame(
            [new PacketNumberRange(100, 100), new PacketNumberRange(90, 80), new PacketNumberRange(70, 70)],
            AckDelay: 1234);

        byte[] bytes = Serialize(ack);

        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(bytes, out List<Frame> frames));
        var parsed = Assert.IsType<AckFrame>(Assert.Single(frames));
        Assert.Equal(ack.Ranges, parsed.Ranges);
        Assert.Equal(1234UL, parsed.AckDelay);
    }

    [Fact]
    public void AckFrame_WithEcn_RoundTrips()
    {
        var ack = new AckFrame([new PacketNumberRange(5, 0)], AckDelay: 0, Ecn: new EcnCounts(10, 0, 2));

        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(Serialize(ack), out List<Frame> frames));
        var parsed = Assert.IsType<AckFrame>(Assert.Single(frames));
        Assert.Equal(new EcnCounts(10, 0, 2), parsed.Ecn);
    }

    // --- CONNECTION_CLOSE / STREAM / PING ------------------------------------------------------

    [Fact]
    public void ConnectionClose_Transport_RoundTrips()
    {
        var close = ConnectionCloseFrame.Transport(TransportError.ProtocolViolation, "böse Frames", triggeringFrameType: 0x06);

        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(Serialize(close), out List<Frame> frames));
        var parsed = Assert.IsType<ConnectionCloseFrame>(Assert.Single(frames));
        Assert.Equal((ulong)TransportError.ProtocolViolation, parsed.ErrorCode);
        Assert.False(parsed.IsApplicationError);
        Assert.Equal(0x06UL, parsed.TriggeringFrameType);
        Assert.Equal("böse Frames", parsed.ReasonPhrase);
    }

    [Theory]
    [InlineData(0UL, false)]
    [InlineData(1000UL, true)]
    public void StreamFrame_RoundTrips(ulong offset, bool fin)
    {
        byte[] data = [1, 2, 3, 4, 5];
        var stream = new StreamFrame(StreamId: 4, offset, data, fin);

        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(Serialize(stream), out List<Frame> frames));
        var parsed = Assert.IsType<StreamFrame>(Assert.Single(frames));
        Assert.Equal(4UL, parsed.StreamId);
        Assert.Equal(offset, parsed.Offset);
        Assert.Equal(fin, parsed.Fin);
        Assert.Equal(data, parsed.Data.ToArray());
    }

    [Fact]
    public void PingAndPadding_Mix_Parses()
    {
        byte[] bytes = Serialize(PingFrame.Instance, new PaddingFrame(3), PingFrame.Instance);

        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(bytes, out List<Frame> frames));
        Assert.Collection(frames,
            f => Assert.IsType<PingFrame>(f),
            f => Assert.Equal(3, Assert.IsType<PaddingFrame>(f).Length),
            f => Assert.IsType<PingFrame>(f));
    }

    // --- Fehlerpfade --------------------------------------------------------------------------

    [Fact]
    public void Parse_UnknownFrameType_ReportsError()
    {
        // 0x40 als 1-Byte-VarInt ist Typ 0 (Padding); nutze 0x1f (reserviert/unbekannt hier).
        byte[] bytes = [0x1f];
        Assert.Equal(FrameParseResult.UnknownFrameType, FrameParser.TryParseAll(bytes, out _));
    }

    [Fact]
    public void Parse_TruncatedCryptoFrame_ReportsEncodingError()
    {
        // CRYPTO, Offset 0, Länge 10, aber nur 2 Datenbytes vorhanden.
        byte[] bytes = [0x06, 0x00, 0x0a, 0xaa, 0xbb];
        Assert.Equal(FrameParseResult.EncodingError, FrameParser.TryParseAll(bytes, out _));
    }
}
