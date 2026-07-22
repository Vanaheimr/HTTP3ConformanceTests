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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class StreamIdTests
{
    [Theory]
    [InlineData(0UL, true, true)]   // client, bidi
    [InlineData(1UL, false, true)]  // server, bidi
    [InlineData(2UL, true, false)]  // client, uni
    [InlineData(3UL, false, false)] // server, uni
    public void Bits_EncodeInitiatorAndDirection(ulong value, bool clientInitiated, bool bidirectional)
    {
        var id = new StreamId(value);
        Assert.Equal(clientInitiated, id.IsClientInitiated);
        Assert.Equal(!clientInitiated, id.IsServerInitiated);
        Assert.Equal(bidirectional, id.IsBidirectional);
        Assert.Equal(!bidirectional, id.IsUnidirectional);
    }

    [Fact]
    public void Create_ProducesExpectedStreamIds()
    {
        Assert.Equal(0UL, StreamId.Create(true, true, 0).Value);   // erster Client-Bidi
        Assert.Equal(4UL, StreamId.Create(true, true, 1).Value);   // zweiter Client-Bidi
        Assert.Equal(2UL, StreamId.Create(true, false, 0).Value);  // erster Client-Uni (Control)
        Assert.Equal(3UL, StreamId.Create(false, false, 0).Value); // erster Server-Uni
    }
}

public class StreamReceiveBufferTests
{
    [Fact]
    public void ReassemblesOutOfOrder_AndTracksFin()
    {
        var buf = new StreamReceiveBuffer();
        Assert.Equal(StreamReceiveResult.Ok, buf.Receive(3, [0x33, 0x44], fin: true));  // Ende zuerst
        Assert.Empty(buf.ReadAvailable());                                              // Lücke -> nichts lesbar
        Assert.Equal(StreamReceiveResult.Ok, buf.Receive(0, [0x00, 0x11, 0x22], false)); // Lücke schließen

        Assert.Equal(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44 }, buf.ReadAvailable());
        Assert.True(buf.FinReceived);
        Assert.True(buf.IsComplete);
    }

    [Fact]
    public void OverlappingAndDuplicateData_HandledIdempotently()
    {
        var buf = new StreamReceiveBuffer();
        buf.Receive(0, [1, 2, 3], false);
        buf.Receive(2, [3, 4, 5], false); // überlappt bei Offset 2
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, buf.ReadAvailable());
    }

    [Fact]
    public void ExceedingFlowControlLimit_ReportsError()
    {
        var buf = new StreamReceiveBuffer { MaxData = 4 };
        Assert.Equal(StreamReceiveResult.FlowControlError, buf.Receive(2, [1, 2, 3], false)); // Ende bei 5 > 4
    }

    [Fact]
    public void ConflictingFinalSize_ReportsError()
    {
        var buf = new StreamReceiveBuffer();
        buf.Receive(0, [1, 2, 3], fin: true);          // Final Size = 3
        Assert.Equal(StreamReceiveResult.FinalSizeError, buf.Receive(3, [4, 5], fin: true)); // Final Size = 5
    }
}

public class StreamSendBufferTests
{
    [Fact]
    public void EmitsFramesWithinFlowControlWindow()
    {
        var send = new StreamSendBuffer(0) { MaxData = 3 };
        send.Write([1, 2, 3, 4, 5]);

        StreamFrame? f1 = send.NextFrame(maxPayload: 10);
        Assert.NotNull(f1);
        Assert.Equal(new byte[] { 1, 2, 3 }, f1!.Data.ToArray()); // durch MaxData=3 begrenzt
        Assert.Equal(0UL, f1.Offset);
        Assert.True(send.IsBlocked);                              // Rest wartet auf Kredit

        send.MaxData = 5; // MAX_STREAM_DATA erhöht das Fenster
        StreamFrame? f2 = send.NextFrame(10);
        Assert.Equal(new byte[] { 4, 5 }, f2!.Data.ToArray());
        Assert.Equal(3UL, f2.Offset);
    }

    [Fact]
    public void RespectsMaxPayload_AndSendsFin()
    {
        var send = new StreamSendBuffer(4) { MaxData = 1000 };
        send.Write([1, 2, 3, 4]);
        send.Finish();

        StreamFrame? f1 = send.NextFrame(maxPayload: 2);
        Assert.Equal(new byte[] { 1, 2 }, f1!.Data.ToArray());
        Assert.False(f1.Fin);

        StreamFrame? f2 = send.NextFrame(maxPayload: 100);
        Assert.Equal(new byte[] { 3, 4 }, f2!.Data.ToArray());
        Assert.True(f2.Fin); // letztes Frame trägt das FIN
        Assert.Null(send.NextFrame(100));
    }
}

public class FlowControlFrameTests
{
    private static T RoundTrip<T>(T frame) where T : Frame
    {
        byte[] bytes = FrameParser.Serialize([frame]);
        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(bytes, out var frames));
        return Assert.IsType<T>(Assert.Single(frames));
    }

    [Fact]
    public void MaxData_RoundTrips() => Assert.Equal(1_000_000UL, RoundTrip(new MaxDataFrame(1_000_000)).MaximumData);

    [Fact]
    public void MaxStreamData_RoundTrips()
    {
        var f = RoundTrip(new MaxStreamDataFrame(4, 65536));
        Assert.Equal(4UL, f.StreamId);
        Assert.Equal(65536UL, f.MaximumStreamData);
    }

    [Fact]
    public void MaxStreams_RoundTrips_BothDirections()
    {
        Assert.True(RoundTrip(new MaxStreamsFrame(true, 100)).Bidirectional);
        Assert.False(RoundTrip(new MaxStreamsFrame(false, 3)).Bidirectional);
    }

    [Fact]
    public void ResetStreamAndStopSending_RoundTrip()
    {
        var reset = RoundTrip(new ResetStreamFrame(4, 0x10c, 999));
        Assert.Equal(999UL, reset.FinalSize);
        var stop = RoundTrip(new StopSendingFrame(8, 0x10c));
        Assert.Equal(8UL, stop.StreamId);
    }
}
