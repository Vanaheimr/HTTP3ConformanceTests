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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class BufferTests
{
    [Fact]
    public void WriteThenRead_RoundTripsAllPrimitives()
    {
        byte[] snapshot;
        using (var writer = new BufferWriter(16))
        {
            writer.WriteByte(0xAB);
            writer.WriteUInt16(0x1234);
            writer.WriteUInt32(0xDEADBEEF);
            writer.WriteUInt64(0x0102030405060708);
            writer.WriteVarInt(151288809941952652UL);
            writer.WriteBytes([0x11, 0x22, 0x33]);
            snapshot = writer.WrittenSpan.ToArray();
        }

        var reader = new BufferReader(snapshot);
        Assert.Equal(0xAB, reader.ReadByte());
        Assert.Equal(0x1234, reader.ReadUInt16());
        Assert.Equal(0xDEADBEEF, reader.ReadUInt32());
        Assert.Equal(0x0102030405060708UL, reader.ReadUInt64());
        Assert.Equal(151288809941952652UL, reader.ReadVarInt());
        Assert.Equal(new byte[] { 0x11, 0x22, 0x33 }, reader.ReadBytes(3).ToArray());
        Assert.True(reader.IsEmpty);
    }

    [Fact]
    public void Writer_GrowsBeyondInitialCapacity()
    {
        using var writer = new BufferWriter(4);
        for (int i = 0; i < 1000; i++)
            writer.WriteByte((byte)i);

        Assert.Equal(1000, writer.Length);
        Assert.Equal(unchecked((byte)999), writer.WrittenSpan[999]);
    }

    [Fact]
    public void WriteRepeated_FillsPadding()
    {
        using var writer = new BufferWriter();
        writer.WriteRepeated(0x00, 1200);

        Assert.Equal(1200, writer.Length);
        Assert.True(writer.WrittenSpan.ToArray().All(b => b == 0x00));
    }

    [Fact]
    public void GetSpan_AllowsBackpatching()
    {
        using var writer = new BufferWriter();
        Span<byte> lengthSlot = writer.GetSpan(2);
        writer.WriteBytes([0xAA, 0xBB, 0xCC]);

        // Länge nachträglich eintragen.
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(lengthSlot, 3);

        Assert.Equal([0x00, 0x03, 0xAA, 0xBB, 0xCC], writer.WrittenSpan.ToArray());
    }

    [Fact]
    public void Reader_TrackksPositionAndRemaining()
    {
        var reader = new BufferReader([0x01, 0x02, 0x03, 0x04]);

        Assert.Equal(4, reader.Remaining);
        reader.ReadUInt16();
        Assert.Equal(2, reader.Position);
        Assert.Equal(2, reader.Remaining);
        Assert.Equal(new byte[] { 0x03, 0x04 }, reader.RemainingSpan.ToArray());
    }

    [Fact]
    public void Reader_TryMethods_ReturnFalseWhenExhausted()
    {
        var reader = new BufferReader([0x01]);

        Assert.True(reader.TryReadByte(out _));
        Assert.False(reader.TryReadByte(out _));
        Assert.False(reader.TryReadUInt16(out _));
    }

    [Fact]
    public void Reader_ThrowsOnOverread()
    {
        // BufferReader ist ein ref struct und kann nicht in ein Lambda (Assert.Throws) kapseln.
        var reader = new BufferReader([0x01, 0x02]);
        bool threw = false;
        try
        {
            reader.ReadUInt32();
        }
        catch (EndOfBufferException)
        {
            threw = true;
        }
        Assert.True(threw);
    }
}
