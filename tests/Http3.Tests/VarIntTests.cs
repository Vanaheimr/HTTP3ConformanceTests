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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Core;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class VarIntTests
{
    // Testvektoren aus RFC 9000, Appendix A.1 ("Sample Variable-Length Integer Decoding").
    // Format: Hex-Wire-Bytes -> erwarteter Dezimalwert.
    [Theory]
    [InlineData("c2197c5eff14e88c", 151288809941952652UL)] // 8-Byte
    [InlineData("9d7f3e7d", 494878333UL)]                    // 4-Byte
    [InlineData("7bbd", 15293UL)]                             // 2-Byte
    [InlineData("25", 37UL)]                                  // 1-Byte
    [InlineData("4025", 37UL)]                                // 2-Byte, aber Wert 37 (nicht-minimale Kodierung)
    public void Decode_RfcSampleVectors(string hex, ulong expected)
    {
        byte[] bytes = Convert.FromHexString(hex);

        bool ok = VarInt.TryRead(bytes, out ulong value, out int read);

        Assert.True(ok);
        Assert.Equal(expected, value);
        Assert.Equal(bytes.Length, read);
    }

    [Theory]
    [InlineData(0UL, 1)]
    [InlineData(63UL, 1)]
    [InlineData(64UL, 2)]
    [InlineData(16383UL, 2)]
    [InlineData(16384UL, 4)]
    [InlineData(1073741823UL, 4)]
    [InlineData(1073741824UL, 8)]
    [InlineData(VarInt.MaxValue, 8)]
    public void GetLength_PicksSmallestEncoding(ulong value, int expectedLength)
    {
        Assert.Equal(expectedLength, VarInt.GetLength(value));
    }

    [Theory]
    [InlineData(0UL)]
    [InlineData(63UL)]
    [InlineData(64UL)]
    [InlineData(16383UL)]
    [InlineData(16384UL)]
    [InlineData(1073741823UL)]
    [InlineData(1073741824UL)]
    [InlineData(151288809941952652UL)]
    [InlineData(VarInt.MaxValue)]
    public void RoundTrip_WriteThenRead(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];

        int written = VarInt.Write(buffer, value);
        bool ok = VarInt.TryRead(buffer[..written], out ulong readBack, out int read);

        Assert.True(ok);
        Assert.Equal(value, readBack);
        Assert.Equal(written, read);
        Assert.Equal(VarInt.GetLength(value), written);
    }

    [Fact]
    public void Write_ProducesMinimalEncoding_ForValue37()
    {
        Span<byte> buffer = stackalloc byte[8];
        int written = VarInt.Write(buffer, 37);

        Assert.Equal(1, written);
        Assert.Equal(0x25, buffer[0]);
    }

    [Fact]
    public void TryRead_ReturnsFalse_WhenTruncated()
    {
        // Erstes Byte kündigt 4 Bytes an, es liegt aber nur eines vor.
        byte[] truncated = [0x9d];

        Assert.False(VarInt.TryRead(truncated, out _, out _));
    }

    [Fact]
    public void TryRead_ReturnsFalse_OnEmptyInput()
    {
        Assert.False(VarInt.TryRead(ReadOnlySpan<byte>.Empty, out _, out _));
    }

    [Fact]
    public void Write_Throws_WhenValueExceedsMax()
    {
        byte[] buffer = new byte[8];
        Assert.Throws<ArgumentOutOfRangeException>(() => VarInt.Write(buffer, VarInt.MaxValue + 1));
    }

    [Fact]
    public void Write_Throws_WhenDestinationTooSmall()
    {
        byte[] tooSmall = new byte[1];
        Assert.Throws<ArgumentException>(() => VarInt.Write(tooSmall, 16384));
    }

    [Theory]
    [InlineData(0x00, 1)]
    [InlineData(0x40, 2)]
    [InlineData(0x80, 4)]
    [InlineData(0xC0, 8)]
    public void GetLengthFromFirstByte_ReadsPrefixBits(byte first, int expected)
    {
        Assert.Equal(expected, VarInt.GetLengthFromFirstByte(first));
    }
}
