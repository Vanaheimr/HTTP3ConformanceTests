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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class InitialPacketFactoryTests
{
    [Fact]
    public void BuildClientInitial_PadsToMinimumSize_AndRoundTrips()
    {
        var dcid = ConnectionId.Parse("0102030405060708");
        var scid = ConnectionId.Parse("aabbccdd");
        var secrets = InitialSecrets.DeriveV1(dcid.Span);
        using var clientProt = new PacketProtection(secrets.Client);

        // Kleiner "ClientHello"-Platzhalter -> muss auf >= 1200 gepolstert werden.
        byte[] cryptoData = new byte[80];
        new Random(7).NextBytes(cryptoData);

        byte[] packet = InitialPacketFactory.BuildClientInitial(
            clientProt, 0x0000_0001, dcid, scid, token: default,
            packetNumber: 0, packetNumberLength: 4, cryptoData);

        Assert.True(packet.Length >= InitialPacketFactory.MinimumClientInitialSize,
            $"Paket war nur {packet.Length} Bytes.");

        // Empfängerseitig: parsen -> entschützen -> Frames -> CRYPTO-Daten zurückgewinnen.
        Assert.True(LongHeader.TryParse(packet, out LongHeaderPrefix? prefix));
        Assert.Equal(dcid, prefix!.DestinationConnectionId);
        Assert.Equal(scid, prefix.SourceConnectionId);

        using var serverView = new PacketProtection(secrets.Client); // gleiche Richtung (Selbsttest)
        byte[] plaintext = new byte[packet.Length];
        Assert.True(serverView.UnprotectPacket(packet, prefix.PacketNumberOffset, -1, longHeader: true,
            plaintext, out ulong pn, out int len));
        Assert.Equal(0UL, pn);

        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(plaintext.AsSpan(0, len), out List<Frame> frames));
        var crypto = Assert.IsType<CryptoFrame>(frames[0]);
        Assert.Equal(cryptoData, crypto.Data.ToArray());
        Assert.IsType<PaddingFrame>(frames[1]); // Rest ist PADDING
    }
}
