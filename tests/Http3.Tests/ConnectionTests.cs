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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class PacketNumberSpaceTests
{
    [Fact]
    public void NextPacketNumber_IncrementsFromZero()
    {
        var space = new PacketNumberSpace();
        Assert.Equal(0UL, space.NextPacketNumber());
        Assert.Equal(1UL, space.NextPacketNumber());
        Assert.Equal(2UL, space.NextPacketNumber());
    }

    [Fact]
    public void ReceivedPackets_DriveAckPendingAndBuildAck()
    {
        var space = new PacketNumberSpace();
        Assert.False(space.AckPending);
        Assert.Null(space.BuildAck());

        space.RecordReceived(0);
        space.RecordReceived(1);
        Assert.True(space.AckPending);

        AckFrame? ack = space.BuildAck();
        Assert.NotNull(ack);
        Assert.Equal(1UL, ack!.LargestAcknowledged);
        Assert.False(space.AckPending); // nach dem Bauen quittiert
        Assert.Equal(1, space.LargestReceived);
    }

    [Fact]
    public void OnAckReceived_TracksLargestAckedByPeer()
    {
        var space = new PacketNumberSpace();
        Assert.Equal(-1, space.LargestAckedByPeer);

        space.OnAckReceived(5);
        Assert.Equal(5, space.LargestAckedByPeer);
        space.OnAckReceived(3); // kleinerer Wert ändert nichts
        Assert.Equal(5, space.LargestAckedByPeer);
    }
}

public class TlsClientHandshakeTests
{
    [Fact]
    public void Start_ProducesClientHelloAtInitialLevel()
    {
        using var tls = new TlsClientHandshake("example.com", new byte[] { 0x01, 0x01, 0x00 });
        tls.Start();

        Assert.True(tls.TryGetOutgoingCrypto(out EncryptionLevel level, out byte[] data));
        Assert.Equal(EncryptionLevel.Initial, level);
        Assert.Equal(0x01, data[0]); // Handshake-Typ ClientHello
        Assert.False(tls.TryGetOutgoingCrypto(out _, out _)); // nur eine Nachricht
    }

    [Fact]
    public void ProvideServerHello_DerivesHandshakeSecrets()
    {
        // Server-Key-Share aus einem echten P-256-Schlüsselpaar.
        using var serverKex = EcdheKeyExchange.Create(NamedGroup.Secp256r1);
        byte[] serverHello = BuildServerHello((ushort)CipherSuite.Aes128GcmSha256,
            (ushort)NamedGroup.Secp256r1, serverKex.PublicKey);

        using var tls = new TlsClientHandshake("example.com", new byte[] { 0x01, 0x01, 0x00 });
        tls.Start();
        tls.TryGetOutgoingCrypto(out _, out _); // ClientHello abholen

        tls.ProvideCrypto(EncryptionLevel.Initial, serverHello);

        Assert.Equal(CipherSuite.Aes128GcmSha256, tls.NegotiatedCipherSuite);
        Assert.NotNull(tls.HandshakeSecrets);
        Assert.Equal(32, tls.HandshakeSecrets!.ServerHandshakeTrafficSecret.Length);
    }

    private static byte[] BuildServerHello(ushort cipher, ushort group, byte[] keyShare)
    {
        string keyShareExt = "0033" + (4 + keyShare.Length).ToString("x4") + group.ToString("x4")
                             + keyShare.Length.ToString("x4") + Convert.ToHexString(keyShare);
        string extensions = "002b00020304" + keyShareExt;
        string body = "0303" + new string('0', 64) + "00" + cipher.ToString("x4") + "00"
                      + (extensions.Length / 2).ToString("x4") + extensions;
        return Hex.Parse("02" + (body.Length / 2).ToString("x6") + body);
    }
}
