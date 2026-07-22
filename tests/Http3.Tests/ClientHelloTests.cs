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
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class ClientHelloTests
{
    private static ClientHelloOptions BuildOptions(out byte[] transportParams)
    {
        using var kex = EcdheKeyExchange.Create(NamedGroup.Secp256r1);

        var tp = new TransportParameters
        {
            InitialSourceConnectionIdValue = ConnectionId.Parse("0102030405"),
        };
        transportParams = tp.Encode();

        return new ClientHelloOptions
        {
            ServerName = "cloudflare-quic.com",
            SupportedGroups = [NamedGroup.Secp256r1],
            KeyShares = [new KeyShareEntry(NamedGroup.Secp256r1, kex.PublicKey)],
            QuicTransportParameters = transportParams,
        };
    }

    [Fact]
    public void Build_ClientHello_HasWellFormedStructureAndRequiredExtensions()
    {
        ClientHelloOptions options = BuildOptions(out _);
        byte[] ch = ClientHello.Build(options);

        var reader = new BufferReader(ch);
        Assert.Equal((byte)HandshakeType.ClientHello, reader.ReadByte());

        int length = (reader.ReadByte() << 16) | (reader.ReadByte() << 8) | reader.ReadByte();
        Assert.Equal(length, reader.Remaining); // 3-Byte-Handshake-Länge deckt exakt den Rest

        Assert.Equal(TlsVersions.Tls12, reader.ReadUInt16()); // legacy_version
        reader.ReadBytes(32);                                 // Random
        Assert.Equal(0, reader.ReadByte());                   // leere legacy_session_id

        ushort csLen = reader.ReadUInt16();
        List<ushort> suites = ReadUInt16List(ref reader, csLen);
        Assert.Contains((ushort)CipherSuite.Aes128GcmSha256, suites);

        Assert.Equal(1, reader.ReadByte()); // compression methods length
        Assert.Equal(0, reader.ReadByte()); // null compression

        ushort extsLen = reader.ReadUInt16();
        Assert.Equal(extsLen, reader.Remaining);
        Dictionary<ushort, byte[]> exts = ReadExtensions(ref reader);

        // supported_versions enthält TLS 1.3
        Assert.True(exts.ContainsKey((ushort)ExtensionType.SupportedVersions));
        byte[] sv = exts[(ushort)ExtensionType.SupportedVersions];
        Assert.Equal(0x0304, (sv[1] << 8) | sv[2]); // [listLen(1)][0x03,0x04]

        // ALPN enthält "h3"
        byte[] alpn = exts[(ushort)ExtensionType.Alpn];
        Assert.Contains("h3", DecodeAlpn(alpn));

        // key_share: secp256r1 mit 65-Byte-Punkt
        byte[] ks = exts[(ushort)ExtensionType.KeyShare];
        int group = (ks[2] << 8) | ks[3];
        int keyLen = (ks[4] << 8) | ks[5];
        Assert.Equal((int)NamedGroup.Secp256r1, group);
        Assert.Equal(65, keyLen);
        Assert.Equal(0x04, ks[6]); // unkomprimierter Punkt

        // SNI enthält den Hostnamen
        byte[] sni = exts[(ushort)ExtensionType.ServerName];
        Assert.Contains("cloudflare-quic.com", System.Text.Encoding.ASCII.GetString(sni));

        // quic_transport_parameters vorhanden und nicht leer
        Assert.True(exts.TryGetValue((ushort)ExtensionType.QuicTransportParameters, out byte[]? qtp));
        Assert.NotEmpty(qtp!);
    }

    [Fact]
    public void Ecdhe_BothParties_DeriveSameSecret()
    {
        using var client = EcdheKeyExchange.Create(NamedGroup.Secp256r1);
        using var server = EcdheKeyExchange.Create(NamedGroup.Secp256r1);

        byte[] clientView = client.DeriveSharedSecret(server.PublicKey);
        byte[] serverView = server.DeriveSharedSecret(client.PublicKey);

        Assert.Equal(clientView, serverView);
        Assert.Equal(32, clientView.Length); // P-256: X-Koordinate = 32 Byte
    }

    [Fact]
    public void TransportParameters_RoundTrip_PreservesValues()
    {
        var tp = new TransportParameters
        {
            MaxIdleTimeoutMs = 15_000,
            InitialMaxDataValue = 500_000,
            InitialMaxStreamsBidiValue = 42,
            InitialSourceConnectionIdValue = ConnectionId.Parse("cafebabe"),
        };

        Assert.True(TransportParameters.TryDecode(tp.Encode(), out TransportParameters? decoded));
        Assert.Equal(15_000UL, decoded!.MaxIdleTimeoutMs);
        Assert.Equal(500_000UL, decoded.InitialMaxDataValue);
        Assert.Equal(42UL, decoded.InitialMaxStreamsBidiValue);
        Assert.Equal(ConnectionId.Parse("cafebabe"), decoded.InitialSourceConnectionIdValue);
    }

    [Fact]
    public void TransportParameters_Decode_IgnoresUnknownParameters()
    {
        // Bekannter Parameter (max_idle_timeout id=01, len=01, wert=05)
        // + unbekannte ID 16383 (2-Byte-VarInt 7fff), len=02, Wert aabb -> muss ignoriert werden.
        byte[] wire = Hex.Parse("010105" + "7fff02aabb");
        Assert.True(TransportParameters.TryDecode(wire, out TransportParameters? tp));
        Assert.Equal(5UL, tp!.MaxIdleTimeoutMs);
    }

    // --- Hilfsfunktionen ----------------------------------------------------------------------

    private static List<ushort> ReadUInt16List(ref BufferReader reader, int byteLength)
    {
        var list = new List<ushort>();
        for (int i = 0; i < byteLength; i += 2)
            list.Add(reader.ReadUInt16());
        return list;
    }

    private static Dictionary<ushort, byte[]> ReadExtensions(ref BufferReader reader)
    {
        var exts = new Dictionary<ushort, byte[]>();
        while (!reader.IsEmpty)
        {
            ushort type = reader.ReadUInt16();
            ushort len = reader.ReadUInt16();
            exts[type] = reader.ReadBytes(len).ToArray();
        }
        return exts;
    }

    private static List<string> DecodeAlpn(byte[] alpn)
    {
        var protocols = new List<string>();
        var reader = new BufferReader(alpn);
        reader.ReadUInt16(); // ProtocolNameList-Länge
        while (!reader.IsEmpty)
        {
            byte len = reader.ReadByte();
            protocols.Add(System.Text.Encoding.ASCII.GetString(reader.ReadBytes(len)));
        }
        return protocols;
    }
}
