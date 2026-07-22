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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Tests für die Connection-ID-Rotation (RFC 9000 §5.1, §19.15/§19.16): den <see cref="ConnectionIdManager"/>
/// isoliert sowie einen vollständigen Umlauf, bei dem der Server eine CID ausgibt und der Client seine DCID
/// darauf umstellt.
/// </summary>
public class ConnectionIdRotationTests
{
    private static ConnectionId Cid(params byte[] bytes) => new(bytes);
    private static byte[] Token() => new byte[16];

    [Fact]
    public void Issue_RespectsActiveConnectionIdLimit()
    {
        var m = new ConnectionIdManager(Cid(1, 1));
        Assert.NotNull(m.Issue(Cid(2, 2), Token(), activeLimit: 2)); // Sequenz 0 + eine weitere
        Assert.Null(m.Issue(Cid(3, 3), Token(), activeLimit: 2));    // Limit erreicht
        Assert.Equal(2, m.LocalCount);
    }

    [Fact]
    public void RetireLocal_RemovesIssuedConnectionId()
    {
        var m = new ConnectionIdManager(Cid(1, 1));
        m.Issue(Cid(2, 2), Token(), activeLimit: 5);
        Assert.Equal(2, m.LocalCount);
        m.RetireLocal(1);
        Assert.Equal(1, m.LocalCount);
    }

    [Fact]
    public void OnNewConnectionId_AddsRemote_AndRetirePriorTo_SwitchesDcid()
    {
        var m = new ConnectionIdManager(Cid(1, 1));
        m.InitializeRemote(Cid(0x10, 0x10)); // entfernte Sequenz 0

        var frame = new NewConnectionIdFrame(SequenceNumber: 1, RetirePriorTo: 1, Cid(0x11, 0x11).ToArray(), Token());
        List<RetireConnectionIdFrame> retires = m.OnNewConnectionId(frame, out bool changed, out ConnectionId newDcid);

        Assert.Single(retires);
        Assert.Equal(0ul, retires[0].SequenceNumber); // seq 0 zurückgezogen
        Assert.True(changed);
        Assert.Equal(Cid(0x11, 0x11), newDcid);        // DCID auf seq 1 gewechselt
        Assert.Equal(1ul, m.CurrentRemoteSequence);
    }

    [Fact]
    public void Rotate_SwitchesToHigherRemote_AndRetiresOld()
    {
        var m = new ConnectionIdManager(Cid(1, 1));
        m.InitializeRemote(Cid(0x10, 0x10));
        m.OnNewConnectionId(new NewConnectionIdFrame(1, 0, Cid(0x11, 0x11).ToArray(), Token()), out _, out _);

        (RetireConnectionIdFrame Retire, ConnectionId NewDcid)? rotation = m.Rotate();
        Assert.NotNull(rotation);
        Assert.Equal(Cid(0x11, 0x11), rotation!.Value.NewDcid);
        Assert.Equal(0ul, rotation.Value.Retire.SequenceNumber);
        Assert.Equal(1ul, m.CurrentRemoteSequence);
        Assert.Null(m.Rotate()); // keine weitere ID verfügbar
    }

    // ---- Integration ----------------------------------------------------------------------

    private static void Pump(QuicClientConnection client, QuicServerConnection server)
    {
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }

    [Fact]
    public void ServerIssuesConnectionId_ClientRotatesDcid_AndDataStillFlows()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.True(client.HandshakeConfirmed);
        Pump(client, server); // Restdaten abfließen lassen

        // Server gibt eine zusätzliche Connection ID aus (NEW_CONNECTION_ID).
        ConnectionId? issued = server.IssueConnectionId();
        Assert.NotNull(issued);
        Assert.Equal(2, server.LocalConnectionIdCount); // seq 0 + neue

        // Frame zum Client bringen; der Client lernt die entfernte CID.
        for (int round = 0; round < 3; round++)
            Pump(client, server);
        Assert.Equal(2, client.RemoteConnectionIdCount);

        // Client stellt seine DCID auf die neue ID um (und zieht die alte per RETIRE_CONNECTION_ID zurück).
        Assert.True(client.RotateDestinationConnectionId());
        Assert.Equal(issued!.Value, client.DestinationConnectionId);

        // Ab jetzt tragen die Pakete des Clients die neue DCID – der Server muss sie weiterhin annehmen.
        QuicStream stream = client.OpenBidirectionalStream();
        stream.Write([9, 8, 7, 6]);
        for (int round = 0; round < 10; round++)
            Pump(client, server);

        // Daten kamen unter der neuen Connection ID an.
        Assert.True(server.Streams.ContainsKey(stream.Id.Value));
        Assert.Equal([9, 8, 7, 6], server.Streams[stream.Id.Value].Read());

        // Der Server hat seine ursprüngliche (seq 0) Connection ID auf RETIRE_CONNECTION_ID zurückgezogen.
        Assert.Equal(1, server.LocalConnectionIdCount);
    }
}
