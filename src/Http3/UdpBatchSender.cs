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

using System.Net;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Versendet die Datagramme eines Pump-Durchlaufs möglichst in wenigen Syscalls (UDP-Batching,
/// Phase 9). Auf <b>Linux</b> werden gleich große Datagramme via <c>UDP_SEGMENT</c> (GSO) zu EINEM
/// <c>sendmsg</c> zusammengefasst — der Kernel zerlegt sie wieder in einzelne Pakete. Auf allen
/// anderen Plattformen (u. a. Windows) fällt der Sender auf eine schlanke Einzelsende-Schleife
/// zurück, die den <see cref="GsoBatcher"/>-Arbeitspuffer und die Ziel-Adresse wiederverwendet.
/// Beides ist auf dem Draht identisch — GSO spart nur Syscalls, nicht Bytes.
/// </summary>
internal sealed class UdpBatchSender
{
    // Linux: SOL_UDP = 17, UDP_SEGMENT = 103 (aus <netinet/udp.h> / <linux/udp.h>).
    private const SocketOptionLevel SolUdp = (SocketOptionLevel)17;
    private const SocketOptionName UdpSegment = (SocketOptionName)103;

    private readonly GsoBatcher _batcher = new();
    private readonly bool _gsoSupported = OperatingSystem.IsLinux();
    private bool _gsoDisabled; // wird gesetzt, falls der Kernel GSO doch ablehnt (dann dauerhaft Fallback)

    /// <summary>
    /// Sendet alle <paramref name="datagrams"/> über den (verbundenen oder unverbundenen)
    /// <paramref name="socket"/>. Ist <paramref name="remote"/> <c>null</c>, gilt der Socket als
    /// verbunden (Client); sonst wird an die Adresse gesendet (Server).
    /// </summary>
    public void Send(Socket socket, IReadOnlyList<byte[]> datagrams, EndPoint? remote)
    {
        if (datagrams.Count == 0)
            return;

        // Ohne GSO: schlichte Einzelsende-Schleife (keine Zwischenkopie).
        if (!_gsoSupported || _gsoDisabled)
        {
            foreach (byte[] datagram in datagrams)
                SendOne(socket, datagram, datagram.Length, remote);
            return;
        }

        _batcher.Batch(datagrams, batch =>
        {
            if (batch.SegmentCount <= 1)
            {
                SendOne(socket, batch.Buffer, batch.Length, remote);
                return;
            }
            try
            {
                socket.SetRawSocketOption((int)SolUdp, (int)UdpSegment, BitConverter.GetBytes(batch.SegmentSize));
                SendOne(socket, batch.Buffer, batch.Length, remote);
                socket.SetRawSocketOption((int)SolUdp, (int)UdpSegment, BitConverter.GetBytes(0)); // GSO wieder aus
            }
            catch (SocketException)
            {
                // Kernel/NIC lehnt GSO ab ⇒ dauerhaft auf Einzelsenden zurückfallen und diesen Batch
                // Segment für Segment nachholen (byte-identisch zum GSO-Ergebnis).
                _gsoDisabled = true;
                for (int offset = 0; offset < batch.Length; offset += batch.SegmentSize)
                {
                    int len = Math.Min(batch.SegmentSize, batch.Length - offset);
                    SendOne(socket, batch.Buffer.AsSpan(offset, len).ToArray(), len, remote);
                }
            }
        });
    }

    private static void SendOne(Socket socket, byte[] buffer, int length, EndPoint? remote)
    {
        if (remote is null)
            socket.Send(buffer, 0, length, SocketFlags.None);
        else
            socket.SendTo(buffer, 0, length, SocketFlags.None, remote);
    }
}
