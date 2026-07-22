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
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3;

/// <summary>
/// Kapselt die QPACK-Anbindung einer HTTP/3-Verbindung: die dynamische Tabelle (Encoder + Decoder), das
/// Lesen der QPACK-Encoder- und Control-Streams der Gegenseite sowie das (De-)Kodieren von Field Sections.
/// Ist die angekündigte Kapazität 0, bleibt alles rein statisch (Cloudflare-interop-sicher); ist sie &gt; 0
/// und kündigt auch der Peer eine Kapazität an, wird die dynamische Tabelle beidseitig genutzt (RFC 9204).
/// </summary>
internal sealed class Http3Qpack
{
    private const ulong DesiredEncoderCapacity = 4096;

    private readonly QpackDynamicEncoder _encoder = new();
    private readonly QpackDynamicDecoder _decoder = new();
    private readonly ulong _localMaxCapacity; // was wir als Decoder ankündigen
    private readonly bool _weAreClient;

    private QuicStream? _encoderStream; // unser ausgehender QPACK-Encoder-Stream (Insert-Instruktionen)
    private QuicStream? _decoderStream; // unser ausgehender QPACK-Decoder-Stream (Section-Acks)
    private bool _encoderCapacitySet;
    private ulong _peerMaxCapacity;
    private bool _peerSettingsSeen;

    private readonly Dictionary<ulong, PeerUniStream> _peerStreams = [];

    public Http3Qpack(ulong localMaxCapacity, bool weAreClient)
    {
        _localMaxCapacity = localMaxCapacity;
        _weAreClient = weAreClient;
    }

    /// <summary>
    /// Die von uns (als Decoder) angekündigte maximale Tabellenkapazität.
    /// </summary>
    public ulong LocalMaxCapacity => _localMaxCapacity;

    /// <summary>
    /// Insert Count der Encoder-Tabelle (Diagnose: &gt; 0 ⇒ dynamische Tabelle wurde genutzt).
    /// </summary>
    public ulong EncoderInsertCount => _encoder.Table.InsertCount;

    /// <summary>
    /// Insert Count der Decoder-Tabelle (Diagnose).
    /// </summary>
    public ulong DecoderInsertCount => _decoder.Table.InsertCount;

    /// <summary>
    /// Vom Peer per Section-Ack/Insert-Count-Increment bestätigte Insert-Anzahl (Diagnose).
    /// </summary>
    public ulong EncoderKnownReceivedCount => _encoder.KnownReceivedCount;

    public void SetEncoderStream(QuicStream stream) => _encoderStream = stream;
    public void SetDecoderStream(QuicStream stream) => _decoderStream = stream;

    /// <summary>
    /// Kodiert eine Header-Liste (für den Stream <paramref name="streamId"/>) zu einer Field Section. Nutzt die
    /// dynamische Tabelle (mit Insert-Instruktionen auf dem Encoder-Stream), sobald wir und der Peer je eine
    /// Kapazität &gt; 0 angekündigt haben; sonst statisch.
    /// </summary>
    public byte[] EncodeHeaders(ulong streamId, IReadOnlyList<HeaderField> headers)
    {
        if (_localMaxCapacity > 0 && _peerSettingsSeen && _peerMaxCapacity > 0 && _encoderStream is not null)
        {
            if (!_encoderCapacitySet)
            {
                _encoderStream.Write(_encoder.SetCapacity(Math.Min(_peerMaxCapacity, DesiredEncoderCapacity)));
                _encoderCapacitySet = true;
            }
            (byte[] instructions, byte[] section) = _encoder.Encode(streamId, headers);
            if (instructions.Length > 0)
                _encoderStream.Write(instructions);
            return section;
        }
        return QpackEncoder.Encode(headers);
    }

    /// <summary>
    /// Dekodiert eine Field Section des Streams <paramref name="streamId"/>. Gibt <c>null</c> zurück, wenn der
    /// Stream blockiert ist (die referenzierten dynamischen Einträge sind noch nicht eingetroffen) – dann später
    /// erneut versuchen. Bei einer dynamischen Sektion wird eine Section-Acknowledgment gesendet (RFC 9204 §4.4.1).
    /// </summary>
    public List<HeaderField>? TryDecodeHeaders(ulong streamId, ReadOnlySpan<byte> section)
    {
        QpackResult result = _decoder.Decode(section, out List<HeaderField> headers, out ulong requiredInsertCount);
        if (result == QpackResult.Blocked)
            return null;
        if (result == QpackResult.Ok && requiredInsertCount > 0 && _decoderStream is not null)
            _decoderStream.Write(QpackDynamicDecoder.EncodeSectionAcknowledgment(streamId));
        return headers; // Ok oder Fehler (leere Liste)
    }

    /// <summary>
    /// Liest die unidirektionalen Streams der Gegenseite (Control für SETTINGS, QPACK-Encoder-Stream).
    /// </summary>
    public void PumpPeerStreams(IReadOnlyDictionary<ulong, QuicStream> streams)
    {
        foreach ((ulong id, QuicStream stream) in streams)
        {
            if (!stream.Id.IsUnidirectional)
                continue;
            bool peerInitiated = _weAreClient ? stream.Id.IsServerInitiated : stream.Id.IsClientInitiated;
            if (!peerInitiated)
                continue;

            if (!_peerStreams.TryGetValue(id, out PeerUniStream? peer))
                _peerStreams[id] = peer = new PeerUniStream(stream);

            byte[] chunk = stream.Read();
            if (chunk.Length > 0)
                peer.Buffer.AddRange(chunk);
            RoutePeerStream(peer);
        }
    }

    private void RoutePeerStream(PeerUniStream peer)
    {
        // Stream-Typ (erster VarInt) einmalig lesen.
        if (peer.Type is null)
        {
            var reader = new BufferReader(peer.Buffer.ToArray());
            if (!reader.TryReadVarInt(out ulong type))
                return; // Typ-VarInt noch unvollständig
            peer.Type = type;
            peer.Buffer.RemoveRange(0, reader.Position);
        }

        switch (peer.Type)
        {
            case Http3StreamType.QpackEncoder:
                byte[] pending = peer.Buffer.ToArray();
                if (_decoder.ProcessEncoderInstructions(pending, out int consumed))
                    peer.Buffer.RemoveRange(0, consumed);
                break;

            case Http3StreamType.QpackDecoder: // Section-Acks / Insert Count Increment des Peers.
                int ackConsumed = _encoder.ProcessDecoderInstructions(peer.Buffer.ToArray());
                peer.Buffer.RemoveRange(0, ackConsumed);
                break;

            case Http3StreamType.Control:
                if (peer.Buffer.Count > 0 &&
                    Http3Frames.TryReadAll(peer.Buffer.ToArray(), out List<Http3Frame> frames, out int used))
                {
                    foreach (Http3Frame frame in frames)
                        if (frame.Type == Http3FrameType.Settings)
                            ParseSettings(frame.Payload.Span);
                    peer.Buffer.RemoveRange(0, used);
                }
                break;

            default: // QPACK-Decoder-Stream, Push u. a.: verwerfen (wir nutzen keine Acks/Push).
                peer.Buffer.Clear();
                break;
        }
    }

    private void ParseSettings(ReadOnlySpan<byte> payload)
    {
        var reader = new BufferReader(payload);
        while (reader.TryReadVarInt(out ulong id) && reader.TryReadVarInt(out ulong value))
            if (id == Http3Setting.QpackMaxTableCapacity)
                _peerMaxCapacity = value;
        _peerSettingsSeen = true;
    }

    private sealed class PeerUniStream(QuicStream stream)
    {
        public QuicStream Stream { get; } = stream;
        public ulong? Type { get; set; }
        public List<byte> Buffer { get; } = [];
    }
}
