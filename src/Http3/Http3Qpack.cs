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
/// Setzt außerdem die Frame-/Stream-Zustandsmaschine der Uni-Streams durch (RFC 9114 §6.2, §7.2):
/// Verstöße der Gegenseite werden über <c>onConnectionError</c> als HTTP/3-Verbindungsfehler gemeldet.
/// </summary>
internal sealed class Http3Qpack
{
    private const ulong DesiredEncoderCapacity = 4096;

    private readonly QpackDynamicEncoder _encoder = new();
    private readonly QpackDynamicDecoder _decoder = new();
    private readonly ulong _localMaxCapacity; // was wir als Decoder ankündigen
    private readonly bool _weAreClient;
    private readonly Action<ulong, string> _fatal; // HTTP/3-Verbindungsfehler (RFC 9114 §8)

    private QuicStream? _encoderStream; // unser ausgehender QPACK-Encoder-Stream (Insert-Instruktionen)
    private QuicStream? _decoderStream; // unser ausgehender QPACK-Decoder-Stream (Section-Acks)
    private bool _encoderCapacitySet;
    private ulong _peerMaxCapacity;
    private bool _peerSettingsSeen;

    private ulong? _peerControlId;  // RFC 9114 §6.2.1: genau EIN Control-Stream pro Peer
    private ulong? _peerEncoderId;  // RFC 9204 §4.2: genau EIN Encoder-/Decoder-Stream pro Peer
    private ulong? _peerDecoderId;

    private readonly Dictionary<ulong, PeerUniStream> _peerStreams = [];
    private readonly HashSet<ulong> _webTransportUniStreams = []; // an den WebTransport-Manager übergebene Uni-Streams

    public Http3Qpack(ulong localMaxCapacity, bool weAreClient, Action<ulong, string> onConnectionError)
    {
        _localMaxCapacity = localMaxCapacity;
        _weAreClient = weAreClient;
        _fatal = onConnectionError;
    }

    /// <summary>
    /// Reservierte HTTP/2-Frame-Typen ohne HTTP/3-Entsprechung (RFC 9114 §7.2.8/§11.2.1) — ihr Empfang
    /// MUSS als Verbindungsfehler H3_FRAME_UNEXPECTED behandelt werden.
    /// </summary>
    internal static bool IsReservedHttp2FrameType(ulong type) => type is 0x02 or 0x06 or 0x08 or 0x09;

    /// <summary>
    /// Vom Peer per SETTINGS_MAX_FIELD_SECTION_SIZE angekündigtes Limit (RFC 9114 §4.2.2);
    /// <c>null</c> = unbegrenzt. Field Sections über diesem Limit SOLLEN NICHT gesendet werden.
    /// </summary>
    public ulong? PeerMaxFieldSectionSize { get; private set; }

    /// <summary>
    /// Der Peer (Server) erlaubt Extended CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL = 1,
    /// RFC 8441 §3 / RFC 9220 §3). Ohne dieses Setting DARF der Client kein :protocol senden.
    /// </summary>
    public bool PeerEnableConnectProtocol { get; private set; }

    /// <summary>
    /// Der Peer nimmt HTTP/3-Datagramme an (SETTINGS_H3_DATAGRAM = 1, RFC 9297 §2.1.1).
    /// </summary>
    public bool PeerH3Datagram { get; private set; }

    /// <summary>
    /// WebTransport-Settings des Peers (draft-webtrans-http3 §9.2): max. Sessions und die Anfangs-
    /// Flow-Control-Limits. <c>WtMaxSessions</c> = 0 ⇒ Peer akzeptiert keine WebTransport-Sessions.
    /// </summary>
    public ulong PeerWtMaxSessions { get; private set; }
    public ulong PeerWtInitialMaxStreamsUni { get; private set; }
    public ulong PeerWtInitialMaxStreamsBidi { get; private set; }
    public ulong PeerWtInitialMaxData { get; private set; }

    /// <summary>
    /// Unkomprimierte Größe einer Field Section nach RFC 9114 §4.2.2: je Feld die Byte-Längen von
    /// Name und Wert plus 32 Bytes Overhead.
    /// </summary>
    internal static ulong FieldSectionSize(IReadOnlyList<HeaderField> fields)
    {
        ulong size = 0;
        foreach (HeaderField field in fields)
            size += (ulong)System.Text.Encoding.UTF8.GetByteCount(field.Name)
                  + (ulong)System.Text.Encoding.UTF8.GetByteCount(field.Value)
                  + 32;
        return size;
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
    /// Liest die unidirektionalen Streams der Gegenseite (Control für SETTINGS, QPACK-Encoder-Stream)
    /// und setzt dabei die Stream-/Frame-Regeln aus RFC 9114 §6.2/§7.2 durch.
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

            if (_webTransportUniStreams.Contains(id))
                continue; // an den WebTransport-Manager übergeben – nicht mehr hier pumpen
            if (!_peerStreams.TryGetValue(id, out PeerUniStream? peer))
                _peerStreams[id] = peer = new PeerUniStream(stream);

            byte[] chunk = stream.Read();
            if (chunk.Length > 0)
                peer.Buffer.AddRange(chunk);
            RoutePeerStream(peer);

            // RFC 9114 §6.2.1 / RFC 9204 §4.2: Control-, Encoder- und Decoder-Stream dürfen NIE enden —
            // weder sauber (FIN) noch per Reset ⇒ H3_CLOSED_CRITICAL_STREAM.
            if ((peer.Type == Http3StreamType.Control || peer.Type == Http3StreamType.QpackEncoder ||
                 peer.Type == Http3StreamType.QpackDecoder) &&
                (stream.Receive.FinReceived || stream.IsResetByPeer))
            {
                _fatal(Http3Error.ClosedCriticalStream, "critical stream closed");
                return;
            }
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

            // Stream-Erzeugungsregeln (einmalig beim Lesen des Typs prüfen):
            switch (type)
            {
                case Http3StreamType.Control when _peerControlId is not null:       // §6.2.1: nur EIN Control-Stream
                case Http3StreamType.QpackEncoder when _peerEncoderId is not null:  // RFC 9204 §4.2: nur je EIN …
                case Http3StreamType.QpackDecoder when _peerDecoderId is not null:  // … Encoder-/Decoder-Stream
                    _fatal(Http3Error.StreamCreationError, "duplicate critical stream");
                    return;
                case Http3StreamType.Control:
                    _peerControlId = peer.Stream.Id.Value;
                    break;
                case Http3StreamType.QpackEncoder:
                    _peerEncoderId = peer.Stream.Id.Value;
                    break;
                case Http3StreamType.QpackDecoder:
                    _peerDecoderId = peer.Stream.Id.Value;
                    break;
                case Http3StreamType.Push when !_weAreClient:
                    // §6.2.2: nur Server pushen; ein client-initiierter Push-Stream ist ein Verbindungsfehler.
                    _fatal(Http3Error.StreamCreationError, "client-initiated push stream");
                    return;
                case Http3StreamType.Push:
                    // §4.6: wir (Client) haben nie ein MAX_PUSH_ID gesendet ⇒ jeder Push-Stream ist illegal.
                    _fatal(Http3Error.IdError, "push stream without MAX_PUSH_ID");
                    return;
            }
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
                        if (!HandleControlFrame(frame))
                            return; // Verbindungsfehler gemeldet
                    peer.Buffer.RemoveRange(0, used);
                }
                break;

            case WebTransport.WebTransportConstants.UniStreamType when OnWebTransportUniStream is not null:
                // WebTransport-Uni-Stream (draft §4.1): 0x54 ‖ Session-ID ‖ Nutzdaten. Session-ID lesen,
                // dann den Stream an den WebTransport-Manager übergeben (der liest fortan direkt).
                var wtReader = new BufferReader(peer.Buffer.ToArray());
                if (!wtReader.TryReadVarInt(out ulong wtSessionId))
                    break; // Session-ID noch unvollständig
                byte[] wtLeftover = peer.Buffer.Skip(wtReader.Position).ToArray();
                _webTransportUniStreams.Add(peer.Stream.Id.Value); // ab jetzt der WebTransport-Manager
                _peerStreams.Remove(peer.Stream.Id.Value);
                OnWebTransportUniStream(peer.Stream, wtSessionId, wtLeftover);
                break;

            default: // Unbekannte/reservierte Stream-Typen: Daten verwerfen, KEIN Verbindungsfehler (§6.2).
                peer.Buffer.Clear();
                break;
        }
    }

    /// <summary>
    /// Callback für einen erkannten WebTransport-Uni-Stream (draft §4.1): (Stream, Session-ID, bereits
    /// mitgelesene Nutzdaten). Ist er gesetzt, kündigt die HTTP/3-Schicht WebTransport an.
    /// </summary>
    public Action<QuicStream, ulong, byte[]>? OnWebTransportUniStream { get; set; }

    /// <summary>
    /// Frame-Zustandsmaschine des Control-Streams (RFC 9114 §6.2.1, §7.2). Gibt <c>false</c> zurück,
    /// wenn ein Verbindungsfehler gemeldet wurde.
    /// </summary>
    private bool HandleControlFrame(Http3Frame frame)
    {
        // §6.2.1: das ERSTE Frame MUSS SETTINGS sein.
        if (!_peerSettingsSeen && frame.Type != Http3FrameType.Settings)
        {
            _fatal(Http3Error.MissingSettings, "first control frame is not SETTINGS");
            return false;
        }

        switch (frame.Type)
        {
            case Http3FrameType.Settings when _peerSettingsSeen:
                _fatal(Http3Error.FrameUnexpected, "second SETTINGS frame"); // §7.2.4
                return false;
            case Http3FrameType.Settings:
                return ParseSettings(frame.Payload.Span);

            case Http3FrameType.Data:    // §7.2.1: DATA nur auf Request-/Push-Streams
            case Http3FrameType.Headers: // §7.2.2: HEADERS nur auf Request-/Push-Streams
                _fatal(Http3Error.FrameUnexpected, "DATA/HEADERS on control stream");
                return false;

            case Http3FrameType.PushPromise:
                // §7.2.5: auf dem Control-Stream immer illegal (und Clients senden PUSH_PROMISE nie).
                _fatal(Http3Error.FrameUnexpected, "PUSH_PROMISE on control stream");
                return false;

            case Http3FrameType.MaxPushId when _weAreClient:
                _fatal(Http3Error.FrameUnexpected, "MAX_PUSH_ID sent to client"); // §7.2.7
                return false;
            case Http3FrameType.MaxPushId:
                return RequireSingleVarInt(frame, "MAX_PUSH_ID"); // wir pushen nicht ⇒ Wert egal

            case Http3FrameType.CancelPush when _weAreClient:
                // §7.2.3: referenziert eine Push-ID jenseits des Erlaubten — wir haben NIE eine erlaubt.
                _fatal(Http3Error.IdError, "CANCEL_PUSH without MAX_PUSH_ID");
                return false;
            case Http3FrameType.CancelPush:
                return RequireSingleVarInt(frame, "CANCEL_PUSH");

            case Http3FrameType.GoAway:
                return HandleGoAway(frame);

            case Http3FrameType.PriorityUpdateRequest when _weAreClient:
            case Http3FrameType.PriorityUpdatePush when _weAreClient:
                // RFC 9218 §7.2: Server MÜSSEN NIE PRIORITY_UPDATE senden.
                _fatal(Http3Error.FrameUnexpected, "PRIORITY_UPDATE sent to client");
                return false;
            case Http3FrameType.PriorityUpdatePush:
                // RFC 9218 §7.2: Push-ID größer als das Maximum bzw. nie versprochen — wir erlauben
                // nie Push, also ist JEDE referenzierte Push-ID illegal.
                _fatal(Http3Error.IdError, "PRIORITY_UPDATE for unpromised push");
                return false;
            case Http3FrameType.PriorityUpdateRequest:
                return HandlePriorityUpdate(frame);

            default:
                if (IsReservedHttp2FrameType(frame.Type))
                {
                    _fatal(Http3Error.FrameUnexpected, "reserved HTTP/2 frame type"); // §7.2.8
                    return false;
                }
                return true; // unbekannte Typen (inkl. Grease 0x1f·N+0x21) ignorieren (§9)
        }
    }

    /// <summary>
    /// Wird beim Server für jedes gültige PRIORITY_UPDATE (RFC 9218 §7.2) aufgerufen:
    /// (Request-Stream-ID, Priority Field Value als ASCII-Text).
    /// </summary>
    public Action<ulong, string>? OnPriorityUpdate { get; set; }

    /// <summary>
    /// PRIORITY_UPDATE für Request-Streams (RFC 9218 §7.2): Payload = Prioritized Element ID (VarInt)
    /// + Priority Field Value (ASCII). Die ID MUSS eine Request-Stream-ID sein (client-initiiert
    /// bidirektional, Bits 0b00), sonst H3_ID_ERROR.
    /// </summary>
    private bool HandlePriorityUpdate(Http3Frame frame)
    {
        var reader = new BufferReader(frame.Payload.Span);
        if (!reader.TryReadVarInt(out ulong id))
        {
            _fatal(Http3Error.FrameError, "malformed PRIORITY_UPDATE payload"); // §7.1
            return false;
        }
        if ((id & 0x03) != 0)
        {
            _fatal(Http3Error.IdError, "PRIORITY_UPDATE for non-request stream"); // RFC 9218 §7.2 MUST
            return false;
        }
        string fieldValue = System.Text.Encoding.ASCII.GetString(frame.Payload.Span[reader.Position..]);
        OnPriorityUpdate?.Invoke(id, fieldValue);
        return true;
    }

    /// <summary>
    /// GOAWAY (RFC 9114 §5.2/§7.2.6): Payload ist genau EIN VarInt. Beim Client MUSS die ID eine
    /// client-initiierte bidirektionale Stream-ID sein (Bits 0b00), sonst H3_ID_ERROR. Mehrere GOAWAYs
    /// sind erlaubt, aber die ID darf NIE anwachsen (§5.2) — sonst ebenfalls H3_ID_ERROR.
    /// </summary>
    private bool HandleGoAway(Http3Frame frame)
    {
        var reader = new BufferReader(frame.Payload.Span);
        if (!reader.TryReadVarInt(out ulong id) || reader.Remaining > 0)
        {
            _fatal(Http3Error.FrameError, "malformed GOAWAY payload"); // §7.1
            return false;
        }
        if (_weAreClient && (id & 0x03) != 0)
        {
            _fatal(Http3Error.IdError, "GOAWAY with non-request stream ID"); // §7.2.6
            return false;
        }
        if (GoAwayId is { } previous && id > previous)
        {
            _fatal(Http3Error.IdError, "GOAWAY identifier increased"); // §5.2
            return false;
        }
        GoAwayId = id;
        return true;
    }

    /// <summary>
    /// Die zuletzt per GOAWAY empfangene Stream-/Push-ID (RFC 9114 §5.2), falls vorhanden.
    /// </summary>
    public ulong? GoAwayId { get; private set; }

    /// <summary>
    /// §7.1: die Nutzlast muss GENAU die definierten Felder enthalten — hier ein einzelner VarInt.
    /// </summary>
    private bool RequireSingleVarInt(Http3Frame frame, string name)
    {
        var reader = new BufferReader(frame.Payload.Span);
        if (!reader.TryReadVarInt(out _) || reader.Remaining > 0)
        {
            _fatal(Http3Error.FrameError, $"malformed {name} payload");
            return false;
        }
        return true;
    }

    /// <summary>
    /// SETTINGS-Nutzlast (RFC 9114 §7.2.4): Paare aus VarInt-ID und -Wert. Reservierte HTTP/2-IDs
    /// (0x00, 0x02–0x05) und doppelte IDs ⇒ H3_SETTINGS_ERROR; Layout-Fehler ⇒ H3_FRAME_ERROR.
    /// </summary>
    private bool ParseSettings(ReadOnlySpan<byte> payload)
    {
        var reader = new BufferReader(payload);
        var seen = new HashSet<ulong>();
        while (reader.Remaining > 0)
        {
            if (!reader.TryReadVarInt(out ulong id) || !reader.TryReadVarInt(out ulong value))
            {
                _fatal(Http3Error.FrameError, "malformed SETTINGS payload"); // §7.1
                return false;
            }
            if (id is 0x00 or 0x02 or 0x03 or 0x04 or 0x05)
            {
                _fatal(Http3Error.SettingsError, "reserved HTTP/2 setting"); // §7.2.4.1/§11.2.2
                return false;
            }
            if (!seen.Add(id))
            {
                _fatal(Http3Error.SettingsError, "duplicate setting identifier"); // §7.2.4
                return false;
            }
            if (id == Http3Setting.QpackMaxTableCapacity)
                _peerMaxCapacity = value;
            else if (id == Http3Setting.MaxFieldSectionSize)
                PeerMaxFieldSectionSize = value; // RFC 9114 §4.2.2
            else if (id == Http3Setting.EnableConnectProtocol)
            {
                if (value > 1)
                {
                    _fatal(Http3Error.SettingsError, "ENABLE_CONNECT_PROTOCOL must be 0 or 1"); // RFC 8441 §3
                    return false;
                }
                PeerEnableConnectProtocol = value == 1;
            }
            else if (id == Http3Setting.H3Datagram)
            {
                if (value > 1)
                {
                    _fatal(Http3Error.SettingsError, "H3_DATAGRAM must be 0 or 1"); // RFC 9297 §2.1.1
                    return false;
                }
                PeerH3Datagram = value == 1;
            }
            else if (id == WebTransport.WebTransportConstants.SettingMaxSessions)
                PeerWtMaxSessions = value; // draft-webtrans-http3 §9.2
            else if (id == WebTransport.WebTransportConstants.SettingInitialMaxStreamsUni)
                PeerWtInitialMaxStreamsUni = value;
            else if (id == WebTransport.WebTransportConstants.SettingInitialMaxStreamsBidi)
                PeerWtInitialMaxStreamsBidi = value;
            else if (id == WebTransport.WebTransportConstants.SettingInitialMaxData)
                PeerWtInitialMaxData = value;
        }
        _peerSettingsSeen = true;
        return true;
    }

    private sealed class PeerUniStream(QuicStream stream)
    {
        public QuicStream Stream { get; } = stream;
        public ulong? Type { get; set; }
        public List<byte> Buffer { get; } = [];
    }
}
