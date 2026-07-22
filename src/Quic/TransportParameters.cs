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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic;

/// <summary>
/// QUIC-Transport-Parameter (RFC 9000, §18). Sie werden im TLS-Handshake als opake Extension
/// <c>quic_transport_parameters</c> (Typ 0x39) ausgetauscht und legen Limits wie Flow-Control-Fenster,
/// Idle-Timeout und Stream-Zahlen fest. Dieses Modell deckt die für einen Client-Handshake nötigen
/// Parameter ab; unbekannte Parameter der Gegenseite werden beim Parsen ignoriert (Greasing-tauglich).
/// </summary>
public sealed class TransportParameters
{
    // Parameter-IDs (RFC 9000 §18.2).
    private const ulong OriginalDestinationConnectionId = 0x00;
    private const ulong MaxIdleTimeout = 0x01;
    private const ulong StatelessResetToken = 0x02;
    private const ulong MaxUdpPayloadSize = 0x03;
    private const ulong InitialMaxData = 0x04;
    private const ulong InitialMaxStreamDataBidiLocal = 0x05;
    private const ulong InitialMaxStreamDataBidiRemote = 0x06;
    private const ulong InitialMaxStreamDataUni = 0x07;
    private const ulong InitialMaxStreamsBidi = 0x08;
    private const ulong InitialMaxStreamsUni = 0x09;
    private const ulong ActiveConnectionIdLimit = 0x0e;
    private const ulong InitialSourceConnectionId = 0x0f;
    private const ulong MaxDatagramFrameSize = 0x20; // RFC 9221 §3
    private const ulong RetrySourceConnectionId = 0x10;
    private const ulong ResetStreamAt = 0x1d; // draft-ietf-quic-reliable-stream-reset §3 (provisorisch)

    /// <summary>
    /// Idle-Timeout in Millisekunden (0 = deaktiviert).
    /// </summary>
    public ulong MaxIdleTimeoutMs { get; set; } = 30_000;

    public ulong MaxUdpPayloadSizeValue { get; set; } = 65527;
    public ulong InitialMaxDataValue { get; set; } = 1_048_576;      // 1 MiB Verbindungsfenster
    public ulong InitialMaxStreamDataBidiLocalValue { get; set; } = 262_144;
    public ulong InitialMaxStreamDataBidiRemoteValue { get; set; } = 262_144;
    public ulong InitialMaxStreamDataUniValue { get; set; } = 262_144;
    public ulong InitialMaxStreamsBidiValue { get; set; } = 100;
    public ulong InitialMaxStreamsUniValue { get; set; } = 100;
    public ulong ActiveConnectionIdLimitValue { get; set; } = 2;

    /// <summary>
    /// Die Source Connection ID aus dem eigenen Initial-Paket. Der Client MUSS diese hier spiegeln,
    /// damit der Server die Handshake-Authentizität prüfen kann (RFC 9001 §8.2).
    /// </summary>
    public ConnectionId InitialSourceConnectionIdValue { get; set; } = ConnectionId.Empty;

    /// <summary>
    /// Nur vom Server gesetzt: die DCID aus dem allerersten Client-Initial.
    /// </summary>
    public ConnectionId? OriginalDestinationConnectionIdValue { get; set; }

    /// <summary>
    /// Nur vom Server gesetzt und nur nach einem Retry: die SCID aus dem Retry-Paket (RFC 9000 §7.3).
    /// </summary>
    public ConnectionId? RetrySourceConnectionIdValue { get; set; }

    /// <summary>
    /// Stateless-Reset-Token (16 Bytes) für die Handshake-Connection-ID (RFC 9000 §10.3, §18.2). Der Empfänger
    /// erkennt daran ein Stateless-Reset-Paket. <c>null</c> = nicht gesetzt.
    /// </summary>
    public byte[]? StatelessResetTokenValue { get; set; }

    /// <summary>
    /// max_datagram_frame_size (RFC 9221 §3): maximale Größe eines DATAGRAM-Frames (inkl. Typ/Länge),
    /// die wir zu EMPFANGEN bereit sind. 0 (Standard) = DATAGRAM-Frames werden nicht unterstützt;
    /// empfohlen ist 65535 („alles, was in ein QUIC-Paket passt").
    /// </summary>
    public ulong MaxDatagramFrameSizeValue { get; set; }

    /// <summary>
    /// reset_stream_at (draft-ietf-quic-reliable-stream-reset §3): kündigt an, dass wir RESET_STREAM_AT-
    /// Frames zu EMPFANGEN bereit sind (leerer Wert). Standard <c>true</c> — die Extension ist harmlos und
    /// ermöglicht Peers die zuverlässige Teilzustellung (z. B. den WebTransport-Stream-Präfix).
    /// </summary>
    public bool ResetStreamAtSupported { get; set; } = true;

    /// <summary>
    /// Der Peer hat reset_stream_at angekündigt — wir DÜRFEN ihm RESET_STREAM_AT-Frames senden. Wird beim
    /// Parsen der Peer-Parameter gesetzt.
    /// </summary>
    public bool PeerSupportsResetStreamAt { get; private set; }

    /// <summary>
    /// Serialisiert die Parameter zu den opaken Extension-Bytes.
    /// </summary>
    public byte[] Encode()
    {
        var writer = new BufferWriter(256);
        try
        {
            WriteInteger(ref writer, MaxIdleTimeout, MaxIdleTimeoutMs);
            if (StatelessResetTokenValue is { Length: 16 } token)
                WriteBytes(ref writer, StatelessResetToken, token);
            WriteInteger(ref writer, MaxUdpPayloadSize, MaxUdpPayloadSizeValue);
            WriteInteger(ref writer, InitialMaxData, InitialMaxDataValue);
            WriteInteger(ref writer, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiLocalValue);
            WriteInteger(ref writer, InitialMaxStreamDataBidiRemote, InitialMaxStreamDataBidiRemoteValue);
            WriteInteger(ref writer, InitialMaxStreamDataUni, InitialMaxStreamDataUniValue);
            WriteInteger(ref writer, InitialMaxStreamsBidi, InitialMaxStreamsBidiValue);
            WriteInteger(ref writer, InitialMaxStreamsUni, InitialMaxStreamsUniValue);
            WriteInteger(ref writer, ActiveConnectionIdLimit, ActiveConnectionIdLimitValue);
            if (MaxDatagramFrameSizeValue > 0)
                WriteInteger(ref writer, MaxDatagramFrameSize, MaxDatagramFrameSizeValue); // RFC 9221 §3
            if (ResetStreamAtSupported)
                WriteBytes(ref writer, ResetStreamAt, []); // draft §3: leerer Wert signalisiert Empfangsbereitschaft
            WriteBytes(ref writer, InitialSourceConnectionId, InitialSourceConnectionIdValue.Span);
            if (OriginalDestinationConnectionIdValue is { } odcid)
                WriteBytes(ref writer, OriginalDestinationConnectionId, odcid.Span);
            if (RetrySourceConnectionIdValue is { } rscid)
                WriteBytes(ref writer, RetrySourceConnectionId, rscid.Span);

            return writer.WrittenSpan.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>
    /// Parst die opaken Extension-Bytes. Unbekannte Parameter-IDs werden übersprungen.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> data, out TransportParameters? parameters)
    {
        parameters = null;
        var result = new TransportParameters
        {
            // Standardwerte, die nur gesetzt werden, wenn der Peer sie sendet; hier neutral vorbelegen.
            MaxIdleTimeoutMs = 0,
        };
        var reader = new BufferReader(data);

        while (!reader.IsEmpty)
        {
            if (!reader.TryReadVarInt(out ulong id) ||
                !reader.TryReadVarInt(out ulong length) ||
                length > (ulong)reader.Remaining ||
                !reader.TryReadBytes((int)length, out ReadOnlySpan<byte> value))
                return false;

            switch (id)
            {
                case MaxIdleTimeout: result.MaxIdleTimeoutMs = ReadVarIntValue(value); break;
                case StatelessResetToken: result.StatelessResetTokenValue = value.ToArray(); break;
                case MaxUdpPayloadSize: result.MaxUdpPayloadSizeValue = ReadVarIntValue(value); break;
                case InitialMaxData: result.InitialMaxDataValue = ReadVarIntValue(value); break;
                case InitialMaxStreamDataBidiLocal: result.InitialMaxStreamDataBidiLocalValue = ReadVarIntValue(value); break;
                case InitialMaxStreamDataBidiRemote: result.InitialMaxStreamDataBidiRemoteValue = ReadVarIntValue(value); break;
                case InitialMaxStreamDataUni: result.InitialMaxStreamDataUniValue = ReadVarIntValue(value); break;
                case InitialMaxStreamsBidi: result.InitialMaxStreamsBidiValue = ReadVarIntValue(value); break;
                case InitialMaxStreamsUni: result.InitialMaxStreamsUniValue = ReadVarIntValue(value); break;
                case ActiveConnectionIdLimit: result.ActiveConnectionIdLimitValue = ReadVarIntValue(value); break;
                case MaxDatagramFrameSize: result.MaxDatagramFrameSizeValue = ReadVarIntValue(value); break;
                case ResetStreamAt:
                    if (value.Length != 0)
                        return false; // draft §3: nicht-leerer Wert ⇒ TRANSPORT_PARAMETER_ERROR
                    result.PeerSupportsResetStreamAt = true;
                    break;
                case InitialSourceConnectionId: result.InitialSourceConnectionIdValue = new ConnectionId(value); break;
                case OriginalDestinationConnectionId: result.OriginalDestinationConnectionIdValue = new ConnectionId(value); break;
                case RetrySourceConnectionId: result.RetrySourceConnectionIdValue = new ConnectionId(value); break;
                default: break; // unbekannt/Grease -> ignorieren
            }
        }

        parameters = result;
        return true;
    }

    private static void WriteInteger(ref BufferWriter writer, ulong id, ulong value)
    {
        writer.WriteVarInt(id);
        writer.WriteVarInt((ulong)VarInt.GetLength(value));
        writer.WriteVarInt(value);
    }

    private static void WriteBytes(ref BufferWriter writer, ulong id, ReadOnlySpan<byte> value)
    {
        writer.WriteVarInt(id);
        writer.WriteVarInt((ulong)value.Length);
        writer.WriteBytes(value);
    }

    private static ulong ReadVarIntValue(ReadOnlySpan<byte> value)
        => VarInt.TryRead(value, out ulong v, out _) ? v : 0;
}
