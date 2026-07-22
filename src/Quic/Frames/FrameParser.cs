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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;

/// <summary>
/// Ergebnis eines Frame-Parse-Vorgangs.
/// </summary>
public enum FrameParseResult
{
    Ok,
    /// <summary>
    /// Ein Frame war abgeschnitten oder syntaktisch ungültig ⇒ FRAME_ENCODING_ERROR.
    /// </summary>
    EncodingError,
    /// <summary>
    /// Unbekannter Frame-Typ ⇒ FRAME_ENCODING_ERROR (Frames sind nicht selbstbeschreibend).
    /// </summary>
    UnknownFrameType,
}

/// <summary>
/// Zerlegt einen entschlüsselten Paket-Payload in seine Frame-Folge (RFC 9000, §12.4).
/// Aufeinanderfolgende PADDING-Bytes werden zu einem <see cref="PaddingFrame"/> zusammengefasst.
/// </summary>
public static class FrameParser
{
    public static FrameParseResult TryParseAll(ReadOnlySpan<byte> payload, out List<Frame> frames)
    {
        frames = [];
        var reader = new BufferReader(payload);

        while (!reader.IsEmpty)
        {
            // PADDING (0x00) als Lauflänge zusammenfassen.
            if (payload[reader.Position] == FrameType.Padding)
            {
                int start = reader.Position;
                while (!reader.IsEmpty && payload[reader.Position] == FrameType.Padding)
                    reader.TrySkip(1);
                frames.Add(new PaddingFrame(reader.Position - start));
                continue;
            }

            if (!reader.TryReadVarInt(out ulong type))
                return FrameParseResult.EncodingError;

            switch (type)
            {
                case FrameType.Ping:
                    frames.Add(PingFrame.Instance);
                    break;

                case FrameType.HandshakeDone:
                    frames.Add(HandshakeDoneFrame.Instance);
                    break;

                case FrameType.AckNoEcn:
                case FrameType.AckEcn:
                    if (!AckFrame.TryReadBody(ref reader, hasEcn: type == FrameType.AckEcn, out AckFrame? ack))
                        return FrameParseResult.EncodingError;
                    frames.Add(ack!);
                    break;

                case FrameType.Crypto:
                    if (!CryptoFrame.TryReadBody(ref reader, out CryptoFrame? crypto))
                        return FrameParseResult.EncodingError;
                    frames.Add(crypto!);
                    break;

                case FrameType.NewToken:
                    if (!NewTokenFrame.TryReadBody(ref reader, out NewTokenFrame? newToken))
                        return FrameParseResult.EncodingError;
                    frames.Add(newToken!);
                    break;

                case 0x18: // NEW_CONNECTION_ID
                    if (!NewConnectionIdFrame.TryReadBody(ref reader, out NewConnectionIdFrame? newCid))
                        return FrameParseResult.EncodingError;
                    frames.Add(newCid!);
                    break;

                case 0x19: // RETIRE_CONNECTION_ID
                    if (!RetireConnectionIdFrame.TryReadBody(ref reader, out RetireConnectionIdFrame? retireCid))
                        return FrameParseResult.EncodingError;
                    frames.Add(retireCid!);
                    break;

                case FrameType.ResetStream:
                    if (!ResetStreamFrame.TryReadBody(ref reader, out ResetStreamFrame? resetStream))
                        return FrameParseResult.EncodingError;
                    frames.Add(resetStream!);
                    break;

                case FrameType.StopSending:
                    if (!StopSendingFrame.TryReadBody(ref reader, out StopSendingFrame? stopSending))
                        return FrameParseResult.EncodingError;
                    frames.Add(stopSending!);
                    break;

                case FrameType.DatagramNoLength:
                case FrameType.DatagramWithLength: // RFC 9221 §4
                    if (!DatagramFrame.TryReadBody(ref reader, hasLength: type == FrameType.DatagramWithLength, out DatagramFrame? datagram))
                        return FrameParseResult.EncodingError;
                    frames.Add(datagram!);
                    break;

                case FrameType.MaxData:
                    if (!MaxDataFrame.TryReadBody(ref reader, out MaxDataFrame? maxData))
                        return FrameParseResult.EncodingError;
                    frames.Add(maxData!);
                    break;

                case FrameType.MaxStreamData:
                    if (!MaxStreamDataFrame.TryReadBody(ref reader, out MaxStreamDataFrame? maxStreamData))
                        return FrameParseResult.EncodingError;
                    frames.Add(maxStreamData!);
                    break;

                case FrameType.MaxStreamsBidi:
                case FrameType.MaxStreamsUni:
                    if (!MaxStreamsFrame.TryReadBody(ref reader, type == FrameType.MaxStreamsBidi, out MaxStreamsFrame? maxStreams))
                        return FrameParseResult.EncodingError;
                    frames.Add(maxStreams!);
                    break;

                case FrameType.DataBlocked:
                    if (!DataBlockedFrame.TryReadBody(ref reader, out DataBlockedFrame? dataBlocked))
                        return FrameParseResult.EncodingError;
                    frames.Add(dataBlocked!);
                    break;

                case FrameType.StreamDataBlocked:
                    if (!StreamDataBlockedFrame.TryReadBody(ref reader, out StreamDataBlockedFrame? streamDataBlocked))
                        return FrameParseResult.EncodingError;
                    frames.Add(streamDataBlocked!);
                    break;

                case FrameType.StreamsBlockedBidi:
                case FrameType.StreamsBlockedUni:
                    if (!StreamsBlockedFrame.TryReadBody(ref reader, type == FrameType.StreamsBlockedBidi, out StreamsBlockedFrame? streamsBlocked))
                        return FrameParseResult.EncodingError;
                    frames.Add(streamsBlocked!);
                    break;

                case FrameType.PathChallenge:
                    if (!PathChallengeFrame.TryReadBody(ref reader, out PathChallengeFrame? pathChallenge))
                        return FrameParseResult.EncodingError;
                    frames.Add(pathChallenge!);
                    break;

                case FrameType.PathResponse:
                    if (!PathResponseFrame.TryReadBody(ref reader, out PathResponseFrame? pathResponse))
                        return FrameParseResult.EncodingError;
                    frames.Add(pathResponse!);
                    break;

                case FrameType.ConnectionCloseQuic:
                case FrameType.ConnectionCloseApp:
                    if (!ConnectionCloseFrame.TryReadBody(ref reader, isApplication: type == FrameType.ConnectionCloseApp, out ConnectionCloseFrame? close))
                        return FrameParseResult.EncodingError;
                    frames.Add(close!);
                    break;

                case >= FrameType.StreamBase and <= 0x0f:
                    if (!StreamFrame.TryReadBody(ref reader, (byte)type, out StreamFrame? stream))
                        return FrameParseResult.EncodingError;
                    frames.Add(stream!);
                    break;

                default:
                    return FrameParseResult.UnknownFrameType;
            }
        }

        return FrameParseResult.Ok;
    }

    /// <summary>
    /// Serialisiert eine Frame-Folge in einen bereits vorhandenen Writer (Hot Path).
    /// </summary>
    public static void WriteAll(ref BufferWriter writer, IEnumerable<Frame> frames)
    {
        foreach (Frame frame in frames)
            frame.Write(ref writer);
    }

    /// <summary>
    /// Bequemlichkeit: serialisiert eine Frame-Folge in ein frisches Byte-Array. Verwaltet den
    /// (mit <c>ref</c> unvereinbaren) <c>using</c>-Konflikt intern per try/finally.
    /// </summary>
    public static byte[] Serialize(IEnumerable<Frame> frames)
    {
        var writer = new BufferWriter();
        try
        {
            WriteAll(ref writer, frames);
            return writer.WrittenSpan.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }
}
