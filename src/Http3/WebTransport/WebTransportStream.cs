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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;

/// <summary>
/// Eine WebTransport-Datenstrom (draft-webtrans-http3 §4.1/§4.2): ein nativer QUIC-Stream, dessen
/// Kopf (Uni-Typ 0x54 bzw. WT_STREAM-Signal 0x41, jeweils gefolgt von der Session-ID) bereits
/// abgetrennt ist — <see cref="Read"/>/<see cref="Write"/> arbeiten auf den reinen Nutzdaten.
/// Reset/StopSending bilden 32-Bit-App-Fehlercodes in den WT_APPLICATION_ERROR-Bereich ab (§4.3).
/// </summary>
public sealed class WebTransportStream
{
    private readonly QuicStream _stream;
    private readonly bool _canSend;    // Senderichtung vorhanden (bidi oder lokal geöffneter Uni)
    private readonly bool _canReceive; // Empfangsrichtung vorhanden (bidi oder eingehender Uni)
    private byte[] _leftover; // zusammen mit dem Kopf gelesene Nutzdaten, die zuerst zurückkommen

    internal WebTransportStream(QuicStream stream, bool bidirectional, bool canSend, bool canReceive, byte[]? leftover = null)
    {
        _stream = stream;
        IsBidirectional = bidirectional;
        _canSend = canSend;
        _canReceive = canReceive;
        _leftover = leftover ?? [];
    }

    /// <summary>
    /// <c>true</c> = bidirektionaler WebTransport-Stream, <c>false</c> = unidirektional.
    /// </summary>
    public bool IsBidirectional { get; }

    /// <summary>
    /// Die zugrunde liegende QUIC-Stream-ID.
    /// </summary>
    public ulong StreamId => _stream.Id.Value;

    /// <summary>
    /// Liest den nächsten zusammenhängenden Nutzdaten-Abschnitt (Kopf bereits abgetrennt).
    /// </summary>
    public byte[] Read()
    {
        byte[] fresh = _stream.Read();
        if (_leftover.Length == 0)
            return fresh;
        byte[] combined = [.. _leftover, .. fresh]; // einmalig den Header-Rest voranstellen
        _leftover = [];
        return combined;
    }

    /// <summary>
    /// Schreibt Nutzdaten (nur auf Bidi- bzw. lokal initiierten Uni-Streams sinnvoll).
    /// </summary>
    public void Write(ReadOnlySpan<byte> data) => _stream.Write(data);

    /// <summary>
    /// Beendet die Senderichtung (FIN).
    /// </summary>
    public void Finish() => _stream.Finish();

    /// <summary>
    /// Der Peer hat seine Senderichtung beendet (FIN) und alles ist gelesen.
    /// </summary>
    public bool IsReceiveComplete => _stream.IsReceiveComplete;

    /// <summary>
    /// Bricht die Senderichtung ab (RESET_STREAM); <paramref name="applicationErrorCode"/> ist ein
    /// 32-Bit-WebTransport-Fehler und wird in den WT_APPLICATION_ERROR-Bereich abgebildet (§4.3).
    /// </summary>
    public void Reset(uint applicationErrorCode)
    {
        if (_canSend)
            _stream.Reset(WebTransportConstants.ApplicationErrorToHttp(applicationErrorCode));
    }

    /// <summary>
    /// Bricht das Lesen ab (STOP_SENDING), mit in den WT_APPLICATION_ERROR-Bereich abgebildetem Code.
    /// </summary>
    public void StopSending(uint applicationErrorCode)
    {
        if (_canReceive)
            _stream.AbortRead(WebTransportConstants.ApplicationErrorToHttp(applicationErrorCode));
    }

    /// <summary>
    /// Der Peer hat diese Stream-Seite zurückgesetzt (RESET_STREAM).
    /// </summary>
    public bool IsResetByPeer => _stream.IsResetByPeer;

    /// <summary>
    /// Der (zurückgerechnete) WebTransport-Anwendungsfehlercode eines Peer-Resets, falls im
    /// WT_APPLICATION_ERROR-Bereich; sonst <c>null</c>.
    /// </summary>
    public uint? PeerResetErrorCode
        => _stream.PeerResetErrorCode is { } http ? WebTransportConstants.HttpToApplicationError(http) : null;

    /// <summary>
    /// Vom Session-Management aufgerufen, wenn die Session endet (§6): beide Richtungen mit
    /// WT_SESSION_GONE abbrechen.
    /// </summary>
    internal void AbortForSessionGone()
    {
        // Nur die tatsächlich vorhandene(n) Richtung(en) abbrechen — sonst STREAM_STATE_ERROR
        // (STOP_SENDING auf einen send-only-Uni bzw. RESET_STREAM auf einen receive-only-Uni).
        if (_canSend)
            _stream.Reset(WebTransportConstants.SessionGone);
        if (_canReceive)
            _stream.AbortRead(WebTransportConstants.SessionGone);
    }

    internal QuicStream Underlying => _stream;
}
