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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

/// <summary>
/// Ein PSK-Angebot des Clients: Ticket-Identity, verschleiertes Alter und der zugehörige Binder.
/// </summary>
public readonly record struct OfferedPsk(byte[] Identity, uint ObfuscatedAge, byte[] Binder);

/// <summary>
/// Die vom Server benötigten Felder eines geparsten ClientHello.
/// </summary>
public sealed class ClientHelloInfo
{
    public required IReadOnlyList<ushort> CipherSuites { get; init; }

    /// <summary>
    /// Key-Share-Einträge des Clients: NamedGroup → öffentlicher Schlüssel.
    /// </summary>
    public required IReadOnlyDictionary<ushort, byte[]> KeyShares { get; init; }

    /// <summary>
    /// Vom Client unterstützte Named Groups (supported_groups-Extension) für die HRR-Wahl.
    /// </summary>
    public required IReadOnlyList<ushort> SupportedGroups { get; init; }

    /// <summary>
    /// Rohe quic_transport_parameters des Clients (opak für TLS).
    /// </summary>
    public byte[]? QuicTransportParameters { get; init; }

    /// <summary>
    /// PSK-Angebote aus pre_shared_key (RFC 8446 §4.2.11); leer, wenn keine Resumption angeboten wird.
    /// </summary>
    public IReadOnlyList<OfferedPsk> OfferedPsks { get; init; } = [];

    /// <summary>
    /// Ob der Client psk_dhe_ke unterstützt (RFC 8446 §4.2.9) – Voraussetzung für unsere Resumption.
    /// </summary>
    public bool OffersPskDheKe { get; init; }

    /// <summary>
    /// Absoluter Offset (im ClientHello-Handshake-Bytestrom) der Binder-Liste, also die Grenze, bis zu der
    /// der PSK-Binder berechnet wird (RFC 8446 §4.2.11.2). <c>-1</c>, wenn kein pre_shared_key vorhanden ist.
    /// </summary>
    public int PskBinderListOffset { get; init; } = -1;

    /// <summary>
    /// Der Client bot eine PSK an und (für 0-RTT) zusätzlich early_data.
    /// </summary>
    public bool OffersEarlyData { get; init; }
}

/// <summary>
/// Parst einen ClientHello serverseitig (RFC 8446 §4.1.2).
/// </summary>
public static class ClientHelloParser
{
    public static bool TryParse(ReadOnlySpan<byte> handshakeMessage, out ClientHelloInfo? info)
    {
        info = null;
        var reader = new BufferReader(handshakeMessage);

        if (!reader.TryReadByte(out byte msgType) || msgType != (byte)HandshakeType.ClientHello)
            return false;
        if (!reader.TryReadByte(out _) || !reader.TryReadByte(out _) || !reader.TryReadByte(out _))
            return false; // 3-Byte-Länge

        if (!reader.TryReadUInt16(out _))            // legacy_version
            return false;
        if (!reader.TryReadBytes(32, out _))         // Random
            return false;
        if (!reader.TryReadByte(out byte sessionIdLen) || !reader.TrySkip(sessionIdLen))
            return false;

        if (!reader.TryReadUInt16(out ushort csLen) || (csLen & 1) != 0)
            return false;
        var cipherSuites = new List<ushort>(csLen / 2);
        for (int i = 0; i < csLen; i += 2)
        {
            if (!reader.TryReadUInt16(out ushort suite))
                return false;
            cipherSuites.Add(suite);
        }

        if (!reader.TryReadByte(out byte compLen) || !reader.TrySkip(compLen))
            return false;

        if (!reader.TryReadUInt16(out ushort extsLen) || extsLen > reader.Remaining)
            return false;
        // Absoluter Offset, an dem der Extensions-Block beginnt (für die Binder-Trunkierungsgrenze).
        int extensionsAbsoluteStart = handshakeMessage.Length - reader.Remaining;
        if (!reader.TryReadBytes(extsLen, out ReadOnlySpan<byte> extensions))
            return false;

        var keyShares = new Dictionary<ushort, byte[]>();
        var supportedGroups = new List<ushort>();
        var offeredPsks = new List<OfferedPsk>();
        byte[]? quicTransportParameters = null;
        bool offersPskDheKe = false;
        bool offersEarlyData = false;
        int binderListOffset = -1;
        if (!ParseExtensions(extensions, extensionsAbsoluteStart, keyShares, supportedGroups, offeredPsks,
                ref quicTransportParameters, ref offersPskDheKe, ref offersEarlyData, ref binderListOffset))
            return false;

        info = new ClientHelloInfo
        {
            CipherSuites = cipherSuites,
            KeyShares = keyShares,
            SupportedGroups = supportedGroups,
            QuicTransportParameters = quicTransportParameters,
            OfferedPsks = offeredPsks,
            OffersPskDheKe = offersPskDheKe,
            OffersEarlyData = offersEarlyData,
            PskBinderListOffset = binderListOffset,
        };
        return true;
    }

    private static bool ParseExtensions(
        ReadOnlySpan<byte> extensions,
        int extensionsAbsoluteStart,
        Dictionary<ushort, byte[]> keyShares,
        List<ushort> supportedGroups,
        List<OfferedPsk> offeredPsks,
        ref byte[]? quicTransportParameters,
        ref bool offersPskDheKe,
        ref bool offersEarlyData,
        ref int binderListOffset)
    {
        var reader = new BufferReader(extensions);
        while (!reader.IsEmpty)
        {
            int extHeaderStart = extensions.Length - reader.Remaining;
            if (!reader.TryReadUInt16(out ushort type) ||
                !reader.TryReadUInt16(out ushort length) ||
                !reader.TryReadBytes(length, out ReadOnlySpan<byte> data))
                return false;

            switch ((ExtensionType)type)
            {
                case ExtensionType.KeyShare:
                    ParseKeyShares(data, keyShares);
                    break;
                case ExtensionType.SupportedGroups:
                    ParseSupportedGroups(data, supportedGroups);
                    break;
                case ExtensionType.QuicTransportParameters:
                    quicTransportParameters = data.ToArray();
                    break;
                case ExtensionType.PskKeyExchangeModes:
                    offersPskDheKe = PskModesContainDhe(data);
                    break;
                case ExtensionType.EarlyData:
                    offersEarlyData = true;
                    break;
                case ExtensionType.PreSharedKey:
                    // Absoluter Offset der Extension-Daten (nach dem 4-Byte-Extension-Header).
                    int dataAbsolute = extensionsAbsoluteStart + extHeaderStart + 4;
                    ParsePreSharedKey(data, dataAbsolute, offeredPsks, ref binderListOffset);
                    break;
            }
        }
        return true;
    }

    private static bool PskModesContainDhe(ReadOnlySpan<byte> data)
    {
        var r = new BufferReader(data);
        if (!r.TryReadByte(out byte listLen) || listLen > r.Remaining)
            return false;
        for (int i = 0; i < listLen; i++)
            if (r.TryReadByte(out byte mode) && mode == (byte)PskKeyExchangeMode.PskDheKe)
                return true;
        return false;
    }

    private static void ParsePreSharedKey(
        ReadOnlySpan<byte> data, int dataAbsoluteOffset, List<OfferedPsk> offeredPsks, ref int binderListOffset)
    {
        var r = new BufferReader(data);
        if (!r.TryReadUInt16(out ushort identitiesLen) || identitiesLen > r.Remaining)
            return;

        // Die Identities (jeweils Ticket + verschleiertes Alter) einsammeln.
        var identities = new List<(byte[] Identity, uint Age)>();
        if (!r.TryReadBytes(identitiesLen, out ReadOnlySpan<byte> identitiesBlock))
            return;
        var ir = new BufferReader(identitiesBlock);
        while (ir.Remaining >= 6)
        {
            if (!ir.TryReadUInt16(out ushort idLen) ||
                !ir.TryReadBytes(idLen, out ReadOnlySpan<byte> id) ||
                !ir.TryReadUInt32(out uint age))
                return;
            identities.Add((id.ToArray(), age));
        }

        // Die Binder-Liste beginnt direkt nach den Identities – das ist die Trunkierungsgrenze.
        binderListOffset = dataAbsoluteOffset + 2 + identitiesLen;

        if (!r.TryReadUInt16(out ushort bindersLen) || bindersLen > r.Remaining)
            return;
        if (!r.TryReadBytes(bindersLen, out ReadOnlySpan<byte> bindersBlock))
            return;
        var br = new BufferReader(bindersBlock);
        int index = 0;
        while (br.Remaining >= 1 && index < identities.Count)
        {
            if (!br.TryReadByte(out byte binderLen) || !br.TryReadBytes(binderLen, out ReadOnlySpan<byte> binder))
                return;
            (byte[] identity, uint ageValue) = identities[index++];
            offeredPsks.Add(new OfferedPsk(identity, ageValue, binder.ToArray()));
        }
    }

    private static void ParseSupportedGroups(ReadOnlySpan<byte> data, List<ushort> groups)
    {
        var reader = new BufferReader(data);
        if (!reader.TryReadUInt16(out _)) // Listenlänge
            return;
        while (reader.TryReadUInt16(out ushort group))
            groups.Add(group);
    }

    private static void ParseKeyShares(ReadOnlySpan<byte> data, Dictionary<ushort, byte[]> keyShares)
    {
        var reader = new BufferReader(data);
        if (!reader.TryReadUInt16(out _)) // client_shares-Länge
            return;
        while (reader.Remaining >= 4)
        {
            if (!reader.TryReadUInt16(out ushort group) ||
                !reader.TryReadUInt16(out ushort keyLen) ||
                !reader.TryReadBytes(keyLen, out ReadOnlySpan<byte> key))
                return;
            keyShares[group] = key.ToArray();
        }
    }
}
