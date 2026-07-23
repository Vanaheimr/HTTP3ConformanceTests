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
/// Splits the body of a Certificate message (RFC 8446 §4.4.2) into the individual DER certificates.
/// Layout: <c>certificate_request_context&lt;0..2^8-1&gt; ‖ CertificateEntry certificate_list&lt;0..2^24-1&gt;</c>,
/// where each entry is <c>cert_data&lt;1..2^24-1&gt; ‖ extensions&lt;0..2^16-1&gt;</c>. The first
/// certificate is the end-entity (leaf) certificate.
/// </summary>
public static class CertificateMessage
{
    public static bool TryParse(ReadOnlySpan<byte> body, out List<byte[]> certificates)
    {
        certificates = [];

        var r = new BufferReader(body);
        if (!r.TryReadByte(out byte contextLength) || !r.TrySkip(contextLength))
            return false;
        if (!TryReadUInt24(ref r, out int listLength) || listLength > r.Remaining)
            return false;

        int listEnd = r.Position + listLength;
        while (r.Position < listEnd)
        {
            if (!TryReadUInt24(ref r, out int certLength) ||
                !r.TryReadBytes(certLength, out ReadOnlySpan<byte> der))
                return false;
            certificates.Add(der.ToArray());

            if (!r.TryReadUInt16(out ushort extLength) || !r.TrySkip(extLength))
                return false;
        }

        return certificates.Count > 0;
    }

    /// <summary>
    /// Reads a 3-byte length (big-endian), as is customary in TLS for certificate vectors.
    /// </summary>
    private static bool TryReadUInt24(ref BufferReader r, out int value)
    {
        value = 0;
        if (!r.TryReadBytes(3, out ReadOnlySpan<byte> b))
            return false;
        value = (b[0] << 16) | (b[1] << 8) | b[2];
        return true;
    }
}
