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

using System.Security.Cryptography;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;

/// <summary>
/// Laufender Transcript-Hash über die Handshake-Nachrichten (RFC 8446 §4.4.1). Nachrichten werden
/// in der Reihenfolge ihres Auftretens angehängt; der Hash lässt sich jederzeit ohne Reset abfragen
/// (nötig, weil verschiedene Secrets an unterschiedlichen Stellen des Transcripts abgeleitet werden).
/// </summary>
public sealed class Transcript : IDisposable
{
    private readonly IncrementalHash _hash;
    private readonly int _hashLength;

    public Transcript(HashAlgorithmName hash)
    {
        _hash = IncrementalHash.CreateHash(hash);
        _hashLength = hash == HashAlgorithmName.SHA384 ? 48 : 32;
    }

    /// <summary>
    /// Hängt eine vollständige Handshake-Nachricht (inkl. Typ + 3-Byte-Länge) an.
    /// </summary>
    public void Append(ReadOnlySpan<byte> handshakeMessage) => _hash.AppendData(handshakeMessage);

    /// <summary>
    /// Der aktuelle Transcript-Hash, ohne den laufenden Zustand zurückzusetzen.
    /// </summary>
    public byte[] CurrentHash()
    {
        byte[] output = new byte[_hashLength];
        _hash.GetCurrentHash(output);
        return output;
    }

    public void Dispose() => _hash.Dispose();
}
