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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Messages;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class HandshakeReassemblyTests
{
    [Fact]
    public void CryptoAssembler_OutOfOrder_ProducesContiguousPrefix()
    {
        var a = new CryptoStreamAssembler();
        a.Add(4, [0x44, 0x55]);      // kommt zuerst, aber Offset 4
        a.Add(0, [0x00, 0x11, 0x22, 0x33]); // schließt die Lücke ab 0

        Assert.Equal(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, a.Contiguous());
    }

    [Fact]
    public void CryptoAssembler_StopsAtGap()
    {
        var a = new CryptoStreamAssembler();
        a.Add(0, [1, 2]);
        a.Add(5, [9, 9]); // Lücke bei 2..5 -> Präfix endet nach 2 Bytes

        Assert.Equal(new byte[] { 1, 2 }, a.Contiguous());
    }

    [Fact]
    public void CryptoAssembler_Duplicates_AreIdempotent()
    {
        var a = new CryptoStreamAssembler();
        a.Add(0, [1, 2, 3]);
        a.Add(0, [1, 2, 3]); // Retransmit desselben Fragments

        Assert.Equal(new byte[] { 1, 2, 3 }, a.Contiguous());
    }

    [Fact]
    public void CryptoAssembler_OverlappingFragment_AppendsOnlyNewBytes()
    {
        var a = new CryptoStreamAssembler();
        a.Add(0, [1, 2, 3]);
        a.Add(2, [3, 4, 5]); // überlappt bei Offset 2

        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, a.Contiguous());
    }

    [Fact]
    public void HandshakeMessages_ParsesMultiple_AndReportsPartialTail()
    {
        // EncryptedExtensions (Typ 08, Länge 2, Rumpf aabb) + Finished (Typ 14, Länge 1, Rumpf cc)
        // + angefangene dritte Nachricht (Typ 0b, Länge 10, aber nur 1 Byte da).
        byte[] buffer = Hex.Parse("08000002aabb" + "14000001cc" + "0b0000 0a ff".Replace(" ", ""));

        Assert.True(HandshakeMessages.TryReadAll(buffer, out var messages, out int consumed));
        Assert.Equal(2, messages.Count);
        Assert.Equal(HandshakeType.EncryptedExtensions, messages[0].Type);
        Assert.Equal(HandshakeType.Finished, messages[1].Type);
        Assert.Equal(new byte[] { 0xaa, 0xbb }, messages[0].Body.ToArray());
        Assert.Equal(6 + 5, consumed); // die dritte, unvollständige Nachricht bleibt ungelesen
    }
}
