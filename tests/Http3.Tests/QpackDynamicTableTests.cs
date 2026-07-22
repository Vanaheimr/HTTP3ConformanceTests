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

using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Tests der dynamischen QPACK-Tabelle (RFC 9204): der byte-genaue Anhang-B.2-Vektor, Duplicate,
/// Encoder↔Decoder-Round-Trip inkl. dynamischer Wiederverwendung sowie Eviction.
/// </summary>
public class QpackDynamicTableTests
{
    [Fact]
    public void Rfc9204_AppendixB2_DecodesDynamicFieldSection()
    {
        var decoder = new QpackDynamicDecoder();

        // Encoder-Stream: Set Capacity 220, Insert :authority www.example.com, Insert :path /sample/path.
        byte[] encoderStream = Convert.FromHexString(
            "3fbd01" +
            "c00f" + "7777772e6578616d706c652e636f6d" +
            "c10c" + "2f73616d706c652f70617468");
        Assert.Equal(QpackResult.Ok, decoder.ProcessEncoderInstructions(encoderStream));
        Assert.Equal(2ul, decoder.Table.InsertCount);
        Assert.Equal(106ul, decoder.Table.Size); // RFC: Size 106 bytes

        // Field Section (Stream 4): RIC=2, Base=0, zwei Post-Base-Indizes.
        byte[] fieldSection = Convert.FromHexString("03811011");
        Assert.Equal(QpackResult.Ok, decoder.Decode(fieldSection, out List<HeaderField> headers));

        Assert.Equal(2, headers.Count);
        Assert.Equal(":authority", headers[0].Name);
        Assert.Equal("www.example.com", headers[0].Value);
        Assert.Equal(":path", headers[1].Name);
        Assert.Equal("/sample/path", headers[1].Value);
    }

    [Fact]
    public void EncoderStream_Duplicate_AddsCopyOfOlderEntry()
    {
        var decoder = new QpackDynamicDecoder();
        decoder.ProcessEncoderInstructions(Convert.FromHexString(
            "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468"));

        // Duplicate mit relativem Index 1 ⇒ absoluter Index InsertCount(2)-1-1 = 0 (:authority).
        Assert.Equal(QpackResult.Ok, decoder.ProcessEncoderInstructions([0x01]));
        Assert.Equal(3ul, decoder.Table.InsertCount);
        Assert.True(decoder.Table.TryGetByAbsolute(2, out (string Name, string Value) copy));
        Assert.Equal(":authority", copy.Name);
        Assert.Equal("www.example.com", copy.Value);
    }

    [Fact]
    public void EncoderDecoder_RoundTrip_UsesDynamicTable()
    {
        var encoder = new QpackDynamicEncoder();
        var decoder = new QpackDynamicDecoder();
        decoder.ProcessEncoderInstructions(encoder.SetCapacity(4096));

        var headers = new List<HeaderField>
        {
            new(":method", "GET"),
            new(":scheme", "https"),
            new(":authority", "example.org"),
            new(":path", "/index.html"),
            new("custom-header", "custom-value"),
        };

        (byte[] instructions, byte[] section) = encoder.Encode(headers);
        Assert.Equal(QpackResult.Ok, decoder.ProcessEncoderInstructions(instructions));
        Assert.Equal(QpackResult.Ok, decoder.Decode(section, out List<HeaderField> decoded));

        Assert.Equal(headers.Count, decoded.Count);
        for (int i = 0; i < headers.Count; i++)
        {
            Assert.Equal(headers[i].Name, decoded[i].Name);
            Assert.Equal(headers[i].Value, decoded[i].Value);
        }
        Assert.True(encoder.Table.InsertCount > 0, "Nicht-statische Header müssen die dynamische Tabelle nutzen.");
        Assert.Equal(encoder.Table.InsertCount, decoder.Table.InsertCount);
    }

    [Fact]
    public void RepeatedHeader_ReferencesDynamicEntry_WithoutReinserting()
    {
        var encoder = new QpackDynamicEncoder();
        var decoder = new QpackDynamicDecoder();
        decoder.ProcessEncoderInstructions(encoder.SetCapacity(4096));

        var headers = new List<HeaderField> { new(":authority", "example.org") };

        (byte[] i1, byte[] s1) = encoder.Encode(headers); // fügt ein
        decoder.ProcessEncoderInstructions(i1);
        Assert.Equal(QpackResult.Ok, decoder.Decode(s1, out _));
        ulong afterFirst = encoder.Table.InsertCount;
        Assert.Equal(1ul, afterFirst);

        (byte[] i2, byte[] s2) = encoder.Encode(headers); // referenziert die vorhandene Zeile
        Assert.Empty(i2);                                  // keine neue Insert-Instruktion
        Assert.Equal(afterFirst, encoder.Table.InsertCount); // kein neuer Eintrag

        Assert.Equal(QpackResult.Ok, decoder.ProcessEncoderInstructions(i2));
        Assert.Equal(QpackResult.Ok, decoder.Decode(s2, out List<HeaderField> decoded));
        Assert.Single(decoded);
        Assert.Equal(":authority", decoded[0].Name);
        Assert.Equal("example.org", decoded[0].Value);
    }

    [Fact]
    public void DynamicTable_EvictsOldest_WhenOverCapacity()
    {
        var table = new QpackDynamicTable();
        table.SetCapacity(60); // eine Zeile (34 B) passt, zwei (68 B) nicht

        Assert.True(table.Insert("a", "1")); // Größe 1+1+32 = 34
        Assert.True(table.Insert("b", "2")); // verdrängt "a"

        Assert.Equal(2ul, table.InsertCount);
        Assert.Equal(34ul, table.Size);
        Assert.False(table.TryGetByAbsolute(0, out _), "Der älteste Eintrag muss verdrängt sein.");
        Assert.True(table.TryGetByAbsolute(1, out (string Name, string Value) e));
        Assert.Equal("b", e.Name);
    }

    [Fact]
    public void DynamicTable_EntryLargerThanCapacity_IsNotInserted()
    {
        var table = new QpackDynamicTable();
        table.SetCapacity(40); // < 34 + Nutzlast? "aa"+"bbbbbbbbbb" = 2+10+32 = 44 > 40
        Assert.False(table.Insert("aa", "bbbbbbbbbb"));
        Assert.Equal(0ul, table.InsertCount);
    }

    [Fact]
    public void SectionAcknowledgment_ReleasesReferences_ReenablingEviction()
    {
        var encoder = new QpackDynamicEncoder();
        encoder.SetCapacity(80); // fasst genau zwei Einträge à 36 B (Name 3 + Wert 1 + 32)

        encoder.Encode(0, [new HeaderField("x-a", "1")]); // Insert abs 0, von Stream 0 referenziert
        encoder.Encode(4, [new HeaderField("x-b", "2")]); // Insert abs 1, von Stream 4 referenziert
        Assert.Equal(2ul, encoder.Table.InsertCount);

        // Stream 8 bräuchte einen 3. Eintrag ⇒ müsste abs 0 verdrängen, der aber referenziert ist ⇒ kein Insert.
        encoder.Encode(8, [new HeaderField("x-c", "3")]);
        Assert.Equal(2ul, encoder.Table.InsertCount);

        // Section-Acknowledgment für Stream 0 gibt abs 0 frei.
        encoder.ProcessDecoderInstructions(QpackDynamicDecoder.EncodeSectionAcknowledgment(0));
        Assert.Equal(2ul, encoder.KnownReceivedCount);

        // Jetzt ist abs 0 unreferenziert und kann verdrängt werden ⇒ der 3. Eintrag passt.
        encoder.Encode(12, [new HeaderField("x-d", "4")]);
        Assert.Equal(3ul, encoder.Table.InsertCount);
    }

    [Fact]
    public void InsertCountIncrement_AdvancesKnownReceivedCount()
    {
        var encoder = new QpackDynamicEncoder();
        encoder.SetCapacity(4096);
        encoder.Encode(0, [new HeaderField("x-a", "1"), new HeaderField("x-b", "2")]);
        Assert.Equal(0ul, encoder.KnownReceivedCount);

        encoder.ProcessDecoderInstructions(QpackDynamicDecoder.EncodeInsertCountIncrement(2));
        Assert.Equal(2ul, encoder.KnownReceivedCount);
    }
}
