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
[TestFixture]
public class QpackDynamicTableTests
{
    [Test]
    public void Rfc9204_AppendixB2_DecodesDynamicFieldSection()
    {
        var decoder = new QpackDynamicDecoder();

        // Encoder-Stream: Set Capacity 220, Insert :authority www.example.com, Insert :path /sample/path.
        byte[] encoderStream = Convert.FromHexString(
            "3fbd01" +
            "c00f" + "7777772e6578616d706c652e636f6d" +
            "c10c" + "2f73616d706c652f70617468");
        Assert.That(decoder.ProcessEncoderInstructions(encoderStream), Is.EqualTo(QpackResult.Ok));
        Assert.That(decoder.Table.InsertCount, Is.EqualTo(2ul));
        Assert.That(decoder.Table.Size, Is.EqualTo(106ul)); // RFC: Size 106 bytes

        // Field Section (Stream 4): RIC=2, Base=0, zwei Post-Base-Indizes.
        byte[] fieldSection = Convert.FromHexString("03811011");
        Assert.That(decoder.Decode(fieldSection, out List<HeaderField> headers), Is.EqualTo(QpackResult.Ok));

        Assert.That(headers.Count, Is.EqualTo(2));
        Assert.That(headers[0].Name, Is.EqualTo(":authority"));
        Assert.That(headers[0].Value, Is.EqualTo("www.example.com"));
        Assert.That(headers[1].Name, Is.EqualTo(":path"));
        Assert.That(headers[1].Value, Is.EqualTo("/sample/path"));
    }

    [Test]
    public void EncoderStream_Duplicate_AddsCopyOfOlderEntry()
    {
        var decoder = new QpackDynamicDecoder();
        decoder.ProcessEncoderInstructions(Convert.FromHexString(
            "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468"));

        // Duplicate mit relativem Index 1 ⇒ absoluter Index InsertCount(2)-1-1 = 0 (:authority).
        Assert.That(decoder.ProcessEncoderInstructions([0x01]), Is.EqualTo(QpackResult.Ok));
        Assert.That(decoder.Table.InsertCount, Is.EqualTo(3ul));
        Assert.That(decoder.Table.TryGetByAbsolute(2, out (string Name, string Value) copy), Is.True);
        Assert.That(copy.Name, Is.EqualTo(":authority"));
        Assert.That(copy.Value, Is.EqualTo("www.example.com"));
    }

    [Test]
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
        Assert.That(decoder.ProcessEncoderInstructions(instructions), Is.EqualTo(QpackResult.Ok));
        Assert.That(decoder.Decode(section, out List<HeaderField> decoded), Is.EqualTo(QpackResult.Ok));

        Assert.That(decoded.Count, Is.EqualTo(headers.Count));
        for (int i = 0; i < headers.Count; i++)
        {
            Assert.That(decoded[i].Name, Is.EqualTo(headers[i].Name));
            Assert.That(decoded[i].Value, Is.EqualTo(headers[i].Value));
        }
        Assert.That(encoder.Table.InsertCount > 0, Is.True, "Nicht-statische Header müssen die dynamische Tabelle nutzen.");
        Assert.That(decoder.Table.InsertCount, Is.EqualTo(encoder.Table.InsertCount));
    }

    [Test]
    public void RepeatedHeader_ReferencesDynamicEntry_WithoutReinserting()
    {
        var encoder = new QpackDynamicEncoder();
        var decoder = new QpackDynamicDecoder();
        decoder.ProcessEncoderInstructions(encoder.SetCapacity(4096));

        var headers = new List<HeaderField> { new(":authority", "example.org") };

        (byte[] i1, byte[] s1) = encoder.Encode(headers); // fügt ein
        decoder.ProcessEncoderInstructions(i1);
        Assert.That(decoder.Decode(s1, out _), Is.EqualTo(QpackResult.Ok));
        ulong afterFirst = encoder.Table.InsertCount;
        Assert.That(afterFirst, Is.EqualTo(1ul));

        (byte[] i2, byte[] s2) = encoder.Encode(headers); // referenziert die vorhandene Zeile
        Assert.That(i2, Is.Empty);                                  // keine neue Insert-Instruktion
        Assert.That(encoder.Table.InsertCount, Is.EqualTo(afterFirst)); // kein neuer Eintrag

        Assert.That(decoder.ProcessEncoderInstructions(i2), Is.EqualTo(QpackResult.Ok));
        Assert.That(decoder.Decode(s2, out List<HeaderField> decoded), Is.EqualTo(QpackResult.Ok));
        Expect.Single(decoded);
        Assert.That(decoded[0].Name, Is.EqualTo(":authority"));
        Assert.That(decoded[0].Value, Is.EqualTo("example.org"));
    }

    [Test]
    public void DynamicTable_EvictsOldest_WhenOverCapacity()
    {
        var table = new QpackDynamicTable();
        table.SetCapacity(60); // eine Zeile (34 B) passt, zwei (68 B) nicht

        Assert.That(table.Insert("a", "1"), Is.True); // Größe 1+1+32 = 34
        Assert.That(table.Insert("b", "2"), Is.True); // verdrängt "a"

        Assert.That(table.InsertCount, Is.EqualTo(2ul));
        Assert.That(table.Size, Is.EqualTo(34ul));
        Assert.That(table.TryGetByAbsolute(0, out _), Is.False, "Der älteste Eintrag muss verdrängt sein.");
        Assert.That(table.TryGetByAbsolute(1, out (string Name, string Value) e), Is.True);
        Assert.That(e.Name, Is.EqualTo("b"));
    }

    [Test]
    public void DynamicTable_EntryLargerThanCapacity_IsNotInserted()
    {
        var table = new QpackDynamicTable();
        table.SetCapacity(40); // < 34 + Nutzlast? "aa"+"bbbbbbbbbb" = 2+10+32 = 44 > 40
        Assert.That(table.Insert("aa", "bbbbbbbbbb"), Is.False);
        Assert.That(table.InsertCount, Is.EqualTo(0ul));
    }

    [Test]
    public void SectionAcknowledgment_ReleasesReferences_ReenablingEviction()
    {
        var encoder = new QpackDynamicEncoder();
        encoder.SetCapacity(80); // fasst genau zwei Einträge à 36 B (Name 3 + Wert 1 + 32)

        encoder.Encode(0, [new HeaderField("x-a", "1")]); // Insert abs 0, von Stream 0 referenziert
        encoder.Encode(4, [new HeaderField("x-b", "2")]); // Insert abs 1, von Stream 4 referenziert
        Assert.That(encoder.Table.InsertCount, Is.EqualTo(2ul));

        // Stream 8 bräuchte einen 3. Eintrag ⇒ müsste abs 0 verdrängen, der aber referenziert ist ⇒ kein Insert.
        encoder.Encode(8, [new HeaderField("x-c", "3")]);
        Assert.That(encoder.Table.InsertCount, Is.EqualTo(2ul));

        // Section-Acknowledgment für Stream 0 gibt abs 0 frei.
        encoder.ProcessDecoderInstructions(QpackDynamicDecoder.EncodeSectionAcknowledgment(0));
        Assert.That(encoder.KnownReceivedCount, Is.EqualTo(2ul));

        // Jetzt ist abs 0 unreferenziert und kann verdrängt werden ⇒ der 3. Eintrag passt.
        encoder.Encode(12, [new HeaderField("x-d", "4")]);
        Assert.That(encoder.Table.InsertCount, Is.EqualTo(3ul));
    }

    [Test]
    public void InsertCountIncrement_AdvancesKnownReceivedCount()
    {
        var encoder = new QpackDynamicEncoder();
        encoder.SetCapacity(4096);
        encoder.Encode(0, [new HeaderField("x-a", "1"), new HeaderField("x-b", "2")]);
        Assert.That(encoder.KnownReceivedCount, Is.EqualTo(0ul));

        encoder.ProcessDecoderInstructions(QpackDynamicDecoder.EncodeInsertCountIncrement(2));
        Assert.That(encoder.KnownReceivedCount, Is.EqualTo(2ul));
    }
}
