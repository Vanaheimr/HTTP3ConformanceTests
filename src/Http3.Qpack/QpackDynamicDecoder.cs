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

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;

/// <summary>
/// QPACK-Decoder mit dynamischer Tabelle (RFC 9204). Zustandsbehaftet: verarbeitet die Encoder-Stream-
/// Instruktionen (Set Capacity, Insert With Name Reference, Insert With Literal Name, Duplicate) in seine
/// dynamische Tabelle und dekodiert anschließend Field Sections, die statische wie dynamische Einträge
/// referenzieren (inkl. Post-Base-Indizierung). Reihenfolge: erst die Encoder-Instruktionen, dann die
/// Field Section; verlangt Letztere mehr Inserts als vorhanden, ist der Stream <see cref="QpackResult.Blocked"/>.
/// </summary>
public sealed class QpackDynamicDecoder
{
    private readonly QpackDynamicTable _table = new();

    /// <summary>
    /// Die dynamische Tabelle des Decoders (Diagnose/Test).
    /// </summary>
    public QpackDynamicTable Table => _table;

    /// <summary>
    /// Kodiert eine Section-Acknowledgment (RFC 9204 §4.4.1): <c>1 StreamID(7+)</c>.
    /// </summary>
    public static byte[] EncodeSectionAcknowledgment(ulong streamId)
    {
        var w = new BufferWriter(4);
        try { QpackPrimitives.EncodeInteger(ref w, streamId, 7, 0b1000_0000); return w.WrittenSpan.ToArray(); }
        finally { w.Dispose(); }
    }

    /// <summary>
    /// Kodiert ein Insert Count Increment (RFC 9204 §4.4.3): <c>0 0 Increment(6+)</c>.
    /// </summary>
    public static byte[] EncodeInsertCountIncrement(ulong increment)
    {
        var w = new BufferWriter(4);
        try { QpackPrimitives.EncodeInteger(ref w, increment, 6, 0b0000_0000); return w.WrittenSpan.ToArray(); }
        finally { w.Dispose(); }
    }

    /// <summary>
    /// Verarbeitet einen Abschnitt des QPACK-Encoder-Streams in die dynamische Tabelle und gibt zurück, ob
    /// alle Bytes vollständige Instruktionen bildeten (<see cref="QpackResult.Ok"/>).
    /// </summary>
    public QpackResult ProcessEncoderInstructions(ReadOnlySpan<byte> data)
        => ProcessEncoderInstructions(data, out int consumed) && consumed == data.Length
            ? QpackResult.Ok
            : QpackResult.DecompressionFailed;

    /// <summary>
    /// Streamende Variante: verarbeitet so viele <b>vollständige</b> Instruktionen wie möglich und setzt
    /// <paramref name="consumed"/> auf die Anzahl verbrauchter Bytes (eine angeschnittene Instruktion am Ende
    /// bleibt liegen). Rückgabe <c>false</c> nur bei einer strukturell ungültigen Instruktion.
    /// </summary>
    public bool ProcessEncoderInstructions(ReadOnlySpan<byte> data, out int consumed)
    {
        consumed = 0;
        var reader = new BufferReader(data);
        while (!reader.IsEmpty)
        {
            if (!TryProcessOneInstruction(ref reader, out bool incomplete))
            {
                // Angeschnittene Instruktion am Puffer-Ende: auf mehr Daten warten (kein Fehler).
                return incomplete;
            }
            consumed = reader.Position;
        }
        return true;
    }

    private bool TryProcessOneInstruction(ref BufferReader reader, out bool incomplete)
    {
        incomplete = true;
        if (!reader.TryReadByte(out byte first))
            return false;

        if ((first & 0x80) != 0) // Insert with Name Reference: 1 T NameIndex(6+) + Value
        {
            bool isStatic = (first & 0x40) != 0;
            if (!QpackPrimitives.TryDecodeInteger(ref reader, first, 6, out ulong nameIndex) ||
                !TryReadString(ref reader, 7, out string value))
                return false;
            if (!TryResolveName(isStatic, nameIndex, out string name) || !_table.Insert(name, value))
            { incomplete = false; return false; } // struktureller Fehler
        }
        else if ((first & 0x40) != 0) // Insert with Literal Name: 0 1 H NameLen(5+) + Name + Value
        {
            if (!QpackPrimitives.TryDecodeString(ref reader, first, 5, out string name) ||
                !TryReadString(ref reader, 7, out string value))
                return false;
            if (!_table.Insert(name, value))
            { incomplete = false; return false; }
        }
        else if ((first & 0x20) != 0) // Set Dynamic Table Capacity: 0 0 1 Capacity(5+)
        {
            if (!QpackPrimitives.TryDecodeInteger(ref reader, first, 5, out ulong capacity))
                return false;
            _table.SetCapacity(capacity);
        }
        else // Duplicate: 0 0 0 Index(5+)
        {
            if (!QpackPrimitives.TryDecodeInteger(ref reader, first, 5, out ulong relIndex))
                return false;
            if (!TryRelativeToAbsolute(relIndex, out ulong abs) ||
                !_table.TryGetByAbsolute(abs, out (string Name, string Value) entry) ||
                !_table.Insert(entry.Name, entry.Value))
            { incomplete = false; return false; }
        }

        incomplete = false;
        return true;
    }

    /// <summary>
    /// Dekodiert eine Field Section (mit Prefix). Encoder-Instruktionen müssen zuvor verarbeitet sein.
    /// </summary>
    public QpackResult Decode(ReadOnlySpan<byte> encoded, out List<HeaderField> headers)
        => Decode(encoded, out headers, out _);

    /// <summary>
    /// Wie <see cref="Decode(ReadOnlySpan{byte}, out List{HeaderField})"/>, meldet zusätzlich den Required
    /// Insert Count der Sektion – ist er &gt; 0, sollte der Aufrufer eine Section-Acknowledgment senden.
    /// </summary>
    public QpackResult Decode(ReadOnlySpan<byte> encoded, out List<HeaderField> headers, out ulong requiredInsertCount)
    {
        headers = [];
        requiredInsertCount = 0;
        var reader = new BufferReader(encoded);

        // Field Section Prefix: Required Insert Count (8+) und Sign+Delta Base (7+).
        if (!reader.TryReadByte(out byte ricByte) ||
            !QpackPrimitives.TryDecodeInteger(ref reader, ricByte, 8, out ulong encodedInsertCount) ||
            !TryReconstructRequiredInsertCount(encodedInsertCount, out requiredInsertCount) ||
            !reader.TryReadByte(out byte baseByte) ||
            !QpackPrimitives.TryDecodeInteger(ref reader, baseByte, 7, out ulong deltaBase))
            return QpackResult.DecompressionFailed;

        bool sign = (baseByte & 0x80) != 0;
        ulong baseValue;
        if (sign)
        {
            if (requiredInsertCount < deltaBase + 1)
                return QpackResult.DecompressionFailed;
            baseValue = requiredInsertCount - deltaBase - 1;
        }
        else
        {
            baseValue = requiredInsertCount + deltaBase;
        }

        if (requiredInsertCount > _table.InsertCount)
            return QpackResult.Blocked; // die referenzierten Einträge sind noch nicht eingetroffen

        while (!reader.IsEmpty)
        {
            if (!reader.TryReadByte(out byte first))
                return QpackResult.DecompressionFailed;

            QpackResult result;
            if ((first & 0x80) != 0)          // Indexed Field Line: 1 T Index(6+)
                result = DecodeIndexed(ref reader, first, baseValue, headers);
            else if ((first & 0x40) != 0)     // Literal With Name Reference: 0 1 N T NameIndex(4+)
                result = DecodeLiteralNameRef(ref reader, first, baseValue, headers);
            else if ((first & 0x20) != 0)     // Literal With Literal Name: 0 0 1 N H NameLen(3+)
                result = DecodeLiteralLiteralName(ref reader, first, headers);
            else if ((first & 0x10) != 0)     // Indexed With Post-Base Index: 0 0 0 1 Index(4+)
                result = DecodePostBaseIndexed(ref reader, first, baseValue, headers);
            else                              // Literal With Post-Base Name Reference: 0 0 0 0 N NameIndex(3+)
                result = DecodePostBaseNameRef(ref reader, first, baseValue, headers);

            if (result != QpackResult.Ok)
                return result;
        }
        return QpackResult.Ok;
    }

    // ---- Field-Line-Repräsentationen -------------------------------------------------------

    private QpackResult DecodeIndexed(ref BufferReader reader, byte first, ulong baseValue, List<HeaderField> headers)
    {
        bool isStatic = (first & 0x40) != 0;
        if (!QpackPrimitives.TryDecodeInteger(ref reader, first, 6, out ulong index))
            return QpackResult.DecompressionFailed;

        if (isStatic)
        {
            if (index >= (ulong)QpackStaticTable.Count)
                return QpackResult.DecompressionFailed;
            (string sn, string sv) = QpackStaticTable.Get((int)index);
            headers.Add(new HeaderField(sn, sv));
            return QpackResult.Ok;
        }

        // Dynamisch (pre-base): Abs = Base - 1 - RelIndex.
        if (baseValue < 1 + index || !_table.TryGetByAbsolute(baseValue - 1 - index, out (string Name, string Value) e))
            return QpackResult.DecompressionFailed;
        headers.Add(new HeaderField(e.Name, e.Value));
        return QpackResult.Ok;
    }

    private QpackResult DecodePostBaseIndexed(ref BufferReader reader, byte first, ulong baseValue, List<HeaderField> headers)
    {
        if (!QpackPrimitives.TryDecodeInteger(ref reader, first, 4, out ulong index) ||
            !_table.TryGetByAbsolute(baseValue + index, out (string Name, string Value) e))
            return QpackResult.DecompressionFailed;
        headers.Add(new HeaderField(e.Name, e.Value));
        return QpackResult.Ok;
    }

    private QpackResult DecodeLiteralNameRef(ref BufferReader reader, byte first, ulong baseValue, List<HeaderField> headers)
    {
        bool isStatic = (first & 0x10) != 0;
        if (!QpackPrimitives.TryDecodeInteger(ref reader, first, 4, out ulong index))
            return QpackResult.DecompressionFailed;

        string name;
        if (isStatic)
        {
            if (index >= (ulong)QpackStaticTable.Count)
                return QpackResult.DecompressionFailed;
            name = QpackStaticTable.Get((int)index).Name;
        }
        else if (baseValue >= 1 + index && _table.TryGetByAbsolute(baseValue - 1 - index, out (string Name, string Value) e))
        {
            name = e.Name;
        }
        else
        {
            return QpackResult.DecompressionFailed;
        }

        if (!TryReadString(ref reader, 7, out string value))
            return QpackResult.DecompressionFailed;
        headers.Add(new HeaderField(name, value));
        return QpackResult.Ok;
    }

    private QpackResult DecodePostBaseNameRef(ref BufferReader reader, byte first, ulong baseValue, List<HeaderField> headers)
    {
        if (!QpackPrimitives.TryDecodeInteger(ref reader, first, 3, out ulong index) ||
            !_table.TryGetByAbsolute(baseValue + index, out (string Name, string Value) e) ||
            !TryReadString(ref reader, 7, out string value))
            return QpackResult.DecompressionFailed;
        headers.Add(new HeaderField(e.Name, value));
        return QpackResult.Ok;
    }

    private static QpackResult DecodeLiteralLiteralName(ref BufferReader reader, byte first, List<HeaderField> headers)
    {
        if (!QpackPrimitives.TryDecodeString(ref reader, first, 3, out string name) ||
            !TryReadString(ref reader, 7, out string value))
            return QpackResult.DecompressionFailed;
        headers.Add(new HeaderField(name, value));
        return QpackResult.Ok;
    }

    // ---- Hilfen ----------------------------------------------------------------------------

    private bool TryResolveName(bool isStatic, ulong nameIndex, out string name)
    {
        name = string.Empty;
        if (isStatic)
        {
            if (nameIndex >= (ulong)QpackStaticTable.Count)
                return false;
            name = QpackStaticTable.Get((int)nameIndex).Name;
            return true;
        }
        if (!TryRelativeToAbsolute(nameIndex, out ulong abs) || !_table.TryGetByAbsolute(abs, out (string Name, string Value) e))
            return false;
        name = e.Name;
        return true;
    }

    // Encoder-Stream: relativer Index bezieht sich auf den zuletzt eingefügten Eintrag.
    private bool TryRelativeToAbsolute(ulong relativeIndex, out ulong absolute)
    {
        absolute = 0;
        if (_table.InsertCount < 1 + relativeIndex)
            return false;
        absolute = _table.InsertCount - 1 - relativeIndex;
        return true;
    }

    // Required Insert Count aus dem kodierten Wert rekonstruieren (RFC 9204 §4.5.1).
    private bool TryReconstructRequiredInsertCount(ulong encoded, out ulong requiredInsertCount)
    {
        requiredInsertCount = 0;
        if (encoded == 0)
            return true;

        ulong maxEntries = _table.MaxEntries;
        ulong fullRange = 2 * maxEntries;
        if (fullRange == 0 || encoded > fullRange)
            return false;

        ulong maxValue = _table.InsertCount + maxEntries;
        ulong maxWrapped = maxValue / fullRange * fullRange;
        requiredInsertCount = maxWrapped + encoded - 1;
        if (requiredInsertCount > maxValue)
        {
            if (requiredInsertCount <= fullRange)
                return false;
            requiredInsertCount -= fullRange;
        }
        return requiredInsertCount != 0;
    }

    private static bool TryReadString(ref BufferReader reader, int prefixBits, out string value)
    {
        value = string.Empty;
        return reader.TryReadByte(out byte first) && QpackPrimitives.TryDecodeString(ref reader, first, prefixBits, out value);
    }
}
