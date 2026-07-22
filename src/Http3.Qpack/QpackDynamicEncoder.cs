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
/// QPACK-Encoder mit dynamischer Tabelle (RFC 9204). Zustandsbehaftet: hält die dynamische Tabelle und
/// erzeugt beim Kodieren einer Header-Liste sowohl die <b>Encoder-Stream-Instruktionen</b> (Inserts) als
/// auch die <b>Field Section</b>. Die Instruktionen müssen vor der Field Section beim Decoder ankommen.
/// <para>Vereinfachungen: Base = Required Insert Count (alle Referenzen pre-base, kein Post-Base);
/// Insert-Instruktionen nutzen Static-Name-Referenzen oder literale Namen (keine dynamischen Name-Refs,
/// keine Duplicate). Der Decoder beherrscht dennoch die vollständige Kodierung (u. a. RFC-Vektoren).</para>
/// </summary>
public sealed class QpackDynamicEncoder
{
    private enum RepKind { StaticIndexed, DynamicIndexed, LiteralStaticName, LiteralLiteralName }
    private readonly record struct Rep(RepKind Kind, ulong Index, string Name, string Value);

    private readonly QpackDynamicTable _table = new();
    private readonly Dictionary<ulong, List<ulong>> _outstandingSections = []; // Stream-ID → referenzierte absolute Indizes
    private ulong _knownReceivedCount; // vom Decoder bestätigte Insert-Anzahl (RFC 9204 §2.1.4)

    /// <summary>
    /// Die dynamische Tabelle des Encoders (Diagnose/Test).
    /// </summary>
    public QpackDynamicTable Table => _table;

    /// <summary>
    /// Vom Decoder bestätigte Insert-Anzahl (Known Received Count). Diagnose.
    /// </summary>
    public ulong KnownReceivedCount => _knownReceivedCount;

    /// <summary>
    /// Setzt die dynamische Tabellenkapazität und liefert die zugehörige Encoder-Stream-Instruktion.
    /// </summary>
    public byte[] SetCapacity(ulong capacity)
    {
        _table.SetCapacity(capacity);
        var w = new BufferWriter(4);
        try
        {
            // Set Dynamic Table Capacity: 0 0 1 Capacity(5+)
            QpackPrimitives.EncodeInteger(ref w, capacity, 5, 0b0010_0000);
            return w.WrittenSpan.ToArray();
        }
        finally { w.Dispose(); }
    }

    /// <summary>
    /// Kodiert eine Header-Liste ohne Section-Tracking (Stream-ID 0). Für einfache Round-Trips/Tests.
    /// </summary>
    public (byte[] Instructions, byte[] FieldSection) Encode(IReadOnlyList<HeaderField> headers)
        => Encode(0, headers);

    /// <summary>
    /// Kodiert eine Header-Liste für den Stream <paramref name="streamId"/>. Liefert (Encoder-Stream-
    /// Instruktionen, Field Section). Referenzierte dynamische Einträge werden festgehalten (gegen Eviction),
    /// bis eine Section-Acknowledgment für diesen Stream eintrifft.
    /// </summary>
    public (byte[] Instructions, byte[] FieldSection) Encode(ulong streamId, IReadOnlyList<HeaderField> headers)
    {
        ReleaseSection(streamId); // etwaige alte Referenzen dieses Streams freigeben

        var instructions = new BufferWriter(64);
        var reps = new List<Rep>(headers.Count);
        var referenced = new List<ulong>();
        long maxReferencedAbsolute = -1;

        try
        {
            foreach (HeaderField header in headers)
            {
                string name = header.Name.ToLowerInvariant();
                string value = header.Value;

                if (QpackStaticTable.TryGetPairIndex(name, value, out int staticPair))
                {
                    reps.Add(new Rep(RepKind.StaticIndexed, (ulong)staticPair, name, value));
                }
                else if (_table.TryFindExact(name, value, out ulong exactAbs))
                {
                    reps.Add(new Rep(RepKind.DynamicIndexed, exactAbs, name, value));
                    referenced.Add(exactAbs);
                    maxReferencedAbsolute = Math.Max(maxReferencedAbsolute, (long)exactAbs);
                }
                else if (_table.Capacity > 0 && _table.CanInsert(name, value) && _table.Insert(name, value))
                {
                    EmitInsert(ref instructions, name, value);
                    ulong abs = _table.InsertCount - 1;
                    reps.Add(new Rep(RepKind.DynamicIndexed, abs, name, value));
                    referenced.Add(abs);
                    maxReferencedAbsolute = Math.Max(maxReferencedAbsolute, (long)abs);
                }
                else if (QpackStaticTable.TryGetNameIndex(name, out int staticName))
                {
                    reps.Add(new Rep(RepKind.LiteralStaticName, (ulong)staticName, name, value));
                }
                else
                {
                    reps.Add(new Rep(RepKind.LiteralLiteralName, 0, name, value));
                }
            }

            ulong requiredInsertCount = maxReferencedAbsolute >= 0 ? (ulong)maxReferencedAbsolute + 1 : 0;
            ulong baseValue = requiredInsertCount; // Base = RIC ⇒ alle dynamischen Referenzen sind pre-base

            // Referenzierte Einträge festhalten, bis die Section-Acknowledgment für diesen Stream eintrifft.
            if (referenced.Count > 0)
            {
                foreach (ulong abs in referenced)
                    _table.AddReference(abs);
                _outstandingSections[streamId] = referenced;
            }

            var section = new BufferWriter(128);
            try
            {
                WritePrefix(ref section, requiredInsertCount);
                foreach (Rep rep in reps)
                    WriteRepresentation(ref section, rep, baseValue);
                return (instructions.WrittenSpan.ToArray(), section.WrittenSpan.ToArray());
            }
            finally { section.Dispose(); }
        }
        finally { instructions.Dispose(); }
    }

    /// <summary>
    /// Verarbeitet die Decoder-Stream-Instruktionen des Peers (RFC 9204 §4.4) und gibt die Anzahl verbrauchter
    /// Bytes zurück (eine angeschnittene Instruktion am Ende bleibt liegen).
    /// </summary>
    public int ProcessDecoderInstructions(ReadOnlySpan<byte> data)
    {
        var reader = new BufferReader(data);
        int consumed = 0;
        while (!reader.IsEmpty)
        {
            if (!reader.TryReadByte(out byte first))
                break;

            bool ok;
            if ((first & 0x80) != 0) // Section Acknowledgment: 1 StreamID(7+)
            {
                ok = QpackPrimitives.TryDecodeInteger(ref reader, first, 7, out ulong streamId);
                if (ok)
                {
                    ReleaseSection(streamId);
                    _knownReceivedCount = _table.InsertCount; // bestätigte Section ⇒ alle bisherigen Inserts empfangen
                }
            }
            else if ((first & 0x40) != 0) // Stream Cancellation: 0 1 StreamID(6+)
            {
                ok = QpackPrimitives.TryDecodeInteger(ref reader, first, 6, out ulong streamId);
                if (ok)
                    ReleaseSection(streamId);
            }
            else // Insert Count Increment: 0 0 Increment(6+)
            {
                ok = QpackPrimitives.TryDecodeInteger(ref reader, first, 6, out ulong increment);
                if (ok)
                    _knownReceivedCount += increment;
            }

            if (!ok)
                break; // angeschnitten – auf mehr Daten warten
            consumed = reader.Position;
        }
        return consumed;
    }

    private void ReleaseSection(ulong streamId)
    {
        if (!_outstandingSections.Remove(streamId, out List<ulong>? refs))
            return;
        foreach (ulong abs in refs)
            _table.RemoveReference(abs);
    }

    private void EmitInsert(ref BufferWriter w, string name, string value)
    {
        if (QpackStaticTable.TryGetNameIndex(name, out int staticName))
        {
            // Insert with Name Reference: 1 T=1 NameIndex(6+) + Value
            QpackPrimitives.EncodeInteger(ref w, (ulong)staticName, 6, 0b1100_0000);
            QpackPrimitives.EncodeString(ref w, value, 7, 0x00);
        }
        else
        {
            // Insert with Literal Name: 0 1 H NameLen(5+) + Name + Value
            QpackPrimitives.EncodeString(ref w, name, 5, 0b0100_0000);
            QpackPrimitives.EncodeString(ref w, value, 7, 0x00);
        }
    }

    private void WritePrefix(ref BufferWriter w, ulong requiredInsertCount)
    {
        ulong encodedInsertCount = 0;
        if (requiredInsertCount != 0)
        {
            ulong fullRange = 2 * _table.MaxEntries; // MaxEntries ≥ 1, wenn es dynamische Einträge gibt
            encodedInsertCount = requiredInsertCount % fullRange + 1;
        }
        QpackPrimitives.EncodeInteger(ref w, encodedInsertCount, 8, 0x00);
        // Base = RIC ⇒ Sign = 0, Delta Base = 0.
        QpackPrimitives.EncodeInteger(ref w, 0, 7, 0x00);
    }

    private void WriteRepresentation(ref BufferWriter w, Rep rep, ulong baseValue)
    {
        switch (rep.Kind)
        {
            case RepKind.StaticIndexed: // 1 T=1 Index(6+)
                QpackPrimitives.EncodeInteger(ref w, rep.Index, 6, 0b1100_0000);
                break;

            case RepKind.DynamicIndexed: // 1 T=0 RelIndex(6+), RelIndex = Base - 1 - Abs
                QpackPrimitives.EncodeInteger(ref w, baseValue - 1 - rep.Index, 6, 0b1000_0000);
                break;

            case RepKind.LiteralStaticName: // 0 1 N=0 T=1 NameIndex(4+) + Value
                QpackPrimitives.EncodeInteger(ref w, rep.Index, 4, 0b0101_0000);
                QpackPrimitives.EncodeString(ref w, rep.Value, 7, 0x00);
                break;

            default: // LiteralLiteralName: 0 0 1 N=0 H NameLen(3+) + Name + Value
                QpackPrimitives.EncodeString(ref w, rep.Name, 3, 0b0010_0000);
                QpackPrimitives.EncodeString(ref w, rep.Value, 7, 0x00);
                break;
        }
    }
}
