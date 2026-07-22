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

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;

/// <summary>
/// Die dynamische QPACK-Tabelle (RFC 9204 §3.2): eine FIFO von Header-Einträgen mit Byte-Kapazität.
/// Einträge werden hinten eingefügt und vorne verdrängt (Eviction), wenn sonst die Kapazität überschritten
/// würde. Jeder Eintrag erhält einen fortlaufenden <b>absoluten Index</b> (ab 0); verdrängte Indizes sind
/// ungültig. Encoder und Decoder halten je eine solche Tabelle und synchronisieren sie über den QPACK-
/// Encoder-Stream.
/// </summary>
public sealed class QpackDynamicTable
{
    private readonly List<(string Name, string Value)> _entries = [];
    private readonly List<int> _refCounts = []; // je Eintrag: offene Referenzen aus noch nicht bestätigten Field Sections (Encoder-Seite)

    /// <summary>
    /// Aktuell gesetzte Kapazität in Bytes (via Set Dynamic Table Capacity bzw. SETTINGS begrenzt).
    /// </summary>
    public ulong Capacity { get; private set; }

    /// <summary>
    /// Aktuelle Größe aller gehaltenen Einträge in Bytes.
    /// </summary>
    public ulong Size { get; private set; }

    /// <summary>
    /// Gesamtzahl je eingefügter Einträge – der nächste Eintrag erhielte diesen absoluten Index.
    /// </summary>
    public ulong InsertCount { get; private set; }

    /// <summary>
    /// Anzahl aktuell gehaltener Einträge.
    /// </summary>
    public int Count => _entries.Count;

    /// <summary>
    /// Maximale theoretische Eintragszahl (RFC 9204 §3.2.2): <c>floor(Kapazität / 32)</c>.
    /// </summary>
    public ulong MaxEntries => Capacity / 32;

    private ulong OldestAbsolute => InsertCount - (ulong)_entries.Count;

    /// <summary>
    /// Eintragsgröße (RFC 9204 §3.2.1): Länge Name + Länge Wert + 32.
    /// </summary>
    public static ulong EntrySize(string name, string value) => (ulong)(name.Length + value.Length + 32);

    /// <summary>
    /// Setzt die Kapazität und verdrängt ggf. Einträge (RFC 9204 §3.2.3).
    /// </summary>
    public void SetCapacity(ulong capacity)
    {
        Capacity = capacity;
        EvictToFit(0);
    }

    /// <summary>
    /// Fügt einen Eintrag ein; verdrängt bei Bedarf die ältesten <b>unreferenzierten</b> Einträge.
    /// <c>false</c>, wenn er selbst die Kapazität übersteigt oder nur durch Verdrängen eines noch
    /// referenzierten Eintrags Platz entstünde (Eviction-Schutz, RFC 9204 §2.1.1).
    /// </summary>
    public bool Insert(string name, string value)
    {
        ulong size = EntrySize(name, value);
        if (size > Capacity || !EvictToFit(size))
            return false;
        _entries.Add((name, value));
        _refCounts.Add(0);
        Size += size;
        InsertCount++;
        return true;
    }

    /// <summary>
    /// Verdrängt die ältesten unreferenzierten Einträge; <c>false</c>, wenn der nötige Platz blockiert ist.
    /// </summary>
    private bool EvictToFit(ulong incoming)
    {
        while (Size + incoming > Capacity)
        {
            if (_entries.Count == 0)
                return incoming <= Capacity; // leer: passt genau dann, wenn incoming ≤ Kapazität
            if (_refCounts[0] > 0)
                return false;                // ältester Eintrag ist referenziert ⇒ nicht verdrängbar
            (string n, string v) = _entries[0];
            _entries.RemoveAt(0);
            _refCounts.RemoveAt(0);
            Size -= EntrySize(n, v);
        }
        return true;
    }

    /// <summary>
    /// Vermerkt eine Referenz auf einen Eintrag (Encoder: schützt ihn bis zur Section-Acknowledgment).
    /// </summary>
    public void AddReference(ulong absoluteIndex)
    {
        if (absoluteIndex < OldestAbsolute || absoluteIndex >= InsertCount)
            return;
        _refCounts[(int)(absoluteIndex - OldestAbsolute)]++;
    }

    /// <summary>
    /// Gibt eine Referenz frei (Encoder: nach Section-Acknowledgment/Stream-Cancellation).
    /// </summary>
    public void RemoveReference(ulong absoluteIndex)
    {
        if (absoluteIndex < OldestAbsolute || absoluteIndex >= InsertCount)
            return;
        int i = (int)(absoluteIndex - OldestAbsolute);
        if (_refCounts[i] > 0)
            _refCounts[i]--;
    }

    /// <summary>
    /// Liefert den Eintrag mit dem absoluten Index, falls er (noch) vorhanden ist.
    /// </summary>
    public bool TryGetByAbsolute(ulong absoluteIndex, out (string Name, string Value) entry)
    {
        entry = default;
        if (absoluteIndex < OldestAbsolute || absoluteIndex >= InsertCount)
            return false;
        entry = _entries[(int)(absoluteIndex - OldestAbsolute)];
        return true;
    }

    /// <summary>
    /// Höchster absoluter Index eines exakten (Name, Wert)-Paares, falls vorhanden.
    /// </summary>
    public bool TryFindExact(string name, string value, out ulong absoluteIndex)
    {
        for (int i = _entries.Count - 1; i >= 0; i--)
            if (_entries[i].Name == name && _entries[i].Value == value)
            {
                absoluteIndex = OldestAbsolute + (ulong)i;
                return true;
            }
        absoluteIndex = 0;
        return false;
    }

    /// <summary>
    /// Höchster absoluter Index eines Eintrags mit passendem Namen (beliebiger Wert), falls vorhanden.
    /// </summary>
    public bool TryFindName(string name, out ulong absoluteIndex)
    {
        for (int i = _entries.Count - 1; i >= 0; i--)
            if (_entries[i].Name == name)
            {
                absoluteIndex = OldestAbsolute + (ulong)i;
                return true;
            }
        absoluteIndex = 0;
        return false;
    }

    /// <summary>
    /// Ob ein Eintrag dieser Größe noch eingefügt werden könnte (ggf. nach Eviction bis zum ältesten unbenutzten).
    /// </summary>
    public bool CanInsert(string name, string value) => EntrySize(name, value) <= Capacity;
}
