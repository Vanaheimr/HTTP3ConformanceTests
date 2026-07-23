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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

/// <summary>
/// Ein GSO-Batch (Generic Segmentation Offload): ein zusammenhängender Puffer aus mehreren gleich
/// großen UDP-Nutzlasten, den der Kernel per <c>UDP_SEGMENT</c> in einem einzigen Sendeaufruf in
/// <see cref="SegmentCount"/> Datagramme der Größe <see cref="SegmentSize"/> zerlegt (das letzte
/// Segment darf kleiner sein). <see cref="Buffer"/>/<see cref="Length"/> sind ein Slice eines
/// gepoolten Arbeitspuffers — nur bis zum nächsten Batch gültig.
/// </summary>
public readonly struct GsoBatch(byte[] buffer, int length, int segmentSize, int segmentCount)
{
    public byte[] Buffer { get; } = buffer;
    public int Length { get; } = length;
    public int SegmentSize { get; } = segmentSize;
    public int SegmentCount { get; } = segmentCount;
}

/// <summary>
/// Gruppiert ausgehende Datagramme in GSO-Batches (UDP-Batching der Phase 9). QUIC sendet in einem
/// Bulk-Transfer je 1-RTT-Paket ein eigenes ~MTU-Datagramm; GSO fasst mehrere davon zu EINEM
/// <c>sendmsg</c> zusammen. Voraussetzung des Kernels: alle Segmente eines Sends sind gleich groß —
/// nur das LETZTE darf kleiner sein. Dieser Batcher bildet genau solche Läufe (maximaler Präfix
/// gleicher Größe, optional plus ein kleineres Schluss-Segment), gedeckelt auf <see cref="MaxSegments"/>
/// Segmente und <see cref="MaxBatchBytes"/> Bytes. Die eigentliche Kernel-Anbindung ist plattform-
/// spezifisch; diese Zerlegung ist rein und damit deterministisch testbar.
/// </summary>
public sealed class GsoBatcher
{
    /// <summary>
    /// Maximale Segmentzahl je GSO-Send (Linux erlaubt bis zu 64 mit UDP_SEGMENT).
    /// </summary>
    public const int MaxSegments = 64;

    /// <summary>
    /// Obergrenze der Gesamtgröße eines Batches (ein UDP-Payload fasst höchstens 65535 Bytes).
    /// </summary>
    public const int MaxBatchBytes = 65535;

    private byte[] _work = new byte[MaxSegments * 1500];

    /// <summary>
    /// Zerlegt <paramref name="datagrams"/> in aufeinanderfolgende GSO-Batches. Jeder Batch wird per
    /// <paramref name="onBatch"/> zurückgegeben, BEVOR der nächste gebildet wird (der Arbeitspuffer
    /// wird wiederverwendet) — der Callback muss den Batch also sofort versenden/kopieren. Ein Batch
    /// mit <see cref="GsoBatch.SegmentCount"/> == 1 ist ein gewöhnliches Einzeldatagramm.
    /// </summary>
    public void Batch(IReadOnlyList<byte[]> datagrams, Action<GsoBatch> onBatch)
    {
        int i = 0;
        int n = datagrams.Count;
        while (i < n)
        {
            int segmentSize = datagrams[i].Length;
            int count = 0;
            int bytes = 0;

            // Maximaler Lauf gleich großer Datagramme (das letzte darf kleiner sein).
            while (i + count < n && count < MaxSegments)
            {
                int len = datagrams[i + count].Length;
                if (len > segmentSize)
                    break; // größeres Datagramm ⇒ neuer Batch
                if (bytes + len > MaxBatchBytes)
                    break;
                bytes += len;
                count++;
                if (len < segmentSize)
                    break; // kleineres Datagramm MUSS das letzte Segment sein (UDP_SEGMENT-Regel)
            }

            EnsureWork(bytes);
            int offset = 0;
            for (int k = 0; k < count; k++)
            {
                byte[] dg = datagrams[i + k];
                dg.CopyTo(_work.AsSpan(offset));
                offset += dg.Length;
            }
            onBatch(new GsoBatch(_work, bytes, segmentSize, count));
            i += count;
        }
    }

    private void EnsureWork(int needed)
    {
        if (_work.Length < needed)
            _work = new byte[Math.Max(needed, _work.Length * 2)];
    }
}
