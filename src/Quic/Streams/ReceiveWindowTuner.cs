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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;

/// <summary>
/// Auto-Tuning des empfangsseitigen Flow-Control-Fensters (Phase 9). Ein festes Fenster drosselt eine
/// schnelle Verbindung mit hoher RTT auf ≈ Fenster/RTT Durchsatz — das Bandbreiten-Verzögerungs-Produkt
/// (BDP) wächst mit der RTT. Heuristik (wie Chromium/quiche): jedes Mal, wenn der Empfänger ein
/// Fenster-Update senden muss (der Kredit ist unter das halbe Fenster gefallen), wird die Zeit seit dem
/// LETZTEN Update gemessen. Ist sie kürzer als ein kleines Vielfaches der RTT, war der Sender schneller
/// am Fensterrand als eine RTT — das Fenster ist der Engpass ⇒ verdoppeln (bis zu einem Limit). So
/// pendelt sich das Fenster selbsttätig auf das BDP der Verbindung ein, ohne von Beginn an groß zu sein.
/// </summary>
public sealed class ReceiveWindowTuner(ulong initialSize, ulong limit)
{
    /// <summary>
    /// Vielfaches der geglätteten RTT: Löst der Sender das Update schneller als so viele RTTs aus,
    /// gilt das Fenster als Engpass und wird vergrößert.
    /// </summary>
    private const long RttMultiplier = 2;

    private long _lastUpdateTicks = -1;

    /// <summary>
    /// Aktuelle Fenstergröße (Startwert = konfiguriertes initial_max_data*; wächst bis <see cref="Limit"/>).
    /// </summary>
    public ulong Size { get; private set; } = initialSize;

    /// <summary>
    /// Obergrenze, bis zu der das Fenster wachsen darf.
    /// </summary>
    public ulong Limit { get; } = Math.Max(initialSize, limit);

    /// <summary>
    /// Meldet, dass jetzt (bei <paramref name="nowTicks"/>) ein Fenster-Update ausgelöst wird, und
    /// vergrößert das Fenster, falls seit dem letzten Update weniger als <see cref="RttMultiplier"/>×RTT
    /// vergangen ist. Gibt <c>true</c> zurück, wenn das Fenster dabei gewachsen ist.
    /// </summary>
    public bool NoteWindowUpdate(long nowTicks, long smoothedRttTicks)
    {
        bool grew = false;
        if (_lastUpdateTicks >= 0 && smoothedRttTicks > 0 && Size < Limit &&
            nowTicks - _lastUpdateTicks < RttMultiplier * smoothedRttTicks)
        {
            Size = Math.Min(Size * 2, Limit);
            grew = true;
        }
        _lastUpdateTicks = nowTicks;
        return grew;
    }
}
