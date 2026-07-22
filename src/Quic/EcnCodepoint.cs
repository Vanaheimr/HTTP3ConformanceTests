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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic;

/// <summary>
/// Der ECN-Codepoint im IP-Header (RFC 3168, die zwei niederwertigen Bits des DS-/TOS-Felds). QUIC nutzt ihn
/// als Congestion-Signal (RFC 9000 §13.4, RFC 9002 §7.3): Der Sender markiert Pakete mit ECT(0)/ECT(1); ein
/// überlasteter Router kann sie auf CE „hochstufen". Der Empfänger zählt die Codepoints je Packet-Number-Space
/// und meldet die Summen im ACK-Frame (Typ 0x03) zurück.
/// </summary>
public enum EcnCodepoint : byte
{
    /// <summary>
    /// Not-ECT (00): ECN wird für dieses Paket nicht genutzt.
    /// </summary>
    NotEct = 0b00,

    /// <summary>
    /// ECT(1) (01): ECN-fähig, Variante 1.
    /// </summary>
    Ect1 = 0b01,

    /// <summary>
    /// ECT(0) (10): ECN-fähig, Variante 0.
    /// </summary>
    Ect0 = 0b10,

    /// <summary>
    /// CE (11): Congestion Experienced – ein Router meldet Überlast.
    /// </summary>
    Ce = 0b11,
}
