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

using System.Security.Cryptography.X509Certificates;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

/// <summary>
/// Steuert, wie der Client das Serverzertifikat prüft. Die <b>CertificateVerify-Signatur</b> (die
/// kryptografische Bindung des Zertifikats an den Handshake, RFC 8446 §4.4.3) wird <b>immer</b>
/// geprüft — sie ist die eigentliche MITM-Abwehr. Diese Optionen betreffen nur die davon getrennte
/// <b>Vertrauens-Policy</b>: Kettenaufbau bis zu einer vertrauenswürdigen Wurzel, Hostname und
/// Gültigkeitszeitraum.
/// </summary>
public sealed record CertificateValidationOptions
{
    /// <summary>
    /// Baut die Zertifikatskette bis zu einer vertrauenswürdigen Wurzel und prüft sie (Standard: an).
    /// </summary>
    public bool VerifyCertificateChain { get; init; } = true;

    /// <summary>
    /// Prüft, ob der Hostname zum Zertifikat passt (SAN/CN, RFC 6125). Standard: an.
    /// </summary>
    public bool VerifyHostname { get; init; } = true;

    /// <summary>
    /// Zusätzliche Trust-Anker. Sind welche gesetzt, wird ausschließlich gegen diese geprüft
    /// (Custom-Root-Trust) statt gegen den System-Trust-Store — nützlich, um ein selbstsigniertes
    /// Testzertifikat gezielt zu vertrauen.
    /// </summary>
    public X509Certificate2Collection? CustomTrustRoots { get; init; }

    /// <summary>
    /// Standard: volle Prüfung gegen die System-Roots inkl. Hostname.
    /// </summary>
    public static CertificateValidationOptions Default { get; } = new();

    /// <summary>
    /// Wie <c>curl -k</c>: Kette und Hostname werden NICHT geprüft, die CertificateVerify-Signatur
    /// aber weiterhin. Für selbstsignierte Testserver (z. B. localhost) gedacht.
    /// </summary>
    public static CertificateValidationOptions Insecure { get; } = new()
    {
        VerifyCertificateChain = false,
        VerifyHostname = false,
    };
}
