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

using NUnit.Framework;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Kleine NUnit-Test-Helfer, die eine Bedingung PRÜFEN und den geprüften Wert ZURÜCKGEBEN — praktisch
/// beim Parsen (Typ eines Elements bestätigen und gleich weiterverwenden). Intern über
/// <see cref="Assert.That(object, NUnit.Framework.Constraints.IResolveConstraint)"/>, also NUnit-nativ.
/// </summary>
internal static class Expect
{
    /// <summary>
    /// Bestätigt, dass <paramref name="value"/> vom Typ <typeparamref name="T"/> ist, und gibt es
    /// getypt zurück.
    /// </summary>
    public static T Type<T>(object? value)
    {
        Assert.That(value, Is.TypeOf<T>());
        return (T)value!;
    }

    /// <summary>
    /// Bestätigt, dass <paramref name="items"/> genau ein Element enthält, und gibt es zurück.
    /// </summary>
    public static T Single<T>(IEnumerable<T> items)
    {
        var list = items.ToList();
        Assert.That(list, Has.Count.EqualTo(1));
        return list[0];
    }
}
