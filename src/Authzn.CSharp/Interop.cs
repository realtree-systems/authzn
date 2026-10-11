using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.FSharp.Collections;
using Microsoft.FSharp.Core;
using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// Conversions between the facade's .NET types and the core's F# types: nullable values and
/// <c>FSharpOption</c>, dictionaries and <c>FSharpMap</c>, delegates and <c>FSharpFunc</c>, and the
/// F# <c>DenyReason</c> union to the C# <see cref="DenyReason"/> enum. No public member signature
/// in the facade uses a <c>Microsoft.FSharp.*</c> type.
/// </summary>
internal static class Interop
{
    internal static readonly IReadOnlyDictionary<string, string> EmptyScope =
        new Dictionary<string, string>();

    internal static readonly IReadOnlyDictionary<string, object> EmptyAttributes =
        new Dictionary<string, object>();

    internal static FSharpOption<T> ToOption<T>(T? value) where T : class =>
        value is null ? FSharpOption<T>.None : FSharpOption<T>.Some(value);

    internal static T? FromOption<T>(FSharpOption<T> option) where T : class =>
        FSharpOption<T>.get_IsSome(option) ? option.Value : null;

    internal static FSharpOption<T> ToOptionStruct<T>(T? value) where T : struct =>
        value.HasValue ? FSharpOption<T>.Some(value.Value) : FSharpOption<T>.None;

    internal static T? FromOptionStruct<T>(FSharpOption<T> option) where T : struct =>
        FSharpOption<T>.get_IsSome(option) ? option.Value : null;

    internal static FSharpMap<string, string> ToStringMap(IReadOnlyDictionary<string, string>? source)
    {
        var map = MapModule.Empty<string, string>();
        if (source is not null)
        {
            foreach (var kv in source)
            {
                map = MapModule.Add(kv.Key, kv.Value, map);
            }
        }

        return map;
    }

    internal static FSharpMap<string, string> ToStringMap(IEnumerable<(string key, string value)>? pairs)
    {
        var map = MapModule.Empty<string, string>();
        if (pairs is not null)
        {
            foreach (var (key, value) in pairs)
            {
                map = MapModule.Add(key, value, map);
            }
        }

        return map;
    }

    internal static FSharpMap<string, object> ToObjectMap(IReadOnlyDictionary<string, object>? source)
    {
        var map = MapModule.Empty<string, object>();
        if (source is not null)
        {
            foreach (var kv in source)
            {
                map = MapModule.Add(kv.Key, kv.Value, map);
            }
        }

        return map;
    }

    internal static IReadOnlyDictionary<string, string> FromStringMap(FSharpMap<string, string> map) =>
        map.ToDictionary(kv => kv.Key, kv => kv.Value);

    internal static FSharpMap<string, Fs.ScopeValue> ToGrantScope(IEnumerable<KeyValuePair<string, ScopeValue>>? source)
    {
        var map = MapModule.Empty<string, Fs.ScopeValue>();
        if (source is not null)
        {
            foreach (var kv in source)
            {
                ArgumentNullException.ThrowIfNull(kv.Value, $"scope[{kv.Key}]");
                map = MapModule.Add(kv.Key, kv.Value.ToFs(), map);
            }
        }

        return map;
    }

    internal static FSharpMap<string, Fs.ScopeValue> ToGrantScope(IEnumerable<(string key, ScopeValue value)>? pairs) =>
        ToGrantScope(pairs?.Select(pair => KeyValuePair.Create(pair.key, pair.value)));

    internal static IReadOnlyDictionary<string, ScopeValue> FromGrantScope(FSharpMap<string, Fs.ScopeValue> map) =>
        map.ToDictionary(kv => kv.Key, kv => ScopeValue.FromFs(kv.Value));

    /// <summary>
    /// Wraps a C# predicate as the core's condition function. The F# <c>AttributeBag</c>
    /// (<c>Map&lt;string,obj&gt;</c>) implements <see cref="IReadOnlyDictionary{TKey,TValue}"/>,
    /// so the predicate receives the request's map by upcast, without copying it.
    /// </summary>
    internal static FSharpFunc<FSharpMap<string, object>, bool> ToCondition(
        Func<IReadOnlyDictionary<string, object>, bool> predicate) =>
        FSharpFunc<FSharpMap<string, object>, bool>.FromConverter(map => predicate(map));

    internal static FSharpOption<FSharpMap<string, Fs.ScopeValue>> ToScopeOption(FSharpMap<string, Fs.ScopeValue>? scope) =>
        scope is null
            ? FSharpOption<FSharpMap<string, Fs.ScopeValue>>.None
            : FSharpOption<FSharpMap<string, Fs.ScopeValue>>.Some(scope);

    internal static FSharpOption<FSharpFunc<FSharpMap<string, object>, bool>> ToConditionOption(
        Func<IReadOnlyDictionary<string, object>, bool>? predicate) =>
        predicate is null
            ? FSharpOption<FSharpFunc<FSharpMap<string, object>, bool>>.None
            : FSharpOption<FSharpFunc<FSharpMap<string, object>, bool>>.Some(ToCondition(predicate));

    internal static DenyReason FromDenyReason(Fs.DenyReason reason)
    {
        if (reason.IsNoAssignments)
        {
            return DenyReason.NoAssignments;
        }

        if (reason.IsNoMatchingPermission)
        {
            return DenyReason.NoMatchingPermission;
        }

        if (reason.IsScopeMismatch)
        {
            return DenyReason.ScopeMismatch;
        }

        if (reason.IsAssignmentNotActive)
        {
            return DenyReason.AssignmentNotActive;
        }

        if (reason.IsGrantNotActive)
        {
            return DenyReason.GrantNotActive;
        }

        if (reason.IsAttributeEvaluationFailed)
        {
            return DenyReason.AttributeEvaluationFailed;
        }

        throw new InvalidOperationException(
            $"Unmapped Authzn.DenyReason case '{reason}'. The C# DenyReason enum is out of sync with the F# core.");
    }
}
