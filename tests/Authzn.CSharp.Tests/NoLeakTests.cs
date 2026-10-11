using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using RealTree.Authzn.CSharp;
using Xunit;

namespace RealTree.Authzn.CSharp.Tests;

/// <summary>
/// Checks that no public method, constructor, property or field of an exported RealTree.Authzn.CSharp type
/// uses a <c>Microsoft.FSharp.*</c> type, directly, as an array element or as a generic argument,
/// so C# code calling the facade never names an FSharp.Core type.
/// </summary>
public class NoLeakTests
{
    private static bool MentionsFSharp(Type type)
    {
        if (type.Namespace is { } ns && ns.StartsWith("Microsoft.FSharp", StringComparison.Ordinal))
        {
            return true;
        }

        if (type.HasElementType && type.GetElementType() is { } element && MentionsFSharp(element))
        {
            return true;
        }

        return type.IsGenericType && type.GetGenericArguments().Any(MentionsFSharp);
    }

    public static IEnumerable<object[]> PublicTypes() =>
        typeof(Authorizer).Assembly.GetExportedTypes().Select(t => new object[] { t });

    [Theory]
    [MemberData(nameof(PublicTypes))]
    public void Public_members_never_expose_fsharp_types(Type type)
    {
        const BindingFlags flags = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        var offenders = new List<string>();

        foreach (var method in type.GetMethods(flags))
        {
            if (MentionsFSharp(method.ReturnType))
            {
                offenders.Add($"{type.Name}.{method.Name} returns {method.ReturnType}");
            }

            foreach (var p in method.GetParameters().Where(p => MentionsFSharp(p.ParameterType)))
            {
                offenders.Add($"{type.Name}.{method.Name} parameter '{p.Name}' is {p.ParameterType}");
            }
        }

        foreach (var ctor in type.GetConstructors(flags))
        {
            foreach (var p in ctor.GetParameters().Where(p => MentionsFSharp(p.ParameterType)))
            {
                offenders.Add($"{type.Name} constructor parameter '{p.Name}' is {p.ParameterType}");
            }
        }

        foreach (var prop in type.GetProperties(flags).Where(prop => MentionsFSharp(prop.PropertyType)))
        {
            offenders.Add($"{type.Name}.{prop.Name} is {prop.PropertyType}");
        }

        foreach (var field in type.GetFields(flags).Where(field => MentionsFSharp(field.FieldType)))
        {
            offenders.Add($"{type.Name}.{field.Name} is {field.FieldType}");
        }

        Assert.True(offenders.Count == 0, string.Join(Environment.NewLine, offenders));
    }
}
