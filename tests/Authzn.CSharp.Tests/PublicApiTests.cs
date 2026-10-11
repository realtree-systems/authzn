using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using Xunit;

namespace RealTree.Authzn.CSharp.Tests;

/// <summary>
/// Compares the public surface of RealTree.Authzn and RealTree.Authzn.CSharp with the approved listings in
/// <c>api/</c>. A change to a public or protected type or member fails here until the listing is
/// updated, so every API change shows up in review as a diff of <c>api/*.txt</c>.
/// </summary>
public class PublicApiTests
{
    [Theory]
    [InlineData("RealTree.Authzn")]
    [InlineData("RealTree.Authzn.CSharp")]
    public void Public_api_matches_the_approved_listing(string assemblyName)
    {
        var assembly = assemblyName == "RealTree.Authzn" ? typeof(global::RealTree.Authzn.PermissionId).Assembly : typeof(Authorizer).Assembly;
        var actual = PublicApi.Describe(assembly);

        var approvedPath = Path.Combine(RepositoryRoot(), "api", assemblyName + ".txt");
        var receivedPath = Path.Combine(RepositoryRoot(), "api", assemblyName + ".received.txt");
        var approved = File.Exists(approvedPath) ? File.ReadAllText(approvedPath).ReplaceLineEndings("\n") : "";

        if (actual == approved)
        {
            File.Delete(receivedPath);
            return;
        }

        File.WriteAllText(receivedPath, actual);
        var expectedLines = approved.Split('\n');
        var actualLines = actual.Split('\n');
        var first = Enumerable.Range(0, Math.Max(expectedLines.Length, actualLines.Length))
            .First(i => i >= expectedLines.Length || i >= actualLines.Length || expectedLines[i] != actualLines[i]);

        Assert.Fail(
            $"The public API of {assemblyName} differs from api/{assemblyName}.txt, first at line {first + 1}:\n" +
            $"  approved: {(first < expectedLines.Length ? expectedLines[first] : "<end>")}\n" +
            $"  actual:   {(first < actualLines.Length ? actualLines[first] : "<end>")}\n" +
            $"If the change is intended, replace api/{assemblyName}.txt with api/{assemblyName}.received.txt " +
            "and include it in the change.");
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Authzn.slnx")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("Authzn.slnx not found above " + AppContext.BaseDirectory);
    }
}

/// <summary>
/// Writes the public and protected surface of an assembly as sorted text: one block per exported
/// type, listing its kind, base type and interfaces, then its constructors, fields, properties,
/// events and methods with parameter names, default values and nullable annotations.
/// </summary>
internal static class PublicApi
{
    private static readonly NullabilityInfoContext Nullability = new();

    private static readonly Dictionary<Type, string> Aliases = new()
    {
        [typeof(void)] = "void", [typeof(object)] = "object", [typeof(string)] = "string",
        [typeof(bool)] = "bool", [typeof(char)] = "char", [typeof(byte)] = "byte", [typeof(sbyte)] = "sbyte",
        [typeof(short)] = "short", [typeof(ushort)] = "ushort", [typeof(int)] = "int", [typeof(uint)] = "uint",
        [typeof(long)] = "long", [typeof(ulong)] = "ulong", [typeof(float)] = "float", [typeof(double)] = "double",
        [typeof(decimal)] = "decimal",
    };

    // Types from these namespaces are written without their namespace.
    private static readonly HashSet<string> ShortNamespaces = new()
    {
        "System", "System.Collections", "System.Collections.Generic", "System.Threading", "System.Threading.Tasks",
    };

    public static string Describe(Assembly assembly)
    {
        var text = new StringBuilder();

        foreach (var type in assembly.GetExportedTypes().OrderBy(t => t.FullName, StringComparer.Ordinal))
        {
            text.Append(Header(type)).Append('\n');

            foreach (var line in Members(type))
            {
                text.Append("  ").Append(line).Append('\n');
            }

            text.Append('\n');
        }

        return text.ToString();
    }

    private static string Header(Type type)
    {
        string kind;
        if (type.IsInterface) kind = "interface";
        else if (type.IsEnum) kind = "enum";
        else if (type.IsSubclassOf(typeof(Delegate))) kind = "delegate";
        else if (type.IsValueType) kind = type.IsDefined(typeof(IsReadOnlyAttribute)) ? "readonly struct" : "struct";
        else if (type.IsAbstract && type.IsSealed) kind = "static class";
        else if (type.IsAbstract) kind = "abstract class";
        else if (type.IsSealed) kind = "sealed class";
        else kind = "class";

        var bases = new List<string>();
        if (type.BaseType is { } baseType && baseType != typeof(object) && baseType != typeof(ValueType)
            && baseType != typeof(Enum) && baseType != typeof(MulticastDelegate))
        {
            bases.Add(Name(baseType));
        }

        bases.AddRange(type.GetInterfaces()
            .Where(i => i.IsPublic || i.IsNestedPublic)
            .Select(Name)
            .OrderBy(n => n, StringComparer.Ordinal));

        return bases.Count == 0 ? $"{kind} {Name(type)}" : $"{kind} {Name(type)} : {string.Join(", ", bases)}";
    }

    private static IEnumerable<string> Members(Type type)
    {
        const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance
            | BindingFlags.Static | BindingFlags.DeclaredOnly;

        if (type.IsEnum)
        {
            return type.GetFields(BindingFlags.Public | BindingFlags.Static)
                .Select(f => $"{f.Name} = {Convert.ChangeType(f.GetRawConstantValue(), Enum.GetUnderlyingType(type))}");
        }

        var constructors = type.GetConstructors(all).Where(Visible).Select(c => $"ctor {Access(c)}({Parameters(c)})");
        var fields = type.GetFields(all).Where(Visible).Select(Field);
        var properties = type.GetProperties(all).Where(p => Visible(p.GetMethod) || Visible(p.SetMethod)).Select(Property);
        var events = type.GetEvents(all).Where(e => Visible(e.AddMethod)).Select(e => $"event {Access(e.AddMethod!)} {Name(e.EventHandlerType!)} {e.Name}");
        // F# emits some property getters (the generated IsCase properties) without the special-name
        // flag, so accessors are recognised through their properties and events instead.
        var accessors = type.GetProperties(all).SelectMany(p => p.GetAccessors(true))
            .Concat(type.GetEvents(all).SelectMany(e => new[] { e.AddMethod, e.RemoveMethod, e.RaiseMethod }))
            .Where(m => m is not null)
            .ToHashSet();
        var methods = type.GetMethods(all)
            .Where(m => Visible(m) && !accessors.Contains(m))
            .Select(Method);

        return constructors.OrderBy(s => s, StringComparer.Ordinal)
            .Concat(fields.OrderBy(s => s, StringComparer.Ordinal))
            .Concat(properties.OrderBy(s => s, StringComparer.Ordinal))
            .Concat(events.OrderBy(s => s, StringComparer.Ordinal))
            .Concat(methods.OrderBy(s => s, StringComparer.Ordinal));
    }

    private static bool Visible(MethodBase? method) =>
        method is not null && (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly);

    private static bool Visible(FieldInfo field) => field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly;

    private static string Access(MethodBase method) => method.IsPublic ? "public" : "protected";

    private static string Field(FieldInfo field)
    {
        var access = field.IsPublic ? "public" : "protected";
        var type = Name(field.FieldType, Nullability.Create(field));

        if (field.IsLiteral)
        {
            return $"const {access} {type} {field.Name} = {Literal(field.GetRawConstantValue())}";
        }

        var modifiers = (field.IsStatic ? " static" : "") + (field.IsInitOnly ? " readonly" : "");
        return $"field {access}{modifiers} {type} {field.Name}";
    }

    private static string Property(PropertyInfo property)
    {
        var accessor = property.GetMethod is { } g && Visible(g) ? g : property.SetMethod!;
        var parts = new List<string>();

        if (Visible(property.GetMethod))
        {
            parts.Add(Access(property.GetMethod!) == Access(accessor) ? "get;" : $"{Access(property.GetMethod!)} get;");
        }

        if (Visible(property.SetMethod))
        {
            var init = property.SetMethod!.ReturnParameter.GetRequiredCustomModifiers().Contains(typeof(IsExternalInit));
            var verb = init ? "init;" : "set;";
            parts.Add(Access(property.SetMethod) == Access(accessor) ? verb : $"{Access(property.SetMethod)} {verb}");
        }

        var indexParameters = property.GetIndexParameters();
        var name = indexParameters.Length == 0
            ? property.Name
            : $"this[{string.Join(", ", indexParameters.Select(Parameter))}]";

        return $"property {Access(accessor)}{Modifiers(accessor)} {Name(property.PropertyType, Nullability.Create(property))} {name} {{ {string.Join(" ", parts)} }}";
    }

    private static string Method(MethodInfo method)
    {
        var generic = method.IsGenericMethodDefinition
            ? $"<{string.Join(", ", method.GetGenericArguments().Select(a => a.Name))}>"
            : "";
        var returnType = Name(method.ReturnType, Nullability.Create(method.ReturnParameter));
        var extension = method.IsDefined(typeof(ExtensionAttribute)) ? "this " : "";

        return $"method {Access(method)}{Modifiers(method)} {returnType} {method.Name}{generic}({extension}{Parameters(method)})";
    }

    private static string Modifiers(MethodInfo method)
    {
        if (method.IsStatic) return " static";
        if (method.IsAbstract) return method.DeclaringType!.IsInterface ? "" : " abstract";
        if (!method.IsVirtual) return "";

        var overrides = method.GetBaseDefinition() != method;
        if (method.IsFinal) return overrides ? " sealed override" : "";
        return overrides ? " override" : " virtual";
    }

    private static string Parameters(MethodBase method) => string.Join(", ", method.GetParameters().Select(Parameter));

    private static string Parameter(ParameterInfo parameter)
    {
        var text = new StringBuilder();

        if (parameter.IsDefined(typeof(ParamArrayAttribute))) text.Append("params ");

        var type = parameter.ParameterType;
        if (type.IsByRef)
        {
            text.Append(parameter.IsOut ? "out " : parameter.IsIn ? "in " : "ref ");
        }

        text.Append(Name(type.IsByRef ? type.GetElementType()! : type, Nullability.Create(parameter)));
        text.Append(' ').Append(parameter.Name);

        if (parameter.HasDefaultValue)
        {
            // A struct parameter declared "= default" reports a null default value.
            var isStructDefault = parameter.DefaultValue is null && type.IsValueType && Nullable.GetUnderlyingType(type) is null;
            text.Append(" = ").Append(isStructDefault ? "default" : Literal(parameter.DefaultValue));
        }

        return text.ToString();
    }

    private static string Literal(object? value) => value switch
    {
        null => "null",
        string s => $"\"{s}\"",
        char c => $"'{c}'",
        bool b => b ? "true" : "false",
        _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture)!,
    };

    private static string Name(Type type) => Name(type, null);

    private static string Name(Type type, NullabilityInfo? nullability)
    {
        if (type.IsByRef) return Name(type.GetElementType()!, nullability);

        if (Nullable.GetUnderlyingType(type) is { } underlying)
        {
            return Name(underlying, nullability?.GenericTypeArguments.FirstOrDefault()) + "?";
        }

        var nullable = !type.IsValueType && nullability?.ReadState == NullabilityState.Nullable ? "?" : "";

        if (type.IsArray)
        {
            return $"{Name(type.GetElementType()!, nullability?.ElementType)}[]{nullable}";
        }

        // An unconstrained T reads as nullable whatever its annotation, so generic parameters carry
        // no nullability mark.
        if (type.IsGenericParameter) return type.Name;

        if (Aliases.TryGetValue(type, out var alias)) return alias + nullable;

        var name = type.Name;
        var tick = name.IndexOf('`');
        if (tick >= 0) name = name[..tick];

        var prefix = type.IsNested
            ? Name(type.DeclaringType!.IsGenericTypeDefinition && !type.IsGenericTypeDefinition
                ? type.DeclaringType
                : type.DeclaringType!) + "."
            : type.Namespace is { } ns && !ShortNamespaces.Contains(ns) ? ns + "." : "";

        if (type.IsGenericType)
        {
            var arguments = type.GetGenericArguments();
            var own = type.IsNested ? arguments.Skip(type.DeclaringType!.GetGenericArguments().Length).ToArray() : arguments;
            var offset = arguments.Length - own.Length;

            if (own.Length > 0)
            {
                var names = own.Select((a, i) => Name(a, nullability?.GenericTypeArguments.ElementAtOrDefault(offset + i)));
                name += $"<{string.Join(", ", names)}>";
            }
        }

        return prefix + name + nullable;
    }
}
