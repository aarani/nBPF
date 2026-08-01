using Nbpf.Core.Native;

namespace Nbpf.Core.ObjectFile;

/// <summary>
/// Maps ELF section names (the SEC() annotation) to program types. Phase 1 only
/// needs tracepoints; each new attach family adds a prefix here plus tests.
/// </summary>
internal static class ProgSections
{
    private static readonly (string Prefix, BpfProgType Type)[] Prefixes =
    [
        ("tracepoint/", BpfProgType.Tracepoint),
        ("tp/", BpfProgType.Tracepoint),
    ];

    internal static bool TryResolve(string sectionName, out BpfProgType type)
    {
        foreach (var (prefix, candidate) in Prefixes)
        {
            if (sectionName.StartsWith(prefix, StringComparison.Ordinal))
            {
                type = candidate;
                return true;
            }
        }

        type = default;
        return false;
    }

    internal static string SupportedPrefixes { get; } =
        string.Join(", ", Prefixes.Select(p => $"'{p.Prefix}'").Distinct());
}
