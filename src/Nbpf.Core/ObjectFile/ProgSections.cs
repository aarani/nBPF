using Nbpf.Core.Native;

namespace Nbpf.Core.ObjectFile;

/// <summary>
/// Maps ELF section names (the SEC() annotation) to program types, following libbpf's
/// conventions. Most families are matched by prefix ("tracepoint/...", "xdp/..."); a
/// bare name with no suffix ("xdp") must match exactly, so look-alikes such as
/// "xdp.frags" — which needs a different load flag — are rejected rather than
/// silently loaded as plain XDP. Each new attach family adds an entry here plus tests.
/// </summary>
internal static class ProgSections
{
    private static readonly (string Prefix, BpfProgType Type)[] Prefixes =
    [
        ("tracepoint/", BpfProgType.Tracepoint),
        ("tp/", BpfProgType.Tracepoint),
        ("xdp/", BpfProgType.Xdp),
    ];

    private static readonly (string Name, BpfProgType Type)[] Fixed =
    [
        ("xdp", BpfProgType.Xdp),
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

        foreach (var (name, candidate) in Fixed)
        {
            if (sectionName.Equals(name, StringComparison.Ordinal))
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

    internal static string SupportedFixedNames { get; } =
        string.Join(", ", Fixed.Select(p => $"'{p.Name}'").Distinct());
}
