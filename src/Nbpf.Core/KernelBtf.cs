using System.Diagnostics.CodeAnalysis;
using Nbpf.Btf;

namespace Nbpf.Core;

/// <summary>
/// The running kernel's own BTF, exposed since 5.4 at <c>/sys/kernel/btf/vmlinux</c> in
/// the plain <c>.BTF</c> wire format. This is the default CO-RE relocation target
/// (DESIGN §4.4 step 4); module BTF and BTFHub fallbacks for BTF-less kernels are
/// phase 8 concerns and not handled here.
/// </summary>
public static class KernelBtf
{
    public const string VmlinuxPath = "/sys/kernel/btf/vmlinux";

    /// <summary>
    /// Reads and parses the running kernel's vmlinux BTF. Throws
    /// <see cref="FileNotFoundException"/> when the kernel does not expose it
    /// (pre-5.4, or built without <c>CONFIG_DEBUG_INFO_BTF</c>).
    /// </summary>
    public static IBtfTypeGraph LoadVmlinux()
    {
        TryLoadVmlinux(out var btf);
        if (btf is null)
            throw new FileNotFoundException($"Kernel BTF not found at {VmlinuxPath}");
        return btf;
    }

    /// <summary>Like <see cref="LoadVmlinux"/>, but false instead of throwing when the
    /// kernel exposes no BTF (including on non-Linux hosts).</summary>
    public static bool TryLoadVmlinux([NotNullWhen(true)] out IBtfTypeGraph? btf)
    {
        if (!File.Exists(VmlinuxPath))
        {
            btf = null;
            return false;
        }

        try
        {
            var btfBytes = File.ReadAllBytes(VmlinuxPath);
            btf = BtfReader.Read(btfBytes);
            return true;
        }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
        {
            btf = null;
            return false;
        }
    }
}
