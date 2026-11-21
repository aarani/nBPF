using Nbpf.Core.Native;

namespace Nbpf.Core;

/// <summary>
/// What a kernel can do, as far as the loader's fallbacks need to know (DESIGN §4.5).
/// <see cref="KernelFeatures.Running"/> answers for the running kernel by probing it;
/// pass another implementation via <c>BpfLoadOptions.Features</c> to make the loader
/// behave as it would on a different kernel, which is how the fallbacks are tested.
/// </summary>
public interface IKernelFeatures
{
    /// <summary>Whether maps of this type can be created.</summary>
    bool HasMapType(BpfMapType type);

    /// <summary>Whether programs of this type can be loaded.</summary>
    bool HasProgramType(BpfProgType type);

    /// <summary>Whether programs of <paramref name="programType"/> may call helper
    /// <paramref name="helperId"/>. Helpers are offered per program type, so a helper
    /// can exist in the kernel and still be unavailable to a given type.</summary>
    bool HasHelper(BpfProgType programType, int helperId);
}
