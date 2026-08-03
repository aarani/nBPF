using Nbpf.Btf;

namespace Nbpf.Core.ObjectFile;

/// <summary>Options for <see cref="BpfObject.Load(byte[], BpfLoadOptions?)"/>.</summary>
public sealed class BpfLoadOptions
{
    /// <summary>
    /// The BTF to resolve CO-RE relocations against. Null means the running kernel's
    /// vmlinux BTF (<see cref="KernelBtf.LoadVmlinux"/>), which is only consulted when
    /// the object actually carries CO-RE relocations. Supplying a graph explicitly is
    /// how tests and cross-kernel tooling relocate without being on the target kernel.
    /// </summary>
    public IBtfTypeGraph? TargetBtf { get; init; }
}
