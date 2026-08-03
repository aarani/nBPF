namespace Nbpf.Btf;

/// <summary>
/// Resolves CO-RE relocations: re-evaluates a <see cref="BtfCoreRelo"/> recorded against
/// the program's own (local) BTF over a target kernel's BTF, producing the value to
/// patch into the instruction. Pure BTF math — no ELF, no instructions, no syscalls.
/// </summary>
public interface ICoreReloResolver
{
    /// <summary>
    /// Resolves one relocation. <paramref name="localBtf"/> is the graph the relocation's
    /// <see cref="BtfCoreRelo.TypeId"/> and access string were recorded against (the
    /// object's own <c>.BTF</c>); <paramref name="targetBtf"/> is the graph to relocate
    /// onto (normally the running kernel's vmlinux BTF).
    /// Throws <see cref="CoreReloException"/> only when the relocation itself is broken;
    /// a missing target comes back as an exists-probe zero or a poisoned result.
    /// </summary>
    CoreReloResult Resolve(BtfCoreRelo relo, IBtfTypeGraph localBtf, IBtfTypeGraph targetBtf);
}
