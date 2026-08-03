namespace Nbpf.Btf;

/// <summary>
/// The outcome of resolving one CO-RE relocation against target BTF (DESIGN §4.4 step 4).
/// Values are unsigned 64-bit because a relocation can patch the two-slot ld_imm64 form;
/// most kinds only ever produce 32-bit values.
/// </summary>
/// <param name="OldValue">
/// The value the compiler baked into the instruction, recomputed here from the
/// <em>local</em> spec (e.g. the local byte offset for
/// <see cref="BtfCoreReloKind.FieldByteOffset"/>). The patcher uses it to verify it is
/// looking at the instruction the relocation describes before touching it.
/// </param>
/// <param name="NewValue">
/// The value the instruction must carry to be correct against the target BTF.
/// Meaningless when <paramref name="Poison"/> is set.
/// </param>
/// <param name="Poison">
/// True when the target has no match and the relocation kind is not an existence probe:
/// the instruction cannot be made correct, so the patcher replaces it with an invalid
/// call. The program still loads if the verifier proves that path dead — which is
/// exactly what a preceding <see cref="BtfCoreReloKind.FieldExists"/> guard arranges.
/// </param>
/// <param name="Validate">
/// True when <paramref name="OldValue"/> is exact and the patcher must reject an
/// instruction that does not carry it. False where the compiler's baked-in value is
/// legitimately ambiguous: bitfield offsets/sizes/left-shifts, and type ids, which the
/// compiler may have emitted against a different ordering of the same BTF.
/// </param>
public readonly record struct CoreReloResult(
    ulong OldValue, ulong NewValue, bool Poison, bool Validate);

/// <summary>
/// A CO-RE relocation that cannot be resolved <em>as stated</em>: a malformed access
/// string, a spec that does not fit the local type it starts from, or target candidates
/// that match but disagree on the result. A merely missing target is not an error —
/// that is the poison / exists-probe case on <see cref="CoreReloResult"/>.
/// </summary>
public sealed class CoreReloException : Exception
{
    public CoreReloException(string message) : base(message) { }
}
