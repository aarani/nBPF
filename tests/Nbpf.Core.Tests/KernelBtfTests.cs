using Nbpf.Btf;
using Xunit;

namespace Nbpf.Core.Tests;

public class KernelBtfTests
{
    [Fact]
    public void Try_load_reflects_whether_the_kernel_exposes_btf()
    {
        var exposed = File.Exists(KernelBtf.VmlinuxPath);

        var loaded = KernelBtf.TryLoadVmlinux(out var btf);

        Assert.Equal(exposed, loaded);
        Assert.Equal(loaded, btf is not null);
    }

    [KernelBtfFact]
    public void Vmlinux_btf_parses_and_contains_task_struct()
    {
        var btf = KernelBtf.LoadVmlinux();

        var task = Assert.IsAssignableFrom<IBtfStruct>(btf.Find("task_struct", BtfKind.Struct));
        Assert.Contains(task.Members, m => m.Name == "pid");
    }
}
