using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using NetWarden.Core.Ipc;

namespace NetWarden.Tests.Ipc;

public class PipeSecurityFactoryTests
{
    [Fact]
    public void Grants_only_administrators_and_system_with_no_inheritance()
    {
        PipeSecurity security = PipeSecurityFactory.AdminsAndSystem();

        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();

        Assert.True(security.AreAccessRulesProtected);
        Assert.All(rules, r => Assert.Equal(AccessControlType.Allow, r.AccessControlType));
        Assert.Equal(
            new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid }
                .Select(t => new SecurityIdentifier(t, null).Value).Order(),
            rules.Select(r => r.IdentityReference.Value).Order());
    }
}
