using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace NetWarden.Core.Ipc;

public static class PipeSecurityFactory
{
    /// <summary>
    /// Only elevated administrators and SYSTEM may connect: the service controls
    /// the firewall and limiter, so normal users must not be able to drive it.
    /// </summary>
    public static PipeSecurity AdminsAndSystem()
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[]
                 {
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                 })
        {
            security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
        }
        return security;
    }
}
