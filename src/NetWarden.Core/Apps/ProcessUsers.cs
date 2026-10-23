using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using static NetWarden.Core.Native.NativeMethods;

namespace NetWarden.Core.Apps;

public sealed record ProcessUser(string Sid, string? Name);

/// <summary>The account each process runs as, cached per (pid, creation time).</summary>
public sealed unsafe partial class ProcessUsers
{
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenUser = 1;

    private readonly ConcurrentDictionary<(int, long), ProcessUser?> _cache = new();

    public ProcessUser? Get(int processId)
    {
        if (processId is 0 or 4)
            return new ProcessUser("S-1-5-18", @"NT AUTHORITY\SYSTEM");
        var facts = ProcessInspector.TryInspect(processId);
        if (facts is null)
            return null;
        if (_cache.Count > 8192)
            _cache.Clear();
        return _cache.GetOrAdd((processId, facts.CreationTime), _ => Read(processId));
    }

    private static ProcessUser? Read(int processId)
    {
        using SafeProcessHandle process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (process.IsInvalid || !OpenProcessToken(process, TOKEN_QUERY, out SafeAccessTokenHandle token))
            return null;
        using (token)
        {
            GetTokenInformation(token, TokenUser, null, 0, out int size);
            if (size == 0)
                return null;
            byte* buffer = stackalloc byte[size];
            if (!GetTokenInformation(token, TokenUser, buffer, size, out _))
                return null;
            // TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first field is the SID pointer.
            var sid = new SecurityIdentifier(*(nint*)buffer);
            string? name = null;
            try
            {
                name = sid.Translate(typeof(NTAccount)).Value;
            }
            catch (IdentityNotMappedException)
            {
            }
            return new ProcessUser(sid.Value, name);
        }
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, void* info, int length, out int returnLength);
}
