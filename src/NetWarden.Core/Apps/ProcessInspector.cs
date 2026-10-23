using Microsoft.Win32.SafeHandles;
using NetWarden.Core.Native;
using NetWarden.Shared.Contracts;
using static NetWarden.Core.Native.NativeMethods;

namespace NetWarden.Core.Apps;

/// <summary>Raw facts about a running process, read through Win32.</summary>
public sealed record ProcessFacts(int ProcessId, string ImagePath, long CreationTime, string? PackageFamilyName);

public static unsafe class ProcessInspector
{
    /// <summary>Returns null if the process has exited or cannot be opened.</summary>
    public static ProcessFacts? TryInspect(int processId)
    {
        using SafeProcessHandle handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (handle.IsInvalid)
            return null;

        string? path = GetImagePath(handle);
        if (path is null)
            return null;

        GetProcessTimes(handle, out long created, out _, out _, out _);
        return new ProcessFacts(processId, path, created, GetPackageFamily(handle));
    }

    private static string? GetImagePath(SafeProcessHandle handle)
    {
        int size = 1024;
        while (size <= 32 * 1024)
        {
            char[] buffer = new char[size];
            int length = size;
            fixed (char* p = buffer)
            {
                if (QueryFullProcessImageName(handle, 0, p, ref length))
                    return new string(buffer, 0, length);
            }
            if (System.Runtime.InteropServices.Marshal.GetLastPInvokeError() != ERROR_INSUFFICIENT_BUFFER)
                return null;
            size *= 2;
        }
        return null;
    }

    private static string? GetPackageFamily(SafeProcessHandle handle)
    {
        uint length = 0;
        int rc = GetPackageFamilyName(handle, ref length, null);
        if (rc == APPMODEL_ERROR_NO_PACKAGE || rc != ERROR_INSUFFICIENT_BUFFER || length == 0)
            return null;

        char* buffer = stackalloc char[(int)length];
        rc = GetPackageFamilyName(handle, ref length, buffer);
        return rc == 0 ? new string(buffer, 0, (int)length - 1) : null;
    }

    /// <summary>Maps process ids to the Win32 services running inside them.</summary>
    public static Dictionary<int, List<ServiceEntry>> GetRunningServices()
    {
        var result = new Dictionary<int, List<ServiceEntry>>();
        nint scm = OpenSCManager(null, null, SC_MANAGER_ENUMERATE_SERVICE);
        if (scm == 0)
            return result;
        try
        {
            uint resume = 0;
            EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                null, 0, out uint needed, out _, ref resume, null);

            while (true)
            {
                byte[] buffer = new byte[needed + 4096];
                fixed (byte* p = buffer)
                {
                    bool ok = EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                        p, (uint)buffer.Length, out needed, out uint count, ref resume, null);
                    int error = ok ? 0 : System.Runtime.InteropServices.Marshal.GetLastPInvokeError();
                    if (!ok && error != ERROR_MORE_DATA)
                        return result;

                    var entries = (ENUM_SERVICE_STATUS_PROCESS*)p;
                    for (int i = 0; i < count; i++)
                    {
                        int pid = (int)entries[i].ProcessId;
                        if (pid == 0)
                            continue;
                        if (!result.TryGetValue(pid, out var list))
                            result[pid] = list = [];
                        list.Add(new ServiceEntry(new string(entries[i].ServiceName), new string(entries[i].DisplayName)));
                    }
                    if (ok)
                        return result;
                }
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }
}
