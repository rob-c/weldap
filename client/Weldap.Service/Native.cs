using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Weldap.Service;

// The whole P/Invoke surface: crypt32 (DPAPI), netapi32 (local accounts), advapi32/kernel32 (pipe, tokens).
// No networking DLL: the only network code is ServerClient, on .NET's own TLS. Passwords are pinned char*.
internal static unsafe partial class Native
{
    // ---- crypt32 (DPAPI) ----
    [StructLayout(LayoutKind.Sequential)]
    public struct DATA_BLOB
    {
        public uint cbData;
        public byte* pbData;
    }

    public const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;
    public const uint CRYPTPROTECT_LOCAL_MACHINE = 0x4;

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptProtectData(DATA_BLOB* pDataIn, IntPtr szDataDescr, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, DATA_BLOB* pDataOut);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptUnprotectData(DATA_BLOB* pDataIn, IntPtr ppszDataDescr, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, DATA_BLOB* pDataOut);

    [LibraryImport("kernel32.dll")]
    public static partial IntPtr LocalFree(IntPtr hMem);

    // ---- netapi32 ----
    public const uint NERR_Success = 0;
    public const uint NERR_UserNotFound = 2221;
    public const uint NERR_GroupExists = 2223;
    public const uint ERROR_ALIAS_EXISTS = 1379;
    public const uint ERROR_MEMBER_IN_ALIAS = 1378;
    public const uint ERROR_MEMBER_NOT_IN_ALIAS = 1377;
    public const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

    public const uint USER_PRIV_USER = 1;
    public const uint UF_SCRIPT = 0x0001;
    public const uint UF_ACCOUNTDISABLE = 0x0002;
    public const uint UF_PASSWD_CANT_CHANGE = 0x0040;
    public const uint UF_NORMAL_ACCOUNT = 0x0200;
    public const uint UF_DONT_EXPIRE_PASSWD = 0x10000;
    public const uint TIMEQ_FOREVER = 0xFFFFFFFF;
    public const int SidTypeUser = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct USER_INFO_1
    {
        public char* usri1_name;
        public char* usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        public char* usri1_home_dir;
        public char* usri1_comment;
        public uint usri1_flags;
        public char* usri1_script_path;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct USER_INFO_2
    {
        public char* usri2_name;
        public char* usri2_password;
        public uint usri2_password_age;
        public uint usri2_priv;
        public char* usri2_home_dir;
        public char* usri2_comment;
        public uint usri2_flags;
        public char* usri2_script_path;
        public uint usri2_auth_flags;
        public char* usri2_full_name;
        public char* usri2_usr_comment;
        public char* usri2_parms;
        public char* usri2_workstations;
        public uint usri2_last_logon;
        public uint usri2_last_logoff;
        public uint usri2_acct_expires;
        public uint usri2_max_storage;
        public uint usri2_units_per_week;
        public byte* usri2_logon_hours;
        public uint usri2_bad_pw_count;
        public uint usri2_num_logons;
        public char* usri2_logon_server;
        public uint usri2_country_code;
        public uint usri2_code_page;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOCALGROUP_INFO_1
    {
        public char* lgrpi1_name;
        public char* lgrpi1_comment;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOCALGROUP_USERS_INFO_0
    {
        public char* lgrui0_name;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOCALGROUP_MEMBERS_INFO_1
    {
        public IntPtr lgrmi1_sid;
        public int lgrmi1_sidusage;
        public char* lgrmi1_name;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOCALGROUP_MEMBERS_INFO_3
    {
        public char* lgrmi3_domainandname;
    }

    [LibraryImport("netapi32.dll")]
    public static partial uint NetUserAdd(char* servername, uint level, void* buf, out uint parmErr);

    [LibraryImport("netapi32.dll")]
    public static partial uint NetUserGetInfo(char* servername, char* username, uint level, out IntPtr bufptr);

    [LibraryImport("netapi32.dll")]
    public static partial uint NetUserSetInfo(char* servername, char* username, uint level, void* buf, out uint parmErr);

    [LibraryImport("netapi32.dll")]
    public static partial uint NetUserGetLocalGroups(char* servername, char* username, uint level, uint flags,
        out IntPtr bufptr, uint prefmaxlen, out uint entriesread, out uint totalentries);

    [LibraryImport("netapi32.dll")]
    public static partial uint NetLocalGroupAdd(char* servername, uint level, void* buf, out uint parmErr);

    [LibraryImport("netapi32.dll")]
    public static partial uint NetLocalGroupAddMembers(char* servername, char* groupname, uint level, void* buf, uint totalentries);

    [LibraryImport("netapi32.dll")]
    public static partial uint NetLocalGroupDelMembers(char* servername, char* groupname, uint level, void* buf, uint totalentries);

    [LibraryImport("netapi32.dll")]
    public static partial uint NetLocalGroupGetMembers(char* servername, char* localgroupname, uint level,
        out IntPtr bufptr, uint prefmaxlen, out uint entriesread, out uint totalentries, IntPtr* resumehandle);

    [LibraryImport("netapi32.dll")]
    public static partial uint NetApiBufferFree(IntPtr buffer);

    // ---- named pipe ----
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    public const uint FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
    public const uint PIPE_TYPE_BYTE = 0x0;
    public const uint PIPE_READMODE_BYTE = 0x0;
    public const uint PIPE_WAIT = 0x0;
    public const uint PIPE_REJECT_REMOTE_CLIENTS = 0x00000008;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint TOKEN_QUERY = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafePipeHandle CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maxInstances,
        uint outBufferSize, uint inBufferSize, uint defaultTimeout, SECURITY_ATTRIBUTES* securityAttributes);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision,
        out IntPtr securityDescriptor, IntPtr securityDescriptorSize);
}
