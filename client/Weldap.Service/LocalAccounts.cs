using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using static Weldap.Service.Native;

namespace Weldap.Service;

/// <summary>
/// Local SAM accounts through netapi32. SR-7: every change re-checks that the account is in the
/// managed group first, so nothing outside WELDAP-Managed is ever modified. Group names come from
/// well-known SIDs, so this works on non-English Windows.
/// </summary>
internal sealed unsafe class LocalAccounts : ILocalAccounts
{
    private const string _managedGroup = LoginSettings.ManagedGroup;
    private readonly string _administrators = GroupName(WellKnownSidType.BuiltinAdministratorsSid);
    private readonly string _users = GroupName(WellKnownSidType.BuiltinUsersSid);

    public LocalAccounts() => EnsureManagedGroup();

    private static string GroupName(WellKnownSidType type)
    {
        var account = (NTAccount)new SecurityIdentifier(type, null).Translate(typeof(NTAccount));
        var value = account.Value;
        return value[(value.IndexOf('\\') + 1)..];
    }

    private void EnsureManagedGroup()
    {
        fixed (char* name = _managedGroup)
        fixed (char* comment = "Local accounts created and managed by WELDAP")
        {
            var info = new LOCALGROUP_INFO_1 { lgrpi1_name = name, lgrpi1_comment = comment };
            var rc = NetLocalGroupAdd(null, 1, &info, out _);
            if (rc is not (NERR_Success or NERR_GroupExists or ERROR_ALIAS_EXISTS))
                throw new LocalAccountException($"create group {_managedGroup}: {rc}", (int)rc);
        }
    }

    public LocalAccount? Find(string name)
    {
        IntPtr buf;
        uint rc;
        fixed (char* n = name) rc = NetUserGetInfo(null, n, 2, out buf);
        if (rc == NERR_UserNotFound) return null;
        if (rc != NERR_Success) throw new LocalAccountException($"get {name}: {rc}", (int)rc);
        try
        {
            var info = (USER_INFO_2*)buf;
            var groups = LocalGroupsOf(name);
            var expires = info->usri2_acct_expires == TIMEQ_FOREVER
                ? (DateTimeOffset?)null
                : DateTimeOffset.FromUnixTimeSeconds(info->usri2_acct_expires);
            return new LocalAccount(
                new string(info->usri2_name),
                IsManaged: groups.Contains(_managedGroup, StringComparer.OrdinalIgnoreCase),
                Enabled: (info->usri2_flags & UF_ACCOUNTDISABLE) == 0,
                IsAdmin: groups.Contains(_administrators, StringComparer.OrdinalIgnoreCase),
                Expires: expires);
        }
        finally
        {
            _ = NetApiBufferFree(buf);
        }
    }

    private List<string> LocalGroupsOf(string name)
    {
        IntPtr buf;
        uint rc, read;
        fixed (char* n = name) rc = NetUserGetLocalGroups(null, n, 0, 0, out buf, MAX_PREFERRED_LENGTH, out read, out _);
        if (rc != NERR_Success) throw new LocalAccountException($"groups of {name}: {rc}", (int)rc);
        try
        {
            var list = new List<string>((int)read);
            var entries = (LOCALGROUP_USERS_INFO_0*)buf;
            for (var i = 0; i < read; i++) list.Add(new string(entries[i].lgrui0_name));
            return list;
        }
        finally
        {
            _ = NetApiBufferFree(buf);
        }
    }

    public IReadOnlyList<LocalAccount> ListManaged()
    {
        var names = new List<string>();
        IntPtr buf;
        uint rc, read;
        fixed (char* g = _managedGroup) rc = NetLocalGroupGetMembers(null, g, 1, out buf, MAX_PREFERRED_LENGTH, out read, out _, null);
        if (rc != NERR_Success) throw new LocalAccountException($"members of {_managedGroup}: {rc}", (int)rc);
        try
        {
            var entries = (LOCALGROUP_MEMBERS_INFO_1*)buf;
            for (var i = 0; i < read; i++)
                if (entries[i].lgrmi1_sidusage == SidTypeUser) names.Add(new string(entries[i].lgrmi1_name));
        }
        finally
        {
            _ = NetApiBufferFree(buf);
        }
        return names.Select(Find).OfType<LocalAccount>().ToList();
    }

    public void Create(string name, ReadOnlySpan<char> password)
    {
        var pw = Terminated(password);
        try
        {
            fixed (char* n = name)
            fixed (char* p = pw)
            {
                var info = new USER_INFO_1
                {
                    usri1_name = n,
                    usri1_password = p,
                    usri1_priv = USER_PRIV_USER,
                    usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE,
                };
                var rc = NetUserAdd(null, 1, &info, out _);
                if (rc != NERR_Success) throw new LocalAccountException($"create {name}: {rc}", (int)rc);
            }
        }
        finally
        {
            Zero(pw);
        }
        // Mark it managed straight away, so a failure below still leaves it recognisably ours.
        AddMember(_managedGroup, name);
        EnsureUser(name);
    }

    public void SetPassword(string name, ReadOnlySpan<char> password)
    {
        RequireManaged(name);
        var pw = Terminated(password);
        try
        {
            fixed (char* p = pw)
            {
                var info = p; // USER_INFO_1003 = { LPWSTR password }
                SetInfo(name, 1003, &info);
            }
        }
        finally
        {
            Zero(pw);
        }
        // FR-5: password never expires, user cannot change it.
        UpdateFlags(name, set: UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE, clear: 0);
    }

    public void SetEnabled(string name, bool enabled)
    {
        RequireManaged(name);
        UpdateFlags(name, set: enabled ? 0 : UF_ACCOUNTDISABLE, clear: enabled ? UF_ACCOUNTDISABLE : 0);
    }

    public void SetExpiry(string name, DateTimeOffset? expires)
    {
        RequireManaged(name);
        var value = expires is { } e ? (uint)Math.Clamp(e.ToUnixTimeSeconds(), 1, uint.MaxValue - 1) : TIMEQ_FOREVER;
        SetInfo(name, 1017, &value); // USER_INFO_1017 = { DWORD acct_expires }
    }

    public void SetAdmin(string name, bool admin)
    {
        RequireManaged(name);
        if (admin) AddMember(_administrators, name);
        else RemoveMember(_administrators, name);
    }

    public void EnsureUser(string name)
    {
        RequireManaged(name);
        AddMember(_users, name);
    }

    private void RequireManaged(string name)
    {
        var account = Find(name) ?? throw new LocalAccountException($"{name} not found");
        if (!account.IsManaged) throw new LocalAccountException($"{name} is not in {_managedGroup}; refusing to change it");
    }

    private void UpdateFlags(string name, uint set, uint clear)
    {
        IntPtr buf;
        uint rc;
        fixed (char* n = name) rc = NetUserGetInfo(null, n, 2, out buf);
        if (rc != NERR_Success) throw new LocalAccountException($"get {name}: {rc}", (int)rc);
        uint flags;
        try
        {
            flags = ((USER_INFO_2*)buf)->usri2_flags;
        }
        finally
        {
            _ = NetApiBufferFree(buf);
        }
        var updated = (flags | set) & ~clear;
        if (updated != flags) SetInfo(name, 1008, &updated); // USER_INFO_1008 = { DWORD flags }
    }

    private static void SetInfo(string name, uint level, void* info)
    {
        uint rc;
        fixed (char* n = name) rc = NetUserSetInfo(null, n, level, info, out _);
        if (rc != NERR_Success) throw new LocalAccountException($"set {name} level {level}: {rc}", (int)rc);
    }

    private static void AddMember(string group, string user)
    {
        var qualified = $"{Environment.MachineName}\\{user}";
        uint rc;
        fixed (char* g = group)
        fixed (char* u = qualified)
        {
            var member = new LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname = u };
            rc = NetLocalGroupAddMembers(null, g, 3, &member, 1);
        }
        if (rc is not (NERR_Success or ERROR_MEMBER_IN_ALIAS))
            throw new LocalAccountException($"add {user} to {group}: {rc}", (int)rc);
    }

    private static void RemoveMember(string group, string user)
    {
        var qualified = $"{Environment.MachineName}\\{user}";
        uint rc;
        fixed (char* g = group)
        fixed (char* u = qualified)
        {
            var member = new LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname = u };
            rc = NetLocalGroupDelMembers(null, g, 3, &member, 1);
        }
        if (rc is not (NERR_Success or ERROR_MEMBER_NOT_IN_ALIAS))
            throw new LocalAccountException($"remove {user} from {group}: {rc}", (int)rc);
    }

    private static char[] Terminated(ReadOnlySpan<char> value)
    {
        var buffer = GC.AllocateArray<char>(value.Length + 1, pinned: true);
        value.CopyTo(buffer);
        return buffer;
    }

    private static void Zero(char[] buffer) => CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));
}
