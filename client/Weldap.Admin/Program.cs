using System.Security.Principal;
using Microsoft.Win32;
using Weldap;
using Weldap.Service;

// weldapadm: an elevated, local account lister/viewer/manager for WELDAP. It talks to the local SAM directly
// (through Weldap.Service), never over the service's locked-down pipe, so it adds no network surface. Every
// mutating verb is one of the operations the service itself uses, so behaviour matches the login/reconcile paths.
return Cli.Run(args);

internal static class Cli
{
    public static int Run(string[] args)
    {
        if (!IsElevated())
        {
            Console.Error.WriteLine("weldapadm must run as an administrator.");
            return 2;
        }
        if (args.Length == 0) return Usage();

        // Settings are best-effort: used only to mark excluded accounts and show policy. The account verbs work
        // without them, so a half-configured machine can still be inspected and repaired.
        LoginSettings? settings = null;
        try { settings = RegistrySettings.Load(); }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Console.Error.WriteLine($"note: settings unavailable ({ex.Message}); excluded accounts are not marked.");
        }

        var accounts = new LocalAccounts();
        var verb = args[0].ToLowerInvariant();
        string? name = args.Length > 1 ? args[1] : null;
        try
        {
            return verb switch
            {
                "list" => List(accounts, settings),
                "show" => Show(accounts, settings, Require(name, verb)),
                "adopt" => Do(accounts, Require(name, verb), a => a.Adopt(Require(name, verb)), "adopted into WELDAP-Managed"),
                "force-local" => ForceLocal(accounts, Require(name, verb), args),
                "enable" => Do(accounts, Require(name, verb), a => a.SetEnabled(Require(name, verb), true), "enabled"),
                "disable" => Do(accounts, Require(name, verb), a => a.SetEnabled(Require(name, verb), false), "disabled"),
                "set-admin" => SetAdmin(accounts, Require(name, verb), args),
                "lockdown" => Lockdown(settings, name),
                _ => Usage(),
            };
        }
        catch (LocalAccountException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 2;
        }
    }

    private static int List(LocalAccounts accounts, LoginSettings? settings)
    {
        Console.WriteLine($"{"NAME",-22} {"CLASS",-13} {"ENABLED",-8} {"ADMIN",-6} LAST LOGON");
        foreach (var a in accounts.ListAll().OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase))
            Console.WriteLine($"{a.Name,-22} {Classify(a, settings),-13} {YesNo(a.Enabled),-8} {YesNo(a.IsAdmin),-6} {LastLogon(a)}");
        return 0;
    }

    private static int Show(LocalAccounts accounts, LoginSettings? settings, string name)
    {
        if (accounts.Find(name) is not { } a)
        {
            Console.Error.WriteLine($"no local account '{name}'.");
            return 2;
        }
        Console.WriteLine($"name        {a.Name}");
        Console.WriteLine($"class       {Classify(a, settings)}");
        Console.WriteLine($"enabled     {YesNo(a.Enabled)}");
        Console.WriteLine($"admin       {YesNo(a.IsAdmin)}");
        Console.WriteLine($"managed     {YesNo(a.IsManaged)}");
        Console.WriteLine($"force-local {YesNo(a.IsForceLocal)}");
        Console.WriteLine($"expires     {(a.Expires is { } e ? e.UtcDateTime.ToString("u") : "never")}");
        Console.WriteLine($"last logon  {LastLogon(a)}");
        return 0;
    }

    private static int ForceLocal(LocalAccounts accounts, string name, string[] args)
    {
        var off = args.Contains("--off", StringComparer.OrdinalIgnoreCase);
        accounts.SetForceLocal(name, !off);
        Console.WriteLine($"{name}: {(off ? "removed from" : "added to")} {LoginSettings.ForceLocalGroup}.");
        return 0;
    }

    private static int SetAdmin(LocalAccounts accounts, string name, string[] args)
    {
        if (args.Length < 3 || args[2].ToLowerInvariant() is not ("on" or "off"))
        {
            Console.Error.WriteLine("usage: weldapadm set-admin <name> on|off");
            return 1;
        }
        var on = args[2].Equals("on", StringComparison.OrdinalIgnoreCase);
        accounts.SetAdmin(name, on);
        Console.WriteLine($"{name}: local admin {(on ? "granted" : "revoked")}.");
        return 0;
    }

    private static int Lockdown(LoginSettings? settings, string? action)
    {
        switch (action?.ToLowerInvariant())
        {
            case null or "status":
                var armed = ReadFlag("LockdownEnforce");
                Console.WriteLine($"lockdown enforcement : {(armed ? "ARMED (unknown accounts are disabled)" : "off (dry run: reported only)")}");
                Console.WriteLine($"adopt pre-existing   : {(settings?.AdoptPreexisting ?? true)}");
                Console.WriteLine($"idle-disable days    : {settings?.IdleDisableDays ?? 30}");
                return 0;
            case "arm":
                return WriteFlag("LockdownEnforce", true, "lockdown enforcement ARMED.");
            case "disarm":
                return WriteFlag("LockdownEnforce", false, "lockdown enforcement disarmed (dry run).");
            default:
                Console.Error.WriteLine("usage: weldapadm lockdown [status|arm|disarm]");
                return 1;
        }
    }

    private static int Do(LocalAccounts accounts, string name, Action<LocalAccounts> op, string done)
    {
        op(accounts);
        Console.WriteLine($"{name}: {done}.");
        return 0;
    }

    private static string Classify(LocalAccount a, LoginSettings? settings) =>
        settings?.IsExcluded(a.Name) == true ? "excluded"
        : a.IsForceLocal ? "force-local"
        : a.IsManaged ? "managed"
        : "unclassified";

    private static string YesNo(bool value) => value ? "yes" : "no";

    private static string LastLogon(LocalAccount a) => a.LastLogon is { } t ? t.UtcDateTime.ToString("u") : "never";

    private static bool ReadFlag(string name)
    {
        using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(RegistrySettings.KeyPath);
        return key?.GetValue(name) is int i && i != 0;
    }

    private static int WriteFlag(string name, bool value, string message)
    {
        using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(RegistrySettings.KeyPath, writable: true);
        if (key is null)
        {
            Console.Error.WriteLine($@"HKLM\{RegistrySettings.KeyPath} is missing; is WELDAP configured?");
            return 2;
        }
        key.SetValue(name, value ? 1 : 0, RegistryValueKind.DWord);
        Console.WriteLine(message);
        return 0;
    }

    private static string Require(string? name, string verb) =>
        name ?? throw new LocalAccountException($"'{verb}' needs an account name");

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int Usage()
    {
        Console.Error.WriteLine("""
            weldapadm — WELDAP local account manager (run as administrator)

              list                      all local accounts and how WELDAP classifies them
              show <name>               details for one account
              adopt <name>              bring a pre-existing account under WELDAP management
              force-local <name>        protect an account as a backup (always works locally)
              force-local <name> --off  stop protecting it
              enable  <name>            re-enable a managed account (e.g. one idle-disabled)
              disable <name>            disable a managed account
              set-admin <name> on|off   grant or revoke local admin on a managed account
              lockdown [status|arm|disarm]  show or set lockdown enforcement
            """);
        return 1;
    }
}
