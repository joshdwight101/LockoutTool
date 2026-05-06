using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace LockoutHybrid;

internal static class Program
{
    private static int Main(string[] args)
    {
        var command = args.Length == 0 ? "help" : args[0].ToLowerInvariant();

        using var runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();

        ExecuteBootstrap(runspace);

        return command switch
        {
            "list-dcs" => ListDomainControllers(runspace),
            "search-locked" => SearchLockedUsers(runspace),
            "unlock" => UnlockUsers(runspace, args.Skip(1).ToArray()),
            _ => ShowHelp()
        };
    }

    private static void ExecuteBootstrap(Runspace runspace)
    {
        using var ps = PowerShell.Create();
        ps.Runspace = runspace;
        ps.AddCommand("Import-Module").AddArgument("ActiveDirectory");
        ps.Invoke();
        ps.Commands.Clear();
        if (ps.HadErrors)
        {
            throw new InvalidOperationException("ActiveDirectory module failed to load.");
        }
    }

    private static int ListDomainControllers(Runspace runspace)
    {
        using var ps = PowerShell.Create();
        ps.Runspace = runspace;
        ps.AddScript("Get-ADDomainController -Filter * | Select-Object HostName,Site,IsGlobalCatalog,IsReadOnly");
        var results = ps.Invoke();
        PrintObjects(results);
        return ps.HadErrors ? 1 : 0;
    }

    private static int SearchLockedUsers(Runspace runspace)
    {
        using var ps = PowerShell.Create();
        ps.Runspace = runspace;
        ps.AddScript(@"
            Search-ADAccount -LockedOut -UsersOnly |
            Select-Object SamAccountName, UserPrincipalName, DistinguishedName
        ");

        var results = ps.Invoke();
        PrintObjects(results);
        return ps.HadErrors ? 1 : 0;
    }

    private static int UnlockUsers(Runspace runspace, IReadOnlyCollection<string> usernames)
    {
        if (usernames.Count == 0)
        {
            Console.WriteLine("Provide one or more sAMAccountName values.");
            return 1;
        }

        using var ps = PowerShell.Create();
        ps.Runspace = runspace;

        ps.AddScript(@"
            param([string[]]$Users)
            $accounts = $Users | ForEach-Object { Get-ADUser -Identity $_ }
            $accounts | Unlock-ADAccount -WhatIf
            $accounts | Select-Object SamAccountName, DistinguishedName
        ").AddParameter("Users", usernames.ToArray());

        var results = ps.Invoke();
        Console.WriteLine("Preview mode (-WhatIf) executed. Remove -WhatIf in script for commit workflow.");
        PrintObjects(results);
        return ps.HadErrors ? 1 : 0;
    }

    private static void PrintObjects(Collection<PSObject> results)
    {
        foreach (var result in results)
        {
            var properties = result.Properties
                .Where(p => p.Value is not null)
                .Select(p => $"{p.Name}={p.Value}");
            Console.WriteLine(string.Join(" | ", properties));
        }
    }

    private static int ShowHelp()
    {
        Console.WriteLine("LockoutHybrid usage:");
        Console.WriteLine("  list-dcs              Discover domain controllers using AD module");
        Console.WriteLine("  search-locked         List currently locked user accounts");
        Console.WriteLine("  unlock user1 user2    Preview bulk unlock operation");
        return 0;
    }
}
