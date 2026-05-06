using System.DirectoryServices.ActiveDirectory;
using System.Diagnostics.Eventing.Reader;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace LockoutHybrid;

internal static class Program
{
    private static readonly int[] InterestingEventIds = [4740, 4771, 4776, 4625, 4767];

    private static int Main(string[] args)
    {
        var parser = HybridCommand.Parse(args);
        if (parser.ShowHelp)
        {
            HybridCommand.PrintHelp();
            return 0;
        }

        using var runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();
        EnsureAdModule(runspace);

        return parser.Mode switch
        {
            HybridMode.Discover => DiscoverDomainControllers(runspace),
            HybridMode.LockedUsers => ListLockedUsers(runspace, parser.Search),
            HybridMode.Analyze => AnalyzeUser(runspace, parser.Identity),
            HybridMode.UnlockPreview => UnlockUsers(runspace, parser.Users, commit: false),
            HybridMode.UnlockCommit => UnlockUsers(runspace, parser.Users, commit: true),
            _ => 1
        };
    }

    private static void EnsureAdModule(Runspace runspace)
    {
        using var ps = PowerShell.Create();
        ps.Runspace = runspace;
        ps.AddCommand("Import-Module").AddArgument("ActiveDirectory");
        ps.Invoke();
        if (ps.HadErrors) throw new InvalidOperationException("ActiveDirectory module is required.");
    }

    private static int DiscoverDomainControllers(Runspace runspace)
    {
        var domain = Domain.GetCurrentDomain();
        Console.WriteLine($"Domain: {domain.Name}");
        using var ps = PowerShell.Create();
        ps.Runspace = runspace;
        ps.AddScript("Get-ADDomainController -Filter * | Select-Object HostName,Site,IsReadOnly,IsGlobalCatalog,IPv4Address");
        PrintPsObjects(ps.Invoke());
        return ps.HadErrors ? 1 : 0;
    }

    private static int ListLockedUsers(Runspace runspace, string? search)
    {
        using var ps = PowerShell.Create();
        ps.Runspace = runspace;
        ps.AddScript(@"
            Search-ADAccount -LockedOut -UsersOnly |
            Select-Object SamAccountName, UserPrincipalName, LastBadPasswordAttempt, LockedOut, DistinguishedName
        ");
        var rows = ps.Invoke();
        foreach (var row in rows)
        {
            var sam = row.Properties["SamAccountName"].Value?.ToString() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(search) && !sam.Contains(search, StringComparison.OrdinalIgnoreCase)) continue;
            PrintRow(row);
        }

        return ps.HadErrors ? 1 : 0;
    }

    private static int AnalyzeUser(Runspace runspace, string? identity)
    {
        if (string.IsNullOrWhiteSpace(identity))
        {
            Console.WriteLine("--identity is required for analyze mode.");
            return 1;
        }

        var events = QuerySecurityEvents(identity, TimeSpan.FromHours(8));
        var narrative = BuildNarrative(identity, events);
        Console.WriteLine(narrative);
        return 0;
    }

    private static int UnlockUsers(Runspace runspace, IReadOnlyList<string> users, bool commit)
    {
        if (users.Count == 0)
        {
            Console.WriteLine("Provide users with --users user1,user2");
            return 1;
        }

        using var ps = PowerShell.Create();
        ps.Runspace = runspace;
        var script = commit
            ? "$u | ForEach-Object { Get-ADUser -Identity $_ } | Unlock-ADAccount -Confirm:$false"
            : "$u | ForEach-Object { Get-ADUser -Identity $_ } | Unlock-ADAccount -WhatIf";
        ps.AddScript("param([string[]]$u) " + script).AddParameter("u", users.ToArray());
        ps.Invoke();
        Console.WriteLine(commit ? "Unlock commit complete." : "Unlock preview complete (-WhatIf).");
        return ps.HadErrors ? 1 : 0;
    }

    private static List<LockoutEvent> QuerySecurityEvents(string identity, TimeSpan window)
    {
        var start = DateTime.UtcNow.Subtract(window);
        var query = "*[System[(EventID=4740 or EventID=4771 or EventID=4776 or EventID=4625 or EventID=4767)]]";
        var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, query) { ReverseDirection = true });
        var output = new List<LockoutEvent>();

        for (EventRecord? record = reader.ReadEvent(); record != null; record = reader.ReadEvent())
        {
            if (record.TimeCreated is null || record.TimeCreated.Value.ToUniversalTime() < start) break;
            var xml = record.ToXml();
            if (!xml.Contains(identity, StringComparison.OrdinalIgnoreCase)) continue;
            output.Add(new LockoutEvent(record.Id, record.TimeCreated.Value, record.MachineName ?? "unknown", xml));
            if (output.Count > 300) break;
        }

        return output;
    }

    private static string BuildNarrative(string identity, IReadOnlyList<LockoutEvent> events)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Lockout Intelligence Report for {identity}");
        sb.AppendLine($"Evidence events: {events.Count}");

        var byId = events.GroupBy(x => x.EventId).ToDictionary(g => g.Key, g => g.Count());
        foreach (var id in InterestingEventIds)
        {
            sb.AppendLine($"  Event {id}: {(byId.TryGetValue(id, out var count) ? count : 0)}");
        }

        var likely = "No high-confidence cause detected.";
        if (events.Any(x => x.EventId == 4771 && x.RawXml.Contains("0x18", StringComparison.OrdinalIgnoreCase)))
            likely = "Likely Kerberos bad-password retry source (4771 with failure code 0x18).";
        else if (events.Any(x => x.EventId == 4776))
            likely = "Likely NTLM credential validation retries (4776 evidence found).";
        else if (events.Any(x => x.EventId == 4625))
            likely = "Likely endpoint/service/process logon failure pattern (4625 evidence found).";

        sb.AppendLine($"Probable cause: {likely}");
        sb.AppendLine("Recent timeline:");
        foreach (var e in events.OrderByDescending(x => x.TimeCreated).Take(20))
            sb.AppendLine($"  {e.TimeCreated:u} | {e.Machine} | EventID={e.EventId}");

        return sb.ToString();
    }

    private static void PrintPsObjects(System.Collections.ObjectModel.Collection<PSObject> results)
    {
        foreach (var r in results) PrintRow(r);
    }

    private static void PrintRow(PSObject row)
    {
        Console.WriteLine(string.Join(" | ", row.Properties.Where(p => p.Value is not null).Select(p => $"{p.Name}={p.Value}")));
    }

    private sealed record LockoutEvent(int EventId, DateTime TimeCreated, string Machine, string RawXml);
}

internal enum HybridMode { Discover, LockedUsers, Analyze, UnlockPreview, UnlockCommit }

internal sealed record HybridCommand
{
    public HybridMode Mode { get; init; } = HybridMode.LockedUsers;
    public string? Search { get; init; }
    public string? Identity { get; init; }
    public List<string> Users { get; init; } = [];
    public bool ShowHelp { get; init; }

    public static HybridCommand Parse(string[] args)
    {
        var cmd = new HybridCommand();
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "discover": cmd.Mode = HybridMode.Discover; break;
                case "locked": cmd.Mode = HybridMode.LockedUsers; break;
                case "analyze": cmd.Mode = HybridMode.Analyze; break;
                case "unlock-preview": cmd.Mode = HybridMode.UnlockPreview; break;
                case "unlock-commit": cmd.Mode = HybridMode.UnlockCommit; break;
                case "--search": cmd = cmd with { Search = args[++i] }; break;
                case "--identity": cmd = cmd with { Identity = args[++i] }; break;
                case "--users": cmd.Users.AddRange(args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)); break;
                case "-h":
                case "--help": return cmd with { ShowHelp = true };
            }
        }
        return cmd;
    }

    public static void PrintHelp()
    {
        Console.WriteLine("LockoutHybrid Intelligence");
        Console.WriteLine("  discover");
        Console.WriteLine("  locked [--search bob]");
        Console.WriteLine("  analyze --identity bob");
        Console.WriteLine("  unlock-preview --users bob,alice");
        Console.WriteLine("  unlock-commit --users bob,alice");
    }
}
