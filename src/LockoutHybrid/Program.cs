using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace LockoutHybrid;

internal static class Program
{
    private static int Main(string[] args)
    {
        var cmd = HybridCommand.Parse(args);
        if (cmd.ShowHelp)
        {
            HybridCommand.PrintHelp();
            return 0;
        }

        using var runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();
        EnsureAdModule(runspace);

        return cmd.Mode switch
        {
            "discover" => Discover(runspace),
            "locked" => Locked(runspace, cmd.Search),
            "analyze" => Analyze(runspace, cmd.Identity, cmd.Hours),
            "connect-cloud" => ConnectCloud(runspace),
            "cloud-signins" => CloudSignins(runspace, cmd.Identity, cmd.Hours),
            "investigate" => Investigate(runspace, cmd.Identity, cmd.Hours),
            "unlock-preview" => Unlock(runspace, cmd.Users, false),
            "unlock-commit" => Unlock(runspace, cmd.Users, true),
            "export" => Export(runspace, cmd.Identity, cmd.Hours, cmd.Output),
            _ => 1
        };
    }

    static void EnsureAdModule(Runspace rs)
    {
        using var ps = PowerShell.Create(); ps.Runspace = rs;
        ps.AddScript("Import-Module ActiveDirectory -ErrorAction Stop"); ps.Invoke();
        if (ps.HadErrors) throw new InvalidOperationException("ActiveDirectory module required.");
    }

    static int Discover(Runspace rs) => InvokeAndPrint(rs, "Get-ADDomainController -Filter * | select HostName,Site,IsReadOnly,IsGlobalCatalog,IPv4Address");
    static int Locked(Runspace rs, string? search)
    {
        var script = "Search-ADAccount -LockedOut -UsersOnly | Get-ADUser -Properties LockedOut,BadLogonCount,LastBadPasswordAttempt,LastLogonDate | select SamAccountName,UserPrincipalName,LockedOut,BadLogonCount,LastBadPasswordAttempt,LastLogonDate";
        return InvokeAndPrint(rs, script, o => string.IsNullOrWhiteSpace(search) || (o.Properties["SamAccountName"].Value?.ToString() ?? "").Contains(search, StringComparison.OrdinalIgnoreCase));
    }

    static int Analyze(Runspace rs, string? identity, int hours)
    {
        if (string.IsNullOrWhiteSpace(identity)) return Fail("--identity required");
        var events = GetOnPremEvents(rs, identity, hours);
        Console.WriteLine(BuildNarrative(identity, events));
        return 0;
    }

    static int ConnectCloud(Runspace rs)
        => InvokeAndPrint(rs, "Import-Module Microsoft.Graph.Authentication -ErrorAction Stop; Import-Module Microsoft.Graph.Reports -ErrorAction Stop; Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All' -NoWelcome");

    static int CloudSignins(Runspace rs, string? identity, int hours)
    {
        if (string.IsNullOrWhiteSpace(identity)) return Fail("--identity required");
        var start = DateTime.UtcNow.AddHours(-hours).ToString("o");
        var script = $"$f=\"userPrincipalName eq '{identity}' and createdDateTime ge {start}\"; Get-MgAuditLogSignIn -Filter $f -Top 100 | select CreatedDateTime,UserPrincipalName,AppDisplayName,IPAddress,ClientAppUsed,Status";
        return InvokeAndPrint(rs, script);
    }

    static int Investigate(Runspace rs, string? identity, int hours)
    {
        if (string.IsNullOrWhiteSpace(identity)) return Fail("--identity required");
        var events = GetOnPremEvents(rs, identity, hours);
        Console.WriteLine(BuildNarrative(identity, events));
        Console.WriteLine("\nCloud sign-ins:");
        CloudSignins(rs, identity, hours);
        return 0;
    }

    static int Unlock(Runspace rs, List<string> users, bool commit)
    {
        if (users.Count == 0) return Fail("--users required");
        var joined = string.Join("','", users);
        var cmd = commit
            ? $"@('{joined}') | % {{ Get-ADUser -Identity $_ }} | Unlock-ADAccount -Confirm:$false"
            : $"@('{joined}') | % {{ Get-ADUser -Identity $_ }} | Unlock-ADAccount -WhatIf";
        return InvokeAndPrint(rs, cmd);
    }

    static int Export(Runspace rs, string? identity, int hours, string output)
    {
        if (string.IsNullOrWhiteSpace(identity)) return Fail("--identity required");
        var events = GetOnPremEvents(rs, identity, hours);
        var report = new { User = identity, GeneratedUtc = DateTime.UtcNow, Narrative = BuildNarrative(identity, events), OnPremEvents = events.Take(50).ToList() };
        File.WriteAllText(output, System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Report written: {output}");
        return 0;
    }

    static List<Dictionary<string, string>> GetOnPremEvents(Runspace rs, string identity, int hours)
    {
        var script = $@"
$ids=4740,4771,4776,4625,4767
$start=(Get-Date).AddHours(-{hours})
foreach($dc in Get-ADDomainController -Filter *) {{
 foreach($id in $ids) {{
  Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{{LogName='Security';Id=$id;StartTime=$start}} -ErrorAction SilentlyContinue |
   ? {{ $_.Message -match [regex]::Escape('{identity}') }} |
   select @{n='SourceDC';e={{$dc.HostName}}},TimeCreated,Id,MachineName,Message
 }}
}}
";
        using var ps = PowerShell.Create(); ps.Runspace = rs; ps.AddScript(script);
        var rows = ps.Invoke();
        return rows.Select(r => r.Properties.ToDictionary(p => p.Name, p => p.Value?.ToString() ?? "")).ToList();
    }

    static string BuildNarrative(string identity, List<Dictionary<string, string>> events)
    {
        var ids = events.Select(e => int.TryParse(e.GetValueOrDefault("Id"), out var v) ? v : 0).ToList();
        var sb = new StringBuilder();
        sb.AppendLine($"Lockout Intelligence Report for {identity}");
        sb.AppendLine($"4740={ids.Count(i=>i==4740)}, 4771={ids.Count(i=>i==4771)}, 4776={ids.Count(i=>i==4776)}, 4625={ids.Count(i=>i==4625)}, 4767={ids.Count(i=>i==4767)}");
        sb.AppendLine(ids.Contains(4771) && events.Any(e=>e.GetValueOrDefault("Message").Contains("0x18",StringComparison.OrdinalIgnoreCase))
            ? "Likely cause: Kerberos bad-password retry pattern."
            : ids.Contains(4776) ? "Likely cause: NTLM retry pattern." : ids.Contains(4625) ? "Likely cause: endpoint/service credential issue." : "Likely cause: undetermined.");
        return sb.ToString();
    }

    static int InvokeAndPrint(Runspace rs, string script, Func<PSObject, bool>? filter = null)
    {
        using var ps = PowerShell.Create(); ps.Runspace = rs; ps.AddScript(script);
        var rows = ps.Invoke();
        foreach (var r in rows.Where(x => filter?.Invoke(x) ?? true))
            Console.WriteLine(string.Join(" | ", r.Properties.Where(p => p.Value is not null).Select(p => $"{p.Name}={p.Value}")));
        return ps.HadErrors ? 1 : 0;
    }

    static int Fail(string m) { Console.WriteLine(m); return 1; }
}

internal sealed class HybridCommand
{
    public string Mode { get; set; } = "investigate";
    public string? Identity { get; set; }
    public string? Search { get; set; }
    public int Hours { get; set; } = 8;
    public string Output { get; set; } = "lockout-report.json";
    public List<string> Users { get; } = [];
    public bool ShowHelp { get; set; }

    public static HybridCommand Parse(string[] args)
    {
        var c = new HybridCommand();
        for (int i=0;i<args.Length;i++)
        {
            switch(args[i].ToLowerInvariant())
            {
                case "discover": case "locked": case "analyze": case "connect-cloud": case "cloud-signins": case "investigate": case "unlock-preview": case "unlock-commit": case "export": c.Mode=args[i].ToLowerInvariant(); break;
                case "--identity": c.Identity=args[++i]; break;
                case "--search": c.Search=args[++i]; break;
                case "--hours": c.Hours=int.Parse(args[++i]); break;
                case "--users": c.Users.AddRange(args[++i].Split(',',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries)); break;
                case "--output": c.Output=args[++i]; break;
                case "-h": case "--help": c.ShowHelp=true; break;
            }
        }
        return c;
    }

    public static void PrintHelp()
    {
        Console.WriteLine("Modes: discover | locked | analyze | connect-cloud | cloud-signins | investigate | unlock-preview | unlock-commit | export");
    }
}
