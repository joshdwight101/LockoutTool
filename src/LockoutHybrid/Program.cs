using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Windows.Forms;

namespace LockoutHybrid;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

internal sealed class MainForm : Form
{
    private readonly TextBox _identity = new() { PlaceholderText = "user@contoso.com or samAccountName", Width = 320 };
    private readonly TextBox _search = new() { PlaceholderText = "search locked users", Width = 220 };
    private readonly TextBox _users = new() { PlaceholderText = "user1,user2", Width = 220 };
    private readonly NumericUpDown _hours = new() { Minimum = 1, Maximum = 72, Value = 8, Width = 80 };
    private readonly TextBox _output = new() { Multiline = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill };

    public MainForm()
    {
        Text = "Lockout Intelligence - C# GUI | Author: Joshua Dwight (@joshdwight101)";
        Width = 1200;
        Height = 760;

        var panel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 120, AutoScroll = true };
        panel.Controls.AddRange([
            Labeled("Identity", _identity),
            Labeled("Search", _search),
            Labeled("Users", _users),
            Labeled("Hours", _hours),
            Btn("Discover DCs", () => Exec("Get-ADDomainController -Filter * | select HostName,Site,IsReadOnly,IsGlobalCatalog")),
            Btn("Locked Users", () => Exec("Search-ADAccount -LockedOut -UsersOnly | select SamAccountName,UserPrincipalName")),
            Btn("Analyze", Analyze),
            Btn("Connect Cloud", () => Exec("Import-Module Microsoft.Graph.Authentication; Import-Module Microsoft.Graph.Reports; Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All' -NoWelcome")),
            Btn("Cloud Sign-ins", Cloud),
            Btn("Unlock Preview", () => Unlock(false)),
            Btn("Unlock Commit", () => Unlock(true))
        ]);

        Controls.Add(_output);
        Controls.Add(panel);
    }

    Control Labeled(string text, Control ctrl)
    {
        var p = new Panel { Width = ctrl.Width + 10, Height = 60 };
        p.Controls.Add(new Label { Text = text, Dock = DockStyle.Top });
        ctrl.Top = 20;
        p.Controls.Add(ctrl);
        return p;
    }

    Button Btn(string text, Action action)
    {
        var b = new Button { Text = text, Width = 130, Height = 34 };
        b.Click += (_, _) => action();
        return b;
    }

    void Analyze()
    {
        if (string.IsNullOrWhiteSpace(_identity.Text)) { _output.Text = "Identity required."; return; }
        var script = $"$ids=4740,4771,4776,4625,4767;$s=(Get-Date).AddHours(-{(int)_hours.Value});foreach($dc in Get-ADDomainController -Filter *){{foreach($id in $ids){{Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{{LogName='Security';Id=$id;StartTime=$s}} -ErrorAction SilentlyContinue|?{{$_.Message -match [regex]::Escape('{_identity.Text}')}}|select TimeCreated,Id,MachineName}}}}";
        Exec(script);
    }

    void Cloud()
    {
        if (string.IsNullOrWhiteSpace(_identity.Text)) { _output.Text = "Identity required."; return; }
        var start = DateTime.UtcNow.AddHours(-(int)_hours.Value).ToString("o");
        Exec($"$f=\"userPrincipalName eq '{_identity.Text}' and createdDateTime ge {start}\"; Get-MgAuditLogSignIn -Filter $f -Top 100 | select CreatedDateTime,AppDisplayName,IPAddress,Status");
    }

    void Unlock(bool commit)
    {
        var users = _users.Text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (users.Length == 0) { _output.Text = "Users required."; return; }
        var arr = string.Join("','", users);
        Exec(commit
            ? $"@('{arr}') | %{{Get-ADUser -Identity $_}} | Unlock-ADAccount -Confirm:$false"
            : $"@('{arr}') | %{{Get-ADUser -Identity $_}} | Unlock-ADAccount -WhatIf");
    }

    void Exec(string script)
    {
        try
        {
            using var rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            using var ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript("Import-Module ActiveDirectory -ErrorAction Stop");
            ps.Invoke();
            ps.Commands.Clear();
            ps.AddScript(script);
            var results = ps.Invoke();
            var sb = new StringBuilder();
            foreach (var r in results)
                sb.AppendLine(string.Join(" | ", r.Properties.Where(p => p.Value is not null).Select(p => $"{p.Name}={p.Value}")));
            if (ps.Streams.Error.Count > 0)
                foreach (var e in ps.Streams.Error) sb.AppendLine("ERROR: " + e);
            _output.Text = sb.ToString();
        }
        catch (Exception ex)
        {
            _output.Text = "ERROR: " + ex.Message;
        }
    }
}
