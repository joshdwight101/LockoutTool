using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Diagnostics.Eventing.Reader;

namespace LockoutPureCSharp;

internal static class Program
{
    private static int Main(string[] args)
    {
        var command = args.Length == 0 ? "help" : args[0].ToLowerInvariant();
        return command switch
        {
            "list-dcs" => ListDomainControllers(),
            "search-locked" => SearchLockedUsers(),
            "events" => FetchLockoutEvents(args.Skip(1).FirstOrDefault() ?? "*"),
            "unlock" => UnlockUsers(args.Skip(1).ToArray()),
            _ => ShowHelp()
        };
    }

    private static int ListDomainControllers()
    {
        var domain = Domain.GetCurrentDomain();
        foreach (DomainController dc in domain.DomainControllers)
        {
            Console.WriteLine($"{dc.Name} | Site={dc.SiteName} | Roles={dc.Roles}");
        }

        return 0;
    }

    private static int SearchLockedUsers()
    {
        using var context = new PrincipalContext(ContextType.Domain);
        using var userFilter = new UserPrincipal(context);
        using var searcher = new PrincipalSearcher(userFilter);

        foreach (var result in searcher.FindAll().OfType<UserPrincipal>())
        {
            if (!result.IsAccountLockedOut())
            {
                continue;
            }

            Console.WriteLine($"{result.SamAccountName} | {result.UserPrincipalName} | LockedOut=True");
        }

        return 0;
    }

    private static int UnlockUsers(IReadOnlyCollection<string> usernames)
    {
        if (usernames.Count == 0)
        {
            Console.WriteLine("Provide one or more sAMAccountName values.");
            return 1;
        }

        using var context = new PrincipalContext(ContextType.Domain);
        foreach (var username in usernames)
        {
            using var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);
            if (user is null)
            {
                Console.WriteLine($"Not found: {username}");
                continue;
            }

            if (!user.IsAccountLockedOut())
            {
                Console.WriteLine($"Already unlocked: {username}");
                continue;
            }

            user.UnlockAccount();
            Console.WriteLine($"Unlocked: {username}");
        }

        return 0;
    }

    private static int FetchLockoutEvents(string username)
    {
        var query = "*[System[(EventID=4740 or EventID=4771 or EventID=4776 or EventID=4625 or EventID=4767)]]";
        var eventQuery = new EventLogQuery("Security", PathType.LogName, query)
        {
            ReverseDirection = true
        };

        using var reader = new EventLogReader(eventQuery);
        var count = 0;

        for (EventRecord? record = reader.ReadEvent(); record != null && count < 200; record = reader.ReadEvent())
        {
            var xml = record.ToXml();
            if (username != "*" && !xml.Contains(username, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            Console.WriteLine($"{record.TimeCreated:u} | EventId={record.Id} | Machine={record.MachineName}");
            count++;
        }

        return 0;
    }

    private static int ShowHelp()
    {
        Console.WriteLine("LockoutPureCSharp usage:");
        Console.WriteLine("  list-dcs              Discover domain controllers in current domain");
        Console.WriteLine("  search-locked         Enumerate locked users via PrincipalSearcher");
        Console.WriteLine("  events [username]     Read lockout-related Security events");
        Console.WriteLine("  unlock user1 user2    Unlock one or more accounts");
        return 0;
    }
}
