using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace USandbox;

/// <summary>One filtering rule. Every criterion that is set must match; rules are tried in order and the first match wins.</summary>
sealed class Rule
{
    public string? Name { get; set; }
    public bool Enabled { get; set; } = true;

    /// <summary>block, allow (stop checking further rules) or passthrough (do not decrypt TLS for this host).</summary>
    public string Action { get; set; } = "block";

    /// <summary>Host glob such as *.example.com; several can be separated by spaces or commas.</summary>
    public string? Host { get; set; }

    /// <summary>Regular expression matched against the full URL.</summary>
    public string? Url { get; set; }

    /// <summary>HTTP method, such as POST.</summary>
    public string? Method { get; set; }

    /// <summary>request, response or both. Used only by content criteria (contains / regex).</summary>
    public string Stage { get; set; } = "request";

    /// <summary>Where contains / regex look: any, headers or body.</summary>
    public string Target { get; set; } = "any";

    /// <summary>Case-insensitive text to look for.</summary>
    public string? Contains { get; set; }

    /// <summary>Regular expression to look for.</summary>
    public string? Regex { get; set; }

    [JsonIgnore] internal Regex? HostRegex, UrlRegex, ContentRegex;

    [JsonIgnore] internal bool HasContent => !string.IsNullOrEmpty(Contains) || !string.IsNullOrEmpty(Regex);
    [JsonIgnore] internal bool HostOnly => string.IsNullOrEmpty(Url) && string.IsNullOrEmpty(Method) && !HasContent;

    public string Describe() => Name ?? string.Join(' ', new[]
    {
        Action,
        Host is { Length: > 0 } ? $"host={Host}" : null,
        Url is { Length: > 0 } ? $"url~{Url}" : null,
        Method is { Length: > 0 } ? $"method={Method}" : null,
        Contains is { Length: > 0 } ? $"contains \"{Contains}\"" : null,
        Regex is { Length: > 0 } ? $"regex /{Regex}/" : null,
    }.Where(s => s != null));

    internal void Compile()
    {
        Action = Action.Trim().ToLowerInvariant();
        if (Action is not ("block" or "allow" or "passthrough")) throw new FormatException($"Rule \"{Describe()}\": action must be block, allow or passthrough.");
        Stage = Stage.Trim().ToLowerInvariant();
        if (Stage is not ("request" or "response" or "both")) throw new FormatException($"Rule \"{Describe()}\": stage must be request, response or both.");
        Target = Target.Trim().ToLowerInvariant();
        if (Target is not ("any" or "headers" or "body")) throw new FormatException($"Rule \"{Describe()}\": target must be any, headers or body.");

        HostRegex = string.IsNullOrWhiteSpace(Host) ? null : new Regex(
            "^(?:" + string.Join('|', Host.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(g => System.Text.RegularExpressions.Regex.Escape(g).Replace(@"\*", ".*").Replace(@"\?", "."))) + ")$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        UrlRegex = string.IsNullOrWhiteSpace(Url) ? null : Compile(Url, "url");
        ContentRegex = string.IsNullOrEmpty(Regex) ? null : Compile(Regex, "regex");
    }

    Regex Compile(string pattern, string field)
    {
        try { return new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)); }
        catch (ArgumentException e) { throw new FormatException($"Rule \"{Describe()}\": bad {field} pattern: {e.Message}"); }
    }
}

sealed class RuleSet
{
    public List<Rule> Rules { get; set; } = new();

    /// <summary>Request and response bodies up to this size are held back and checked before they are passed on.</summary>
    public int MaxInspectBytes { get; set; } = 8 * 1024 * 1024;

    static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static RuleSet Parse(string json)
    {
        var set = JsonSerializer.Deserialize<RuleSet>(json, Json) ?? new RuleSet();
        set.Rules ??= new();
        foreach (var rule in set.Rules) rule.Compile();
        return set;
    }

    public static RuleSet Load(string? path) => path != null && File.Exists(path) ? Parse(File.ReadAllText(path)) : new RuleSet();

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    IEnumerable<Rule> Active => Rules.Where(r => r.Enabled);

    public bool HasResponseContentRules => Active.Any(r => r.HasContent && r.Stage is "response" or "both");

    /// <summary>Decision for a new connection, before any HTTP is seen: block, allow, passthrough or null for no opinion.</summary>
    public Rule? MatchConnection(string host)
    {
        foreach (var rule in Active)
        {
            if (rule.HostRegex != null && !rule.HostRegex.IsMatch(host)) continue;
            if (rule.Action == "passthrough") return rule;
            if (rule.HostOnly) return rule;
            // A rule that needs the URL or content cannot decide yet; keep looking for a host-only one,
            // but an earlier "allow" for this host must not be overtaken by a later host-only block.
            if (rule.Action == "allow") return null;
        }
        return null;
    }

    /// <summary>First matching block/allow rule for a request, or for a response when <paramref name="response"/> is set.</summary>
    public Rule? MatchMessage(string host, string method, string url, string requestHeaders, Func<string> requestBody,
                              string? responseHeaders = null, Func<string>? responseBody = null)
    {
        bool isResponse = responseHeaders != null;
        foreach (var rule in Active)
        {
            if (rule.Action == "passthrough") continue;
            if (rule.HostRegex != null && !rule.HostRegex.IsMatch(host)) continue;
            if (rule.UrlRegex != null && !rule.UrlRegex.IsMatch(url)) continue;
            if (!string.IsNullOrEmpty(rule.Method) && !rule.Method.Equals(method, StringComparison.OrdinalIgnoreCase)) continue;

            if (rule.HasContent)
            {
                bool appliesHere = isResponse ? rule.Stage is "response" or "both" : rule.Stage is "request" or "both";
                if (!appliesHere) continue;
                string headers = isResponse ? responseHeaders! : requestHeaders;
                Func<string> body = isResponse ? responseBody! : requestBody;
                if (!ContentMatches(rule, headers, body)) continue;
            }
            else if (isResponse)
            {
                continue; // non-content rules were already decided when the request was checked
            }
            return rule;
        }
        return null;
    }

    static bool ContentMatches(Rule rule, string headers, Func<string> body)
    {
        bool Check(string text) =>
            (string.IsNullOrEmpty(rule.Contains) || text.Contains(rule.Contains, StringComparison.OrdinalIgnoreCase)) &&
            (rule.ContentRegex == null || SafeMatch(rule.ContentRegex, text));

        return rule.Target switch
        {
            "headers" => Check(headers),
            "body" => Check(body()),
            _ => Check(headers + "\r\n" + body()),
        };
    }

    static bool SafeMatch(Regex regex, string text)
    {
        try { return regex.IsMatch(text); }
        catch (RegexMatchTimeoutException) { return false; }
    }
}
