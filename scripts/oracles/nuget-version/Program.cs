// The oracle for packages/core/src/version/nuget.ts: NuGet's own NuGet.Versioning.
//
//   npx tsx scripts/oracles/nuget-versions-input.ts /tmp/nuget-versions.txt /tmp/nuget-names.txt
//   dotnet run --project scripts/oracles/nuget-version -- /tmp/nuget-names.txt < /tmp/nuget-versions.txt \
//     > packages/core/test/fixtures/nuget-version-oracle.json
//
// Reads one version string per line on stdin. Writes JSON: pairs that are neighbours in NuGet's own ordering, pairs chosen at
// random (a fixed seed, so the file is reproducible), a hand-picked list of the cases that are easy to get wrong, the strings
// NuGet refuses, and the lowercase form of every package name the file given as the first argument lists. A pair is "a|b|c"
// where c is -1, 0 or 1. CI never runs this: the result is committed.
using System.Text.Json;
using NuGet.Versioning;

var lines = Console.In.ReadToEnd().Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).Distinct().ToList();
var valid = new List<(string Text, NuGetVersion Version)>();
var feedRefused = new List<string>();
foreach (var l in lines)
{
    if (NuGetVersion.TryParse(l, out var v)) valid.Add((l, v)); else feedRefused.Add(l);
}

var cmp = VersionComparer.VersionRelease;
string Pair(string a, string b) => $"{a}|{b}|{Math.Sign(cmp.Compare(NuGetVersion.Parse(a), NuGetVersion.Parse(b)))}";

var ordered = valid.OrderBy(x => x.Version, cmp).ToList();
var rng = new Random(20261109);
var step = Math.Max(ordered.Count / 2500, 1);
var adjacent = Enumerable.Range(0, ordered.Count - 1).Where(i => i % step == 0).Select(i => Pair(ordered[i].Text, ordered[i + 1].Text)).Take(2500).ToList();
var random = Enumerable.Range(0, 2500).Select(_ => Pair(valid[rng.Next(valid.Count)].Text, valid[rng.Next(valid.Count)].Text)).ToList();

var handpicked = new (string, string)[]
{
    ("1.0", "1.0.0"), ("1.0.0", "1.0.0.0"), ("1", "1.0.0.0"), ("1.0.0.1", "1.0.0"), ("1.0.0.10", "1.0.0.9"),
    ("1.0.0-rc", "1.0.0-RC"), ("1.0.0-alpha", "1.0.0-ALPHA"), ("1.0.0-Beta", "1.0.0-alpha"), ("1.0.0-rc", "1.0.0"),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta"), ("1.0.0-alpha.10", "1.0.0-alpha.2"), ("1.0.0-alpha", "1.0.0-alpha.1"),
    ("1.0.0-1", "1.0.0-a"), ("1.0.0-01", "1.0.0-1"), ("1.0.0-2", "1.0.0-10"), ("1.0.0--a", "1.0.0-a"), ("1.0.0-a-b", "1.0.0-a.b"),
    ("1.0.0+build", "1.0.0"), ("1.0.0+a", "1.0.0+b"), ("1.0.0-rc+a", "1.0.0-rc"),
    ("10.02.0", "10.2.0"), ("03.02.01", "3.2.1"), ("1.05.374.54", "1.5.374.54"),
    ("1.2.6.62716-preview", "1.2.6.62716"), ("1.2.6.62716-preview", "1.2.6.62715"),
    ("2147483647.0.0", "2147483646.0.0"), ("1.0.0-99999999999999999999", "1.0.0-99999999999999999998"),
    ("1.0.0-preview.1", "1.0.0-preview"), ("1.0.0-preview.1.2", "1.0.0-preview.1"),
}.Where(p => NuGetVersion.TryParse(p.Item1, out _) && NuGetVersion.TryParse(p.Item2, out _)).Select(p => Pair(p.Item1, p.Item2)).ToList();

var probes = new[] { "", " ", "abc", "1.0.0.0.0", "1.0.0.", ".1.0", "1..0", "v1.0", "1.0.0-", "1.0.0+", "1.0.0-a..b", "1.-1.0", "1.0.0-a_b", "1.0.0 beta", "1.0.0-a+", "-1.0", "1.0.0-é", "１.０", "99999999999.0.0", "1.0.0.-1", "1.0.0-01", "1.0.0-a.01", "1.0.0-a.", "1.0.0-.a", "2147483648.0.0", "1.2147483648.0", "1.0.2147483648", "1.0.0.2147483648", "1.0.0-0", "1.0.0-00" };
var refused = probes.Where(p => !NuGetVersion.TryParse(p, out _) || p.Trim().Length == 0).ToList();

var nameFold = new List<string[]>();
if (args.Length > 0)
    foreach (var n in File.ReadAllLines(args[0]).Where(n => n.Length > 0).Distinct())
        nameFold.Add(new[] { n, n.ToLowerInvariant() });

Console.WriteLine(JsonSerializer.Serialize(new
{
    generatedWith = $"dotnet {Environment.Version} / NuGet.Versioning {typeof(NuGetVersion).Assembly.GetName().Version}",
    feedVersions = valid.Count,
    feedRefusedByNuGet = feedRefused,
    adjacent, random, handpicked, refused, nameFold,
}, new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
