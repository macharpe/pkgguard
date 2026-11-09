// The oracle for packages/core/src/version/go.ts and parse/go.ts: Go's own golang.org/x/mod.
//
//	npx tsx scripts/oracles/go-versions-input.ts /tmp/go-versions.txt /tmp/go-names.txt
//	(cd scripts/oracles/go-version && go run . /tmp/go-names.txt < /tmp/go-versions.txt) \
//	  > packages/core/test/fixtures/go-version-oracle.json
//
// Reads one version string per line on stdin, as OSV writes them (no leading "v"; the oracle adds it). Writes JSON: pairs that
// are neighbours in Go's own ordering, pairs chosen at random (a fixed seed, so the file is reproducible), a hand-picked list of
// the cases that are easy to get wrong, the strings semver refuses, how the proxy escapes each module path in the file given as
// the first argument, which of those paths CheckPath accepts, and how it escapes the versions that contain a capital. A pair is
// "a|b|c" where c is -1, 0 or 1. CI never runs this: the result is committed.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

func lines(r *bufio.Scanner) []string {
	var out []string
	seen := map[string]bool{}
	for r.Scan() {
		l := strings.TrimSpace(r.Text())
		if l != "" && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	all := lines(in)
	var valid, refusedFeed []string
	for _, l := range all {
		if semver.IsValid("v" + l) {
			valid = append(valid, l)
		} else {
			refusedFeed = append(refusedFeed, l)
		}
	}
	cmp := func(a, b string) int { return semver.Compare("v"+a, "v"+b) }
	pair := func(a, b string) string { return fmt.Sprintf("%s|%s|%d", a, b, cmp(a, b)) }

	ordered := append([]string(nil), valid...)
	sort.SliceStable(ordered, func(i, j int) bool { return cmp(ordered[i], ordered[j]) < 0 })
	step := len(ordered) / 2500
	if step < 1 {
		step = 1
	}
	var adjacent []string
	for i := 0; i+1 < len(ordered) && len(adjacent) < 2500; i += step {
		adjacent = append(adjacent, pair(ordered[i], ordered[i+1]))
	}
	rng := rand.New(rand.NewSource(20261109))
	var random []string
	for i := 0; i < 2500; i++ {
		random = append(random, pair(valid[rng.Intn(len(valid))], valid[rng.Intn(len(valid))]))
	}

	hand := [][2]string{
		{"1", "1.0.0"}, {"1.2", "1.2.0"}, {"1.2", "1.2.1"}, {"1.0", "1"}, {"0.46", "0.46.0"}, {"136", "136.0.0"},
		{"1.0.0+incompatible", "1.0.0"}, {"2.0.0+incompatible", "2.0.0+incompatible"}, {"2.0.0+a", "2.0.0+b"},
		{"0.0.0-20210101000000-0123456789ab", "0.0.0-20210101000000-0123456789ac"}, {"0.0.0-20210101000000-abcdefabcdef", "0.0.0"},
		{"1.0.0-rc.1", "1.0.0-rc.2"}, {"1.0.0-rc.10", "1.0.0-rc.2"}, {"1.0.0-alpha", "1.0.0-alpha.1"}, {"1.0.0-1", "1.0.0-a"},
		{"1.0.0-rc1", "1.0.0"}, {"1.0.0-RC", "1.0.0-rc"}, {"1.0.0-a-b", "1.0.0-a.b"}, {"1.0.0--a", "1.0.0-a"},
		{"10.0.0", "9.0.0"}, {"1.10.0", "1.9.0"}, {"1.0.10", "1.0.9"}, {"1.0.0-0", "1.0.0-1"},
		{"99999999999999999999.0.0", "99999999999999999998.0.0"}, {"1.0.0-99999999999999999999", "1.0.0-99999999999999999998"},
	}
	var handpicked []string
	for _, p := range hand {
		if semver.IsValid("v"+p[0]) && semver.IsValid("v"+p[1]) {
			handpicked = append(handpicked, pair(p[0], p[1]))
		}
	}

	probes := []string{"", "v", "1.", ".1", "1..0", "1.2.3.4", "01.0.0", "1.02.0", "1.0.03", "1.0.0-01", "1.0.0-", "1.0.0+", "1.0-rc1", "1-rc1",
		"1+b", "1.0+b", "1.0.0-a..b", "1.0.0-é", "v1.0.0", "1.0.0-a_b", "1.0.0+a..b", "1.0.0 ", " 1.0.0", "1.0.0-0", "1.0.0-00", "1.2.3-", "x.y.z", "1.0.0-a+b+c", "1.0.0+a_b", "1.0.0+a-b", "1.0.0-a.b+c.d", "1.0.0+é"}
	var refused []string
	for _, p := range probes {
		if !semver.IsValid("v" + p) {
			refused = append(refused, p)
		}
	}

	type esc struct {
		Name      string `json:"name"`
		Escaped   string `json:"escaped"`
		CheckPath bool   `json:"checkPath"`
	}
	var paths []esc
	var unescapable []string
	if len(os.Args) > 1 {
		f, err := os.Open(os.Args[1])
		if err != nil {
			panic(err)
		}
		sc := bufio.NewScanner(f)
		for _, name := range lines(sc) {
			e, err := module.EscapePath(name)
			if err != nil {
				unescapable = append(unescapable, name)
				continue
			}
			paths = append(paths, esc{name, e, module.CheckPath(name) == nil})
		}
	}
	var versionEsc [][2]string
	for _, v := range all {
		if strings.ContainsAny(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && semver.IsValid("v"+v) {
			if e, err := module.EscapeVersion("v" + v); err == nil {
				versionEsc = append(versionEsc, [2]string{"v" + v, e})
			}
		}
	}

	out := map[string]any{
		"generatedWith":    fmt.Sprintf("go %s / golang.org/x/mod", goVersion()),
		"feedVersions":     len(valid),
		"feedRefusedByGo":  refusedFeed,
		"adjacent":         adjacent,
		"random":           random,
		"handpicked":       handpicked,
		"refused":          refused,
		"paths":            paths,
		"unescapablePaths": unescapable,
		"versionEscapes":   versionEsc,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
