#!/usr/bin/env ruby
# The oracle for packages/core/src/version/gem.ts: Ruby's own Gem::Version.
#
# It must be a CURRENT RubyGems. Before 3.1 `Gem::Version#<=>` compared raw segments, so `2.2.rc15 <=> 2.2.0.beta` is
# -1; since, it compares canonical segments (trailing zeros dropped) and the answer is 1. rubygems.org and current
# clients use the new rule, and so does the port. An old system Ruby is not an oracle: load a current version.rb
# standalone, from the official source, with that Ruby's own RubyGems switched off:
#
#   D=$(mktemp -d); mkdir $D/rubygems
#   for f in version deprecate; do curl -sf -o $D/rubygems/$f.rb https://raw.githubusercontent.com/rubygems/rubygems/v3.5.23/lib/rubygems/$f.rb; done
#   RUBYGEMS_TAG=v3.5.23 ruby --disable-gems -I $D scripts/oracles/gem-version.rb < /tmp/gem-versions.txt \
#     > packages/core/test/fixtures/gem-version-oracle.json
#
# Reads one version string per line. Writes, as JSON: pairs of versions that are neighbours in Ruby's own ordering, pairs
# chosen at random (a fixed seed, so the file is reproducible), a hand-picked list of the cases that are easy to get wrong,
# and strings Ruby refuses. A pair is "a|b|c" where c is -1, 0 or 1. CI never runs this: the result is committed.
require "json"
require "rubygems/version" unless defined?(Gem::Version)

lines = STDIN.read.split("\n").map(&:strip).reject(&:empty?).uniq
valid, invalid = lines.partition { |v| Gem::Version.correct?(v) }
versions = valid.map { |v| [v, Gem::Version.new(v)] }
ordered = versions.sort_by { |_, g| g }

pair = ->(a, b) { "#{a}|#{b}|#{Gem::Version.new(a) <=> Gem::Version.new(b)}" }
rng = Random.new(20_261_109)

# Neighbours in Ruby's order: where a wrong comparator is most likely to disagree.
step = [ordered.length / 2500, 1].max
adjacent = (0...(ordered.length - 1)).step(step).map { |i| pair.(ordered[i][0], ordered[i + 1][0]) }.first(2500)
random = Array.new(2500) { pair.(valid[rng.rand(valid.length)], valid[rng.rand(valid.length)]) }

handpicked = [
  %w[1.0 1], %w[1.0.0 1.0], %w[1.0.0.0 1], %w[0 0.0.0], %w[1.0 1.0.1],
  %w[1.0.0.pre 1.0.0], %w[1.0.0.pre 1.0.0.rc1], %w[1.0.0.a 1.0.0.pre], %w[1.0.0.rc1 1.0.0.rc2], %w[1.0.0.rc10 1.0.0.rc2],
  %w[1.0-rc1 1.0.pre.rc1], %w[1.0-rc1 1.0.0], %w[2.0.0-beta 2.0.0.beta], %w[1.0.pre 1.0.pre.0],
  %w[1.0.a 1.0.0], %w[1.0.a.1 1.0.a], %w[1.0.A 1.0.a], %w[1.0.Z 1.0.a],
  %w[1.10 1.9], %w[10 9], %w[1.2.3.4 1.2.3], %w[1.2.3.4 1.2.3.10], %w[0.0.0-0 0.0.0],
  %w[99999999999999999999 99999999999999999998], %w[1.99999999999999999999 1.99999999999999999998],
  %w[1.0.0.1.2.3.4.5 1.0.0.1.2.3.4.5.0], [" 1.0 ", "1.0"], ["1.0\t", "1.0"],
].map { |a, b| pair.(a, b) }

refused = ["", " ", "abc", "1.0.", ".1", "1..0", "v1.0", "1.0 1", "1.0-", "1_0", "1.0+1", "1,0", "1.0.0 beta", "１.０"].select { |v| !Gem::Version.correct?(v) || v.strip.empty? }

puts JSON.pretty_generate(
  "generatedWith" => "ruby #{RUBY_VERSION} / rubygems #{defined?(Gem::VERSION) ? Gem::VERSION : ENV.fetch("RUBYGEMS_TAG", "unknown")} (Gem::Version)",
  "feedVersions" => valid.length,
  "feedRefusedByRuby" => invalid.length,
  "adjacent" => adjacent,
  "random" => random,
  "handpicked" => handpicked,
  "refused" => refused,
)
