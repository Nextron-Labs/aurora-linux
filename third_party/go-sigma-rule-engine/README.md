# go-sigma-rule-engine (Aurora copy)

Sigma rule parser and match engine used by Aurora Linux
(`lib/consumer/sigma`).

- **Upstream:** [markuskont/go-sigma-rule-engine](https://github.com/markuskont/go-sigma-rule-engine) **v0.3.0**, which has had no commits for about three years.
- **License:** Apache-2.0, see [LICENSE](LICENSE), which is upstream's unchanged.

Files changed from upstream start with a `// Modified by Nextron Systems`
line. Files Aurora added start with `// Added by Nextron Systems`. Upstream's
`examples/`, `.github/`, `go.mod` and `go.sum` are not included. The package
builds as part of the Aurora module.

## Changes from upstream v0.3.0

- **Case-insensitive matching.** String values (equals, `contains`,
  `startswith`, `endswith`, wildcards and keywords) match case-insensitively,
  as the Sigma specification requires. Upstream compared them
  case-sensitively. Folding is ASCII-only, so look-alike Unicode (for example
  the Kelvin sign) cannot satisfy a filter. Regexes stay case-sensitive.
  (`ident.go`, `pattern.go`)
- **`|cased` modifier.** Matches the value case-sensitively. (`ident.go`)
- **`|re|i`, `|re|m`, `|re|s` sub-modifiers.** They become Go inline regex
  flags. They are rejected without `|re`. (`ident.go`)
- **No `/.../` regex values.** Upstream compiled a value or keyword written
  as `/.../` into a case-sensitive regex with the slashes removed. Sigma has
  no such syntax (regexes use `|re`), and SigmaHQ uses such values for paths
  (`/bin/bash -c exec 5<>/dev/tcp/`), so they are now plain values like any
  other. (`pattern.go`)
- **Tests:** `modifiers_test.go` is new. In `ident_test.go`, the case that
  tested `/.../` regex keywords now tests them as plain values.
  `parser_test.go` and `tree_test.go` only have comments reformatted by gofmt,
  as do a few comments in `pattern.go`.
