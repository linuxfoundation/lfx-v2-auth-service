# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Go Toolchain Version

Freely bump `go.mod`'s `go` directive to the latest available *patch*
release (e.g. `1.X.Y` → `1.X.{Y+1}`) to pick up security fixes. Do **not**
bump the *minor* version (e.g. `1.X.x` → `1.{X+1}.x`) unless the user
explicitly asks for it, **and** you've validated it against the Go version
MegaLinter itself bundles -- MegaLinter's `golangci-lint` binary is
statically compiled against a specific Go version and refuses to analyze a
module whose `go.mod` directive is newer than that. (This is a property of
`golangci-lint` itself, not of MegaLinter's `osv-scanner`/`trivy`-based
`REPOSITORY_OSV_SCANNER` check, which is a separate, unrelated linter.) A
`go.mod` directive newer than what `golangci-lint` was built with breaks it
outright. This is a hard ceiling with no environment-variable workaround --
`GOTOOLCHAIN: auto` only affects invocations of the `go` command itself
and does nothing for this precompiled binary's own internal version
checks (confirmed empirically: setting it in both the workflow and
`.mega-linter.yml` still failed).

Also be careful with `go get -u`/`go mod tidy`: an indirect dependency
bump (e.g. a Kubernetes client library) can silently drag `go.mod`'s `go`
directive forward with it if that dependency's own `go.mod` requires a
newer Go version than the current directive. Check `git diff -- go.mod`
after any dependency refresh and revert/pin the offending dependency to an
older compatible release if it pulled the directive past the validated
ceiling.

To find MegaLinter's bundled Go version:

```bash
# 1. Find the MegaLinter flavor and pinned version tag used in CI.
grep -A1 'oxsecurity/megalinter' .github/workflows/*.yml
# e.g. "uses: oxsecurity/megalinter/flavors/<flavor>@<sha>  # <tag>"

# 2. Fetch that flavor's Dockerfile and read its GO_ALPINE_VERSION build
#    arg -- this is what the final image installs as `go`, not
#    GO_IMAGE_VERSION (which only applies to an intermediate builder
#    stage).
curl -s "https://raw.githubusercontent.com/oxsecurity/megalinter/<tag>/flavors/<flavor>/Dockerfile" \
  | grep -i 'GO_ALPINE_VERSION'
```

`go.mod`'s `go` directive must never exceed that bundled version. Note this
is a proxy for what `golangci-lint`'s own binary was built with, not a
guarantee -- if a MegaLinter run still fails after following this
procedure, check `golangci-lint --version` inside the pinned MegaLinter
image directly to see the Go version it actually reports. Staying
one minor version behind it (rather than matching its minor *and* patch
exactly) leaves room to always take the latest patch release for security
fixes without ever being blocked by MegaLinter's own bundled patch version
lagging a newly disclosed vulnerability.

There's no built-in `go` subcommand to look up the latest patch release for
a given minor version -- query the official `go.dev/dl` JSON feed instead:

```bash
# Find the latest patch release for the minor version pinned in go.mod.
MINOR=$(grep '^go ' go.mod | awk '{print $2}' | cut -d. -f1,2)
curl -s "https://go.dev/dl/?mode=json&include=all" \
  | jq -r --arg m "go${MINOR}." '.[].version | select(startswith($m))' \
  | sort -V | tail -1
```
