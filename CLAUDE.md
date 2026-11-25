# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Go Toolchain Version

Follow the `lfx-megalinter` skill's Go version policy. It sets `go.mod` to
the latest patch of the previous stable Go minor and caps it at the minor
bundled by the pinned MegaLinter release. This importable module declares the
minor-level dependency floor in `go` and pins the patch in `toolchain`.
