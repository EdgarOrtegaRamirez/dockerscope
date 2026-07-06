# DockerScope - AI Agent Guide

## Overview

DockerScope is a comprehensive Dockerfile analysis and optimization toolkit in Go. It parses Dockerfiles, analyzes them for security issues, optimization opportunities, and best practices, and provides actionable recommendations.

## Building

```bash
go build -o dockerscope ./cmd/dockerscope/
```

## Running Tests

```bash
go test ./...
```

## Project Structure

- `parser.go` - Dockerfile parser with instruction extraction
- `analyzer.go` - Analysis engine with security/optimization checks
- `cmd/dockerscope/main.go` - CLI with 7 commands (analyze, scan, lint, stats, info, diff, init)
- `parser_test.go` - 21 tests

## Key Patterns

- Parser extracts instructions with line numbers, flags, and JSON support
- Analyzer runs security, optimization, and best practice checks
- Issues have severity (INFO, WARNING, ERROR, CRITICAL) and categories
- Score calculated from issue severities (0-100)
- CLI supports text, JSON, and markdown output formats

## Commands

1. `analyze` - Full Dockerfile analysis with scoring
2. `scan` - Scan directory for Dockerfiles
3. `lint` - CI-friendly linting (exits non-zero on errors)
4. `stats` - Dockerfile statistics
5. `info` - Instruction breakdown and stage info
6. `diff` - Compare two Dockerfiles
7. `init` - Generate optimized Dockerfile templates

## Dependencies

- `github.com/spf13/cobra` - CLI framework
- Standard library for parsing and analysis

## Testing

Tests cover:
- Dockerfile parsing (multi-stage, JSON arrays, line continuation)
- Instruction extraction
- Analysis scoring
- Security issue detection
- Optimization issue detection
- Summary generation
- Category and severity grouping
- Dockerfile discovery
