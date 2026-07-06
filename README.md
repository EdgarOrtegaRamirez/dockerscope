# DockerScope

A comprehensive Dockerfile analysis and optimization toolkit. Analyze Dockerfiles for security issues, optimization opportunities, and best practices.

## Features

- **Analyze**: Full Dockerfile analysis with security, optimization, and best practice checks
- **Scan**: Scan directories for Dockerfiles and get quick summaries
- **Lint**: CI-friendly linting that exits non-zero on errors
- **Stats**: Detailed Dockerfile statistics
- **Info**: Instruction breakdown and stage information
- **Diff**: Compare two Dockerfiles side-by-side
- **Init**: Generate optimized Dockerfile templates for Go, Python, Node.js, and Rust

## Quick Start

### Install

```bash
go install github.com/EdgarOrtegaRamirez/dockerscope/cmd/dockerscope@latest
```

### Build from source

```bash
git clone https://github.com/EdgarOrtegaRamirez/dockerscope
cd dockerscope
go build -o dockerscope ./cmd/dockerscope/
```

## Usage

### Analyze a Dockerfile

```bash
# Basic analysis
dockerscope analyze Dockerfile

# With fix suggestions
dockerscope analyze --fix Dockerfile

# Filter by severity
dockerscope analyze --severity warning Dockerfile

# JSON output
dockerscope analyze --output json Dockerfile
```

### Scan a directory

```bash
# Scan current directory
dockerscope scan .

# Scan with JSON output
dockerscope scan --output json /path/to/project
```

### Lint (CI-friendly)

```bash
# Lint with default severity (warning)
dockerscope lint Dockerfile

# Lint with custom severity
dockerscope lint --severity error Dockerfile
```

### Get statistics

```bash
dockerscope stats Dockerfile
```

### Compare Dockerfiles

```bash
dockerscope diff Dockerfile.old Dockerfile.new
```

### Generate template

```bash
# Generate Go Dockerfile
dockerscope init go

# Generate Python Dockerfile
dockerscope init python

# Generate Node.js Dockerfile
dockerscope init node

# Generate Rust Dockerfile
dockerscope init rust
```

## Checks Performed

### Security
- Running as root detection
- chmod 777 detection
- Dangerous command detection (rm -rf /, sudo)
- User instruction presence

### Optimization
- apt-get cleanup recommendations
- pip cache recommendations
- Layer count optimization
- Multi-stage build suggestions
- Base image variant recommendations

### Best Practices
- Latest tag usage
- ADD vs COPY usage
- WORKDIR path recommendations
- HEALTHCHECK presence
- .dockerignore reminders

## Scoring

DockerScope assigns a score from 0-100 based on:
- Critical issues: -25 points each
- Error issues: -15 points each
- Warning issues: -5 points each
- Info issues: -1 point each

## Example Output

```
=== DockerScope Analysis: Dockerfile ===
Base Image: golang:1.24-alpine
Multi-stage: true
Layers: 4
Score: 85/100

Issues: 0 critical, 0 errors, 1 warnings, 2 info

--- OPTIMIZATION ---
[WARN] Line 3: apt-get install without cleanup increases image size
  → Add '&& rm -rf /var/lib/apt/lists/*' after apt-get install

--- BEST-PRACTICE ---
[INFO] Line 0: Consider using multi-stage builds to reduce final image size
[INFO] Line 0: No HEALTHCHECK instruction - consider adding one
```

## Architecture

```
dockerscope/
├── parser.go          # Dockerfile parser with instruction extraction
├── analyzer.go        # Analysis engine with security/optimization checks
├── cmd/dockerscope/
│   └── main.go        # CLI with 7 commands
└── parser_test.go     # 21 tests
```

## Development

```bash
# Run tests
go test ./...

# Build
go build -o dockerscope ./cmd/dockerscope/

# Lint
go vet ./...
```

## License

MIT
