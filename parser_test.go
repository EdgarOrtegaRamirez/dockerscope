package dockerscope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDockerfile(t *testing.T) {
	// Create a test Dockerfile
	content := `FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/server .
EXPOSE 8080
USER nonroot
CMD ["./server"]
`

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test Dockerfile: %v", err)
	}

	df, err := ParseDockerfile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to parse Dockerfile: %v", err)
	}

	if len(df.Instructions) == 0 {
		t.Error("expected at least one instruction")
	}

	if df.StageCount != 2 {
		t.Errorf("expected 2 stages, got %d", df.StageCount)
	}

	if !df.HasUSER {
		t.Error("expected HasUSER to be true")
	}

	if !df.Has_EXPOSE {
		t.Error("expected Has_EXPOSE to be true")
	}

	if !df.Has_WORKDIR {
		t.Error("expected Has_WORKDIR to be true")
	}

	if !df.Has_COPY {
		t.Error("expected Has_COPY to be true")
	}

	// Check stage names
	if name, ok := df.StageNames["builder"]; !ok {
		t.Error("expected 'builder' stage")
	} else if name != 0 {
		t.Errorf("expected builder at index 0, got %d", name)
	}
}

func TestParseInstruction(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		lineNum  int
		expected Instruction
	}{
		{
			name:    "simple RUN",
			line:    "RUN echo hello",
			lineNum: 1,
			expected: Instruction{
				Keyword:       "RUN",
				Args:          "echo hello",
				LineNum:       1,
				ModifiesLayer: true,
			},
		},
		{
			name:    "JSON array RUN",
			line:    `RUN ["echo", "hello"]`,
			lineNum: 1,
			expected: Instruction{
				Keyword:       "RUN",
				Args:          `["echo", "hello"]`,
				LineNum:       1,
				IsJSON:        true,
				ModifiesLayer: true,
			},
		},
		{
			name:    "COPY with flags",
			line:    "COPY --from=builder /app/server .",
			lineNum: 1,
			expected: Instruction{
				Keyword:       "COPY",
				Args:          "--from=builder /app/server .",
				LineNum:       1,
				Flags:         []string{"--from=builder"},
				ModifiesLayer: true,
			},
		},
		{
			name:    "FROM with AS",
			line:    "FROM golang:1.24-alpine AS builder",
			lineNum: 1,
			expected: Instruction{
				Keyword: "FROM",
				Args:    "golang:1.24-alpine AS builder",
				LineNum: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instr, err := parseInstruction(tt.line, tt.lineNum)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if instr.Keyword != tt.expected.Keyword {
				t.Errorf("keyword: got %s, want %s", instr.Keyword, tt.expected.Keyword)
			}
			if instr.Args != tt.expected.Args {
				t.Errorf("args: got %s, want %s", instr.Args, tt.expected.Args)
			}
			if instr.IsJSON != tt.expected.IsJSON {
				t.Errorf("isJSON: got %v, want %v", instr.IsJSON, tt.expected.IsJSON)
			}
			if instr.ModifiesLayer != tt.expected.ModifiesLayer {
				t.Errorf("modifiesLayer: got %v, want %v", instr.ModifiesLayer, tt.expected.ModifiesLayer)
			}
		})
	}
}

func TestParseJSONArray(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple array",
			input:    `["echo", "hello"]`,
			expected: []string{"echo", "hello"},
		},
		{
			name:     "single element",
			input:    `["echo"]`,
			expected: []string{"echo"},
		},
		{
			name:     "empty array",
			input:    `[]`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseJSONArray(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("length: got %d, want %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("index %d: got %s, want %s", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestAnalyzeDockerfile(t *testing.T) {
	content := `FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/server .
EXPOSE 8080
USER nonroot
CMD ["./server"]
`

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test Dockerfile: %v", err)
	}

	df, err := ParseDockerfile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to parse Dockerfile: %v", err)
	}

	result := AnalyzeDockerfile(df)

	if result.Score <= 0 {
		t.Errorf("expected positive score, got %d", result.Score)
	}

	if result.LayerCount <= 0 {
		t.Errorf("expected positive layer count, got %d", result.LayerCount)
	}

	if !result.MultiStage {
		t.Error("expected MultiStage to be true")
	}

	if result.BaseImage == "" {
		t.Error("expected non-empty base image")
	}
}

func TestAnalyzeSecurityIssues(t *testing.T) {
	content := `FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
COPY . .
RUN chmod 777 /app
USER root
CMD ["./app"]
`

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test Dockerfile: %v", err)
	}

	df, err := ParseDockerfile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to parse Dockerfile: %v", err)
	}

	result := AnalyzeDockerfile(df)

	// Check for critical security issues
	hasCritical := false
	for _, issue := range result.Issues {
		if issue.Severity == SeverityCritical {
			hasCritical = true
			break
		}
	}

	if !hasCritical {
		t.Error("expected critical security issues (chmod 777, root user)")
	}

	// Check for security category
	hasSecurity := false
	for _, issue := range result.Issues {
		if issue.Category == "security" {
			hasSecurity = true
			break
		}
	}

	if !hasSecurity {
		t.Error("expected security category issues")
	}
}

func TestAnalyzeOptimizationIssues(t *testing.T) {
	content := `FROM golang:1.24
WORKDIR /app
COPY . .
RUN apt-get update
RUN apt-get install -y curl
RUN go build -o app .
CMD ["./app"]
`

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test Dockerfile: %v", err)
	}

	df, err := ParseDockerfile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to parse Dockerfile: %v", err)
	}

	result := AnalyzeDockerfile(df)

	// Check for optimization issues
	hasOptimization := false
	for _, issue := range result.Issues {
		if issue.Category == "optimization" {
			hasOptimization = true
			break
		}
	}

	if !hasOptimization {
		t.Error("expected optimization category issues")
	}
}

func TestGetSummary(t *testing.T) {
	content := `FROM golang:1.24-alpine
WORKDIR /app
COPY . .
RUN go build -o app .
USER nonroot
CMD ["./app"]
`

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test Dockerfile: %v", err)
	}

	df, err := ParseDockerfile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to parse Dockerfile: %v", err)
	}

	result := AnalyzeDockerfile(df)
	summary := result.GetSummary()

	if summary == "" {
		t.Error("expected non-empty summary")
	}

	if !containsString(summary, "Score:") {
		t.Error("summary should contain score")
	}
}

func TestGetIssuesByCategory(t *testing.T) {
	content := `FROM golang:1.24
RUN apt-get update
COPY . .
USER root
`

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test Dockerfile: %v", err)
	}

	df, err := ParseDockerfile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to parse Dockerfile: %v", err)
	}

	result := AnalyzeDockerfile(df)
	byCategory := result.GetIssuesByCategory()

	if len(byCategory) == 0 {
		t.Error("expected issues grouped by category")
	}

	// Check that categories exist
	for _, category := range []string{"security", "optimization", "best-practice"} {
		if issues, ok := byCategory[category]; !ok || len(issues) == 0 {
			t.Errorf("expected issues in category %s", category)
		}
	}
}

func TestGetIssuesBySeverity(t *testing.T) {
	content := `FROM golang:1.24
RUN chmod 777 /app
COPY . .
`

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test Dockerfile: %v", err)
	}

	df, err := ParseDockerfile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to parse Dockerfile: %v", err)
	}

	result := AnalyzeDockerfile(df)
	bySeverity := result.GetIssuesBySeverity()

	if len(bySeverity) == 0 {
		t.Error("expected issues grouped by severity")
	}

	// Check that at least one severity level has issues
	hasIssues := false
	for _, issues := range bySeverity {
		if len(issues) > 0 {
			hasIssues = true
			break
		}
	}

	if !hasIssues {
		t.Error("expected at least one severity level with issues")
	}
}

func TestFindDockerfiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test directory structure
	subdir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// Create Dockerfiles
	dockerfiles := []string{
		filepath.Join(tmpDir, "Dockerfile"),
		filepath.Join(tmpDir, "Dockerfile.dev"),
		filepath.Join(subdir, "Dockerfile"),
	}

	for _, df := range dockerfiles {
		if err := os.WriteFile(df, []byte("FROM scratch"), 0644); err != nil {
			t.Fatalf("failed to write Dockerfile: %v", err)
		}
	}

	// Create a non-Dockerfile
	if err := os.WriteFile(filepath.Join(tmpDir, "Makefile"), []byte("all:"), 0644); err != nil {
		t.Fatalf("failed to write Makefile: %v", err)
	}

	found, err := FindDockerfiles(tmpDir)
	if err != nil {
		t.Fatalf("failed to find Dockerfiles: %v", err)
	}

	if len(found) != 3 {
		t.Errorf("expected 3 Dockerfiles, found %d", len(found))
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityInfo, "INFO"},
		{SeverityWarning, "WARN"},
		{SeverityError, "ERROR"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.severity.String(); got != tt.expected {
				t.Errorf("got %s, want %s", got, tt.expected)
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
