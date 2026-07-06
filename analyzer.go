package dockerscope

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Severity levels
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARN"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Issue represents a finding from analysis
type Issue struct {
	Severity    Severity
	Category    string
	Message     string
	Line        int
	Suggestion  string
	RuleID      string
}

// AnalysisResult contains all findings from analyzing a Dockerfile
type AnalysisResult struct {
	Dockerfile     *Dockerfile
	Issues         []Issue
	Score          int // 0-100
	LayerCount     int
	EstimatedSize  string
	BaseImage      string
	MultiStage     bool
	HasHealthCheck bool
	HasUser        bool
	HasNonRoot     bool
}

// AnalyzeDockerfile performs comprehensive analysis on a Dockerfile
func AnalyzeDockerfile(df *Dockerfile) *AnalysisResult {
	result := &AnalysisResult{
		Dockerfile: df,
		MultiStage: df.StageCount > 1,
	}

	// Find base image
	for _, instr := range df.Instructions {
		if instr.Keyword == "FROM" {
			parts := strings.Fields(instr.Args)
			if len(parts) > 0 {
				result.BaseImage = parts[0]
				break
			}
		}
	}

	// Count layers
	for _, instr := range df.Instructions {
		if instr.ModifiesLayer {
			result.LayerCount++
		}
	}

	// Run all checks
	result.runChecks()

	// Calculate score
	result.calculateScore()

	return result
}

func (r *AnalysisResult) runChecks() {
	df := r.Dockerfile

	for i, instr := range df.Instructions {
		switch instr.Keyword {
		case "FROM":
			r.checkBaseImage(instr, i)
		case "RUN":
			r.checkRunInstruction(instr, i)
		case "COPY":
			r.checkCopyInstruction(instr, i)
		case "ADD":
			r.checkAddInstruction(instr, i)
		case "EXPOSE":
			r.checkExpose(instr, i)
		case "HEALTHCHECK":
			r.HasHealthCheck = true
		case "USER":
			r.HasUser = true
			r.checkUser(instr, i)
		case "WORKDIR":
			r.checkWorkdir(instr, i)
		}
	}

	// Global checks
	r.checkGlobalBestPractices()
}

func (r *AnalysisResult) checkBaseImage(instr Instruction, line int) {
	image := instr.Args

	// Check for latest tag
	if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
		r.addIssue(SeverityWarning, "best-practice", "Base image uses 'latest' tag or no tag specified",
			line, "Pin to a specific version for reproducible builds (e.g., golang:1.24-alpine)")
	}

	// Check for alpine variants (smaller images)
	if strings.Contains(image, "golang:") && !strings.Contains(image, "alpine") && !strings.Contains(image, "slim") {
		r.addIssue(SeverityInfo, "optimization", "Consider using Alpine or slim variant for smaller image size",
			line, "Use golang:1.24-alpine instead of golang:1.24")
	}

	// Check for scratch usage
	if image == "scratch" {
		r.addIssue(SeverityInfo, "security", "Using scratch base image - ensure all binaries are statically compiled",
			line, "")
	}
}

func (r *AnalysisResult) checkRunInstruction(instr Instruction, line int) {
	var cmd string
	if instr.IsJSON && len(instr.JSONArgs) > 0 {
		cmd = strings.Join(instr.JSONArgs, " ")
	} else {
		cmd = instr.Args
	}

	// Check for apt-get without cleanup
	if strings.Contains(cmd, "apt-get install") && !strings.Contains(cmd, "rm -rf /var/lib/apt/lists") {
		r.addIssue(SeverityWarning, "optimization",
			"apt-get install without cleanup increases image size",
			line, "Add '&& rm -rf /var/lib/apt/lists/*' after apt-get install")
	}

	// Check for pip install without --no-cache-dir
	if strings.Contains(cmd, "pip install") && !strings.Contains(cmd, "--no-cache-dir") {
		r.addIssue(SeverityWarning, "optimization",
			"pip install without --no-cache-dir increases image size",
			line, "Add '--no-cache-dir' to pip install")
	}

	// Check for curl without version pin
	if strings.Contains(cmd, "curl ") && strings.Contains(cmd, "http") {
		r.addIssue(SeverityInfo, "security",
			"Using curl to download - verify checksums when possible",
			line, "Consider adding checksum verification")
	}

	// Check for apt-get update without install in same RUN
	if strings.Contains(cmd, "apt-get update") && !strings.Contains(cmd, "apt-get install") {
		r.addIssue(SeverityWarning, "best-practice",
			"apt-get update in separate RUN creates stale cache",
			line, "Combine apt-get update && apt-get install in single RUN")
	}

	// Check for common security issues
	securityPatterns := []struct {
		pattern string
		message string
	}{
		{"chmod 777", "World-writable permissions are a security risk"},
		{"chmod -R 777", "Recursive world-writable permissions are dangerous"},
		{"rm -rf /", "Dangerous deletion of root directory"},
		{"sudo ", "Avoid using sudo in Dockerfile"},
		{"su -", "Avoid using su in Dockerfile"},
	}

	for _, sp := range securityPatterns {
		if strings.Contains(cmd, sp.pattern) {
			r.addIssue(SeverityCritical, "security", sp.message, line, "")
		}
	}
}

func (r *AnalysisResult) checkCopyInstruction(instr Instruction, line int) {
	args := instr.Args

	// Check for COPY . . (copies everything including .git)
	if strings.Contains(args, ". .") || strings.Contains(args, ". /") {
		r.addIssue(SeverityWarning, "best-practice",
			"COPY . copies everything - use .dockerignore to exclude unnecessary files",
			line, "Ensure .dockerignore excludes .git, node_modules, __pycache__, etc.")
	}
}

func (r *AnalysisResult) checkAddInstruction(instr Instruction, line int) {
	args := instr.Args

	// ADD is only needed for tar extraction or URL downloads
	if !strings.Contains(args, ".tar") && !strings.Contains(args, "http") {
		r.addIssue(SeverityWarning, "best-practice",
			"ADD used without tar extraction or URL - prefer COPY for simple file copying",
			line, "Use COPY instead of ADD unless you need tar extraction or URL download")
	}
}

func (r *AnalysisResult) checkExpose(instr Instruction, line int) {
	// EXPOSE is informational only - just note it
	r.addIssue(SeverityInfo, "documentation",
		"EXPOSE is informational - actual port mapping happens at runtime",
		line, "")
}

func (r *AnalysisResult) checkUser(instr Instruction, line int) {
	user := strings.TrimSpace(instr.Args)

	// Check if running as root
	if user == "root" || user == "0" {
		r.addIssue(SeverityCritical, "security",
			"Container runs as root - major security risk",
			line, "Use a non-root user: USER nonroot:nonroot")
	} else {
		r.HasNonRoot = true
	}
}

func (r *AnalysisResult) checkWorkdir(instr Instruction, line int) {
	dir := strings.TrimSpace(instr.Args)

	// Check for relative paths
	if !strings.HasPrefix(dir, "/") {
		r.addIssue(SeverityWarning, "best-practice",
			"WORKDIR uses relative path - may cause confusion",
			line, "Use absolute path (e.g., WORKDIR /app)")
	}

	// Check for common directories
	if dir == "/" {
		r.addIssue(SeverityWarning, "best-practice",
			"WORKDIR is root directory - avoid using / as working directory",
			line, "Use a dedicated directory like /app")
	}
}

func (r *AnalysisResult) checkGlobalBestPractices() {
	df := r.Dockerfile

	// Check for multi-stage build
	if df.StageCount < 2 {
		r.addIssue(SeverityInfo, "optimization",
			"Consider using multi-stage builds to reduce final image size",
			0, "Use multi-stage builds: build in one stage, copy artifacts to minimal final stage")
	}

	// Check for HEALTHCHECK
	if !df.HasHEALTHCHECK {
		r.addIssue(SeverityInfo, "best-practice",
			"No HEALTHCHECK instruction - consider adding one for container orchestration",
			0, "Add HEALTHCHECK for better container orchestration support")
	}

	// Check for non-root user
	if !df.HasUSER {
		r.addIssue(SeverityWarning, "security",
			"No USER instruction - container will run as root",
			0, "Add USER instruction to run as non-root user")
	}

	// Check for too many layers
	if r.LayerCount > 20 {
		r.addIssue(SeverityWarning, "optimization",
			fmt.Sprintf("Too many layers (%d) - consider combining RUN commands", r.LayerCount),
			0, "Combine related RUN commands to reduce layers")
	}

	// Check for ADD usage
	if df.Has_ADD {
		r.addIssue(SeverityInfo, "best-practice",
			"ADD instruction used - prefer COPY unless tar extraction needed",
			0, "Use COPY instead of ADD for simple file copying")
	}

	// Check for WORKDIR
	if !df.Has_WORKDIR {
		r.addIssue(SeverityInfo, "best-practice",
			"No WORKDIR instruction - using default working directory",
			0, "Add WORKDIR for explicit working directory")
	}
}

func (r *AnalysisResult) addIssue(severity Severity, category, message string, line int, suggestion string) {
	issue := Issue{
		Severity:   severity,
		Category:   category,
		Message:    message,
		Line:       line,
		Suggestion: suggestion,
		RuleID:     generateRuleID(category, message),
	}
	r.Issues = append(r.Issues, issue)
}

func (r *AnalysisResult) calculateScore() {
	score := 100

	// Deductions based on severity
	for _, issue := range r.Issues {
		switch issue.Severity {
		case SeverityCritical:
			score -= 25
		case SeverityError:
			score -= 15
		case SeverityWarning:
			score -= 5
		case SeverityInfo:
			score -= 1
		}
	}

	// Cap at 0
	if score < 0 {
		score = 0
	}

	r.Score = score
}

func generateRuleID(category, message string) string {
	// Create a simple rule ID from category and first few words
	words := strings.Fields(message)
	if len(words) > 3 {
		words = words[:3]
	}
	slug := strings.ToLower(strings.Join(words, "-"))
	// Remove non-alphanumeric characters except hyphens
	reg := regexp.MustCompile(`[^a-z0-9-]`)
	slug = reg.ReplaceAllString(slug, "")
	return fmt.Sprintf("%s-%s", category, slug)
}

// GetSummary returns a human-readable summary of the analysis
func (r *AnalysisResult) GetSummary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("=== DockerScope Analysis: %s ===\n", filepath.Base(r.Dockerfile.Path)))
	sb.WriteString(fmt.Sprintf("Base Image: %s\n", r.BaseImage))
	sb.WriteString(fmt.Sprintf("Multi-stage: %v\n", r.MultiStage))
	sb.WriteString(fmt.Sprintf("Layers: %d\n", r.LayerCount))
	sb.WriteString(fmt.Sprintf("Score: %d/100\n\n", r.Score))

	// Count by severity
	critical := 0
	errors := 0
	warnings := 0
	infos := 0

	for _, issue := range r.Issues {
		switch issue.Severity {
		case SeverityCritical:
			critical++
		case SeverityError:
			errors++
		case SeverityWarning:
			warnings++
		case SeverityInfo:
			infos++
		}
	}

	sb.WriteString(fmt.Sprintf("Issues: %d critical, %d errors, %d warnings, %d info\n",
		critical, errors, warnings, infos))

	return sb.String()
}

// GetIssuesByCategory returns issues grouped by category
func (r *AnalysisResult) GetIssuesByCategory() map[string][]Issue {
	byCategory := make(map[string][]Issue)
	for _, issue := range r.Issues {
		byCategory[issue.Category] = append(byCategory[issue.Category], issue)
	}
	return byCategory
}

// GetIssuesBySeverity returns issues grouped by severity
func (r *AnalysisResult) GetIssuesBySeverity() map[Severity][]Issue {
	bySeverity := make(map[Severity][]Issue)
	for _, issue := range r.Issues {
		bySeverity[issue.Severity] = append(bySeverity[issue.Severity], issue)
	}
	return bySeverity
}
