package dockerscope

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Instruction represents a single Dockerfile instruction
type Instruction struct {
	Keyword       string   // FROM, RUN, COPY, etc.
	Args          string   // Raw arguments
	LineNum       int      // Line number in file
	IsJSON        bool     // Whether this uses JSON array syntax
	JSONArgs      []string // Parsed JSON array arguments
	Flags         []string // Parser flags (e.g., --mount, --from)
	ModifiesLayer bool     // Whether this instruction creates a new layer
}

// Dockerfile represents a parsed Dockerfile
type Dockerfile struct {
	Path           string
	Instructions   []Instruction
	StageNames     map[string]int // stage name -> instruction index
	StageCount     int
	HasHEALTHCHECK bool
	HasUSER        bool
	Has_EXPOSE     bool
	Has_WORKDIR    bool
	Has_COPY       bool
	Has_ADD        bool
}

// ParseDockerfile parses a Dockerfile into a structured representation
func ParseDockerfile(path string) (*Dockerfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Dockerfile: %w", err)
	}
	defer file.Close()

	df := &Dockerfile{
		Path:       path,
		StageNames: make(map[string]int),
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	var continuation strings.Builder
	inContinuation := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle line continuation
		if inContinuation {
			continuation.WriteString(" ")
			continuation.WriteString(line)
			if strings.HasSuffix(line, "\\") {
				// Remove trailing backslash
				s := continuation.String()
				s = s[:len(s)-1]
				continuation.Reset()
				continuation.WriteString(s)
				continue
			}
			// Process the complete line
			line = continuation.String()
			inContinuation = false
			continuation.Reset()
		} else if strings.HasSuffix(line, "\\") {
			continuation.WriteString(strings.TrimSuffix(line, "\\"))
			inContinuation = true
			continue
		}

		// Parse the instruction
		instr, err := parseInstruction(line, lineNum)
		if err != nil {
			continue // Skip malformed instructions
		}

		df.Instructions = append(df.Instructions, *instr)

		// Track stages
		if instr.Keyword == "FROM" {
			df.StageCount++
			// Extract stage name if present (e.g., "FROM base AS builder")
			parts := strings.Fields(instr.Args)
			for i, part := range parts {
				if strings.ToUpper(part) == "AS" && i+1 < len(parts) {
					df.StageNames[strings.ToLower(parts[i+1])] = len(df.Instructions) - 1
				}
			}
		}

		// Track special instructions
		switch instr.Keyword {
		case "HEALTHCHECK":
			df.HasHEALTHCHECK = true
		case "USER":
			df.HasUSER = true
		case "EXPOSE":
			df.Has_EXPOSE = true
		case "WORKDIR":
			df.Has_WORKDIR = true
		case "COPY":
			df.Has_COPY = true
		case "ADD":
			df.Has_ADD = true
		}
	}

	return df, scanner.Err()
}

func parseInstruction(line string, lineNum int) (*Instruction, error) {
	// Find the keyword
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty instruction")
	}

	keyword := strings.ToUpper(fields[0])
	args := ""
	// Get everything after the keyword
	idx := strings.Index(strings.ToUpper(line), keyword)
	if idx >= 0 {
		args = strings.TrimSpace(line[idx+len(keyword):])
	}

	instr := &Instruction{
		Keyword: keyword,
		Args:    args,
		LineNum: lineNum,
	}

	// Check if args is JSON array
	trimmed := strings.TrimSpace(args)
	if strings.HasPrefix(trimmed, "[") {
		instr.IsJSON = true
		// Parse JSON array (simplified - doesn't handle nested JSON)
		instr.JSONArgs = parseJSONArray(trimmed)
	}

	// Parse flags
	instr.Flags = parseFlags(args)

	// Determine if this creates a layer
	switch keyword {
	case "RUN", "COPY", "ADD":
		instr.ModifiesLayer = true
	}

	return instr, nil
}

func parseJSONArray(s string) []string {
	// Remove [ and ]
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")

	var result []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(s); i++ {
		ch := s[i]

		if inQuote {
			if ch == '\\' && i+1 < len(s) {
				// Skip escaped character
				current.WriteByte(ch)
				i++
				current.WriteByte(s[i])
				continue
			}
			if ch == quoteChar {
				inQuote = false
				result = append(result, current.String())
				current.Reset()
				continue
			}
			current.WriteByte(ch)
		} else {
			if ch == '"' || ch == '\'' {
				inQuote = true
				quoteChar = ch
				current.Reset()
			} else if ch == ',' {
				// Skip commas between elements
			}
		}
	}

	return result
}

func parseFlags(args string) []string {
	var flags []string
	fields := strings.Fields(args)
	for _, field := range fields {
		if strings.HasPrefix(field, "--") {
			flags = append(flags, field)
		}
	}
	return flags
}

// FindDockerfiles finds all Dockerfiles in a directory
func FindDockerfiles(dir string) ([]string, error) {
	var dockerfiles []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			// Skip hidden directories and common non-relevant dirs
			name := info.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check for Dockerfile patterns
		base := filepath.Base(path)
		if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasPrefix(base, "dockerfile.") {
			dockerfiles = append(dockerfiles, path)
		}

		return nil
	})

	return dockerfiles, err
}
