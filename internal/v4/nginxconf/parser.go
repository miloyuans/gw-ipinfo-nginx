package nginxconf

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var hostPattern = regexp.MustCompile(`^[a-z0-9.-]+$`)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) ParseHosts(ctx context.Context, paths []string) ([]string, error) {
	seen := make(map[string]struct{})
	for _, path := range paths {
		if err := p.parseFile(ctx, filepath.Clean(path), seen, map[string]struct{}{}); err != nil {
			return nil, err
		}
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func (p *Parser) parseFile(ctx context.Context, path string, seen map[string]struct{}, visiting map[string]struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if _, ok := visiting[path]; ok {
		return nil
	}
	visiting[path] = struct{}{}
	defer delete(visiting, path)

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open nginx conf %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	serverDepth := 0
	dir := filepath.Dir(path)
	for scanner.Scan() {
		line := stripComment(scanner.Text())
		if line == "" {
			continue
		}
		if includePath, ok := parseInclude(line); ok {
			includeMatches, err := filepath.Glob(filepath.Join(dir, includePath))
			if err != nil {
				return fmt.Errorf("glob include %s in %s: %w", includePath, path, err)
			}
			for _, includeMatch := range includeMatches {
				if err := p.parseFile(ctx, filepath.Clean(includeMatch), seen, visiting); err != nil {
					return err
				}
			}
			continue
		}
		if strings.HasPrefix(line, "server") && strings.Contains(line, "{") {
			serverDepth++
		}
		if serverDepth > 0 {
			if names, ok := parseServerNames(line); ok {
				for _, host := range names {
					if normalized, ok := normalizeHost(host); ok {
						seen[normalized] = struct{}{}
					}
				}
			}
		}
		serverDepth += strings.Count(line, "{") - strings.Count(line, "}")
		if serverDepth < 0 {
			serverDepth = 0
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan nginx conf %s: %w", path, err)
	}
	return nil
}

func stripComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}

func parseInclude(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "include ") || !strings.HasSuffix(line, ";") {
		return "", false
	}
	value := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "include"), ";"))
	if value == "" {
		return "", false
	}
	return value, true
}

func parseServerNames(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "server_name ") || !strings.HasSuffix(line, ";") {
		return nil, false
	}
	rest := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "server_name"), ";"))
	if rest == "" {
		return nil, false
	}
	return strings.Fields(rest), true
}

func normalizeHost(raw string) (string, bool) {
	value := strings.TrimSpace(strings.ToLower(raw))
	value = strings.TrimSuffix(value, ".")
	if value == "" || value == "_" || strings.Contains(value, "*") {
		return "", false
	}
	if strings.Contains(value, ":") {
		if idx := strings.Index(value, ":"); idx > 0 && !strings.Contains(value[idx+1:], ":") {
			value = value[:idx]
		}
	}
	if !hostPattern.MatchString(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return "", false
	}
	return value, true
}
