// SPDX-License-Identifier: GPL-3.0-only

package openssl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	ExitGeneral     = 1
	ExitUsage       = 2
	ExitUnsupported = 3
	ExitVerify      = 4
)

var versionPattern = regexp.MustCompile(`(?i)^OpenSSL\s+(\d+)\.(\d+)\.(\d+)`)

// Version is the parsed OpenSSL semantic version.
type Version struct {
	Major int    `json:"major"`
	Minor int    `json:"minor"`
	Patch int    `json:"patch"`
	Raw   string `json:"raw"`
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Supported reports whether this build is within CryptoWrapper's supported
// and security-patched OpenSSL range.
func (v Version) Supported() bool {
	switch v.Major {
	case 3:
		if v.Minor < 6 {
			return false
		}
		return v.Minor > 6 || v.Patch >= 3
	case 4:
		return v.Minor > 0 || v.Patch >= 1
	default:
		return false
	}
}

func ParseVersion(raw string) (Version, error) {
	line := strings.TrimSpace(strings.SplitN(raw, "\n", 2)[0])
	match := versionPattern.FindStringSubmatch(line)
	if match == nil {
		return Version{}, fmt.Errorf("unrecognized OpenSSL version: %q", line)
	}
	values := make([]int, 3)
	for i := range values {
		value, err := strconv.Atoi(match[i+1])
		if err != nil {
			return Version{}, fmt.Errorf("parse OpenSSL version: %w", err)
		}
		values[i] = value
	}
	return Version{Major: values[0], Minor: values[1], Patch: values[2], Raw: line}, nil
}

// CommandError contains sanitized command failure details.
type CommandError struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *CommandError) Error() string {
	if e.Stderr == "" {
		return fmt.Sprintf("openssl %s: %v", strings.Join(e.Args, " "), e.Err)
	}
	return fmt.Sprintf("openssl %s: %s", strings.Join(e.Args, " "), e.Stderr)
}

func (e *CommandError) Unwrap() error { return e.Err }

// Client safely invokes OpenSSL without a shell.
type Client struct {
	Path    string
	Verbose bool
	Log     io.Writer
}

func Resolve(explicit string) (*Client, error) {
	path := explicit
	if path == "" {
		path = os.Getenv("CW_OPENSSL")
	}
	if path == "" {
		var err error
		path, err = exec.LookPath("openssl")
		if err != nil {
			return nil, errors.New("openssl executable not found; install OpenSSL 3.6.3+ or 4.0.1+ and ensure it is on PATH, or use --openssl/CW_OPENSSL; then run 'cw doctor'")
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect openssl executable: %w", err)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("openssl path is not executable: %s", path)
	}
	return &Client{Path: path, Log: io.Discard}, nil
}

func (c *Client) Run(ctx context.Context, args ...string) ([]byte, error) {
	return c.RunInput(ctx, nil, args...)
}

func (c *Client) RunInput(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
	return c.run(ctx, input, nil, args...)
}

// RunPassphrase supplies a passphrase over child file descriptor 3. The
// secret never appears in argv or the environment.
func (c *Client) RunPassphrase(ctx context.Context, passphrase []byte, args ...string) ([]byte, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create passphrase pipe: %w", err)
	}
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		payload := make([]byte, len(passphrase)+1)
		copy(payload, passphrase)
		payload[len(payload)-1] = '\n'
		_, writeErr := writer.Write(payload)
		for index := range payload {
			payload[index] = 0
		}
		closeErr := writer.Close()
		if writeErr != nil {
			done <- writeErr
			return
		}
		done <- closeErr
	}()
	output, runErr := c.run(ctx, nil, []*os.File{reader}, args...)
	writeErr := <-done
	if runErr != nil {
		return nil, runErr
	}
	if writeErr != nil {
		return nil, fmt.Errorf("write passphrase pipe: %w", writeErr)
	}
	return output, nil
}

func (c *Client) run(ctx context.Context, input io.Reader, extraFiles []*os.File, args ...string) ([]byte, error) {
	if c.Verbose {
		fmt.Fprintf(c.Log, "+ %s %s\n", c.Path, strings.Join(args, " "))
	}
	command := exec.CommandContext(ctx, c.Path, args...)
	command.Stdin = input
	command.ExtraFiles = extraFiles
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, &CommandError{
			Args:   append([]string(nil), args...),
			Stderr: strings.TrimSpace(stderr.String()),
			Err:    err,
		}
	}
	return stdout.Bytes(), nil
}

func (c *Client) Version(ctx context.Context) (Version, error) {
	output, err := c.Run(ctx, "version")
	if err != nil {
		return Version{}, err
	}
	return ParseVersion(string(output))
}

// RequireSupported returns the installed OpenSSL version or an actionable
// dependency error before an OpenSSL-backed operation is attempted.
func (c *Client) RequireSupported(ctx context.Context) (Version, error) {
	version, err := c.Version(ctx)
	if err != nil {
		return Version{}, fmt.Errorf(
			"cannot use OpenSSL at %s: %w; install OpenSSL 3.6.3+ or 4.0.1+, select it with --openssl/CW_OPENSSL, then run 'cw doctor'",
			c.Path, err,
		)
	}
	if !version.Supported() {
		return Version{}, fmt.Errorf(
			"unsupported OpenSSL %s at %s; install OpenSSL 3.6.3+ or 4.0.1+, select it with --openssl/CW_OPENSSL, then run 'cw doctor'",
			version, c.Path,
		)
	}
	return version, nil
}

func (c *Client) Providers(ctx context.Context) ([]string, error) {
	output, err := c.Run(ctx, "list", "-providers")
	if err != nil {
		return nil, err
	}
	var providers []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			name := strings.TrimSpace(line)
			if name != "" {
				providers = append(providers, name)
			}
		}
	}
	return providers, nil
}

// ListAlgorithms returns normalized OpenSSL algorithm names for a category.
func (c *Client) ListAlgorithms(ctx context.Context, category string) ([]string, error) {
	flags := map[string]string{
		"keys":       "-public-key-algorithms",
		"ciphers":    "-cipher-algorithms",
		"digests":    "-digest-algorithms",
		"signatures": "-signature-algorithms",
	}
	flag, ok := flags[category]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm category %q", category)
	}
	output, err := c.Run(ctx, "list", flag)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, ":") || strings.HasPrefix(line, "Name:") ||
			strings.HasPrefix(line, "Type:") || strings.HasPrefix(line, "OID:") ||
			strings.HasPrefix(line, "PEM string:") || strings.HasPrefix(line, "Alias for:") {
			continue
		}
		if index := strings.Index(line, " @ "); index >= 0 {
			line = line[:index]
		}
		if strings.HasPrefix(line, "IDs:") {
			addAlgorithmAliases(seen, strings.TrimSpace(strings.TrimPrefix(line, "IDs:")))
			continue
		}
		if strings.HasPrefix(line, "{") {
			addAlgorithmAliases(seen, line)
			continue
		}
		if index := strings.Index(line, " => "); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		if strings.ContainsAny(line, "{}\t") || strings.Contains(line, " implementation") {
			continue
		}
		seen[line] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func addAlgorithmAliases(seen map[string]struct{}, value string) {
	value = strings.TrimSpace(strings.Trim(value, "{}"))
	for _, alias := range strings.Split(value, ",") {
		alias = strings.TrimSpace(alias)
		if alias == "" || isOID(alias) {
			continue
		}
		seen[alias] = struct{}{}
	}
}

func isOID(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return strings.Contains(value, ".")
}
