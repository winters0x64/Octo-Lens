package auth

import (
	"fmt"
	"os"
	"runtime"
)

// LoadPrivateKey loads the GitHub App private key from either:
// 1. GITHUB_APP_PRIVATE_KEY env var (raw PEM content)
// 2. GITHUB_APP_PRIVATE_KEY_PATH env var (file path)
// 3. Explicit file path argument
//
// File permissions are validated to be no wider than 0600.
func LoadPrivateKey(explicitPath string) ([]byte, error) {
	// Priority 1: raw PEM content from env var
	if raw := os.Getenv("GITHUB_APP_PRIVATE_KEY"); raw != "" {
		return []byte(raw), nil
	}

	// Priority 2: env var path
	path := os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH")
	if path == "" {
		path = explicitPath
	}

	if path == "" {
		return nil, fmt.Errorf("private key not provided: set GITHUB_APP_PRIVATE_KEY, GITHUB_APP_PRIVATE_KEY_PATH, or use --private-key flag")
	}

	if err := validateFilePermissions(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	return data, nil
}

func validateFilePermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	// Skip in containers — Docker volume mounts on macOS don't preserve Unix perms
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat private key file: %w", err)
	}

	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		return fmt.Errorf(
			"private key file %q has permissions %04o, which are too open; must be 0600 or stricter (no group/other access)",
			path, perm,
		)
	}

	return nil
}
