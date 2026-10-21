package config

import (
	"errors"
	"os"
	"path/filepath"
)

// Inspect is read-only: unlike Load, it never creates a directory or a missing
// management credential. Intended for configuration display, not wallet use.
func Inspect(dir string) (Config, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return Config{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return Config{}, errors.New("config directory must be a private real directory")
	}
	c, err := readConfig(dir)
	if err != nil {
		return Config{}, err
	}
	c.ManagementToken, err = readManagementToken(filepath.Join(dir, managementTokenFile))
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return Config{}, err
	}
	if c.ManagementToken != "" && c.ManagementToken == c.APIKey {
		return Config{}, errors.New("management credential must differ from the inference API key")
	}
	return c, nil
}
