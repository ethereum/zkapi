package config

import (
	"errors"
	"os"
)

// LocalAccess is what a local inference client of the running daemon needs.
// It deliberately excludes the management credential and wallet settings.
type LocalAccess struct {
	Listen       string
	APIKey       string
	DefaultModel string
}

// ReadLocalAccess is read-only: unlike Load and Inspect it never creates a
// directory or credential and never reads the management credential.
func ReadLocalAccess(dir string) (LocalAccess, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return LocalAccess{}, errors.New("configuration missing")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return LocalAccess{}, errors.New("config directory must be a private real directory")
	}
	c, err := readConfig(dir)
	if err != nil {
		return LocalAccess{}, err
	}
	return LocalAccess{Listen: c.Listen, APIKey: c.APIKey, DefaultModel: c.DefaultModel}, nil
}
