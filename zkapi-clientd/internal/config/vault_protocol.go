package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Kept outside config.json so the pinned legacy decoder can still read its
// unchanged profile. The preference shares daemon.lock with all config edits.
func LoadVaultProtocol(dir string) (string, error) {
	path := filepath.Join(dir, "vault-protocol")
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return "", nil
	}
	if err != nil {
		return "", errors.New("cannot read saved vault protocol")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return "", errors.New("vault-protocol must be an owner-only regular file")
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); !ok || owner.Uid != uint32(os.Geteuid()) {
		return "", errors.New("vault-protocol must belong to the current user")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64))
	if err != nil {
		return "", errors.New("cannot read saved vault protocol")
	}
	value := strings.TrimSpace(string(raw))
	if value != "legacy" && value != "concession" {
		return "", errors.New("invalid saved vault protocol; expected legacy or concession")
	}
	return value, nil
}

func UpdateVaultProtocol(dir string, previous Config, expected, next string) error {
	if next != "" && next != "legacy" && next != "concession" {
		return errors.New("vault protocol must be legacy or concession")
	}
	if err := EnsureDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, "daemon.lock")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("cannot lock profile for vault selection")
	}
	lock := os.NewFile(uintptr(fd), path)
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("daemon.lock must be a regular owner-only file")
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("daemon.lock must belong to the current user")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("profile is in use; stop serve before changing vault protocol")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	current, err := Load(dir)
	if err != nil {
		return err
	}
	saved, err := LoadVaultProtocol(dir)
	if err != nil {
		return err
	}
	if current != previous || saved != expected {
		return errors.New("profile changed while editing; review and retry vault selection")
	}
	target := filepath.Join(dir, "vault-protocol")
	if next == "" {
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(dir)
	}
	file, err := os.CreateTemp(dir, ".vault-protocol-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(next + "\n"); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), target); err != nil {
		return err
	}
	return syncDir(dir)
}
