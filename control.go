package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// stopTokenPath locates a per-user control credential for one dashboard listener.
// The user cache directory avoids a predictable name in a shared /tmp directory.
func stopTokenPath(addr string) (string, error) {
	return controlTokenPath(addr, "certainted-control-", true)
}

func legacyStopTokenPath(addr string) (string, error) {
	return controlTokenPath(addr, "certained-control-", false)
}

func controlTokenPath(addr, prefix string, create bool) (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("identify local user: %w", err)
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate local user cache: %w", err)
	}
	userHash := sha256.Sum256([]byte(current.Uid))
	dir := filepath.Join(cacheDir, prefix+hex.EncodeToString(userHash[:8]))
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("create control directory: %w", err)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !controlOwnerOK(info) {
		return "", errors.New("control directory is not a private directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("control directory permissions are too broad")
	}
	addrHash := sha256.Sum256([]byte(addr))
	return filepath.Join(dir, hex.EncodeToString(addrHash[:])+".token"), nil
}

func createStopToken(addr string) (string, func(), error) {
	path, err := stopTokenPath(addr)
	if err != nil {
		return "", nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || !controlOwnerOK(info) {
			return "", nil, errors.New("control token path is not a regular file")
		}
		// Binding the listener has already succeeded, so any prior token for
		// this exact address belongs to an instance that is no longer listening.
		if err := os.Remove(path); err != nil {
			return "", nil, fmt.Errorf("remove stale control token: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", nil, err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", nil, fmt.Errorf("create stop token: %w", err)
	}
	token := hex.EncodeToString(secret[:])
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", nil, fmt.Errorf("write stop token: %w", err)
	}
	_, writeErr := io.WriteString(f, token+"\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", nil, errors.Join(writeErr, closeErr)
	}
	cleanup := func() {
		current, err := os.ReadFile(path)
		if err == nil && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(current))), []byte(token)) == 1 {
			_ = os.Remove(path)
		}
	}
	return token, cleanup, nil
}

type stopCredential struct {
	token string
	path  string
}

func readStopTokens(addr string) ([]stopCredential, error) {
	paths := []func(string) (string, error){stopTokenPath, legacyStopTokenPath}
	var credentials []stopCredential
	var firstError error
	for _, pathForAddress := range paths {
		path, err := pathForAddress(addr)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if firstError == nil {
				firstError = err
			}
			continue
		}
		token, err := readStopTokenFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if firstError == nil {
				firstError = err
			}
			continue
		}
		credentials = append(credentials, stopCredential{token: token, path: path})
	}
	if len(credentials) == 0 {
		if firstError != nil {
			return nil, firstError
		}
		return nil, errors.New("no Certainted stop token for this dashboard address (no instance, or an older instance needs one restart)")
	}
	return credentials, nil
}

func readStopTokenFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || !controlOwnerOK(info) || info.Size() > 128 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return "", errors.New("control token file is not private")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("invalid control token")
	}
	return token, nil
}
