package objectstore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// LocalBackend persists chunks under a root directory. Intended for
// development and tests; not production.
type LocalBackend struct {
	Root string
}

// NewLocal returns a LocalBackend rooted at dir, creating it if
// necessary.
func NewLocal(dir string) (*LocalBackend, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &LocalBackend{Root: dir}, nil
}

func (b *LocalBackend) Name() string { return "local" }

func (b *LocalBackend) path(key string) (string, error) {
	if strings.Contains(key, "..") || strings.HasPrefix(key, "/") || strings.HasPrefix(key, `\`) {
		return "", errors.New("objectstore/local: invalid key")
	}
	clean := filepath.ToSlash(filepath.Clean(key))
	if clean == "." || clean == "" || strings.HasPrefix(clean, "..") {
		return "", errors.New("objectstore/local: invalid key")
	}
	return filepath.Join(b.Root, filepath.FromSlash(clean)), nil
}

func (b *LocalBackend) PutChunk(ctx context.Context, key string, body io.Reader, size int64) error {
	p, err := b.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func (b *LocalBackend) GetChunk(ctx context.Context, key string) (io.ReadCloser, error) {
	p, err := b.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

func (b *LocalBackend) Head(ctx context.Context, key string) (int64, error) {
	p, err := b.path(key)
	if err != nil {
		return 0, err
	}
	st, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return st.Size(), nil
}

func (b *LocalBackend) Delete(ctx context.Context, key string) error {
	p, err := b.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
