package objectstore

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
)

// Walk visits every object in the local store with its backend key and size.
// It is what a migration to a bucket needs: the local backend is the only
// one without a listing API, and its layout (a directory tree mirroring the
// key) makes enumeration a filesystem walk. In-flight temp files from
// PutChunk are skipped.
func (b *LocalBackend) Walk(ctx context.Context, fn func(key string, size int64) error) error {
	return filepath.WalkDir(b.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".tmp-") {
			return nil
		}
		rel, rerr := filepath.Rel(b.Root, p)
		if rerr != nil {
			return rerr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		return fn(filepath.ToSlash(rel), info.Size())
	})
}
