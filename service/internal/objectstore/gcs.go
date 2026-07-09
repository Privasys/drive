package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// GCS is a Google Cloud Storage object backend. It stores each key as an
// object in a bucket; the drive service prefixes keys per-tenant, so one
// bucket safely hosts many tenants. The backend sees only opaque,
// content-addressed AEAD ciphertext.
type GCS struct {
	client *storage.Client
	bucket *storage.BucketHandle
	name   string
}

// GCSConfig configures a GCS backend. CredentialsJSON is a service
// account key (the "gcs-sa-json" BYO bucket credential). When empty,
// application default credentials are used (a fleet-managed bucket).
type GCSConfig struct {
	Bucket          string
	CredentialsJSON []byte
}

// NewGCS opens a GCS backend for the configured bucket.
func NewGCS(ctx context.Context, cfg GCSConfig) (*GCS, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("objectstore: GCS bucket is required")
	}
	var opts []option.ClientOption
	if len(cfg.CredentialsJSON) > 0 {
		opts = append(opts, option.WithCredentialsJSON(cfg.CredentialsJSON))
	}
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("objectstore: GCS client: %w", err)
	}
	return &GCS{client: client, bucket: client.Bucket(cfg.Bucket), name: "gcs:" + cfg.Bucket}, nil
}

// Close releases the underlying GCS client.
func (g *GCS) Close() error { return g.client.Close() }

func (g *GCS) Name() string { return g.name }

// PutChunk writes bytes to key. Idempotent for content-addressed keys:
// re-writing the same content is a harmless overwrite.
func (g *GCS) PutChunk(ctx context.Context, key string, body io.Reader, size int64) error {
	w := g.bucket.Object(key).NewWriter(ctx)
	if _, err := io.Copy(w, body); err != nil {
		_ = w.Close()
		return fmt.Errorf("objectstore: GCS put %s: %w", key, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("objectstore: GCS put %s: %w", key, err)
	}
	return nil
}

// GetChunk returns a streaming reader for key, or ErrNotFound.
func (g *GCS) GetChunk(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := g.bucket.Object(key).NewReader(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("objectstore: GCS get %s: %w", key, err)
	}
	return rc, nil
}

// Head returns the object size, or ErrNotFound.
func (g *GCS) Head(ctx context.Context, key string) (int64, error) {
	attrs, err := g.bucket.Object(key).Attrs(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("objectstore: GCS head %s: %w", key, err)
	}
	return attrs.Size, nil
}

// Delete removes key. Deleting a missing key is not an error.
func (g *GCS) Delete(ctx context.Context, key string) error {
	err := g.bucket.Object(key).Delete(ctx)
	if err != nil && !errors.Is(err, storage.ErrObjectNotExist) {
		return fmt.Errorf("objectstore: GCS delete %s: %w", key, err)
	}
	return nil
}
