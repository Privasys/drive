package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3 is an S3-compatible object backend. One implementation serves AWS
// S3, OVH Object Storage (its S3-compatible endpoint), MinIO, Cloudflare
// R2 and any other S3 API: the provider is selected by Endpoint. Each
// key is an object in a bucket, per-tenant-prefixed so one bucket hosts
// many tenants; it sees only opaque AEAD ciphertext.
type S3 struct {
	client *s3.Client
	bucket string
	name   string
}

// S3Config configures an S3-compatible backend.
type S3Config struct {
	Bucket    string
	Region    string // e.g. "us-east-1"; OVH uses its region (e.g. "gra")
	Endpoint  string // empty for AWS S3; the provider URL for OVH/MinIO/R2
	AccessKey string
	SecretKey string
	// Name overrides the backend's reported name (e.g. "ovh"); defaults
	// to "s3".
	Name string
	// PathStyle forces path-style addressing (bucket in the path, not
	// the host). Required by MinIO and some OVH setups.
	PathStyle bool
}

// NewS3 opens an S3-compatible backend.
func NewS3(ctx context.Context, cfg S3Config) (*S3, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("objectstore: S3 bucket is required")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("objectstore: S3 access key and secret are required")
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	client := s3.New(s3.Options{
		Region:       region,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		BaseEndpoint: endpointPtr(cfg.Endpoint),
		UsePathStyle: cfg.PathStyle || cfg.Endpoint != "", // path-style for non-AWS providers
	})
	name := cfg.Name
	if name == "" {
		name = "s3"
	}
	return &S3{client: client, bucket: cfg.Bucket, name: name + ":" + cfg.Bucket}, nil
}

func endpointPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// NewOVH opens an OVH Object Storage backend via its S3-compatible API.
// OVH is S3 with a per-region endpoint (e.g.
// https://s3.gra.io.cloud.ovh.net) and path-style addressing; this is a
// thin, named wrapper over the S3 backend so "OVH" is a first-class
// provider. Endpoint and region are required.
func NewOVH(ctx context.Context, cfg S3Config) (*S3, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("objectstore: OVH endpoint is required (e.g. https://s3.<region>.io.cloud.ovh.net)")
	}
	cfg.PathStyle = true
	cfg.Name = "ovh"
	return NewS3(ctx, cfg)
}

func (b *S3) Name() string { return b.name }

// PutChunk stores bytes at key. Content-addressed keys make a re-put of
// the same content a harmless overwrite.
func (b *S3) PutChunk(ctx context.Context, key string, body io.Reader, size int64) error {
	in := &s3.PutObjectInput{Bucket: &b.bucket, Key: &key, Body: body}
	if size > 0 {
		in.ContentLength = aws.Int64(size)
	}
	if _, err := b.client.PutObject(ctx, in); err != nil {
		return fmt.Errorf("objectstore: S3 put %s: %w", key, err)
	}
	return nil
}

// GetChunk returns a streaming reader for key, or ErrNotFound.
func (b *S3) GetChunk(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &b.bucket, Key: &key})
	if err != nil {
		if isS3NotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("objectstore: S3 get %s: %w", key, err)
	}
	return out.Body, nil
}

// Head returns the object size, or ErrNotFound.
func (b *S3) Head(ctx context.Context, key string) (int64, error) {
	out, err := b.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &b.bucket, Key: &key})
	if err != nil {
		if isS3NotFound(err) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("objectstore: S3 head %s: %w", key, err)
	}
	if out.ContentLength == nil {
		return 0, nil
	}
	return *out.ContentLength, nil
}

// Delete removes key. Deleting a missing key is not an error (S3 DELETE
// is idempotent).
func (b *S3) Delete(ctx context.Context, key string) error {
	if _, err := b.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &b.bucket, Key: &key}); err != nil {
		if isS3NotFound(err) {
			return nil
		}
		return fmt.Errorf("objectstore: S3 delete %s: %w", key, err)
	}
	return nil
}

// isS3NotFound reports whether err is a missing-key error: the typed
// NoSuchKey/NotFound errors, or any API error with a 404 status
// (HeadObject returns an untyped 404, and S3-compatible providers vary).
func isS3NotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		if code == "NoSuchKey" || code == "NotFound" || code == "404" {
			return true
		}
	}
	var respErr interface{ HTTPStatusCode() int }
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusNotFound {
		return true
	}
	// Some providers wrap the status in the message.
	return strings.Contains(err.Error(), "StatusCode: 404") ||
		strings.Contains(err.Error(), "NoSuchKey")
}
