package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Converter turns a non-text document (PDF / Office / image) into
// markdown for the section builder. Returns the converted text and the
// converter identity (stamped on the stored conversion).
type Converter interface {
	Convert(ctx context.Context, name, mime string, content []byte) (text string, converter string, err error)
}

// SidecarConverter talks to the in-container docling sidecar over its
// unix socket (never TCP: co-located apps share the host network
// namespace on enclave-os). Conversion of large scanned PDFs on CPU can
// take minutes; the indexer is a background worker, so the timeout is
// generous.
type SidecarConverter struct {
	Socket string
	// Version identifies the conversion pipeline for the stored stamp;
	// filled from /healthz on first use.
	version string
	client  *http.Client
}

// NewSidecarConverter returns a converter for the given unix socket,
// or nil when the socket path is empty (no sidecar in this build).
func NewSidecarConverter(socket string) *SidecarConverter {
	if socket == "" {
		return nil
	}
	return &SidecarConverter{
		Socket: socket,
		client: &http.Client{
			Timeout: 10 * time.Minute,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

func (c *SidecarConverter) name() string {
	if c.version == "" {
		// Best-effort health probe for the version stamp.
		resp, err := c.client.Get("http://docling/healthz")
		if err == nil {
			var h struct {
				Docling string `json:"docling"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&h)
			resp.Body.Close()
			if h.Docling != "" {
				c.version = "docling/" + h.Docling
			}
		}
		if c.version == "" {
			return "docling"
		}
	}
	return c.version
}

func (c *SidecarConverter) Convert(ctx context.Context, name, _ string, content []byte) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docling/convert", bytes.NewReader(content))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("X-Filename", name)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("docling sidecar: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Markdown string `json:"markdown"`
		Error    string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return "", "", fmt.Errorf("docling sidecar: %w", err)
	}
	if resp.StatusCode == http.StatusUnprocessableEntity {
		// The document itself cannot be converted (corrupt, encrypted,
		// unsupported) — a permanent error, not a sidecar outage.
		return "", "", &PermanentError{Msg: strings.TrimSpace(out.Error)}
	}
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("docling sidecar: status %d: %s", resp.StatusCode, out.Error)
	}
	return out.Markdown, c.name(), nil
}

// PermanentError marks a conversion failure that retrying cannot fix
// (the indexer sets status failed instead of parking pending).
type PermanentError struct{ Msg string }

func (e *PermanentError) Error() string { return "conversion failed: " + e.Msg }
