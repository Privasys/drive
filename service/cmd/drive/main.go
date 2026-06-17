// Privasys Drive — service entrypoint.
//
// Subcommands:
//
//	drive serve [--addr ADDR] [--db DSN] [--data DIR] [--dev]
//
// In `--dev` the service uses an in-memory SQLite store, a local-disk
// object backend rooted at --data, and the dev OIDC verifier
// (`Authorization: Bearer dev:<sub>:<email>`).
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Privasys/drive/service/internal/api"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/mcp"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/oidc"
	"github.com/Privasys/drive/service/internal/store"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: drive <serve|version> [flags]")
}

// defaultAddr honours the platform-allocated $PORT (host networking makes a
// container's listen port its host port, so the management-service assigns it
// and injects PORT). Falls back to :8443 for local runs.
func defaultAddr() string {
	if p := os.Getenv("PORT"); p != "" {
		return "0.0.0.0:" + p
	}
	return "127.0.0.1:8443"
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr(), "listen address (env: PORT for the platform-allocated port)")
	dsn := fs.String("db", "", "SQL DSN; empty == ephemeral SQLite for --dev")
	data := fs.String("data", "data-dev", "local-disk object backend root (dev only)")
	dev := fs.Bool("dev", false, "enable dev verifier and ephemeral defaults")
	mekHex := fs.String("mek-hex", "", "hex MEK for dev/test (auto-generated if empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	driver := "sqlite"
	dataSource := *dsn
	if dataSource == "" {
		dataSource = ":memory:"
	}
	db, err := sql.Open(driver, dataSource)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	st, err := store.New(db, store.DialectSQLite)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*data, 0o700); err != nil {
		return err
	}
	bk, err := objectstore.NewLocal(*data)
	if err != nil {
		return err
	}
	gr := grants.New(db, false)

	mek, err := loadMEK(*mekHex, *dev)
	if err != nil {
		return err
	}

	srv := &api.Server{
		Store:    st,
		Backend:  bk,
		Grants:   gr,
		Verifier: oidc.DevVerifier{},
		MEK:      mek,
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/", srv.Routes())
	mux.Handle("/mcp/", mcp.Handler(srv))

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("drive %s listening on http://%s (data=%s)", version, *addr, filepath.Clean(*data))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpSrv.Shutdown(ctx)
}

func loadMEK(mekHex string, dev bool) ([]byte, error) {
	if mekHex != "" {
		// Stable per process for tests / local runs.
		sum := sha256.Sum256([]byte(mekHex))
		return sum[:], nil
	}
	if dev {
		// Deterministic dev MEK so SDK + CLI tests can decrypt across restarts.
		sum := sha256.Sum256([]byte("privasys-drive-dev-mek-do-not-use-in-prod"))
		return sum[:], nil
	}
	return nil, errors.New("--mek-hex required (production: fetch from vault constellation)")
}
