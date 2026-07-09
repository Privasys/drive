// Privasys Drive — service entrypoint.
//
// Subcommands:
//
//	drive serve [--addr ADDR] [--db DSN] [--state DIR] [--dev]
//
// On the platform (enclave-os-virtual) the manager injects $PORT and the
// sealed per-app volume is mounted at /data; the service keeps its index,
// object store and instance config there and re-lifts the manager's
// configure-then-freeze gate on restart from the persisted config.
//
// In `--dev` the service uses an in-memory SQLite store, a local-disk
// object backend under --state, and the dev OIDC verifier
// (`Authorization: Bearer dev:<sub>:<email>`).
package main

import (
	"context"
	"crypto/rand"
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
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/Privasys/drive/service/internal/api"
	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/oidc"
	"github.com/Privasys/drive/service/internal/platform"
	"github.com/Privasys/drive/service/internal/store"
	"github.com/Privasys/drive/service/internal/vaultmek"
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

// defaultStateDir is the sealed per-app volume on the platform, a local
// dir otherwise. Overridable via DRIVE_STATE_DIR / --state.
func defaultStateDir(onPlatform bool) string {
	if d := os.Getenv("DRIVE_STATE_DIR"); d != "" {
		return d
	}
	if onPlatform {
		return "/data"
	}
	return "data-dev"
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func serve(args []string) error {
	pf := platform.Load()

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr(), "listen address (env: PORT for the platform-allocated port)")
	dsn := fs.String("db", "", "SQL DSN; empty == <state>/drive.db (in-memory for --dev)")
	state := fs.String("state", defaultStateDir(pf.OnPlatform()), "state dir: index DB, object store, instance config (env: DRIVE_STATE_DIR)")
	dev := fs.Bool("dev", false, "enable dev verifier and ephemeral defaults")
	mekHex := fs.String("mek-hex", "", "hex MEK for dev/test (env: DRIVE_MEK_HEX)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(*state, 0o700); err != nil {
		return err
	}

	dataSource := *dsn
	if dataSource == "" {
		dataSource = os.Getenv("DRIVE_DB_DSN")
	}
	driver, dialect := "sqlite", store.DialectSQLite
	switch {
	case strings.HasPrefix(dataSource, "postgres://") || strings.HasPrefix(dataSource, "postgresql://"):
		driver, dialect = "pgx", store.DialectPostgres
	case dataSource == "" && *dev:
		dataSource = ":memory:"
	case dataSource == "":
		dataSource = filepath.Join(*state, "drive.db")
	}
	db, err := sql.Open(driver, dataSource)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	st, err := store.New(db, dialect)
	if err != nil {
		return err
	}
	bk, err := openBackend(context.Background(), *state)
	if err != nil {
		return err
	}
	gr := grants.New(db, dialect == store.DialectPostgres)

	mek, err := loadMEK(*mekHex, *state, *dev)
	if err != nil {
		return err
	}

	var verifier oidc.Verifier
	var revoked *oidc.RevokedSet
	if *dev {
		verifier = oidc.DevVerifier{}
	} else {
		issuer := env("OIDC_ISSUER", "https://privasys.id")
		verifier = oidc.NewJWKSVerifier(issuer, os.Getenv("OIDC_AUDIENCE"))
		if feed := env("OIDC_REVOKED_URL", issuer+"/sessions/revoked"); feed != "off" {
			revoked = oidc.NewRevokedSet(feed, 0)
		}
	}

	// Per-tenant vault MEKs need the manager-minted app identity, so the
	// client only exists on the platform; off-platform tenants stay on
	// the instance MEK.
	var meks *vaultmek.Client
	if pf.OnPlatform() && pf.ContainerToken != "" {
		meks = vaultmek.New(pf.ManagerURL+"/api/v1/vault-identity", pf.ContainerToken)
	}

	srv := &api.Server{
		Store:    st,
		Backend:  bk,
		Grants:   gr,
		Verifier: verifier,
		MEK:      mek,
		MEKs:     meks,
		Revoked:  revoked,
		Platform: pf,
		StateDir: *state,
		DevMode:  *dev,
		Version:  version,
	}

	// Re-apply persisted config on restart: the manager re-arms the
	// configure-then-freeze gate on every container load, so read the
	// sealed config and re-lift the gate ourselves (no owner needed
	// after the one-time setup).
	if cfg, err := config.Load(*state); err != nil {
		log.Printf("drive: read persisted config: %v", err)
	} else if cfg != nil {
		srv.InstallConfig(cfg)
		if err := pf.LiftFreeze(); err != nil {
			log.Printf("drive: re-lift freeze on restart: %v", err)
		} else if pf.OnPlatform() {
			log.Printf("drive: re-applied persisted config (mode %s); freeze lifted", cfg.Mode)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	revoked.Start(ctx)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(manifestPath()),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("drive %s listening on http://%s (state=%s)", version, *addr, filepath.Clean(*state))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	sdCtx, sdCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sdCancel()
	return httpSrv.Shutdown(sdCtx)
}

// openBackend selects the instance object backend from the environment:
// DRIVE_OBJECT_BACKEND=gcs uses Google Cloud Storage (DRIVE_GCS_BUCKET,
// optional DRIVE_GCS_KEY_FILE — else application default credentials);
// anything else uses the local-disk backend under <state>/objects. A
// per-tenant BYO bucket credential can override this per tenant later.
func openBackend(ctx context.Context, state string) (objectstore.Backend, error) {
	switch strings.ToLower(os.Getenv("DRIVE_OBJECT_BACKEND")) {
	case "gcs":
		bucket := os.Getenv("DRIVE_GCS_BUCKET")
		var creds []byte
		if kf := os.Getenv("DRIVE_GCS_KEY_FILE"); kf != "" {
			b, err := os.ReadFile(kf)
			if err != nil {
				return nil, fmt.Errorf("DRIVE_GCS_KEY_FILE: %w", err)
			}
			creds = b
		}
		return objectstore.NewGCS(ctx, objectstore.GCSConfig{Bucket: bucket, CredentialsJSON: creds})
	case "s3", "ovh":
		cfg := objectstore.S3Config{
			Bucket:    os.Getenv("DRIVE_S3_BUCKET"),
			Region:    os.Getenv("DRIVE_S3_REGION"),
			Endpoint:  os.Getenv("DRIVE_S3_ENDPOINT"),
			AccessKey: os.Getenv("DRIVE_S3_ACCESS_KEY"),
			SecretKey: os.Getenv("DRIVE_S3_SECRET_KEY"),
		}
		if strings.ToLower(os.Getenv("DRIVE_OBJECT_BACKEND")) == "ovh" {
			return objectstore.NewOVH(ctx, cfg)
		}
		return objectstore.NewS3(ctx, cfg)
	default:
		objectsDir := filepath.Join(state, "objects")
		if err := os.MkdirAll(objectsDir, 0o700); err != nil {
			return nil, err
		}
		return objectstore.NewLocal(objectsDir)
	}
}

// manifestPath locates the image-baked privasys.json (also the source of
// the org.privasys.manifest OCI label); dev runs pick it up from the cwd.
func manifestPath() string {
	if p := os.Getenv("DRIVE_MANIFEST_PATH"); p != "" {
		return p
	}
	for _, p := range []string{"/privasys.json", "privasys.json"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// loadMEK resolves the interim instance-wide MEK. An explicit hex seed
// wins (tests / local runs) and --dev uses a deterministic value;
// otherwise a random MEK is generated on first boot and persisted on
// the state dir, which on the platform is the sealed /data volume
// (protected by the vault-backed, measurement-gated volume DEK).
// Per-tenant vault-held MEKs supersede this instance-wide interim.
func loadMEK(mekHex, stateDir string, dev bool) ([]byte, error) {
	if mekHex == "" {
		mekHex = os.Getenv("DRIVE_MEK_HEX")
	}
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
	mekPath := filepath.Join(stateDir, "mek")
	if b, err := os.ReadFile(mekPath); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("persisted MEK at %s has length %d, want 32", mekPath, len(b))
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	mek := make([]byte, 32)
	if _, err := rand.Read(mek); err != nil {
		return nil, err
	}
	if err := os.WriteFile(mekPath, mek, 0o600); err != nil {
		return nil, err
	}
	log.Printf("drive: generated instance MEK, persisted on %s", filepath.Clean(stateDir))
	return mek, nil
}
