package main

import (
    "context"
    "crypto/rsa"
    "database/sql"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/fsnotify/fsnotify"
    "github.com/getsentry/sentry-go"
    "github.com/natefinch/lumberjack"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/sirupsen/logrus"

    "github.com/ajadi/NodeGoDNS/auth"
    "github.com/ajadi/NodeGoDNS/backup"
    "github.com/ajadi/NodeGoDNS/cache"
    "github.com/ajadi/NodeGoDNS/config"
    "github.com/ajadi/NodeGoDNS/dnsserver"
    "github.com/ajadi/NodeGoDNS/grpcapi"
    "github.com/ajadi/NodeGoDNS/httpapi"
    "github.com/ajadi/NodeGoDNS/middleware"
    "github.com/ajadi/NodeGoDNS/models"
    "github.com/ajadi/NodeGoDNS/utils"

    _ "github.com/lib/pq"
    _ "github.com/mattn/go-sqlite3"
)

// main is the entry point of NodeGoDNS application.
// It loads configuration, sets up logging, initializes DB,
// starts DNS, HTTP, and gRPC servers, and handles graceful shutdown.
func main() {
    cfg := config.LoadConfig()

    // Initialize Sentry if DSN is provided
    utils.InitializeSentry(os.Getenv("SENTRY_DSN"))
    defer sentry.Flush(2 * time.Second)

    // Logging to a rotating file
    logrus.SetFormatter(&logrus.JSONFormatter{})
    logrus.SetOutput(&lumberjack.Logger{
        Filename:   "logs/server.log",
        MaxSize:    100,
        MaxBackups: cfg.MaxBackups,
        MaxAge:     28,
        Compress:   true,
    })
    level, err := logrus.ParseLevel(cfg.LogLevel)
    if err != nil {
        logrus.Warn("Invalid log level, defaulting to info")
        level = logrus.InfoLevel
    }
    logrus.SetLevel(level)

    // Initialize database (PostgreSQL or SQLite)
    db, err := initializeDatabase(cfg)
    if err != nil {
        logrus.Fatal("Database initialization error:", err)
    }
    defer db.Close()

    // Create backup & cache services
    backupSvc := backup.NewBackupService(cfg.BackupDir, cfg.ZonesBackupDir, cfg.KeysBackupDir, cfg.MaxBackups)
    cacheSvc := cache.NewDNSCache(cfg.CacheDefaultTTL, cfg.CacheCleanupInterval)

    // Load DNS zones from local JSON files
    zones := make(map[string]models.Zone)
    zonesMutex := &sync.RWMutex{}
    if err := utils.LoadZones(zones, zonesMutex, cfg.ZonesDir); err != nil {
        logrus.Fatal("Error loading zones:", err)
    }

    // Generate or load DNSSEC keys (ZSK/KSK)
    zsk, err := utils.LoadPrivateKey("keys/zsk.pem")
    if err != nil {
        zsk, err = utils.GenerateRSAKey(2048)
        if err != nil {
            logrus.Fatal("Error generating ZSK:", err)
        }
        if err := utils.SavePrivateKey("keys/zsk.pem", zsk); err != nil {
            logrus.Fatal("Error saving ZSK:", err)
        }
        logrus.Info("ZSK generated and saved")
    } else {
        logrus.Info("ZSK loaded from file")
    }

    ksk, err := utils.LoadPrivateKey("keys/ksk.pem")
    if err != nil {
        ksk, err = utils.GenerateRSAKey(2048)
        if err != nil {
            logrus.Fatal("Error generating KSK:", err)
        }
        if err := utils.SavePrivateKey("keys/ksk.pem", ksk); err != nil {
            logrus.Fatal("Error saving KSK:", err)
        }
        logrus.Info("KSK generated and saved")
    } else {
        logrus.Info("KSK loaded from file")
    }

    // Insert DNSKEY records into each zone if missing
    createAndAddDNSKEYs(zones, zonesMutex, zsk, ksk)

    // Authentication service
    authSvc := auth.NewAuthService(db, cfg.JWTSecret)
    // Example: register an admin user (ignore if "already exists")
    if err := authSvc.RegisterUser("admin", "secure_password"); err != nil {
        if !strings.Contains(err.Error(), "already exists") {
            logrus.Fatal("Error registering user:", err)
        }
    }

    // Build the HTTP API
    httpAPI := httpapi.NewHTTPAPI(
        zones, zonesMutex, backupSvc,
        func() error { return utils.SaveZones(zones, zonesMutex, cfg.ZonesDir) },
        func(action, zoneName string) {
            message := fmt.Sprintf("%s: %s", action, zoneName)
            httpAPI.SSEHub.Broadcast(message)
        },
    )

    // Build the gRPC server
    grpcServer := grpcapi.NewZoneSyncServer(
        zones, zonesMutex, backupSvc,
        func() error { return utils.SaveZones(zones, zonesMutex, cfg.ZonesDir) },
        func(action, zoneName string) {
            message := fmt.Sprintf("%s: %s", action, zoneName)
            httpAPI.SSEHub.Broadcast(message)
        },
        []byte(cfg.JWTSecret),
    )

    // Build and start DNS server
    dnsSrv := dnsserver.NewDNSServer(zones, zonesMutex, cacheSvc, zsk, ksk, true, []string{"127.0.0.1/32"})
    if err := dnsserver.StartDNSServer(dnsSrv, cfg.DNSPort); err != nil {
        logrus.Fatal("Error starting DNS server:", err)
    }

    // Build the HTTP mux with rate limiting
    httpMux := http.NewServeMux()
    httpMux.Handle("/zone", authSvc.Middleware(http.HandlerFunc(httpAPI.HandleZones)))
    httpMux.Handle("/backup", authSvc.Middleware(http.HandlerFunc(httpAPI.HandleBackup)))
    httpMux.Handle("/restore_specific_backup", authSvc.Middleware(http.HandlerFunc(httpAPI.HandleRestoreSpecificBackup)))
    httpMux.Handle("/login", http.HandlerFunc(authSvc.HandleLogin))
    httpMux.Handle("/metrics", promhttp.Handler())
    httpMux.Handle("/subscribe", authSvc.Middleware(http.HandlerFunc(httpAPI.HandleSubscribe)))

    rateLimitedHandler := middleware.RateLimiterMiddleware(httpMux)
    httpServer := &http.Server{
        Addr:    cfg.HTTPPort,
        Handler: rateLimitedHandler,
    }

    // Start HTTP
    go func() {
        logrus.WithFields(logrus.Fields{"addr": cfg.HTTPPort}).Info("HTTP API started (NodeGoDNS)")
        if err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
            logrus.Fatal("HTTP API error:", err)
        }
    }()

    // Start gRPC
    grpcSrv, err := grpcapi.StartGRPCServer(cfg.GRPCPort, cfg.TLSCertFile, cfg.TLSKeyFile, grpcServer)
    if err != nil {
        logrus.Fatal("Error starting gRPC server:", err)
    }

    // Watch .env for dynamic config changes
    go watchConfig(&cfg, func(newCfg config.Config) {
        logrus.Info("Configuration updated via .env, applying changes (NodeGoDNS)...")
        newLevel, e := logrus.ParseLevel(newCfg.LogLevel)
        if e == nil {
            logrus.SetLevel(newLevel)
        }
    })

    // Graceful shutdown
    stop := make(chan os.Signal, 1)
    signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
    <-stop

    logrus.Info("Shutdown signal received, terminating NodeGoDNS...")
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := httpServer.Shutdown(ctx); err != nil {
        logrus.Fatal("Error shutting down HTTP server:", err)
    }
    grpcSrv.GracefulStop()
    logrus.Info("NodeGoDNS application shutdown successfully")
}

// initializeDatabase chooses sqlite or postgres based on config.DBType
func initializeDatabase(cfg config.Config) (*sql.DB, error) {
    var (
        db  *sql.DB
        err error
    )
    switch cfg.DBType {
    case "postgres":
        db, err = sql.Open("postgres", cfg.DatabaseURL)
        if err != nil {
            return nil, fmt.Errorf("failed to open postgres: %w", err)
        }
    case "sqlite":
        db, err = sql.Open("sqlite3", "NodeGoDNS.db")
        if err != nil {
            return nil, fmt.Errorf("failed to open sqlite: %w", err)
        }
    default:
        return nil, fmt.Errorf("unknown DB_TYPE: %s", cfg.DBType)
    }

    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    if err := runMigrations(db, cfg.DBType); err != nil {
        return nil, fmt.Errorf("error running migrations: %w", err)
    }
    return db, nil
}

func runMigrations(db *sql.DB, dbType string) error {
    var schema string
    switch dbType {
    case "postgres":
        schema = `
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
`
    case "sqlite":
        schema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`
    default:
        return fmt.Errorf("unsupported dbType: %s", dbType)
    }

    if _, err := db.Exec(schema); err != nil {
        return fmt.Errorf("failed to exec schema: %w", err)
    }
    return nil
}

func createAndAddDNSKEYs(zones map[string]models.Zone, zonesMutex *sync.RWMutex, zsk, ksk *rsa.PrivateKey) {
    zonesMutex.Lock()
    defer zonesMutex.Unlock()

    for zoneName, zone := range zones {
        if len(zone.DNSKEY) == 0 {
            dnsKeyZSK := models.DNSKEY{
                Name:      zoneName,
                Flags:     256, // ZSK
                Protocol:  3,
                Algorithm: 8,  // RSASHA256
                PublicKey: utils.PublicKey(&zsk.PublicKey),
            }
            dnsKeyKSK := models.DNSKEY{
                Name:      zoneName,
                Flags:     257, // KSK
                Protocol:  3,
                Algorithm: 8,
                PublicKey: utils.PublicKey(&ksk.PublicKey),
            }
            zone.DNSKEY = append(zone.DNSKEY, dnsKeyZSK, dnsKeyKSK)
            zones[zoneName] = zone

            logrus.WithFields(logrus.Fields{"zone": zoneName}).
                Info("DNSKEY records added to zone")
        }
    }
}

// watchConfig monitors .env file changes for dynamic reload.
func watchConfig(cfg *config.Config, onUpdate func(config.Config)) {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        logrus.Fatal("Failed to create file watcher:", err)
    }
    defer watcher.Close()

    configPath := ".env"
    if _, err := os.Stat(configPath); os.IsNotExist(err) {
        logrus.Warn(".env file not found, skipping config watch")
        return
    }
    if err := watcher.Add(configPath); err != nil {
        logrus.Fatal("Failed to watch .env file:", err)
    }

    for {
        select {
        case event, ok := <-watcher.Events:
            if !ok {
                return
            }
            if event.Op&fsnotify.Write == fsnotify.Write {
                logrus.Info(".env file changed, reloading config (NodeGoDNS)")
                newCfg := config.LoadConfig()
                onUpdate(newCfg)
            }
        case err, ok := <-watcher.Errors:
            if !ok {
                return
            }
            logrus.Error("File watcher error:", err)
        }
    }
}
