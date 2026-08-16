package main

import (
	"context"
	"crypto/rsa"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/auth"
	"github.com/GagarinRu/gophkeeper/internal/config"
	"github.com/GagarinRu/gophkeeper/internal/crypto"
	"github.com/GagarinRu/gophkeeper/internal/handler"
	"github.com/GagarinRu/gophkeeper/internal/logger"
	"github.com/GagarinRu/gophkeeper/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func shutdownSignals() []os.Signal {
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if runtime.GOOS != "windows" {
		sigs = append(sigs, syscall.SIGQUIT)
	}
	return sigs
}

func resolveDataKey(opts config.ServerOptions) []byte {
	if opts.DataEncryptionKey != "" {
		return crypto.KeyFromSecret(opts.DataEncryptionKey)
	}
	return crypto.KeyFromSecret(opts.JWTSecret)
}

func main() {
	printBuildInfo()

	opts := config.DefaultServerOptions()

	if configPath := config.ConfigPath(); configPath != "" {
		file, err := config.ReadServerJSON(configPath)
		if err != nil {
			panic("failed to load config: " + err.Error())
		}
		opts, err = config.ApplyServerJSON(opts, file)
		if err != nil {
			panic("failed to apply config: " + err.Error())
		}
	}

	var (
		addr        string
		logLevel    string
		databaseDSN string
		jwtSecret   string
		dataKey     string
		cryptoKey   string
	)
	flag.StringVar(&addr, "a", opts.Address, "Server address")
	flag.StringVar(&logLevel, "l", opts.LogLevel, "Log level")
	flag.StringVar(&databaseDSN, "d", opts.DatabaseDSN, "Database DSN")
	flag.StringVar(&jwtSecret, "jwt-secret", opts.JWTSecret, "JWT signing secret")
	flag.StringVar(&dataKey, "data-key", opts.DataEncryptionKey, "Data encryption secret")
	flag.StringVar(&cryptoKey, "crypto-key", opts.CryptoKeyPath, "Path to private key for decryption")
	flag.StringVar(new(string), "c", "", "Path to JSON config file")
	flag.StringVar(new(string), "config", "", "Path to JSON config file")
	flag.Parse()

	visited := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	if visited["a"] {
		opts.Address = addr
	}
	if visited["l"] {
		opts.LogLevel = logLevel
	}
	if visited["d"] {
		opts.DatabaseDSN = databaseDSN
	}
	if visited["jwt-secret"] {
		opts.JWTSecret = jwtSecret
	}
	if visited["data-key"] {
		opts.DataEncryptionKey = dataKey
	}
	if visited["crypto-key"] {
		opts.CryptoKeyPath = cryptoKey
	}

	opts = config.ApplyServerEnv(opts)

	if err := logger.Initialize(opts.LogLevel); err != nil {
		logger.Log.Fatal("Failed to initialize logger", zap.Error(err))
	}
	defer func() { _ = logger.Log.Sync() }()

	if opts.DatabaseDSN == "" {
		logger.Log.Fatal("Database DSN is required", zap.String("hint", "use -d or DATABASE_DSN"))
	}

	store, err := storage.NewPostgresStorage(opts.DatabaseDSN, resolveDataKey(opts))
	if err != nil {
		logger.Log.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer func() { _ = store.Close() }()

	var privateKey *rsa.PrivateKey
	if opts.CryptoKeyPath != "" {
		privateKey, err = crypto.LoadPrivateKey(opts.CryptoKeyPath)
		if err != nil {
			logger.Log.Fatal("Failed to load private key", zap.String("path", opts.CryptoKeyPath), zap.Error(err))
		}
	}

	authService := auth.NewService(store, opts.JWTSecret)
	h := handler.NewHandler(store, authService, privateKey)

	logger.Log.Info("Starting server",
		zap.String("address", opts.Address),
		zap.String("database_dsn", opts.DatabaseDSN),
	)

	r := chi.NewRouter()
	r.Use(middleware.StripSlashes)
	r.Use(h.DecryptMiddleware)
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/ping", h.Ping)
	r.Post("/api/register", h.Register)
	r.Post("/api/login", h.Login)
	r.Group(func(r chi.Router) {
		r.Use(authService.RequireAuth)
		r.Post("/api/secrets", h.CreateSecret)
		r.Get("/api/secrets", h.ListSecrets)
		r.Get("/api/sync", h.Sync)
		r.Get("/api/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
			h.GetSecret(w, r, chi.URLParam(r, "id"))
		})
		r.Put("/api/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
			h.UpdateSecret(w, r, chi.URLParam(r, "id"))
		})
		r.Delete("/api/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
			h.DeleteSecret(w, r, chi.URLParam(r, "id"))
		})
	})

	server := &http.Server{Addr: opts.Address, Handler: logger.RequestLogger(r)}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.Fatal("Server failed", zap.Error(err))
		}
	}()
	logger.Log.Info("Server started", zap.String("address", opts.Address))

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals()...)
	defer stop()
	<-ctx.Done()
	logger.Log.Info("Received shutdown signal")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Log.Fatal("Server shutdown failed", zap.Error(err))
	}
	logger.Log.Info("HTTP server stopped gracefully")
}
