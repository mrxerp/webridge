package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"webridge/internal/audit"
	"webridge/internal/auth"
	"webridge/internal/config"
	"webridge/internal/handlers"
	appmiddleware "webridge/internal/middleware"
	"webridge/internal/wetransfer"
)

func main() {
	configPath := flag.String("config", config.GetConfigPath(), "Path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := setupLogger(cfg.Logging)

	wtClient := wetransfer.NewClient(time.Duration(cfg.WeTransfer.RequestTimeout), cfg.WeTransfer.MaxRedirects)

	rateLimiter := appmiddleware.NewRateLimiter(cfg.Limits.RateLimitPerMinute)

	var auditStore *audit.Store
	auditStore, err = audit.OpenStore(cfg.Audit.DBPath, logger)
	if err != nil {
		logger.Warn("audit store unavailable, using in-memory", "error", err)
	}
	if auditStore != nil {
		defer auditStore.Close()
		auditStore.Purge(cfg.Audit.RetentionDays)
		logger.Info("audit store ready", "db", cfg.Audit.DBPath, "retention_days", cfg.Audit.RetentionDays)
	}

	auditLog := audit.NewWithStore(5000, auditStore, audit.AnomalyConfig{
		OffHoursStart:      cfg.Audit.OffHoursStart,
		OffHoursEnd:        cfg.Audit.OffHoursEnd,
		BulkDownloadCount:  cfg.Audit.BulkDownloadCount,
		BulkDownloadWindow: cfg.Audit.BulkDownloadWindow,
		MaxFileSizeGB:      cfg.Audit.MaxFileSizeGB,
	})
	ldapFile := os.Getenv("LDAP_SETTINGS_FILE")
	if ldapFile == "" {
		ldapFile = filepath.Join(filepath.Dir(*configPath), "ldap-settings.json")
	}
	imapFile := os.Getenv("IMAP_SETTINGS_FILE")
	if imapFile == "" {
		imapFile = filepath.Join(filepath.Dir(*configPath), "imap-settings.json")
	}
	authSvc := auth.New(cfg, logger, ldapFile, imapFile)
	downloadHandler := handlers.NewDownloadHandler(cfg, logger, auditLog, wtClient)
	uiHandler := handlers.UIHandler(cfg)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handlers.Healthz)

	guard := func(perm string, h http.Handler) http.Handler {
		return authSvc.RequireAuth(authSvc.RequirePerm(perm)(h))
	}

	mux.HandleFunc("POST /api/v1/auth/login", authSvc.Login(auditLog))
	mux.HandleFunc("POST /api/v1/auth/logout", authSvc.Logout(auditLog))

	mux.Handle("GET /api/v1/me", authSvc.RequireAuth(http.HandlerFunc(authSvc.Me)))
	mux.Handle("GET /api/v1/downloads/recent", authSvc.RequireAuth(http.HandlerFunc(downloadHandler.RecentHandler)))

	mux.Handle("GET /api/v1/info", guard("download", http.HandlerFunc(downloadHandler.InfoHandler)))
	mux.Handle("GET /api/v1/download", guard("download", http.HandlerFunc(downloadHandler.ServeHTTP)))

	mux.Handle("GET /api/v1/admin/metrics", guard("audit", http.HandlerFunc(auditLog.MetricsHandler)))
	mux.Handle("GET /api/v1/admin/audit", guard("audit", http.HandlerFunc(auditLog.EventsHandler)))
	mux.Handle("GET /api/v1/admin/audit/export", guard("audit", http.HandlerFunc(auditLog.ExportCSVHandler)))
	mux.Handle("POST /api/v1/audit/log", authSvc.RequireAuth(http.HandlerFunc(auditLog.LogClientEvent)))

	mux.Handle("GET /api/v1/admin/users", guard("users", http.HandlerFunc(authSvc.ListUsers)))
	mux.Handle("GET /api/v1/admin/ldap", guard("users", http.HandlerFunc(authSvc.LDAPStatus)))
	mux.Handle("PUT /api/v1/admin/ldap", guard("users", http.HandlerFunc(authSvc.UpdateLDAP(auditLog))))
	mux.Handle("GET /api/v1/admin/imap", guard("users", http.HandlerFunc(authSvc.IMAPStatus)))
	mux.Handle("PUT /api/v1/admin/imap", guard("users", http.HandlerFunc(authSvc.UpdateIMAP(auditLog))))
	mux.Handle("POST /api/v1/admin/imap/test", guard("users", http.HandlerFunc(authSvc.TestIMAP(auditLog))))
	mux.Handle("POST /api/v1/admin/users", guard("users", http.HandlerFunc(authSvc.CreateUser(auditLog))))
	mux.Handle("PUT /api/v1/admin/users/{username}", guard("users", http.HandlerFunc(authSvc.UpdateUser(auditLog))))
	mux.Handle("DELETE /api/v1/admin/users/{username}", guard("users", http.HandlerFunc(authSvc.DeleteUser(auditLog))))

	mux.Handle("GET /api/v1/admin/groups", guard("groups", http.HandlerFunc(authSvc.ListGroups)))
	mux.Handle("POST /api/v1/admin/groups", guard("groups", http.HandlerFunc(authSvc.CreateGroup(auditLog))))
	mux.Handle("PUT /api/v1/admin/groups/{name}", guard("groups", http.HandlerFunc(authSvc.UpdateGroup(auditLog))))
	mux.Handle("DELETE /api/v1/admin/groups/{name}", guard("groups", http.HandlerFunc(authSvc.DeleteGroup(auditLog))))

	mux.Handle("GET /api/v1/admin/bruteforce", guard("users", http.HandlerFunc(authSvc.BruteforceStateHandler)))
	mux.Handle("PUT /api/v1/admin/bruteforce/config", guard("users", http.HandlerFunc(authSvc.BruteforceConfigHandler)))
	mux.Handle("POST /api/v1/admin/bruteforce/reset", guard("users", http.HandlerFunc(authSvc.BruteforceResetHandler)))

	mux.Handle("/", uiHandler)

	var handler http.Handler = mux
	for _, mw := range []func(http.Handler) http.Handler{
		appmiddleware.AccessLog(cfg.Audit.AccessLogDir, logger),
		appmiddleware.Logging(logger),
		appmiddleware.SecurityHeaders,
		appmiddleware.ValidateURL,
		rateLimiter.Middleware,
	} {
		handler = mw(handler)
	}

	server := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:        handler,
		ReadTimeout:    time.Duration(cfg.Server.ReadTimeout),
		WriteTimeout:   time.Duration(cfg.Server.WriteTimeout),
		IdleTimeout:    time.Duration(cfg.Server.IdleTimeout),
		MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
	}

	go func() {
		logger.Info("starting server", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("server exited")
}

func setupLogger(cfg config.LoggingConfig) *slog.Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}
