package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/viniosilva/ipanemaboxapi/internal/factory"
	"github.com/viniosilva/ipanemaboxapi/internal/utils/config"
	"github.com/viniosilva/ipanemaboxapi/internal/utils/logger"
	"github.com/viniosilva/ipanemaboxapi/pkg/postgres"
)

func main() {
	cfg, err := config.ViperConfigure(".")
	if err != nil {
		slog.Error(fmt.Sprintf("failed on config.ViperConfigure: %v", err))
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logger.GetLogLevel(cfg.Api.LogLevel)}))
	slog.SetDefault(logger)

	db, err := postgres.Connect(cfg.DB.Host, cfg.DB.Port, cfg.DB.DbName, cfg.DB.Username, cfg.DB.Password, cfg.DB.Ssl)
	if err != nil {
		slog.Error(fmt.Sprintf("failed on postgres.Connect: %v", err))
		os.Exit(1)
	}

	factory := factory.Build(db)

	router := gin.Default()
	router.GET("/api/healthcheck", factory.HealthCheckController.Check)
	router.POST("/api/v1/customers", factory.CustomerController.Create)

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", cfg.Api.Host, cfg.Api.Port),
		Handler: router.Handler(),
	}

	go func() {
		slog.Info(fmt.Sprintf("api listening on %s", srv.Addr))

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error(fmt.Sprintf("failed on srv.ListenAndServe: %v", err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	if err := db.Close(); err != nil {
		slog.Error(fmt.Sprintf("db close error: %v", err))
	}

	slog.Info("server exiting")
}

// Refs: https://gin-gonic.com/docs/examples/graceful-restart-or-stop/
