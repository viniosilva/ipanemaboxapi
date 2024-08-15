package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/viniosilva/ipanemaboxapi/internal/factory"
	"github.com/viniosilva/ipanemaboxapi/internal/utils/logger"
)

var (
	host     = flag.String("host", "localhost", "host to listen on")
	port     = flag.String("port", "3000", "port to listen on")
	logLevel = flag.Uint("log-level", 4, "set loglevel")
)

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logger.GetLogLevel(*logLevel)}))
	slog.SetDefault(logger)

	factory := factory.Build()

	router := gin.Default()
	router.GET("/api/healthcheck", factory.HealthCheckController.Check)
	router.POST("/api/v1/customers", factory.CustomerController.Create)

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", *host, *port),
		Handler: router.Handler(),
	}

	go func() {
		slog.Info(fmt.Sprintf("api listening on %s", srv.Addr))

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("server exiting")
}

// Refs: https://gin-gonic.com/docs/examples/graceful-restart-or-stop/
