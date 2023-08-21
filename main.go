package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/vinosilva/ipanemaboxapi/internal/config"
	"github.com/vinosilva/ipanemaboxapi/internal/infra"
)

func main() {
	infra.ConfigZapLooger()

	c, err := config.GetConfig(".")
	if err != nil {
		log.Fatalf("config.GetConfig: %s\n", err)
	}

	db, err := infra.MySQLConnect(c.MySQL.Username, c.MySQL.Password, c.MySQL.Host, c.MySQL.Port,
		c.MySQL.Database, c.MySQL.ConnMaxLifetime, c.MySQL.MaxOpenConns, c.MySQL.MaxIdleConns)
	if err != nil {
		log.Fatalf("infra.MySQLConnect: %s\n", err)
	}

	dep := config.FactoryBuild(db)

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", c.Api.Host, c.Api.Port),
		Handler: infra.GinSetup(c.Api.Host, c.Api.Port, infra.Zap, dep.HealthController, dep.CustomerController),
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("srv.ListenAndServe: %s\n", err)
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx := context.Background()
	infra.Zap.Info("Shutdown server...")

	db.Close()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("srv.Shutdown: %s\n", err)
	}

	infra.Zap.Info("Bye")
}
