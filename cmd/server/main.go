package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/viniosilva/ipanemaboxapi/docs"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/application"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/infrastructure"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/presentation"
	"github.com/viniosilva/ipanemaboxapi/internal/shared/presentation/middleware"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

// @title Ipanema Box API
// @version 1.0
// @description API for the Ipanema Box project
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token
func main() {
	docs.SwaggerInfo.BasePath = "/api"

	r := gin.Default()
	r.Use(middleware.ErrorHandler())

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "OK"})
	})

	di := makeDIContainer()
	presentation.SetupRouter(r.Group("/api"), di.AuthHandler, di.TokenService)

	addr := fmt.Sprintf("%s:%s", os.Getenv("API_HOST"), os.Getenv("API_PORT"))
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	go func() {
		log.Printf("server listening on %s\n", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	log.Println("shutdown server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Println("server shutdown:", err)
	}

	log.Println("server exiting")
}

type DIContainer struct {
	AuthHandler  *presentation.AuthHandler
	TokenService *infrastructure.TokenService
}

func makeDIContainer() *DIContainer {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("failed to load .env file: %v", err)
	}

	db, err := pkg.NewPostgresGormDB(
		os.Getenv("POSTGRES_USERNAME"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
		os.Getenv("POSTGRES_DBNAME"),
		os.Getenv("POSTGRES_TZ"),
		os.Getenv("POSTGRES_SSL") == "true",
	)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	cacheDB, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		log.Fatalf("failed to convert REDIS_DB to int: %v", err)
	}

	cache := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       cacheDB,
	})

	tokenJWTExpiresAtInMinutes, err := strconv.ParseInt(os.Getenv("TOKEN_JWT_EXPIRES_AT_IN_MIN"), 10, 64)
	if err != nil {
		log.Fatalf("failed to convert TOKEN_JWT_EXPIRES_AT to int: %v", err)
	}
	refreshTokenExpiresAtInMinutes, err := strconv.ParseInt(os.Getenv("REFRESH_TOKEN_EXPIRES_AT_IN_MIN"), 10, 64)
	if err != nil {
		log.Fatalf("failed to convert REFRESH_TOKEN_EXPIRES_AT to int: %v", err)
	}

	tokenRepo := infrastructure.NewRedisTokenRepository(cache, "token")
	tokenSvc := infrastructure.NewTokenService(tokenRepo,
		os.Getenv("SERVICE_NAME"),
		os.Getenv("TOKEN_SECRET_KEY"),
		time.Duration(tokenJWTExpiresAtInMinutes)*time.Minute,
		time.Duration(refreshTokenExpiresAtInMinutes)*time.Minute,
	)

	authRepo := infrastructure.NewUserRepository(db)
	authSvc := application.NewAuthService(authRepo, tokenSvc)

	return &DIContainer{
		AuthHandler:  presentation.NewAuthHandler(authSvc),
		TokenService: tokenSvc,
	}
}
