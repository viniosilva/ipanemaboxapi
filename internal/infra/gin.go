package infra

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/vinosilva/ipanemaboxapi/docs"
	"go.uber.org/zap"
)

type HealthController interface {
	Check(ctx *gin.Context)
}

type CustomerController interface {
	Create(ctx *gin.Context)
	FindAll(ctx *gin.Context)
	FindByID(ctx *gin.Context)
	Update(ctx *gin.Context)
}

// @title           Ipanema Box API
// @version         0.0.1
// @description     Ipanema Box management system
// @contact.name   API Support
// @contact.email  support@ipanemabox.com.br
func GinSetup(host, port string, logger *zap.SugaredLogger, healthController HealthController, customerController CustomerController) *gin.Engine {
	r := gin.New()
	r.Use(JSONLogMiddleware(logger, []string{"/api/swagger/", "/api/healthcheck"}))
	r.Use(gin.Recovery())

	docs.SwaggerInfo.BasePath = "/api"

	if host != "" {
		docs.SwaggerInfo.Host = fmt.Sprintf("%s:%s", host, port)
	}

	r.GET("/api/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	r.GET("/api/healthcheck", healthController.Check)

	r.POST("/api/v1/customers", customerController.Create)
	r.GET("/api/v1/customers", customerController.FindAll)
	r.GET("/api/v1/customers/:customer_id", customerController.FindByID)
	r.PATCH("/api/v1/customers/:customer_id", customerController.Update)

	return r
}

func JSONLogMiddleware(logger *zap.SugaredLogger, skipPaths []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		for _, p := range skipPaths {
			if strings.HasPrefix(path, p) {
				return
			}
		}

		start := time.Now()
		query := c.Request.URL.RawQuery

		c.Next()

		duration := time.Now().Sub(start)

		loggerFn := logger.Infow
		if c.Writer.Status() >= http.StatusInternalServerError {
			loggerFn = logger.Errorw
		}

		loggerFn("request",
			"client_ip", c.ClientIP(),
			"start", start.UnixMilli(),
			"duration", duration.Milliseconds(),
			"method", c.Request.Method,
			"path", c.Request.RequestURI,
			"query", query,
			"status", c.Writer.Status(),
			"referrer", c.Request.Referer(),
			"request_id", c.Writer.Header().Get("Request-Id"),
		)
	}
}
