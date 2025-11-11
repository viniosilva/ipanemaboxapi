package presentation

import (
	"github.com/gin-gonic/gin"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/infrastructure"
	"github.com/viniosilva/ipanemaboxapi/internal/shared/presentation/middleware"
)

func SetupRouter(router *gin.RouterGroup, h *AuthHandler, tokenSvc *infrastructure.TokenService) {
	authRouter := router.Group("/auth")
	authRouter.POST("/register", h.Register)
	authRouter.POST("/login", h.Login)
	authRouter.DELETE("/logout", middleware.AuthenticateMiddleware(tokenSvc), h.Logout)
	authRouter.PUT("/update-password", middleware.AuthenticateMiddleware(tokenSvc), h.UpdateUserPassword)
	authRouter.POST("/refresh", h.RefreshToken)
}
