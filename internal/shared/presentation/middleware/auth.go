package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/infrastructure"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

var (
	ErrAuthHeaderRequired      = pkg.NewDomainError("authHeaderRequired", "authorization header is required")
	ErrAuthHeaderPrefixInvalid = pkg.NewDomainError("authHeaderPrefixInvalid", "authorization header must start with Bearer")
	ErrInvalidToken            = pkg.NewDomainError("invalidToken", "invalid token")
	ErrTokenUserIDNotExists    = pkg.NewDomainError("tokenUserIDNotExists", "user ID not exists in token")
	ErrInvalidUserID           = pkg.NewDomainError("invalidUserID", "invalid user ID in token")
)

type contextKey string

const (
	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "
	UserIDKey           = contextKey("userID")
)

func AuthenticateMiddleware(tokenSvc *infrastructure.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader(AuthorizationHeader)
		if header == "" {
			c.Error(ErrAuthHeaderRequired)
			c.Abort()
			return
		}
		if !strings.HasPrefix(header, BearerPrefix) {
			c.Error(ErrAuthHeaderPrefixInvalid)
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(header, BearerPrefix)
		claims, err := tokenSvc.ValidateTokenJWT(c.Request.Context(), tokenString)
		if err != nil {
			c.Error(ErrInvalidToken)
			c.Abort()
			return
		}

		c.Set(UserIDKey, claims.Subject)
		c.Next()
	}
}

func GetCtxUserID(c *gin.Context) (uuid.UUID, error) {
	userID, exists := c.Get(UserIDKey)
	if !exists {
		return uuid.UUID{}, ErrTokenUserIDNotExists
	}

	userUUID, err := uuid.Parse(userID.(string))
	if err != nil {
		return uuid.UUID{}, ErrInvalidUserID
	}

	return userUUID, nil
}
