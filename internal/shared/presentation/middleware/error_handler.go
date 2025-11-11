package middleware

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

const (
	internalServerErrorMessage = "an unexpected error occurred"
)

type ServerErrorResponse struct {
	Message string `json:"message" example:"an unexpected error occurred"`
}

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err

			var domainErr pkg.DomainError
			if errors.As(err, &domainErr) {
				switch domainErr.Code() {
				case ErrAuthHeaderRequired.Code(),
					ErrAuthHeaderPrefixInvalid.Code(),
					ErrInvalidToken.Code(),
					ErrTokenUserIDNotExists.Code(),
					ErrInvalidUserID.Code():
					c.JSON(http.StatusUnauthorized, ServerErrorResponse{
						Message: domainErr.Error(),
					})
					return
				default:
					c.JSON(http.StatusInternalServerError, ServerErrorResponse{
						Message: internalServerErrorMessage,
					})
					return
				}
			}

			var validationErr pkg.ValidationError
			if errors.As(err, &validationErr) {
				c.JSON(http.StatusUnprocessableEntity, validationErr)
				return
			}

			c.JSON(http.StatusInternalServerError, ServerErrorResponse{
				Message: internalServerErrorMessage,
			})
		}
	}
}
