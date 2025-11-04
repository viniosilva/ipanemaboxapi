package middleware

import (
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
			switch v := c.Errors.Last().Err.(type) {
			case pkg.ValidationError:
				c.JSON(http.StatusUnprocessableEntity, v)
			case pkg.DomainError:
				switch v.Code() {
				case ErrAuthHeaderRequired.Code(),
					ErrAuthHeaderPrefixInvalid.Code(),
					ErrInvalidToken.Code(),
					ErrTokenUserIDNotExists.Code(),
					ErrInvalidUserID.Code():
					c.JSON(http.StatusUnauthorized, ServerErrorResponse{
						Message: v.Error(),
					})
				default:
					c.JSON(http.StatusInternalServerError, ServerErrorResponse{
						Message: internalServerErrorMessage,
					})
				}
			default:
				c.JSON(http.StatusInternalServerError, ServerErrorResponse{
					Message: internalServerErrorMessage,
				})
			}
		}
	}
}
