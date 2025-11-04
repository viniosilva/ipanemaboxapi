package presentation

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/application"
	"github.com/viniosilva/ipanemaboxapi/internal/shared/presentation/middleware"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

type AuthHandler struct {
	authService application.AuthService
}

func NewAuthHandler(authService application.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Register godoc
// @Summary Register a new user
// @Description *Validation errors:*
// @Description - name: userNameEmpty
// @Description - email: emailEmpty, emailInvalid, userAlreadyExists
// @Description - password: passwordEmpty, passwordTooLong, passwordWeak
// @Description - phone: phoneInvalid
// @Tags auth
// @Accept json
// @Produce json
// @Param user body RegisterRequest true "User to register"
// @Success 201 {object} RegisterResponse
// @Failure 422 {object} pkg.ValidationError "Unprocessable Entity"
// @Failure 500 {object} middleware.ServerErrorResponse "Internal Server Error"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.BindJSON(&req); err != nil {
		c.Error(err)
		return
	}

	user, err := h.authService.Register(c.Request.Context(), application.RegisterInput{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
		Phone:    req.Phone,
	})
	if err != nil {
		if e, ok := pkg.GetValidationErrors(err, RegisterRequestValidations); ok {
			c.Error(e)
			return
		}

		c.Error(err)
		return
	}

	res := RegisterResponse{
		ID:    user.ID,
		Name:  user.Name,
		Email: string(user.Email),
	}
	if user.Phone != nil {
		phone := string(*user.Phone)
		res.Phone = &phone
	}

	c.JSON(http.StatusCreated, res)
}

// Login godoc
// @Summary Login a user
// @Description *Validation errors:*
// @Description - email: emailEmpty, emailInvalid
// @Description - password: passwordEmpty, userNotFound
// @Tags auth
// @Accept json
// @Produce json
// @Param user body LoginRequest true "User to login"
// @Success 200 {object} LoginResponse
// @Failure 422 {object} pkg.ValidationError "Unprocessable Entity"
// @Failure 500 {object} middleware.ServerErrorResponse "Internal Server Error"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.Error(err)
		return
	}

	token, err := h.authService.Login(c.Request.Context(), application.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		if e, ok := pkg.GetValidationErrors(err, LoginRequestValidations); ok {
			c.Error(e)
			return
		}

		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token: token.Token,
	})
}

// Logout godoc
// @Summary Logout a user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 204 {object} nil "No Content"
// @Failure 401 {object} middleware.ServerErrorResponse "Unauthorized"
// @Failure 500 {object} middleware.ServerErrorResponse "Internal Server Error"
// @Router /auth/logout [delete]
func (h *AuthHandler) Logout(c *gin.Context) {
	userID, err := middleware.GetCtxUserID(c)
	if err != nil {
		c.Error(err)
		return
	}

	err = h.authService.Logout(c.Request.Context(), userID)
	if err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}

// UpdateUserPassword godoc
// @Summary Update user password
// @Description *Validation errors:*
// @Description - old_password: passwordEmpty, invalidPassword
// @Description - new_password: passwordEmpty, passwordTooLong, passwordWeak
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param user body UpdateUserPasswordRequest true "User password update data"
// @Success 204 {object} nil "No Content"
// @Failure 401 {object} middleware.ServerErrorResponse "Unauthorized"
// @Failure 403 {object} middleware.ServerErrorResponse "Forbidden"
// @Failure 422 {object} pkg.ValidationError "Unprocessable Entity"
// @Failure 500 {object} middleware.ServerErrorResponse "Internal Server Error"
// @Router /auth/update-password [put]
func (h *AuthHandler) UpdateUserPassword(c *gin.Context) {
	userID, err := middleware.GetCtxUserID(c)
	if err != nil {
		c.Error(err)
		return
	}

	var req UpdateUserPasswordRequest
	if err := c.BindJSON(&req); err != nil {
		c.Error(err)
		return
	}

	err = h.authService.UpdateUserPassword(c.Request.Context(), application.UpdateUserPasswordInput{
		UserID:      userID,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	})
	if err != nil {
		if e, ok := pkg.GetValidationErrors(err, UpdateUserPasswordRequestValidations); ok {
			c.Error(e)
			return
		}

		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}
