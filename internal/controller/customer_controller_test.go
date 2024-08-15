package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/controller/presenter"
)

func TestNewCustomerController(t *testing.T) {
	got := NewCustomerController()

	assert.NotNil(t, got)
}

func TestCustomerController_Create(t *testing.T) {
	type args struct {
		payload string
	}
	tests := map[string]struct {
		args       args
		wantStatus int
		want       presenter.CustomerRes
		wantErr    presenter.ErrorRes
	}{
		"should be successful": {
			args: args{
				payload: `{"name":"Testing"}`,
			},
			wantStatus: http.StatusCreated,
			want:       presenter.CustomerRes{ID: 1, Name: "Testing"},
		},
		"should throw error when payload is empty": {
			args:       args{payload: "{}"},
			wantStatus: http.StatusBadRequest,
			wantErr:    presenter.ErrorRes{Message: "Key: 'CustomerReq.Name' Error:Field validation for 'Name' failed on the 'required' tag"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			controller := NewCustomerController()
			r := gin.Default()
			r.POST("/api/v1/customers", controller.Create)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPost, "/api/v1/customers", strings.NewReader(tt.args.payload))
			r.ServeHTTP(w, req)

			var body presenter.CustomerRes
			json.Unmarshal(w.Body.Bytes(), &body)
			var bodyErr presenter.ErrorRes
			json.Unmarshal(w.Body.Bytes(), &bodyErr)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.want, body)
			assert.Equal(t, tt.wantErr, bodyErr)
		})
	}
}
