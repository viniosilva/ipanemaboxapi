package exception

import (
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/vinosilva/ipanemaboxapi/mock"
)

func TestValidationException(t *testing.T) {
	tests := map[string]struct {
		err      validator.ValidationErrors
		wantErr  string
		wantErrs []string
	}{
		"should be an errors": {
			err:      validator.ValidationErrors{&mock.FieldError{Itag: "error", Ins: "error"}},
			wantErr:  `Key: 'error' Error:Field validation for '' failed on the 'error' tag`,
			wantErrs: []string{`Key: 'error' Error:Field validation for '' failed on the 'error' tag`},
		},
		"should be 2 errors": {
			err: validator.ValidationErrors{
				&mock.FieldError{Itag: "error 1", Ins: "error 1"},
				&mock.FieldError{Itag: "error 2", Ins: "error 2"},
			},
			wantErr: `Key: 'error 1' Error:Field validation for '' failed on the 'error 1' tag, Key: 'error 2' Error:Field validation for '' failed on the 'error 2' tag`,
			wantErrs: []string{
				`Key: 'error 1' Error:Field validation for '' failed on the 'error 1' tag`,
				`Key: 'error 2' Error:Field validation for '' failed on the 'error 2' tag`,
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := NewValidationException(tt.err)

			assert.Equal(t, ValidationExceptionName, got.Name)
			assert.Equal(t, tt.wantErr, got.Error())
			assert.Equal(t, tt.wantErrs, got.Errors)
		})
	}
}
