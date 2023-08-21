package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vinosilva/ipanemaboxapi/mock"
)

func TestHealthRepository_NewHealth(t *testing.T) {
	t.Run("should be success", func(t *testing.T) {
		//setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		dbMock := mock.NewMockDB(ctrl)

		// given
		got := NewHealth(dbMock)

		assert.NotNil(t, got)
	})
}

func TestHealthRepository_Ping(t *testing.T) {
	tests := map[string]struct {
		mock    func(db *mock.MockDB)
		wantErr string
	}{
		"should be success": {
			mock: func(db *mock.MockDB) {
				db.EXPECT().PingContext(gomock.Any()).Return(nil)
			},
		},
		"should throw error": {
			mock: func(db *mock.MockDB) {
				db.EXPECT().PingContext(gomock.Any()).Return(fmt.Errorf("error"))
			},
			wantErr: "error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			//setup
			ctx := context.Background()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			dbMock := mock.NewMockDB(ctrl)
			tt.mock(dbMock)

			// given
			healthRepository := NewHealth(dbMock)

			// when
			err := healthRepository.Ping(ctx)

			// then
			if err != nil {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
