package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vinosilva/ipanemaboxapi/internal/dto"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
	"github.com/vinosilva/ipanemaboxapi/mock"
)

type sqlResultMock struct {
	id   int64
	rows int64
	err  error
}

func (impl sqlResultMock) LastInsertId() (int64, error) {
	return impl.id, impl.err
}
func (impl sqlResultMock) RowsAffected() (int64, error) {
	return impl.rows, impl.err
}

func TestCustomerRepository_NewCustomer(t *testing.T) {
	t.Run("should be success", func(t *testing.T) {
		//setup
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		dbMock := mock.NewMockDB(ctrl)

		// given
		got := NewCustomer(dbMock)

		assert.NotNil(t, got)
	})
}

func TestCustomerRepository_Create(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock    func(db *mock.MockDB, iTime *mock.MockITime)
		data    dto.CustomerCreateData
		want    *model.Customer
		wantErr string
	}{
		"should be success": {
			mock: func(dbMock *mock.MockDB, iTime *mock.MockITime) {
				dbMock.EXPECT().NamedExecContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(sqlResultMock{id: 1}, nil)
				iTime.EXPECT().Now().Return(tm)
			},
			data: dto.CustomerCreateData{
				FullName: "full name",
				Email:    "email@email.com",
			},
			want: &model.Customer{
				ID:        1,
				CreatedAt: &tm,
				UpdatedAt: &tm,
				FullName:  "full name",
				Email:     "email@email.com",
			},
		},
		"should throw error on db.NamedExecContext": {
			mock: func(db *mock.MockDB, iTime *mock.MockITime) {
				db.EXPECT().NamedExecContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("error"))
				iTime.EXPECT().Now().Return(tm)
			},
			wantErr: "error",
		},
		"should throw error on res.LastInsertId": {
			mock: func(db *mock.MockDB, iTime *mock.MockITime) {
				res := sqlResultMock{err: fmt.Errorf("error")}
				db.EXPECT().NamedExecContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(res, nil)
				iTime.EXPECT().Now().Return(tm)
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
			timeMock := mock.NewMockITime(ctrl)
			_time = timeMock
			tt.mock(dbMock, timeMock)

			// given
			customerRepository := NewCustomer(dbMock)

			// when
			got, err := customerRepository.Create(ctx, tt.data)

			// then
			assert.Equal(t, tt.want, got)

			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerRepository_FindAll(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock    func(db *mock.MockDB)
		data    dto.CustomerFindAllData
		want    *dto.CustomersResult
		wantErr string
	}{
		"should return customers": {
			mock: func(dbMock *mock.MockDB) {
				dbMock.EXPECT().SelectContext(gomock.Any(), gomock.Any(), gomock.Any()).SetArg(1, []model.Customer{
					{
						ID:        1,
						CreatedAt: &tm,
						UpdatedAt: &tm,
						FullName:  "full name",
						Email:     "email@email.com",
					},
				}).Return(nil)
			},
			want: &dto.CustomersResult{
				Data: []model.Customer{
					{
						ID:        1,
						CreatedAt: &tm,
						UpdatedAt: &tm,
						FullName:  "full name",
						Email:     "email@email.com",
					},
				},
			},
		},
		"should throw error": {
			mock: func(dbMock *mock.MockDB) {
				dbMock.EXPECT().SelectContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("error"))
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
			customerRepository := NewCustomer(dbMock)

			// when
			got, err := customerRepository.FindAll(ctx, tt.data)

			// then
			assert.Equal(t, tt.want, got)

			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerRepository_FindByID(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock    func(db *mock.MockDB)
		id      int64
		want    *model.Customer
		wantErr string
	}{
		"should return customer": {
			mock: func(dbMock *mock.MockDB) {
				dbMock.EXPECT().GetContext(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).SetArg(1, model.Customer{
					ID:        1,
					CreatedAt: &tm,
					UpdatedAt: &tm,
					FullName:  "full name",
					Email:     "email@email.com",
				}).Return(nil)
			},
			id: 1,
			want: &model.Customer{
				ID:        1,
				CreatedAt: &tm,
				UpdatedAt: &tm,
				FullName:  "full name",
				Email:     "email@email.com",
			},
		},
		"should throw not found exception on GetContext": {
			mock: func(dbMock *mock.MockDB) {
				dbMock.EXPECT().GetContext(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("sql: no rows in result set"))
			},
			wantErr: "customer not found",
		},
		"should throw error": {
			mock: func(dbMock *mock.MockDB) {
				dbMock.EXPECT().GetContext(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("error"))
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
			customerRepository := NewCustomer(dbMock)

			// when
			got, err := customerRepository.FindByID(ctx, tt.id)

			// then
			assert.Equal(t, tt.want, got)

			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerRepository_Update(t *testing.T) {
	tm := time.Now()

	tests := map[string]struct {
		mock    func(db *mock.MockDB, iTime *mock.MockITime)
		data    dto.CustomerUpdateData
		wantErr string
	}{
		"should be success": {
			mock: func(dbMock *mock.MockDB, iTime *mock.MockITime) {
				query := "\n\t\tUPDATE customers\n\t\tSET fullname = :fullname, email = :email, updated_at = :now\n\t\tWHERE id = :id\n\t\t\tAND updated_at = :updated_at\n\t\t\tAND deleted_at IS NULL\n\t"
				args := map[string]interface{}{
					"fullname":   "updated full name",
					"email":      "updatedemail@email.com",
					"now":        tm,
					"id":         int64(1),
					"updated_at": tm,
				}

				dbMock.EXPECT().NamedExecContext(gomock.Any(), query, args).Return(sqlResultMock{rows: 1}, nil)
				iTime.EXPECT().Now().Return(tm)
			},
			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "updated full name",
				Email:     "updatedemail@email.com",
				UpdatedAt: tm,
			},
		},
		"should be success when not send all fields": {
			mock: func(dbMock *mock.MockDB, iTime *mock.MockITime) {
				query := "\n\t\tUPDATE customers\n\t\tSET fullname = :fullname, updated_at = :now\n\t\tWHERE id = :id\n\t\t\tAND updated_at = :updated_at\n\t\t\tAND deleted_at IS NULL\n\t"
				args := map[string]interface{}{
					"fullname":   "updated full name",
					"now":        tm,
					"id":         int64(1),
					"updated_at": tm,
				}

				dbMock.EXPECT().NamedExecContext(gomock.Any(), query, args).Return(sqlResultMock{rows: 1}, nil)
				iTime.EXPECT().Now().Return(tm)
			},
			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "updated full name",
				UpdatedAt: tm,
			},
		},
		"should do nothing when fields is empty": {
			mock: func(dbMock *mock.MockDB, iTime *mock.MockITime) {},
			data: dto.CustomerUpdateData{
				ID:        1,
				UpdatedAt: tm,
			},
		},
		"should throw not found exception on NamedExecContext": {
			mock: func(dbMock *mock.MockDB, iTime *mock.MockITime) {
				query := "\n\t\tUPDATE customers\n\t\tSET fullname = :fullname, email = :email, updated_at = :now\n\t\tWHERE id = :id\n\t\t\tAND updated_at = :updated_at\n\t\t\tAND deleted_at IS NULL\n\t"
				args := map[string]interface{}{
					"fullname":   "updated full name",
					"email":      "updatedemail@email.com",
					"now":        tm,
					"id":         int64(1),
					"updated_at": tm,
				}

				dbMock.EXPECT().NamedExecContext(gomock.Any(), query, args).Return(sqlResultMock{}, nil)
				iTime.EXPECT().Now().Return(tm)
			},
			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "updated full name",
				Email:     "updatedemail@email.com",
				UpdatedAt: tm,
			},
			wantErr: "customer not found",
		},
		"should throw error on NamedExecContext": {
			mock: func(dbMock *mock.MockDB, iTime *mock.MockITime) {
				query := "\n\t\tUPDATE customers\n\t\tSET fullname = :fullname, email = :email, updated_at = :now\n\t\tWHERE id = :id\n\t\t\tAND updated_at = :updated_at\n\t\t\tAND deleted_at IS NULL\n\t"
				args := map[string]interface{}{
					"fullname":   "updated full name",
					"email":      "updatedemail@email.com",
					"now":        tm,
					"id":         int64(1),
					"updated_at": tm,
				}

				dbMock.EXPECT().NamedExecContext(gomock.Any(), query, args).Return(nil, fmt.Errorf("error"))
				iTime.EXPECT().Now().Return(tm)
			},
			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "updated full name",
				Email:     "updatedemail@email.com",
				UpdatedAt: tm,
			},
			wantErr: "error",
		},
		"should throw error on res.RowsAffected": {
			mock: func(dbMock *mock.MockDB, iTime *mock.MockITime) {
				query := "\n\t\tUPDATE customers\n\t\tSET fullname = :fullname, email = :email, updated_at = :now\n\t\tWHERE id = :id\n\t\t\tAND updated_at = :updated_at\n\t\t\tAND deleted_at IS NULL\n\t"
				args := map[string]interface{}{
					"fullname":   "updated full name",
					"email":      "updatedemail@email.com",
					"now":        tm,
					"id":         int64(1),
					"updated_at": tm,
				}

				dbMock.EXPECT().NamedExecContext(gomock.Any(), query, args).Return(sqlResultMock{err: fmt.Errorf("error")}, nil)
				iTime.EXPECT().Now().Return(tm)
			},
			data: dto.CustomerUpdateData{
				ID:        1,
				FullName:  "updated full name",
				Email:     "updatedemail@email.com",
				UpdatedAt: tm,
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
			timeMock := mock.NewMockITime(ctrl)
			_time = timeMock
			tt.mock(dbMock, timeMock)

			// given
			customerRepository := NewCustomer(dbMock)

			// when
			err := customerRepository.Update(ctx, tt.data)

			// then
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
