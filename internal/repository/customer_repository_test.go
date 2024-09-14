package repository

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/exception"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
)

func TestNewCustomerRepository(t *testing.T) {
	got := NewCustomerRepository(nil)

	assert.NotNil(t, got)
}

func TestCustomerRepository_Create(t *testing.T) {
	insertCustomerQuery := `INSERT INTO customers \(name\) VALUES \(\$1\) RETURNING id`
	type args struct {
		ctx         context.Context
		customerDto dto.CustomerDataDto
	}
	tests := map[string]struct {
		mock    func(mock sqlmock.Sqlmock)
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should create customer successfully": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(insertCustomerQuery).
					ExpectQuery().
					WithArgs("Testing").
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
			},
			args: args{
				ctx:         context.TODO(),
				customerDto: dto.CustomerDataDto{Name: "Testing"},
			},
			want: &model.Customer{ID: 1, Name: "Testing"},
		},
		"should throw error on PrepareNamedContext": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(insertCustomerQuery).WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx:         context.TODO(),
				customerDto: dto.CustomerDataDto{Name: "Testing"},
			},
			wantErr: "error",
		},
		"should throw error on QueryRowContext": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(insertCustomerQuery).
					ExpectQuery().
					WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx:         context.TODO(),
				customerDto: dto.CustomerDataDto{Name: "Testing"},
			},
			wantErr: "error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.mock(mock)

			repository := NewCustomerRepository(sqlx.NewDb(db, "postgres"))
			got, err := repository.Create(tt.args.ctx, tt.args.customerDto)

			mock.ExpectationsWereMet()
			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerRepository_Find(t *testing.T) {
	findCustomerQuery := `SELECT id, name FROM customers WHERE id = \$1`
	type args struct {
		ctx context.Context
		id  int64
	}
	tests := map[string]struct {
		mock    func(mock sqlmock.Sqlmock)
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should find customer successfully": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(findCustomerQuery).
					WithArgs(1).
					WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(1, "Testing"))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
			},
			want: &model.Customer{ID: 1, Name: "Testing"},
		},
		"should throw error when customer not found": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(findCustomerQuery).
					WithArgs(2).
					WillReturnError(sql.ErrNoRows)
			},
			args: args{
				ctx: context.TODO(),
				id:  2,
			},
			wantErr: "customer not found by ID 2",
		},
		"should throw error": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(findCustomerQuery).
					WithArgs(3).
					WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx: context.TODO(),
				id:  3,
			},
			wantErr: "error",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.mock(mock)

			repository := NewCustomerRepository(sqlx.NewDb(db, "postgres"))
			got, err := repository.Find(tt.args.ctx, tt.args.id)

			mock.ExpectationsWereMet()
			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerRepository_Update(t *testing.T) {
	updateCustomerQuery := `UPDATE customers SET name = \$1 WHERE id = \$2 RETURNING id, name`
	type args struct {
		ctx         context.Context
		id          int64
		customerDto dto.CustomerDataDto
	}
	tests := map[string]struct {
		mock    func(mock sqlmock.Sqlmock)
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should update customer successfully": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(updateCustomerQuery).
					ExpectQuery().
					WithArgs("Testing", 1).
					WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(1, "Testing"))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
				customerDto: dto.CustomerDataDto{
					Name: "Testing",
				},
			},
			want: &model.Customer{
				ID:   1,
				Name: "Testing",
			},
		},
		"should throw error when customer not found": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(updateCustomerQuery).
					ExpectQuery().
					WithArgs("Testing", 2).
					WillReturnError(exception.NewNotFoundException("customer not found by ID 2"))
			},
			args: args{
				ctx: context.TODO(),
				id:  2,
				customerDto: dto.CustomerDataDto{
					Name: "Testing",
				},
			},
			wantErr: "customer not found by ID 2",
		},
		"should throw error on PrepareContext": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(updateCustomerQuery).
					WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
				customerDto: dto.CustomerDataDto{
					Name: "Testing",
				},
			},
			wantErr: "error",
		},
		"should throw error on QueryRowContext": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(updateCustomerQuery).
					ExpectQuery().
					WithArgs("Testing", 1).
					WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
				customerDto: dto.CustomerDataDto{
					Name: "Testing",
				},
			},
			wantErr: "error",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.mock(mock)

			repository := NewCustomerRepository(sqlx.NewDb(db, "postgres"))
			got, err := repository.Update(tt.args.ctx, tt.args.id, tt.args.customerDto)

			mock.ExpectationsWereMet()
			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
