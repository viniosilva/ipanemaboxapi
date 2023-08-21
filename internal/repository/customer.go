package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/vinosilva/ipanemaboxapi/internal/dto"
	"github.com/vinosilva/ipanemaboxapi/internal/exception"
	"github.com/vinosilva/ipanemaboxapi/internal/model"
)

var _time ITime

func init() {
	_time = &timeImpl{}
}

type CustomerRepository struct {
	Repository
	db DB
}

func NewCustomer(db DB) *CustomerRepository {
	return &CustomerRepository{
		db: db,
	}
}

func (impl *CustomerRepository) Create(ctx context.Context, data dto.CustomerCreateData) (*model.Customer, error) {
	now := _time.Now()
	customerModel := &model.Customer{
		CreatedAt: &now,
		UpdatedAt: &now,
		FullName:  data.FullName,
		Email:     data.Email,
	}

	query := `
		INSERT INTO customers (created_at, updated_at, fullname, email)
		VALUES (:created_at, :updated_at, :fullname, :email)
	`

	res, err := impl.db.NamedExecContext(ctx, query, customerModel)
	if err != nil {
		return nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	customerModel.ID = id

	return customerModel, nil
}

func (impl *CustomerRepository) FindAll(ctx context.Context, data dto.CustomerFindAllData) (*dto.CustomersResult, error) {
	limit, offset := impl.getLimitAndOffset(data.Page, data.Size)
	query := fmt.Sprintf(`
		SELECT id,
			created_at,
			updated_at,
			fullname,
			email
		FROM customers
		WHERE deleted_at IS NULL
		ORDER BY created_at
		LIMIT %d OFFSET %d
	`, limit, offset)

	var res []model.Customer
	err := impl.db.SelectContext(ctx, &res, query)
	if err != nil {
		return nil, err
	}

	return &dto.CustomersResult{
		Data: res,
	}, nil
}

func (impl *CustomerRepository) FindByID(ctx context.Context, id int64) (*model.Customer, error) {
	query := `
		SELECT id,
			created_at,
			updated_at,
			fullname,
			email
		FROM customers
		WHERE id = ?
			AND deleted_at IS NULL
	`

	var res model.Customer
	err := impl.db.GetContext(ctx, &res, query, id)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, exception.NewNotFoundException("customer")
		}
		return nil, err
	}

	return &res, nil
}

func (impl *CustomerRepository) Update(ctx context.Context, data dto.CustomerUpdateData) error {
	sets := []string{}
	args := map[string]interface{}{}

	if data.FullName != "" {
		sets = append(sets, "fullname = :fullname")
		args["fullname"] = data.FullName
	}
	if data.Email != "" {
		sets = append(sets, "email = :email")
		args["email"] = data.Email
	}
	if len(sets) == 0 {
		return nil
	}

	sets = append(sets, "updated_at = :now")
	args["now"] = _time.Now()
	args["id"] = data.ID
	args["updated_at"] = data.UpdatedAt

	query := fmt.Sprintf(`
		UPDATE customers
		SET %s
		WHERE id = :id
			AND updated_at = :updated_at
			AND deleted_at IS NULL
	`, strings.Join(sets, ", "))

	res, err := impl.db.NamedExecContext(ctx, query, args)
	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return exception.NewNotFoundException("customer")
	}

	return nil
}
