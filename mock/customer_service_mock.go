// Code generated by MockGen. DO NOT EDIT.
// Source: internal/service/customer_service.go
//
// Generated by this command:
//
//	mockgen -source=internal/service/customer_service.go -destination=mock/customer_service_mock.go -package=mock
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	dto "github.com/viniosilva/ipanemaboxapi/internal/dto"
	model "github.com/viniosilva/ipanemaboxapi/internal/model"
	gomock "go.uber.org/mock/gomock"
)

// MockCustomerRepository is a mock of CustomerRepository interface.
type MockCustomerRepository struct {
	ctrl     *gomock.Controller
	recorder *MockCustomerRepositoryMockRecorder
}

// MockCustomerRepositoryMockRecorder is the mock recorder for MockCustomerRepository.
type MockCustomerRepositoryMockRecorder struct {
	mock *MockCustomerRepository
}

// NewMockCustomerRepository creates a new mock instance.
func NewMockCustomerRepository(ctrl *gomock.Controller) *MockCustomerRepository {
	mock := &MockCustomerRepository{ctrl: ctrl}
	mock.recorder = &MockCustomerRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCustomerRepository) EXPECT() *MockCustomerRepositoryMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockCustomerRepository) Create(ctx context.Context, customerDto dto.CreateCustomerDto) (*model.Customer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, customerDto)
	ret0, _ := ret[0].(*model.Customer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockCustomerRepositoryMockRecorder) Create(ctx, customerDto any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockCustomerRepository)(nil).Create), ctx, customerDto)
}

// Find mocks base method.
func (m *MockCustomerRepository) Find(ctx context.Context, id int64) (*model.Customer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Find", ctx, id)
	ret0, _ := ret[0].(*model.Customer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Find indicates an expected call of Find.
func (mr *MockCustomerRepositoryMockRecorder) Find(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Find", reflect.TypeOf((*MockCustomerRepository)(nil).Find), ctx, id)
}
