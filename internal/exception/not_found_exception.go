package exception

import "fmt"

// NotFoundException define generic not found error
type NotFoundException struct {
	msg string
}

// Error implementation to NotFoundExcpetion
func (e *NotFoundException) Error() string {
	return e.msg
}

// func NotFoundException(msg string) error {
func NewNotFoundException(msg string, args ...any) error {
	return &NotFoundException{
		msg: fmt.Sprintf(msg, args...),
	}
}
