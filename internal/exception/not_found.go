package exception

import "fmt"

const NotFoundExceptionName = "not_found"

type NotFoundException struct {
	Name   string
	Errors []string
	err    string
}

func NewNotFoundException(target string) *NotFoundException {
	return &NotFoundException{
		Name: NotFoundExceptionName,
		err:  fmt.Sprintf("%s not found", target),
	}
}

func (impl *NotFoundException) Error() string {
	return impl.err
}
