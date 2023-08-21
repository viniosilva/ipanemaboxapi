package mock

import (
	"fmt"
	"reflect"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
)

const (
	fieldErrMsg = "Key: '%s' Error:Field validation for '%s' failed on the '%s' tag"
)

type FieldError struct {
	v              *validator.Validate
	Itag           string
	actualTag      string
	Ins            string
	structNs       string
	fieldLen       uint8
	structfieldLen uint8
	value          interface{}
	param          string
	kind           reflect.Kind
	typ            reflect.Type
}

func (impl *FieldError) Tag() string {
	return impl.Itag
}

func (impl *FieldError) ActualTag() string {
	return impl.actualTag
}

func (impl *FieldError) Namespace() string {
	return impl.Ins
}

func (impl *FieldError) StructNamespace() string {
	return impl.structNs
}

func (impl *FieldError) Field() string {

	return impl.Ins[len(impl.Ins)-int(impl.fieldLen):]
}

func (impl *FieldError) StructField() string {
	return impl.structNs[len(impl.structNs)-int(impl.structfieldLen):]
}

func (impl *FieldError) Value() interface{} {
	return impl.value
}

func (impl *FieldError) Param() string {
	return impl.param
}

func (impl *FieldError) Kind() reflect.Kind {
	return impl.kind
}

func (impl *FieldError) Type() reflect.Type {
	return impl.typ
}

func (impl *FieldError) Error() string {
	return fmt.Sprintf(fieldErrMsg, impl.Ins, impl.Field(), impl.Itag)
}

func (impl *FieldError) Translate(ut ut.Translator) string {
	return "translate"
}
