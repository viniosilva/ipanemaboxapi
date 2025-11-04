package pkg_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

func TestPointer(t *testing.T) {
	t.Run("should return pointer when value is string", func(t *testing.T) {
		value := "test string"
		result := pkg.Pointer(value)

		assert.NotNil(t, result)
		assert.Equal(t, value, *result)
	})

	t.Run("should return pointer when value is int", func(t *testing.T) {
		value := 42
		result := pkg.Pointer(value)

		assert.NotNil(t, result)
		assert.Equal(t, value, *result)
	})

	t.Run("should return pointer when value is bool", func(t *testing.T) {
		value := true
		result := pkg.Pointer(value)

		assert.NotNil(t, result)
		assert.Equal(t, value, *result)
	})

	t.Run("should return pointer when value is empty string", func(t *testing.T) {
		value := ""
		result := pkg.Pointer(value)

		assert.NotNil(t, result)
		assert.Equal(t, value, *result)
	})
}
