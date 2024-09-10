package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuild(t *testing.T) {
	got := Build(nil)
	assert.NotNil(t, got)
}
